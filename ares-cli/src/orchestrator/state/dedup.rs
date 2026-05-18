//! Dedup persistence — mark_exploited, persist_dedup, persist_mssql.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::{OpStateEventPayload, VulnerabilityInfo};
use ares_core::state;

use redis::aio::ConnectionLike;

use super::publishing::emit_op_state;
use super::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

/// After this many consecutive failed exploit dispatches for the same vuln,
/// the exploitation workflow stops re-dispatching it. Set just high enough
/// to absorb transient failures (LLM hiccups, throttle bumps) while still
/// catching unsatisfiable preconditions in well under an hour:
/// 5 attempts × 120s cooldown = ~10 min ceiling per stuck vuln.
pub const MAX_EXPLOIT_FAILURES: u32 = 5;

impl SharedState {
    /// Mark a vulnerability as exploited.
    ///
    /// Also marks any vulnerabilities superseded by this exploit. A successful
    /// `mssql_impersonation`/`mssql_linked_server` on a host implies the
    /// host-level `mssql_access` is exploited too; a `dc_secretsdump_<domain>`
    /// makes any `forest_trust_escalation` or `child_to_parent` whose
    /// `target_domain == <domain>` moot — the trust-key chain was rendered
    /// unnecessary because the target was reached by another path. Without
    /// this, the loot view shows artificial ✗ rows whose goal was already met.
    pub async fn mark_exploited(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        vuln_id: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_EXPLOITED
        );

        // Compute superseded vuln_ids from in-memory discovered_vulnerabilities.
        let superseded: Vec<String> = {
            let state = self.inner.read().await;
            let primary = state.discovered_vulnerabilities.get(vuln_id);
            compute_superseded(vuln_id, primary, &state.discovered_vulnerabilities)
        };

        let mut conn = queue.connection();
        let _: () = conn.sadd(&key, vuln_id).await?;
        for sid in &superseded {
            let _: () = conn.sadd(&key, sid).await?;
        }
        let _: () = conn.expire(&key, 86400).await?;

        emit_op_state(
            self.recorder(),
            &operation_id,
            OpStateEventPayload::VulnExploited {
                vuln_id: vuln_id.to_string(),
                exploited_by: String::new(),
                result: None,
            },
        )
        .await;

        let mut state = self.inner.write().await;
        state.exploited_vulnerabilities.insert(vuln_id.to_string());
        for sid in superseded {
            tracing::info!(
                primary = %vuln_id,
                superseded = %sid,
                "Marking superseded vulnerability as exploited"
            );
            state.exploited_vulnerabilities.insert(sid);
        }
        Ok(())
    }

    /// Persist a dedup set entry to Redis.
    pub async fn persist_dedup(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        set_name: &str,
        key: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let redis_key = format!(
            "{}:{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DEDUP_PREFIX,
            set_name
        );
        let mut conn = queue.connection();
        let _: () = conn.sadd(&redis_key, key).await?;
        let _: () = conn.expire(&redis_key, 86400).await?;
        Ok(())
    }

    /// Remove a dedup set entry from Redis (used to allow retries after a
    /// transient failure such as auth-mismatch on enumeration).
    pub async fn unpersist_dedup(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        set_name: &str,
        key: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let redis_key = format!(
            "{}:{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DEDUP_PREFIX,
            set_name
        );
        let mut conn = queue.connection();
        let _: () = conn.srem(&redis_key, key).await?;
        Ok(())
    }

    /// Persist MSSQL enum dispatched entry to Redis.
    pub async fn persist_mssql_dispatched(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        ip: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let redis_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_MSSQL_ENUM_DISPATCHED
        );
        let mut conn = queue.connection();
        let _: () = conn.sadd(&redis_key, ip).await?;
        let _: () = conn.expire(&redis_key, 86400).await?;
        Ok(())
    }

    /// Increment the failure counter for `vuln_id` and return the new count.
    /// Called from result processing on every failed exploit task. When the
    /// count reaches `MAX_EXPLOIT_FAILURES` the exploitation workflow will
    /// abandon the vuln on the next pop.
    pub async fn record_exploit_failure(&self, vuln_id: &str) -> u32 {
        let mut state = self.inner.write().await;
        let count = state
            .exploit_failure_counts
            .entry(vuln_id.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        *count
    }

    /// Returns true once `vuln_id` has accumulated `MAX_EXPLOIT_FAILURES`
    /// consecutive failures. Checked by the exploitation workflow before
    /// dispatching a vuln from the priority queue.
    pub async fn is_exploit_abandoned(&self, vuln_id: &str) -> bool {
        let state = self.inner.read().await;
        state
            .exploit_failure_counts
            .get(vuln_id)
            .map(|c| *c >= MAX_EXPLOIT_FAILURES)
            .unwrap_or(false)
    }
}

/// Given the primary vuln being marked exploited, return additional vuln_ids
/// that this exploit logically supersedes. Pure function — no I/O — so it can
/// be unit tested directly.
fn compute_superseded(
    vuln_id: &str,
    primary: Option<&VulnerabilityInfo>,
    discovered: &std::collections::HashMap<String, VulnerabilityInfo>,
) -> Vec<String> {
    let Some(primary) = primary else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match primary.vuln_type.as_str() {
        // Host-deep MSSQL exploits supersede the host-level mssql_access vuln
        // — getting EXECUTE AS or linked-server pivot proves the access path
        // worked.
        "mssql_impersonation" | "mssql_linked_server" | "mssql_xpcmdshell" => {
            for (vid, v) in discovered {
                if vid == vuln_id {
                    continue;
                }
                if v.vuln_type == "mssql_access" && v.target == primary.target {
                    out.push(vid.clone());
                }
            }
        }
        // Once a domain is fully compromised via DCSync, any trust-chain or
        // child-to-parent vuln whose `target_domain` is that domain is moot.
        "dc_secretsdump" => {
            let dominated = primary
                .details
                .get("domain")
                .and_then(|v| v.as_str())
                .map(str::to_lowercase);
            let Some(dominated) = dominated else {
                return out;
            };
            for (vid, v) in discovered {
                if vid == vuln_id {
                    continue;
                }
                if !matches!(
                    v.vuln_type.as_str(),
                    "forest_trust_escalation" | "child_to_parent"
                ) {
                    continue;
                }
                let tgt = v
                    .details
                    .get("target_domain")
                    .and_then(|d| d.as_str())
                    .map(str::to_lowercase)
                    .unwrap_or_default();
                if tgt == dominated {
                    out.push(vid.clone());
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{compute_superseded, MAX_EXPLOIT_FAILURES};
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::models::VulnerabilityInfo;
    use ares_core::state::mock_redis::MockRedisConnection;
    use std::collections::HashMap;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    fn vuln(id: &str, vtype: &str, target: &str, details: &[(&str, &str)]) -> VulnerabilityInfo {
        let mut d = HashMap::new();
        for (k, v) in details {
            d.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: vtype.to_string(),
            target: target.to_string(),
            discovered_by: "test".to_string(),
            discovered_at: chrono::Utc::now(),
            details: d,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[tokio::test]
    async fn mark_exploited_adds_to_state_and_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state.mark_exploited(&q, "VULN-001").await.unwrap();

        let s = state.inner.read().await;
        assert!(s.exploited_vulnerabilities.contains("VULN-001"));

        // Verify persisted to Redis
        let mut conn = q.connection();
        let key = "ares:op:op-1:exploited".to_string();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &key)
                .await
                .unwrap();
        assert!(members.contains("VULN-001"));
    }

    #[tokio::test]
    async fn persist_dedup_stores_in_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .persist_dedup(&q, "cred_spray", "admin@192.168.58.1")
            .await
            .unwrap();

        let mut conn = q.connection();
        let key = "ares:op:op-1:dedup:cred_spray".to_string();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &key)
                .await
                .unwrap();
        assert!(members.contains("admin@192.168.58.1"));
    }

    #[tokio::test]
    async fn persist_mssql_dispatched_stores_in_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .persist_mssql_dispatched(&q, "192.168.58.5")
            .await
            .unwrap();

        let mut conn = q.connection();
        let key = "ares:op:op-1:mssql_enum_dispatched".to_string();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &key)
                .await
                .unwrap();
        assert!(members.contains("192.168.58.5"));
    }

    #[test]
    fn supersede_mssql_impersonation_supersedes_host_access() {
        let mut discovered = HashMap::new();
        discovered.insert(
            "mssql_192_168_58_51".to_string(),
            vuln("mssql_192_168_58_51", "mssql_access", "192.168.58.51", &[]),
        );
        discovered.insert(
            "mssql_impersonation_192.168.58.51".to_string(),
            vuln(
                "mssql_impersonation_192.168.58.51",
                "mssql_impersonation",
                "192.168.58.51",
                &[],
            ),
        );
        let primary = discovered.get("mssql_impersonation_192.168.58.51");
        let out = compute_superseded("mssql_impersonation_192.168.58.51", primary, &discovered);
        assert_eq!(out, vec!["mssql_192_168_58_51".to_string()]);
    }

    #[test]
    fn supersede_mssql_linked_server_supersedes_host_access() {
        let mut discovered = HashMap::new();
        discovered.insert(
            "mssql_192_168_58_254".to_string(),
            vuln(
                "mssql_192_168_58_254",
                "mssql_access",
                "192.168.58.254",
                &[],
            ),
        );
        let lsid = "mssql_linked_server_192.168.58.254_SQL".to_string();
        discovered.insert(
            lsid.clone(),
            vuln(&lsid, "mssql_linked_server", "192.168.58.254", &[]),
        );
        let out = compute_superseded(&lsid, discovered.get(&lsid), &discovered);
        assert_eq!(out, vec!["mssql_192_168_58_254".to_string()]);
    }

    #[test]
    fn supersede_mssql_does_not_match_other_hosts() {
        let mut discovered = HashMap::new();
        discovered.insert(
            "mssql_192_168_58_51".to_string(),
            vuln("mssql_192_168_58_51", "mssql_access", "192.168.58.51", &[]),
        );
        discovered.insert(
            "mssql_impersonation_192.168.58.254".to_string(),
            vuln(
                "mssql_impersonation_192.168.58.254",
                "mssql_impersonation",
                "192.168.58.254",
                &[],
            ),
        );
        let primary = discovered.get("mssql_impersonation_192.168.58.254");
        let out = compute_superseded("mssql_impersonation_192.168.58.254", primary, &discovered);
        assert!(out.is_empty());
    }

    #[test]
    fn supersede_dc_secretsdump_covers_trust_and_child_to_parent() {
        let mut discovered = HashMap::new();
        discovered.insert(
            "dc_secretsdump_fabrikam.local".to_string(),
            vuln(
                "dc_secretsdump_fabrikam.local",
                "dc_secretsdump",
                "192.168.58.58",
                &[("domain", "fabrikam.local")],
            ),
        );
        discovered.insert(
            "forest_trust_contoso.local_fabrikam.local".to_string(),
            vuln(
                "forest_trust_contoso.local_fabrikam.local",
                "forest_trust_escalation",
                "192.168.58.58",
                &[("target_domain", "fabrikam.local")],
            ),
        );
        discovered.insert(
            "child_to_parent_child_fabrikam".to_string(),
            vuln(
                "child_to_parent_child_fabrikam",
                "child_to_parent",
                "192.168.58.58",
                &[("target_domain", "fabrikam.local")],
            ),
        );
        // Unrelated trust should NOT be superseded.
        discovered.insert(
            "forest_trust_fabrikam_child".to_string(),
            vuln(
                "forest_trust_fabrikam_child",
                "forest_trust_escalation",
                "192.168.58.150",
                &[("target_domain", "child.contoso.local")],
            ),
        );
        let primary = discovered.get("dc_secretsdump_fabrikam.local");
        let mut out = compute_superseded("dc_secretsdump_fabrikam.local", primary, &discovered);
        out.sort();
        assert_eq!(
            out,
            vec![
                "child_to_parent_child_fabrikam".to_string(),
                "forest_trust_contoso.local_fabrikam.local".to_string(),
            ]
        );
    }

    #[test]
    fn supersede_returns_empty_when_primary_missing() {
        let discovered = HashMap::new();
        let out = compute_superseded("ghost", None, &discovered);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn mark_exploited_propagates_to_superseded() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.discovered_vulnerabilities.insert(
                "mssql_192_168_58_51".into(),
                vuln("mssql_192_168_58_51", "mssql_access", "192.168.58.51", &[]),
            );
            s.discovered_vulnerabilities.insert(
                "mssql_impersonation_192.168.58.51".into(),
                vuln(
                    "mssql_impersonation_192.168.58.51",
                    "mssql_impersonation",
                    "192.168.58.51",
                    &[],
                ),
            );
        }

        state
            .mark_exploited(&q, "mssql_impersonation_192.168.58.51")
            .await
            .unwrap();

        let s = state.inner.read().await;
        assert!(s
            .exploited_vulnerabilities
            .contains("mssql_impersonation_192.168.58.51"));
        assert!(s.exploited_vulnerabilities.contains("mssql_192_168_58_51"));

        let mut conn = q.connection();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, "ares:op:op-1:exploited")
                .await
                .unwrap();
        assert!(members.contains("mssql_impersonation_192.168.58.51"));
        assert!(members.contains("mssql_192_168_58_51"));
    }

    #[tokio::test]
    async fn record_exploit_failure_increments_counter() {
        let state = SharedState::new("op-1".to_string());
        assert_eq!(
            state.record_exploit_failure("mssql_192_168_58_254").await,
            1
        );
        assert_eq!(
            state.record_exploit_failure("mssql_192_168_58_254").await,
            2
        );
        assert_eq!(
            state.record_exploit_failure("mssql_192_168_58_254").await,
            3
        );
        // Different vuln tracked independently.
        assert_eq!(state.record_exploit_failure("other_vuln").await, 1);
    }

    #[tokio::test]
    async fn is_exploit_abandoned_below_threshold() {
        let state = SharedState::new("op-1".to_string());
        for _ in 0..(MAX_EXPLOIT_FAILURES - 1) {
            state.record_exploit_failure("vuln_a").await;
        }
        assert!(!state.is_exploit_abandoned("vuln_a").await);
        assert!(!state.is_exploit_abandoned("never_failed").await);
    }

    #[tokio::test]
    async fn is_exploit_abandoned_at_and_above_threshold() {
        let state = SharedState::new("op-1".to_string());
        for _ in 0..MAX_EXPLOIT_FAILURES {
            state.record_exploit_failure("vuln_a").await;
        }
        assert!(state.is_exploit_abandoned("vuln_a").await);
        // Further failures don't un-abandon.
        state.record_exploit_failure("vuln_a").await;
        assert!(state.is_exploit_abandoned("vuln_a").await);
    }

    #[tokio::test]
    async fn mark_exploited_emits_event_with_capturing_recorder() {
        use ares_core::models::OpStateEventPayload;
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-ex".to_string(), recorder.clone());
        let q = mock_queue();

        state.mark_exploited(&q, "VULN-007").await.unwrap();

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        match &evs[0].payload {
            OpStateEventPayload::VulnExploited { vuln_id, .. } => {
                assert_eq!(vuln_id, "VULN-007");
            }
            other => panic!("expected VulnExploited, got {other:?}"),
        }
    }
}
