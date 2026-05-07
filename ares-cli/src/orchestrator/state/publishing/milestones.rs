//! Milestone publishing: golden ticket, domain admin.

use std::collections::HashMap;

use anyhow::Result;

use ares_core::models::VulnerabilityInfo;
use ares_core::state::RedisStateReader;

use redis::aio::ConnectionLike;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

impl SharedState {
    /// Set has_golden_ticket flag and persist to Redis.
    pub async fn set_golden_ticket(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        domain: &str,
    ) -> Result<()> {
        {
            let state = self.inner.read().await;
            if state.has_golden_ticket {
                return Ok(());
            }
        }
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_golden_ticket",
                &serde_json::Value::Bool(true),
            )
            .await?;

        // Resolve DC IP for the vulnerability target
        let dc_target = {
            let state = self.inner.read().await;
            state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned()
                .unwrap_or_else(|| domain.to_string())
        };

        let mut state = self.inner.write().await;
        state.has_golden_ticket = true;
        tracing::info!(domain = %domain, "🏆 Golden ticket flag set");
        drop(state);

        // Synthesize a golden_ticket vulnerability so loot reflects the achievement
        let vuln_id = format!("golden_ticket_{}", domain.to_lowercase());
        let mut details = HashMap::new();
        details.insert(
            "domain".into(),
            serde_json::Value::String(domain.to_string()),
        );
        details.insert(
            "note".into(),
            serde_json::Value::String(
                "Golden ticket forged — persistent domain access via krbtgt key".to_string(),
            ),
        );
        let vuln = VulnerabilityInfo {
            vuln_id: vuln_id.clone(),
            vuln_type: "golden_ticket".to_string(),
            target: dc_target,
            discovered_by: "golden_ticket_automation".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        let _ = self.publish_vulnerability(queue, vuln).await;
        let _ = self.mark_exploited(queue, &vuln_id).await;
        Ok(())
    }

    /// Set has_domain_admin flag and persist to Redis.
    pub async fn set_domain_admin(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        path: Option<String>,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_domain_admin",
                &serde_json::Value::Bool(true),
            )
            .await?;
        if let Some(ref p) = path {
            reader
                .set_meta_field(
                    &mut conn,
                    "domain_admin_path",
                    &serde_json::Value::String(p.clone()),
                )
                .await?;
        }

        let mut state = self.inner.write().await;
        state.has_domain_admin = true;
        state.domain_admin_path = path.clone();

        // Emit OTel span recording domain admin achievement.
        // Walk parent_id chain from krbtgt hash to compute attack depth.
        let (attack_path_str, depth) = {
            let krbtgt = state.hashes.iter().find(|h| {
                h.username.eq_ignore_ascii_case("krbtgt")
                    && h.hash_type.to_lowercase().contains("ntlm")
            });
            let depth = match krbtgt {
                Some(h) => {
                    // Count chain depth by walking parent_id
                    let mut d = 1usize;
                    let mut current_id = h.parent_id.clone();
                    let mut seen = std::collections::HashSet::new();
                    while let Some(ref pid) = current_id {
                        if !seen.insert(pid.clone()) {
                            break;
                        }
                        d += 1;
                        // Check credentials then hashes for the parent
                        if let Some(c) = state.credentials.iter().find(|c| c.id == *pid) {
                            current_id = c.parent_id.clone();
                        } else if let Some(h2) = state.hashes.iter().find(|h2| h2.id == *pid) {
                            current_id = h2.parent_id.clone();
                        } else {
                            break;
                        }
                    }
                    d
                }
                None => 0,
            };
            let ap = path
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("domain_admin_achieved")
                .to_string();
            (ap, depth)
        };
        let op_id = state.operation_id.clone();
        drop(state);

        // Domain-admin is an operation-level milestone (not scoped to a single
        // task), so we leave `task.id` empty and only correlate by `op.id`.
        let span = ares_core::telemetry::spans::trace_domain_admin(
            &attack_path_str,
            depth,
            Some(&op_id),
            None,
        );
        let _guard = span.enter();
        tracing::info!(attack_path = %attack_path_str, depth = depth, "🏆 Domain admin achieved");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[tokio::test]
    async fn set_golden_ticket_sets_flag() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state.set_golden_ticket(&q, "contoso.local").await.unwrap();

        let s = state.inner.read().await;
        assert!(s.has_golden_ticket);
    }

    #[tokio::test]
    async fn set_golden_ticket_idempotent() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state.set_golden_ticket(&q, "contoso.local").await.unwrap();
        // Second call should be a no-op
        state.set_golden_ticket(&q, "contoso.local").await.unwrap();

        let s = state.inner.read().await;
        assert!(s.has_golden_ticket);
    }

    #[tokio::test]
    async fn set_golden_ticket_creates_vulnerability() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state.set_golden_ticket(&q, "contoso.local").await.unwrap();

        let s = state.inner.read().await;
        assert!(s
            .discovered_vulnerabilities
            .contains_key("golden_ticket_contoso.local"));
        let vuln = &s.discovered_vulnerabilities["golden_ticket_contoso.local"];
        assert_eq!(vuln.vuln_type, "golden_ticket");
    }

    #[tokio::test]
    async fn set_golden_ticket_uses_dc_ip_as_target() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        {
            let mut s = state.inner.write().await;
            s.domain_controllers
                .insert("contoso.local".to_string(), "192.168.58.1".to_string());
        }

        state.set_golden_ticket(&q, "contoso.local").await.unwrap();

        let s = state.inner.read().await;
        let vuln = &s.discovered_vulnerabilities["golden_ticket_contoso.local"];
        assert_eq!(vuln.target, "192.168.58.1");
    }

    #[tokio::test]
    async fn set_domain_admin_sets_flag() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .set_domain_admin(&q, Some("secretsdump → krbtgt".to_string()))
            .await
            .unwrap();

        let s = state.inner.read().await;
        assert!(s.has_domain_admin);
        assert_eq!(s.domain_admin_path.as_deref(), Some("secretsdump → krbtgt"));
    }

    #[tokio::test]
    async fn set_domain_admin_without_path() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state.set_domain_admin(&q, None).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.has_domain_admin);
        assert!(s.domain_admin_path.is_none());
    }

    #[tokio::test]
    async fn set_domain_admin_persists_meta_to_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .set_domain_admin(&q, Some("exploit chain".to_string()))
            .await
            .unwrap();

        // Verify meta fields persisted to Redis
        let reader = RedisStateReader::new("op-1".to_string());
        let mut conn = q.connection();
        let meta = reader.get_meta(&mut conn).await.unwrap();
        assert!(meta.has_domain_admin);
    }
}
