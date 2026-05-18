//! Entity publishing: users, vulnerabilities, shares, timeline, tasks, netbios, trusts.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::{OpStateEventPayload, Share, User, VulnerabilityInfo};
use ares_core::state::{self, RedisStateReader};

use redis::aio::ConnectionLike;

use super::emit_op_state;
use crate::dedup::is_ghost_machine_account;
use crate::orchestrator::state::{SharedState, KEY_VULN_QUEUE};
use crate::orchestrator::task_queue::TaskQueueCore;

impl SharedState {
    /// Add a user to state and Redis (with dedup).
    ///
    /// Cross-domain dedup: if the same username already exists in a different
    /// domain that shares a trust relationship with the new domain, the new
    /// entry is rejected. This prevents Global Catalog queries (port 3268)
    /// from creating phantom users attributed to the wrong domain — e.g.
    /// a user in `child.contoso.local` appearing as `fabrikam.local\user`
    /// when enumerated via a cross-forest GC query.
    pub async fn publish_user(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        user: User,
    ) -> Result<bool> {
        // Check for duplicate in memory (exact match or cross-domain trust match)
        {
            let state = self.inner.read().await;
            let dedup = format!(
                "{}@{}",
                user.username.to_lowercase(),
                user.domain.to_lowercase()
            );
            let username_lower = user.username.to_lowercase();
            let domain_lower = user.domain.to_lowercase();

            for existing in &state.users {
                let existing_key = format!(
                    "{}@{}",
                    existing.username.to_lowercase(),
                    existing.domain.to_lowercase()
                );
                // Exact duplicate
                if existing_key == dedup {
                    return Ok(false);
                }
                // Cross-domain duplicate: same username, different domain, trust exists
                if existing.username.to_lowercase() == username_lower
                    && existing.domain.to_lowercase() != domain_lower
                {
                    let existing_domain = existing.domain.to_lowercase();
                    let domains_are_trusted = state.trusted_domains.contains_key(&domain_lower)
                        || state.trusted_domains.contains_key(&existing_domain)
                        || are_in_same_forest(&domain_lower, &existing_domain);
                    if domains_are_trusted {
                        tracing::debug!(
                            username = %user.username,
                            new_domain = %user.domain,
                            existing_domain = %existing.domain,
                            "Skipping cross-domain duplicate user (trust/forest relationship)"
                        );
                        return Ok(false);
                    }
                }
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_user(&mut conn, &user).await?;
        if added {
            emit_op_state(
                self.recorder(),
                &operation_id,
                OpStateEventPayload::UserDiscovered { user: user.clone() },
            )
            .await;
            let user_domain = user.domain.clone();
            {
                let mut state = self.inner.write().await;
                state.users.push(user);
            }
            // A new user in a domain unblocks AS-REP roasting for that domain:
            // the first auto_credential_access tick may have fired against the
            // domain with no usernames in state (cross-forest target where
            // anonymous SAMR is denied) and dedup'd; clearing the dedup lets
            // the next tick re-dispatch with the now-known userlist. This is
            // the load-bearing path for compromising a SID-filtered foreign
            // forest where DCSync via the trust key won't work — AS-REP roast
            // of a vulnerable account is the only no-cred-needed entry point.
            if !user_domain.is_empty() {
                let mut state = self.inner.write().await;
                state.unmark_processed(super::super::DEDUP_ASREP_DOMAINS, &user_domain);
                drop(state);
                let _ = self
                    .unpersist_dedup(queue, super::super::DEDUP_ASREP_DOMAINS, &user_domain)
                    .await;
            }
        }
        Ok(added)
    }

    /// Add a vulnerability to state and Redis.
    ///
    /// If a `strategy` is provided, its technique weights override the vuln's
    /// hardcoded priority before insertion into the exploitation ZSET.
    pub async fn publish_vulnerability(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        vuln: VulnerabilityInfo,
    ) -> Result<bool> {
        self.publish_vulnerability_with_strategy(queue, vuln, None)
            .await
    }

    /// Publish a vulnerability with optional strategy-based priority override.
    pub async fn publish_vulnerability_with_strategy(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        mut vuln: VulnerabilityInfo,
        strategy: Option<&crate::orchestrator::strategy::Strategy>,
    ) -> Result<bool> {
        if should_drop_ghost_acl_vulnerability(&vuln) {
            tracing::debug!(
                vuln_id = %vuln.vuln_id,
                vuln_type = %vuln.vuln_type,
                target = %vuln.target,
                "Dropping ghost-machine ACL vulnerability"
            );
            return Ok(false);
        }

        // Apply strategy weight override if provided
        if let Some(strategy_cfg) = strategy {
            let effective = strategy_cfg.effective_priority(&vuln.vuln_type);
            if effective != vuln.priority {
                tracing::debug!(
                    vuln_type = %vuln.vuln_type,
                    original = vuln.priority,
                    effective = effective,
                    "Strategy override applied to vuln priority"
                );
                vuln.priority = effective;
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_vulnerability(&mut conn, &vuln).await?;
        if added {
            emit_op_state(
                self.recorder(),
                &operation_id,
                OpStateEventPayload::VulnDiscovered { vuln: vuln.clone() },
            )
            .await;

            // Also add to vuln queue ZSET for exploitation workflow
            let vuln_queue_key =
                format!("{}:{}:{}", state::KEY_PREFIX, operation_id, KEY_VULN_QUEUE);
            let vuln_json = serde_json::to_string(&vuln).unwrap_or_default();
            let score = vuln.priority as f64;
            let _: () = conn
                .zadd(&vuln_queue_key, &vuln_json, score)
                .await
                .unwrap_or(());
            let _: () = conn.expire(&vuln_queue_key, 86400).await.unwrap_or(());

            let mut state = self.inner.write().await;
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        Ok(added)
    }

    /// Add a share to state and Redis (with dedup).
    pub async fn publish_share(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        share: Share,
    ) -> Result<bool> {
        // Check for duplicate in memory
        {
            let state = self.inner.read().await;
            if state.shares.iter().any(|s| {
                s.host.to_lowercase() == share.host.to_lowercase()
                    && s.name.to_lowercase() == share.name.to_lowercase()
            }) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_share(&mut conn, &share).await?;
        if added {
            let mut state = self.inner.write().await;
            state.shares.push(share);
        }
        Ok(added)
    }

    /// Persist a timeline event to Redis and add MITRE techniques.
    pub async fn persist_timeline_event(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        event: &serde_json::Value,
        mitre_techniques: &[String],
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();

        reader.add_timeline_event(&mut conn, event).await?;

        for technique in mitre_techniques {
            let _ = reader.add_technique(&mut conn, technique).await;
        }

        emit_op_state(
            self.recorder(),
            &operation_id,
            OpStateEventPayload::TimelineEvent {
                event: event.clone(),
            },
        )
        .await;

        Ok(())
    }

    /// Record a pending task in memory and persist to Redis HASH.
    ///
    /// Key: `ares:op:{id}:pending_tasks`.
    pub async fn track_pending_task(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        task: ares_core::models::TaskInfo,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let task_id = task.task_id.clone();
        let json = serde_json::to_string(&task).unwrap_or_default();

        // Persist to Redis
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS,
        );
        let mut conn = queue.connection();
        let _: Result<(), _> = redis::AsyncCommands::hset(&mut conn, &key, &task_id, &json).await;
        let _: Result<(), _> = redis::AsyncCommands::expire(&mut conn, &key, 86400i64).await;

        // Update in-memory state
        let mut state = self.inner.write().await;
        state.pending_tasks.insert(task_id, task);
        Ok(())
    }

    /// Move a task from pending to completed, persisting both changes to Redis.
    ///
    /// Keys: `ares:op:{id}:pending_tasks`, `ares:op:{id}:completed_tasks`
    pub async fn complete_task(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        task_id: &str,
        result: ares_core::models::TaskResult,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let result_json = serde_json::to_string(&result).unwrap_or_default();

        let pending_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS,
        );
        let completed_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_COMPLETED_TASKS,
        );

        let mut conn = queue.connection();
        // Remove from pending, add to completed
        let _: Result<(), _> = redis::AsyncCommands::hdel(&mut conn, &pending_key, task_id).await;
        let _: Result<(), _> =
            redis::AsyncCommands::hset(&mut conn, &completed_key, task_id, &result_json).await;
        let _: Result<(), _> =
            redis::AsyncCommands::expire(&mut conn, &completed_key, 86400i64).await;

        // Update in-memory state
        let mut state = self.inner.write().await;
        state.pending_tasks.remove(task_id);
        state.completed_tasks.insert(task_id.to_string(), result);
        Ok(())
    }

    /// Persist a NetBIOS to FQDN mapping to Redis HASH.
    ///
    /// Key: `ares:op:{id}:netbios_map` HASH.
    pub async fn publish_netbios(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        netbios: &str,
        fqdn: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_NETBIOS_MAP,
        );
        let mut conn = queue.connection();
        let _: () = redis::AsyncCommands::hset(&mut conn, &key, netbios, fqdn).await?;
        let _: () = redis::AsyncCommands::expire(&mut conn, &key, 86400i64).await?;

        let mut state = self.inner.write().await;
        state
            .netbios_to_fqdn
            .insert(netbios.to_string(), fqdn.to_string());
        Ok(())
    }

    /// Add a trust relationship to state and Redis.
    ///
    /// Also publishes the trust target as an authoritative candidate domain.
    /// Trust enumeration is the only path that surfaces a foreign forest's
    /// FQDN before any of its hosts are scanned. Without this, downstream
    /// per-domain automations (AS-REP roast, SID enum, cross-forest forge)
    /// that iterate `state.domains` would never see the foreign forest until
    /// host discovery catches up — which on hardened/segmented networks may
    /// never happen. Trust enumeration is `AuthenticatedAd` evidence, which
    /// is authoritative on its own and promotes immediately.
    pub async fn publish_trust_info(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        trust: ares_core::models::TrustInfo,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_trusted_domain(&mut conn, &trust).await?;
        if added {
            let domain_key = trust.domain.to_lowercase();
            // Capture the SID *before* moving `trust` into the map. Upserting
            // domain_sids from trust-enum data is the load-bearing step that
            // lets `auto_trust_follow` pass its parent-SID gate on hardened
            // 2019+ parent DCs where the post-hoc SAMR / null-session lsaquery
            // fallbacks (in `golden_ticket::resolve_domain_sid`) are blocked.
            let trust_sid = trust.security_identifier.clone();
            {
                let mut state = self.inner.write().await;
                state.trusted_domains.insert(domain_key.clone(), trust);
                if let Some(ref sid) = trust_sid {
                    state.domain_sids.insert(domain_key.clone(), sid.clone());
                }
            }
            if let Some(sid) = trust_sid {
                // Persist to redis so a replayed/reloaded operation inherits
                // the SID — mirrors the persistence path used after a SAMR
                // lookup succeeds in resolve_domain_sid.
                let mut conn2 = queue.connection();
                let _ = reader.set_domain_sid(&mut conn2, &domain_key, &sid).await;
            }
            // Also promote the foreign domain into state.domains so the
            // per-domain automations pick it up.
            if let Err(e) = self
                .publish_candidate_domain(
                    queue,
                    &domain_key,
                    ares_core::models::DomainEvidence::AuthenticatedAd,
                    None,
                )
                .await
            {
                tracing::warn!(
                    domain = %domain_key,
                    err = %e,
                    "Failed to promote trust target domain into state.domains"
                );
            }
        }
        Ok(added)
    }
}

/// Check if two domains share a forest (one is a subdomain of the other).
///
/// e.g. `child.contoso.local` and `contoso.local` are in the same forest.
/// This catches parent/child domain relationships without requiring an
/// explicit trust entry.
fn are_in_same_forest(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

fn should_drop_ghost_acl_vulnerability(vuln: &VulnerabilityInfo) -> bool {
    if !is_acl_style_vulnerability(&vuln.vuln_type) {
        return false;
    }

    ghost_machine_target(vuln)
}

fn is_acl_style_vulnerability(vuln_type: &str) -> bool {
    let vtype = vuln_type.trim().to_lowercase();
    matches!(
        vtype.as_str(),
        "genericall"
            | "genericwrite"
            | "writedacl"
            | "writeowner"
            | "writeproperty"
            | "allextendedrights"
            | "self_membership"
            | "write_membership"
            | "genericall_computer"
            | "genericwrite_computer"
    ) || vtype.contains("forcechangepassword")
}

fn ghost_machine_target(vuln: &VulnerabilityInfo) -> bool {
    if is_ghost_machine_account(&vuln.target) {
        return true;
    }

    ["target", "target_computer", "target_account"]
        .into_iter()
        .filter_map(|key| vuln.details.get(key).and_then(|v| v.as_str()))
        .any(is_ghost_machine_account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::models::{TaskInfo, TrustInfo, VulnerabilityInfo};
    use ares_core::state::mock_redis::MockRedisConnection;
    use chrono::Utc;
    use std::collections::HashMap;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    fn make_user(username: &str, domain: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: "test".to_string(),
        }
    }

    fn make_vuln(vuln_id: &str, vuln_type: &str, target: &str) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: target.to_string(),
            discovered_by: "test".to_string(),
            discovered_at: Utc::now(),
            details: HashMap::new(),
            recommended_agent: "exploit".to_string(),
            priority: 50,
        }
    }

    fn make_vuln_with_details(
        vuln_id: &str,
        vuln_type: &str,
        target: &str,
        details: HashMap<String, serde_json::Value>,
    ) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: target.to_string(),
            discovered_by: "test".to_string(),
            discovered_at: Utc::now(),
            details,
            recommended_agent: "exploit".to_string(),
            priority: 50,
        }
    }

    fn make_share(host: &str, name: &str) -> Share {
        Share {
            host: host.to_string(),
            name: name.to_string(),
            permissions: "READ".to_string(),
            comment: String::new(),
            authenticated_as: None,
        }
    }

    fn make_task_info(task_id: &str, task_type: &str) -> TaskInfo {
        TaskInfo {
            task_id: task_id.to_string(),
            task_type: task_type.to_string(),
            assigned_agent: "recon".to_string(),
            status: ares_core::models::TaskStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            last_activity_at: Utc::now(),
            params: HashMap::new(),
            result: None,
            error: None,
            retry_count: 0,
            max_retries: 3,
        }
    }

    fn make_trust(domain: &str) -> TrustInfo {
        TrustInfo {
            domain: domain.to_string(),
            flat_name: String::new(),
            direction: "bidirectional".to_string(),
            trust_type: "forest".to_string(),
            sid_filtering: false,
            security_identifier: None,
        }
    }

    #[tokio::test]
    async fn publish_user_adds_to_state() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let user = make_user("alice", "contoso.local");
        let added = state.publish_user(&q, user).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.users.len(), 1);
        assert_eq!(s.users[0].username, "alice");
        assert_eq!(s.users[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn publish_user_dedup_exact() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let user1 = make_user("alice", "contoso.local");
        let user2 = make_user("alice", "contoso.local");
        assert!(state.publish_user(&q, user1).await.unwrap());
        assert!(!state.publish_user(&q, user2).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.users.len(), 1);
    }

    #[tokio::test]
    async fn publish_user_dedup_cross_domain_with_trust() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Establish trust between contoso.local and fabrikam.local
        let trust = make_trust("fabrikam.local");
        state.publish_trust_info(&q, trust).await.unwrap();

        // Add user in contoso.local
        let user1 = make_user("alice", "contoso.local");
        assert!(state.publish_user(&q, user1).await.unwrap());

        // Same username in trusted domain should be deduped
        let user2 = make_user("alice", "fabrikam.local");
        assert!(!state.publish_user(&q, user2).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.users.len(), 1);
    }

    #[tokio::test]
    async fn publish_user_different_domains_no_trust() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // No trust established — same username in different domains should both be added
        let user1 = make_user("alice", "contoso.local");
        let user2 = make_user("alice", "fabrikam.local");
        assert!(state.publish_user(&q, user1).await.unwrap());
        assert!(state.publish_user(&q, user2).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.users.len(), 2);
    }

    #[tokio::test]
    async fn publish_vulnerability_adds_to_state() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let vuln = make_vuln("VULN-001", "smb_signing", "192.168.58.1");
        let added = state.publish_vulnerability(&q, vuln).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert!(s.discovered_vulnerabilities.contains_key("VULN-001"));
        let v = &s.discovered_vulnerabilities["VULN-001"];
        assert_eq!(v.vuln_type, "smb_signing");
        assert_eq!(v.target, "192.168.58.1");
    }

    #[tokio::test]
    async fn publish_vulnerability_dedup() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let vuln1 = make_vuln("VULN-001", "smb_signing", "192.168.58.1");
        let vuln2 = make_vuln("VULN-001", "smb_signing", "192.168.58.1");
        assert!(state.publish_vulnerability(&q, vuln1).await.unwrap());
        assert!(!state.publish_vulnerability(&q, vuln2).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.discovered_vulnerabilities.len(), 1);
    }

    #[tokio::test]
    async fn publish_vulnerability_rejects_ghost_acl_target() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let vuln = make_vuln("VULN-ACL-001", "allextendedrights", "WIN-DPPJMLU3XS6$");
        let added = state.publish_vulnerability(&q, vuln).await.unwrap();
        assert!(!added);

        let s = state.inner.read().await;
        assert!(s.discovered_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn publish_vulnerability_rejects_ghost_acl_target_in_details() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let mut details = HashMap::new();
        details.insert("target".to_string(), serde_json::json!("WIN-DPPJMLU3XS6$"));
        let vuln = make_vuln_with_details("VULN-ACL-002", "genericall", "placeholder", details);
        let added = state.publish_vulnerability(&q, vuln).await.unwrap();
        assert!(!added);

        let s = state.inner.read().await;
        assert!(s.discovered_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn publish_vulnerability_keeps_real_acl_machine_target() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let vuln = make_vuln("VULN-ACL-003", "genericall", "DC01$");
        let added = state.publish_vulnerability(&q, vuln).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert!(s.discovered_vulnerabilities.contains_key("VULN-ACL-003"));
    }

    #[tokio::test]
    async fn publish_share_adds_to_state() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let share = make_share("192.168.58.1", "ADMIN$");
        let added = state.publish_share(&q, share).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.shares.len(), 1);
        assert_eq!(s.shares[0].host, "192.168.58.1");
        assert_eq!(s.shares[0].name, "ADMIN$");
    }

    #[tokio::test]
    async fn publish_share_dedup() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let share1 = make_share("192.168.58.1", "ADMIN$");
        let share2 = make_share("192.168.58.1", "ADMIN$");
        assert!(state.publish_share(&q, share1).await.unwrap());
        assert!(!state.publish_share(&q, share2).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.shares.len(), 1);
    }

    #[tokio::test]
    async fn persist_timeline_event_stores_event() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let event = serde_json::json!({
            "timestamp": "2025-01-01T00:00:00Z",
            "description": "Discovered open SMB port",
        });
        let techniques = vec!["T1049".to_string(), "T1018".to_string()];

        state
            .persist_timeline_event(&q, &event, &techniques)
            .await
            .unwrap();

        // Verify the timeline event was stored in Redis
        let mut conn = q.connection();
        let timeline_key = "ares:op:op-1:timeline".to_string();
        let events: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &timeline_key, 0, -1)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        let stored: serde_json::Value = serde_json::from_str(&events[0]).unwrap();
        assert_eq!(stored["description"], "Discovered open SMB port");

        // Verify techniques were stored
        let tech_key = "ares:op:op-1:techniques".to_string();
        let techs: Vec<String> = redis::AsyncCommands::smembers(&mut conn, &tech_key)
            .await
            .unwrap();
        assert_eq!(techs.len(), 2);
        assert!(techs.contains(&"T1049".to_string()));
        assert!(techs.contains(&"T1018".to_string()));
    }

    #[tokio::test]
    async fn track_pending_task_and_complete() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let task = make_task_info("task-42", "recon");
        state.track_pending_task(&q, task).await.unwrap();

        // Verify task is in pending
        {
            let s = state.inner.read().await;
            assert!(s.pending_tasks.contains_key("task-42"));
            assert!(s.completed_tasks.is_empty());
        }

        // Complete the task
        let result = ares_core::models::TaskResult {
            task_id: "task-42".to_string(),
            success: true,
            result: Some(serde_json::json!({"output": "NT AUTHORITY\\SYSTEM"})),
            error: None,
            worker_pod: None,
            completed_at: Utc::now(),
        };
        state.complete_task(&q, "task-42", result).await.unwrap();

        // Verify task moved from pending to completed
        let s = state.inner.read().await;
        assert!(!s.pending_tasks.contains_key("task-42"));
        assert!(s.completed_tasks.contains_key("task-42"));
        assert!(s.completed_tasks["task-42"].success);
    }

    #[tokio::test]
    async fn publish_netbios_stores_mapping() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .publish_netbios(&q, "CONTOSO", "contoso.local")
            .await
            .unwrap();

        let s = state.inner.read().await;
        assert_eq!(
            s.netbios_to_fqdn.get("CONTOSO"),
            Some(&"contoso.local".to_string())
        );

        // Also verify it was persisted to Redis
        let mut conn = q.connection();
        let key = "ares:op:op-1:netbios_map".to_string();
        let fqdn: String = redis::AsyncCommands::hget(&mut conn, &key, "CONTOSO")
            .await
            .unwrap();
        assert_eq!(fqdn, "contoso.local");
    }

    #[tokio::test]
    async fn publish_trust_info_adds_trust() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let trust = make_trust("fabrikam.local");
        let added = state.publish_trust_info(&q, trust).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert!(s.trusted_domains.contains_key("fabrikam.local"));
        let t = &s.trusted_domains["fabrikam.local"];
        assert_eq!(t.trust_type, "forest");
    }

    #[tokio::test]
    async fn publish_trust_info_upserts_domain_sid_when_carried() {
        // When the trust enum captured securityIdentifier, publish_trust_info
        // must mirror it into state.domain_sids so `auto_trust_follow` passes
        // its parent-SID gate without needing the SAMR/lsaquery fallbacks.
        // This is the load-bearing wiring for the child→parent forge path.
        let state = SharedState::new("op-sid".to_string());
        let q = mock_queue();

        let mut trust = make_trust("contoso.local");
        trust.security_identifier = Some("S-1-5-21-1111111111-2222222222-3333333333".into());
        let added = state.publish_trust_info(&q, trust).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(
            s.domain_sids.get("contoso.local").map(String::as_str),
            Some("S-1-5-21-1111111111-2222222222-3333333333"),
            "domain_sids must be populated from the trust's security_identifier"
        );
    }

    #[tokio::test]
    async fn publish_trust_info_no_sid_leaves_domain_sids_empty() {
        // Trust enum runs without securityIdentifier must not corrupt
        // domain_sids — `golden_ticket::resolve_domain_sid` fills it via SAMR/lsaquery.
        let state = SharedState::new("op-nosid".to_string());
        let q = mock_queue();

        let trust = make_trust("fabrikam.local");
        assert!(trust.security_identifier.is_none());
        let added = state.publish_trust_info(&q, trust).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert!(
            !s.domain_sids.contains_key("fabrikam.local"),
            "missing SID must NOT insert a domain_sids entry"
        );
    }

    #[test]
    fn same_domain_is_same_forest() {
        assert!(are_in_same_forest("contoso.local", "contoso.local"));
    }

    #[test]
    fn parent_child_is_same_forest() {
        assert!(are_in_same_forest("child.contoso.local", "contoso.local"));
        assert!(are_in_same_forest("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn unrelated_domains_not_same_forest() {
        assert!(!are_in_same_forest("contoso.local", "fabrikam.local"));
        assert!(!are_in_same_forest("child.contoso.local", "fabrikam.local"));
    }

    #[tokio::test]
    async fn publish_user_emits_event_with_capturing_recorder() {
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-u".to_string(), recorder.clone());
        let q = mock_queue();
        assert!(state
            .publish_user(&q, make_user("alice", "contoso.local"))
            .await
            .unwrap());

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        match &evs[0].payload {
            OpStateEventPayload::UserDiscovered { user } => {
                assert_eq!(user.username, "alice");
                assert_eq!(user.domain, "contoso.local");
            }
            other => panic!("expected UserDiscovered, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_user_dedup_does_not_emit_event() {
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-u-dup".to_string(), recorder.clone());
        let q = mock_queue();
        assert!(state
            .publish_user(&q, make_user("alice", "contoso.local"))
            .await
            .unwrap());
        assert!(!state
            .publish_user(&q, make_user("alice", "contoso.local"))
            .await
            .unwrap());
        assert_eq!(recorder.captured().await.len(), 1);
    }

    #[tokio::test]
    async fn publish_vulnerability_emits_event_with_capturing_recorder() {
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-v".to_string(), recorder.clone());
        let q = mock_queue();
        let vuln = make_vuln("VULN-001", "esc1", "192.168.58.10");
        assert!(state.publish_vulnerability(&q, vuln).await.unwrap());

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        match &evs[0].payload {
            OpStateEventPayload::VulnDiscovered { vuln } => {
                assert_eq!(vuln.vuln_id, "VULN-001");
                assert_eq!(vuln.vuln_type, "esc1");
            }
            other => panic!("expected VulnDiscovered, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn persist_timeline_event_emits_event_with_capturing_recorder() {
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-t".to_string(), recorder.clone());
        let q = mock_queue();
        let ev = serde_json::json!({"description": "smb 445 open"});
        state
            .persist_timeline_event(&q, &ev, &["T1135".to_string()])
            .await
            .unwrap();

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        match &evs[0].payload {
            OpStateEventPayload::TimelineEvent { event } => {
                assert_eq!(event["description"], "smb 445 open");
            }
            other => panic!("expected TimelineEvent, got {other:?}"),
        }
    }
}
