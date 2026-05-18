//! Redis persistence — load_from_redis & refresh_from_redis.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{debug, info};

use ares_core::models::CandidateDomain;
use ares_core::state::{self, RedisStateReader};

use redis::aio::ConnectionLike;

use super::{SharedState, ALL_DEDUP_SETS, DEDUP_ACL_STEPS, DEDUP_TRUST_FOLLOW};
use crate::orchestrator::task_queue::TaskQueueCore;

impl SharedState {
    /// Load state from Redis (called at startup).
    pub async fn load_from_redis(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
    ) -> Result<()> {
        let mut conn = queue.connection();
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };

        let reader = RedisStateReader::new(operation_id.clone());

        // Load collections
        let loaded = reader
            .load_state(&mut conn)
            .await
            .context("Failed to load state from Redis")?;

        let Some(loaded) = loaded else {
            info!(operation_id = %operation_id, "No existing state in Redis — starting fresh");
            return Ok(());
        };

        // Trust workflow dedups (`trust_follow:*` and `trust_extract:*` live in
        // the same set) gate "once per op execution" decisions — forge a Kerberos
        // ticket for a foreign realm, extract a trust key. They were 24h-TTL'd
        // and persisted across orchestrator restarts, which meant any code-change
        // requiring a re-fire had to be paired with a manual SREM. Clear them on
        // load so a restart re-runs the trust path against the latest code.
        let trust_follow_key = format!(
            "{}:{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DEDUP_PREFIX,
            DEDUP_TRUST_FOLLOW
        );
        let prior_members: HashSet<String> =
            conn.smembers(&trust_follow_key).await.unwrap_or_default();
        if !prior_members.is_empty() {
            let _: redis::RedisResult<i64> = conn.del(&trust_follow_key).await;
            info!(
                cleared = prior_members.len(),
                "Cleared trust_follow dedup on op load — trust workflow will re-fire"
            );
        }

        // Load dedup sets
        let mut dedup_sets: HashMap<String, HashSet<String>> = HashMap::new();
        for set_name in ALL_DEDUP_SETS {
            let key = format!(
                "{}:{}:{}:{}",
                state::KEY_PREFIX,
                operation_id,
                state::KEY_DEDUP_PREFIX,
                set_name
            );
            let members: HashSet<String> = conn.smembers(&key).await.unwrap_or_default();
            if !members.is_empty() {
                debug!(set = set_name, count = members.len(), "Loaded dedup set");
            }
            dedup_sets.insert(set_name.to_string(), members);
        }

        // Load MSSQL enum dispatched
        let mssql_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_MSSQL_ENUM_DISPATCHED
        );
        let mssql_dispatched: HashSet<String> = conn.smembers(&mssql_key).await.unwrap_or_default();

        // Load domain SIDs
        let domain_sids_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DOMAIN_SIDS
        );
        let domain_sids: HashMap<String, String> =
            conn.hgetall(&domain_sids_key).await.unwrap_or_default();

        // Load RID-500 admin account names
        let admin_names_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_ADMIN_NAMES
        );
        let admin_names: HashMap<String, String> =
            conn.hgetall(&admin_names_key).await.unwrap_or_default();

        // Load trusted domains
        let trusted_domains_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_TRUSTED_DOMAINS
        );
        let raw_trusts: HashMap<String, String> =
            conn.hgetall(&trusted_domains_key).await.unwrap_or_default();
        let mut trusted_domains = HashMap::new();
        for (domain, json_str) in &raw_trusts {
            if let Ok(trust) = serde_json::from_str::<ares_core::models::TrustInfo>(json_str) {
                trusted_domains.insert(domain.clone(), trust);
            }
        }

        let candidate_domains_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_CANDIDATE_DOMAINS
        );
        let raw_candidates: HashMap<String, String> = conn
            .hgetall(&candidate_domains_key)
            .await
            .unwrap_or_default();
        let mut candidate_domains = HashMap::new();
        for (fqdn, json_str) in &raw_candidates {
            if let Ok(candidate) = serde_json::from_str::<CandidateDomain>(json_str) {
                candidate_domains.insert(fqdn.clone(), candidate);
            }
        }

        // Load ACL chains
        let acl_chains_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_ACL_CHAINS
        );
        let acl_chains_raw: Vec<String> = conn
            .lrange(&acl_chains_key, 0, -1)
            .await
            .unwrap_or_default();
        let acl_chains: Vec<serde_json::Value> = acl_chains_raw
            .iter()
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect();

        // Load pending tasks from Redis HASH
        let pending_tasks_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS
        );
        let raw_pending: std::collections::HashMap<String, String> =
            conn.hgetall(&pending_tasks_key).await.unwrap_or_default();
        let mut pending_tasks = std::collections::HashMap::new();
        for (task_id, json_str) in &raw_pending {
            if let Ok(task_info) = serde_json::from_str::<ares_core::models::TaskInfo>(json_str) {
                pending_tasks.insert(task_id.clone(), task_info);
            }
        }

        // Load completed tasks from Redis HASH
        let completed_tasks_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_COMPLETED_TASKS
        );
        let raw_completed: std::collections::HashMap<String, String> =
            conn.hgetall(&completed_tasks_key).await.unwrap_or_default();
        let mut completed_tasks = std::collections::HashMap::new();
        for (task_id, json_str) in &raw_completed {
            if let Ok(task_result) = serde_json::from_str::<ares_core::models::TaskResult>(json_str)
            {
                completed_tasks.insert(task_id.clone(), task_result);
            }
        }

        // Load dispatched ACL steps from dedup set
        let acl_dedup_key = format!(
            "{}:{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DEDUP_PREFIX,
            DEDUP_ACL_STEPS
        );
        let dispatched_acl_steps: HashSet<String> =
            conn.smembers(&acl_dedup_key).await.unwrap_or_default();

        // Load forged Kerberos tickets
        let kerberos_tickets_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_KERBEROS_TICKETS
        );
        let raw_tickets: HashMap<String, String> = conn
            .hgetall(&kerberos_tickets_key)
            .await
            .unwrap_or_default();
        let kerberos_tickets: Vec<ares_core::models::KerberosTicket> = raw_tickets
            .into_values()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();

        // Apply to state
        let mut state = self.inner.write().await;
        state.target = loaded.target;
        state.target_ips = loaded.target_ips;
        state.credentials = loaded.all_credentials;
        state.hashes = loaded.all_hashes;
        state.hosts = loaded.all_hosts;
        state.users = loaded.all_users;
        state.shares = loaded.all_shares;
        state.domains = loaded.all_domains;
        state.discovered_vulnerabilities = loaded.discovered_vulnerabilities;
        state.exploited_vulnerabilities = loaded.exploited_vulnerabilities;
        state.domain_controllers = loaded.domain_controllers;
        state.netbios_to_fqdn = loaded.netbios_to_fqdn;
        state.domain_sids = domain_sids;
        state.admin_names = admin_names;
        state.trusted_domains = trusted_domains;
        state.candidate_domains = candidate_domains;
        // Rebuild dominated_domains from krbtgt hashes
        state.dominated_domains = state
            .hashes
            .iter()
            .filter(|h| {
                h.username.to_lowercase() == "krbtgt" && h.hash_type.to_lowercase().contains("ntlm")
            })
            .map(|h| {
                if h.domain.is_empty() {
                    // Resolve from sibling hashes (same parent_id / secretsdump run)
                    h.parent_id
                        .as_deref()
                        .and_then(|pid| {
                            state.hashes.iter().find_map(|other| {
                                if other.parent_id.as_deref() == Some(pid)
                                    && !other.domain.is_empty()
                                {
                                    Some(other.domain.to_lowercase())
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or_default()
                } else {
                    h.domain.to_lowercase()
                }
            })
            .filter(|d| !d.is_empty())
            .collect();
        // Mirror rebuilt set to Redis so post-mortem `SCARD` stays consistent
        // after orchestrator restart. Source of truth remains the krbtgt
        // hashes; this is purely a visibility mirror.
        let dominated_snapshot: Vec<String> = state.dominated_domains.iter().cloned().collect();
        if !dominated_snapshot.is_empty() {
            let dominated_key = format!(
                "{}:{}:{}",
                state::KEY_PREFIX,
                operation_id,
                state::KEY_DOMINATED_DOMAINS
            );
            for d in &dominated_snapshot {
                let _: redis::RedisResult<i64> = conn.sadd(&dominated_key, d).await;
            }
            let _: redis::RedisResult<i64> = conn.expire(&dominated_key, 86400).await;
        }
        state.has_domain_admin = loaded.has_domain_admin;
        state.has_golden_ticket = loaded.has_golden_ticket;
        state.domain_admin_path = loaded.domain_admin_path;
        state.dedup = dedup_sets;
        state.mssql_enum_dispatched = mssql_dispatched;
        state.acl_chains = acl_chains;
        state.dispatched_acl_steps = dispatched_acl_steps;
        state.pending_tasks = pending_tasks;
        state.completed_tasks = completed_tasks;
        state.kerberos_tickets = kerberos_tickets;

        let cred_count = state.credentials.len();
        let hash_count = state.hashes.len();
        let host_count = state.hosts.len();
        let vuln_count = state.discovered_vulnerabilities.len();
        drop(state);

        info!(
            operation_id = %operation_id,
            credentials = cred_count,
            hashes = hash_count,
            hosts = host_count,
            vulnerabilities = vuln_count,
            "State loaded from Redis"
        );

        Ok(())
    }

    /// Refresh state from Redis (periodic sync — merges remote data into local state).
    pub async fn refresh_from_redis(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
    ) -> Result<()> {
        let mut conn = queue.connection();
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());

        let credentials = reader.get_credentials(&mut conn).await.unwrap_or_default();
        let hashes = reader.get_hashes(&mut conn).await.unwrap_or_default();
        let hosts = reader.get_hosts(&mut conn).await.unwrap_or_default();
        let domains = reader.get_domains(&mut conn).await.unwrap_or_default();
        let vulns = reader
            .get_vulnerabilities(&mut conn)
            .await
            .unwrap_or_default();
        let exploited = reader
            .get_exploited_vulnerabilities(&mut conn)
            .await
            .unwrap_or_default();
        let meta = reader.get_meta(&mut conn).await.unwrap_or_default();
        let dc_map = reader.get_dc_map(&mut conn).await.unwrap_or_default();

        // Load domain SIDs
        let domain_sids_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DOMAIN_SIDS
        );
        let domain_sids: HashMap<String, String> =
            conn.hgetall(&domain_sids_key).await.unwrap_or_default();

        // Load RID-500 admin account names
        let admin_names_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_ADMIN_NAMES
        );
        let admin_names: HashMap<String, String> =
            conn.hgetall(&admin_names_key).await.unwrap_or_default();

        // Refresh ACL chains
        let acl_chains_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_ACL_CHAINS
        );
        let acl_chains_raw: Vec<String> = conn
            .lrange(&acl_chains_key, 0, -1)
            .await
            .unwrap_or_default();
        let acl_chains: Vec<serde_json::Value> = acl_chains_raw
            .iter()
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect();

        // Refresh trusted domains
        let trusted_domains_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_TRUSTED_DOMAINS
        );
        let raw_trusts: HashMap<String, String> =
            conn.hgetall(&trusted_domains_key).await.unwrap_or_default();
        let mut trusted_domains = HashMap::new();
        for (domain, json_str) in &raw_trusts {
            if let Ok(trust) = serde_json::from_str::<ares_core::models::TrustInfo>(json_str) {
                trusted_domains.insert(domain.clone(), trust);
            }
        }

        let candidate_domains_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_CANDIDATE_DOMAINS
        );
        let raw_candidates: HashMap<String, String> = conn
            .hgetall(&candidate_domains_key)
            .await
            .unwrap_or_default();
        let mut candidate_domains = HashMap::new();
        for (fqdn, json_str) in &raw_candidates {
            if let Ok(candidate) = serde_json::from_str::<CandidateDomain>(json_str) {
                candidate_domains.insert(fqdn.clone(), candidate);
            }
        }

        // Refresh Kerberos tickets
        let kerberos_tickets_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_KERBEROS_TICKETS
        );
        let raw_tickets: HashMap<String, String> = conn
            .hgetall(&kerberos_tickets_key)
            .await
            .unwrap_or_default();
        let kerberos_tickets: Vec<ares_core::models::KerberosTicket> = raw_tickets
            .into_values()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();

        let mut state = self.inner.write().await;
        state.credentials = credentials;
        state.hashes = hashes;
        state.hosts = hosts;
        state.domains = domains;
        state.discovered_vulnerabilities = vulns;
        state.exploited_vulnerabilities = exploited;
        state.has_domain_admin = meta.has_domain_admin;
        state.has_golden_ticket = meta.has_golden_ticket;
        state.domain_admin_path = meta.domain_admin_path;
        state.domain_controllers = dc_map;
        state.domain_sids = domain_sids;
        state.admin_names = admin_names;
        state.trusted_domains = trusted_domains;
        state.candidate_domains = candidate_domains;
        state.acl_chains = acl_chains;
        state.kerberos_tickets = kerberos_tickets;
        // Rebuild dominated_domains from refreshed hashes
        state.dominated_domains = state
            .hashes
            .iter()
            .filter(|h| {
                h.username.to_lowercase() == "krbtgt" && h.hash_type.to_lowercase().contains("ntlm")
            })
            .map(|h| {
                if h.domain.is_empty() {
                    // Resolve from sibling hashes (same parent_id / secretsdump run)
                    h.parent_id
                        .as_deref()
                        .and_then(|pid| {
                            state.hashes.iter().find_map(|other| {
                                if other.parent_id.as_deref() == Some(pid)
                                    && !other.domain.is_empty()
                                {
                                    Some(other.domain.to_lowercase())
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or_default()
                } else {
                    h.domain.to_lowercase()
                }
            })
            .filter(|d| !d.is_empty())
            .collect();

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
    async fn load_from_redis_empty_state() {
        let state = SharedState::new("op-fresh".to_string());
        let q = mock_queue();

        // No data in Redis — should succeed and leave state empty
        state.load_from_redis(&q).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.credentials.is_empty());
        assert!(s.hashes.is_empty());
        assert!(s.hosts.is_empty());
        assert!(!s.has_domain_admin);
        assert!(!s.has_golden_ticket);
    }

    /// Helper to seed the meta key so `exists()` returns true for `load_from_redis`.
    async fn seed_meta(q: &TaskQueueCore<MockRedisConnection>, op_id: &str) {
        let reader = RedisStateReader::new(op_id.to_string());
        let mut conn = q.connection();
        reader
            .set_meta_field(&mut conn, "target_ip", &serde_json::json!("192.168.58.1"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn load_from_redis_with_seeded_data() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Seed meta so exists() returns true, then publish data
        seed_meta(&q, "op-1").await;

        // Publish a DC host so the suffix is promoted authoritatively
        // (non-DC FQDN suffixes are now held as candidates, not domains).
        let host = ares_core::models::Host {
            ip: "192.168.58.5".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec!["445/tcp".to_string()],
            is_dc: true,
            owned: false,
        };
        state.publish_host(&q, host).await.unwrap();

        let cred = ares_core::models::Credential {
            id: "cred-1".to_string(),
            username: "admin".to_string(),
            password: "P@ssw0rd".to_string(),
            domain: "contoso.local".to_string(),
            source: "test".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        state.publish_credential(&q, cred).await.unwrap();

        // Now create a fresh state and load from the same Redis
        let state2 = SharedState::new("op-1".to_string());
        state2.load_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].ip, "192.168.58.5");
        assert_eq!(s.credentials.len(), 1);
        assert_eq!(s.credentials[0].username, "admin");
        assert!(s.domains.contains(&"contoso.local".to_string()));
    }

    #[tokio::test]
    async fn load_from_redis_restores_dedup_sets() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        seed_meta(&q, "op-1").await;

        // Persist a dedup entry
        state
            .persist_dedup(&q, "crack_requests", "hash123")
            .await
            .unwrap();

        // Load into fresh state
        let state2 = SharedState::new("op-1".to_string());
        state2.load_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        assert!(s.dedup["crack_requests"].contains("hash123"));
    }

    #[tokio::test]
    async fn load_from_redis_clears_trust_follow_dedup() {
        // trust_follow / trust_extract dedups are "once per op execution"
        // decisions. Persisting them across orchestrator restarts blocks
        // re-firing the trust workflow after a code change. Confirm load
        // clears the set so the workflow runs again on the next tick.
        let state = SharedState::new("op-trust".to_string());
        let q = mock_queue();
        seed_meta(&q, "op-trust").await;

        // Other dedup sets must NOT be cleared — only trust_follow.
        state
            .persist_dedup(&q, "trust_follow", "trust_follow:foreign.local:foreign$")
            .await
            .unwrap();
        state
            .persist_dedup(&q, "trust_follow", "trust_extract:foreign.local")
            .await
            .unwrap();
        state
            .persist_dedup(&q, "crack_requests", "hash-stays")
            .await
            .unwrap();

        let state2 = SharedState::new("op-trust".to_string());
        state2.load_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        assert!(
            s.dedup
                .get("trust_follow")
                .map(|set| set.is_empty())
                .unwrap_or(true),
            "trust_follow dedup should be cleared on op load"
        );
        // Sibling dedup must survive — only trust_follow gets reset.
        assert!(s.dedup["crack_requests"].contains("hash-stays"));

        // And the Redis-side set should be deleted too, not just the
        // in-memory copy, otherwise SADD-NX checks would still see prior keys.
        let mut conn = q.connection();
        let live: HashSet<String> = conn
            .smembers("ares:op:op-trust:dedup:trust_follow")
            .await
            .unwrap();
        assert!(live.is_empty(), "Redis trust_follow set must be empty");
    }

    #[tokio::test]
    async fn load_from_redis_restores_candidate_domains() {
        let state = SharedState::new("op-candidates".to_string());
        let q = mock_queue();

        seed_meta(&q, "op-candidates").await;
        state
            .publish_candidate_domain(
                &q,
                "transient.contoso.local",
                ares_core::models::DomainEvidence::HostnameInference,
                Some("192.168.58.50".to_string()),
            )
            .await
            .unwrap();
        state
            .mark_candidate_probed(&q, "transient.contoso.local")
            .await
            .unwrap();

        let state2 = SharedState::new("op-candidates".to_string());
        state2.load_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        let candidate = s.candidate_domains.get("transient.contoso.local").unwrap();
        assert!(candidate.probed);
        assert_eq!(candidate.source_host_ip.as_deref(), Some("192.168.58.50"));
    }

    #[tokio::test]
    async fn refresh_from_redis_updates_state() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Seed a host via publishing
        let host = ares_core::models::Host {
            ip: "192.168.58.5".to_string(),
            hostname: "srv01.contoso.local".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        };
        state.publish_host(&q, host).await.unwrap();

        // Create a second state that shares the Redis connection but is empty
        let state2 = SharedState::new("op-1".to_string());
        assert!(state2.inner.read().await.hosts.is_empty());

        // Refresh should pull data from Redis
        state2.refresh_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].ip, "192.168.58.5");
    }

    #[tokio::test]
    async fn load_from_redis_restores_milestones() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        seed_meta(&q, "op-1").await;

        // Set milestones
        state.set_golden_ticket(&q, "contoso.local").await.unwrap();
        state
            .set_domain_admin(&q, Some("attack chain".to_string()))
            .await
            .unwrap();

        // Load into fresh state
        let state2 = SharedState::new("op-1".to_string());
        state2.load_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        assert!(s.has_golden_ticket);
        assert!(s.has_domain_admin);
        assert_eq!(s.domain_admin_path.as_deref(), Some("attack chain"));
    }

    #[tokio::test]
    async fn load_from_redis_restores_pending_tasks() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        seed_meta(&q, "op-1").await;

        let task = ares_core::models::TaskInfo {
            task_id: "task-99".to_string(),
            task_type: "recon".to_string(),
            assigned_agent: "scanner".to_string(),
            status: ares_core::models::TaskStatus::Pending,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            last_activity_at: chrono::Utc::now(),
            params: std::collections::HashMap::new(),
            result: None,
            error: None,
            retry_count: 0,
            max_retries: 3,
        };
        state.track_pending_task(&q, task).await.unwrap();

        let state2 = SharedState::new("op-1".to_string());
        state2.load_from_redis(&q).await.unwrap();

        let s = state2.inner.read().await;
        assert!(s.pending_tasks.contains_key("task-99"));
    }
}
