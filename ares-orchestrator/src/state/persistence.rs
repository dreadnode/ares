//! Redis persistence — load_from_redis & refresh_from_redis.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{debug, info};

use ares_core::state::{self, RedisStateReader};

use super::{SharedState, ALL_DEDUP_SETS, DEDUP_ACL_STEPS};
use crate::task_queue::TaskQueue;

impl SharedState {
    /// Load state from Redis (called at startup).
    pub async fn load_from_redis(&self, queue: &TaskQueue) -> Result<()> {
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

        let loaded = match loaded {
            Some(s) => s,
            None => {
                info!(operation_id = %operation_id, "No existing state in Redis — starting fresh");
                return Ok(());
            }
        };

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
        // Rebuild dominated_domains from krbtgt hashes
        state.dominated_domains = state
            .hashes
            .iter()
            .filter(|h| {
                h.username.to_lowercase() == "krbtgt" && h.hash_type.to_lowercase().contains("ntlm")
            })
            .map(|h| {
                if h.domain.is_empty() {
                    state.domains.first().cloned().unwrap_or_default()
                } else {
                    h.domain.to_lowercase()
                }
            })
            .filter(|d| !d.is_empty())
            .collect();
        state.has_domain_admin = loaded.has_domain_admin;
        state.has_golden_ticket = loaded.has_golden_ticket;
        state.domain_admin_path = loaded.domain_admin_path;
        state.dedup = dedup_sets;
        state.mssql_enum_dispatched = mssql_dispatched;
        state.acl_chains = acl_chains;
        state.dispatched_acl_steps = dispatched_acl_steps;
        state.pending_tasks = pending_tasks;
        state.completed_tasks = completed_tasks;

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

    /// Refresh state from Redis (periodic sync).
    pub async fn refresh_from_redis(&self, queue: &TaskQueue) -> Result<()> {
        let mut conn = queue.connection();
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());

        let credentials = reader.get_credentials(&mut conn).await.unwrap_or_default();
        let hashes = reader.get_hashes(&mut conn).await.unwrap_or_default();
        let hosts = reader.get_hosts(&mut conn).await.unwrap_or_default();
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

        let mut state = self.inner.write().await;
        state.credentials = credentials;
        state.hashes = hashes;
        state.hosts = hosts;
        state.discovered_vulnerabilities = vulns;
        state.exploited_vulnerabilities = exploited;
        state.has_domain_admin = meta.has_domain_admin;
        state.has_golden_ticket = meta.has_golden_ticket;
        state.domain_admin_path = meta.domain_admin_path;
        state.domain_controllers = dc_map;
        state.domain_sids = domain_sids;
        state.admin_names = admin_names;
        state.trusted_domains = trusted_domains;
        state.acl_chains = acl_chains;
        // Rebuild dominated_domains from refreshed hashes
        state.dominated_domains = state
            .hashes
            .iter()
            .filter(|h| {
                h.username.to_lowercase() == "krbtgt" && h.hash_type.to_lowercase().contains("ntlm")
            })
            .map(|h| {
                if h.domain.is_empty() {
                    state.domains.first().cloned().unwrap_or_default()
                } else {
                    h.domain.to_lowercase()
                }
            })
            .filter(|d| !d.is_empty())
            .collect();

        Ok(())
    }
}
