//! In-memory shared state synced with Redis.
//!
//! `SharedState` wraps the operation state in `Arc<RwLock<...>>` so that all
//! background automation tasks can read state concurrently, and writes
//! (credential publishing, result processing) are serialized.
//!
//! State is loaded from Redis at startup and updated incrementally as results
//! arrive. Dedup sets are persisted to Redis so they survive orchestrator restarts.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tokio::sync::RwLock;
use tracing::{debug, info};

use ares_core::models::*;
use ares_core::state::{self, RedisStateReader};

use crate::task_queue::TaskQueue;

// ---------------------------------------------------------------------------
// Dedup set names (match Python `ares:op:{op_id}:dedup:{name}`)
// ---------------------------------------------------------------------------

pub const DEDUP_CRACK_REQUESTS: &str = "crack_requests";
pub const DEDUP_SECRETSDUMP: &str = "secretsdump";
pub const DEDUP_DELEGATION_CREDS: &str = "delegation_creds";
pub const DEDUP_ADCS_SERVERS: &str = "adcs_servers";
pub const DEDUP_BLOODHOUND_DOMAINS: &str = "bloodhound_domains";
pub const DEDUP_SPIDERED_SHARES: &str = "spidered_shares";
pub const DEDUP_EXPANSION_CREDS: &str = "expansion_creds";
pub const DEDUP_ASREP_DOMAINS: &str = "asrep_domains";
pub const DEDUP_USERNAME_SPRAY: &str = "username_spray";
pub const DEDUP_PASSWORD_SPRAY: &str = "password_spray";
pub const DEDUP_ESC8_SERVERS: &str = "esc8_servers";
pub const DEDUP_COERCED_DCS: &str = "coerced_dcs";
pub const DEDUP_WRITABLE_SHARES: &str = "writable_shares";
pub const DEDUP_HASH_LATERAL: &str = "hash_lateral";
pub const DEDUP_SCANNED_TARGETS: &str = "scanned_targets";
pub const DEDUP_ACL_STEPS: &str = "acl_steps";

/// Vuln queue ZSET key suffix.
pub const KEY_VULN_QUEUE: &str = "vuln_queue";

/// Discovery list key prefix (NOT under ares:op:).
pub const DISCOVERY_KEY_PREFIX: &str = "ares:discoveries";

// ---------------------------------------------------------------------------
// StateInner — the actual mutable state
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct StateInner {
    pub operation_id: String,
    pub target: Option<Target>,
    pub target_ips: Vec<String>,

    // Collections (append-mostly)
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub shares: Vec<Share>,
    pub domains: Vec<String>,
    pub weaknesses: Vec<String>,

    // Vulnerability tracking
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,

    // Maps
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,
    pub domain_sids: HashMap<String, String>,

    // Flags
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,

    // Dedup sets (persisted to Redis)
    pub dedup: HashMap<String, HashSet<String>>,

    // MSSQL enum tracking (persisted to Redis SET)
    pub mssql_enum_dispatched: HashSet<String>,

    // ACL chain data (from BloodHound, stored in Redis LIST)
    pub acl_chains: Vec<serde_json::Value>,

    // ACL step dedup (tracks which chain steps have been dispatched)
    pub dispatched_acl_steps: HashSet<String>,

    // Pending/completed tasks (in-memory only)
    pub pending_tasks: HashMap<String, TaskInfo>,
    pub completed_tasks: HashMap<String, ares_core::models::TaskResult>,

    // Completion flag (set externally to signal operation should wrap up)
    pub completed: bool,
}

impl StateInner {
    fn new(operation_id: String) -> Self {
        let mut dedup = HashMap::new();
        for name in ALL_DEDUP_SETS {
            dedup.insert(name.to_string(), HashSet::new());
        }

        Self {
            operation_id,
            target: None,
            target_ips: Vec::new(),
            credentials: Vec::new(),
            hashes: Vec::new(),
            hosts: Vec::new(),
            users: Vec::new(),
            shares: Vec::new(),
            domains: Vec::new(),
            weaknesses: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            domain_sids: HashMap::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            dedup,
            mssql_enum_dispatched: HashSet::new(),
            acl_chains: Vec::new(),
            dispatched_acl_steps: HashSet::new(),
            pending_tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
            completed: false,
        }
    }

    /// Check if a dedup key exists in the named set.
    pub fn is_processed(&self, set_name: &str, key: &str) -> bool {
        self.dedup
            .get(set_name)
            .map(|s| s.contains(key))
            .unwrap_or(false)
    }

    /// Mark a key as processed in the named set.
    pub fn mark_processed(&mut self, set_name: &str, key: String) {
        self.dedup
            .entry(set_name.to_string())
            .or_default()
            .insert(key);
    }
}

const ALL_DEDUP_SETS: &[&str] = &[
    DEDUP_CRACK_REQUESTS,
    DEDUP_SECRETSDUMP,
    DEDUP_DELEGATION_CREDS,
    DEDUP_ADCS_SERVERS,
    DEDUP_BLOODHOUND_DOMAINS,
    DEDUP_SPIDERED_SHARES,
    DEDUP_EXPANSION_CREDS,
    DEDUP_ASREP_DOMAINS,
    DEDUP_USERNAME_SPRAY,
    DEDUP_PASSWORD_SPRAY,
    DEDUP_ESC8_SERVERS,
    DEDUP_COERCED_DCS,
    DEDUP_WRITABLE_SHARES,
    DEDUP_HASH_LATERAL,
    DEDUP_SCANNED_TARGETS,
    DEDUP_ACL_STEPS,
];

// ---------------------------------------------------------------------------
// SharedState — thread-safe wrapper
// ---------------------------------------------------------------------------

/// Thread-safe shared state with read/write access.
#[derive(Clone)]
pub struct SharedState {
    inner: Arc<RwLock<StateInner>>,
}

impl SharedState {
    /// Create a new empty state.
    pub fn new(operation_id: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateInner::new(operation_id))),
        }
    }

    /// Read-only access to the state.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, StateInner> {
        self.inner.read().await
    }

    /// Write access to the state.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, StateInner> {
        self.inner.write().await
    }

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
        state.weaknesses = loaded.all_weaknesses;
        state.discovered_vulnerabilities = loaded.discovered_vulnerabilities;
        state.exploited_vulnerabilities = loaded.exploited_vulnerabilities;
        state.domain_controllers = loaded.domain_controllers;
        state.netbios_to_fqdn = loaded.netbios_to_fqdn;
        state.domain_sids = domain_sids;
        state.has_domain_admin = loaded.has_domain_admin;
        state.has_golden_ticket = loaded.has_golden_ticket;
        state.domain_admin_path = loaded.domain_admin_path;
        state.dedup = dedup_sets;
        state.mssql_enum_dispatched = mssql_dispatched;
        state.acl_chains = acl_chains;
        state.dispatched_acl_steps = dispatched_acl_steps;

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

    /// Persist a dedup set entry to Redis.
    pub async fn persist_dedup(&self, queue: &TaskQueue, set_name: &str, key: &str) -> Result<()> {
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

    /// Persist MSSQL enum dispatched entry to Redis.
    pub async fn persist_mssql_dispatched(&self, queue: &TaskQueue, ip: &str) -> Result<()> {
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

    /// Add a credential to state and Redis (with dedup).
    pub async fn publish_credential(&self, queue: &TaskQueue, cred: Credential) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_credential(&mut conn, &cred).await?;
        if added {
            let mut state = self.inner.write().await;
            state.credentials.push(cred);
        }
        Ok(added)
    }

    /// Add a hash to state and Redis (with dedup).
    pub async fn publish_hash(&self, queue: &TaskQueue, hash: Hash) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_hash(&mut conn, &hash).await?;
        if added {
            let mut state = self.inner.write().await;
            state.hashes.push(hash);
        }
        Ok(added)
    }

    /// Add a host to state and Redis.
    pub async fn publish_host(&self, queue: &TaskQueue, host: Host) -> Result<bool> {
        // Check for duplicate IP in memory
        {
            let state = self.inner.read().await;
            if state.hosts.iter().any(|h| h.ip == host.ip) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader.add_host(&mut conn, &host).await?;

        // Update DC map if this is a domain controller
        if (host.is_dc || host.detect_dc()) && !host.hostname.is_empty() {
            let domain = host
                .hostname
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".");
            if !domain.is_empty() {
                let dc_key = format!(
                    "{}:{}:{}",
                    state::KEY_PREFIX,
                    self.inner.read().await.operation_id,
                    state::KEY_DC_MAP
                );
                let _: () = conn.hset(&dc_key, &domain, &host.ip).await?;
            }
        }

        let mut state = self.inner.write().await;
        state.hosts.push(host);
        Ok(true)
    }

    /// Add a vulnerability to state and Redis.
    pub async fn publish_vulnerability(
        &self,
        queue: &TaskQueue,
        vuln: VulnerabilityInfo,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_vulnerability(&mut conn, &vuln).await?;
        if added {
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

    /// Mark a vulnerability as exploited.
    pub async fn mark_exploited(&self, queue: &TaskQueue, vuln_id: &str) -> Result<()> {
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
        let mut conn = queue.connection();
        let _: () = conn.sadd(&key, vuln_id).await?;
        let _: () = conn.expire(&key, 86400).await?;

        let mut state = self.inner.write().await;
        state.exploited_vulnerabilities.insert(vuln_id.to_string());
        Ok(())
    }

    /// Set has_domain_admin flag and persist to Redis.
    pub async fn set_domain_admin(&self, queue: &TaskQueue, path: Option<String>) -> Result<()> {
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
        state.domain_admin_path = path;
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
        state.acl_chains = acl_chains;

        Ok(())
    }

    /// Get the vuln queue ZSET key.
    pub async fn vuln_queue_key(&self) -> String {
        let state = self.inner.read().await;
        format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            state.operation_id,
            KEY_VULN_QUEUE
        )
    }

    /// Get the discovery list key.
    pub async fn discovery_key(&self) -> String {
        let state = self.inner.read().await;
        format!("{}:{}", DISCOVERY_KEY_PREFIX, state.operation_id)
    }

    /// Get the operation ID.
    pub async fn operation_id(&self) -> String {
        self.inner.read().await.operation_id.clone()
    }
}
