//! Redis-native state backend for reading SharedRedTeamState.
//!
//! This module provides Redis-native storage access for SharedRedTeamState collections,
//! matching the Python `RedisStateBackend` key patterns exactly.
//!
//! Redis key structure:
//!     ares:op:{op_id}:credentials       HASH (dedup_key -> JSON)
//!     ares:op:{op_id}:hashes            HASH (dedup_key -> JSON)
//!     ares:op:{op_id}:hosts             LIST (JSON per entry)
//!     ares:op:{op_id}:users             LIST (JSON per entry)
//!     ares:op:{op_id}:shares            HASH (dedup_key -> JSON)
//!     ares:op:{op_id}:weaknesses        HASH (dedup_key -> block)
//!     ares:op:{op_id}:domains           SET
//!     ares:op:{op_id}:vulns             HASH (vuln_id -> JSON)
//!     ares:op:{op_id}:exploited         SET
//!     ares:op:{op_id}:meta              HASH
//!     ares:op:{op_id}:dc_map            HASH
//!     ares:op:{op_id}:netbios_map       HASH
//!     ares:op:{op_id}:artifacts         HASH
//!     ares:op:{op_id}:timeline          LIST (JSON per entry)
//!     ares:op:{op_id}:dedup:{set_name}  SET
//!     ares:op:{op_id}:techniques        SET
//!     ares:op:{op_id}:golden_tickets    LIST
//!     ares:op:{op_id}:adminsd_backdoors LIST
//!     ares:op:{op_id}:acl_chains        LIST
//!     ares:op:{op_id}:gmsa_accounts     LIST
//!
//! Lock keys:
//!     ares:lock:{op_id}                 STRING (operation lock)
//!
//! Task status keys:
//!     ares:task_status:{task_id}         STRING (JSON TaskStatusRecord)

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use tracing::warn;

use crate::models::{
    BlueTaskInfo, Credential, Evidence, Hash, Host, OperationMeta, Share, SharedBlueTeamState,
    SharedRedTeamState, Target, TimelineEvent, TriageRecord, User, VulnerabilityInfo,
};

/// Redis key prefix for all operation state.
pub const KEY_PREFIX: &str = "ares:op";

/// Redis key prefix for operation locks.
pub const LOCK_PREFIX: &str = "ares:lock";

/// Redis key prefix for task status records.
pub const TASK_STATUS_PREFIX: &str = "ares:task_status";

// Collection key suffixes (appended to `ares:op:{op_id}:`)
pub const KEY_CREDENTIALS: &str = "credentials";
pub const KEY_HASHES: &str = "hashes";
pub const KEY_HOSTS: &str = "hosts";
pub const KEY_USERS: &str = "users";
pub const KEY_SHARES: &str = "shares";
pub const KEY_WEAKNESSES: &str = "weaknesses";
pub const KEY_DOMAINS: &str = "domains";
pub const KEY_VULNS: &str = "vulns";
pub const KEY_EXPLOITED: &str = "exploited";
pub const KEY_META: &str = "meta";
pub const KEY_DC_MAP: &str = "dc_map";
pub const KEY_NETBIOS_MAP: &str = "netbios_map";
pub const KEY_ARTIFACTS: &str = "artifacts";
pub const KEY_TIMELINE: &str = "timeline";
pub const KEY_GOLDEN_TICKETS: &str = "golden_tickets";
pub const KEY_ADMINSD_BACKDOORS: &str = "adminsd_backdoors";
pub const KEY_ACL_CHAINS: &str = "acl_chains";
pub const KEY_GMSA_ACCOUNTS: &str = "gmsa_accounts";
pub const KEY_DEDUP_PREFIX: &str = "dedup";
pub const KEY_TECHNIQUES: &str = "techniques";
pub const KEY_MSSQL_ENUM_DISPATCHED: &str = "mssql_enum_dispatched";
pub const KEY_PENDING_TASKS: &str = "pending_tasks";
pub const KEY_COMPLETED_TASKS: &str = "completed_tasks";
pub const KEY_VULN_TYPE_FAILURES: &str = "vuln_type_failures";
pub const KEY_DOMAIN_SIDS: &str = "domain_sids";

/// Pub/Sub channel prefix for state update notifications.
pub const STATE_UPDATE_CHANNEL_PREFIX: &str = "ares:state:updates";

/// Build a Redis key for an operation's collection.
///
/// # Examples
/// ```
/// use ares_core::state::build_key;
/// assert_eq!(build_key("op-123", "meta"), "ares:op:op-123:meta");
/// ```
pub fn build_key(operation_id: &str, suffix: &str) -> String {
    format!("{KEY_PREFIX}:{operation_id}:{suffix}")
}

/// Build a Redis lock key for an operation.
pub fn build_lock_key(operation_id: &str) -> String {
    format!("{LOCK_PREFIX}:{operation_id}")
}

/// Read-only Redis state backend for CLI operations.
///
/// This provides methods to read operation state from Redis, matching
/// the Python `RedisStateBackend` serialization format exactly.
pub struct RedisStateReader {
    operation_id: String,
}

impl RedisStateReader {
    pub fn new(operation_id: String) -> Self {
        Self { operation_id }
    }

    fn key(&self, suffix: &str) -> String {
        build_key(&self.operation_id, suffix)
    }

    /// Check if the operation exists in Redis.
    pub async fn exists(&self, conn: &mut impl AsyncCommands) -> Result<bool, redis::RedisError> {
        let exists: bool = conn.exists(self.key(KEY_META)).await?;
        Ok(exists)
    }

    /// Load operation metadata from `ares:op:{id}:meta` HASH.
    pub async fn get_meta(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<OperationMeta, redis::RedisError> {
        let data: HashMap<String, String> = conn.hgetall(self.key(KEY_META)).await?;
        Ok(OperationMeta::from_redis_hash(&data))
    }

    /// Load all credentials from `ares:op:{id}:credentials` HASH.
    ///
    /// Values are JSON-serialized Credential objects; keys are dedup keys (ignored).
    pub async fn get_credentials(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Credential>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_CREDENTIALS)).await?;
        let mut result = Vec::with_capacity(items.len());
        for (_dedup_key, json_str) in items {
            match serde_json::from_str::<Credential>(&json_str) {
                Ok(cred) => result.push(cred),
                Err(e) => warn!("Failed to deserialize credential: {e}"),
            }
        }
        Ok(result)
    }

    /// Load all hashes from `ares:op:{id}:hashes` HASH.
    pub async fn get_hashes(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Hash>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_HASHES)).await?;
        let mut result = Vec::with_capacity(items.len());
        for (_dedup_key, json_str) in items {
            match serde_json::from_str::<Hash>(&json_str) {
                Ok(h) => result.push(h),
                Err(e) => warn!("Failed to deserialize hash: {e}"),
            }
        }
        Ok(result)
    }

    /// Load all hosts from `ares:op:{id}:hosts` LIST.
    pub async fn get_hosts(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Host>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(KEY_HOSTS), 0, -1).await?;
        let mut result = Vec::with_capacity(items.len());
        for json_str in items {
            match serde_json::from_str::<Host>(&json_str) {
                Ok(h) => result.push(h),
                Err(e) => warn!("Failed to deserialize host: {e}"),
            }
        }
        Ok(result)
    }

    /// Load all users from `ares:op:{id}:users` LIST.
    pub async fn get_users(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<User>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(KEY_USERS), 0, -1).await?;
        let mut result = Vec::with_capacity(items.len());
        for json_str in items {
            match serde_json::from_str::<User>(&json_str) {
                Ok(u) => result.push(u),
                Err(e) => warn!("Failed to deserialize user: {e}"),
            }
        }
        Ok(result)
    }

    /// Load all shares from `ares:op:{id}:shares` HASH.
    pub async fn get_shares(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Share>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_SHARES)).await?;
        let mut result = Vec::with_capacity(items.len());
        for (_dedup_key, json_str) in items {
            match serde_json::from_str::<Share>(&json_str) {
                Ok(s) => result.push(s),
                Err(e) => warn!("Failed to deserialize share: {e}"),
            }
        }
        Ok(result)
    }

    /// Load all weaknesses from `ares:op:{id}:weaknesses` HASH.
    ///
    /// Values are the weakness description blocks (markdown strings).
    pub async fn get_weaknesses(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_WEAKNESSES)).await?;
        Ok(items.into_values().collect())
    }

    /// Load all domains from `ares:op:{id}:domains` SET.
    pub async fn get_domains(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(KEY_DOMAINS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load all vulnerabilities from `ares:op:{id}:vulns` HASH.
    pub async fn get_vulnerabilities(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, VulnerabilityInfo>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_VULNS)).await?;
        let mut result = HashMap::with_capacity(items.len());
        for (vuln_id, json_str) in items {
            match serde_json::from_str::<VulnerabilityInfo>(&json_str) {
                Ok(v) => {
                    result.insert(vuln_id, v);
                }
                Err(e) => warn!("Failed to deserialize vulnerability {vuln_id}: {e}"),
            }
        }
        Ok(result)
    }

    /// Load exploited vulnerability IDs from `ares:op:{id}:exploited` SET.
    pub async fn get_exploited_vulnerabilities(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashSet<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(KEY_EXPLOITED)).await?;
        Ok(items)
    }

    /// Load domain controller map from `ares:op:{id}:dc_map` HASH.
    pub async fn get_dc_map(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, String>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_DC_MAP)).await?;
        Ok(items)
    }

    /// Load NetBIOS to FQDN map from `ares:op:{id}:netbios_map` HASH.
    pub async fn get_netbios_map(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, String>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_NETBIOS_MAP)).await?;
        Ok(items)
    }

    /// Check if the operation has an active lock.
    pub async fn is_running(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<bool, redis::RedisError> {
        let exists: bool = conn.exists(build_lock_key(&self.operation_id)).await?;
        Ok(exists)
    }

    /// Load the full SharedRedTeamState from Redis.
    ///
    /// This is the Rust equivalent of `_load_state_from_redis()` in cli_ops.py.
    pub async fn load_state(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Option<SharedRedTeamState>, redis::RedisError> {
        if !self.exists(conn).await? {
            return Ok(None);
        }

        let meta = self.get_meta(conn).await?;
        let credentials = self.get_credentials(conn).await?;
        let hashes = self.get_hashes(conn).await?;
        let hosts = self.get_hosts(conn).await?;
        let users = self.get_users(conn).await?;
        let shares = self.get_shares(conn).await?;
        let domains = self.get_domains(conn).await?;
        let weaknesses = self.get_weaknesses(conn).await?;
        let vulnerabilities = self.get_vulnerabilities(conn).await?;
        let exploited = self.get_exploited_vulnerabilities(conn).await?;
        let dc_map = self.get_dc_map(conn).await?;
        let netbios_map = self.get_netbios_map(conn).await?;

        let target = meta.target_ip.as_ref().map(|ip| Target {
            ip: ip.clone(),
            hostname: String::new(),
            domain: meta.target_domain.clone().unwrap_or_default(),
            environment: String::new(),
        });

        let target_ips = if meta.target_ips.is_empty() {
            meta.target_ip.iter().cloned().collect()
        } else {
            meta.target_ips.clone()
        };

        let state = SharedRedTeamState {
            operation_id: self.operation_id.clone(),
            target,
            target_ips,
            started_at: meta.started_at.unwrap_or_else(Utc::now),
            completed_at: meta.completed_at,
            all_domains: domains,
            all_credentials: credentials,
            all_hashes: hashes,
            all_hosts: hosts,
            all_users: users,
            all_shares: shares,
            all_weaknesses: weaknesses,
            discovered_vulnerabilities: vulnerabilities,
            exploited_vulnerabilities: exploited,
            has_domain_admin: meta.has_domain_admin,
            has_golden_ticket: meta.has_golden_ticket,
            domain_admin_path: meta.domain_admin_path,
            domain_controllers: dc_map,
            netbios_to_fqdn: netbios_map,
        };

        Ok(Some(state))
    }

    /// Add a credential to Redis HASH.
    ///
    /// Uses the same dedup key format as Python: `cred:{domain}:{username}:{password_md5_16}`
    pub async fn add_credential(
        &self,
        conn: &mut impl AsyncCommands,
        cred: &Credential,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_CREDENTIALS);
        let dedup_field = build_credential_dedup_key(cred);
        let data = serde_json::to_string(cred).unwrap_or_default();

        let added: bool = conn.hset_nx(&key, &dedup_field, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?; // 24h TTL
        }
        Ok(added)
    }

    /// Add a vulnerability to Redis HASH.
    pub async fn add_vulnerability(
        &self,
        conn: &mut impl AsyncCommands,
        vuln: &VulnerabilityInfo,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_VULNS);
        let data = serde_json::to_string(vuln).unwrap_or_default();

        let added: bool = conn.hset_nx(&key, &vuln.vuln_id, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?;
        }
        Ok(added)
    }

    /// Add a host to Redis LIST.
    pub async fn add_host(
        &self,
        conn: &mut impl AsyncCommands,
        host: &Host,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(KEY_HOSTS);
        let data = serde_json::to_string(host).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Add a domain to Redis SET.
    pub async fn add_domain(
        &self,
        conn: &mut impl AsyncCommands,
        domain: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_DOMAINS);
        let added: i64 = conn.sadd(&key, domain.to_lowercase()).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(added > 0)
    }

    /// Add a hash to Redis HASH with deduplication.
    ///
    /// Uses the same dedup key format as Python's `_build_hash_dedup_key()`.
    pub async fn add_hash(
        &self,
        conn: &mut impl AsyncCommands,
        hash: &Hash,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_HASHES);
        let dedup_field = build_hash_dedup_key(hash);
        let data = serde_json::to_string(hash).unwrap_or_default();

        let added: bool = conn.hset_nx(&key, &dedup_field, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?;
        }
        Ok(added)
    }

    /// Set a meta field in the operation's meta HASH.
    ///
    /// Values are JSON-encoded to match Python's `json.dumps(value)`.
    pub async fn set_meta_field(
        &self,
        conn: &mut impl AsyncCommands,
        field: &str,
        value: &serde_json::Value,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(KEY_META);
        let serialized = serde_json::to_string(value).unwrap_or_default();
        let _: () = conn.hset(&key, field, &serialized).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Set a domain SID in the `domain_sids` HASH.
    pub async fn set_domain_sid(
        &self,
        conn: &mut impl AsyncCommands,
        domain: &str,
        sid: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(KEY_DOMAIN_SIDS);
        let _: () = conn.hset(&key, domain, sid).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Load timeline events from `ares:op:{id}:timeline` LIST.
    ///
    /// Each entry is a JSON object with at least `timestamp`, `description`,
    /// and optionally `mitre_techniques`.
    pub async fn get_timeline(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<serde_json::Value>, redis::RedisError> {
        let key = self.key(KEY_TIMELINE);
        let items: Vec<String> = conn.lrange(&key, 0, -1).await?;
        let mut events = Vec::new();
        for item in items {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&item) {
                events.push(val);
            }
        }
        Ok(events)
    }

    /// Load MITRE ATT&CK technique IDs from `ares:op:{id}:techniques` SET.
    pub async fn get_techniques(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let key = self.key(KEY_TECHNIQUES);
        let items: Vec<String> = conn.smembers(&key).await?;
        Ok(items)
    }

    /// Get a cached report from `ares:op:{id}:report` STRING.
    pub async fn get_report(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Option<String>, redis::RedisError> {
        let key = format!("{}:report", self.key_prefix());
        let report: Option<String> = conn.get(&key).await?;
        Ok(report)
    }

    /// Returns the key prefix for this operation: `ares:op:{op_id}`
    fn key_prefix(&self) -> String {
        format!("{KEY_PREFIX}:{}", self.operation_id)
    }
}

/// Build credential dedup key matching Python format:
/// `cred:{domain}:{username}:{md5(password)[:16]}`
pub fn build_credential_dedup_key(cred: &Credential) -> String {
    use md5::{Digest, Md5};

    let domain = cred.domain.trim().to_lowercase();
    let username = cred.username.trim().to_lowercase();
    let mut hasher = Md5::new();
    hasher.update(cred.password.as_bytes());
    let password_hash = format!("{:x}", hasher.finalize());
    let password_hash_short = &password_hash[..16.min(password_hash.len())];

    format!("cred:{domain}:{username}:{password_hash_short}")
}

/// Build hash dedup key matching Python's `_build_hash_dedup_key()`.
///
/// Dedup key format varies by hash type:
/// - AS-REP: `asrep:{domain}:{username}`
/// - Kerberoast: `krb:{domain}:{username}:{etype}:{spn}` or `krb:{domain}:{username}:{hash[:32]}`
/// - NTLM/other: `ntlm:{domain}:{username}:{hash[:32]}`
pub fn build_hash_dedup_key(hash: &Hash) -> String {
    let hash_type = hash.hash_type.trim().to_lowercase();
    let hash_value = &hash.hash_value;
    let username = hash.username.trim().to_lowercase();
    let domain = hash.domain.trim().to_lowercase();

    // AS-REP detection
    let is_asrep = matches!(hash_type.as_str(), "as-rep" | "asrep" | "krb5asrep")
        || hash_value.starts_with("$krb5asrep$");
    if is_asrep {
        return format!("asrep:{domain}:{username}");
    }

    // Kerberoast detection
    let is_kerberoast = matches!(
        hash_type.as_str(),
        "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
    ) || hash_value.starts_with("$krb5tgs$");
    if is_kerberoast {
        if let Some(spn_key) = extract_kerberoast_spn_key(hash_value) {
            return format!("krb:{domain}:{username}:{spn_key}");
        }
        let prefix = &hash_value[..32.min(hash_value.len())];
        return format!("krb:{domain}:{username}:{prefix}");
    }

    // NTLM/other
    let prefix = &hash_value[..32.min(hash_value.len())];
    format!("ntlm:{domain}:{username}:{prefix}")
}

/// Extract SPN and encryption type from a Kerberoast hash for deduplication.
///
/// Hash format: `$krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted`
fn extract_kerberoast_spn_key(hash_value: &str) -> Option<String> {
    if !hash_value.starts_with("$krb5tgs$") {
        return None;
    }
    let dollar_parts: Vec<&str> = hash_value.split('$').collect();
    if dollar_parts.len() < 4 {
        return None;
    }
    let etype = dollar_parts[2];
    let asterisk_parts: Vec<&str> = hash_value.split('*').collect();
    if asterisk_parts.len() < 2 {
        return None;
    }
    let inner_parts: Vec<&str> = asterisk_parts[1].split('$').collect();
    if inner_parts.len() < 3 {
        return None;
    }
    let spn = inner_parts[2];
    Some(format!("{etype}:{spn}"))
}

/// Publish a state update notification via Redis PUBLISH.
///
/// Channel: `ares:state:updates:{operation_id}`
/// Message: `{"type":"state_update","operation_id":"...","ts":"..."}`
///
/// Returns the number of subscribers that received the message.
pub async fn publish_state_update(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<i64, redis::RedisError> {
    let channel = format!("{STATE_UPDATE_CHANNEL_PREFIX}:{operation_id}");
    let message = serde_json::json!({
        "type": "state_update",
        "operation_id": operation_id,
        "ts": chrono::Utc::now().to_rfc3339(),
    });
    let msg_str = serde_json::to_string(&message).unwrap_or_default();
    let count: i64 = conn.publish(&channel, &msg_str).await?;
    Ok(count)
}

/// List all operation IDs by scanning `ares:op:*:meta` keys.
pub async fn list_operation_ids(
    conn: &mut impl AsyncCommands,
) -> Result<Vec<String>, redis::RedisError> {
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:op:*:meta")
        .query_async(conn)
        .await?;

    let mut op_ids = Vec::new();
    for key in keys {
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() >= 3 {
            op_ids.push(parts[2].to_string());
        }
    }
    op_ids.sort();
    Ok(op_ids)
}

/// List all running operation IDs by scanning lock keys.
pub async fn list_running_operations(
    conn: &mut impl AsyncCommands,
) -> Result<HashSet<String>, redis::RedisError> {
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{LOCK_PREFIX}:*"))
        .query_async(conn)
        .await?;

    let mut running = HashSet::new();
    for key in keys {
        let parts: Vec<&str> = key.splitn(3, ':').collect();
        if parts.len() >= 3 {
            running.insert(parts[2].to_string());
        }
    }
    Ok(running)
}

/// Resolve the latest operation ID, preferring running operations.
///
/// Matches the Python `_resolve_latest_operation()` logic.
pub async fn resolve_latest_operation(
    conn: &mut impl AsyncCommands,
) -> Result<Option<String>, redis::RedisError> {
    let running_ops = list_running_operations(conn).await?;
    let all_op_ids = list_operation_ids(conn).await?;

    if all_op_ids.is_empty() {
        return Ok(None);
    }

    // Collect (started_at, op_id, is_running) tuples
    let mut ops: Vec<(Option<DateTime<Utc>>, String, bool)> = Vec::new();

    for op_id in &all_op_ids {
        let meta_key = build_key(op_id, KEY_META);
        let data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
        let started_at = data
            .get("started_at")
            .and_then(|s| {
                DateTime::parse_from_rfc3339(s)
                    .ok()
                    .or_else(|| s.parse().ok())
            })
            .map(|dt| dt.with_timezone(&Utc));
        let is_running = running_ops.contains(op_id);
        ops.push((started_at, op_id.clone(), is_running));
    }

    // Prefer running operations
    let running: Vec<_> = ops
        .iter()
        .filter(|(_, _, is_running)| *is_running)
        .collect();
    if !running.is_empty() {
        return Ok(Some(pick_latest(&running)));
    }

    // Fall back to latest by started_at
    let all: Vec<_> = ops.iter().collect();
    Ok(Some(pick_latest(&all)))
}

fn pick_latest(items: &[&(Option<DateTime<Utc>>, String, bool)]) -> String {
    // Prefer items with a timestamp, sort descending
    let mut with_time: Vec<_> = items.iter().filter(|(t, _, _)| t.is_some()).collect();
    if !with_time.is_empty() {
        with_time.sort_by(|a, b| b.0.cmp(&a.0));
        return with_time[0].1.clone();
    }
    // Fallback: sort by op_id descending
    let mut by_id: Vec<_> = items.to_vec();
    by_id.sort_by(|a, b| b.1.cmp(&a.1));
    by_id[0].1.clone()
}

/// Delete an operation and all its associated Redis keys.
pub async fn delete_operation(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<usize, redis::RedisError> {
    // Find all keys for this operation
    let pattern = format!("{KEY_PREFIX}:{operation_id}:*");
    let mut keys: Vec<String> = redis::cmd("KEYS").arg(&pattern).query_async(conn).await?;

    // Also delete the lock key
    keys.push(build_lock_key(operation_id));

    // Delete task status keys for this operation
    let task_keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{TASK_STATUS_PREFIX}:*"))
        .query_async(conn)
        .await?;

    for task_key in task_keys {
        let raw: Option<String> = conn.get(&task_key).await?;
        if let Some(json_str) = raw {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                if data.get("operation_id").and_then(|v| v.as_str()) == Some(operation_id) {
                    keys.push(task_key);
                }
            }
        }
    }

    let mut deleted = 0usize;
    for key in &keys {
        let count: usize = conn.del(key).await?;
        deleted += count;
    }

    Ok(deleted)
}

// ============================================================================
// Blue Team State Reader
// ============================================================================

/// Redis key prefix for all blue team investigation state.
pub const BLUE_KEY_PREFIX: &str = "ares:blue:inv";

/// Redis lock key prefix for blue team investigations.
pub const BLUE_LOCK_PREFIX: &str = "ares:blue:lock";

// Blue team collection key suffixes (appended to `ares:blue:inv:{inv_id}:`)
pub const BLUE_KEY_EVIDENCE: &str = "evidence";
pub const BLUE_KEY_TIMELINE: &str = "timeline";
pub const BLUE_KEY_TECHNIQUES: &str = "techniques";
pub const BLUE_KEY_TACTICS: &str = "tactics";
pub const BLUE_KEY_HOSTS: &str = "hosts";
pub const BLUE_KEY_USERS: &str = "users";
pub const BLUE_KEY_QUERY_TYPES: &str = "query_types";
pub const BLUE_KEY_META: &str = "meta";
pub const BLUE_KEY_PENDING_TASKS: &str = "tasks:pending";
pub const BLUE_KEY_COMPLETED_TASKS: &str = "tasks:completed";
pub const BLUE_KEY_TECHNIQUE_NAMES: &str = "technique_names";
pub const BLUE_KEY_RECOMMENDATIONS: &str = "recommendations";
pub const BLUE_KEY_TRIAGE_DECISION: &str = "triage:decision";
pub const BLUE_KEY_TRIAGE_RECORDS: &str = "triage:records";

/// Build a Redis key for a blue team investigation's collection.
///
/// # Examples
/// ```
/// use ares_core::state::build_blue_key;
/// assert_eq!(build_blue_key("inv-123", "meta"), "ares:blue:inv:inv-123:meta");
/// ```
pub fn build_blue_key(investigation_id: &str, suffix: &str) -> String {
    format!("{BLUE_KEY_PREFIX}:{investigation_id}:{suffix}")
}

/// Build a Redis lock key for a blue team investigation.
pub fn build_blue_lock_key(investigation_id: &str) -> String {
    format!("{BLUE_LOCK_PREFIX}:{investigation_id}")
}

/// Read-only Redis state backend for blue team investigations.
///
/// This provides methods to read investigation state from Redis, matching
/// the Python `BlueStateBackend` key patterns exactly.
pub struct BlueStateReader {
    investigation_id: String,
}

impl BlueStateReader {
    pub fn new(investigation_id: String) -> Self {
        Self { investigation_id }
    }

    fn key(&self, suffix: &str) -> String {
        build_blue_key(&self.investigation_id, suffix)
    }

    /// Check if the investigation exists in Redis.
    pub async fn exists(&self, conn: &mut impl AsyncCommands) -> Result<bool, redis::RedisError> {
        let exists: bool = conn.exists(self.key(BLUE_KEY_META)).await?;
        Ok(exists)
    }

    /// Load all evidence from `ares:blue:inv:{id}:evidence` HASH.
    ///
    /// Values are JSON-serialized Evidence objects; keys are dedup keys.
    pub async fn get_evidence(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Evidence>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(BLUE_KEY_EVIDENCE)).await?;
        let mut result = Vec::with_capacity(items.len());
        for (_dedup_key, json_str) in items {
            match serde_json::from_str::<Evidence>(&json_str) {
                Ok(ev) => result.push(ev),
                Err(e) => warn!("Failed to deserialize evidence: {e}"),
            }
        }
        Ok(result)
    }

    /// Load timeline events from `ares:blue:inv:{id}:timeline` LIST.
    pub async fn get_timeline(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<TimelineEvent>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(BLUE_KEY_TIMELINE), 0, -1).await?;
        let mut result = Vec::with_capacity(items.len());
        for json_str in items {
            match serde_json::from_str::<TimelineEvent>(&json_str) {
                Ok(ev) => result.push(ev),
                Err(e) => warn!("Failed to deserialize timeline event: {e}"),
            }
        }
        Ok(result)
    }

    /// Load MITRE ATT&CK technique IDs from `ares:blue:inv:{id}:techniques` SET.
    pub async fn get_techniques(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(BLUE_KEY_TECHNIQUES)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load MITRE ATT&CK tactic IDs from `ares:blue:inv:{id}:tactics` SET.
    pub async fn get_tactics(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(BLUE_KEY_TACTICS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load technique name mappings from `ares:blue:inv:{id}:technique_names` HASH.
    pub async fn get_technique_names(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, String>, redis::RedisError> {
        let items: HashMap<String, String> =
            conn.hgetall(self.key(BLUE_KEY_TECHNIQUE_NAMES)).await?;
        Ok(items)
    }

    /// Load queried hosts from `ares:blue:inv:{id}:hosts` SET.
    pub async fn get_hosts(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(BLUE_KEY_HOSTS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load queried users from `ares:blue:inv:{id}:users` SET.
    pub async fn get_users(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(BLUE_KEY_USERS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load executed query types from `ares:blue:inv:{id}:query_types` SET.
    pub async fn get_query_types(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: HashSet<String> = conn.smembers(self.key(BLUE_KEY_QUERY_TYPES)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load recommendations from `ares:blue:inv:{id}:recommendations` LIST.
    pub async fn get_recommendations(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: Vec<String> = conn
            .lrange(self.key(BLUE_KEY_RECOMMENDATIONS), 0, -1)
            .await?;
        Ok(items)
    }

    /// Load the current triage decision from `ares:blue:inv:{id}:triage:decision` STRING.
    pub async fn get_triage_decision(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Option<serde_json::Value>, redis::RedisError> {
        let raw: Option<String> = conn.get(self.key(BLUE_KEY_TRIAGE_DECISION)).await?;
        match raw {
            Some(json_str) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(val) => Ok(Some(val)),
                Err(e) => {
                    warn!("Failed to deserialize triage decision: {e}");
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Load triage records from `ares:blue:inv:{id}:triage:records` LIST.
    pub async fn get_triage_records(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<TriageRecord>, redis::RedisError> {
        let items: Vec<String> = conn
            .lrange(self.key(BLUE_KEY_TRIAGE_RECORDS), 0, -1)
            .await?;
        let mut result = Vec::with_capacity(items.len());
        for json_str in items {
            match serde_json::from_str::<TriageRecord>(&json_str) {
                Ok(rec) => result.push(rec),
                Err(e) => warn!("Failed to deserialize triage record: {e}"),
            }
        }
        Ok(result)
    }

    /// Load pending tasks from `ares:blue:inv:{id}:tasks:pending` HASH.
    pub async fn get_pending_tasks(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, BlueTaskInfo>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(BLUE_KEY_PENDING_TASKS)).await?;
        let mut result = HashMap::with_capacity(items.len());
        for (task_id, json_str) in items {
            match serde_json::from_str::<BlueTaskInfo>(&json_str) {
                Ok(task) => {
                    result.insert(task_id, task);
                }
                Err(e) => warn!("Failed to deserialize pending task {task_id}: {e}"),
            }
        }
        Ok(result)
    }

    /// Load completed tasks from `ares:blue:inv:{id}:tasks:completed` HASH.
    pub async fn get_completed_tasks(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, BlueTaskInfo>, redis::RedisError> {
        let items: HashMap<String, String> =
            conn.hgetall(self.key(BLUE_KEY_COMPLETED_TASKS)).await?;
        let mut result = HashMap::with_capacity(items.len());
        for (task_id, json_str) in items {
            match serde_json::from_str::<BlueTaskInfo>(&json_str) {
                Ok(task) => {
                    result.insert(task_id, task);
                }
                Err(e) => warn!("Failed to deserialize completed task {task_id}: {e}"),
            }
        }
        Ok(result)
    }

    /// Load meta fields from `ares:blue:inv:{id}:meta` HASH.
    ///
    /// Meta fields are stored as JSON-encoded values (via Python's `json.dumps()`).
    pub async fn get_meta(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, serde_json::Value>, redis::RedisError> {
        let raw: HashMap<String, String> = conn.hgetall(self.key(BLUE_KEY_META)).await?;
        let mut result = HashMap::with_capacity(raw.len());
        for (field, json_str) in raw {
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(val) => {
                    result.insert(field, val);
                }
                Err(_) => {
                    // Fall back to treating it as a plain string
                    result.insert(field, serde_json::Value::String(json_str));
                }
            }
        }
        Ok(result)
    }

    /// Check if the investigation has an active lock.
    pub async fn is_running(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<bool, redis::RedisError> {
        let exists: bool = conn
            .exists(build_blue_lock_key(&self.investigation_id))
            .await?;
        Ok(exists)
    }

    /// Load the full SharedBlueTeamState from Redis.
    ///
    /// This is the Rust equivalent of `BlueStateBackend.snapshot()`.
    pub async fn load_state(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Option<SharedBlueTeamState>, redis::RedisError> {
        if !self.exists(conn).await? {
            return Ok(None);
        }

        let meta = self.get_meta(conn).await?;
        let evidence = self.get_evidence(conn).await?;
        let timeline = self.get_timeline(conn).await?;
        let techniques = self.get_techniques(conn).await?;
        let tactics = self.get_tactics(conn).await?;
        let technique_names = self.get_technique_names(conn).await?;
        let hosts = self.get_hosts(conn).await?;
        let users = self.get_users(conn).await?;
        let query_types = self.get_query_types(conn).await?;
        let recommendations = self.get_recommendations(conn).await?;
        let triage_decision = self.get_triage_decision(conn).await?;
        let triage_records = self.get_triage_records(conn).await?;
        let pending_tasks = self.get_pending_tasks(conn).await?;
        let completed_tasks = self.get_completed_tasks(conn).await?;

        // Extract scalar meta fields
        let stage = meta
            .get("stage")
            .and_then(|v| v.as_str())
            .unwrap_or("triage")
            .to_string();
        let started_at = meta
            .get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let escalated = meta
            .get("escalated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let escalation_reason = meta
            .get("escalation_reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let attack_synopsis = meta
            .get("attack_synopsis")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let alert = meta
            .get("alert")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let state = SharedBlueTeamState {
            investigation_id: self.investigation_id.clone(),
            alert,
            stage,
            started_at,
            evidence,
            timeline,
            identified_techniques: techniques,
            identified_tactics: tactics,
            technique_names,
            queried_hosts: hosts,
            queried_users: users,
            executed_query_types: query_types,
            escalated,
            escalation_reason,
            attack_synopsis,
            recommendations,
            triage_decision,
            triage_records,
            pending_tasks,
            completed_tasks,
        };

        Ok(Some(state))
    }
}

/// List all blue team investigation IDs by scanning `ares:blue:inv:*:meta` keys.
pub async fn list_investigation_ids(
    conn: &mut impl AsyncCommands,
) -> Result<Vec<String>, redis::RedisError> {
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:blue:inv:*:meta")
        .query_async(conn)
        .await?;

    let mut inv_ids = Vec::new();
    for key in keys {
        // Key format: ares:blue:inv:{id}:meta
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() >= 4 {
            inv_ids.push(parts[3].to_string());
        }
    }
    inv_ids.sort();
    Ok(inv_ids)
}

/// List all running blue team investigation IDs by scanning lock keys.
pub async fn list_running_investigations(
    conn: &mut impl AsyncCommands,
) -> Result<HashSet<String>, redis::RedisError> {
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{BLUE_LOCK_PREFIX}:*"))
        .query_async(conn)
        .await?;

    let mut running = HashSet::new();
    for key in keys {
        // Key format: ares:blue:lock:{id}
        let parts: Vec<&str> = key.splitn(4, ':').collect();
        if parts.len() >= 4 {
            running.insert(parts[3].to_string());
        }
    }
    Ok(running)
}

/// Resolve the latest blue team investigation ID, preferring running investigations.
pub async fn resolve_latest_investigation(
    conn: &mut impl AsyncCommands,
) -> Result<Option<String>, redis::RedisError> {
    let running_invs = list_running_investigations(conn).await?;
    let all_inv_ids = list_investigation_ids(conn).await?;

    if all_inv_ids.is_empty() {
        return Ok(None);
    }

    // Collect (started_at, inv_id, is_running) tuples
    let mut invs: Vec<(Option<String>, String, bool)> = Vec::new();

    for inv_id in &all_inv_ids {
        let meta_key = build_blue_key(inv_id, BLUE_KEY_META);
        let data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
        let started_at = data.get("started_at").and_then(|s| {
            // Try JSON-decoding first (Python stores as json.dumps(value))
            if let Ok(serde_json::Value::String(inner)) =
                serde_json::from_str::<serde_json::Value>(s)
            {
                Some(inner)
            } else if !s.is_empty() && s != "null" {
                Some(s.clone())
            } else {
                None
            }
        });
        let is_running = running_invs.contains(inv_id);
        invs.push((started_at, inv_id.clone(), is_running));
    }

    // Prefer running investigations
    let running: Vec<_> = invs
        .iter()
        .filter(|(_, _, is_running)| *is_running)
        .collect();
    if !running.is_empty() {
        return Ok(Some(pick_latest_blue(&running)));
    }

    // Fall back to latest by started_at
    let all: Vec<_> = invs.iter().collect();
    Ok(Some(pick_latest_blue(&all)))
}

fn pick_latest_blue(items: &[&(Option<String>, String, bool)]) -> String {
    // Prefer items with a timestamp, sort descending
    let mut with_time: Vec<_> = items.iter().filter(|(t, _, _)| t.is_some()).collect();
    if !with_time.is_empty() {
        with_time.sort_by(|a, b| b.0.cmp(&a.0));
        return with_time[0].1.clone();
    }
    // Fallback: sort by inv_id descending
    let mut by_id: Vec<_> = items.to_vec();
    by_id.sort_by(|a, b| b.1.cmp(&a.1));
    by_id[0].1.clone()
}

/// Delete an investigation and all its associated Redis keys.
pub async fn delete_investigation(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
) -> Result<usize, redis::RedisError> {
    let pattern = format!("{BLUE_KEY_PREFIX}:{investigation_id}:*");
    let mut keys: Vec<String> = redis::cmd("KEYS").arg(&pattern).query_async(conn).await?;

    // Also delete the lock key
    keys.push(build_blue_lock_key(investigation_id));

    let mut deleted = 0usize;
    for key in &keys {
        let count: usize = conn.del(key).await?;
        deleted += count;
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_key() {
        assert_eq!(build_key("op-123", "meta"), "ares:op:op-123:meta");
        assert_eq!(
            build_key("op-123", "credentials"),
            "ares:op:op-123:credentials"
        );
    }

    #[test]
    fn test_build_lock_key() {
        assert_eq!(build_lock_key("op-123"), "ares:lock:op-123");
    }

    #[test]
    fn test_credential_dedup_key() {
        let cred = Credential {
            id: "test".to_string(),
            username: "TestUser".to_string(),
            password: "Password123".to_string(), // pragma: allowlist secret
            domain: "CONTOSO.LOCAL".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        let key = build_credential_dedup_key(&cred);
        // Should be lowercase and use md5 of password
        assert!(key.starts_with("cred:contoso.local:testuser:"));
        assert_eq!(key.len(), "cred:contoso.local:testuser:".len() + 16);
    }
}
