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
    Credential, Hash, Host, OperationMeta, Share, SharedRedTeamState, Target, User,
    VulnerabilityInfo,
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
