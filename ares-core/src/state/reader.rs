//! Red team Redis state reader.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use redis::AsyncCommands;

use crate::models::{
    Credential, Hash, Host, OperationMeta, Share, SharedRedTeamState, Target, User,
    VulnerabilityInfo,
};

use super::dedup_keys::{build_credential_dedup_key, build_hash_dedup_key};
use super::keys::*;
use super::try_deserialize;

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
        super::build_key(&self.operation_id, suffix)
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
        let result = items
            .into_values()
            .filter_map(|json_str| try_deserialize(&json_str, "credential"))
            .collect();
        Ok(result)
    }

    /// Load all hashes from `ares:op:{id}:hashes` HASH.
    pub async fn get_hashes(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Hash>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_HASHES)).await?;
        let result = items
            .into_values()
            .filter_map(|json_str| try_deserialize(&json_str, "hash"))
            .collect();
        Ok(result)
    }

    /// Load all hosts from `ares:op:{id}:hosts` LIST.
    pub async fn get_hosts(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Host>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(KEY_HOSTS), 0, -1).await?;
        let result = items
            .iter()
            .filter_map(|json_str| try_deserialize(json_str, "host"))
            .collect();
        Ok(result)
    }

    /// Load all users from `ares:op:{id}:users` LIST.
    pub async fn get_users(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<User>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(KEY_USERS), 0, -1).await?;
        let result = items
            .iter()
            .filter_map(|json_str| try_deserialize(json_str, "user"))
            .collect();
        Ok(result)
    }

    /// Load all shares from `ares:op:{id}:shares` HASH.
    pub async fn get_shares(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Share>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_SHARES)).await?;
        let result = items
            .into_values()
            .filter_map(|json_str| try_deserialize(&json_str, "share"))
            .collect();
        Ok(result)
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
            if let Some(v) =
                try_deserialize::<VulnerabilityInfo>(&json_str, &format!("vulnerability {vuln_id}"))
            {
                result.insert(vuln_id, v);
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
        let exists: bool = conn
            .exists(super::build_lock_key(&self.operation_id))
            .await?;
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

        let trusted_domains = self.get_trusted_domains(conn).await.unwrap_or_default();
        let timeline_events = self.get_timeline(conn).await.unwrap_or_default();
        let techniques = self.get_techniques(conn).await.unwrap_or_default();

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
            discovered_vulnerabilities: vulnerabilities,
            exploited_vulnerabilities: exploited,
            has_domain_admin: meta.has_domain_admin,
            has_golden_ticket: meta.has_golden_ticket,
            domain_admin_path: meta.domain_admin_path,
            domain_controllers: dc_map,
            netbios_to_fqdn: netbios_map,
            trusted_domains,
            all_timeline_events: timeline_events,
            all_techniques: techniques,
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

    /// Add a user to Redis LIST (with dedup via username+domain).
    pub async fn add_user(
        &self,
        conn: &mut impl AsyncCommands,
        user: &User,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_USERS);
        let existing: Vec<String> = conn.lrange(&key, 0, -1).await?;
        let dedup_key = format!(
            "{}@{}",
            user.username.to_lowercase(),
            user.domain.to_lowercase()
        );
        for item in &existing {
            if let Ok(u) = serde_json::from_str::<User>(item) {
                let existing_key =
                    format!("{}@{}", u.username.to_lowercase(), u.domain.to_lowercase());
                if existing_key == dedup_key {
                    return Ok(false);
                }
            }
        }
        let data = serde_json::to_string(user).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(true)
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

    /// Set the RID-500 account name for a domain in the `admin_names` HASH.
    pub async fn set_admin_name(
        &self,
        conn: &mut impl AsyncCommands,
        domain: &str,
        name: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(KEY_ADMIN_NAMES);
        let _: () = conn.hset(&key, domain, name).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Add a share to `ares:op:{id}:shares` HASH (with dedup by host+name).
    pub async fn add_share(
        &self,
        conn: &mut impl AsyncCommands,
        share: &Share,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_SHARES);
        let dedup_field = format!(
            "{}:{}",
            share.host.to_lowercase(),
            share.name.to_lowercase()
        );
        let data = serde_json::to_string(share).unwrap_or_default();

        let added: bool = conn.hset_nx(&key, &dedup_field, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?;
        }
        Ok(added)
    }

    /// Add a timeline event to `ares:op:{id}:timeline` LIST.
    pub async fn add_timeline_event(
        &self,
        conn: &mut impl AsyncCommands,
        event: &serde_json::Value,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(KEY_TIMELINE);
        let data = serde_json::to_string(event).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Add a MITRE ATT&CK technique to `ares:op:{id}:techniques` SET.
    pub async fn add_technique(
        &self,
        conn: &mut impl AsyncCommands,
        technique_id: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_TECHNIQUES);
        let added: i64 = conn.sadd(&key, technique_id).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(added > 0)
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
        let events = items
            .iter()
            .filter_map(|item| serde_json::from_str::<serde_json::Value>(item).ok())
            .collect();
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

    /// Increment a vulnerability type failure counter.
    ///
    /// Key: `ares:op:{id}:vuln_type_failures` HASH — matches Python's `HINCRBY`
    /// for tracking per-vulnerability-type failure counts.
    pub async fn increment_vuln_type_failure(
        &self,
        conn: &mut impl AsyncCommands,
        vuln_type: &str,
    ) -> Result<i64, redis::RedisError> {
        let key = self.key(KEY_VULN_TYPE_FAILURES);
        let count: i64 = conn.hincr(&key, vuln_type, 1i64).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(count)
    }

    /// Get the failure count for a vulnerability type.
    pub async fn get_vuln_type_failure_count(
        &self,
        conn: &mut impl AsyncCommands,
        vuln_type: &str,
    ) -> Result<i64, redis::RedisError> {
        let key = self.key(KEY_VULN_TYPE_FAILURES);
        let count: Option<String> = conn.hget(&key, vuln_type).await?;
        Ok(count.and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    /// Get all vulnerability type failure counts.
    pub async fn get_all_vuln_type_failures(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<std::collections::HashMap<String, i64>, redis::RedisError> {
        let key = self.key(KEY_VULN_TYPE_FAILURES);
        let data: std::collections::HashMap<String, String> = conn.hgetall(&key).await?;
        let result = data
            .into_iter()
            .filter_map(|(k, v)| v.parse::<i64>().ok().map(|c| (k, c)))
            .collect();
        Ok(result)
    }

    /// Load trusted domains from `ares:op:{id}:trusted_domains` HASH.
    pub async fn get_trusted_domains(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, crate::models::TrustInfo>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(KEY_TRUSTED_DOMAINS)).await?;
        let mut result = HashMap::with_capacity(items.len());
        for (domain, json_str) in items {
            if let Some(trust) = try_deserialize(&json_str, &format!("trust {domain}")) {
                result.insert(domain, trust);
            }
        }
        Ok(result)
    }

    /// Add a trust relationship to `ares:op:{id}:trusted_domains` HASH.
    pub async fn add_trusted_domain(
        &self,
        conn: &mut impl AsyncCommands,
        trust: &crate::models::TrustInfo,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_TRUSTED_DOMAINS);
        let domain_key = trust.domain.to_lowercase();
        let data = serde_json::to_string(trust).unwrap_or_default();
        let added: bool = conn.hset_nx(&key, &domain_key, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?;
        }
        Ok(added)
    }

    /// Returns the key prefix for this operation: `ares:op:{op_id}`
    fn key_prefix(&self) -> String {
        format!("{KEY_PREFIX}:{}", self.operation_id)
    }
}
