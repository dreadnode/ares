//! Red team Redis state reader.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use redis::AsyncCommands;

use crate::models::{
    Credential, Hash, Host, KerberosTicket, OperationMeta, Share, SharedRedTeamState, Target, User,
    VulnerabilityInfo,
};

use super::dedup_keys::{build_credential_dedup_key, build_hash_dedup_key, parse_ntlm_dedup_key};
use super::keys::*;
use super::try_deserialize;

/// Read-only Redis state backend for CLI operations.
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
            red_completed_at: meta.red_completed_at,
            red_completion_reason: meta.red_completion_reason,
            red_blocked_on_blue: meta.red_blocked_on_blue,
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
    /// Dedup key format: `cred:{domain}:{username}:{password_md5_16}`.
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
    /// Dedup key built via `super::dedup_keys::hash_dedup_key`.
    ///
    /// For NTLM rows, also collapses qualified vs unqualified domain duplicates
    /// across distinct dedup keys: `DC01$` (empty domain) and
    /// `contoso.local\DC01$` (qualified) hash to different fields but
    /// represent the same secret. Pre-scan existing fields and:
    ///
    ///   - skip the insert if incoming has empty domain and a populated-domain
    ///     entry already exists (qualified wins);
    ///   - delete any empty-domain shadow when inserting a populated-domain
    ///     entry.
    ///
    /// Cross-domain qualified entries (e.g. same hash on two different AD
    /// domains, as can happen in lab environments) are preserved.
    pub async fn add_hash(
        &self,
        conn: &mut impl AsyncCommands,
        hash: &Hash,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(KEY_HASHES);
        let dedup_field = build_hash_dedup_key(hash);
        let data = serde_json::to_string(hash).unwrap_or_default();

        if let Some((incoming_domain, incoming_user, incoming_hash)) =
            parse_ntlm_dedup_key(&dedup_field)
        {
            let existing_fields: Vec<String> = conn.hkeys(&key).await?;
            for field in &existing_fields {
                let Some((existing_domain, existing_user, existing_hash)) =
                    parse_ntlm_dedup_key(field)
                else {
                    continue;
                };
                if existing_user != incoming_user || existing_hash != incoming_hash {
                    continue;
                }
                if incoming_domain.is_empty() && !existing_domain.is_empty() {
                    return Ok(false);
                }
                if !incoming_domain.is_empty() && existing_domain.is_empty() {
                    let _: i64 = conn.hdel(&key, field).await?;
                }
            }
        }

        let added: bool = conn.hset_nx(&key, &dedup_field, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?;
            return Ok(true);
        }

        // Upsert path: a prior call added this user/hash with no AES256 key,
        // and this call carries one. Win2016+ DCs reject RC4-only inter-realm
        // tickets, so the AES key is required for cross-forest forge — we
        // can't afford to lose it to dedup.
        if hash.aes_key.is_some() {
            let existing: Option<String> = conn.hget(&key, &dedup_field).await?;
            let existing_has_aes = existing
                .as_deref()
                .and_then(|s| serde_json::from_str::<Hash>(s).ok())
                .and_then(|h| h.aes_key)
                .is_some();
            if !existing_has_aes {
                let _: () = conn.hset(&key, &dedup_field, &data).await?;
                let _: () = conn.expire(&key, 86400).await?;
            }
        }
        Ok(false)
    }

    /// Set a meta field in the operation's meta HASH.
    ///
    /// Values are JSON-encoded.
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

    /// Get a domain SID from the `domain_sids` HASH.
    pub async fn get_domain_sid(
        &self,
        conn: &mut impl AsyncCommands,
        domain: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let key = self.key(KEY_DOMAIN_SIDS);
        let sid: Option<String> = conn.hget(&key, domain).await?;
        Ok(sid)
    }

    /// Get all domain SIDs from the `domain_sids` HASH (lowercase keys).
    pub async fn get_domain_sids(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, String>, redis::RedisError> {
        let key = self.key(KEY_DOMAIN_SIDS);
        let data: HashMap<String, String> = conn.hgetall(&key).await?;
        Ok(data)
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

    /// Get the RID-500 account name for a domain from the `admin_names` HASH.
    pub async fn get_admin_name(
        &self,
        conn: &mut impl AsyncCommands,
        domain: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let key = self.key(KEY_ADMIN_NAMES);
        let name: Option<String> = conn.hget(&key, domain).await?;
        Ok(name)
    }

    /// Add a forged inter-realm Kerberos ticket to `ares:op:{id}:kerberos_tickets` HASH.
    ///
    /// Keyed by `{source}:{target}:{username}` for dedup. A newer ticket for
    /// the same principal silently overwrites the old one (`HSET`, not `HSETNX`).
    pub async fn add_kerberos_ticket(
        &self,
        conn: &mut impl AsyncCommands,
        ticket: &KerberosTicket,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(KEY_KERBEROS_TICKETS);
        let field = ticket.dedup_key();
        let data = serde_json::to_string(ticket).unwrap_or_default();
        let _: () = conn.hset(&key, &field, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Load all forged Kerberos tickets from `ares:op:{id}:kerberos_tickets` HASH.
    pub async fn get_kerberos_tickets(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<KerberosTicket>, redis::RedisError> {
        let key = self.key(KEY_KERBEROS_TICKETS);
        let items: std::collections::HashMap<String, String> = conn.hgetall(&key).await?;
        let result = items
            .into_values()
            .filter_map(|json_str| try_deserialize(&json_str, "kerberos_ticket"))
            .collect();
        Ok(result)
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
    /// Key: `ares:op:{id}:vuln_type_failures` HASH — `HINCRBY` per vulnerability
    /// type for tracking failure counts.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use crate::state::mock_redis::MockRedisConnection;
    use redis::AsyncCommands;
    use serde_json::json;

    fn make_reader() -> RedisStateReader {
        RedisStateReader::new("op-test".to_string())
    }

    fn make_credential(user: &str, domain: &str, pass: &str) -> Credential {
        Credential {
            id: format!("cred-{user}"),
            username: user.to_string(),
            password: pass.to_string(),
            domain: domain.to_string(),
            source: "test".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(user: &str, domain: &str, hash_value: &str) -> Hash {
        Hash {
            id: format!("hash-{user}"),
            username: user.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: "secretsdump".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn make_host(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        }
    }

    fn make_user(username: &str, domain: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: "ldap".to_string(),
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

    fn make_vuln(vuln_id: &str, vuln_type: &str, target: &str) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: target.to_string(),
            discovered_by: "recon-1".to_string(),
            discovered_at: chrono::Utc::now(),
            details: HashMap::new(),
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn make_trust(domain: &str, trust_type: &str) -> TrustInfo {
        TrustInfo {
            domain: domain.to_string(),
            flat_name: domain.split('.').next().unwrap_or("").to_uppercase(),
            direction: "bidirectional".to_string(),
            trust_type: trust_type.to_string(),
            sid_filtering: false,
            security_identifier: None,
        }
    }

    // -- exists ---------------------------------------------------------------

    #[tokio::test]
    async fn exists_empty_returns_false() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        assert!(!reader.exists(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn exists_after_set_meta_field_returns_true() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        reader
            .set_meta_field(&mut conn, "target_ip", &json!("192.168.58.1"))
            .await
            .unwrap();
        assert!(reader.exists(&mut conn).await.unwrap());
    }

    // -- get_meta / set_meta_field -------------------------------------------

    #[tokio::test]
    async fn get_meta_empty_returns_defaults() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let meta = reader.get_meta(&mut conn).await.unwrap();
        assert!(!meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.target_ip.is_none());
        assert!(meta.target_domain.is_none());
    }

    #[tokio::test]
    async fn set_and_get_meta_fields() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        reader
            .set_meta_field(&mut conn, "target_ip", &json!("192.168.58.10"))
            .await
            .unwrap();
        reader
            .set_meta_field(&mut conn, "target_domain", &json!("contoso.local"))
            .await
            .unwrap();
        reader
            .set_meta_field(&mut conn, "has_domain_admin", &json!(true))
            .await
            .unwrap();

        let meta = reader.get_meta(&mut conn).await.unwrap();
        assert_eq!(meta.target_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(meta.target_domain.as_deref(), Some("contoso.local"));
        assert!(meta.has_domain_admin);
    }

    // -- get_credentials / add_credential ------------------------------------

    #[tokio::test]
    async fn get_credentials_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let creds = reader.get_credentials(&mut conn).await.unwrap();
        assert!(creds.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_credential() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let cred = make_credential("admin", "contoso.local", "P@ssw0rd!");
        let added = reader.add_credential(&mut conn, &cred).await.unwrap();
        assert!(added);

        let creds = reader.get_credentials(&mut conn).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "admin");
        assert_eq!(creds[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn add_credential_dedup_rejects_duplicate() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let cred = make_credential("admin", "contoso.local", "P@ssw0rd!");
        assert!(reader.add_credential(&mut conn, &cred).await.unwrap());
        assert!(!reader.add_credential(&mut conn, &cred).await.unwrap());

        let creds = reader.get_credentials(&mut conn).await.unwrap();
        assert_eq!(creds.len(), 1);
    }

    // -- get_hashes / add_hash -----------------------------------------------

    #[tokio::test]
    async fn get_hashes_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let hashes = reader.get_hashes(&mut conn).await.unwrap();
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_hash() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let hash = make_hash("admin", "contoso.local", "aad3b435b51404eeaad3b435b51404ee");
        let added = reader.add_hash(&mut conn, &hash).await.unwrap();
        assert!(added);

        let hashes = reader.get_hashes(&mut conn).await.unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "admin");
    }

    #[tokio::test]
    async fn add_hash_dedup_rejects_duplicate() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let hash = make_hash("admin", "contoso.local", "aad3b435b51404eeaad3b435b51404ee");
        assert!(reader.add_hash(&mut conn, &hash).await.unwrap());
        assert!(!reader.add_hash(&mut conn, &hash).await.unwrap());

        let hashes = reader.get_hashes(&mut conn).await.unwrap();
        assert_eq!(hashes.len(), 1);
    }

    #[tokio::test]
    async fn add_hash_skips_empty_domain_when_qualified_exists() {
        // Insert a qualified entry first, then attempt an empty-domain insert
        // for the same (user, hash). The empty-domain version is a degraded
        // shadow of the qualified one and must be rejected.
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let qualified = make_hash(
            "DC01$",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:a3f11b5a18f97db9a3d4f16aed85a1b6",
        );
        let unqualified = make_hash(
            "DC01$",
            "",
            "aad3b435b51404eeaad3b435b51404ee:a3f11b5a18f97db9a3d4f16aed85a1b6",
        );
        assert!(reader.add_hash(&mut conn, &qualified).await.unwrap());
        assert!(!reader.add_hash(&mut conn, &unqualified).await.unwrap());

        let hashes = reader.get_hashes(&mut conn).await.unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn add_hash_replaces_empty_domain_with_qualified() {
        // Inverse: an empty-domain row was inserted first (e.g. unprefixed
        // line in a secretsdump batch). When the qualified version arrives
        // later, the shadow should be replaced — qualified wins.
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let unqualified = make_hash(
            "DC01$",
            "",
            "aad3b435b51404eeaad3b435b51404ee:a3f11b5a18f97db9a3d4f16aed85a1b6",
        );
        let qualified = make_hash(
            "DC01$",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:a3f11b5a18f97db9a3d4f16aed85a1b6",
        );
        assert!(reader.add_hash(&mut conn, &unqualified).await.unwrap());
        assert!(reader.add_hash(&mut conn, &qualified).await.unwrap());

        let hashes = reader.get_hashes(&mut conn).await.unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn add_hash_keeps_distinct_qualified_domains() {
        // Two qualified entries with the same (user, hash) but different
        // domains represent the same secret usable across realms (a real
        // pattern in trusted/seeded labs). Both records must be preserved
        // so cross-domain attribution survives.
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let h1 = make_hash(
            "Administrator",
            "fabrikam.local",
            "aad3b435b51404eeaad3b435b51404ee:2e993405ab82e4454afc9c9bb0939a25",
        );
        let h2 = make_hash(
            "Administrator",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:2e993405ab82e4454afc9c9bb0939a25",
        );
        assert!(reader.add_hash(&mut conn, &h1).await.unwrap());
        assert!(reader.add_hash(&mut conn, &h2).await.unwrap());

        let hashes = reader.get_hashes(&mut conn).await.unwrap();
        assert_eq!(hashes.len(), 2);
    }

    // -- get_hosts / add_host ------------------------------------------------

    #[tokio::test]
    async fn get_hosts_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let hosts = reader.get_hosts(&mut conn).await.unwrap();
        assert!(hosts.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_host() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let host = make_host("192.168.58.5", "dc01.contoso.local");
        reader.add_host(&mut conn, &host).await.unwrap();

        let hosts = reader.get_hosts(&mut conn).await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.58.5");
        assert_eq!(hosts[0].hostname, "dc01.contoso.local");
    }

    // -- get_users / add_user ------------------------------------------------

    #[tokio::test]
    async fn get_users_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let users = reader.get_users(&mut conn).await.unwrap();
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_user() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let user = make_user("jdoe", "contoso.local");
        let added = reader.add_user(&mut conn, &user).await.unwrap();
        assert!(added);

        let users = reader.get_users(&mut conn).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "jdoe");
    }

    #[tokio::test]
    async fn add_user_dedup_by_username_domain() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let user = make_user("jdoe", "contoso.local");
        assert!(reader.add_user(&mut conn, &user).await.unwrap());
        // Same user again, possibly different case
        let user_dup = make_user("JDoe", "CONTOSO.LOCAL");
        assert!(!reader.add_user(&mut conn, &user_dup).await.unwrap());

        let users = reader.get_users(&mut conn).await.unwrap();
        assert_eq!(users.len(), 1);
    }

    // -- get_shares / add_share ----------------------------------------------

    #[tokio::test]
    async fn get_shares_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let shares = reader.get_shares(&mut conn).await.unwrap();
        assert!(shares.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_share() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let share = make_share("192.168.58.5", "ADMIN$");
        let added = reader.add_share(&mut conn, &share).await.unwrap();
        assert!(added);

        let shares = reader.get_shares(&mut conn).await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "ADMIN$");
    }

    #[tokio::test]
    async fn add_share_dedup_by_host_name() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let share = make_share("192.168.58.5", "ADMIN$");
        assert!(reader.add_share(&mut conn, &share).await.unwrap());
        assert!(!reader.add_share(&mut conn, &share).await.unwrap());

        let shares = reader.get_shares(&mut conn).await.unwrap();
        assert_eq!(shares.len(), 1);
    }

    // -- get_domains / add_domain --------------------------------------------

    #[tokio::test]
    async fn get_domains_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let domains = reader.get_domains(&mut conn).await.unwrap();
        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_domain() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let added = reader.add_domain(&mut conn, "contoso.local").await.unwrap();
        assert!(added);

        let domains = reader.get_domains(&mut conn).await.unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "contoso.local");
    }

    #[tokio::test]
    async fn add_domain_dedup_via_set() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        assert!(reader.add_domain(&mut conn, "contoso.local").await.unwrap());
        assert!(!reader.add_domain(&mut conn, "contoso.local").await.unwrap());

        let domains = reader.get_domains(&mut conn).await.unwrap();
        assert_eq!(domains.len(), 1);
    }

    // -- get_vulnerabilities / add_vulnerability -----------------------------

    #[tokio::test]
    async fn get_vulnerabilities_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let vulns = reader.get_vulnerabilities(&mut conn).await.unwrap();
        assert!(vulns.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_vulnerability() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let vuln = make_vuln("esc1_192.168.58.5", "ADCS_ESC1", "192.168.58.5");
        let added = reader.add_vulnerability(&mut conn, &vuln).await.unwrap();
        assert!(added);

        let vulns = reader.get_vulnerabilities(&mut conn).await.unwrap();
        assert_eq!(vulns.len(), 1);
        assert!(vulns.contains_key("esc1_192.168.58.5"));
        assert_eq!(vulns["esc1_192.168.58.5"].vuln_type, "ADCS_ESC1");
    }

    // -- get_exploited_vulnerabilities (via mock directly) -------------------

    #[tokio::test]
    async fn get_exploited_vulnerabilities_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let exploited = reader
            .get_exploited_vulnerabilities(&mut conn)
            .await
            .unwrap();
        assert!(exploited.is_empty());
    }

    #[tokio::test]
    async fn get_exploited_vulnerabilities_with_data() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let key = "ares:op:op-test:exploited".to_string();
        let _: () = conn.sadd(&key, "esc1_192.168.58.5").await.unwrap();
        let _: () = conn.sadd(&key, "deleg_svc_sql").await.unwrap();

        let exploited = reader
            .get_exploited_vulnerabilities(&mut conn)
            .await
            .unwrap();
        assert_eq!(exploited.len(), 2);
        assert!(exploited.contains("esc1_192.168.58.5"));
        assert!(exploited.contains("deleg_svc_sql"));
    }

    // -- get_dc_map / get_netbios_map (via mock directly) --------------------

    #[tokio::test]
    async fn get_dc_map_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let dc_map = reader.get_dc_map(&mut conn).await.unwrap();
        assert!(dc_map.is_empty());
    }

    #[tokio::test]
    async fn get_dc_map_with_data() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let key = "ares:op:op-test:dc_map".to_string();
        let _: () = conn
            .hset(&key, "192.168.58.5", "dc01.contoso.local")
            .await
            .unwrap();

        let dc_map = reader.get_dc_map(&mut conn).await.unwrap();
        assert_eq!(dc_map.len(), 1);
        assert_eq!(dc_map["192.168.58.5"], "dc01.contoso.local");
    }

    #[tokio::test]
    async fn get_netbios_map_with_data() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let key = "ares:op:op-test:netbios_map".to_string();
        let _: () = conn.hset(&key, "CONTOSO", "contoso.local").await.unwrap();

        let nb_map = reader.get_netbios_map(&mut conn).await.unwrap();
        assert_eq!(nb_map.len(), 1);
        assert_eq!(nb_map["CONTOSO"], "contoso.local");
    }

    // -- is_running ----------------------------------------------------------

    #[tokio::test]
    async fn is_running_false_when_no_lock() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        assert!(!reader.is_running(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn is_running_true_when_lock_exists() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let lock_key = "ares:lock:op-test";
        let _: () = conn.set(lock_key, "1").await.unwrap();
        assert!(reader.is_running(&mut conn).await.unwrap());
    }

    // -- add_timeline_event / get_timeline -----------------------------------

    #[tokio::test]
    async fn get_timeline_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let timeline = reader.get_timeline(&mut conn).await.unwrap();
        assert!(timeline.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_timeline_events() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let event = json!({
            "timestamp": "2025-01-28T12:00:00Z",
            "description": "Initial access via kerberoast",
            "mitre_techniques": ["T1558.003"]
        });
        reader.add_timeline_event(&mut conn, &event).await.unwrap();

        let timeline = reader.get_timeline(&mut conn).await.unwrap();
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0]["description"], "Initial access via kerberoast");
    }

    // -- add_technique / get_techniques --------------------------------------

    #[tokio::test]
    async fn get_techniques_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let techniques = reader.get_techniques(&mut conn).await.unwrap();
        assert!(techniques.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_techniques() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        assert!(reader.add_technique(&mut conn, "T1558.003").await.unwrap());
        assert!(reader.add_technique(&mut conn, "T1003.006").await.unwrap());
        // Duplicate is rejected by set
        assert!(!reader.add_technique(&mut conn, "T1558.003").await.unwrap());

        let techniques = reader.get_techniques(&mut conn).await.unwrap();
        assert_eq!(techniques.len(), 2);
    }

    // -- get_report ----------------------------------------------------------

    #[tokio::test]
    async fn get_report_none_when_missing() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let report = reader.get_report(&mut conn).await.unwrap();
        assert!(report.is_none());
    }

    #[tokio::test]
    async fn get_report_returns_stored_string() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let key = "ares:op:op-test:report";
        let _: () = conn
            .set(key, "# Report\nDomain admin achieved.")
            .await
            .unwrap();

        let report = reader.get_report(&mut conn).await.unwrap();
        assert_eq!(report.as_deref(), Some("# Report\nDomain admin achieved."));
    }

    // -- increment_vuln_type_failure / get_vuln_type_failure_count / get_all --

    #[tokio::test]
    async fn vuln_type_failure_count_starts_at_zero() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let count = reader
            .get_vuln_type_failure_count(&mut conn, "ADCS_ESC1")
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn increment_and_get_vuln_type_failure() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let c1 = reader
            .increment_vuln_type_failure(&mut conn, "ADCS_ESC1")
            .await
            .unwrap();
        assert_eq!(c1, 1);
        let c2 = reader
            .increment_vuln_type_failure(&mut conn, "ADCS_ESC1")
            .await
            .unwrap();
        assert_eq!(c2, 2);

        let count = reader
            .get_vuln_type_failure_count(&mut conn, "ADCS_ESC1")
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn get_all_vuln_type_failures() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        reader
            .increment_vuln_type_failure(&mut conn, "ADCS_ESC1")
            .await
            .unwrap();
        reader
            .increment_vuln_type_failure(&mut conn, "ADCS_ESC1")
            .await
            .unwrap();
        reader
            .increment_vuln_type_failure(&mut conn, "delegation")
            .await
            .unwrap();

        let all = reader.get_all_vuln_type_failures(&mut conn).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all["ADCS_ESC1"], 2);
        assert_eq!(all["delegation"], 1);
    }

    // -- get_trusted_domains / add_trusted_domain ----------------------------

    #[tokio::test]
    async fn get_trusted_domains_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let trusted = reader.get_trusted_domains(&mut conn).await.unwrap();
        assert!(trusted.is_empty());
    }

    #[tokio::test]
    async fn add_and_get_trusted_domain() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let trust = make_trust("child.contoso.local", "parent_child");
        let added = reader.add_trusted_domain(&mut conn, &trust).await.unwrap();
        assert!(added);

        let trusted = reader.get_trusted_domains(&mut conn).await.unwrap();
        assert_eq!(trusted.len(), 1);
        assert!(trusted.contains_key("child.contoso.local"));
        assert!(trusted["child.contoso.local"].is_parent_child());
    }

    #[tokio::test]
    async fn add_trusted_domain_dedup() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let trust = make_trust("child.contoso.local", "parent_child");
        assert!(reader.add_trusted_domain(&mut conn, &trust).await.unwrap());
        assert!(!reader.add_trusted_domain(&mut conn, &trust).await.unwrap());
    }

    // -- set_domain_sid / set_admin_name -------------------------------------

    #[tokio::test]
    async fn set_domain_sid_stores_value() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        reader
            .set_domain_sid(&mut conn, "contoso.local", "S-1-5-21-123456789")
            .await
            .unwrap();

        let key = "ares:op:op-test:domain_sids";
        let sid: Option<String> = conn.hget(key, "contoso.local").await.unwrap();
        assert_eq!(sid.as_deref(), Some("S-1-5-21-123456789"));
    }

    #[tokio::test]
    async fn set_admin_name_stores_value() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        reader
            .set_admin_name(&mut conn, "contoso.local", "Administrator")
            .await
            .unwrap();

        let key = "ares:op:op-test:admin_names";
        let name: Option<String> = conn.hget(key, "contoso.local").await.unwrap();
        assert_eq!(name.as_deref(), Some("Administrator"));
    }

    // -- load_state ----------------------------------------------------------

    #[tokio::test]
    async fn load_state_returns_none_when_empty() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();
        let state = reader.load_state(&mut conn).await.unwrap();
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn load_state_full_roundtrip() {
        let mut conn = MockRedisConnection::new();
        let reader = make_reader();

        // Set meta fields
        reader
            .set_meta_field(&mut conn, "target_ip", &json!("192.168.58.10"))
            .await
            .unwrap();
        reader
            .set_meta_field(&mut conn, "target_domain", &json!("contoso.local"))
            .await
            .unwrap();
        reader
            .set_meta_field(&mut conn, "has_domain_admin", &json!(true))
            .await
            .unwrap();

        // Add data
        let cred = make_credential("admin", "contoso.local", "P@ssw0rd!");
        reader.add_credential(&mut conn, &cred).await.unwrap();

        let host = make_host("192.168.58.5", "dc01.contoso.local");
        reader.add_host(&mut conn, &host).await.unwrap();

        reader.add_domain(&mut conn, "contoso.local").await.unwrap();

        reader.add_technique(&mut conn, "T1558.003").await.unwrap();

        let event = json!({"timestamp": "2025-01-28T12:00:00Z", "description": "started"});
        reader.add_timeline_event(&mut conn, &event).await.unwrap();

        let trust = make_trust("child.contoso.local", "parent_child");
        reader.add_trusted_domain(&mut conn, &trust).await.unwrap();

        // Load full state
        let state = reader.load_state(&mut conn).await.unwrap();
        assert!(state.is_some());
        let state = state.unwrap();

        assert_eq!(state.operation_id, "op-test");
        assert!(state.has_domain_admin);
        assert!(state.target.is_some());
        assert_eq!(state.target.as_ref().unwrap().ip, "192.168.58.10");
        assert_eq!(state.all_credentials.len(), 1);
        assert_eq!(state.all_hosts.len(), 1);
        assert_eq!(state.all_domains.len(), 1);
        assert_eq!(state.all_techniques.len(), 1);
        assert_eq!(state.all_timeline_events.len(), 1);
        assert_eq!(state.trusted_domains.len(), 1);
    }
}
