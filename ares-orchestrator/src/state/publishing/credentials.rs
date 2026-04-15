//! Credential and hash publishing methods.

use anyhow::Result;

use ares_core::models::{Credential, Hash};
use ares_core::state::{self, RedisStateReader};

use crate::state::SharedState;
use crate::task_queue::TaskQueue;

use super::sanitize_credential;

impl SharedState {
    /// Add a credential to state and Redis (with dedup).
    ///
    /// Sanitizes the credential before storage (strips "Password:" prefix, trailing
    /// metadata, normalizes domains, rejects noise). When the credential's domain is
    /// a valid FQDN (contains a dot), it is automatically added to `state.domains`
    /// (matches Python's `add_credential()` behavior).
    pub async fn publish_credential(&self, queue: &TaskQueue, cred: Credential) -> Result<bool> {
        // Sanitize and validate before storage
        let netbios_map = {
            let state = self.inner.read().await;
            state.netbios_to_fqdn.clone()
        };
        let cred = match sanitize_credential(cred, &netbios_map) {
            Some(c) => c,
            None => return Ok(false),
        };

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_credential(&mut conn, &cred).await?;
        if added {
            // Auto-extract domain from credential (matches Python add_credential)
            let cred_domain = cred.domain.to_lowercase();
            if cred_domain.contains('.') {
                let mut state = self.inner.write().await;
                if !state.domains.contains(&cred_domain) {
                    state.domains.push(cred_domain.clone());
                    let domain_key = format!(
                        "{}:{}:{}",
                        state::KEY_PREFIX,
                        operation_id,
                        state::KEY_DOMAINS,
                    );
                    let _: Result<(), _> =
                        redis::AsyncCommands::sadd(&mut conn, &domain_key, &cred_domain).await;
                    let _: Result<(), _> =
                        redis::AsyncCommands::expire(&mut conn, &domain_key, 86400i64).await;
                    tracing::info!(
                        domain = %cred_domain,
                        username = %cred.username,
                        "Auto-extracted domain from credential"
                    );
                }
                state.credentials.push(cred);
            } else {
                let mut state = self.inner.write().await;
                state.credentials.push(cred);
            }
        }
        Ok(added)
    }

    /// Add a hash to state and Redis (with dedup).
    ///
    /// When a `krbtgt` NTLM hash is stored, `has_domain_admin` is automatically
    /// set — mirroring Python's `add_hash()` behaviour so that `auto_golden_ticket`
    /// triggers without requiring the LLM to emit a structured JSON payload.
    pub async fn publish_hash(&self, queue: &TaskQueue, hash: Hash) -> Result<bool> {
        use ares_core::models::VulnerabilityInfo;
        use std::collections::HashMap;

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_hash(&mut conn, &hash).await?;
        if added {
            let is_krbtgt = hash.username.to_lowercase() == "krbtgt"
                && hash.hash_type.to_lowercase().contains("ntlm");
            let hash_domain = hash.domain.clone();
            let mut state = self.inner.write().await;
            state.hashes.push(hash);

            // Track per-domain domination when krbtgt NTLM hash arrives
            if is_krbtgt {
                let krbtgt_domain = if hash_domain.is_empty() {
                    state.domains.first().cloned().unwrap_or_default()
                } else {
                    hash_domain.to_lowercase()
                };
                if !krbtgt_domain.is_empty() {
                    state.dominated_domains.insert(krbtgt_domain.clone());
                    tracing::info!(domain = %krbtgt_domain, "Domain dominated (krbtgt hash obtained)");
                }

                // Resolve DC target IP for vulnerability entry
                let dc_target = state
                    .domain_controllers
                    .get(&krbtgt_domain)
                    .cloned()
                    .unwrap_or_else(|| krbtgt_domain.clone());

                // Auto-set domain admin when first krbtgt NTLM hash arrives (matches Python)
                if !state.has_domain_admin {
                    drop(state);
                    let path = Some("secretsdump → krbtgt NTLM hash".to_string());
                    if let Err(e) = self.set_domain_admin(queue, path).await {
                        tracing::warn!(err = %e, "Failed to auto-set domain admin from krbtgt hash");
                    } else {
                        tracing::info!(
                            "🎯 Domain Admin auto-set from krbtgt NTLM hash in publish_hash"
                        );
                    }
                } else {
                    drop(state);
                }

                // Synthesize a dc_secretsdump vulnerability so the discovered
                // vulnerabilities list reflects the DA achievement path.
                let vuln_id = format!("dc_secretsdump_{}", krbtgt_domain);
                let mut details = HashMap::new();
                details.insert(
                    "domain".into(),
                    serde_json::Value::String(krbtgt_domain.clone()),
                );
                details.insert(
                    "note".into(),
                    serde_json::Value::String(
                        "Domain controller compromised via secretsdump — krbtgt NTLM hash extracted"
                            .to_string(),
                    ),
                );
                let vuln = VulnerabilityInfo {
                    vuln_id: vuln_id.clone(),
                    vuln_type: "dc_secretsdump".to_string(),
                    target: dc_target,
                    discovered_by: "credential_access".to_string(),
                    discovered_at: chrono::Utc::now(),
                    details,
                    recommended_agent: String::new(),
                    priority: 1,
                };
                let _ = self.publish_vulnerability(queue, vuln).await;
                let _ = self.mark_exploited(queue, &vuln_id).await;
            }
        }
        Ok(added)
    }

    /// Update a hash's `cracked_password` field in memory and Redis.
    ///
    /// Finds the first hash matching the given username and domain (case-insensitive)
    /// that has no cracked password yet, sets it, and persists the change to the Redis
    /// HASH by scanning fields and updating the matching entry.
    pub async fn update_hash_cracked_password(
        &self,
        queue: &TaskQueue,
        username: &str,
        domain: &str,
        password: &str,
    ) -> Result<bool> {
        // Update in-memory state and capture the updated hash for Redis persist
        let (op_id, hash_type) = {
            let mut state = self.inner.write().await;
            let idx = state.hashes.iter().position(|h| {
                h.username.eq_ignore_ascii_case(username)
                    && h.domain.eq_ignore_ascii_case(domain)
                    && h.cracked_password.is_none()
            });
            match idx {
                Some(i) => {
                    state.hashes[i].cracked_password = Some(password.to_string());
                    let ht = state.hashes[i].hash_type.clone();
                    (state.operation_id.clone(), ht)
                }
                None => return Ok(false),
            }
        };

        // Persist to Redis HASH: scan fields, find the matching entry, update it
        let hash_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_HASHES,);
        let mut conn = queue.connection();
        let entries: std::collections::HashMap<String, String> =
            redis::AsyncCommands::hgetall(&mut conn, &hash_key)
                .await
                .unwrap_or_default();
        for (field, value) in &entries {
            if let Ok(mut h) = serde_json::from_str::<Hash>(value) {
                if h.username.eq_ignore_ascii_case(username)
                    && h.domain.eq_ignore_ascii_case(domain)
                    && h.cracked_password.is_none()
                {
                    h.cracked_password = Some(password.to_string());
                    let updated_json = serde_json::to_string(&h).unwrap_or_default();
                    let _: Result<(), _> =
                        redis::AsyncCommands::hset(&mut conn, &hash_key, field, &updated_json)
                            .await;
                    break;
                }
            }
        }

        tracing::info!(
            username = %username,
            domain = %domain,
            hash_type = %hash_type,
            "Hash cracked_password updated in state and Redis"
        );

        Ok(true)
    }
}
