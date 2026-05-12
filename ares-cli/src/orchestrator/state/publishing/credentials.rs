//! Credential and hash publishing methods.

use anyhow::Result;

use ares_core::models::{Credential, Hash, OpStateEventPayload};
use ares_core::state::{self, RedisStateReader};

use redis::aio::ConnectionLike;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

use super::{emit_op_state, sanitize_credential};

impl SharedState {
    /// Add a credential to state and Redis (with dedup).
    ///
    /// Sanitizes the credential before storage (strips "Password:" prefix, trailing
    /// metadata, normalizes domains, rejects noise). When the credential's domain is
    /// a valid FQDN (contains a dot), it is automatically added to `state.domains`
    /// (matches Python's `add_credential()` behavior).
    pub async fn publish_credential(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        cred: Credential,
    ) -> Result<bool> {
        // Sanitize and validate before storage
        let (netbios_map, known_domains) = {
            let state = self.inner.read().await;
            // Known domains = explicit state.domains plus any DC domain keys.
            // We use this to snap typo'd FQDNs to their canonical form.
            let mut known: Vec<String> = state.domains.iter().map(|d| d.to_lowercase()).collect();
            for dc_domain in state.domain_controllers.keys() {
                let lower = dc_domain.to_lowercase();
                if !known.contains(&lower) {
                    known.push(lower);
                }
            }
            (state.netbios_to_fqdn.clone(), known)
        };
        let cred = match sanitize_credential(cred, &netbios_map, &known_domains) {
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
            // Phase 2 dual-write: append to the op-state log after Redis confirms
            // the credential is new (Redis is the dedup oracle).
            emit_op_state(
                self.recorder(),
                &operation_id,
                OpStateEventPayload::CredentialCaptured {
                    credential: cred.clone(),
                },
            )
            .await;

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
    pub async fn publish_hash(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        hash: Hash,
    ) -> Result<bool> {
        use ares_core::models::VulnerabilityInfo;
        use std::collections::HashMap;

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_hash(&mut conn, &hash).await?;
        if added {
            // Phase 2 dual-write: emit before consuming `hash` into state.
            emit_op_state(
                self.recorder(),
                &operation_id,
                OpStateEventPayload::HashCaptured { hash: hash.clone() },
            )
            .await;

            let is_krbtgt = hash.username.to_lowercase() == "krbtgt"
                && hash.hash_type.to_lowercase().contains("ntlm");
            let hash_domain = hash.domain.clone();
            let mut state = self.inner.write().await;
            state.hashes.push(hash);

            // Track per-domain domination when krbtgt NTLM hash arrives
            if is_krbtgt {
                let krbtgt_domain = if hash_domain.is_empty() {
                    // Resolve domain from sibling hashes produced by the same
                    // secretsdump run (same parent_id) that DO carry a domain.
                    // Prefer siblings whose domain matches a known DC domain to
                    // avoid misattribution when hashes from different domains
                    // share a parent_id.
                    let just_pushed = state.hashes.last();
                    let parent = just_pushed.and_then(|h| h.parent_id.as_deref());
                    parent
                        .and_then(|pid| {
                            // First pass: find a sibling whose domain matches a known DC
                            let from_dc = state.hashes.iter().find_map(|h| {
                                if h.parent_id.as_deref() == Some(pid) && !h.domain.is_empty() {
                                    let d = h.domain.to_lowercase();
                                    if state.domain_controllers.contains_key(&d) {
                                        return Some(d);
                                    }
                                }
                                None
                            });
                            // Fallback: any sibling with a domain
                            from_dc.or_else(|| {
                                state.hashes.iter().find_map(|h| {
                                    if h.parent_id.as_deref() == Some(pid) && !h.domain.is_empty() {
                                        Some(h.domain.to_lowercase())
                                    } else {
                                        None
                                    }
                                })
                            })
                        })
                        .unwrap_or_default()
                } else {
                    hash_domain.to_lowercase()
                };
                // Only mark as dominated if the domain is a known DC domain.
                // This prevents false domination claims from misattributed hashes
                // (e.g. when secretsdump output lacks a domain prefix and sibling
                // resolution picks up a hash from an unrelated domain).
                if !krbtgt_domain.is_empty()
                    && (state.domain_controllers.contains_key(&krbtgt_domain)
                        || state.domains.contains(&krbtgt_domain))
                {
                    if state.dominated_domains.insert(krbtgt_domain.clone()) {
                        tracing::info!(domain = %krbtgt_domain, "Domain dominated (krbtgt hash obtained)");
                    }
                } else if !krbtgt_domain.is_empty() {
                    tracing::warn!(
                        domain = %krbtgt_domain,
                        "krbtgt hash domain not in known domains/DCs — skipping domination"
                    );
                }

                // Resolve DC target IP for vulnerability entry. Only synthesize a
                // vuln when the krbtgt domain resolved to a known DC — otherwise we
                // emit a `dc_secretsdump on ` finding with empty target/domain.
                let dc_target = state.domain_controllers.get(&krbtgt_domain).cloned();

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
                if let Some(dc_target) = dc_target {
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
                } else {
                    tracing::warn!(
                        domain = %krbtgt_domain,
                        "krbtgt hash without resolvable DC target — skipping dc_secretsdump vuln synthesis"
                    );
                }
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
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::op_state_log::OpStateRecorder;
    use ares_core::state::mock_redis::MockRedisConnection;
    use std::sync::Arc;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    fn capturing_state(op_id: &str) -> (SharedState, Arc<OpStateRecorder>) {
        let recorder = Arc::new(OpStateRecorder::capturing());
        let state = SharedState::with_recorder(op_id.to_string(), recorder.clone());
        (state, recorder)
    }

    fn make_cred(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: "test".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(username: &str, domain: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            hash_type: hash_type.to_string(),
            hash_value: hash_value.to_string(),
            source: "test".to_string(),
            discovered_at: None,
            cracked_password: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }
    }

    #[tokio::test]
    async fn publish_credential_adds_to_state() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let cred = make_cred("alice", "P@ssw0rd!", "contoso.local");
        let added = state.publish_credential(&q, cred).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.credentials.len(), 1);
        assert_eq!(s.credentials[0].username, "alice");
    }

    #[tokio::test]
    async fn publish_credential_dedup() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let cred1 = make_cred("alice", "P@ssw0rd!", "contoso.local");
        let cred2 = make_cred("alice", "P@ssw0rd!", "contoso.local");
        assert!(state.publish_credential(&q, cred1).await.unwrap());
        assert!(!state.publish_credential(&q, cred2).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.credentials.len(), 1);
    }

    #[tokio::test]
    async fn publish_credential_auto_extracts_domain() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let cred = make_cred("alice", "P@ssw0rd!", "contoso.local");
        state.publish_credential(&q, cred).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.domains.contains(&"contoso.local".to_string()));
    }

    #[tokio::test]
    async fn publish_credential_rejects_invalid() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Empty password should be rejected by sanitize_credential
        let cred = make_cred("alice", "", "contoso.local");
        let added = state.publish_credential(&q, cred).await.unwrap();
        assert!(!added);

        let s = state.inner.read().await;
        assert!(s.credentials.is_empty());
    }

    #[tokio::test]
    async fn publish_credential_no_domain_extraction_for_short() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Domain without dots should not be added to domains list
        let cred = make_cred("alice", "P@ssw0rd!", "CONTOSO");
        state.publish_credential(&q, cred).await.unwrap();

        let s = state.inner.read().await;
        // Domain "CONTOSO" has no dot, so it's not auto-extracted
        assert!(!s.domains.iter().any(|d| d == "contoso"));
    }

    #[tokio::test]
    async fn publish_hash_adds_to_state() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash = make_hash("admin", "contoso.local", "NTLM", "aabbccdd");
        let added = state.publish_hash(&q, hash).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].username, "admin");
    }

    #[tokio::test]
    async fn publish_hash_dedup() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash1 = make_hash("admin", "contoso.local", "NTLM", "aabbccdd");
        let hash2 = make_hash("admin", "contoso.local", "NTLM", "aabbccdd");
        assert!(state.publish_hash(&q, hash1).await.unwrap());
        assert!(!state.publish_hash(&q, hash2).await.unwrap());
    }

    #[tokio::test]
    async fn publish_krbtgt_hash_sets_domain_admin() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Set up a known domain so domination check passes
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let hash = make_hash("krbtgt", "contoso.local", "NTLM", "aabbccdd11223344");
        state.publish_hash(&q, hash).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.has_domain_admin);
        assert!(s.dominated_domains.contains("contoso.local"));
    }

    #[tokio::test]
    async fn publish_krbtgt_hash_without_resolvable_domain_skips_vuln() {
        // Regression: a krbtgt hash with no domain prefix and no siblings to
        // resolve from used to synthesize a `dc_secretsdump` vuln with empty
        // target/domain — surfacing as `dc_secretsdump on ` in the report.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash = make_hash("krbtgt", "", "NTLM", "aabbccdd11223344");
        state.publish_hash(&q, hash).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            !s.discovered_vulnerabilities
                .values()
                .any(|v| v.vuln_type == "dc_secretsdump"),
            "should not synthesize dc_secretsdump vuln when domain is unresolvable"
        );
        assert!(s.dominated_domains.is_empty());
    }

    #[tokio::test]
    async fn update_hash_cracked_password() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash = make_hash("admin", "contoso.local", "NTLM", "aabbccdd");
        state.publish_hash(&q, hash).await.unwrap();

        let updated = state
            .update_hash_cracked_password(&q, "admin", "contoso.local", "CrackedPW!")
            .await
            .unwrap();
        assert!(updated);

        let s = state.inner.read().await;
        assert_eq!(s.hashes[0].cracked_password.as_deref(), Some("CrackedPW!"));
    }

    #[tokio::test]
    async fn update_hash_cracked_password_not_found() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let updated = state
            .update_hash_cracked_password(&q, "nobody", "contoso.local", "pw")
            .await
            .unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn publish_credential_emits_event_with_capturing_recorder() {
        let (state, recorder) = capturing_state("op-emit");
        let q = mock_queue();
        let cred = make_cred("alice", "P@ssw0rd!", "contoso.local");
        assert!(state.publish_credential(&q, cred).await.unwrap());

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1, "exactly one event should be emitted");
        assert_eq!(evs[0].op_id, "op-emit");
        match &evs[0].payload {
            OpStateEventPayload::CredentialCaptured { credential } => {
                assert_eq!(credential.username, "alice");
                assert_eq!(credential.domain, "contoso.local");
            }
            other => panic!("expected CredentialCaptured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_credential_dedup_does_not_emit_duplicate_event() {
        let (state, recorder) = capturing_state("op-dedup");
        let q = mock_queue();
        let cred1 = make_cred("alice", "P@ssw0rd!", "contoso.local");
        let cred2 = make_cred("alice", "P@ssw0rd!", "contoso.local");
        assert!(state.publish_credential(&q, cred1).await.unwrap());
        assert!(!state.publish_credential(&q, cred2).await.unwrap());

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1, "dedup'd insert must not emit a second event");
    }

    #[tokio::test]
    async fn publish_credential_rejected_input_does_not_emit() {
        // Invalid credential (empty password) is dropped by sanitize_credential
        // before any Redis write — must not emit an event either.
        let (state, recorder) = capturing_state("op-reject");
        let q = mock_queue();
        let cred = make_cred("alice", "", "contoso.local");
        assert!(!state.publish_credential(&q, cred).await.unwrap());
        assert!(recorder.captured().await.is_empty());
    }

    #[tokio::test]
    async fn publish_hash_emits_event_with_capturing_recorder() {
        let (state, recorder) = capturing_state("op-h");
        let q = mock_queue();
        let hash = make_hash("admin", "contoso.local", "NTLM", "aabbccdd");
        assert!(state.publish_hash(&q, hash).await.unwrap());

        let evs = recorder.captured().await;
        // krbtgt path emits multiple events (hash + vuln + exploited). Plain
        // admin hash only emits hash.captured.
        assert_eq!(evs.len(), 1);
        match &evs[0].payload {
            OpStateEventPayload::HashCaptured { hash } => {
                assert_eq!(hash.username, "admin");
                assert_eq!(hash.hash_type, "NTLM");
            }
            other => panic!("expected HashCaptured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disabled_recorder_emits_nothing() {
        // SharedState::new() defaults to OpStateRecorder::Disabled.
        let state = SharedState::new("op-noop".to_string());
        let q = mock_queue();
        state
            .publish_credential(&q, make_cred("alice", "P@ssw0rd!", "contoso.local"))
            .await
            .unwrap();
        // No recorder handle to inspect — the assertion here is "no panic and
        // no async hang on the no-op record path". Combined with the active
        // tests above, this exercises both branches of `is_active`.
    }
}
