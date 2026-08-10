//! Credential and hash publishing methods.

use anyhow::Result;

use ares_core::models::{Credential, Hash, OpStateEventPayload};
use ares_core::state::{self, RedisStateReader};

use redis::aio::ConnectionLike;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

use super::{credential_source_trust, emit_op_state, sanitize_credential, strip_netexec_artifact};

fn is_hex32(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_ntlm_hash_value(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    match parts.as_slice() {
        [nt] => is_hex32(nt),
        [lm, nt] => is_hex32(lm) && is_hex32(nt),
        _ => false,
    }
}

fn krbtgt_nt_half(hash: &Hash) -> Option<&str> {
    if !hash.username.trim().eq_ignore_ascii_case("krbtgt")
        || !hash.hash_type.to_lowercase().contains("ntlm")
        || hash.domain.trim().is_empty()
    {
        return None;
    }
    let value = hash.hash_value.trim();
    let nt = value.rsplit(':').next().unwrap_or(value);
    is_hex32(nt).then_some(nt)
}

impl SharedState {
    /// Add a credential to state and Redis (with dedup).
    ///
    /// Sanitizes the credential before storage (strips "Password:" prefix, trailing
    /// metadata, normalizes domains, rejects noise). The credential's `domain`
    /// field is stored as-is on the credential, but is NEVER promoted into the
    /// canonical `state.domains` registry — that registry is reserved for
    /// authoritative recon (LDAP root DSE, DC enumeration, trust queries) so an
    /// LLM-supplied typo like `child.contossso.com` cannot pollute the
    /// global view.
    pub async fn publish_credential(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        cred: Credential,
    ) -> Result<bool> {
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
        let Some(cred) = sanitize_credential(cred, &netbios_map, &known_domains) else {
            return Ok(false);
        };

        // Reject phantom domain misattribution. Forest-wide LDAP/GC searches,
        // SYSVOL script scrapes, and registry autologon dumps can surface a
        // (user, password) pair under one realm while a more authoritative
        // source already pinned that pair to a different realm. When the
        // existing entry comes from a strictly more trustworthy source, treat
        // the new entry as a misattribution. Otherwise it pollutes
        // find_trust_credential and yields cross-forest LDAP bind 0x52e.
        if !cred.password.is_empty() {
            let new_trust = credential_source_trust(&cred.source);
            let state = self.inner.read().await;
            let conflict = state.credentials.iter().find(|c| {
                c.username.eq_ignore_ascii_case(&cred.username)
                    && c.password == cred.password
                    && !c.domain.eq_ignore_ascii_case(&cred.domain)
            });
            if let Some(existing) = conflict {
                let existing_trust = credential_source_trust(&existing.source);
                if existing_trust > new_trust {
                    tracing::warn!(
                        username = %cred.username,
                        rejected_domain = %cred.domain,
                        rejected_source = %cred.source,
                        kept_domain = %existing.domain,
                        kept_source = %existing.source,
                        "Rejecting phantom credential — same (user, password) already known under a different domain from a more trusted source"
                    );
                    return Ok(false);
                }
            }
        }

        let operation_id = self.operation_id().await;
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_credential(&mut conn, &cred).await?;
        if added {
            // Append to the op-state log after Redis confirms
            // the credential is new (Redis is the dedup oracle).
            emit_op_state(
                self.recorder(),
                &operation_id,
                OpStateEventPayload::CredentialCaptured {
                    credential: cred.clone(),
                },
            )
            .await;

            // Warn (don't promote) when the credential's domain is unknown — this
            // is how we surface LLM hallucinations without letting them mutate
            // canonical state. Use NetExec-artifact-stripped form for the check.
            let cred_domain = strip_netexec_artifact(&cred.domain.to_lowercase()).to_string();
            let mut state = self.inner.write().await;
            if cred_domain.contains('.')
                && !state
                    .domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&cred_domain))
                && !state
                    .domain_controllers
                    .keys()
                    .any(|d| d.eq_ignore_ascii_case(&cred_domain))
            {
                tracing::warn!(
                    domain = %cred_domain,
                    username = %cred.username,
                    source = %cred.source,
                    "Credential references unknown domain — not promoting to state.domains (authoritative recon required)"
                );
            }
            state.credentials.push(cred);
        }
        Ok(added)
    }

    /// Add a hash to state and Redis (with dedup).
    ///
    /// When a `krbtgt` NTLM hash is stored, `has_domain_admin` is automatically
    /// set so that `auto_golden_ticket` triggers without requiring the LLM to
    /// emit a structured JSON payload.
    pub async fn publish_hash(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        mut hash: Hash,
    ) -> Result<bool> {
        use ares_core::models::VulnerabilityInfo;
        use std::collections::HashMap;

        // Canonicalize realm casing. AD realms are case-insensitive; storing them
        // mixed-case (`CONTOSO.LOCAL` from secretsdump, `contoso.local` from
        // sibling parsers) splits the same identity into two state entries and
        // slips past dedup keys built with `format!("{domain}\\{user}")`.
        // Mirrors the same normalization in `sanitize_credential`.
        hash.domain = hash.domain.to_lowercase();

        // Canonicalize flat NetBIOS → FQDN when known. `secretsdump.py`'s NTDS
        // output emits `CHILD\administrator:500:...`; the extractor stamps
        // `domain="child"` verbatim. Other emitters (LDAP dumps, orchestrator
        // summaries) tag the same secret with the FQDN. Without this step both
        // land as separate Redis fields (`ntlm:child:administrator:<h>` and
        // `ntlm:child.contoso.local:administrator:<h>`), splitting the same
        // identity and defeating dedup. `canonicalize_domain_label` returns
        // `None` when the flat name is unknown to state — keep the original
        // label rather than mint a phantom FQDN.
        if !hash.domain.is_empty() {
            let state_read = self.inner.read().await;
            if let Some(canonical) =
                super::super::canonicalize_domain_label(&hash.domain, &state_read)
            {
                if canonical != hash.domain {
                    tracing::debug!(
                        username = %hash.username,
                        original = %hash.domain,
                        canonical = %canonical,
                        "Canonicalizing hash domain flat→FQDN before dedup"
                    );
                    hash.domain = canonical;
                }
            }
        }

        // Reject malformed NTLM hashes before they enter state. Accept both a
        // bare NT half and standard secretsdump LM:NT pairs; tools can consume
        // either, but relay artifacts with partial/extra bytes only cause
        // downstream auth confusion.
        if hash.hash_type.to_lowercase() == "ntlm" {
            let v = &hash.hash_value;
            if !is_valid_ntlm_hash_value(v) {
                tracing::warn!(
                    username = %hash.username,
                    domain = %hash.domain,
                    hash_len = v.len(),
                    "Dropping malformed NTLM hash (expected 32 hex chars or LM:NT)"
                );
                return Ok(false);
            }
        }

        if let Some(incoming_nt) = krbtgt_nt_half(&hash) {
            let state_read = self.inner.read().await;
            if let Some(existing) = state_read.hashes.iter().find(|h| {
                !h.domain.eq_ignore_ascii_case(&hash.domain)
                    && krbtgt_nt_half(h).is_some_and(|nt| nt.eq_ignore_ascii_case(incoming_nt))
            }) {
                tracing::warn!(
                    incoming_domain = %hash.domain,
                    incoming_source = %hash.source,
                    existing_domain = %existing.domain,
                    existing_source = %existing.source,
                    "Dropping krbtgt NTLM hash already held by another domain — a krbtgt secret is unique per domain, so the incoming label is misattributed"
                );
                return Ok(false);
            }
        }

        let operation_id = self.operation_id().await;
        let operation_id_for_redis = operation_id.clone();
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_hash(&mut conn, &hash).await?;
        if !added {
            // Upsert path: redis dedup rejected the row, but if this hash
            // carries an AES256 key and the in-memory entry doesn't, mirror
            // the redis upsert performed by add_hash so cross-forest forge
            // gets AES on the very next 30s tick (Win2016+ rejects RC4-only
            // inter-realm tickets — losing AES to dedup blocks fabrikam compromise).
            if hash.aes_key.is_some() {
                let mut state = self.inner.write().await;
                if let Some(existing) = state.hashes.iter_mut().find(|h| {
                    h.username.eq_ignore_ascii_case(&hash.username)
                        && h.domain.eq_ignore_ascii_case(&hash.domain)
                        && h.hash_type.eq_ignore_ascii_case(&hash.hash_type)
                        && h.hash_value == hash.hash_value
                }) {
                    if existing.aes_key.is_none() {
                        existing.aes_key = hash.aes_key.clone();
                        tracing::info!(
                            username = %hash.username,
                            domain = %hash.domain,
                            "Upserted AES256 key onto existing in-memory hash entry"
                        );
                    }
                }
            }
            return Ok(false);
        }
        emit_op_state(
            self.recorder(),
            &operation_id,
            OpStateEventPayload::HashCaptured { hash: hash.clone() },
        )
        .await;

        // Convergence timestamp: a `$`-suffixed NTLM hash is a machine-account
        // or trust key — the input the cross-forest pivot needs to fire. Log
        // once on first landing so we can measure "op start → trust key in
        // state" against the trust-info and pivot-dispatch stages.
        if hash.username.trim_end_matches(' ').ends_with('$')
            && hash.hash_type.to_lowercase().contains("ntlm")
        {
            tracing::info!(
                convergence_stage = 2,
                event = "trust_key_hash_first_landing",
                op_id = %operation_id,
                account = %hash.username,
                domain = %hash.domain,
                has_aes = hash.aes_key.is_some(),
                "convergence: first machine/trust-key NTLM hash landing"
            );
        }

        // Capture identity fields before `hash` is moved into state.hashes —
        // they drive the implicit-user backfill below.
        let backfill_username = hash.username.clone();
        let backfill_domain = hash.domain.clone();
        {
            let is_krbtgt = hash.username.to_lowercase() == "krbtgt"
                && hash.hash_type.to_lowercase().contains("ntlm");
            let hash_domain = hash.domain.clone();
            let hash_source = hash.source.clone();
            let mut state = self.inner.write().await;
            state.push_hash_capped(hash);

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
                                    let d = strip_netexec_artifact(&h.domain.to_lowercase())
                                        .to_string();
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
                                        Some(
                                            strip_netexec_artifact(&h.domain.to_lowercase())
                                                .to_string(),
                                        )
                                    } else {
                                        None
                                    }
                                })
                            })
                        })
                        .unwrap_or_default()
                } else {
                    strip_netexec_artifact(&hash_domain.to_lowercase()).to_string()
                };
                // Only mark as dominated if the domain is a known DC domain.
                // This prevents false domination claims from misattributed hashes
                // (e.g. when secretsdump output lacks a domain prefix and sibling
                // resolution picks up a hash from an unrelated domain).
                let mut newly_dominated: Option<String> = None;
                if !krbtgt_domain.is_empty()
                    && (state.domain_controllers.contains_key(&krbtgt_domain)
                        || state.domains.contains(&krbtgt_domain))
                {
                    if state.dominated_domains.insert(krbtgt_domain.clone()) {
                        tracing::info!(domain = %krbtgt_domain, "Domain dominated (krbtgt hash obtained)");
                        newly_dominated = Some(krbtgt_domain.clone());
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

                // Auto-set domain admin when the first krbtgt NTLM hash arrives.
                let is_first_da = !state.has_domain_admin;
                let da_domain = krbtgt_domain.clone();
                drop(state);

                let path = Some(crate::orchestrator::state::krbtgt_da_path(&hash_source));
                let mut da_flag_ok = true;
                if is_first_da {
                    if let Err(e) = self.set_domain_admin(queue, path.clone()).await {
                        tracing::warn!(err = %e, "Failed to auto-set domain admin from krbtgt hash");
                        da_flag_ok = false;
                    } else {
                        tracing::info!(
                            "🎯 Domain Admin auto-set from krbtgt NTLM hash in publish_hash"
                        );
                    }
                }

                // One CRITICAL event per domain that falls. Gating this on
                // `is_first_da` emitted a single event for the whole op, so a
                // 3-of-3 forest compromise read as 1 domain in the report.
                let emit_da_event = da_flag_ok && (newly_dominated.is_some() || is_first_da);
                if emit_da_event {
                    let techniques = vec!["T1003.006".to_string(), "T1078.002".to_string()];
                    let event_id =
                        format!("evt-da-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
                    let event = serde_json::json!({
                        "id": event_id,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "source": "domain_admin",
                        "description": format!(
                            "CRITICAL: Domain Admin achieved for {} via {}",
                            da_domain,
                            path.as_deref().unwrap_or("krbtgt hash")
                        ),
                        "mitre_techniques": techniques,
                    });
                    let _ = self
                        .persist_timeline_event(queue, &event, &techniques)
                        .await;
                }

                // Mirror in-memory `dominated_domains` to a Redis SET so
                // post-mortem scripts (`SCARD ares:op:<id>:dominated_domains`)
                // and external dashboards can observe the same view. The
                // in-memory set is the source of truth — this is purely a
                // visibility mirror.
                if let Some(domain) = newly_dominated {
                    use redis::AsyncCommands;
                    let key = format!(
                        "{}:{}:{}",
                        state::KEY_PREFIX,
                        operation_id_for_redis,
                        state::KEY_DOMINATED_DOMAINS
                    );
                    let mut conn = queue.connection();
                    let _: redis::RedisResult<i64> = conn.sadd(&key, &domain).await;
                    let _: redis::RedisResult<i64> = conn.expire(&key, 86400).await;
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

        // Backfill the users table with an implicit User row derived from the
        // hash. This closes the gap where cross-forest LDAP enum is blocked
        // (or the operator never ran user-enum) but secretsdump still lands
        // identities — without this, the report's user count understates
        // what we actually know. Machine accounts (`$` suffix) are excluded:
        // those are trust-key / computer-account material, surfaced via the
        // hash's `is_trust_key` flag, not as user rows.
        if !backfill_username.is_empty()
            && !backfill_username.ends_with('$')
            && !backfill_domain.is_empty()
        {
            let user = ares_core::models::User {
                username: backfill_username,
                domain: backfill_domain,
                description: String::new(),
                is_admin: false,
                source: "secretsdump_implicit".to_string(),
                member_of: Vec::new(),
            };
            // Errors here are non-fatal — the hash already landed.
            let _ = self.publish_user(queue, user).await;
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

    /// Flip `is_admin` on every credential for `username`@`domain`, in memory
    /// **and** in Redis.
    ///
    /// Returns `true` only when this call performed a genuine `false → true`
    /// transition in memory, so a repeated `Pwn3d!` line for an
    /// already-upgraded principal does not re-fire the caller's timeline event
    /// and priority dispatch. `false` also covers "no credential for this
    /// principal is in state", which must stay distinguishable from success:
    /// emitting an admin event with no credential behind it is the phantom
    /// shape that `seimpersonate` credit had.
    ///
    /// The in-memory-only mutation this replaces is why 437 credential rows
    /// across 92 reports rendered `Admin = No` and zero rendered `Yes`, in ops
    /// that had a `Pwn3d!` event for that very principal: reports read Redis,
    /// and `add_credential` is `hset_nx`, so re-publishing an upgraded
    /// credential is a no-op rather than an update. This writes the field with
    /// `hset`, the same in-memory/Redis reconciliation `mark_host_owned`
    /// already does for `Host::owned`.
    ///
    /// Redis is reconciled whenever the principal matches at all, not only on a
    /// fresh flip — an operation that already mutated memory before this fix
    /// has `is_admin` true in state and false in Redis, and only an
    /// unconditional pass heals that disagreement.
    ///
    /// Every matching row is rewritten, not just the first. The dedup key
    /// includes a password digest (`cred:{domain}:{username}:{md5_16}`), so one
    /// principal legitimately holds several rows — a plaintext from a
    /// description leak and the same account's cracked password are different
    /// fields — and leaving the others stale would let a shadow row keep
    /// reporting the principal as non-admin.
    pub async fn mark_credentials_admin(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        username: &str,
        domain: &str,
    ) -> Result<bool> {
        let (op_id, flipped) = {
            let mut state = self.inner.write().await;
            let mut matched = false;
            let mut flipped = false;
            for cred in state.credentials.iter_mut() {
                if cred.username.eq_ignore_ascii_case(username)
                    && cred.domain.eq_ignore_ascii_case(domain)
                {
                    matched = true;
                    if !cred.is_admin {
                        cred.is_admin = true;
                        flipped = true;
                    }
                }
            }
            if !matched {
                return Ok(false);
            }
            (state.operation_id.clone(), flipped)
        };

        let cred_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_CREDENTIALS);
        let mut conn = queue.connection();
        let entries: std::collections::HashMap<String, String> =
            redis::AsyncCommands::hgetall(&mut conn, &cred_key)
                .await
                .unwrap_or_default();

        let mut rewritten = 0usize;
        for (field, value) in &entries {
            let Ok(mut cred) = serde_json::from_str::<Credential>(value) else {
                continue;
            };
            if !cred.username.eq_ignore_ascii_case(username)
                || !cred.domain.eq_ignore_ascii_case(domain)
                || cred.is_admin
            {
                continue;
            }
            cred.is_admin = true;
            let updated = serde_json::to_string(&cred).unwrap_or_default();
            if redis::AsyncCommands::hset::<_, _, _, ()>(&mut conn, &cred_key, field, &updated)
                .await
                .is_ok()
            {
                rewritten += 1;
            }
        }

        tracing::info!(
            username = %username,
            domain = %domain,
            rows_rewritten = rewritten,
            flipped,
            "Credential is_admin persisted to state and Redis"
        );

        Ok(flipped)
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

    const NTLM_HASH_A: &str = "aad3b435b51404eeaad3b435b51404ee"; // pragma: allowlist secret

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
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
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
    async fn publish_credential_does_not_pollute_state_domains() {
        // LLM-supplied domains must never be promoted into the canonical
        // `state.domains` registry — otherwise a typo like
        // `child.contossso.com` corrupts every downstream tick loop.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let cred = make_cred("alice", "P@ssw0rd!", "child.contossso.com");
        state.publish_credential(&q, cred).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            s.domains.is_empty(),
            "state.domains must remain untouched by credential ingestion, got {:?}",
            s.domains
        );
        assert_eq!(s.credentials.len(), 1);
    }

    #[tokio::test]
    async fn publish_foreign_forest_credential_lands_in_state() {
        // A verified foothold credential for a forest we do NOT own (its domain
        // is absent from state.domains) must still persist to state.credentials.
        // auto_adcs_enumeration reads state.credentials to build cred_domains
        // and dispatch certipy_find against the foreign CA — if a spray/AS-REP/
        // SMB-verified foreign cred were dropped here, cred_domains would never
        // list the foreign forest and it could never fall. The domain is NOT
        // promoted into the authoritative state.domains registry.
        let state = SharedState::new("op-foreign".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let mut cred = make_cred("svc_sql", "Passw0rd!Foreign", "fabrikam.local");
        cred.source = "password_spray".to_string();
        let added = state.publish_credential(&q, cred).await.unwrap();
        assert!(added, "foreign-forest foothold cred must be accepted");

        let s = state.inner.read().await;
        assert!(
            s.credentials
                .iter()
                .any(|c| c.domain == "fabrikam.local" && c.username == "svc_sql"),
            "foreign-forest cred must land in state.credentials, got {:?}",
            s.credentials
        );
        assert!(
            !s.domains.iter().any(|d| d == "fabrikam.local"),
            "foreign domain must not be promoted into authoritative state.domains"
        );
    }

    #[tokio::test]
    async fn publish_credential_rejects_phantom_description_field_dup() {
        // Forest-wide LDAP/GC searches can return a user from one domain while
        // the parser's tracked `current_domain` points at another. When that
        // happens, a description_field cred is published under the wrong
        // domain — same (user, password) but different domain — and pollutes
        // find_trust_credential's cross-forest selection. publish_credential
        // must reject the phantom so cross-forest auth picks a real principal.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let real = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "alice".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "child.contoso.local".to_string(),
            source: "initial".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(state.publish_credential(&q, real).await.unwrap());

        let phantom = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "alice".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "contoso.local".to_string(),
            source: "description_field".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(!state.publish_credential(&q, phantom).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.credentials.len(), 1);
        assert_eq!(s.credentials[0].domain, "child.contoso.local");
    }

    #[tokio::test]
    async fn publish_credential_rejects_low_trust_after_high_trust_phantom() {
        // Generalization of description_field rejection to all low-trust
        // sources. autologon_registry pulled a CHILD user but the surrounding
        // line gave a parent-realm prefix (`CONTOSO\bob`).
        // secretsdump already pinned the user to child.contoso.local;
        // the parent-realm copy must be rejected as a phantom.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let real = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "bob".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "child.contoso.local".to_string(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(state.publish_credential(&q, real).await.unwrap());

        let phantom = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "bob".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "contoso.local".to_string(),
            source: "autologon_registry".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(!state.publish_credential(&q, phantom).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.credentials.len(), 1);
        assert_eq!(s.credentials[0].domain, "child.contoso.local");
    }

    #[tokio::test]
    async fn publish_credential_high_trust_not_rejected_after_low_trust() {
        // Symmetric guard: when the wrong-realm record arrives FIRST from a
        // low-trust source, a later HIGH-trust correct-realm record must NOT
        // be rejected by a blanket conflict rule.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let phantom = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "bob".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "contoso.local".to_string(),
            source: "autologon_registry".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(state.publish_credential(&q, phantom).await.unwrap());

        let real = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "bob".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "child.contoso.local".to_string(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(state.publish_credential(&q, real).await.unwrap());

        let s = state.inner.read().await;
        // Both stored — a stricter eviction policy could remove the phantom,
        // but the priority is to ensure the high-trust record lands in state.
        assert!(
            s.credentials
                .iter()
                .any(|c| c.domain == "child.contoso.local" && c.source == "secretsdump"),
            "high-trust correct-realm credential must be stored"
        );
    }

    #[tokio::test]
    async fn publish_credential_equal_trust_both_stored() {
        // Two same-source records for the same (user, password) with
        // different realms: trust ranking can't disambiguate, so we keep
        // both and let downstream realm-strict consumers pick the right one.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let a = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "bob".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "child.contoso.local".to_string(),
            source: "autologon_registry".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        let b = Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: "bob".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: "contoso.local".to_string(),
            source: "autologon_registry".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert!(state.publish_credential(&q, a).await.unwrap());
        assert!(state.publish_credential(&q, b).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.credentials.len(), 2);
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

        let hash = make_hash("admin", "contoso.local", "NTLM", NTLM_HASH_A);
        let added = state.publish_hash(&q, hash).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].username, "admin");
    }

    #[tokio::test]
    async fn publish_hash_accepts_secretsdump_lm_nt_pair() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let lm_nt = format!("aad3b435b51404eeaad3b435b51404ee:{NTLM_HASH_A}");
        let hash = make_hash("admin", "contoso.local", "NTLM", &lm_nt);
        let added = state.publish_hash(&q, hash).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].hash_value, lm_nt);
    }

    #[tokio::test]
    async fn publish_hash_dedup() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash1 = make_hash("admin", "contoso.local", "NTLM", NTLM_HASH_A);
        let hash2 = make_hash("admin", "contoso.local", "NTLM", NTLM_HASH_A);
        assert!(state.publish_hash(&q, hash1).await.unwrap());
        assert!(!state.publish_hash(&q, hash2).await.unwrap());
    }

    #[tokio::test]
    async fn publish_hash_canonicalizes_realm_to_lowercase() {
        // Same hash arriving with mixed-case realms (`CONTOSO.LOCAL` from one
        // tool, `contoso.local` from another) must not split into two entries.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let upper = make_hash("admin", "CONTOSO.LOCAL", "NTLM", NTLM_HASH_A);
        let lower = make_hash("admin", "contoso.local", "NTLM", NTLM_HASH_A);
        assert!(state.publish_hash(&q, upper).await.unwrap());
        assert!(!state.publish_hash(&q, lower).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn publish_hash_canonicalizes_flat_netbios_to_fqdn() {
        // The secretsdump NTDS extractor tags hashes with the flat NetBIOS name
        // it sees in `CHILD\administrator:500:...:<h>:::`, while LDAP dumps and
        // orchestrator-side emitters tag the same identity with the FQDN. Both
        // must collapse into a single dedup slot; leaving flat- and FQDN-keyed
        // rows side-by-side splits candidate selection (which keys on FQDN).
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("child.contoso.local".to_string());
        }

        let flat = make_hash("admin", "CHILD", "NTLM", NTLM_HASH_A);
        let fqdn = make_hash("admin", "child.contoso.local", "NTLM", NTLM_HASH_A);
        assert!(state.publish_hash(&q, flat).await.unwrap());
        assert!(!state.publish_hash(&q, fqdn).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].domain, "child.contoso.local");
    }

    #[tokio::test]
    async fn publish_hash_preserves_unknown_flat_domain() {
        // When the flat name doesn't resolve to any known FQDN (no
        // netbios_to_fqdn entry, no first-label match against state.domains,
        // no trust metadata), keep the label rather than mint a phantom FQDN.
        // The hash still stores as `ntlm:unknown:...` — better a truthful
        // "unattributed" tag than a fabricated domain that pollutes candidate
        // selection.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let hash = make_hash("admin", "STRANGER", "NTLM", NTLM_HASH_A);
        assert!(state.publish_hash(&q, hash).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].domain, "stranger");
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

        let hash = make_hash("krbtgt", "contoso.local", "NTLM", NTLM_HASH_A);
        state.publish_hash(&q, hash).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.has_domain_admin);
        assert!(s.dominated_domains.contains("contoso.local"));
    }

    #[tokio::test]
    async fn publish_krbtgt_lm_nt_hash_sets_domain_admin() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let lm_nt = format!("aad3b435b51404eeaad3b435b51404ee:{NTLM_HASH_A}");
        let hash = make_hash("krbtgt", "contoso.local", "NTLM", &lm_nt);
        state.publish_hash(&q, hash).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.has_domain_admin);
        assert!(s.dominated_domains.contains("contoso.local"));
        assert_eq!(s.hashes[0].hash_value, lm_nt);
    }

    #[tokio::test]
    async fn publish_krbtgt_hash_mirrors_dominated_to_redis_set() {
        // SCARD ares:op:<id>:dominated_domains should reflect the in-memory
        // set so post-mortem scripts and dashboards see the same view.
        let state = SharedState::new("op-mirror".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let hash = make_hash("krbtgt", "contoso.local", "NTLM", NTLM_HASH_A);
        state.publish_hash(&q, hash).await.unwrap();

        let mut conn = q.connection();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, "ares:op:op-mirror:dominated_domains")
                .await
                .unwrap();
        assert!(members.contains("contoso.local"));
    }

    #[tokio::test]
    async fn publish_krbtgt_hash_without_resolvable_domain_skips_vuln() {
        // A krbtgt hash with no domain prefix and no siblings to resolve
        // from must not synthesize a `dc_secretsdump` vuln (would surface
        // as `dc_secretsdump on ` with empty target/domain in the report).
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash = make_hash("krbtgt", "", "NTLM", NTLM_HASH_A);
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

    const KRBTGT_NT_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90"; // pragma: allowlist secret
    const KRBTGT_NT_B: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"; // pragma: allowlist secret

    async fn state_with_domains(op_id: &str, domains: &[&str]) -> SharedState {
        let state = SharedState::new(op_id.to_string());
        {
            let mut s = state.inner.write().await;
            for d in domains {
                s.domains.push((*d).to_string());
            }
        }
        state
    }

    #[tokio::test]
    async fn publish_krbtgt_rejects_same_nt_half_under_a_second_domain() {
        let state = state_with_domains("op-1", &["contoso.local", "child.contoso.local"]).await;
        let q = mock_queue();

        let real = make_hash("krbtgt", "contoso.local", "NTLM", KRBTGT_NT_A);
        assert!(state.publish_hash(&q, real).await.unwrap());

        let mut phantom = make_hash("krbtgt", "child.contoso.local", "NTLM", KRBTGT_NT_A);
        phantom.source = "output_extraction".to_string();
        assert!(
            !state.publish_hash(&q, phantom).await.unwrap(),
            "a krbtgt secret is unique per domain; the second label must be rejected"
        );

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
        assert!(s.dominated_domains.contains("contoso.local"));
        assert!(
            !s.dominated_domains.contains("child.contoso.local"),
            "misattributed krbtgt must not dominate a second domain"
        );
    }

    #[tokio::test]
    async fn publish_krbtgt_collision_detected_across_lm_nt_and_bare_nt_forms() {
        let state = state_with_domains("op-1", &["contoso.local", "fabrikam.local"]).await;
        let q = mock_queue();

        let lm_nt = format!("aad3b435b51404eeaad3b435b51404ee:{KRBTGT_NT_A}");
        let real = make_hash("krbtgt", "contoso.local", "NTLM", &lm_nt);
        assert!(state.publish_hash(&q, real).await.unwrap());

        let phantom = make_hash("krbtgt", "fabrikam.local", "NTLM", KRBTGT_NT_A);
        assert!(!state.publish_hash(&q, phantom).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.dominated_domains.len(), 1);
    }

    #[tokio::test]
    async fn publish_krbtgt_allows_distinct_values_per_domain() {
        let state = state_with_domains("op-1", &["contoso.local", "child.contoso.local"]).await;
        let q = mock_queue();

        let root = make_hash("krbtgt", "contoso.local", "NTLM", KRBTGT_NT_A);
        let child = make_hash("krbtgt", "child.contoso.local", "NTLM", KRBTGT_NT_B);
        assert!(state.publish_hash(&q, root).await.unwrap());
        assert!(state.publish_hash(&q, child).await.unwrap());

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 2);
        assert!(s.dominated_domains.contains("contoso.local"));
        assert!(s.dominated_domains.contains("child.contoso.local"));
    }

    #[tokio::test]
    async fn publish_non_krbtgt_still_keeps_shared_hash_across_domains() {
        let state = state_with_domains("op-1", &["contoso.local", "fabrikam.local"]).await;
        let q = mock_queue();

        let a = make_hash("Administrator", "contoso.local", "NTLM", KRBTGT_NT_A);
        let b = make_hash("Administrator", "fabrikam.local", "NTLM", KRBTGT_NT_A);
        assert!(state.publish_hash(&q, a).await.unwrap());
        assert!(
            state.publish_hash(&q, b).await.unwrap(),
            "a reused local Administrator password across realms is a real finding"
        );

        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 2);
    }

    #[tokio::test]
    async fn publish_krbtgt_without_domain_is_not_treated_as_a_collision() {
        let state = state_with_domains("op-1", &["contoso.local"]).await;
        let q = mock_queue();

        let real = make_hash("krbtgt", "contoso.local", "NTLM", KRBTGT_NT_A);
        assert!(state.publish_hash(&q, real).await.unwrap());

        let unlabeled = make_hash("krbtgt", "", "NTLM", KRBTGT_NT_A);
        state.publish_hash(&q, unlabeled).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.dominated_domains.contains("contoso.local"));
        assert_eq!(s.dominated_domains.len(), 1);
    }

    #[tokio::test]
    async fn update_hash_cracked_password() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let hash = make_hash("admin", "contoso.local", "NTLM", NTLM_HASH_A);
        state.publish_hash(&q, hash).await.unwrap();

        let updated = state
            .update_hash_cracked_password(&q, "admin", "contoso.local", "CrackedPW!")
            .await
            .unwrap();
        assert!(updated);

        let s = state.inner.read().await;
        assert_eq!(s.hashes[0].cracked_password.as_deref(), Some("CrackedPW!"));
    }

    /// Read the `is_admin` flags Redis actually holds for `username`.
    ///
    /// Every assertion about this fix has to go through Redis: reports read
    /// Redis, and the bug was that memory and Redis disagreed. An in-memory-only
    /// assertion passes against the broken code.
    async fn redis_admin_flags(
        state: &SharedState,
        q: &TaskQueueCore<MockRedisConnection>,
        username: &str,
    ) -> Vec<bool> {
        let op_id = state.inner.read().await.operation_id.clone();
        let key = format!(
            "{}:{}:{}",
            ares_core::state::KEY_PREFIX,
            op_id,
            ares_core::state::KEY_CREDENTIALS
        );
        let mut conn = q.connection();
        let entries: std::collections::HashMap<String, String> =
            redis::AsyncCommands::hgetall(&mut conn, &key)
                .await
                .unwrap_or_default();
        entries
            .values()
            .filter_map(|v| serde_json::from_str::<Credential>(v).ok())
            .filter(|c| c.username.eq_ignore_ascii_case(username))
            .map(|c| c.is_admin)
            .collect()
    }

    #[tokio::test]
    async fn mark_credentials_admin_persists_the_flag_to_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .publish_credential(&q, make_cred("alice", "P@ssw0rd!", "contoso.local"))
            .await
            .unwrap();

        assert_eq!(
            redis_admin_flags(&state, &q, "alice").await,
            vec![false],
            "precondition: the published credential is not admin yet"
        );

        let flipped = state
            .mark_credentials_admin(&q, "alice", "contoso.local")
            .await
            .unwrap();

        assert!(flipped, "a false→true transition must report true");
        assert_eq!(
            redis_admin_flags(&state, &q, "alice").await,
            vec![true],
            "is_admin never reached Redis — this is the defect that rendered 437 rows as `Admin = No`"
        );
        assert!(state.inner.read().await.credentials[0].is_admin);
    }

    #[tokio::test]
    async fn mark_credentials_admin_updates_every_row_for_the_principal() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Two rows, one principal: the dedup key carries a password digest, so
        // a description leak and a cracked password are separate fields.
        state
            .publish_credential(&q, make_cred("alice", "P@ssw0rd!", "contoso.local"))
            .await
            .unwrap();
        state
            .publish_credential(&q, make_cred("alice", "Summer2026!", "contoso.local"))
            .await
            .unwrap();

        assert_eq!(redis_admin_flags(&state, &q, "alice").await.len(), 2);

        state
            .mark_credentials_admin(&q, "alice", "contoso.local")
            .await
            .unwrap();

        let flags = redis_admin_flags(&state, &q, "alice").await;
        assert_eq!(
            flags,
            vec![true, true],
            "a stale shadow row keeps reporting the principal as non-admin"
        );
    }

    #[tokio::test]
    async fn mark_credentials_admin_is_case_insensitive_on_principal() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .publish_credential(&q, make_cred("alice", "P@ssw0rd!", "contoso.local"))
            .await
            .unwrap();

        // netexec prints the domain uppercased in the `Pwn3d!` line.
        let flipped = state
            .mark_credentials_admin(&q, "ALICE", "CONTOSO.LOCAL")
            .await
            .unwrap();

        assert!(flipped);
        assert_eq!(redis_admin_flags(&state, &q, "alice").await, vec![true]);
    }

    #[tokio::test]
    async fn mark_credentials_admin_reports_false_when_no_credential_matches() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .publish_credential(&q, make_cred("alice", "P@ssw0rd!", "contoso.local"))
            .await
            .unwrap();

        // An admin event with no credential behind it is the `seimpersonate`
        // phantom shape; the caller keys its timeline event off this bool.
        assert!(!state
            .mark_credentials_admin(&q, "bob", "contoso.local")
            .await
            .unwrap());
        assert!(!state
            .mark_credentials_admin(&q, "alice", "fabrikam.local")
            .await
            .unwrap());
        assert_eq!(redis_admin_flags(&state, &q, "alice").await, vec![false]);
    }

    #[tokio::test]
    async fn mark_credentials_admin_reports_false_on_a_repeat_but_still_heals_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .publish_credential(&q, make_cred("alice", "P@ssw0rd!", "contoso.local"))
            .await
            .unwrap();

        assert!(state
            .mark_credentials_admin(&q, "alice", "contoso.local")
            .await
            .unwrap());
        assert!(
            !state
                .mark_credentials_admin(&q, "alice", "contoso.local")
                .await
                .unwrap(),
            "a repeated Pwn3d! line must not re-fire the caller's timeline event"
        );

        // The pre-fix shape: memory true, Redis false. Only an unconditional
        // Redis pass reconciles it, so the repeat call must still write.
        state.inner.write().await.credentials[0].is_admin = true;
        let key = format!(
            "{}:{}:{}",
            ares_core::state::KEY_PREFIX,
            "op-1",
            ares_core::state::KEY_CREDENTIALS
        );
        let mut conn = q.connection();
        let entries: std::collections::HashMap<String, String> =
            redis::AsyncCommands::hgetall(&mut conn, &key)
                .await
                .unwrap();
        let (field, value) = entries.iter().next().unwrap();
        let mut stale: Credential = serde_json::from_str(value).unwrap();
        stale.is_admin = false;
        let _: () = redis::AsyncCommands::hset(
            &mut conn,
            &key,
            field,
            serde_json::to_string(&stale).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(redis_admin_flags(&state, &q, "alice").await, vec![false]);

        state
            .mark_credentials_admin(&q, "alice", "contoso.local")
            .await
            .unwrap();
        assert_eq!(
            redis_admin_flags(&state, &q, "alice").await,
            vec![true],
            "an in-memory/Redis disagreement must heal on the next Pwn3d! line"
        );
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
    async fn cracked_kerberoast_hash_stamped_when_password_already_known() {
        // Kerberoast/AS-REP hashes dedup by principal (`krb:{domain}:{user}:{spn}`
        // / `asrep:{domain}:{user}`), so an account has a single ticket Hash row
        // per op regardless of re-roasts. The gap this guards: when the account's
        // password is *already known* from another source (GPP, cleartext, a
        // prior crack, a spray hit), cracking the ticket re-derives that same
        // plaintext and `publish_credential` dedups it — the credential key is
        // `cred:{domain}:{user}:{md5(password)}`, independent of source, so the
        // publish returns Ok(false). Result processing must still stamp the
        // ticket Hash's cracked_password on that duplicate path; otherwise
        // `is_reportable_hash` surfaces the raw ticket blob *alongside* the
        // cracked Credential and the external scoreboard double-counts the
        // account. This exercises the primitive the fix relies on: the stamp is
        // independent of whether the credential row was new.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // svc_sql's password is already known — a Credential exists (e.g. GPP).
        state
            .publish_credential(&q, make_cred("svc_sql", "SqlPass1", "contoso.local"))
            .await
            .unwrap();
        // Its kerberoast ticket lands uncracked.
        let ticket = make_hash(
            "svc_sql",
            "contoso.local",
            "kerberoast",
            "$krb5tgs$18$svc_sql$CONTOSO.LOCAL$aaaa0000$bbbb",
        );
        state.publish_hash(&q, ticket).await.unwrap();

        // The crack re-derives the known plaintext; the credential is a duplicate.
        assert!(
            !state
                .publish_credential(&q, make_cred("svc_sql", "SqlPass1", "contoso.local"))
                .await
                .unwrap(),
            "a cracked credential for an already-known password dedups to Ok(false)"
        );

        // The ticket Hash must still be stamped so it drops from the loot report
        // (is_reportable_hash keys on cracked_password.is_some()).
        assert!(state
            .update_hash_cracked_password(&q, "svc_sql", "contoso.local", "SqlPass1")
            .await
            .unwrap());
        let s = state.inner.read().await;
        let ticket = s
            .hashes
            .iter()
            .find(|h| h.hash_type == "kerberoast")
            .expect("kerberoast ticket present");
        assert_eq!(ticket.cracked_password.as_deref(), Some("SqlPass1"));
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
        let hash = make_hash("admin", "contoso.local", "NTLM", NTLM_HASH_A);
        assert!(state.publish_hash(&q, hash).await.unwrap());

        let evs = recorder.captured().await;
        // Plain admin hash emits hash.captured plus a UserDiscovered event from
        // the implicit-user backfill (publish_user is called for non-machine
        // accounts so the report's user count reflects identities surfaced via
        // secretsdump). krbtgt would emit additional vuln/exploited events.
        let hash_event = evs
            .iter()
            .find(|e| matches!(e.payload, OpStateEventPayload::HashCaptured { .. }))
            .expect("must emit HashCaptured");
        match &hash_event.payload {
            OpStateEventPayload::HashCaptured { hash } => {
                assert_eq!(hash.username, "admin");
                assert_eq!(hash.hash_type, "NTLM");
            }
            other => panic!("expected HashCaptured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_hash_rejects_malformed_ntlm() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // 33 chars — relay artifact
        let bad = make_hash(
            "jdoe",
            "child.contoso.local",
            "NTLM",
            "aad3b435b51404eeaad3b435b51404ee0",
        ); // pragma: allowlist secret
        assert!(!state.publish_hash(&q, bad).await.unwrap());

        // 8 chars — truncated capture
        let short = make_hash("jdoe", "child.contoso.local", "NTLM", "aabbccdd");
        assert!(!state.publish_hash(&q, short).await.unwrap());

        let s = state.inner.read().await;
        assert!(s.hashes.is_empty(), "malformed hashes must not enter state");
    }

    #[tokio::test]
    async fn publish_hash_accepts_non_ntlm_any_length() {
        // AES256 keys are 64 hex chars; we must not reject them.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        let aes = make_hash(
            "krbtgt",
            "contoso.local",
            "AES256",
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
        );
        assert!(state.publish_hash(&q, aes).await.unwrap());
        let s = state.inner.read().await;
        assert_eq!(s.hashes.len(), 1);
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
