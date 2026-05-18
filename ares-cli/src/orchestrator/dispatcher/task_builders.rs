//! Convenience methods for common task types (request_crack, request_recon, etc.).

use anyhow::Result;
use serde_json::json;
use tracing::{debug, info, instrument};

use ares_core::models::{Credential, Hash};

use crate::orchestrator::state::{StateInner, DEDUP_CROSS_REALM_LATERAL, DEDUP_SCANNED_TARGETS};

use super::Dispatcher;

/// Credential + hash pair selected for an exploit task.
#[derive(Default, Debug)]
struct ExploitAuth {
    credential: Option<Credential>,
    hash: Option<Hash>,
}

impl ExploitAuth {
    /// True when the selected auth actually matches the target domain.
    ///
    /// An empty `target_domain` means the caller does not constrain by domain
    /// (e.g. anonymous/local exploits) — any selected auth counts as a match.
    fn matches_domain(&self, target_domain: &str) -> bool {
        if target_domain.is_empty() {
            return self.credential.is_some() || self.hash.is_some();
        }
        let cred_match = self
            .credential
            .as_ref()
            .map(|c| c.domain.eq_ignore_ascii_case(target_domain))
            .unwrap_or(false);
        let hash_match = self
            .hash
            .as_ref()
            .map(|h| h.domain.eq_ignore_ascii_case(target_domain))
            .unwrap_or(false);
        cred_match || hash_match
    }
}

/// Select a credential + hash for an exploit task.
///
/// Lookup order:
///   1. Credential by `account_name` (any domain).
///   2. Credential in the target domain, excluding delegation accounts.
///   3. Hash by `account_name` (any domain).
///   4. Hash in the target domain.
///
/// When no `domain` is supplied, falls back to "any non-delegation credential"
/// — preserved for legacy callers that dispatch domain-agnostic exploits.
/// Callers that specify a `domain` should consult [`ExploitAuth::matches_domain`]
/// and defer dispatch when it returns false, rather than firing the task with
/// a wrong-realm credential attached.
fn select_exploit_auth(
    state: &StateInner,
    account_name: Option<&str>,
    domain: &str,
) -> ExploitAuth {
    let credential = if let Some(acct) = account_name {
        state
            .credentials
            .iter()
            .find(|c| c.username.eq_ignore_ascii_case(acct))
    } else {
        None
    }
    .or_else(|| {
        if !domain.is_empty() {
            state.credentials.iter().find(|c| {
                c.domain.eq_ignore_ascii_case(domain) && !state.is_delegation_account(&c.username)
            })
        } else {
            state
                .credentials
                .iter()
                .find(|c| !state.is_delegation_account(&c.username))
        }
    })
    .cloned();

    let hash = if let Some(acct) = account_name {
        state
            .hashes
            .iter()
            .find(|h| h.username.eq_ignore_ascii_case(acct))
    } else if !domain.is_empty() {
        state
            .hashes
            .iter()
            .find(|h| h.domain.eq_ignore_ascii_case(domain))
    } else {
        None
    }
    .cloned();

    ExploitAuth { credential, hash }
}

/// Vuln types that do not require an authenticated credential to exploit.
///
/// These run pre-auth (against the network stack of the DC, or via NTLM relay)
/// and would be incorrectly deferred by the credential gate. Kept narrow on
/// purpose — adding a vuln that actually requires auth bypasses the gate and
/// produces wrong-realm dispatch failures.
fn vuln_type_is_preauth(vtype: &str) -> bool {
    matches!(
        vtype.to_ascii_lowercase().as_str(),
        "zerologon"
            | "nopac"
            | "petitpotam_unauth"
            | "printnightmare_unauth"
            | "dfscoerce_unauth"
            | "esc8_relay"
    )
}

/// Vuln types whose exploitation primitive lives in the `acl` worker's
/// toolset (bloodyAD, pywhisker, dacl_edit). Used to route `request_exploit`
/// to the right worker when the emitting parser left `recommended_agent`
/// empty — the historical default of `privesc` left the LLM agent without
/// any ACL-modifying tool and the chain bailed with "missing bloodyAD".
///
/// Matches on substrings so we cover both the bare form (e.g.
/// `allextendedrights`) and the prefixed form emitted by acl_discovery
/// (`acl_allextendedrights_<sid>_<target>`).
fn is_acl_style_vuln_type(vtype: &str) -> bool {
    let v = vtype.to_ascii_lowercase();
    v.contains("genericall")
        || v.contains("genericwrite")
        || v.contains("writedacl")
        || v.contains("writeowner")
        || v.contains("writeproperty")
        || v.contains("allextendedrights")
        || v.contains("forcechangepassword")
        || v.contains("self_membership")
        || v.contains("write_membership")
        || v.contains("addmember")
        || v.contains("addself")
}

impl Dispatcher {
    /// Submit a crack task for a hash.
    #[instrument(
        name = "automation.request_crack",
        skip(self, hash),
        fields(username = %hash.username, domain = %hash.domain, hash_type = %hash.hash_type),
    )]
    pub async fn request_crack(&self, hash: &ares_core::models::Hash) -> Result<Option<String>> {
        let payload = json!({
            "hash_type": hash.hash_type,
            "hash_value": hash.hash_value,
            "username": hash.username,
            "domain": hash.domain,
        });
        // Crack tasks are non-LLM, normal priority
        self.throttled_submit("crack", "cracker", payload, 5).await
    }

    /// Submit a recon task.
    ///
    /// Guards:
    /// 1. Skip entirely if domain admin has been achieved
    /// 2. Skip nmap tasks if all targets are already in `scanned_targets`
    /// 3. Auto-dispatch nmap prerequisite before enumeration if targets not scanned
    #[instrument(
        name = "automation.request_recon",
        skip(self, credential),
        fields(target_ip = %target_ip, domain = %domain, technique_count = techniques.len()),
    )]
    pub async fn request_recon(
        &self,
        target_ip: &str,
        domain: &str,
        techniques: &[&str],
        credential: Option<&ares_core::models::Credential>,
    ) -> Result<Option<String>> {
        // Guard 1: Skip recon if domain admin already achieved
        {
            let state = self.state.read().await;
            if state.has_domain_admin {
                debug!(
                    target_ip = target_ip,
                    "Skipping recon — domain admin already achieved"
                );
                return Ok(None);
            }
        }

        let is_nmap = techniques.contains(&"network_scan") || techniques.contains(&"nmap_scan");
        let is_smb_signing = techniques.contains(&"smb_signing_check");
        let is_scan_only = (is_nmap || is_smb_signing)
            && techniques
                .iter()
                .all(|t| *t == "network_scan" || *t == "nmap_scan" || *t == "smb_signing_check");

        // Guard 2: Skip nmap/scan tasks if target already scanned
        if is_scan_only {
            let state = self.state.read().await;
            if state.is_processed(DEDUP_SCANNED_TARGETS, target_ip) {
                debug!(
                    target_ip = target_ip,
                    "Skipping scan — target already in scanned_targets"
                );
                return Ok(None);
            }
        }

        // Guard 3: Auto-dispatch nmap prerequisite before enumeration
        // If this is NOT a scan task and the target hasn't been scanned yet,
        // dispatch an nmap scan first at priority 1 (urgent).
        if !is_scan_only {
            let needs_scan = {
                let state = self.state.read().await;
                !state.is_processed(DEDUP_SCANNED_TARGETS, target_ip)
            };
            if needs_scan {
                info!(
                    target_ip = target_ip,
                    "Auto-dispatching nmap prerequisite before enumeration"
                );
                let scan_payload = json!({
                    "target_ip": target_ip,
                    "domain": domain,
                    "techniques": ["network_scan", "smb_signing_check"],
                });
                // Priority 1 = urgent, scanned before the enumeration task
                let _ = self
                    .throttled_submit("recon", "recon", scan_payload, 1)
                    .await;
            }
        }

        // Mark nmap targets as scanned (optimistic, to prevent duplicate dispatches)
        if is_nmap {
            {
                let mut state = self.state.write().await;
                state.mark_processed(DEDUP_SCANNED_TARGETS, target_ip.to_string());
            }
            // Persist to Redis so it survives restarts
            let _ = self
                .state
                .persist_dedup(&self.queue, DEDUP_SCANNED_TARGETS, target_ip)
                .await;
        }

        let mut payload = json!({
            "target_ip": target_ip,
            "domain": domain,
            "techniques": techniques,
        });
        if let Some(cred) = credential {
            payload["credential"] = json!({
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            });
        }

        // Nmap tasks get priority 1, other recon priority 5
        let priority = if is_nmap { 1 } else { 5 };
        self.throttled_submit("recon", "recon", payload, priority)
            .await
    }

    /// Submit a low-hanging fruit credential discovery task (SYSVOL, GPP, LDAP, LAPS).
    ///
    /// Sends multiple high-success-rate techniques in a single task so the LLM
    /// agent executes them sequentially.
    #[instrument(
        name = "automation.request_low_hanging_fruit",
        skip(self, credential),
        fields(target_ip = %target_ip, domain = %domain, priority = priority, username = %credential.username),
    )]
    pub async fn request_low_hanging_fruit(
        &self,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "techniques": [
                "sysvol_script_search",
                "gpp_password_finder",
                "ldap_search_descriptions",
                "laps_dump"
            ],
            "reason": "low_hanging_fruit",
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a credential access task (kerberoast, asrep, secretsdump, etc.).
    #[instrument(
        name = "automation.request_credential_access",
        skip(self, credential),
        fields(technique = %technique, target_ip = %target_ip, domain = %domain, priority = priority, username = %credential.username),
    )]
    pub async fn request_credential_access(
        &self,
        technique: &str,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": technique,
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a secretsdump task.
    #[instrument(
        name = "automation.request_secretsdump",
        skip(self, credential),
        fields(target_ip = %target_ip, priority = priority, username = %credential.username, domain = %credential.domain),
    )]
    pub async fn request_secretsdump(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "secretsdump",
            "target_ip": target_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a secretsdump task using NTLM hash (pass-the-hash).
    ///
    /// When `just_dc_user` is `Some`, the task is narrowed to a single-account
    /// DCSync (e.g. `Some("krbtgt")` for golden-ticket preparation). The flag
    /// is plumbed into the payload so the prompt template can surface it as an
    /// explicit argument in the example signature — without that, the LLM
    /// agent omits `-just-dc-user` and impacket falls back to a full dump
    /// (which is what we already have for the parent realm) or trips DRSUAPI
    /// hardening.
    #[instrument(
        name = "automation.request_secretsdump_hash",
        skip(self, hash_value),
        fields(target_ip = %target_ip, username = %username, domain = %domain, priority = priority),
    )]
    pub async fn request_secretsdump_hash(
        &self,
        target_ip: &str,
        username: &str,
        domain: &str,
        hash_value: &str,
        priority: i32,
        just_dc_user: Option<&str>,
    ) -> Result<Option<String>> {
        let mut payload = json!({
            "technique": "secretsdump",
            "target_ip": target_ip,
            "credential": {
                "username": username,
                "domain": domain,
            },
            "hash_value": hash_value,
        });
        if let Some(target_user) = just_dc_user {
            payload["just_dc_user"] = json!(target_user);
        }
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a lateral movement task.
    ///
    /// Refuses to dispatch when the credential's realm differs from the target
    /// host's realm and no trust path is known — wrong-realm NTLM/Kerberos auth
    /// against a foreign DC just returns ACCESS_DENIED and burns LLM tokens.
    #[instrument(
        name = "automation.request_lateral",
        skip(self, credential),
        fields(target_ip = %target_ip, technique = %technique, username = %credential.username, domain = %credential.domain),
    )]
    pub async fn request_lateral(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        technique: &str,
    ) -> Result<Option<String>> {
        // Stable key shared with the cross-realm guard below so a rejection
        // permanently suppresses retries from credential_expansion and the LLM.
        let cross_realm_key = format!(
            "{}|{}|{}|{}",
            credential.domain.to_lowercase(),
            credential.username.to_lowercase(),
            target_ip,
            technique
        );

        {
            let state = self.state.read().await;
            if state.is_processed(DEDUP_CROSS_REALM_LATERAL, &cross_realm_key) {
                debug!(
                    target_ip = target_ip,
                    cred_user = %credential.username,
                    technique = technique,
                    "Skipping lateral — already rejected as cross-realm dead-end"
                );
                return Ok(None);
            }
        }

        // Resolve target's realm from state.hosts (FQDN suffix).
        let target_domain = {
            let state = self.state.read().await;
            state
                .hosts
                .iter()
                .find(|h| h.ip == target_ip)
                .and_then(|h| h.hostname.split_once('.').map(|(_, d)| d.to_lowercase()))
        };
        if let Some(td) = target_domain {
            let cd = credential.domain.to_lowercase();
            if !cd.is_empty()
                && cd != td
                && !td.ends_with(&format!(".{cd}"))
                && !cd.ends_with(&format!(".{td}"))
            {
                tracing::warn!(
                    target_ip = %target_ip,
                    target_domain = %td,
                    cred_domain = %cd,
                    cred_user = %credential.username,
                    technique = %technique,
                    "Refusing cross-realm lateral movement — use forest_trust_escalation or get a same-realm credential first"
                );
                {
                    let mut state = self.state.write().await;
                    state.mark_processed(DEDUP_CROSS_REALM_LATERAL, cross_realm_key.clone());
                }
                let _ = self
                    .state
                    .persist_dedup(&self.queue, DEDUP_CROSS_REALM_LATERAL, &cross_realm_key)
                    .await;
                return Ok(None);
            }
        }
        let payload = json!({
            "technique": technique,
            "target_ip": target_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("lateral_movement", "lateral", payload, 5)
            .await
    }

    /// Submit an exploit task for a vulnerability.
    ///
    /// Looks up the best available credential or hash for the vuln's target/domain
    /// and attaches it to the payload so the agent doesn't have to discover auth independently.
    #[instrument(
        name = "automation.request_exploit",
        skip(self, vuln),
        fields(
            vuln_id = %vuln.vuln_id,
            vuln_type = %vuln.vuln_type,
            target = %vuln.target,
            priority = priority,
        ),
    )]
    pub async fn request_exploit(
        &self,
        vuln: &ares_core::models::VulnerabilityInfo,
        priority: i32,
    ) -> Result<Option<String>> {
        let mut payload = json!({
            "vuln_id": vuln.vuln_id,
            "vuln_type": vuln.vuln_type,
            "target": vuln.target,
            "details": vuln.details,
        });

        let account_name = vuln
            .details
            .get("account_name")
            .and_then(|v| v.as_str())
            .or_else(|| vuln.details.get("AccountName").and_then(|v| v.as_str()));

        let domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let (auth, all_creds_for_mssql) = {
            let state = self.state.read().await;
            let auth = select_exploit_auth(&state, account_name, domain);

            // Credential gate: refuse to dispatch when the vuln targets a
            // specific AD domain but no usable credential or hash exists for
            // that domain. Without this, the orchestrator dispatches the
            // exploit with a wrong-realm credential (or no auth at all)
            // attached, the LLM agent fails with KRB 0x52e or "no
            // credential," the cooldown burns through MAX_EXPLOIT_FAILURES,
            // and the vuln is marked abandoned — even though the cracker or
            // a later inject would have unlocked the path. Returning
            // Ok(None) here lets the exploitation workflow re-enqueue the
            // vuln and retry once a domain-matched credential lands.
            //
            // Pre-auth attacks (zerologon and friends) bypass the gate
            // because they don't need authentication to fire.
            if !domain.is_empty()
                && !vuln_type_is_preauth(&vuln.vuln_type)
                && !auth.matches_domain(domain)
            {
                debug!(
                    vuln_id = %vuln.vuln_id,
                    vuln_type = %vuln.vuln_type,
                    domain = domain,
                    "Deferring exploit — no credential or hash available for target domain"
                );
                return Ok(None);
            }

            // For MSSQL vulns, include ALL available credentials for the
            // domain so the LLM can try each one (different users have
            // different MSSQL permissions — e.g. sam.wilson can
            // EXECUTE AS LOGIN = 'sa').
            let all_creds = if vuln.vuln_type.starts_with("mssql") && !domain.is_empty() {
                let v: Vec<_> = state
                    .credentials
                    .iter()
                    .filter(|c| {
                        c.domain.eq_ignore_ascii_case(domain)
                            && !state.is_delegation_account(&c.username)
                    })
                    .map(|c| {
                        json!({
                            "username": c.username,
                            "password": c.password,
                            "domain": c.domain,
                        })
                    })
                    .collect();
                Some(v)
            } else {
                None
            };

            (auth, all_creds)
        };

        if let Some(ref cred) = auth.credential {
            payload["credential"] = json!({
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            });
        }

        if let Some(all_creds) = all_creds_for_mssql {
            if all_creds.len() > 1 {
                payload["all_credentials"] = json!(all_creds);
            }
        }

        if let Some(ref hash) = auth.hash {
            payload["hash"] = json!(hash.hash_value);
            payload["hash_username"] = json!(hash.username);
            if let Some(ref aes) = hash.aes_key {
                payload["aes_key"] = json!(aes);
            }
        }

        // Per-vuln role override. Explicit `recommended_agent` wins. When the
        // emitting parser left it empty, infer the worker that actually has
        // the right tools: ACL primitives (genericall/writedacl/writeproperty/
        // allextendedrights/etc.) route to the `acl` worker which exposes
        // `bloodyad_add_group_member`, `bloodyad_set_password`,
        // `bloodyad_add_genericall`, `pywhisker`, and `dacl_edit`. The
        // legacy default of `privesc` left the agent with certipy/mssql/
        // delegation tools only, so AllExtendedRights-on-group primitives
        // dispatched as `exploit_*` would bail with "missing bloodyAD".
        let role: String = if !vuln.recommended_agent.is_empty() {
            vuln.recommended_agent.clone()
        } else if is_acl_style_vuln_type(&vuln.vuln_type) {
            "acl".to_string()
        } else {
            "privesc".to_string()
        };
        self.throttled_submit("exploit", &role, payload, priority)
            .await
    }

    /// Submit a BloodHound collection task.
    #[instrument(
        name = "automation.request_bloodhound",
        skip(self, credential),
        fields(domain = %domain, dc_ip = %dc_ip, username = %credential.username),
    )]
    pub async fn request_bloodhound(
        &self,
        domain: &str,
        dc_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "bloodhound_collect",
            "domain": domain,
            "target_ip": dc_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 7).await
    }

    /// Submit a share enumeration task against a host using credentials.
    #[instrument(
        name = "automation.request_share_enumeration",
        skip(self, credential),
        fields(host_ip = %host_ip, username = %credential.username, domain = %credential.domain),
    )]
    pub async fn request_share_enumeration(
        &self,
        host_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "techniques": ["enumerate_shares"],
            "target_ip": host_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 5).await
    }

    /// Submit a share spider task.
    #[instrument(
        name = "automation.request_share_spider",
        skip(self, credential),
        fields(host_ip = %host_ip, share_name = %share_name, username = %credential.username),
    )]
    pub async fn request_share_spider(
        &self,
        host_ip: &str,
        share_name: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "share_spider",
            "target_ip": host_ip,
            "share_name": share_name,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, 8)
            .await
    }

    /// Submit a coercion task.
    #[instrument(
        name = "automation.request_coercion",
        skip(self),
        fields(target_ip = %target_ip, listener_ip = %listener_ip, technique_count = techniques.len()),
    )]
    pub async fn request_coercion(
        &self,
        target_ip: &str,
        listener_ip: &str,
        techniques: &[&str],
    ) -> Result<Option<String>> {
        let payload = json!({
            "target_ip": target_ip,
            "listener_ip": listener_ip,
            "techniques": techniques,
        });
        self.throttled_submit("coercion", "coercion", payload, 3)
            .await
    }

    /// Refresh the operation lock TTL. Called periodically.
    pub async fn extend_lock(&self) -> Result<()> {
        let op_id = self.state.operation_id().await;
        self.queue.extend_lock(&op_id, self.config.lock_ttl).await?;
        Ok(())
    }

    /// Publish a state update notification via Redis PubSub.
    pub async fn notify_state_update(&self) -> Result<()> {
        let op_id = self.state.operation_id().await;
        self.queue.publish_state_update(&op_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred(username: &str, domain: &str) -> Credential {
        Credential {
            id: format!("cred-{username}-{domain}"),
            username: username.into(),
            password: "P@ssw0rd!".into(),
            domain: domain.into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(username: &str, domain: &str) -> Hash {
        Hash {
            id: format!("hash-{username}-{domain}"),
            username: username.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            hash_type: "NTLM".into(),
            domain: domain.into(),
            cracked_password: None,
            source: "test".into(),
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

    #[test]
    fn select_auth_prefers_account_name_over_domain() {
        let mut state = StateInner::new("op-test".into());
        state.credentials.push(make_cred("bob", "fabrikam.local"));
        state.credentials.push(make_cred("alice", "contoso.local"));

        let auth = select_exploit_auth(&state, Some("alice"), "fabrikam.local");

        assert_eq!(auth.credential.as_ref().unwrap().username, "alice");
        assert_eq!(auth.credential.as_ref().unwrap().domain, "contoso.local");
    }

    #[test]
    fn select_auth_finds_domain_cred_when_account_unset() {
        let mut state = StateInner::new("op-test".into());
        state.credentials.push(make_cred("alice", "contoso.local"));
        state.credentials.push(make_cred("carol", "fabrikam.local"));

        let auth = select_exploit_auth(&state, None, "fabrikam.local");

        assert_eq!(auth.credential.as_ref().unwrap().username, "carol");
    }

    #[test]
    fn select_auth_returns_no_cred_when_domain_unmatched() {
        let mut state = StateInner::new("op-test".into());
        state.credentials.push(make_cred("alice", "contoso.local"));

        let auth = select_exploit_auth(&state, None, "fabrikam.local");

        assert!(
            auth.credential.is_none(),
            "must not fall back to wrong-realm cred"
        );
    }

    #[test]
    fn select_auth_falls_back_to_any_cred_when_no_domain() {
        let mut state = StateInner::new("op-test".into());
        state.credentials.push(make_cred("alice", "contoso.local"));

        let auth = select_exploit_auth(&state, None, "");

        assert_eq!(auth.credential.as_ref().unwrap().username, "alice");
    }

    #[test]
    fn select_auth_picks_domain_hash_when_account_unset() {
        let mut state = StateInner::new("op-test".into());
        state.hashes.push(make_hash("carol", "fabrikam.local"));
        state.hashes.push(make_hash("alice", "contoso.local"));

        let auth = select_exploit_auth(&state, None, "fabrikam.local");

        assert_eq!(auth.hash.as_ref().unwrap().domain, "fabrikam.local");
    }

    #[test]
    fn select_auth_domain_match_is_case_insensitive() {
        let mut state = StateInner::new("op-test".into());
        state.credentials.push(make_cred("alice", "FABRIKAM.LOCAL"));

        let auth = select_exploit_auth(&state, None, "fabrikam.local");

        assert!(auth.credential.is_some());
    }

    #[test]
    fn matches_domain_true_when_cred_matches() {
        let auth = ExploitAuth {
            credential: Some(make_cred("alice", "fabrikam.local")),
            hash: None,
        };
        assert!(auth.matches_domain("fabrikam.local"));
        assert!(auth.matches_domain("FABRIKAM.LOCAL"));
    }

    #[test]
    fn matches_domain_true_when_hash_matches() {
        let auth = ExploitAuth {
            credential: None,
            hash: Some(make_hash("alice", "fabrikam.local")),
        };
        assert!(auth.matches_domain("fabrikam.local"));
    }

    #[test]
    fn matches_domain_false_when_neither_matches() {
        // A cred for the wrong realm must NOT satisfy the gate: the exploit
        // should be deferred, not dispatched with a wrong-realm cred attached.
        let auth = ExploitAuth {
            credential: Some(make_cred("alice", "contoso.local")),
            hash: None,
        };
        assert!(!auth.matches_domain("fabrikam.local"));
    }

    #[test]
    fn matches_domain_empty_target_accepts_any_auth() {
        let auth = ExploitAuth {
            credential: Some(make_cred("alice", "contoso.local")),
            hash: None,
        };
        // Empty target = no domain constraint, any auth matches.
        assert!(auth.matches_domain(""));
    }

    #[test]
    fn matches_domain_empty_target_rejects_no_auth() {
        let auth = ExploitAuth::default();
        assert!(!auth.matches_domain(""));
    }

    #[test]
    fn preauth_vuln_types_bypass_gate() {
        for vt in [
            "zerologon",
            "ZeroLogon",
            "nopac",
            "petitpotam_unauth",
            "printnightmare_unauth",
            "dfscoerce_unauth",
            "esc8_relay",
        ] {
            assert!(vuln_type_is_preauth(vt), "{vt} should be pre-auth");
        }
    }

    #[test]
    fn auth_required_vuln_types_do_not_bypass_gate() {
        for vt in [
            "mssql_access",
            "writeproperty",
            "genericall",
            "dcsync",
            "esc1",
            "kerberoast",
        ] {
            assert!(
                !vuln_type_is_preauth(vt),
                "{vt} should require credential gate"
            );
        }
    }

    #[test]
    fn select_auth_skips_delegation_account_in_domain_fallback() {
        let mut state = StateInner::new("op-test".into());
        // Mark svc_deleg as a delegation account by adding a vuln that names it.
        state.discovered_vulnerabilities.insert(
            "vuln-deleg".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "vuln-deleg".into(),
                vuln_type: "constrained_delegation".into(),
                target: "192.168.58.10".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(
                        "account_name".into(),
                        serde_json::Value::String("svc_deleg".into()),
                    );
                    m
                },
                recommended_agent: String::new(),
                priority: 1,
            },
        );
        state
            .credentials
            .push(make_cred("svc_deleg", "fabrikam.local"));
        state.credentials.push(make_cred("alice", "fabrikam.local"));

        // account_name unset → falls back to domain match, must skip svc_deleg.
        let auth = select_exploit_auth(&state, None, "fabrikam.local");

        assert_eq!(auth.credential.as_ref().unwrap().username, "alice");
    }

    #[test]
    fn is_acl_style_vuln_type_matches_bare_and_prefixed() {
        // Bare forms emitted by some parsers.
        assert!(is_acl_style_vuln_type("genericall"));
        assert!(is_acl_style_vuln_type("GenericAll"));
        assert!(is_acl_style_vuln_type("writedacl"));
        assert!(is_acl_style_vuln_type("allextendedrights"));
        assert!(is_acl_style_vuln_type("forcechangepassword"));
        assert!(is_acl_style_vuln_type("writeowner"));
        assert!(is_acl_style_vuln_type("writeproperty"));
        // Prefixed forms emitted by acl_discovery / bloodhound bridging.
        assert!(is_acl_style_vuln_type(
            "acl_allextendedrights_s-1-5-21-1-2-3-519_administrators"
        ));
        assert!(is_acl_style_vuln_type("acl_writeproperty_member_admins"));
        assert!(is_acl_style_vuln_type("acl_genericall_dc01$"));
    }

    #[test]
    fn is_acl_style_vuln_type_rejects_non_acl() {
        assert!(!is_acl_style_vuln_type("mssql_access"));
        assert!(!is_acl_style_vuln_type("dcsync"));
        assert!(!is_acl_style_vuln_type("adcs_esc1"));
        assert!(!is_acl_style_vuln_type("constrained_delegation"));
        assert!(!is_acl_style_vuln_type("kerberoast"));
        assert!(!is_acl_style_vuln_type(""));
    }

    #[test]
    fn is_acl_style_vuln_type_matches_membership_variants() {
        assert!(is_acl_style_vuln_type("self_membership"));
        assert!(is_acl_style_vuln_type("write_membership"));
        assert!(is_acl_style_vuln_type("addmember"));
        assert!(is_acl_style_vuln_type("addself"));
        assert!(is_acl_style_vuln_type("AddMember"));
        assert!(is_acl_style_vuln_type("acl_addmember_administrators"));
    }

    #[test]
    fn is_acl_style_vuln_type_genericwrite_variant() {
        assert!(is_acl_style_vuln_type("genericwrite"));
        assert!(is_acl_style_vuln_type("GenericWrite"));
        assert!(is_acl_style_vuln_type("acl_genericwrite_dc01"));
    }
}
