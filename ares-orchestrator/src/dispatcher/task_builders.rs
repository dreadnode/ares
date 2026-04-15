//! Convenience methods for common task types (request_crack, request_recon, etc.).

use anyhow::Result;
use serde_json::json;
use tracing::{debug, info};

use crate::state::DEDUP_SCANNED_TARGETS;

use super::Dispatcher;

impl Dispatcher {
    /// Submit a crack task for a hash.
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
    /// Guards (mirroring Python's `request_recon` in `routing.py`):
    /// 1. Skip entirely if domain admin has been achieved
    /// 2. Skip nmap tasks if all targets are already in `scanned_targets`
    /// 3. Auto-dispatch nmap prerequisite before enumeration if targets not scanned
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
    /// Mirrors Python's fast credential discovery dispatch: sends multiple high-success-rate
    /// techniques in a single task so the LLM agent executes them sequentially.
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

    /// Submit a lateral movement task.
    pub async fn request_lateral(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        technique: &str,
    ) -> Result<Option<String>> {
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

        // Look up credentials for this exploit from state
        {
            let state = self.state.read().await;

            // Try account_name from vuln details first, then fall back to any cred for the target domain
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

            // Try to find a matching credential
            let cred = if let Some(acct) = account_name {
                state
                    .credentials
                    .iter()
                    .find(|c| c.username.to_lowercase() == acct.to_lowercase())
            } else {
                None
            }
            .or_else(|| {
                // Fall back to any non-delegation credential for the vuln's domain
                if !domain.is_empty() {
                    state.credentials.iter().find(|c| {
                        c.domain.to_lowercase() == domain.to_lowercase()
                            && !state.is_delegation_account(&c.username)
                    })
                } else {
                    // Fall back to first available non-delegation credential
                    state
                        .credentials
                        .iter()
                        .find(|c| !state.is_delegation_account(&c.username))
                }
            });

            if let Some(cred) = cred {
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            }

            // For MSSQL vulns, include ALL available credentials for the domain
            // so the LLM can try each one (different users have different MSSQL
            // permissions — e.g. sam.wilson can EXECUTE AS LOGIN = 'sa').
            if vuln.vuln_type.starts_with("mssql") && !domain.is_empty() {
                let all_creds: Vec<_> = state
                    .credentials
                    .iter()
                    .filter(|c| {
                        c.domain.to_lowercase() == domain.to_lowercase()
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
                if all_creds.len() > 1 {
                    payload["all_credentials"] = json!(all_creds);
                }
            }

            // Also attach a hash if available for the account
            if let Some(acct) = account_name {
                if let Some(hash) = state
                    .hashes
                    .iter()
                    .find(|h| h.username.to_lowercase() == acct.to_lowercase())
                {
                    payload["hash"] = json!(hash.hash_value);
                    payload["hash_username"] = json!(hash.username);
                    if let Some(ref aes) = hash.aes_key {
                        payload["aes_key"] = json!(aes);
                    }
                }
            }
        }

        let role = if vuln.recommended_agent.is_empty() {
            "privesc"
        } else {
            &vuln.recommended_agent
        };
        self.throttled_submit("exploit", role, payload, priority)
            .await
    }

    /// Submit a BloodHound collection task.
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

    /// Submit a delegation enumeration task.
    pub async fn request_delegation_enum(
        &self,
        domain: &str,
        dc_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "find_delegation",
            "domain": domain,
            "target_ip": dc_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("privesc_enumeration", "recon", payload, 5)
            .await
    }

    /// Submit a share enumeration task against a host using credentials.
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

    /// Submit a CERTIPY find task for ADCS enumeration.
    pub async fn request_certipy_find(
        &self,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "certipy_find",
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 4).await
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
