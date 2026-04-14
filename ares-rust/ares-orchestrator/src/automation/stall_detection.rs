//! auto_stall_detection -- detect when the operation is stuck and take action.
//!
//! When no new credentials or hashes have been discovered for a configurable
//! period (default: 5 minutes), this automation triggers fallback actions:
//!
//!   1. Re-attempt password spray with discovered users
//!   2. Start responder + NTLM relay if not already running
//!   3. Re-run LDAP description search with all known creds
//!
//! This prevents the operation from idling when all easy wins are exhausted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// How long without new discoveries before we consider the op stalled.
const STALL_THRESHOLD: Duration = Duration::from_secs(180); // 3 minutes

/// Minimum interval between stall recovery actions.
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(120); // 2 minutes

/// Monitors for discovery stalls and triggers fallback actions.
/// Interval: 60s.
pub async fn auto_stall_detection(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let start = Instant::now();
    let mut last_cred_count = 0usize;
    let mut last_hash_count = 0usize;
    let mut last_change = Instant::now();
    let mut last_recovery = Instant::now() - RECOVERY_COOLDOWN; // allow immediate first recovery
    let mut recovery_attempts = 0u32;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Don't check stall in the first 3 minutes (let initial recon complete)
        if start.elapsed() < Duration::from_secs(180) {
            continue;
        }

        let (cred_count, hash_count, has_da, has_creds, has_users, has_dcs) = {
            let state = dispatcher.state.read().await;
            (
                state.credentials.len(),
                state.hashes.len(),
                state.has_domain_admin,
                !state.credentials.is_empty(),
                !state.users.is_empty(),
                !state.domain_controllers.is_empty(),
            )
        };

        // Skip if we've achieved domain admin
        if has_da {
            continue;
        }

        // Check if there has been progress
        if cred_count > last_cred_count || hash_count > last_hash_count {
            last_cred_count = cred_count;
            last_hash_count = hash_count;
            last_change = Instant::now();
            recovery_attempts = 0; // Reset on progress
            continue;
        }

        // Not stalled yet
        if last_change.elapsed() < STALL_THRESHOLD {
            continue;
        }

        // Cooldown between recovery actions
        if last_recovery.elapsed() < RECOVERY_COOLDOWN {
            continue;
        }

        // Cap recovery attempts (don't spam indefinitely)
        if recovery_attempts >= 10 {
            continue;
        }

        info!(
            stall_duration_secs = last_change.elapsed().as_secs(),
            cred_count,
            hash_count,
            recovery_attempt = recovery_attempts + 1,
            "Operation stall detected — triggering fallback actions"
        );

        last_recovery = Instant::now();
        recovery_attempts += 1;

        // --- Fallback 1: Password spray with discovered users ---
        // Skip domains with pending delegation vulns — sprays lock delegation
        // accounts and prevent S4U exploitation from succeeding.
        if has_users && has_dcs {
            let spray_work: Vec<(String, String)> = {
                let state = dispatcher.state.read().await;
                // Collect domains that have pending delegation vulns
                let delegation_domains: std::collections::HashSet<String> = state
                    .discovered_vulnerabilities
                    .values()
                    .filter(|v| {
                        let vt = v.vuln_type.to_lowercase();
                        (vt == "constrained_delegation" || vt == "rbcd")
                            && !state.exploited_vulnerabilities.contains(&v.vuln_id)
                    })
                    .filter_map(|v| {
                        v.details
                            .get("domain")
                            .or_else(|| v.details.get("Domain"))
                            .and_then(|d| d.as_str())
                            .map(|d| d.to_lowercase())
                    })
                    .collect();
                state
                    .domain_controllers
                    .iter()
                    .filter(|(domain, _)| {
                        // Skip domains with pending delegation vulns
                        if delegation_domains.contains(&domain.to_lowercase()) {
                            return false;
                        }
                        // Use recovery_attempts in key so each round dispatches fresh sprays
                        let key = format!(
                            "stall_spray:{}:{}",
                            domain.to_lowercase(),
                            recovery_attempts
                        );
                        !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
                    })
                    .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
                    .collect()
            };

            for (domain, dc_ip) in spray_work {
                let payload = json!({
                    "technique": "password_spray",
                    "target_ip": dc_ip,
                    "domain": domain,
                    "use_common_passwords": true,
                });

                match dispatcher
                    .throttled_submit("credential_access", "credential_access", payload, 7)
                    .await
                {
                    Ok(Some(task_id)) => {
                        info!(task_id = %task_id, domain = %domain, "Stall recovery: password spray dispatched");
                        let key = format!(
                            "stall_spray:{}:{}",
                            domain.to_lowercase(),
                            recovery_attempts
                        );
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_PASSWORD_SPRAY, key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_PASSWORD_SPRAY, &key)
                            .await;
                    }
                    Ok(None) => {}
                    Err(e) => warn!(err = %e, "Stall recovery: spray failed"),
                }
            }
        }

        // --- Fallback 2: Low-hanging fruit (SYSVOL, GPP, LDAP descriptions, LAPS) ---
        if has_creds && has_dcs {
            let lhf_work: Vec<(String, String, String, ares_core::models::Credential)> = {
                let state = dispatcher.state.read().await;
                state
                    .credentials
                    .iter()
                    .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                    .filter_map(|cred| {
                        let cred_domain = cred.domain.to_lowercase();
                        let key = format!(
                            "stall_lhf:{}:{}:{}",
                            cred_domain,
                            cred.username.to_lowercase(),
                            recovery_attempts
                        );
                        if state.is_processed(DEDUP_EXPANSION_CREDS, &key) {
                            return None;
                        }
                        let dc_ip = state
                            .domain_controllers
                            .get(&cred_domain)
                            .cloned()
                            .or_else(|| {
                                let suffix = format!(".{cred_domain}");
                                state
                                    .domain_controllers
                                    .iter()
                                    .find(|(d, _)| d.ends_with(&suffix))
                                    .map(|(_, ip)| ip.clone())
                            })?;
                        Some((key, dc_ip, cred_domain, cred.clone()))
                    })
                    .take(2)
                    .collect()
            };

            for (key, dc_ip, domain, cred) in lhf_work {
                match dispatcher
                    .request_low_hanging_fruit(&dc_ip, &domain, &cred, 6)
                    .await
                {
                    Ok(Some(task_id)) => {
                        info!(task_id = %task_id, domain = %domain, "Stall recovery: low-hanging fruit dispatched");
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_EXPANSION_CREDS, key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_EXPANSION_CREDS, &key)
                            .await;
                    }
                    Ok(None) => {}
                    Err(e) => warn!(err = %e, "Stall recovery: low-hanging fruit failed"),
                }
            }
        }
    }
}
