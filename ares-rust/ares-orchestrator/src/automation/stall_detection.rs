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
const STALL_THRESHOLD: Duration = Duration::from_secs(300); // 5 minutes

/// Minimum interval between stall recovery actions.
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(600); // 10 minutes

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
        if recovery_attempts >= 3 {
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
        if has_users && has_dcs {
            let spray_work: Vec<(String, String)> = {
                let state = dispatcher.state.read().await;
                state
                    .domain_controllers
                    .iter()
                    .filter(|(domain, _)| {
                        let key = format!("stall_spray:{}", domain.to_lowercase());
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
                        let key = format!("stall_spray:{}", domain.to_lowercase());
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

        // --- Fallback 2: LDAP description search with all creds ---
        if has_creds && has_dcs {
            let ldap_work: Option<(String, String, ares_core::models::Credential)> = {
                let state = dispatcher.state.read().await;
                state.credentials.first().and_then(|cred| {
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned()?;
                    let key = format!("stall_ldap:{}:{}", cred.domain, cred.username);
                    if state.is_processed(DEDUP_EXPANSION_CREDS, &key) {
                        return None;
                    }
                    Some((key, dc_ip, cred.clone()))
                })
            };

            if let Some((key, dc_ip, cred)) = ldap_work {
                let payload = json!({
                    "technique": "ldap_search_descriptions",
                    "target_ip": dc_ip,
                    "domain": cred.domain,
                    "credential": {
                        "username": cred.username,
                        "password": cred.password,
                        "domain": cred.domain,
                    },
                });

                match dispatcher
                    .throttled_submit("credential_access", "credential_access", payload, 6)
                    .await
                {
                    Ok(Some(task_id)) => {
                        info!(task_id = %task_id, "Stall recovery: LDAP description search dispatched");
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
                    Err(e) => warn!(err = %e, "Stall recovery: LDAP search failed"),
                }
            }
        }
    }
}
