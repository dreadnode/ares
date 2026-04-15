//! auto_bloodhound -- BloodHound collection per domain.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_llm::routing::find_domain_credential;

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Dispatches BloodHound collection for each discovered domain.
/// Interval: 30s. Matches Python `_auto_bloodhound`.
///
/// Selects the best credential per domain (same-domain preferred, with
/// trust-scope enforcement) instead of using a single global credential.
pub async fn auto_bloodhound(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            if state.credentials.is_empty() {
                continue;
            }

            state
                .domains
                .iter()
                .filter(|d| !state.is_processed(DEDUP_BLOODHOUND_DOMAINS, d))
                .filter_map(|domain| {
                    let dc_ip = state.domain_controllers.get(domain).cloned()?;
                    // Select best credential for this specific domain
                    let cred = find_domain_credential(
                        domain,
                        &state.credentials,
                        &state.netbios_to_fqdn,
                        &state.trusted_domains,
                    );
                    match cred {
                        Some(c) => Some((domain.clone(), dc_ip, c.clone())),
                        None => {
                            debug!(domain = %domain, "No valid credential for BloodHound");
                            None
                        }
                    }
                })
                .collect()
        };

        for (domain, dc_ip, cred) in work {
            match dispatcher.request_bloodhound(&domain, &dc_ip, &cred).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "BloodHound collection dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_BLOODHOUND_DOMAINS, domain.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_BLOODHOUND_DOMAINS, &domain)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch BloodHound"),
            }
        }
    }
}
