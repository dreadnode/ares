//! auto_adcs_enumeration -- detect ADCS servers via CertEnroll share.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Detects ADCS servers by looking for CertEnroll shares and dispatches certipy_find.
/// Interval: 30s. Matches Python `_auto_adcs_enumeration`.
pub async fn auto_adcs_enumeration(
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

        // Find CertEnroll shares on unprocessed hosts + get a credential
        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let cred = match state
                .credentials
                .iter()
                .find(|c| {
                    !state.is_delegation_account(&c.username)
                        && !state.is_credential_quarantined(&c.username, &c.domain)
                })
                .or_else(|| state.credentials.first())
            {
                Some(c) => c.clone(),
                None => continue,
            };
            state
                .shares
                .iter()
                .filter(|s| s.name.to_lowercase() == "certenroll")
                .filter(|s| !state.is_processed(DEDUP_ADCS_SERVERS, &s.host))
                .filter_map(|s| {
                    // Resolve the domain for this ADCS host by matching the
                    // host's FQDN against known domains, or finding which DC
                    // subnet the host belongs to.  Falls back to first domain.
                    let host_lower = s.host.to_lowercase();
                    let domain = state
                        .hosts
                        .iter()
                        .find(|h| h.ip == s.host || h.hostname.to_lowercase() == host_lower)
                        .and_then(|h| {
                            // Extract domain from FQDN: braavos.essos.local → essos.local
                            let fqdn = h.hostname.to_lowercase();
                            fqdn.split_once('.').map(|(_, d)| d.to_string())
                        })
                        .and_then(|d| {
                            // Verify it's a known domain
                            if state.domains.iter().any(|known| known.to_lowercase() == d) {
                                Some(d)
                            } else {
                                // Try parent match (e.g. child.contoso.local → contoso.local)
                                state
                                    .domains
                                    .iter()
                                    .find(|known| {
                                        d.ends_with(&format!(".{}", known.to_lowercase()))
                                    })
                                    .or_else(|| {
                                        state.domains.iter().find(|known| {
                                            known.to_lowercase().ends_with(&format!(".{d}"))
                                        })
                                    })
                                    .cloned()
                                    .or(Some(d))
                            }
                        })
                        .or_else(|| state.domains.first().cloned())?;
                    Some((s.host.clone(), domain, cred.clone()))
                })
                .collect()
        };

        for (host_ip, domain, cred) in work {
            match dispatcher
                .request_certipy_find(&host_ip, &domain, &cred)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, host = %host_ip, "ADCS enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ADCS_SERVERS, host_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ADCS_SERVERS, &host_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch ADCS enumeration"),
            }
        }
    }
}
