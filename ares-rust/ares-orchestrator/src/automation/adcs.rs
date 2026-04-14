//! auto_adcs_enumeration -- detect ADCS servers via CertEnroll share.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

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
                .map(|s| {
                    let domain = state.domains.first().cloned().unwrap_or_default();
                    (s.host.clone(), domain, cred.clone())
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
