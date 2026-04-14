//! auto_share_spider -- spider readable shares for credentials.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Spiders readable shares for credentials using available creds.
/// Interval: 30s. Matches Python `_auto_share_spider`.
pub async fn auto_share_spider(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            // Use first non-delegation credential to avoid burning auth budget
            // on accounts reserved for S4U exploitation.
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
                .filter(|s| {
                    let perms = s.permissions.to_uppercase();
                    perms.contains("READ") && !s.name.to_uppercase().ends_with('$')
                })
                .filter_map(|s| {
                    let dedup = format!("{}:{}:{}:{}", s.host, s.name, cred.username, cred.domain);
                    if state.is_processed(DEDUP_SPIDERED_SHARES, &dedup) {
                        None
                    } else {
                        Some((dedup, s.host.clone(), s.name.clone(), cred.clone()))
                    }
                })
                .take(3) // limit batch size
                .collect()
        };

        for (dedup_key, host, share, cred) in work {
            match dispatcher.request_share_spider(&host, &share, &cred).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, host = %host, share = %share, "Share spider dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SPIDERED_SHARES, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SPIDERED_SHARES, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch share spider"),
            }
        }
    }
}
