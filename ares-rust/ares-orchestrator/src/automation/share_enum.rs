//! auto_share_enumeration -- enumerate SMB shares on discovered hosts using credentials.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Dispatches share enumeration on each known host when credentials are available.
/// Interval: 20s. Dedup key: "{host_ip}:{cred_user}:{cred_domain}".
pub async fn auto_share_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut no_cred_logged = false;

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
                Some(c) => {
                    no_cred_logged = false;
                    c.clone()
                }
                None => {
                    if !no_cred_logged {
                        info!(
                            hosts = state.hosts.len(),
                            target_ips = state.target_ips.len(),
                            "Share enum: no credentials in memory yet, waiting"
                        );
                        no_cred_logged = true;
                    }
                    continue;
                }
            };

            // Enumerate shares on every known host (target IPs + discovered hosts)
            let mut ips: Vec<String> = state.target_ips.clone();
            for host in &state.hosts {
                if !ips.contains(&host.ip) {
                    ips.push(host.ip.clone());
                }
            }

            ips.into_iter()
                .filter_map(|ip| {
                    let dedup = format!(
                        "{}:{}:{}",
                        ip,
                        cred.username.to_lowercase(),
                        cred.domain.to_lowercase()
                    );
                    if state.is_processed(DEDUP_SHARE_ENUM, &dedup) {
                        None
                    } else {
                        Some((dedup, ip, cred.clone()))
                    }
                })
                .take(5)
                .collect()
        };

        for (dedup_key, host_ip, cred) in work {
            match dispatcher.request_share_enumeration(&host_ip, &cred).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, host = %host_ip, "Share enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SHARE_ENUM, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SHARE_ENUM, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch share enumeration"),
            }
        }
    }
}
