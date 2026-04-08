//! auto_crack_dispatch -- submit crack tasks for new hashes.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

use super::crack_dedup_key;

/// Scans for uncracked hashes and submits crack tasks.
/// Interval: 15s. Matches Python `_auto_crack_dispatch`.
pub async fn auto_crack_dispatch(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Collect unprocessed hashes
        let work: Vec<(String, ares_core::models::Hash)> = {
            let state = dispatcher.state.read().await;
            state
                .hashes
                .iter()
                .filter(|h| h.cracked_password.is_none())
                .filter_map(|h| {
                    let dedup = crack_dedup_key(h);
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        None
                    } else {
                        Some((dedup, h.clone()))
                    }
                })
                .collect()
        };

        for (dedup_key, hash) in work {
            match dispatcher.request_crack(&hash).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, hash_type = %hash.hash_type, "Crack task dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, &dedup_key)
                        .await;
                }
                Ok(None) => {} // deferred or throttled
                Err(e) => warn!(err = %e, "Failed to dispatch crack task"),
            }
        }
    }
}
