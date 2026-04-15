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

        // Serialize crack tasks: hashcat only allows one instance at a time.
        // Skip this tick if a cracker task is already running.
        if dispatcher.tracker.count_for_role("cracker").await > 0 {
            debug!("Crack task already active, skipping dispatch this tick");
            continue;
        }

        // Only dispatch one crack task per tick to avoid hashcat PID conflicts.
        // Remaining hashes will be picked up on subsequent ticks.
        if let Some((dedup_key, hash)) = work.into_iter().next() {
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
