//! state_refresh -- periodic refresh of state from Redis.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::warn;

use crate::dispatcher::Dispatcher;

/// Periodically refreshes state from Redis to pick up worker-published discoveries.
/// Interval: 10s.
pub async fn state_refresh(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip first tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if let Err(e) = dispatcher.state.refresh_from_redis(&dispatcher.queue).await {
            warn!(err = %e, "State refresh failed");
        }
    }
}
