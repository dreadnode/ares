//! Result consumption loop.
//!
//! A dedicated tokio task that polls Redis for completed task results and
//! feeds them back to the main orchestration loop via an mpsc channel.
//! Mirrors the Python `MonitoringMixin._result_consumer` but uses async
//! Rust instead of a dedicated thread.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::config::OrchestratorConfig;
use crate::routing::ActiveTaskTracker;
use crate::task_queue::{TaskQueue, TaskResult};

// ---------------------------------------------------------------------------
// CompletedTask — sent over the channel to the main loop
// ---------------------------------------------------------------------------

/// A completed task result, ready for the orchestrator to process.
#[derive(Debug)]
pub struct CompletedTask {
    pub task_id: String,
    pub result: TaskResult,
}

// ---------------------------------------------------------------------------
// Result consumer
// ---------------------------------------------------------------------------

/// Spawn the result-consumer background task.
///
/// Returns an mpsc receiver that the main loop reads from.
pub fn spawn_result_consumer(
    queue: TaskQueue,
    tracker: ActiveTaskTracker,
    config: Arc<OrchestratorConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<CompletedTask>) {
    // Bounded channel — back-pressure if the main loop can't keep up.
    let (tx, rx) = mpsc::channel::<CompletedTask>(256);

    let handle = tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        let poll_interval = config.result_poll_interval;

        info!("Result consumer started");

        loop {
            // Check shutdown before each poll cycle
            if *shutdown.borrow() {
                info!("Result consumer shutting down");
                break;
            }

            match consume_cycle(&queue, &tracker, &tx).await {
                Ok(found) => {
                    if consecutive_failures > 0 {
                        info!(
                            prev_failures = consecutive_failures,
                            "Result consumer recovered"
                        );
                    }
                    consecutive_failures = 0;

                    if found > 0 {
                        debug!(results = found, "Consumed results");
                        // When results arrive, poll again immediately instead
                        // of sleeping — results often come in bursts.
                        continue;
                    }
                }
                Err(e) => {
                    consecutive_failures += 1;
                    let is_conn = is_connection_error(&e);

                    if is_conn {
                        let delay = Duration::from_secs(std::cmp::min(
                            60,
                            2_u64.pow(consecutive_failures.min(5)),
                        ));

                        if consecutive_failures >= 10 {
                            error!(
                                attempt = consecutive_failures,
                                err = %e,
                                "Result consumer: Redis unavailable for extended period, still retrying"
                            );
                        } else {
                            warn!(
                                attempt = consecutive_failures,
                                err = %e,
                                delay_secs = delay.as_secs(),
                                "Result consumer: connection error, retrying"
                            );
                        }

                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {},
                            _ = shutdown.changed() => {
                                info!("Result consumer shutting down (signalled during backoff)");
                                break;
                            }
                        }
                        continue;
                    } else {
                        warn!(err = %e, "Result consumer non-connection error");
                    }
                }
            }

            // Normal pace — sleep between polls
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {},
                _ = shutdown.changed() => {
                    info!("Result consumer shutting down (signalled during sleep)");
                    break;
                }
            }
        }

        info!("Result consumer stopped");
    });

    (handle, rx)
}

/// One polling cycle: check all tracked tasks for results.
async fn consume_cycle(
    queue: &TaskQueue,
    tracker: &ActiveTaskTracker,
    tx: &mpsc::Sender<CompletedTask>,
) -> Result<usize> {
    let task_ids = tracker.task_ids().await;
    if task_ids.is_empty() {
        return Ok(0);
    }

    let results = queue
        .check_results_batch(&task_ids)
        .await
        .inspect_err(|e| warn!(tracked = task_ids.len(), err = %e, "check_results_batch failed"))?;

    let mut found = 0_usize;
    for (task_id, maybe_result) in results {
        if let Some(result) = maybe_result {
            // Remove from tracker
            tracker.remove(&task_id).await;

            // Send to main loop
            let completed = CompletedTask {
                task_id: task_id.clone(),
                result,
            };
            if tx.send(completed).await.is_err() {
                // Main loop dropped the receiver — shutting down
                info!("Result channel closed, stopping consumer");
                break;
            }
            found += 1;
        }
    }

    Ok(found)
}

/// Heuristic to identify Redis connection errors.
fn is_connection_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string().to_lowercase();
    [
        "connection",
        "connect",
        "closed",
        "timeout",
        "broken pipe",
        "reset",
        "refused",
        "sentinel",
    ]
    .iter()
    .any(|kw| msg.contains(kw))
}
