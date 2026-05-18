//! Result consumption loop.
//!
//! A dedicated tokio task that polls Redis for completed task results and
//! feeds them back to the main orchestration loop via an mpsc channel.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::dispatcher::CredentialInflight;
use crate::orchestrator::routing::ActiveTaskTracker;
use crate::orchestrator::task_queue::{TaskQueue, TaskResult};

/// A completed task result, ready for the orchestrator to process.
#[derive(Debug)]
pub struct CompletedTask {
    pub task_id: String,
    pub result: TaskResult,
}

/// Spawn the result-consumer background task.
///
/// Returns an mpsc receiver that the main loop reads from.
pub fn spawn_result_consumer(
    queue: TaskQueue,
    tracker: ActiveTaskTracker,
    credential_inflight: CredentialInflight,
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

            match consume_cycle(&queue, &tracker, &credential_inflight, &tx).await {
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
    credential_inflight: &CredentialInflight,
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
            // Remove from tracker and release the per-credential inflight
            // slot the task was holding (if any). The slot is now bound to
            // the tracker entry's lifetime, so a hung tokio future never
            // pins the slot indefinitely.
            if let Some(removed) = tracker.remove(&task_id).await {
                if let Some(ref key) = removed.credential_key {
                    credential_inflight.release(key).await;
                }
            }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_err(msg: &str) -> anyhow::Error {
        anyhow::anyhow!("{}", msg)
    }

    #[test]
    fn connection_keyword_matches() {
        assert!(is_connection_error(&conn_err("connection refused")));
    }

    #[test]
    fn connect_keyword_matches() {
        assert!(is_connection_error(&conn_err("failed to connect to host")));
    }

    #[test]
    fn closed_keyword_matches() {
        assert!(is_connection_error(&conn_err("stream closed unexpectedly")));
    }

    #[test]
    fn timeout_keyword_matches() {
        assert!(is_connection_error(&conn_err(
            "timeout waiting for response"
        )));
    }

    #[test]
    fn broken_pipe_keyword_matches() {
        assert!(is_connection_error(&conn_err("broken pipe")));
    }

    #[test]
    fn reset_keyword_matches() {
        assert!(is_connection_error(&conn_err("connection reset by peer")));
    }

    #[test]
    fn refused_keyword_matches() {
        assert!(is_connection_error(&conn_err("connection refused")));
    }

    #[test]
    fn sentinel_keyword_matches() {
        assert!(is_connection_error(&conn_err(
            "sentinel failover in progress"
        )));
    }

    #[test]
    fn unrelated_error_does_not_match() {
        assert!(!is_connection_error(&conn_err("permission denied")));
    }

    #[test]
    fn empty_error_does_not_match() {
        assert!(!is_connection_error(&conn_err("")));
    }

    #[test]
    fn case_insensitive_match() {
        assert!(is_connection_error(&conn_err("CONNECTION RESET")));
        assert!(is_connection_error(&conn_err("TIMEOUT")));
        assert!(is_connection_error(&conn_err("Broken Pipe")));
    }

    #[test]
    fn parse_error_does_not_match() {
        assert!(!is_connection_error(&conn_err("failed to parse JSON")));
    }
}
