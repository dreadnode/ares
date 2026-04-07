//! Completion and golden-ticket wait loops.
//!
//! These functions block (async) until the operation reaches a terminal state:
//! domain admin achieved, golden ticket forged, max runtime exceeded, or
//! explicit shutdown.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::SharedState;

/// Golden ticket processing statuses that indicate the domain is "done".
const GT_DONE_STATUSES: &[&str] = &[
    "success",
    "failed_no_dc",
    "failed_no_sid",
    "failed_ticketer",
];

/// Wait until all domains with krbtgt hashes have had their golden tickets
/// processed (or timeout).
///
/// Returns `true` if a golden ticket was successfully forged for at least one domain.
pub async fn wait_for_golden_ticket(
    state: &SharedState,
    mut shutdown_rx: watch::Receiver<bool>,
    timeout: Duration,
    interval: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut processed_domains: HashSet<String> = HashSet::new();

    info!(
        timeout_secs = timeout.as_secs(),
        "Waiting for golden ticket completion"
    );

    loop {
        // Check shutdown
        if *shutdown_rx.borrow() {
            info!("Golden ticket wait interrupted by shutdown");
            return false;
        }

        // Check timeout
        if tokio::time::Instant::now() >= deadline {
            warn!("Golden ticket wait timed out");
            break;
        }

        let (has_gt, all_done, domains_needing_gt) = {
            let inner = state.read().await;

            // Find domains that have krbtgt NTLM hashes
            let krbtgt_domains: HashSet<String> = inner
                .hashes
                .iter()
                .filter(|h| h.username.to_lowercase() == "krbtgt")
                .map(|h| {
                    if h.domain.is_empty() {
                        inner.domains.first().cloned().unwrap_or_default()
                    } else {
                        h.domain.to_lowercase()
                    }
                })
                .filter(|d| !d.is_empty())
                .collect();

            if krbtgt_domains.is_empty() {
                debug!("No krbtgt hashes found, nothing to wait for");
                return inner.has_golden_ticket;
            }

            // Check which domains still need processing
            let domains_needing_gt: Vec<String> = krbtgt_domains
                .iter()
                .filter(|d| !processed_domains.contains(*d))
                .cloned()
                .collect();

            let all_done = domains_needing_gt.is_empty();
            (inner.has_golden_ticket, all_done, domains_needing_gt)
        };

        // If has_golden_ticket flag is set, we're done
        if has_gt {
            info!("Golden ticket flag set, wait complete");
            return true;
        }

        // If all domains are processed, we're done
        if all_done {
            info!("All krbtgt domains processed for golden ticket");
            break;
        }

        debug!(
            pending = domains_needing_gt.len(),
            "Waiting for golden ticket on domains"
        );

        // Check completed tasks for golden ticket results
        {
            let inner = state.read().await;
            for (task_id, result) in &inner.completed_tasks {
                if let Some(ref payload) = result.result {
                    // Check if this is a golden ticket result
                    let is_gt = payload
                        .get("technique")
                        .and_then(|v| v.as_str())
                        .map(|t| t == "golden_ticket")
                        .unwrap_or(false);

                    if !is_gt {
                        continue;
                    }

                    let status = payload.get("status").and_then(|v| v.as_str()).unwrap_or(
                        if result.success {
                            "success"
                        } else {
                            "failed_ticketer"
                        },
                    );

                    if GT_DONE_STATUSES.contains(&status) {
                        if let Some(domain) = payload.get("domain").and_then(|v| v.as_str()) {
                            if !processed_domains.contains(domain) {
                                info!(
                                    task_id = %task_id,
                                    domain = domain,
                                    status = status,
                                    "Golden ticket result processed"
                                );
                                processed_domains.insert(domain.to_lowercase());
                            }
                        }
                    }
                }
            }
        }

        // Sleep until next check or shutdown
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Golden ticket wait interrupted by shutdown");
                    return false;
                }
            }
        }
    }

    // Final check
    let inner = state.read().await;
    inner.has_golden_ticket
}

/// Main operation completion loop.
///
/// Polls every `interval` checking for:
/// - `has_domain_admin` flag set
/// - `completed` flag set (external completion signal)
/// - Max runtime exceeded
///
/// On any completion condition, waits for golden ticket (with a shorter timeout)
/// before returning.
pub async fn wait_for_completion(
    state: &SharedState,
    dispatcher: &Arc<Dispatcher>,
    mut shutdown_rx: watch::Receiver<bool>,
    max_runtime: Duration,
    interval: Duration,
) {
    let start = tokio::time::Instant::now();

    info!(
        max_runtime_secs = max_runtime.as_secs(),
        "Completion monitor started"
    );

    loop {
        // Check shutdown
        if *shutdown_rx.borrow() {
            info!("Completion monitor interrupted by shutdown");
            return;
        }

        let elapsed = start.elapsed();
        let (has_da, has_gt, completed) = {
            let inner = state.read().await;
            (inner.has_domain_admin, inner.has_golden_ticket, false)
        };

        // Check completion conditions
        let reason = if completed {
            Some("operation marked completed")
        } else if elapsed >= max_runtime {
            Some("max runtime exceeded")
        } else if has_da {
            Some("domain admin achieved")
        } else {
            None
        };

        if let Some(reason) = reason {
            info!(
                reason = reason,
                elapsed_secs = elapsed.as_secs(),
                has_domain_admin = has_da,
                has_golden_ticket = has_gt,
                "Completion condition met"
            );

            // If we have DA but not golden ticket, wait for it
            if has_da && !has_gt {
                info!("Waiting for golden ticket before final completion");
                let gt_timeout = Duration::from_secs(60);
                let gt_interval = Duration::from_secs(5);
                let _got_gt =
                    wait_for_golden_ticket(state, shutdown_rx.clone(), gt_timeout, gt_interval)
                        .await;
            }

            // Extend the lock one final time before returning
            if let Err(e) = dispatcher.extend_lock().await {
                warn!(err = %e, "Failed to extend lock during completion");
            }

            return;
        }

        // Sleep until next check or shutdown
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Completion monitor interrupted by shutdown");
                    return;
                }
            }
        }
    }
}
