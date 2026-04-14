//! Completion and golden-ticket wait loops.
//!
//! These functions block (async) until the operation reaches a terminal state:
//! all forests dominated, golden tickets forged, max runtime exceeded, or
//! explicit shutdown.
//!
//! Two config flags control early-exit behaviour (mutually exclusive):
//! - `stop_on_domain_admin`: stop as soon as DA is achieved on any domain,
//!   without waiting for all trusted forests to be dominated.
//! - `stop_on_golden_ticket`: continue past DA to forge a golden ticket with
//!   ExtraSid for child→parent escalation, then stop once forged.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::SharedState;

/// Golden ticket processing statuses that indicate the domain is "done".
#[allow(dead_code)]
const GT_DONE_STATUSES: &[&str] = &[
    "success",
    "failed_no_dc",
    "failed_no_sid",
    "failed_ticketer",
];

/// Pure computation: given state fields, return undominated forest root domains.
///
/// Used by both the async `undominated_forests()` and `SharedState::snapshot()`.
pub fn compute_undominated_forests(
    target_domain: Option<&str>,
    first_domain: Option<&str>,
    trusted_domains: &std::collections::HashMap<String, ares_core::models::TrustInfo>,
    dominated_domains: &HashSet<String>,
) -> Vec<String> {
    let mut required_forests: HashSet<String> = HashSet::new();

    if let Some(td) = target_domain {
        if !td.is_empty() {
            required_forests.insert(forest_root_of(td));
        }
    }
    if let Some(fd) = first_domain {
        required_forests.insert(forest_root_of(fd));
    }

    for trust in trusted_domains.values() {
        if trust.is_cross_forest() {
            required_forests.insert(forest_root_of(&trust.domain));
        }
    }

    if required_forests.is_empty() {
        return Vec::new();
    }

    let dominated_roots: HashSet<String> = dominated_domains
        .iter()
        .map(|d| forest_root_of(d))
        .collect();

    required_forests
        .difference(&dominated_roots)
        .cloned()
        .collect()
}

/// Check if all trusted forests have been dominated.
///
/// Returns a list of forest root domains that still need krbtgt hashes.
/// An empty list means all forests are dominated.
///
/// This mirrors Python's `all_forests_dominated()` which checks that
/// krbtgt hashes are obtained from every trusted forest, not just the
/// initial target domain.
pub async fn undominated_forests(state: &SharedState) -> Vec<String> {
    let inner = state.read().await;
    compute_undominated_forests(
        inner.target.as_ref().map(|t| t.domain.as_str()),
        inner.domains.first().map(|d| d.as_str()),
        &inner.trusted_domains,
        &inner.dominated_domains,
    )
}

/// Extract forest root from a domain FQDN.
///
/// For `north.contoso.local` → `contoso.local`
/// For `contoso.local` → `contoso.local`
fn forest_root_of(domain: &str) -> String {
    let lower = domain.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() <= 2 {
        lower
    } else {
        // Walk up to find the 2-part root (assumes .local/.com TLD)
        parts[parts.len() - 2..].join(".")
    }
}

/// Wait until all domains with krbtgt hashes have had their golden tickets
/// processed (or timeout).
///
/// Returns `true` if a golden ticket was successfully forged for at least one domain.
#[allow(dead_code)]
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
/// - All forests dominated (krbtgt from every trusted forest)
/// - `completed` flag set (external completion signal)
/// - Max runtime exceeded
///
/// Behaviour is influenced by two mutually exclusive config flags:
/// - `stop_on_domain_admin`: stop as soon as DA is achieved on *any* domain,
///   without waiting for forests or golden tickets.
/// - `stop_on_golden_ticket`: continue past DA to forge a golden ticket with
///   ExtraSid, then stop. If the ticket isn't forged within 60 s of DA, stop
///   anyway.
///
/// When neither flag is set (default), the operation continues until all
/// trusted forests are dominated or max runtime is exceeded.
pub async fn wait_for_completion(
    state: &SharedState,
    dispatcher: &Arc<Dispatcher>,
    mut shutdown_rx: watch::Receiver<bool>,
    max_runtime: Duration,
    interval: Duration,
) {
    let start = tokio::time::Instant::now();

    // Read stop-condition flags from config (default: both false)
    let (stop_on_da, stop_on_gt) = dispatcher
        .ares_config
        .as_ref()
        .map(|c| {
            (
                c.operation.stop_on_domain_admin,
                c.operation.stop_on_golden_ticket,
            )
        })
        .unwrap_or((false, false));

    info!(
        max_runtime_secs = max_runtime.as_secs(),
        stop_on_domain_admin = stop_on_da,
        stop_on_golden_ticket = stop_on_gt,
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
            (
                inner.has_domain_admin,
                inner.has_golden_ticket,
                inner.completed,
            )
        };

        // Check completion conditions.
        //
        // Priority order matches Python's _wait_for_completion():
        // 1. External completed flag (e.g. CLI stop signal)
        // 2. Max runtime exceeded
        // 3. stop_on_domain_admin: stop immediately on DA
        // 4. stop_on_golden_ticket: stop when DA + golden ticket achieved
        // 5. Default: stop when all trusted forests are dominated
        let reason = if completed {
            Some("operation marked completed")
        } else if elapsed >= max_runtime {
            Some("max runtime exceeded")
        } else if has_da {
            if stop_on_da {
                // Config says stop immediately on DA — skip forest check
                Some("domain admin achieved (stop_on_domain_admin)")
            } else if stop_on_gt {
                // stop_on_golden_ticket: keep running until GT is forged.
                // Do NOT fall through to the "all forests dominated" default
                // path — that would exit without the golden ticket.
                if has_gt {
                    Some("golden ticket forged (stop_on_golden_ticket)")
                } else {
                    None // Continue — waiting for golden ticket
                }
            } else {
                // Default: continue until all forests are dominated
                let remaining = undominated_forests(state).await;
                if remaining.is_empty() {
                    Some("all forests dominated")
                } else {
                    debug!(
                        undominated = ?remaining,
                        "DA achieved but forests remain undominated"
                    );
                    None // Continue — other forests still need krbtgt
                }
            }
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

            // Signal the main loop to stop via Redis so it breaks out of its
            // select! within the next 5-second poll cycle.
            {
                let mut conn = dispatcher.queue.connection();
                if let Err(e) = ares_core::state::request_stop_operation(
                    &mut conn,
                    &dispatcher.config.operation_id,
                )
                .await
                {
                    warn!(err = %e, "Failed to set Redis stop signal from completion monitor");
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gt_done_statuses_contains_success() {
        assert!(GT_DONE_STATUSES.contains(&"success"));
    }

    #[test]
    fn test_gt_done_statuses_contains_failures() {
        assert!(GT_DONE_STATUSES.contains(&"failed_no_dc"));
        assert!(GT_DONE_STATUSES.contains(&"failed_no_sid"));
        assert!(GT_DONE_STATUSES.contains(&"failed_ticketer"));
    }

    #[test]
    fn test_gt_done_statuses_does_not_contain_pending() {
        assert!(!GT_DONE_STATUSES.contains(&"pending"));
        assert!(!GT_DONE_STATUSES.contains(&"in_progress"));
    }

    #[test]
    fn test_gt_done_statuses_count() {
        assert_eq!(GT_DONE_STATUSES.len(), 4);
    }

    #[test]
    fn test_forest_root_of_simple() {
        assert_eq!(forest_root_of("contoso.local"), "contoso.local");
    }

    #[test]
    fn test_forest_root_of_child() {
        assert_eq!(forest_root_of("north.contoso.local"), "contoso.local");
    }

    #[test]
    fn test_forest_root_of_deep_child() {
        assert_eq!(forest_root_of("sub.north.contoso.local"), "contoso.local");
    }
}
