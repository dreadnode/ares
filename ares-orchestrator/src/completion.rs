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

use chrono::Utc;
use redis::AsyncCommands;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::SharedState;

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

            // When blue team is enabled, auto-submit an investigation from the
            // operation state if none have been submitted yet, then wait for all
            // investigations to drain before signalling stop.
            // Cap at 45 minutes to avoid hanging forever if an investigation is stuck.
            if std::env::var("ARES_BLUE_ENABLED").as_deref() == Ok("1") {
                info!("Blue team enabled — waiting for investigations to finish before shutdown");
                let mut conn = dispatcher.queue.connection();

                // Check if any blue investigations already exist for this operation.
                // If not, auto-submit one so blue always gets at least one run.
                let op_inv_key = format!(
                    "ares:blue:op:{}:investigations",
                    dispatcher.config.operation_id
                );
                let existing: i64 = redis::cmd("SCARD")
                    .arg(&op_inv_key)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                if existing == 0 {
                    info!("No blue investigations found — auto-submitting from operation state");
                    if let Err(e) =
                        auto_submit_blue_investigation(state, dispatcher, &mut conn).await
                    {
                        warn!(err = %e, "Failed to auto-submit blue investigation");
                    }
                }
                let blue_deadline = tokio::time::Instant::now() + Duration::from_secs(2700);
                loop {
                    if *shutdown_rx.borrow() {
                        info!("Completion monitor interrupted by shutdown while waiting for blue");
                        break;
                    }

                    if tokio::time::Instant::now() >= blue_deadline {
                        warn!("Blue team wait deadline reached (45m) — proceeding with shutdown");
                        break;
                    }

                    let active: i64 = redis::cmd("SCARD")
                        .arg(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS)
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(0);
                    let queued: i64 = redis::cmd("LLEN")
                        .arg("ares:blue:investigations")
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(0);

                    if active == 0 && queued == 0 {
                        info!("All blue investigations finished");
                        break;
                    }

                    info!(
                        active_investigations = active,
                        queued_investigations = queued,
                        "Waiting for blue team to finish..."
                    );

                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }

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

/// Auto-submit a blue team investigation from the current red team operation state.
///
/// Mirrors the logic in `ares-cli/src/blue/submit.rs::blue_from_operation()` but
/// runs inline within the orchestrator process so blue always gets at least one
/// investigation even when the red operation completes before blue's first poll.
async fn auto_submit_blue_investigation(
    state: &SharedState,
    dispatcher: &Arc<Dispatcher>,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<(), anyhow::Error> {
    let op_id = &dispatcher.config.operation_id;
    let now = Utc::now();
    let inv_id = format!("inv-{}", now.format("%Y%m%d-%H%M%S"));

    // Read state snapshot for building the synthetic alert
    let (target_domain, target_env, cred_count, host_count, vuln_count, has_da, target_ips) = {
        let inner = state.read().await;
        let domain = inner
            .target
            .as_ref()
            .map(|t| t.domain.clone())
            .unwrap_or_default();
        let env = inner
            .target
            .as_ref()
            .map(|t| t.environment.clone())
            .unwrap_or_default();
        let ips: Vec<String> = inner.hosts.iter().map(|h| h.ip.clone()).collect();
        (
            domain,
            env,
            inner.credentials.len(),
            inner.hosts.len(),
            inner.discovered_vulnerabilities.len(),
            inner.has_domain_admin,
            ips,
        )
    };

    // Collect attack techniques from Redis
    let techniques_key = format!("ares:op:{op_id}:techniques");
    let techniques: Vec<String> = redis::cmd("SMEMBERS")
        .arg(&techniques_key)
        .query_async(conn)
        .await
        .unwrap_or_default();

    let operation_context = serde_json::json!({
        "operation_id": op_id,
        "attack_window_start": now.to_rfc3339(),
        "attack_window_end": now.to_rfc3339(),
        "techniques_used": &techniques[..std::cmp::min(techniques.len(), 20)],
        "deployment": target_env,
    });

    let alert = serde_json::json!({
        "labels": {
            "alertname": format!("RedTeamOperation_{}", op_id),
            "severity": "critical",
            "source": "ares-red-team",
            "deployment": target_env,
        },
        "annotations": {
            "summary": format!(
                "Red team operation {op_id} - {cred_count} credentials, {host_count} hosts, {vuln_count} vulnerabilities",
            ),
            "description": format!(
                "Investigate blue team detection coverage for red team operation {op_id}. \
                 Domain: {target_domain}. Domain admin: {has_da}.",
            ),
        },
        "operation_context": operation_context,
        "startsAt": now.to_rfc3339(),
        "endsAt": now.to_rfc3339(),
        "target_ips": &target_ips[..std::cmp::min(target_ips.len(), 50)],
    });

    // Resolve model from env (same precedence as CLI)
    let model = std::env::var("ARES_BLUE_LLM_MODEL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("ARES_MODEL_OVERRIDE").ok())
        .or_else(|| std::env::var("ARES_ORCHESTRATOR_MODEL").ok())
        .or_else(|| std::env::var("ARES_MODEL").ok());

    let grafana_url = std::env::var("GRAFANA_URL").ok();
    let grafana_api_key = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok();

    let max_steps: u32 = std::env::var("ARES_BLUE_MAX_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(75);

    let request = serde_json::json!({
        "investigation_id": inv_id,
        "alert": alert,
        "correlation_context": null,
        "model": model,
        "max_steps": max_steps,
        "multi_agent": true,
        "auto_route": false,
        "report_dir": null,
        "grafana_url": grafana_url,
        "grafana_api_key": grafana_api_key,
        "submitted_at": now.to_rfc3339(),
    });

    // Store env vars for the blue runner (Grafana token, API keys)
    let env_vars: std::collections::HashMap<String, String> = [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "GRAFANA_URL",
    ]
    .iter()
    .filter_map(|&key| std::env::var(key).ok().map(|v| (key.to_string(), v)))
    .collect();

    if !env_vars.is_empty() {
        let env_vars_key = format!("ares:blue:inv:{inv_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_vars_key, &env_json).await?;
        let _: () = conn.expire(&env_vars_key, 3600).await?;
    }

    // Pre-register as active BEFORE pushing to queue to avoid TOCTOU race:
    // without this, the completion wait loop can observe both queued==0 and
    // active==0 in the window between the blue orchestrator's BRPOP (drains
    // the queue) and its register_investigation (SADDs to active set).
    let _: () = conn
        .sadd(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS, &inv_id)
        .await?;
    let _: () = conn
        .expire(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS, 86400)
        .await?;

    // Push investigation request to queue
    let request_json = serde_json::to_string(&request)?;
    let _: () = conn
        .rpush("ares:blue:investigations", &request_json)
        .await?;

    // Track investigation against operation
    let op_inv_key = format!("ares:blue:op:{op_id}:investigations");
    let _: () = conn.sadd(&op_inv_key, &inv_id).await?;
    let _: () = conn.expire(&op_inv_key, 7 * 24 * 3600).await?;

    info!(
        investigation_id = inv_id,
        operation_id = op_id,
        "Auto-submitted blue investigation from operation state"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
