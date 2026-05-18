//! Completion and golden-ticket wait loops.
//!
//! These functions block (async) until the operation reaches a terminal state:
//! all forests dominated, golden tickets forged, max runtime exceeded, or
//! explicit shutdown.
//!
//! Two config flags control early-exit behaviour (mutually exclusive):
//! - `stop_on_domain_admin`: stop as soon as DA is achieved on any domain,
//!   without waiting for all trusted forests to be dominated.
//! - `stop_on_golden_ticket`: continue past DA to forge a golden ticket, then
//!   stop immediately once forged on any domain.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use redis::AsyncCommands;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::SharedState;

/// Pure computation: given state fields, return undominated forest root domains.
///
/// Used by both the async `undominated_forests()` and `SharedState::snapshot()`.
pub fn compute_undominated_forests(
    target_domain: Option<&str>,
    first_domain: Option<&str>,
    trusted_domains: &std::collections::HashMap<String, ares_core::models::TrustInfo>,
    dominated_domains: &HashSet<String>,
    domain_controllers: &std::collections::HashMap<String, String>,
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

    // Include forest roots from all known DCs. This prevents premature
    // completion when trust enumeration hasn't finished yet — domains
    // discovered via recon (e.g. fabrikam.local with a known DC) are tracked
    // as required forests even before trust relationships are enumerated.
    for dc_domain in domain_controllers.keys() {
        if !dc_domain.is_empty() {
            required_forests.insert(forest_root_of(dc_domain));
        }
    }

    if required_forests.is_empty() {
        return Vec::new();
    }

    // Only count a domain as covering a forest root when that domain IS the
    // forest root.  Dominating a child domain (e.g. contoso.local)
    // does NOT mean the forest root (contoso.local) is compromised — its
    // DC has a separate krbtgt.  The child-to-parent escalation (ExtraSid /
    // trust key) must still happen before we declare the forest dominated.
    let dominated_roots: HashSet<String> = dominated_domains
        .iter()
        .filter(|d| {
            let root = forest_root_of(d);
            root == d.to_lowercase()
        })
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
/// An empty list means all forests are dominated. Domination requires krbtgt
/// hashes from every trusted forest, not just the initial target domain.
pub async fn undominated_forests(state: &SharedState) -> Vec<String> {
    let inner = state.read().await;
    compute_undominated_forests(
        inner.target.as_ref().map(|t| t.domain.as_str()),
        inner.domains.first().map(|d| d.as_str()),
        &inner.trusted_domains,
        &inner.dominated_domains,
        &inner.domain_controllers,
    )
}

/// Redis-authoritative count of red-team tasks still pending completion.
async fn redis_pending_red_tasks(dispatcher: &Arc<Dispatcher>) -> Result<usize, redis::RedisError> {
    let key = ares_core::state::build_key(
        &dispatcher.config.operation_id,
        ares_core::state::KEY_PENDING_TASKS,
    );
    let mut conn = dispatcher.queue.connection();
    redis::cmd("HLEN").arg(&key).query_async(&mut conn).await
}

/// Extract forest root from a domain FQDN.
///
/// For `child.contoso.local` → `contoso.local`
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
/// - `stop_on_golden_ticket`: continue past DA to forge a golden ticket, then
///   stop immediately once forged on any domain.
///
/// When neither flag is set (default), the operation continues until all
/// trusted forests are dominated or max runtime is exceeded.
/// Snapshot of completion-relevant state the decision helper consumes.
#[derive(Debug, Clone)]
pub(crate) struct CompletionSnapshot {
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub completed: bool,
    pub undominated_forests_empty: bool,
    /// `Some(elapsed_since_dominance)` when the `all_forests_dominated_at`
    /// timestamp has been recorded; `None` before it's been set.
    pub all_dominated_for: Option<Duration>,
}

/// Outcome of a single completion check.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompletionDecision {
    /// Stop now — the reason string is forwarded to the operator log.
    Stop(&'static str),
    /// Don't stop, but record this tick as "all forests dominated" so the
    /// grace-period timer can start counting down. The caller writes
    /// `state.all_forests_dominated_at = Some(Instant::now())`.
    BeginGracePeriod,
    /// Keep waiting; no state mutation needed.
    Continue,
}

/// Decide whether the completion loop should stop, begin the post-DA grace
/// period, or continue waiting. Pure — no Redis, no tokio sleeps.
///
/// Decision priority (matches the inline logic this replaces):
/// 1. `completed` flag set externally → Stop("operation marked completed")
/// 2. `elapsed >= max_runtime` → Stop("max runtime exceeded")
/// 3. `has_domain_admin && stop_on_da` → Stop on DA
/// 4. `has_domain_admin && stop_on_gt`:
///     - `has_golden_ticket` → Stop on GT
///     - otherwise → Continue (still waiting for GT)
/// 5. `has_domain_admin` (default mode):
///     - undominated forests remain → Continue
///     - all dominated, grace timer set, `elapsed_since >= grace_period` → Stop
///     - all dominated, grace timer set, still inside grace → Continue
///     - all dominated, grace timer unset → BeginGracePeriod
/// 6. otherwise → Continue
pub(crate) fn evaluate_completion(
    snapshot: &CompletionSnapshot,
    elapsed: Duration,
    max_runtime: Duration,
    stop_on_da: bool,
    stop_on_gt: bool,
    grace_period: Duration,
) -> CompletionDecision {
    if snapshot.completed {
        return CompletionDecision::Stop("operation marked completed");
    }
    if elapsed >= max_runtime {
        return CompletionDecision::Stop("max runtime exceeded");
    }
    if !snapshot.has_domain_admin {
        return CompletionDecision::Continue;
    }
    if stop_on_da {
        return CompletionDecision::Stop("domain admin achieved (stop_on_domain_admin)");
    }
    if stop_on_gt {
        return if snapshot.has_golden_ticket {
            CompletionDecision::Stop("golden ticket forged (stop_on_golden_ticket)")
        } else {
            CompletionDecision::Continue
        };
    }
    if !snapshot.undominated_forests_empty {
        return CompletionDecision::Continue;
    }
    match snapshot.all_dominated_for {
        Some(since) if since >= grace_period => {
            CompletionDecision::Stop("all forests dominated (post-exploitation complete)")
        }
        Some(_) => CompletionDecision::Continue,
        None => CompletionDecision::BeginGracePeriod,
    }
}

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
        let (has_da, has_gt, completed, all_dominated_for) = {
            let inner = state.read().await;
            (
                inner.has_domain_admin,
                inner.has_golden_ticket,
                inner.completed,
                inner.all_forests_dominated_at.map(|t| t.elapsed()),
            )
        };

        // The grace-period check needs to know whether ALL forests are dominated.
        // That helper takes the SharedState (it reads inner under a fresh lock)
        // and is async, so it can't live inside the pure decision helper.
        let undominated_forests_empty = if has_da && !stop_on_da && !stop_on_gt {
            undominated_forests(state).await.is_empty()
        } else {
            false
        };

        let snapshot = CompletionSnapshot {
            has_domain_admin: has_da,
            has_golden_ticket: has_gt,
            completed,
            undominated_forests_empty,
            all_dominated_for,
        };
        let grace_period = Duration::from_secs(180);
        let decision = evaluate_completion(
            &snapshot,
            elapsed,
            max_runtime,
            stop_on_da,
            stop_on_gt,
            grace_period,
        );

        let reason = match decision {
            CompletionDecision::Stop(r) => Some(r),
            CompletionDecision::BeginGracePeriod => {
                let mut inner = state.write().await;
                inner.all_forests_dominated_at = Some(tokio::time::Instant::now());
                drop(inner);
                info!(
                    "All forests dominated — starting {}s post-exploitation grace period",
                    grace_period.as_secs()
                );
                None
            }
            CompletionDecision::Continue => None,
        };

        if let Some(reason) = reason {
            info!(
                reason = reason,
                elapsed_secs = elapsed.as_secs(),
                has_domain_admin = has_da,
                has_golden_ticket = has_gt,
                "Completion condition met"
            );

            let blue_enabled = std::env::var("ARES_BLUE_ENABLED").as_deref() == Ok("1");
            if let Err(e) = mark_red_completion_for_loot(dispatcher, reason, blue_enabled).await {
                warn!(err = %e, "Failed to persist red completion metadata");
            }

            // When blue team is enabled, auto-submit an investigation from the
            // operation state if none have been submitted yet, then wait for all
            // investigations to drain before signalling stop.
            // Cap at 45 minutes to avoid hanging forever if an investigation is stuck.
            if blue_enabled {
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
                    let queued: i64 = match dispatcher.queue.nats_broker() {
                        Some(nats) => match nats
                            .jetstream()
                            .get_stream(ares_core::nats::BLUE_TASKS_STREAM)
                            .await
                        {
                            Ok(stream) => stream.cached_info().state.messages as i64,
                            Err(_) => 0,
                        },
                        None => 0,
                    };

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

            // Wait for active red team tasks and deferred queue to drain
            // before signalling shutdown. Cap at 5 minutes to avoid hanging.
            let red_deadline = tokio::time::Instant::now() + Duration::from_secs(300);
            loop {
                if *shutdown_rx.borrow() {
                    info!("Completion monitor interrupted by shutdown while waiting for red team drain");
                    break;
                }

                if tokio::time::Instant::now() >= red_deadline {
                    warn!("Red team drain deadline reached (5m) — proceeding with shutdown");
                    break;
                }

                let active_tasks = dispatcher.tracker.total().await;
                let deferred_tasks = dispatcher.deferred.total_count().await;
                let redis_pending_tasks = match redis_pending_red_tasks(dispatcher).await {
                    Ok(count) => count,
                    Err(e) => {
                        warn!(err = %e, "Failed to read pending red task count from Redis");
                        usize::MAX
                    }
                };

                if redis_pending_tasks == 0 && deferred_tasks == 0 {
                    if active_tasks != 0 {
                        warn!(
                            active_tasks,
                            "Local active-task tracker is non-zero, but Redis has no pending tasks; treating tracker entries as stale and proceeding with shutdown"
                        );
                    }
                    info!("All red team tasks drained");
                    break;
                }

                info!(
                    active_tasks,
                    redis_pending_tasks,
                    deferred_tasks,
                    "Waiting for red team tasks to drain before shutdown..."
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

async fn mark_red_completion_for_loot(
    dispatcher: &Arc<Dispatcher>,
    reason: &str,
    blocked_on_blue: bool,
) -> Result<(), redis::RedisError> {
    let key =
        ares_core::state::build_key(&dispatcher.config.operation_id, ares_core::state::KEY_META);
    let completed_at = Utc::now().to_rfc3339();
    let mut conn = dispatcher.queue.connection();
    redis::pipe()
        .hset(
            &key,
            "red_completed_at",
            serde_json::to_string(&completed_at).unwrap_or_default(),
        )
        .hset(
            &key,
            "red_completion_reason",
            serde_json::to_string(reason).unwrap_or_default(),
        )
        .hset(
            &key,
            "red_blocked_on_blue",
            serde_json::to_string(&blocked_on_blue).unwrap_or_default(),
        )
        .expire(&key, 86400)
        .query_async::<()>(&mut conn)
        .await?;
    Ok(())
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

    // Pre-register as active BEFORE publishing to avoid TOCTOU race:
    // without this, the completion wait loop can observe both queued==0 and
    // active==0 in the window between the blue orchestrator's pull (drains
    // the queue) and its register_investigation (SADDs to active set).
    let _: () = conn
        .sadd(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS, &inv_id)
        .await?;
    let _: () = conn
        .expire(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS, 86400)
        .await?;

    // Track investigation against operation
    let op_inv_key = format!("ares:blue:op:{op_id}:investigations");
    let _: () = conn.sadd(&op_inv_key, &inv_id).await?;
    let _: () = conn.expire(&op_inv_key, 7 * 24 * 3600).await?;

    // Publish investigation request to NATS
    let nats = dispatcher
        .queue
        .nats_broker()
        .ok_or_else(|| anyhow::anyhow!("Dispatcher TaskQueue has no NATS broker"))?;
    ares_core::state::blue_task_queue::BlueTaskQueue::submit_investigation_request(&nats, &request)
        .await?;

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
    fn forest_root_of_simple() {
        assert_eq!(forest_root_of("contoso.local"), "contoso.local");
    }

    #[test]
    fn forest_root_of_child() {
        assert_eq!(forest_root_of("child.contoso.local"), "contoso.local");
    }

    #[test]
    fn forest_root_of_deep_child() {
        assert_eq!(forest_root_of("sub.child.contoso.local"), "contoso.local");
    }

    fn make_trust(domain: &str, trust_type: &str) -> ares_core::models::TrustInfo {
        ares_core::models::TrustInfo {
            domain: domain.to_string(),
            flat_name: domain.split('.').next().unwrap_or(domain).to_uppercase(),
            direction: "bidirectional".to_string(),
            trust_type: trust_type.to_string(),
            sid_filtering: false,
            security_identifier: None,
        }
    }

    #[test]
    fn undominated_single_domain_no_trusts() {
        let trusted = std::collections::HashMap::new();
        let dcs = std::collections::HashMap::new();
        let mut dominated = HashSet::new();
        // Target domain not yet dominated
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert_eq!(result, vec!["contoso.local"]);

        // Now dominated
        dominated.insert("contoso.local".to_string());
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_cross_forest_trust() {
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "fabrikam.local".to_string(),
            make_trust("fabrikam.local", "forest"),
        );

        // Only contoso dominated — fabrikam remains
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert_eq!(result, vec!["fabrikam.local"]);
    }

    #[test]
    fn undominated_all_forests_dominated() {
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "fabrikam.local".to_string(),
            make_trust("fabrikam.local", "forest"),
        );

        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        dominated.insert("fabrikam.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_child_domain_not_separate_forest() {
        // parent_child trust should NOT add a separate required forest
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "child.contoso.local".to_string(),
            make_trust("child.contoso.local", "parent_child"),
        );

        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        // parent_child is NOT cross-forest, so child.contoso.local is not required
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_child_domain_does_not_cover_forest() {
        // Dominating a child domain does NOT cover the forest root — the
        // forest root DC has its own krbtgt and must be secretsdumped via
        // trust escalation (ExtraSid / trust key).
        let trusted = std::collections::HashMap::new();
        let mut dominated = HashSet::new();
        dominated.insert("child.contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        // Child DA does not satisfy the forest root requirement
        assert_eq!(result, vec!["contoso.local"]);
    }

    #[test]
    fn undominated_forest_root_dominated_directly() {
        // Dominating the forest root itself should satisfy the requirement
        let trusted = std::collections::HashMap::new();
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_dc_discovered_before_trust_enum() {
        // fabrikam.local DC discovered via recon but trust not yet enumerated.
        // The DC should be included in required_forests to prevent premature
        // completion.
        let trusted = std::collections::HashMap::new();
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let mut dcs = std::collections::HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.220".to_string());
        dcs.insert("fabrikam.local".to_string(), "192.168.58.58".to_string());
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("child.contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        // fabrikam.local DC is known but not dominated → should appear
        assert_eq!(result, vec!["fabrikam.local"]);
    }

    #[test]
    fn forest_root_of_case_insensitive() {
        assert_eq!(forest_root_of("CONTOSO.LOCAL"), "contoso.local");
        assert_eq!(forest_root_of("North.Contoso.Local"), "contoso.local");
    }

    #[test]
    fn forest_root_of_single_label() {
        // Single-label domain (unusual but should not panic)
        assert_eq!(forest_root_of("localhost"), "localhost");
    }

    #[test]
    fn forest_root_of_empty() {
        assert_eq!(forest_root_of(""), "");
    }

    #[test]
    fn undominated_no_target_no_first_domain() {
        // Both target_domain and first_domain are None
        let trusted = std::collections::HashMap::new();
        let dominated = HashSet::new();
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(None, None, &trusted, &dominated, &dcs);
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_empty_target_domain() {
        // target_domain is Some("") — should be treated as missing
        let trusted = std::collections::HashMap::new();
        let dominated = HashSet::new();
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(Some(""), None, &trusted, &dominated, &dcs);
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_only_first_domain() {
        // target_domain is None but first_domain is set
        let trusted = std::collections::HashMap::new();
        let dominated = HashSet::new();
        let dcs = std::collections::HashMap::new();
        let result =
            compute_undominated_forests(None, Some("contoso.local"), &trusted, &dominated, &dcs);
        assert_eq!(result, vec!["contoso.local"]);
    }

    #[test]
    fn undominated_external_trust_is_cross_forest() {
        // "external" trust type should be treated as cross-forest
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "fabrikam.local".to_string(),
            make_trust("fabrikam.local", "external"),
        );
        let dominated = HashSet::new();
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert!(result.contains(&"fabrikam.local".to_string()));
        assert!(result.contains(&"contoso.local".to_string()));
    }

    #[test]
    fn undominated_unknown_trust_not_cross_forest() {
        // "unknown" trust type should NOT be treated as cross-forest
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "fabrikam.local".to_string(),
            make_trust("fabrikam.local", "unknown"),
        );
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        // "unknown" is not cross-forest, so fabrikam should NOT appear
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_multiple_cross_forest_trusts() {
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "fabrikam.local".to_string(),
            make_trust("fabrikam.local", "forest"),
        );
        trusted.insert(
            "tailspintoys.local".to_string(),
            make_trust("tailspintoys.local", "forest"),
        );

        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        dominated.insert("fabrikam.local".to_string());
        // tailspintoys not dominated
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert_eq!(result, vec!["tailspintoys.local"]);
    }

    #[test]
    fn undominated_child_trust_domain_maps_to_parent_forest() {
        // Cross-forest trust with a child domain like "north.fabrikam.local"
        // should map to forest root "fabrikam.local"
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            "north.fabrikam.local".to_string(),
            make_trust("north.fabrikam.local", "forest"),
        );

        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert_eq!(result, vec!["fabrikam.local"]);
    }

    #[test]
    fn undominated_empty_dc_key_ignored() {
        // Empty string DC key should be ignored
        let trusted = std::collections::HashMap::new();
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let mut dcs = std::collections::HashMap::new();
        dcs.insert("".to_string(), "192.168.58.1".to_string());
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_case_insensitive_dominated() {
        // forest_root_of lowercases, so dominated domains with mixed case should still match
        let trusted = std::collections::HashMap::new();
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        let dcs = std::collections::HashMap::new();
        let result =
            compute_undominated_forests(Some("CONTOSO.LOCAL"), None, &trusted, &dominated, &dcs);
        // target "CONTOSO.LOCAL" lowercases to "contoso.local" which is dominated
        assert!(result.is_empty());
    }

    #[test]
    fn undominated_target_and_first_same_forest() {
        // target and first_domain in the same forest should only produce one entry
        let trusted = std::collections::HashMap::new();
        let dominated = HashSet::new();
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("child.contoso.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "contoso.local");
    }

    #[test]
    fn undominated_target_and_first_different_forests() {
        let trusted = std::collections::HashMap::new();
        let dominated = HashSet::new();
        let dcs = std::collections::HashMap::new();
        let result = compute_undominated_forests(
            Some("contoso.local"),
            Some("fabrikam.local"),
            &trusted,
            &dominated,
            &dcs,
        );
        assert_eq!(result.len(), 2);
        let mut sorted = result;
        sorted.sort();
        assert_eq!(sorted, vec!["contoso.local", "fabrikam.local"]);
    }

    #[test]
    fn make_trust_helper() {
        let trust = make_trust("fabrikam.local", "forest");
        assert_eq!(trust.domain, "fabrikam.local");
        assert_eq!(trust.flat_name, "FABRIKAM");
        assert_eq!(trust.trust_type, "forest");
        assert!(trust.is_cross_forest());
        assert!(!trust.sid_filtering);

        let parent_child = make_trust("child.contoso.local", "parent_child");
        assert!(!parent_child.is_cross_forest());
    }

    // ── tests for evaluate_completion ─────────────────────────────────

    fn empty_snapshot() -> CompletionSnapshot {
        CompletionSnapshot {
            has_domain_admin: false,
            has_golden_ticket: false,
            completed: false,
            undominated_forests_empty: false,
            all_dominated_for: None,
        }
    }

    fn ten_min() -> Duration {
        Duration::from_secs(600)
    }
    fn three_min() -> Duration {
        Duration::from_secs(180)
    }

    #[test]
    fn completion_completed_flag_wins() {
        let mut snap = empty_snapshot();
        snap.completed = true;
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::Stop("operation marked completed")
        );
    }

    #[test]
    fn completion_max_runtime_exceeded() {
        let snap = empty_snapshot();
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::from_secs(601),
                ten_min(),
                false,
                false,
                three_min()
            ),
            CompletionDecision::Stop("max runtime exceeded")
        );
    }

    #[test]
    fn completion_no_da_continues() {
        let snap = empty_snapshot();
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::Continue
        );
    }

    #[test]
    fn completion_stop_on_da_short_circuits_grace() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), true, false, three_min()),
            CompletionDecision::Stop("domain admin achieved (stop_on_domain_admin)")
        );
    }

    #[test]
    fn completion_stop_on_gt_waits_until_ticket_forged() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, true, three_min()),
            CompletionDecision::Continue
        );
        snap.has_golden_ticket = true;
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, true, three_min()),
            CompletionDecision::Stop("golden ticket forged (stop_on_golden_ticket)")
        );
    }

    #[test]
    fn completion_default_mode_waits_for_all_forests() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = false;
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::Continue
        );
    }

    #[test]
    fn completion_all_forests_dominated_begins_grace_period() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        // Grace timer not set yet → BeginGracePeriod.
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::BeginGracePeriod
        );
    }

    #[test]
    fn completion_grace_period_still_running_continues() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        snap.all_dominated_for = Some(Duration::from_secs(60));
        // 60s elapsed, grace is 180s → still continuing.
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::Continue
        );
    }

    #[test]
    fn completion_grace_period_complete_stops() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        snap.all_dominated_for = Some(Duration::from_secs(181));
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::Stop("all forests dominated (post-exploitation complete)")
        );
    }

    #[test]
    fn completion_stop_on_da_beats_completed_priority() {
        // `completed` runs first; even with stop_on_da configured, the
        // external completed flag wins because it's priority 1.
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.completed = true;
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), true, false, three_min()),
            CompletionDecision::Stop("operation marked completed")
        );
    }

    #[test]
    fn completion_max_runtime_beats_da_grace() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::from_secs(601),
                ten_min(),
                false,
                false,
                three_min(),
            ),
            CompletionDecision::Stop("max runtime exceeded")
        );
    }

    #[test]
    fn completion_grace_period_boundary_exact_match_stops() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        snap.all_dominated_for = Some(three_min());
        assert_eq!(
            evaluate_completion(&snap, Duration::ZERO, ten_min(), false, false, three_min()),
            CompletionDecision::Stop("all forests dominated (post-exploitation complete)")
        );
    }
}
