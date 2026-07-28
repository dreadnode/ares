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

use chrono::{DateTime, Utc};
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

    let dominated_roots = dominated_forest_roots(dominated_domains);

    required_forests
        .difference(&dominated_roots)
        .cloned()
        .collect()
}

/// The set of forest root domains that are fully dominated.
///
/// Only count a domain as covering a forest root when that domain IS the
/// forest root. Dominating a child domain (e.g. `child.contoso.local`) does
/// NOT mean the forest root (`contoso.local`) is compromised — its DC has a
/// separate krbtgt. The child-to-parent escalation (ExtraSid / trust key) must
/// still happen before we declare the forest dominated. Shared by
/// [`compute_undominated_forests`] and [`has_pending_cross_forest_escalation`]
/// so the two completion guards can't drift.
fn dominated_forest_roots(dominated_domains: &HashSet<String>) -> HashSet<String> {
    dominated_domains
        .iter()
        .filter(|d| forest_root_of(d) == d.to_lowercase())
        .map(|d| forest_root_of(d))
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

/// Whether any discovered `forest_trust_escalation` vuln is still unexploited
/// and not written off — cross-forest work the op must not abandon.
///
/// Pure over the two vuln collections so it unit-tests without a live
/// `SharedState`.
fn has_pending_cross_forest_escalation(
    discovered: &std::collections::HashMap<String, ares_core::models::VulnerabilityInfo>,
    exploited: &HashSet<String>,
    dominated_domains: &HashSet<String>,
) -> bool {
    let dominated_roots = dominated_forest_roots(dominated_domains);
    discovered.values().any(|v| {
        v.vuln_type == "forest_trust_escalation"
            && !exploited.contains(&v.vuln_id)
            && !is_trust_escalation_written_off(v)
            && !escalation_target_forest_dominated(v, &dominated_roots)
    })
}

/// True when a `forest_trust_escalation` vuln targets a forest whose root is
/// already dominated. Such an escalation is satisfied-by-domination: the op
/// reached that forest's krbtgt by another path (native ADCS ESC13, a direct
/// DCSync) so the trust forge is moot and must not pin the op open. Without
/// this, a discovered-but-never-exploited trust forge — the SID-filtered
/// dead-ends that are never `written_off` — keeps `is_multi_forest_op_complete`
/// false and runs a fully-owned op out to the hard max-runtime cap.
///
/// A missing or blank `target_domain` is treated as NOT dominated so the vuln
/// stays pending — the conservative default.
fn escalation_target_forest_dominated(
    vuln: &ares_core::models::VulnerabilityInfo,
    dominated_roots: &HashSet<String>,
) -> bool {
    vuln.details
        .get("target_domain")
        .and_then(serde_json::Value::as_str)
        .filter(|d| !d.is_empty())
        .map(|d| dominated_roots.contains(&forest_root_of(d)))
        .unwrap_or(false)
}

/// A cross-forest escalation is "written off" when `details["written_off"]` is
/// `true`.
///
/// Nothing in the orchestrator writes that flag today — the trust automation
/// leaves a SID-filtered forge unexploited and un-flagged, so this predicate is
/// false for every escalation a live op produces. The only writer is the test
/// helper below. The escape valve that actually retires a dead trust is
/// [`escalation_target_forest_dominated`]: the op stops waiting once the target
/// forest falls by another path (native ADCS ESC13, a direct DCSync). Absent
/// that, a cross-forest escalation pins the op open to `max_runtime`.
fn is_trust_escalation_written_off(vuln: &ares_core::models::VulnerabilityInfo) -> bool {
    vuln.details
        .get("written_off")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Backstop for [`undominated_forests`]: false while any cross-forest
/// `forest_trust_escalation` remains unexploited and not written off.
///
/// [`compute_undominated_forests`] only marks a forest required when its trust
/// is classified `is_cross_forest()` or a DC is keyed under the forest root. A
/// `forest_trust_escalation` vuln can sit in state (queued against the foreign
/// DC's IP) while neither holds — that gap let a two-forest op self-terminate
/// with the parent forest still unowned and its escalation un-fired. Gating
/// completion on the vuln directly closes it: the op runs on (bounded by
/// max_runtime) until the escalation is exploited or explicitly written off.
///
/// An escalation whose target forest is already dominated does not count — see
/// [`escalation_target_forest_dominated`].
async fn is_multi_forest_op_complete(state: &SharedState) -> bool {
    let inner = state.read().await;
    !has_pending_cross_forest_escalation(
        &inner.discovered_vulnerabilities,
        &inner.exploited_vulnerabilities,
        &inner.dominated_domains,
    )
}

/// Timeout the blue runner applies to a single investigation. The drain budget
/// is derived from it, so the two must not drift; the assertion below fails the
/// build if they ever do.
const BLUE_INVESTIGATION_TIMEOUT_SECS: u64 = 2700;

#[cfg(feature = "blue")]
const _: () = assert!(
    BLUE_INVESTIGATION_TIMEOUT_SECS
        == crate::orchestrator::blue::runner::INVESTIGATION_TIMEOUT_SECS
);

/// Headroom the drain wait allows on top of one investigation timeout, covering
/// runner pickup latency and final report generation.
///
/// The budget MUST exceed the investigation timeout. When the two were equal the
/// drain deadline and the investigation's own timeout fired at the same instant,
/// so an investigation submitted at red completion was always abandoned
/// mid-flight instead of being allowed to finish or time out on its own terms.
const BLUE_DRAIN_SLACK_SECS: u64 = 600;

/// A blue investigation the drain wait is blocking on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchedInvestigation {
    pub id: String,
    /// Whether an absent status means "still outstanding".
    ///
    /// True for an investigation this monitor just submitted — the runner has
    /// not registered it yet, and treating that gap as finished would race the
    /// op to shutdown before blue ever starts. False for pre-existing ones,
    /// whose status key may simply have outlived its TTL from an earlier run of
    /// the same operation.
    pub wait_when_status_missing: bool,
}

/// Whether a watched investigation is still worth waiting for.
pub(crate) fn still_outstanding(status: Option<&str>, wait_when_status_missing: bool) -> bool {
    match status {
        Some(s) => !ares_core::state::blue_status_is_terminal(s),
        None => wait_when_status_missing,
    }
}

/// Resolve the blue drain budget, honouring `ARES_BLUE_DRAIN_MAX_SECS`.
pub(crate) fn resolve_blue_drain_budget(override_secs: Option<&str>) -> Duration {
    override_secs
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| {
            Duration::from_secs(BLUE_INVESTIGATION_TIMEOUT_SECS + BLUE_DRAIN_SLACK_SECS)
        })
}

/// Filter `watched` down to the investigations that have not reached a terminal
/// status yet.
async fn outstanding_investigations(
    conn: &mut redis::aio::ConnectionManager,
    watched: &[WatchedInvestigation],
) -> Vec<String> {
    let mut outstanding = Vec::new();
    for w in watched {
        let status = ares_core::state::read_blue_status(conn, &w.id)
            .await
            .unwrap_or(None);
        if still_outstanding(status.as_deref(), w.wait_when_status_missing) {
            outstanding.push(w.id.clone());
        }
    }
    outstanding
}

/// This operation's investigations that are registered and not yet terminal.
///
/// A member with no status key is deliberately excluded: the operation set lives
/// for 7 days while status keys expire after 1 day, so a resumed operation would
/// otherwise treat last week's investigations as in flight and wait out the
/// whole drain budget.
async fn in_flight_op_investigations(
    conn: &mut redis::aio::ConnectionManager,
    operation_id: &str,
) -> Vec<String> {
    let key = format!("ares:blue:op:{operation_id}:investigations");
    let ids: Vec<String> = redis::cmd("SMEMBERS")
        .arg(&key)
        .query_async(conn)
        .await
        .unwrap_or_default();

    let mut in_flight = Vec::new();
    for id in ids {
        let status = ares_core::state::read_blue_status(conn, &id)
            .await
            .unwrap_or(None);
        if status
            .as_deref()
            .is_some_and(|s| !ares_core::state::blue_status_is_terminal(s))
        {
            in_flight.push(id);
        }
    }
    in_flight
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
/// Runtime is bounded by a **soft** and a **hard** cap. The soft cap is the
/// normal budget; the hard cap is a strict ceiling that always terminates.
/// The soft cap yields to `Continue` only when the op has achieved DA on at
/// least one domain *and* still has an undominated forest — i.e. the run is
/// visibly progressing on multi-forest work but ran out of the primary
/// budget. Without DA there's no evidence the op is close enough to warrant
/// more time; with DA but all forests done, the op is just idling.
///
/// Decision priority:
/// 1. `completed` flag set externally → Stop("operation marked completed")
/// 2. `elapsed >= hard_max_runtime` → Stop("hard max runtime exceeded")
/// 3. `elapsed >= soft_max_runtime`:
///     - DA achieved AND undominated forests remain → fall through (extend)
///     - otherwise → Stop("max runtime exceeded")
/// 4. `has_domain_admin && stop_on_da` → Stop on DA
/// 5. `has_domain_admin && stop_on_gt`:
///     - `has_golden_ticket` → Stop on GT
///     - otherwise → Continue (still waiting for GT)
/// 6. `has_domain_admin` (default mode):
///     - undominated forests remain → Continue
///     - all dominated, grace timer set, `elapsed_since >= grace_period` → Stop
///     - all dominated, grace timer set, still inside grace → Continue
///     - all dominated, grace timer unset → BeginGracePeriod
/// 7. otherwise → Continue
pub(crate) fn evaluate_completion(
    snapshot: &CompletionSnapshot,
    elapsed: Duration,
    soft_max_runtime: Duration,
    hard_max_runtime: Duration,
    stop_on_da: bool,
    stop_on_gt: bool,
    grace_period: Duration,
) -> CompletionDecision {
    if snapshot.completed {
        return CompletionDecision::Stop("operation marked completed");
    }
    if elapsed >= hard_max_runtime {
        return CompletionDecision::Stop("hard max runtime exceeded");
    }
    if elapsed >= soft_max_runtime
        && (!snapshot.has_domain_admin || snapshot.undominated_forests_empty)
    {
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
    blue_enabled: bool,
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

    // Hard cap = 2× the configured budget. The soft cap (max_runtime) is the
    // normal ceiling; the hard cap is the strict upper bound that fires even
    // when the op is still visibly progressing on an undominated forest.
    let hard_max_runtime = max_runtime.saturating_mul(2);

    info!(
        max_runtime_secs = max_runtime.as_secs(),
        hard_max_runtime_secs = hard_max_runtime.as_secs(),
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
        //
        // Also require that no cross-forest `forest_trust_escalation` is left
        // unexploited-and-not-written-off: `undominated_forests` misses a forest
        // whose trust wasn't classified `is_cross_forest()` and whose DC isn't
        // keyed under its root, so the vuln is the authoritative "cross-forest
        // work remains" signal. Both must clear before the op is eligible to
        // stop.
        let undominated_forests_empty = if has_da && !stop_on_da && !stop_on_gt {
            undominated_forests(state).await.is_empty() && is_multi_forest_op_complete(state).await
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
            hard_max_runtime,
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

            // Freeze red dispatch immediately. Everything past this point is
            // teardown — the blue-drain wait and the red-task drain below. Without
            // this, the automation loops and deferred queue keep spawning new
            // exploit/recon agent loops (burning tokens on the un-exploitable
            // ACL/ADCS backlog) for the entire blue-drain window, which can run
            // up to 45 minutes. Blue investigations run on their own runner and
            // are unaffected.
            dispatcher.mark_red_draining();
            info!("Red dispatch frozen — draining in-flight tasks; blue investigations continue");

            if let Err(e) = mark_red_completion_for_loot(dispatcher, reason, blue_enabled).await {
                warn!(err = %e, "Failed to persist red completion metadata");
            }

            // When blue team is enabled, submit the terminal investigation — the
            // only one built from the complete loot and the full attack window —
            // then wait for it and it alone. Mid-op investigations still in
            // flight are superseded rather than waited on: the blue runner
            // executes investigations serially, so leaving one running holds the
            // terminal investigation behind it for up to a full investigation
            // timeout, which is what used to strand the terminal one unfinished
            // at the drain deadline.
            if blue_enabled {
                info!("Blue team enabled — waiting for investigations to finish before shutdown");
                let mut conn = dispatcher.queue.connection();
                let op_id = dispatcher.config.operation_id.clone();

                // Snapshot before submitting so the terminal investigation can
                // never appear in its own supersede list.
                let in_flight = in_flight_op_investigations(&mut conn, &op_id).await;

                let mut watched: Vec<WatchedInvestigation> = Vec::new();
                match auto_submit_blue_investigation(state, dispatcher, &mut conn).await {
                    Ok(inv_id) => {
                        info!(
                            investigation_id = %inv_id,
                            "Submitted terminal blue investigation from operation state"
                        );
                        watched.push(WatchedInvestigation {
                            id: inv_id,
                            wait_when_status_missing: true,
                        });
                    }
                    Err(e) => {
                        warn!(err = %e, "Failed to submit terminal blue investigation");
                    }
                }

                for id in &in_flight {
                    match ares_core::state::request_blue_supersede(&mut conn, id).await {
                        Ok(()) => info!(
                            investigation_id = %id,
                            "Superseded mid-op investigation to free the blue runner slot"
                        ),
                        Err(e) => {
                            // Couldn't cancel it, so it will keep holding the
                            // runner — wait for it instead of stranding it.
                            warn!(err = %e, investigation_id = %id, "Failed to request supersede");
                            watched.push(WatchedInvestigation {
                                id: id.clone(),
                                wait_when_status_missing: false,
                            });
                        }
                    }
                }

                if watched.is_empty() {
                    info!("No blue investigations to wait for");
                } else {
                    let budget = resolve_blue_drain_budget(
                        std::env::var("ARES_BLUE_DRAIN_MAX_SECS").ok().as_deref(),
                    );
                    let blue_deadline = tokio::time::Instant::now() + budget;
                    loop {
                        if *shutdown_rx.borrow() {
                            info!(
                                "Completion monitor interrupted by shutdown while waiting for blue"
                            );
                            break;
                        }

                        if tokio::time::Instant::now() >= blue_deadline {
                            warn!(
                                budget_secs = budget.as_secs(),
                                "Blue team wait deadline reached — proceeding with shutdown"
                            );
                            break;
                        }

                        let outstanding = outstanding_investigations(&mut conn, &watched).await;
                        if outstanding.is_empty() {
                            info!("All blue investigations finished");
                            break;
                        }

                        info!(
                            outstanding_investigations = outstanding.len(),
                            ids = ?outstanding,
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

    // Eagerly render + cache the red report from live state so the Taskfile
    // watch loop's `ops report` fetch (which fires as soon as `ops status`
    // reports completed) hits the cached copy instead of racing on partial
    // Redis reads. Best-effort: a render failure must not fail red completion.
    if let Err(e) =
        crate::ops::report::generate_and_cache_report(&mut conn, &dispatcher.config.operation_id)
            .await
    {
        warn!(err = %e, "Failed to eagerly cache red report on completion");
    }

    Ok(())
}

/// Submit the terminal blue investigation for this operation and return its id.
///
/// Mirrors the logic in `ares-cli/src/blue/submit.rs::blue_from_operation()` but
/// runs inline within the orchestrator process, so the investigation that sees
/// the complete loot and the true attack window is submitted deterministically
/// at red completion rather than racing the milestone loop in
/// [`crate::orchestrator::blue::auto_submit`].
async fn auto_submit_blue_investigation(
    state: &SharedState,
    dispatcher: &Arc<Dispatcher>,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<String, anyhow::Error> {
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

    // Read the op's real start time from Redis — bootstrap.rs writes it once
    // via HSETNX so this survives restarts. Falling back to `now` would give
    // blue a zero-width window and score 0.
    let meta_key = format!("ares:op:{op_id}:meta");
    let started_at_raw: Option<String> = redis::cmd("HGET")
        .arg(&meta_key)
        .arg("started_at")
        .query_async(conn)
        .await
        .unwrap_or_default();
    let attack_window_start = started_at_raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<DateTime<Utc>>(s).ok())
        .unwrap_or(now);

    let operation_context = serde_json::json!({
        "operation_id": op_id,
        "attack_window_start": attack_window_start.to_rfc3339(),
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

    Ok(inv_id)
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

    fn make_forest_escalation_vuln(
        vuln_id: &str,
        target_domain: &str,
        written_off: bool,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert(
            "target_domain".to_string(),
            serde_json::json!(target_domain),
        );
        if written_off {
            details.insert("written_off".to_string(), serde_json::json!(true));
        }
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: "forest_trust_escalation".to_string(),
            target: "192.168.58.159".to_string(),
            discovered_by: "trust_automation".to_string(),
            discovered_at: Utc::now(),
            details,
            recommended_agent: "privesc".to_string(),
            priority: 100,
        }
    }

    #[test]
    fn pending_escalation_blocks_completion() {
        // A discovered, unexploited forest_trust_escalation into an un-owned
        // forest keeps the op alive.
        let mut discovered = std::collections::HashMap::new();
        discovered.insert(
            "v1".to_string(),
            make_forest_escalation_vuln("v1", "fabrikam.local", false),
        );
        let exploited = HashSet::new();
        assert!(has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &HashSet::new()
        ));
    }

    #[test]
    fn exploited_escalation_allows_completion() {
        let mut discovered = std::collections::HashMap::new();
        discovered.insert(
            "v1".to_string(),
            make_forest_escalation_vuln("v1", "fabrikam.local", false),
        );
        let mut exploited = HashSet::new();
        exploited.insert("v1".to_string());
        assert!(!has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &HashSet::new()
        ));
    }

    #[test]
    fn written_off_escalation_allows_completion() {
        // The escape valve: a flagged-dead trust must not pin the op open.
        let mut discovered = std::collections::HashMap::new();
        discovered.insert(
            "v1".to_string(),
            make_forest_escalation_vuln("v1", "fabrikam.local", true),
        );
        let exploited = HashSet::new();
        assert!(!has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &HashSet::new()
        ));
    }

    #[test]
    fn non_forest_vulns_ignored_by_completion_gate() {
        // Only forest_trust_escalation gates multi-forest completion; a stray
        // unexploited esc1 (single-forest) must not block the op forever.
        let mut discovered = std::collections::HashMap::new();
        let mut esc1 = make_forest_escalation_vuln("v1", "fabrikam.local", false);
        esc1.vuln_type = "esc1".to_string();
        discovered.insert("v1".to_string(), esc1);
        let exploited = HashSet::new();
        assert!(!has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &HashSet::new()
        ));
    }

    #[test]
    fn escalation_into_dominated_forest_allows_completion() {
        // Regression: both forests were owned via direct paths (native ADCS /
        // DCSync), leaving an un-exploited, never-written-off trust forge in
        // state. Its target forest is already dominated, so it must NOT pin the
        // op open to the hard max-runtime cap.
        let mut discovered = std::collections::HashMap::new();
        discovered.insert(
            "v1".to_string(),
            make_forest_escalation_vuln("v1", "fabrikam.local", false),
        );
        let exploited = HashSet::new();
        let dominated: HashSet<String> = ["fabrikam.local".to_string()].into_iter().collect();
        assert!(!has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &dominated
        ));
    }

    #[test]
    fn escalation_into_undominated_forest_still_blocks() {
        // A different forest being owned must not satisfy an escalation whose
        // own target forest is still un-owned.
        let mut discovered = std::collections::HashMap::new();
        discovered.insert(
            "v1".to_string(),
            make_forest_escalation_vuln("v1", "fabrikam.local", false),
        );
        let exploited = HashSet::new();
        let dominated: HashSet<String> = ["contoso.local".to_string()].into_iter().collect();
        assert!(has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &dominated
        ));
    }

    #[test]
    fn escalation_target_dominated_via_child_only_still_blocks() {
        // Dominating a child domain does not own the forest root, so a trust
        // forge into that root stays pending.
        let mut discovered = std::collections::HashMap::new();
        discovered.insert(
            "v1".to_string(),
            make_forest_escalation_vuln("v1", "contoso.local", false),
        );
        let exploited = HashSet::new();
        let dominated: HashSet<String> = ["child.contoso.local".to_string()].into_iter().collect();
        assert!(has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &dominated
        ));
    }

    #[test]
    fn escalation_missing_target_domain_stays_pending() {
        // Conservative default: a vuln with no target_domain can't be proven
        // moot, so it keeps blocking.
        let mut discovered = std::collections::HashMap::new();
        let mut v = make_forest_escalation_vuln("v1", "fabrikam.local", false);
        v.details.remove("target_domain");
        discovered.insert("v1".to_string(), v);
        let exploited = HashSet::new();
        let dominated: HashSet<String> = ["fabrikam.local".to_string()].into_iter().collect();
        assert!(has_pending_cross_forest_escalation(
            &discovered,
            &exploited,
            &dominated
        ));
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
    fn twenty_min() -> Duration {
        Duration::from_secs(1200)
    }
    fn three_min() -> Duration {
        Duration::from_secs(180)
    }

    #[test]
    fn completion_completed_flag_wins() {
        let mut snap = empty_snapshot();
        snap.completed = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
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
                twenty_min(),
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
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
            CompletionDecision::Continue
        );
    }

    #[test]
    fn completion_stop_on_da_short_circuits_grace() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                true,
                false,
                three_min()
            ),
            CompletionDecision::Stop("domain admin achieved (stop_on_domain_admin)")
        );
    }

    #[test]
    fn completion_stop_on_gt_waits_until_ticket_forged() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                true,
                three_min()
            ),
            CompletionDecision::Continue
        );
        snap.has_golden_ticket = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                true,
                three_min()
            ),
            CompletionDecision::Stop("golden ticket forged (stop_on_golden_ticket)")
        );
    }

    #[test]
    fn completion_default_mode_waits_for_all_forests() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = false;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
            CompletionDecision::Continue
        );
    }

    #[test]
    fn completion_all_forests_dominated_begins_grace_period() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
            CompletionDecision::BeginGracePeriod
        );
    }

    #[test]
    fn completion_grace_period_still_running_continues() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        snap.all_dominated_for = Some(Duration::from_secs(60));
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
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
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
            CompletionDecision::Stop("all forests dominated (post-exploitation complete)")
        );
    }

    #[test]
    fn completion_stop_on_da_beats_completed_priority() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.completed = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                true,
                false,
                three_min()
            ),
            CompletionDecision::Stop("operation marked completed")
        );
    }

    #[test]
    fn completion_soft_cap_stops_when_all_forests_done() {
        // DA achieved and all forests dominated → the soft cap fires; no
        // reason to extend beyond it once there's nothing left to compromise.
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::from_secs(601),
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min(),
            ),
            CompletionDecision::Stop("max runtime exceeded")
        );
    }

    #[test]
    fn completion_soft_cap_extends_when_forest_still_owed() {
        // DA on one domain but a trusted forest is still uncompromised — this
        // is the case that used to lose the second forest to the guillotine.
        // The soft cap must yield to Continue so the op keeps working the
        // remaining forest until it lands DA or hits the hard cap.
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = false;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::from_secs(601),
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min(),
            ),
            CompletionDecision::Continue
        );
    }

    #[test]
    fn completion_hard_cap_stops_even_with_forest_owed() {
        // The hard cap is the strict upper bound — even if a forest is still
        // uncompromised, the op must terminate rather than run forever.
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = false;
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::from_secs(1201),
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min(),
            ),
            CompletionDecision::Stop("hard max runtime exceeded")
        );
    }

    // ── tests for the blue drain wait ─────────────────────────────────

    #[test]
    fn drain_budget_must_outlast_one_investigation() {
        // The regression this guards: when the budget equalled the investigation
        // timeout, an investigation submitted at red completion was guaranteed to
        // be abandoned at the exact instant it would have timed out.
        assert!(
            resolve_blue_drain_budget(None) > Duration::from_secs(BLUE_INVESTIGATION_TIMEOUT_SECS)
        );
    }

    #[test]
    fn drain_budget_default() {
        assert_eq!(
            resolve_blue_drain_budget(None),
            Duration::from_secs(BLUE_INVESTIGATION_TIMEOUT_SECS + BLUE_DRAIN_SLACK_SECS)
        );
    }

    #[test]
    fn drain_budget_env_override() {
        assert_eq!(
            resolve_blue_drain_budget(Some("120")),
            Duration::from_secs(120)
        );
        assert_eq!(
            resolve_blue_drain_budget(Some("  900 ")),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn drain_budget_rejects_junk_and_zero() {
        let default = resolve_blue_drain_budget(None);
        assert_eq!(resolve_blue_drain_budget(Some("")), default);
        assert_eq!(resolve_blue_drain_budget(Some("soon")), default);
        assert_eq!(resolve_blue_drain_budget(Some("-5")), default);
        assert_eq!(resolve_blue_drain_budget(Some("0")), default);
    }

    #[test]
    fn outstanding_while_status_is_non_terminal() {
        for status in ["queued", "in_progress", "triage", "hunting"] {
            assert!(still_outstanding(Some(status), true), "{status}");
            assert!(still_outstanding(Some(status), false), "{status}");
        }
    }

    #[test]
    fn not_outstanding_once_status_is_terminal() {
        for status in [
            "completed",
            "escalated",
            "failed",
            "timed_out",
            "superseded",
        ] {
            assert!(!still_outstanding(Some(status), true), "{status}");
            assert!(!still_outstanding(Some(status), false), "{status}");
        }
    }

    #[test]
    fn missing_status_follows_the_wait_flag() {
        // Just-submitted investigation: the runner hasn't registered it yet, so
        // the gap must count as outstanding or the op shuts down before blue
        // starts.
        assert!(still_outstanding(None, true));
        // Pre-existing investigation whose status key expired: not worth waiting
        // out the whole budget for.
        assert!(!still_outstanding(None, false));
    }

    #[test]
    fn superseded_status_is_terminal_for_the_drain_wait() {
        // A superseded investigation must release the drain wait — otherwise
        // freeing the runner slot would trade one stall for another.
        assert!(ares_core::state::blue_status_is_terminal("superseded"));
    }

    #[test]
    fn completion_grace_period_boundary_exact_match_stops() {
        let mut snap = empty_snapshot();
        snap.has_domain_admin = true;
        snap.undominated_forests_empty = true;
        snap.all_dominated_for = Some(three_min());
        assert_eq!(
            evaluate_completion(
                &snap,
                Duration::ZERO,
                ten_min(),
                twenty_min(),
                false,
                false,
                three_min()
            ),
            CompletionDecision::Stop("all forests dominated (post-exploitation complete)")
        );
    }
}
