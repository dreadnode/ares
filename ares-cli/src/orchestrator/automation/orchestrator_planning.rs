use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::proposals::mediation_enabled;

const DEFAULT_INTERVAL_SECS: u64 = 180;
const DEFAULT_WARMUP_SECS: u64 = 120;
const DEFAULT_MIN_GAP_SECS: u64 = 60;
const REVIEWS_PER_WINDOW: u64 = 3;

fn secs_from_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn effective_interval_secs(configured: u64, window_secs: u64, mediation_on: bool) -> u64 {
    if !mediation_on {
        return configured;
    }
    configured.min((window_secs / REVIEWS_PER_WINDOW).max(1))
}

fn planner_enabled() -> bool {
    match std::env::var("ARES_ORCHESTRATOR_PLANNER") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

fn planning_turn_is_due(since_last_turn: Option<Duration>, min_gap: Duration) -> bool {
    match since_last_turn {
        None => true,
        Some(elapsed) => elapsed >= min_gap,
    }
}

pub async fn auto_orchestrator_planning(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    if !planner_enabled() {
        info!("Orchestrator planner disabled by ARES_ORCHESTRATOR_PLANNER");
        return;
    }

    let configured_interval_secs = secs_from_env(
        "ARES_ORCHESTRATOR_PLANNER_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );
    let warmup_secs = secs_from_env("ARES_ORCHESTRATOR_PLANNER_WARMUP_SECS", DEFAULT_WARMUP_SECS);
    let min_gap_secs = secs_from_env(
        "ARES_ORCHESTRATOR_PLANNER_MIN_GAP_SECS",
        DEFAULT_MIN_GAP_SECS,
    );
    let window_secs = dispatcher.proposals.window().as_secs();
    let mediation_on = mediation_enabled();
    let interval_secs =
        effective_interval_secs(configured_interval_secs, window_secs, mediation_on);

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let min_gap = Duration::from_secs(min_gap_secs);
    let planning_notify = dispatcher.planning_notify.clone();
    let mut last_turn: Option<Instant> = None;

    let start = Instant::now();
    info!(
        interval_secs,
        configured_interval_secs,
        warmup_secs,
        window_secs,
        min_gap_secs,
        mediation_on,
        "Orchestrator planner started"
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = planning_notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if start.elapsed() < Duration::from_secs(warmup_secs) {
            continue;
        }

        if !planning_turn_is_due(last_turn.map(|t| t.elapsed()), min_gap) {
            debug!("Orchestrator planner: inside the minimum gap, skipping wake");
            continue;
        }

        if dispatcher.is_red_draining() {
            debug!("Orchestrator planner: red draining, skipping tick");
            continue;
        }

        if dispatcher.tracker.count_for_role("orchestrator").await > 0 {
            debug!("Orchestrator planner: a planning task is still running, skipping tick");
            continue;
        }

        let payload = build_planning_payload(&dispatcher).await;

        match dispatcher
            .throttled_submit("orchestrator_plan", "orchestrator", payload, 4)
            .await
        {
            Ok(outcome) => {
                debug!(?outcome, "Orchestrator planner: submitted planning task");
            }
            Err(e) => {
                warn!(err = %e, "Orchestrator planner: failed to submit planning task");
            }
        }

        last_turn = Some(Instant::now());
    }

    info!("Orchestrator planner stopped");
}

async fn build_planning_payload(dispatcher: &Arc<Dispatcher>) -> serde_json::Value {
    let undominated = crate::orchestrator::completion::undominated_forests(&dispatcher.state).await;

    let state = dispatcher.state.read().await;

    let uncracked = state
        .hashes
        .iter()
        .filter(|h| h.cracked_password.is_none())
        .count();
    let unexploited: Vec<&str> = state
        .discovered_vulnerabilities
        .iter()
        .filter(|(id, _)| !state.exploited_vulnerabilities.contains(*id))
        .map(|(id, _)| id.as_str())
        .take(40)
        .collect();

    serde_json::json!({
        "domains": state.domains,
        "credentials": state.credentials.len(),
        "admin_credentials": state.credentials.iter().filter(|c| c.is_admin).count(),
        "hashes": state.hashes.len(),
        "uncracked_hashes": uncracked,
        "hosts": state.hosts.len(),
        "has_domain_admin": state.has_domain_admin,
        "undominated_forests": undominated,
        "unexploited_vulnerability_ids": unexploited,
        "pending_tasks": state.pending_tasks.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secs_from_env_rejects_zero_and_garbage() {
        let key = "ARES_TEST_PLANNER_SECS_UNSET";
        std::env::remove_var(key);
        assert_eq!(secs_from_env(key, 180), 180);

        std::env::set_var(key, "0");
        assert_eq!(secs_from_env(key, 180), 180);

        std::env::set_var(key, "not-a-number");
        assert_eq!(secs_from_env(key, 180), 180);

        std::env::set_var(key, " 45 ");
        assert_eq!(secs_from_env(key, 180), 45);

        std::env::remove_var(key);
    }

    #[test]
    fn planner_defaults_on_and_respects_falsey_values() {
        let key = "ARES_ORCHESTRATOR_PLANNER";
        std::env::remove_var(key);
        assert!(
            planner_enabled(),
            "the orchestrator is the team lead; with the planner off nothing creates an \
             orchestrator turn, so complete_operation is never called and the rules are the \
             only scheduler"
        );

        for falsey in ["0", "false", "off", "no", "FALSE", " Off "] {
            std::env::set_var(key, falsey);
            assert!(!planner_enabled(), "{falsey} must disable the planner");
        }

        for truthy in ["1", "true", "on", "yes"] {
            std::env::set_var(key, truthy);
            assert!(planner_enabled(), "{truthy} must leave the planner enabled");
        }

        std::env::remove_var(key);
    }

    #[test]
    fn the_first_wake_always_plans() {
        assert!(
            planning_turn_is_due(None, Duration::from_secs(60)),
            "the warm-up delay already gates the first turn; the gap must not add a second wait"
        );
    }

    #[test]
    fn a_discovery_burst_cannot_outpace_the_minimum_gap() {
        let min_gap = Duration::from_secs(60);
        assert!(
            !planning_turn_is_due(Some(Duration::from_secs(1)), min_gap),
            "wake-on-discovery without a floor is what turned a 180s cadence into 208 turns in \
             one op, because every publish woke the planner and single-flight caps concurrency \
             rather than frequency"
        );
        assert!(!planning_turn_is_due(
            Some(Duration::from_secs(59)),
            min_gap
        ));
    }

    #[test]
    fn a_discovery_after_the_gap_plans_without_waiting_for_the_tick() {
        let min_gap = Duration::from_secs(60);
        assert!(planning_turn_is_due(Some(Duration::from_secs(60)), min_gap));
        assert!(
            planning_turn_is_due(Some(Duration::from_secs(61)), min_gap),
            "reacting to published discoveries faster than the timer is the point of the signal"
        );
    }

    #[test]
    fn a_zero_gap_leaves_every_wake_eligible() {
        assert!(planning_turn_is_due(
            Some(Duration::from_secs(0)),
            Duration::ZERO
        ));
    }

    #[test]
    fn without_mediation_the_configured_interval_is_untouched() {
        assert_eq!(
            effective_interval_secs(DEFAULT_INTERVAL_SECS, 180, false),
            DEFAULT_INTERVAL_SECS,
            "a planner-only opt-in must not pay for a review cadence it has nothing to review"
        );
    }

    #[test]
    fn mediation_forces_review_cadence_strictly_inside_the_release_window() {
        let window_secs = 180;
        let interval = effective_interval_secs(DEFAULT_INTERVAL_SECS, window_secs, true);

        assert!(
            interval < window_secs,
            "a review tick no faster than the window means work auto-releases before it is ever \
             reviewed, so mediation buys latency and no veto"
        );
        assert_eq!(interval, 60);
    }

    #[test]
    fn a_faster_configured_interval_is_left_alone() {
        assert_eq!(
            effective_interval_secs(15, 180, true),
            15,
            "the cap is a ceiling on review latency, not a floor"
        );
    }

    #[test]
    fn the_interval_never_collapses_to_zero() {
        assert_eq!(
            effective_interval_secs(180, 1, true),
            1,
            "tokio::time::interval panics on a zero period, so a sub-REVIEWS_PER_WINDOW window \
             must still yield a tickable duration"
        );
    }
}
