use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

const DEFAULT_INTERVAL_SECS: u64 = 180;
const DEFAULT_WARMUP_SECS: u64 = 120;

fn secs_from_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
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

pub async fn auto_orchestrator_planning(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    if !planner_enabled() {
        info!("Orchestrator planner disabled by ARES_ORCHESTRATOR_PLANNER");
        return;
    }

    let interval_secs = secs_from_env(
        "ARES_ORCHESTRATOR_PLANNER_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );
    let warmup_secs = secs_from_env("ARES_ORCHESTRATOR_PLANNER_WARMUP_SECS", DEFAULT_WARMUP_SECS);

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let start = Instant::now();
    info!(interval_secs, warmup_secs, "Orchestrator planner started");

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = dispatcher.proposals.wait_for_arrival() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if start.elapsed() < Duration::from_secs(warmup_secs) {
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
        assert!(planner_enabled(), "planner must default to enabled");

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
}
