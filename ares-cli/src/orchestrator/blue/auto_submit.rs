//! Auto-submit blue team investigations from red team operation state.
//!
//! When `ARES_BLUE_ENABLED=1`, this background task watches for red team
//! findings and automatically submits investigation requests to the
//! `ares:blue:investigations` queue. Without this, the blue orchestrator
//! polls an empty queue forever — investigation requests must be pushed
//! explicitly (via CLI) or auto-submitted (this module).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ares_core::models::SharedRedTeamState;
use ares_core::state::RedisStateReader;
use chrono::Utc;
use redis::AsyncCommands;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::task_queue::TaskQueue;

/// "Deep activity" thresholds — red has looted enough that a blue investigation
/// is worth running even before it reaches a hard milestone. Both must hold.
const MIN_CREDENTIALS_DEEP: usize = 5;
const MIN_VULNS_DEEP: usize = 3;

/// How long to wait after orchestrator start before first check.
const INITIAL_DELAY_SECS: u64 = 90;

/// How often to check if a new investigation should be submitted.
const CHECK_INTERVAL_SECS: u64 = 30;

const DEFAULT_REINVESTIGATE_AFTER_SECS: u64 = 900;

fn reinvestigate_after_secs() -> u64 {
    std::env::var("ARES_BLUE_REINVESTIGATE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_REINVESTIGATE_AFTER_SECS)
}

async fn has_unfinished_investigation(
    conn: &mut redis::aio::ConnectionManager,
    operation_id: &str,
) -> bool {
    let key = format!("ares:blue:op:{operation_id}:investigations");
    let ids: Vec<String> = redis::cmd("SMEMBERS")
        .arg(&key)
        .query_async(conn)
        .await
        .unwrap_or_default();

    for id in ids {
        let status = ares_core::state::read_blue_status(conn, &id)
            .await
            .unwrap_or(None);
        if !status
            .as_deref()
            .is_some_and(ares_core::state::blue_status_is_terminal)
        {
            return true;
        }
    }
    false
}

/// Strength of the red-team milestone reached so far, read from Redis.
///
/// Monotonic over an operation's life (credentials/vulns only grow;
/// `has_domain_admin` and the completion timestamps latch). The auto-submit
/// loop re-fires a fresh investigation whenever this level *increases*, so a
/// later run sees the fuller loot and technique set rather than firing once,
/// early, on a trivial host count.
///
/// - 3: red reached a terminal state (full loot is now in Redis)
/// - 2: Domain Admin achieved
/// - 1: deep-enough activity (`>= MIN_CREDENTIALS_DEEP` creds AND
///   `>= MIN_VULNS_DEEP` vulns)
/// - 0: nothing worth investigating yet
fn milestone_level(state: &SharedRedTeamState) -> u8 {
    if state.red_completed_at.is_some() || state.completed_at.is_some() {
        3
    } else if state.has_domain_admin {
        2
    } else if state.all_credentials.len() >= MIN_CREDENTIALS_DEEP
        && state.discovered_vulnerabilities.len() >= MIN_VULNS_DEEP
    {
        1
    } else {
        0
    }
}

/// Collect the distinct MITRE technique IDs red actually used, from both the
/// techniques set and the recorded timeline events. This is what populates the
/// alert's `techniques_used` (previously hardcoded empty), which the initial
/// alert prompt renders as "HUNT FOR EVIDENCE OF THESE SPECIFIC TECHNIQUES".
fn collect_techniques(state: &SharedRedTeamState) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for t in &state.all_techniques {
        let t = t.trim();
        if !t.is_empty() {
            set.insert(t.to_string());
        }
    }
    for ev in &state.all_timeline_events {
        if let Some(arr) = ev.get("mitre_techniques").and_then(|v| v.as_array()) {
            for t in arr.iter().filter_map(|v| v.as_str()) {
                let t = t.trim();
                if !t.is_empty() {
                    set.insert(t.to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Collect env vars that blue tools need (Grafana, Loki, etc.).
fn collect_blue_env_vars() -> std::collections::HashMap<String, String> {
    const NAMES: &[&str] = &[
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "GRAFANA_URL",
        "LOKI_URL",
        "LOKI_AUTH_TOKEN",
        "PROMETHEUS_URL",
    ];
    let mut map = std::collections::HashMap::new();
    for name in NAMES {
        if let Ok(val) = std::env::var(name) {
            if !val.is_empty() {
                map.insert(name.to_string(), val);
            }
        }
    }
    map
}

/// Spawn the blue auto-submit task as a background tokio task.
///
/// `red_draining` is the dispatcher's freeze flag. Once red completes, the
/// completion monitor owns the terminal investigation, so this loop must stop
/// submitting: a milestone-3 investigation queued after the freeze lands in the
/// drain wait's own watch set and cannot finish inside it.
pub fn spawn_blue_auto_submit(
    queue: TaskQueue,
    config: Arc<OrchestratorConfig>,
    model_spec: String,
    red_draining: Arc<AtomicBool>,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = auto_submit_loop(queue, config, model_spec, red_draining, shutdown_rx).await
        {
            warn!("Blue auto-submit exited with error: {e}");
        }
    })
}

async fn auto_submit_loop(
    queue: TaskQueue,
    config: Arc<OrchestratorConfig>,
    model_spec: String,
    red_draining: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    info!("Blue auto-submit: waiting {INITIAL_DELAY_SECS}s for red team activity");

    // Wait for initial red team activity
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(INITIAL_DELAY_SECS)) => {}
        _ = shutdown_rx.changed() => return Ok(()),
    }

    // Highest milestone level we've already submitted an investigation for.
    let mut last_level: u8 = 0;
    let mut last_submit: Option<tokio::time::Instant> = None;
    let reader = RedisStateReader::new(config.operation_id.clone());

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        if red_draining.load(Ordering::SeqCst) {
            info!("Blue auto-submit: red dispatch frozen — completion owns the terminal investigation");
            break;
        }

        // Read red state from Redis — NOT the orchestrator's in-memory
        // SharedState. If the red orchestrator restarted, its in-memory state
        // is empty even though Redis holds the full historical loot; reading
        // Redis is what makes the alert body and technique list accurate.
        let mut conn = queue.connection();
        let loaded = reader.load_state(&mut conn).await;
        match loaded {
            Ok(Some(state)) => {
                let level = milestone_level(&state);
                let interval = reinvestigate_after_secs();
                let stale = interval > 0
                    && level > 0
                    && last_submit.is_some_and(|at| at.elapsed() >= Duration::from_secs(interval));
                let refresh =
                    stale && !has_unfinished_investigation(&mut conn, &config.operation_id).await;

                if level > last_level || refresh {
                    info!(
                        credentials = state.all_credentials.len(),
                        vulns = state.discovered_vulnerabilities.len(),
                        has_domain_admin = state.has_domain_admin,
                        milestone_level = level,
                        refresh,
                        "Blue auto-submit: submitting investigation"
                    );
                    match submit_investigation(&queue, &state, &config, &model_spec).await {
                        Ok(inv_id) => {
                            last_level = last_level.max(level);
                            last_submit = Some(tokio::time::Instant::now());
                            info!(
                                investigation_id = %inv_id,
                                operation_id = %config.operation_id,
                                milestone_level = level,
                                refresh,
                                "Blue auto-submit: investigation queued"
                            );
                        }
                        Err(e) => {
                            warn!("Blue auto-submit: failed to submit investigation: {e}");
                        }
                    }
                }
            }
            Ok(None) => {
                // Red hasn't written any operation state to Redis yet.
            }
            Err(e) => {
                warn!("Blue auto-submit: failed to load red state from Redis: {e}");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(CHECK_INTERVAL_SECS)) => {}
            _ = shutdown_rx.changed() => break,
        }
    }

    info!("Blue auto-submit task finished");
    Ok(())
}

/// Build and submit a blue investigation request from the red team state
/// loaded from Redis.
async fn submit_investigation(
    queue: &TaskQueue,
    state: &SharedRedTeamState,
    config: &OrchestratorConfig,
    model_spec: &str,
) -> Result<String> {
    let now = Utc::now();

    let op_id = &config.operation_id;
    let inv_id = format!("inv-{}", now.format("%Y%m%d-%H%M%S"));

    // Collect target data from the Redis-loaded state.
    let target_ips: Vec<String> = state
        .all_hosts
        .iter()
        .map(|h| h.ip.clone())
        .filter(|ip| !ip.is_empty())
        .collect();
    let target_users: Vec<String> = state
        .all_credentials
        .iter()
        .map(|c| c.username.clone())
        .collect();
    let cred_count = state.all_credentials.len();
    let host_count = state.all_hosts.len();
    let vuln_count = state.discovered_vulnerabilities.len();
    let domains: Vec<String> = state.all_domains.clone();

    // Real MITRE techniques red used, from the techniques set + timeline.
    let techniques: Vec<String> = collect_techniques(state);

    let grafana_url = std::env::var("GRAFANA_URL").ok();
    let grafana_token = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok();

    // Parse the op's start time from its ID (op-YYYYMMDD-HHMMSS).
    let attack_window_start = crate::ops::delete::parse_operation_timestamp(op_id).unwrap_or(now);
    // End the window at the op's real end when red has finished, so a
    // terminal-state submission covers the whole attack rather than clipping
    // the window to submission time. Falls back to `now` for mid-op submissions.
    let attack_window_end = state.red_completed_at.or(state.completed_at).unwrap_or(now);

    // Build synthetic alert (mirrors `ares blue from-operation`)
    let operation_context = serde_json::json!({
        "operation_id": op_id,
        "attack_window_start": attack_window_start.to_rfc3339(),
        "attack_window_end": attack_window_end.to_rfc3339(),
        "techniques_used": techniques,
        "domains": domains,
    });

    let alert = serde_json::json!({
        "labels": {
            "alertname": format!("RedTeamOperation_{op_id}"),
            "severity": "critical",
            "source": "ares-red-team",
        },
        "annotations": {
            "summary": format!(
                "Red team operation {op_id} - {cred_count} credentials, {host_count} hosts, {vuln_count} vulnerabilities",
            ),
            "description": format!(
                "Investigate blue team detection coverage for red team operation {op_id}. \
                 Operation is in progress.",
            ),
        },
        "operation_context": operation_context,
        "startsAt": now.to_rfc3339(),
        "target_ips": &target_ips[..std::cmp::min(target_ips.len(), 50)],
        "target_users": &target_users[..std::cmp::min(target_users.len(), 50)],
    });

    // Strip provider prefix for the model name (blue runner does this too)
    let model = model_spec
        .split_once('/')
        .map(|(_, name)| name)
        .unwrap_or(model_spec);

    let request = serde_json::json!({
        "investigation_id": inv_id,
        "alert": alert,
        "correlation_context": null,
        "model": model,
        "max_steps": 75,
        "multi_agent": true,
        "auto_route": false,
        "report_dir": null,
        "operation_id": op_id,
        "grafana_url": grafana_url,
        "grafana_api_key": grafana_token,
        "submitted_at": now.to_rfc3339(),
    });

    let mut conn = queue.connection();

    // Store env vars for the investigation (blue tools read these from Redis)
    let env_vars = collect_blue_env_vars();
    if !env_vars.is_empty() {
        let env_key = format!("ares:blue:inv:{inv_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_key, &env_json).await?;
        let _: () = conn.expire(&env_key, 3600).await?;
    }

    // Track investigation against operation (Redis state)
    let op_inv_key = format!("ares:blue:op:{op_id}:investigations");
    let _: () = conn.sadd(&op_inv_key, &inv_id).await?;
    let _: () = conn.expire(&op_inv_key, 7 * 24 * 3600).await?;

    // Publish investigation request to NATS (reuse the orchestrator's broker)
    let nats = queue
        .nats_broker()
        .ok_or_else(|| anyhow::anyhow!("Orchestrator TaskQueue has no NATS broker"))?;
    ares_core::state::blue_task_queue::BlueTaskQueue::submit_investigation_request(&nats, &request)
        .await?;

    Ok(inv_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, VulnerabilityInfo};

    fn state() -> SharedRedTeamState {
        SharedRedTeamState::new("op-20260707-000000".into())
    }

    fn cred(i: usize) -> Credential {
        Credential {
            id: format!("c{i}"),
            username: format!("user{i}"),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn vuln(i: usize) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: format!("v{i}"),
            vuln_type: "esc1".into(),
            target: "192.168.58.10".into(),
            discovered_by: "test".into(),
            discovered_at: Utc::now(),
            details: std::collections::HashMap::new(),
            recommended_agent: String::new(),
            priority: 0,
        }
    }

    #[test]
    fn milestone_level_empty_is_zero() {
        assert_eq!(milestone_level(&state()), 0);
    }

    #[test]
    fn reinvestigate_interval_defaults_and_respects_override() {
        std::env::remove_var("ARES_BLUE_REINVESTIGATE_SECS");
        assert_eq!(reinvestigate_after_secs(), DEFAULT_REINVESTIGATE_AFTER_SECS);
        std::env::set_var("ARES_BLUE_REINVESTIGATE_SECS", "600");
        assert_eq!(reinvestigate_after_secs(), 600);
        std::env::set_var("ARES_BLUE_REINVESTIGATE_SECS", "0");
        assert_eq!(reinvestigate_after_secs(), 0);
        std::env::set_var("ARES_BLUE_REINVESTIGATE_SECS", "junk");
        assert_eq!(reinvestigate_after_secs(), DEFAULT_REINVESTIGATE_AFTER_SECS);
        std::env::remove_var("ARES_BLUE_REINVESTIGATE_SECS");
    }

    #[test]
    fn milestone_level_deep_activity_is_one() {
        let mut s = state();
        s.all_credentials = (0..MIN_CREDENTIALS_DEEP).map(cred).collect();
        for i in 0..MIN_VULNS_DEEP {
            s.discovered_vulnerabilities
                .insert(format!("v{i}"), vuln(i));
        }
        assert_eq!(milestone_level(&s), 1);
    }

    #[test]
    fn milestone_level_deep_needs_both_thresholds() {
        let mut s = state();
        // Enough creds but zero vulns — must NOT reach the deep level.
        s.all_credentials = (0..MIN_CREDENTIALS_DEEP + 3).map(cred).collect();
        assert_eq!(milestone_level(&s), 0);
    }

    #[test]
    fn milestone_level_domain_admin_is_two() {
        let mut s = state();
        s.has_domain_admin = true;
        assert_eq!(milestone_level(&s), 2);
    }

    #[test]
    fn milestone_level_terminal_beats_domain_admin() {
        let mut s = state();
        s.has_domain_admin = true;
        s.red_completed_at = Some(Utc::now());
        assert_eq!(milestone_level(&s), 3);
    }

    #[test]
    fn milestone_level_completed_at_is_terminal() {
        let mut s = state();
        s.completed_at = Some(Utc::now());
        assert_eq!(milestone_level(&s), 3);
    }

    #[test]
    fn collect_techniques_merges_dedups_and_drops_blanks() {
        let mut s = state();
        s.all_techniques = vec!["T1558.004".into(), "T1649".into(), "  ".into()];
        s.all_timeline_events = vec![
            serde_json::json!({ "mitre_techniques": ["T1134.005", "T1649"] }),
            serde_json::json!({ "description": "no techniques here" }),
        ];
        // BTreeSet output: sorted, deduped, whitespace-only dropped.
        assert_eq!(
            collect_techniques(&s),
            vec!["T1134.005", "T1558.004", "T1649"]
        );
    }
}
