//! Auto-submit blue team investigations from red team operation state.
//!
//! When `ARES_BLUE_ENABLED=1`, this background task watches for red team
//! findings and automatically submits investigation requests to the
//! `ares:blue:investigations` queue. Without this, the blue orchestrator
//! polls an empty queue forever — investigation requests must be pushed
//! explicitly (via CLI) or auto-submitted (this module).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use redis::AsyncCommands;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::OrchestratorConfig;
use crate::state::SharedState;
use crate::task_queue::TaskQueue;

/// Minimum red team activity before submitting a blue investigation.
const MIN_CREDENTIALS: usize = 1;
const MIN_HOSTS: usize = 2;

/// How long to wait after orchestrator start before first check.
const INITIAL_DELAY_SECS: u64 = 90;

/// How often to check if a new investigation should be submitted.
const CHECK_INTERVAL_SECS: u64 = 30;

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
pub fn spawn_blue_auto_submit(
    queue: TaskQueue,
    shared_state: SharedState,
    config: Arc<OrchestratorConfig>,
    model_spec: String,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = auto_submit_loop(queue, shared_state, config, model_spec, shutdown_rx).await
        {
            warn!("Blue auto-submit exited with error: {e}");
        }
    })
}

async fn auto_submit_loop(
    queue: TaskQueue,
    shared_state: SharedState,
    config: Arc<OrchestratorConfig>,
    model_spec: String,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    info!("Blue auto-submit: waiting {INITIAL_DELAY_SECS}s for red team activity");

    // Wait for initial red team activity
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(INITIAL_DELAY_SECS)) => {}
        _ = shutdown_rx.changed() => return Ok(()),
    }

    let mut submitted = false;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        if !submitted {
            let state = shared_state.read().await;
            let cred_count = state.credentials.len();
            let host_count = state.hosts.len();
            let vuln_count = state.discovered_vulnerabilities.len();
            let has_enough = cred_count >= MIN_CREDENTIALS || host_count >= MIN_HOSTS;
            drop(state);

            if has_enough {
                info!(
                    credentials = cred_count,
                    hosts = host_count,
                    vulns = vuln_count,
                    "Blue auto-submit: red team has enough findings, submitting investigation"
                );

                match submit_investigation(&queue, &shared_state, &config, &model_spec).await {
                    Ok(inv_id) => {
                        info!(
                            investigation_id = %inv_id,
                            operation_id = %config.operation_id,
                            "Blue auto-submit: investigation queued"
                        );
                        submitted = true;
                    }
                    Err(e) => {
                        warn!("Blue auto-submit: failed to submit investigation: {e}");
                    }
                }
            }
        }

        if submitted {
            // Done — exit the loop
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(CHECK_INTERVAL_SECS)) => {}
            _ = shutdown_rx.changed() => break,
        }
    }

    info!("Blue auto-submit task finished");
    Ok(())
}

/// Build and submit a blue investigation request from the current red team state.
async fn submit_investigation(
    queue: &TaskQueue,
    shared_state: &SharedState,
    config: &OrchestratorConfig,
    model_spec: &str,
) -> Result<String> {
    let state = shared_state.read().await;
    let now = Utc::now();

    let op_id = &config.operation_id;
    let inv_id = format!("inv-{}", now.format("%Y%m%d-%H%M%S"));

    // Collect target data from state
    let target_ips: Vec<String> = state.hosts.iter().map(|h| h.ip.clone()).collect();
    let target_users: Vec<String> = state
        .credentials
        .iter()
        .map(|c| c.username.clone())
        .collect();
    let cred_count = state.credentials.len();
    let host_count = state.hosts.len();
    let vuln_count = state.discovered_vulnerabilities.len();
    let domains: Vec<String> = state.domains.clone();

    // Collect MITRE techniques from timeline if available
    let techniques: Vec<String> = Vec::new(); // Timeline techniques would need Redis lookup

    drop(state);

    let grafana_url = std::env::var("GRAFANA_URL").ok();
    let grafana_token = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok();

    // Build synthetic alert (mirrors ares-cli blue from-operation)
    let operation_context = serde_json::json!({
        "operation_id": op_id,
        "attack_window_start": now.to_rfc3339(),
        "attack_window_end": now.to_rfc3339(),
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

    // Push to investigation queue
    let request_json = serde_json::to_string(&request)?;
    let _: () = conn
        .rpush("ares:blue:investigations", &request_json)
        .await?;

    // Track investigation against operation
    let op_inv_key = format!("ares:blue:op:{op_id}:investigations");
    let _: () = conn.sadd(&op_inv_key, &inv_id).await?;
    let _: () = conn.expire(&op_inv_key, 7 * 24 * 3600).await?;

    Ok(inv_id)
}
