use anyhow::{Context, Result};
use chrono::Utc;
use redis::AsyncCommands;
use tracing::info;

use ares_core::state::RedisStateReader;

use crate::ops::submit::{collect_env_vars, resolve_model, BLUE_ENV_VAR_NAMES};
use crate::redis_conn::{connect_redis, resolve_operation_id};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn blue_submit(
    redis_url: Option<String>,
    alert_json: String,
    investigation_id: Option<String>,
    model: Option<String>,
    max_steps: u32,
    multi_agent: bool,
    auto_route: bool,
    grafana_url: Option<String>,
    grafana_api_key: Option<String>,
) -> Result<()> {
    // Parse alert JSON: either from file or inline string
    let alert: serde_json::Value = if std::path::Path::new(&alert_json).is_file() {
        let content = std::fs::read_to_string(&alert_json)
            .with_context(|| format!("Failed to read alert file: {alert_json}"))?;
        serde_json::from_str(&content)
            .with_context(|| format!("Invalid JSON in file: {alert_json}"))?
    } else {
        serde_json::from_str(&alert_json).context("Invalid alert JSON string")?
    };

    // Resolve model — if not specified, the orchestrator will use its config default
    let effective_model = resolve_model(&model);

    let inv_id = investigation_id
        .unwrap_or_else(|| format!("inv-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S")));

    let env_vars = collect_env_vars(BLUE_ENV_VAR_NAMES);
    if !env_vars.is_empty() {
        let mut keys: Vec<&str> = env_vars.keys().map(|s| s.as_str()).collect();
        keys.sort();
        info!(
            "Submitting investigation with env vars: {}",
            keys.join(", ")
        );
    }

    let now = Utc::now();

    // Format must match Python blue_orchestrator_client.py
    let request = serde_json::json!({
        "investigation_id": inv_id,
        "alert": alert,
        "correlation_context": null,
        "model": effective_model,
        "max_steps": max_steps,
        "multi_agent": multi_agent,
        "auto_route": auto_route,
        "report_dir": null,
        "grafana_url": grafana_url,
        "grafana_api_key": grafana_api_key,
        "submitted_at": now.to_rfc3339(),
    });

    let mut conn = connect_redis(redis_url).await?;

    // Stored separately to avoid exposing secrets in the main queue
    if !env_vars.is_empty() {
        let env_vars_key = format!("ares:blue:inv:{inv_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_vars_key, &env_json).await?;
        let _: () = conn.expire(&env_vars_key, 3600).await?;
    }

    // Push investigation request to queue
    let request_json = serde_json::to_string(&request)?;
    let _: () = conn
        .rpush("ares:blue:investigations", &request_json)
        .await?;

    info!("Investigation submitted: {inv_id}");
    println!("Investigation submitted: {inv_id}");
    println!("Status: submitted");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn blue_from_operation(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    model: Option<String>,
    max_steps: u32,
    grafana_url: Option<String>,
    grafana_api_key: Option<String>,
) -> Result<()> {
    let mut conn = connect_redis(redis_url.clone()).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    // Load the red team operation state
    let reader = RedisStateReader::new(op_id.clone());
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let is_running = reader.is_running(&mut conn).await?;

    // Extract attack window
    let window_start = state.started_at;
    let window_end = state.completed_at.unwrap_or_else(Utc::now);

    info!("Operation: {op_id}");
    info!(
        "Attack window: {} to {}",
        window_start.to_rfc3339(),
        window_end.to_rfc3339()
    );
    info!("Running: {is_running}");

    // Resolve model — if not specified, the orchestrator will use its config default
    let effective_model = resolve_model(&model);

    // Resolve Grafana config
    let grafana_url = grafana_url.or_else(|| std::env::var("GRAFANA_URL").ok());
    let grafana_api_key =
        grafana_api_key.or_else(|| std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok());

    if grafana_url.is_none() {
        anyhow::bail!("Grafana URL required. Use --grafana-url or set GRAFANA_URL");
    }
    if grafana_api_key.is_none() {
        anyhow::bail!(
            "Grafana API key required. Use --grafana-api-key or set GRAFANA_SERVICE_ACCOUNT_TOKEN"
        );
    }

    let env_vars = collect_env_vars(BLUE_ENV_VAR_NAMES);

    // Build operation context that will be attached to each investigation
    let target_env = state
        .target
        .as_ref()
        .map(|t| t.environment.clone())
        .unwrap_or_default();

    // Collect attack techniques from state
    let techniques_key = format!("ares:op:{op_id}:techniques");
    let techniques: Vec<String> = redis::cmd("SMEMBERS")
        .arg(&techniques_key)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    let operation_context = serde_json::json!({
        "operation_id": op_id,
        "attack_window_start": window_start.to_rfc3339(),
        "attack_window_end": window_end.to_rfc3339(),
        "techniques_used": &techniques[..std::cmp::min(techniques.len(), 20)],
        "deployment": target_env,
    });

    // Build summary of what was found in the operation
    let cred_count = state.all_credentials.len();
    let host_count = state.all_hosts.len();
    let vuln_count = state.discovered_vulnerabilities.len();

    // Collect host IPs and usernames from operation for alert context
    let target_ips: Vec<String> = state.all_hosts.iter().map(|h| h.ip.clone()).collect();
    let target_users: Vec<String> = state
        .all_credentials
        .iter()
        .map(|c| c.username.clone())
        .collect();

    // Generate a synthetic alert from the red team operation data
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
                 Attack window: {} to {}. Domain admin: {}.",
                window_start.to_rfc3339(),
                window_end.to_rfc3339(),
                state.has_domain_admin,
            ),
        },
        "operation_context": operation_context,
        "startsAt": window_start.to_rfc3339(),
        "endsAt": window_end.to_rfc3339(),
        "target_ips": &target_ips[..std::cmp::min(target_ips.len(), 50)],
        "target_users": &target_users[..std::cmp::min(target_users.len(), 50)],
    });

    // Submit as a single multi-agent investigation
    let now = Utc::now();
    let inv_id = format!("inv-{}", now.format("%Y%m%d-%H%M%S"));

    let request = serde_json::json!({
        "investigation_id": inv_id,
        "alert": alert,
        "correlation_context": null,
        "model": effective_model,
        "max_steps": max_steps,
        "multi_agent": true,
        "auto_route": false,
        "report_dir": null,
        "grafana_url": grafana_url,
        "grafana_api_key": grafana_api_key,
        "submitted_at": now.to_rfc3339(),
    });

    // Stored separately to avoid exposing secrets in the main queue
    if !env_vars.is_empty() {
        let env_vars_key = format!("ares:blue:inv:{inv_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_vars_key, &env_json).await?;
        let _: () = conn.expire(&env_vars_key, 3600).await?;
    }

    // Push to investigation queue
    let request_json = serde_json::to_string(&request)?;
    let _: () = conn
        .rpush("ares:blue:investigations", &request_json)
        .await?;

    // Track investigation against operation
    let op_inv_key = format!("ares:blue:op:{op_id}:investigations");
    let _: () = conn.sadd(&op_inv_key, &inv_id).await?;
    let _: () = conn.expire(&op_inv_key, 7 * 24 * 3600).await?; // 7 day TTL

    info!("Investigation submitted: {inv_id}");
    println!("Investigation submitted: {inv_id} (from operation {op_id})");
    println!("Status: submitted");
    println!("\nTrack progress with: ares-cli blue operation-status {op_id}");

    Ok(())
}
