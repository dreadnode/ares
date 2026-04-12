//! Ares Orchestrator — Rust-native orchestration loop.

#![allow(dead_code)]
//!
//! Entry point for the `ares-orchestrator` binary. Rust owns the tokio event
//! loop and all Redis IO. When `ARES_LLM_MODEL` is set, tasks are driven by
//! the Rust LLM agent loop; otherwise they are pushed to Redis for workers.
//!
//! Startup sequence:
//!   1. Load config from env vars
//!   2. Connect to Redis
//!   3. Acquire the operation lock
//!   4. Load shared state from Redis
//!   5. Spawn background tasks: heartbeat monitor, result consumer, deferred
//!      processor, cost summary, automation tasks, exploitation workflow,
//!      discovery poller, state refresh
//!   6. Enter the main orchestration loop

mod automation;
mod automation_spawner;
mod blue;
mod bootstrap;
pub(crate) mod callback_handler;
mod completion;
mod config;
mod cost_summary;
mod deferred;
mod dispatcher;
mod exploitation;
mod llm_runner;
mod monitoring;
mod output_extraction;
mod recovery;
mod result_processing;
mod results;
mod routing;
mod state;
mod task_queue;
mod throttling;
mod tool_dispatcher;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::automation_spawner::spawn_automation_tasks;
use crate::bootstrap::{bootstrap_meta, dispatch_initial_recon};
use crate::config::OrchestratorConfig;
use crate::cost_summary::spawn_cost_summary;
use crate::deferred::DeferredQueue;
use crate::dispatcher::Dispatcher;
use crate::monitoring::{spawn_heartbeat_monitor, spawn_lock_keeper, AgentRegistry};
use crate::results::spawn_result_consumer;
use crate::routing::ActiveTaskTracker;
use crate::state::SharedState;
use crate::task_queue::TaskQueue;
use crate::throttling::Throttler;

#[tokio::main]
async fn main() -> Result<()> {
    // --- Telemetry (console + OTLP when endpoint is configured) ---
    let _telemetry = ares_core::telemetry::init_telemetry(
        ares_core::telemetry::TelemetryConfig::new("ares-orchestrator"),
    );

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "ares-orchestrator starting"
    );

    // --- Configuration ---
    let config =
        Arc::new(OrchestratorConfig::from_env().context("Failed to load config from environment")?);

    // Load the YAML config (optional — provides agent definitions, vuln priorities, etc.)
    let ares_config = match ares_core::config::AresConfig::from_env() {
        Ok(cfg) => {
            info!(
                config_name = %cfg.operation.name,
                agent_roles = cfg.agents.len(),
                "Loaded YAML config"
            );
            Some(Arc::new(cfg))
        }
        Err(e) => {
            info!("No YAML config loaded (using env vars only): {e}");
            None
        }
    };

    info!(
        operation_id = %config.operation_id,
        max_concurrent = config.max_concurrent_tasks,
        has_yaml_config = ares_config.is_some(),
        "Configuration loaded"
    );

    // --- Redis connection ---
    let queue = TaskQueue::connect(&config.redis_url)
        .await
        .context("Failed to connect to Redis")?;

    // --- Operation lock ---
    let acquired = queue
        .try_acquire_lock(&config.operation_id, config.lock_ttl)
        .await?;
    if !acquired {
        anyhow::bail!(
            "Operation {} is locked by another orchestrator",
            config.operation_id
        );
    }

    // --- Shared state ---
    let shared_state = SharedState::new(config.operation_id.clone());
    shared_state
        .load_from_redis(&queue)
        .await
        .context("Failed to load state from Redis")?;

    // --- Seed state from config (fresh operations have no Redis state yet) ---
    {
        let mut state = shared_state.write().await;
        if state.target_ips.is_empty() && !config.target_ips.is_empty() {
            state.target_ips = config.target_ips.clone();
            info!(
                target_domain = %config.target_domain,
                target_ips = ?config.target_ips,
                "Seeded target info from operation payload"
            );
        }
        // Seed target domain into state so automation tasks have it
        if !config.target_domain.is_empty() {
            let domain = config.target_domain.to_lowercase();
            if !state.domains.contains(&domain) {
                state.domains.push(domain.clone());
                // Also persist to Redis
                let domain_key = format!("ares:op:{}:domains", state.operation_id);
                let mut conn = queue.connection();
                let _: Result<(), _> =
                    redis::AsyncCommands::sadd(&mut conn, &domain_key, &domain).await;
                let _: Result<(), _> =
                    redis::AsyncCommands::expire(&mut conn, &domain_key, 86400i64).await;
                info!(domain = %domain, "Seeded target domain");
            }

            // Seed domain_controllers from target IPs so automation tasks
            // (AS-REP roast, Kerberoast, BloodHound, delegation enum) can fire
            // immediately without waiting for recon to report back.
            // Use the first target IP as the DC for the target domain.
            if state.domain_controllers.is_empty() {
                if let Some(first_ip) = config.target_ips.first() {
                    let dc_key = format!(
                        "{}:{}:{}",
                        ares_core::state::KEY_PREFIX,
                        state.operation_id,
                        ares_core::state::KEY_DC_MAP,
                    );
                    let mut conn = queue.connection();
                    let _: Result<(), _> =
                        redis::AsyncCommands::hset(&mut conn, &dc_key, &domain, first_ip).await;
                    state
                        .domain_controllers
                        .insert(domain.clone(), first_ip.clone());
                    info!(
                        domain = %domain,
                        dc_ip = %first_ip,
                        "Seeded domain controller from target IPs (enables immediate automation)"
                    );
                }
            }

            // Seed placeholder hosts for ALL target IPs (matches Python startup).
            // This ensures all IPs appear in the host list even before recon runs,
            // and detect_dc() on service results can trigger domain extraction.
            {
                let host_key = format!(
                    "{}:{}:{}",
                    ares_core::state::KEY_PREFIX,
                    state.operation_id,
                    ares_core::state::KEY_HOSTS,
                );
                let mut conn = queue.connection();
                for ip in &config.target_ips {
                    if !state.hosts.iter().any(|h| h.ip == *ip) {
                        let placeholder = ares_core::models::Host {
                            ip: ip.clone(),
                            hostname: String::new(),
                            os: String::new(),
                            roles: vec![],
                            services: vec![],
                            is_dc: false,
                            owned: false,
                        };
                        let data = serde_json::to_string(&placeholder).unwrap_or_default();
                        let _: Result<(), _> =
                            redis::AsyncCommands::rpush(&mut conn, &host_key, &data).await;
                        state.hosts.push(placeholder);
                    }
                }
                let _: Result<(), _> =
                    redis::AsyncCommands::expire(&mut conn, &host_key, 86400i64).await;
                info!(
                    count = config.target_ips.len(),
                    "Seeded placeholder hosts for all target IPs"
                );
            }
        }
    }

    // --- Inject initial credential (if provided) ---
    if let Some(ref cred) = config.initial_credential {
        let credential = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: cred.username.clone(),
            password: cred.password.clone(),
            domain: cred.domain.clone(),
            source: "initial".to_string(),
            discovered_at: Some(chrono::Utc::now()),
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        match shared_state.publish_credential(&queue, credential).await {
            Ok(true) => info!(
                username = %cred.username,
                domain = %cred.domain,
                "Seeded initial credential"
            ),
            Ok(false) => info!("Initial credential already exists (dedup)"),
            Err(e) => warn!("Failed to seed initial credential: {e}"),
        }
    }

    // Write operation metadata to Redis so workers can discover us
    bootstrap_meta(&queue, &config).await?;

    let tracker = ActiveTaskTracker::new();
    let registry = AgentRegistry::new();
    let throttler = Arc::new(Throttler::new(config.clone(), tracker.clone()));
    let deferred = Arc::new(DeferredQueue::new(queue.clone(), config.clone()));

    // --- LLM provider ---
    // Priority: ARES_LLM_MODEL env var > config YAML agents.orchestrator.model
    let model_spec = std::env::var("ARES_LLM_MODEL").ok().or_else(|| {
        let config_path = std::env::var("ARES_CONFIG")
            .unwrap_or_else(|_| "/ares/config/multi-agent-production.yaml".to_string());
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|content| {
                let yaml: serde_yaml::Value = serde_yaml::from_str(&content).ok()?;
                let model = yaml["agents"]["orchestrator"]["model"].as_str()?;
                // Prefix with "openai/" if no provider prefix present
                let spec = if model.contains('/') {
                    model.to_string()
                } else {
                    format!("openai/{model}")
                };
                info!(config = %config_path, model = %spec, "Model loaded from config YAML");
                Some(spec)
            })
    }).context("No LLM model configured — set ARES_LLM_MODEL or agents.orchestrator.model in config YAML")?;
    let (provider, model_name) =
        ares_llm::create_provider(&model_spec).context("Failed to create LLM provider")?;

    // Choose tool dispatch strategy:
    // ARES_TOOL_DISPATCH=local → in-process via ares_tools::dispatch()
    // default → Redis queue for worker consumption (ares:tool_exec:{role})
    let tool_disp: Arc<dyn ares_llm::ToolDispatcher> =
        if std::env::var("ARES_TOOL_DISPATCH").as_deref() == Ok("local") {
            info!("Tool dispatch: local (in-process via ares-tools)");
            Arc::new(tool_dispatcher::LocalToolDispatcher::new())
        } else {
            info!("Tool dispatch: Redis queue (ares:tool_exec:{{role}})");
            Arc::new(tool_dispatcher::RedisToolDispatcher::new(
                queue.clone(),
                config.operation_id.clone(),
            ))
        };

    let llm_runner = Arc::new(llm_runner::LlmTaskRunner::new(
        provider,
        model_name.clone(),
        tool_disp,
        shared_state.clone(),
    ));
    info!(
        model = %model_name,
        "LLM runner initialized — Rust drives all agent loops"
    );

    // --- Central dispatcher ---
    let dispatcher = Arc::new(Dispatcher::new(
        queue.clone(),
        tracker.clone(),
        throttler.clone(),
        deferred.clone(),
        shared_state.clone(),
        config.clone(),
        ares_config.clone(),
        llm_runner.clone(),
    ));

    // --- Wire orchestrator callback handler ---
    // Deferred initialization: the handler needs the dispatcher, which contains
    // the llm_runner, creating a circular dependency. OnceLock breaks the cycle.
    let callback_handler = Arc::new(
        callback_handler::OrchestratorCallbackHandler::new(shared_state.clone(), queue.clone())
            .with_dispatcher(dispatcher.clone()),
    );
    llm_runner.set_callback_handler(callback_handler);
    info!("Orchestrator callback handler wired (query + dispatch tools)");

    // --- Shutdown signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Spawn background tasks ---

    // Core infrastructure — lock keeper runs independently to prevent
    // lock expiry even if heartbeat sweeps or Redis calls hang.
    let lock_handle = spawn_lock_keeper(queue.clone(), config.clone(), shutdown_rx.clone());

    let hb_handle = spawn_heartbeat_monitor(
        queue.clone(),
        registry.clone(),
        tracker.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let (_result_handle, mut result_rx) = spawn_result_consumer(
        queue.clone(),
        tracker.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let deferred_handle = deferred::spawn_deferred_processor(
        deferred.clone(),
        queue.clone(),
        tracker.clone(),
        throttler.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let cost_handle = spawn_cost_summary(queue.clone(), config.clone(), shutdown_rx.clone());

    // Exploitation workflow
    let exploit_disp = dispatcher.clone();
    let exploit_shutdown = shutdown_rx.clone();
    let exploit_handle = tokio::spawn(async move {
        exploitation::exploitation_workflow(exploit_disp, exploit_shutdown).await
    });

    // Discovery poller
    let disc_disp = dispatcher.clone();
    let disc_shutdown = shutdown_rx.clone();
    let disc_handle =
        tokio::spawn(
            async move { result_processing::discovery_poller(disc_disp, disc_shutdown).await },
        );

    // State refresh
    let refresh_disp = dispatcher.clone();
    let refresh_shutdown = shutdown_rx.clone();
    let refresh_handle =
        tokio::spawn(
            async move { automation::state_refresh(refresh_disp, refresh_shutdown).await },
        );

    // --- Automation tasks ---
    let auto_handles = spawn_automation_tasks(dispatcher.clone(), shutdown_rx.clone());

    // --- Blue team orchestrator (optional — enabled when ARES_BLUE_ENABLED=1) ---
    let blue_handle = if std::env::var("ARES_BLUE_ENABLED").as_deref() == Ok("1") {
        // Create a separate LLM provider for the blue team
        let blue_model_spec =
            std::env::var("ARES_BLUE_LLM_MODEL").unwrap_or_else(|_| model_spec.clone());
        let (blue_provider, blue_model) = ares_llm::create_provider(&blue_model_spec)
            .context("Failed to create blue team LLM provider")?;

        let blue_disp: Arc<dyn ares_llm::ToolDispatcher> =
            if std::env::var("ARES_TOOL_DISPATCH").as_deref() == Ok("local") {
                Arc::new(tool_dispatcher::LocalToolDispatcher::new())
            } else {
                Arc::new(tool_dispatcher::RedisToolDispatcher::new(
                    queue.clone(),
                    config.operation_id.clone(),
                ))
            };

        info!(model = %blue_model, "Starting blue team orchestrator");
        Some(blue::spawn_blue_orchestrator(
            blue_provider,
            blue_model,
            blue_disp,
            config.redis_url.clone(),
            shutdown_rx.clone(),
        ))
    } else {
        None
    };

    // --- Recovery check ---
    {
        let recovery_mgr = recovery::OperationRecoveryManager::new(config.redis_url.clone());
        match recovery_mgr.recover(&config.operation_id).await {
            Ok(recovered) => {
                if !recovered.requeued_task_ids.is_empty() || !recovered.failed_task_ids.is_empty()
                {
                    info!(
                        requeued = recovered.requeued_task_ids.len(),
                        failed = recovered.failed_task_ids.len(),
                        "Recovery: re-enqueued interrupted tasks"
                    );
                }
            }
            Err(e) => {
                // Recovery failure is non-fatal — we already loaded state above
                warn!(err = %e, "Recovery check failed (non-fatal, continuing)");
            }
        }
    }

    // --- Completion monitor ---
    let completion_disp = dispatcher.clone();
    let completion_state = shared_state.clone();
    let completion_shutdown = shutdown_rx.clone();
    let completion_handle = tokio::spawn(async move {
        completion::wait_for_completion(
            &completion_state,
            &completion_disp,
            completion_shutdown,
            std::time::Duration::from_secs(7200),
            std::time::Duration::from_secs(10),
        )
        .await;
        info!("Completion monitor finished — operation complete");
    });

    info!(
        operation_id = %config.operation_id,
        automation_tasks = auto_handles.len(),
        "Orchestration loop started — all background tasks running"
    );

    // --- Pre-flight tool availability check ---
    // Wait briefly for workers to start and publish their tool inventories,
    // then warn loudly about any critical missing tools.
    {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let missing = preflight_tool_check(&mut queue.connection()).await;
        if !missing.is_empty() {
            for (role, tools) in &missing {
                warn!(
                    role = %role,
                    missing = ?tools,
                    "PREFLIGHT: worker is missing critical tools — operations will be degraded"
                );
            }
        } else {
            info!("Preflight tool check passed — all critical tools available");
        }
    }

    // --- Dispatch initial reconnaissance (seeds the reactive automation pipeline) ---
    if !config.target_ips.is_empty() {
        let recon_count = dispatch_initial_recon(&dispatcher, &config).await;
        info!(tasks = recon_count, "Initial recon dispatched");
    } else {
        warn!("No target IPs configured — skipping initial recon dispatch");
    }

    // --- Main loop ---
    loop {
        tokio::select! {
            // Process completed task results
            result = result_rx.recv() => {
                match result {
                    Some(completed) => {
                        result_processing::process_completed_task(
                            &completed,
                            &dispatcher,
                            &throttler,
                        ).await;
                    }
                    None => {
                        // Result consumer died — channel closed.
                        // Respawn it after a brief delay.
                        error!("Result consumer channel closed unexpectedly — restarting consumer");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let (_new_handle, new_rx) = spawn_result_consumer(
                            queue.clone(),
                            tracker.clone(),
                            config.clone(),
                            shutdown_rx.clone(),
                        );
                        result_rx = new_rx;
                    }
                }
            }

            // Graceful shutdown on SIGTERM / SIGINT
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    // --- Graceful shutdown ---
    info!("Shutting down background tasks...");
    let _ = shutdown_tx.send(true);

    let shutdown_timeout = std::time::Duration::from_secs(10);
    tokio::select! {
        _ = async {
            let _ = tokio::join!(
                lock_handle,
                hb_handle,
                deferred_handle,
                cost_handle,
                exploit_handle,
                disc_handle,
                refresh_handle,
                completion_handle,
            );
            for h in auto_handles {
                let _ = h.await;
            }
            if let Some(h) = blue_handle {
                let _ = h.await;
            }
        } => {
            info!("All background tasks stopped");
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("Background task shutdown timed out");
        }
    }

    // --- Finalize operation in Redis ---
    // Write completion metadata, status key, clear lock and active pointer.
    // Matches Python's operation completion sequence.
    {
        let mut conn = queue.connection();
        let has_da = shared_state.read().await.has_domain_admin;
        let status = if has_da { "completed" } else { "stopped" };
        match ares_core::state::finalize_operation(&mut conn, &config.operation_id, status).await {
            Ok(()) => info!(
                operation_id = %config.operation_id,
                status = status,
                "Operation finalized in Redis"
            ),
            Err(e) => warn!(
                operation_id = %config.operation_id,
                err = %e,
                "Failed to finalize operation in Redis"
            ),
        }
    }

    info!("ares-orchestrator stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Pre-flight tool check
// ---------------------------------------------------------------------------

/// Critical tools per worker role. If any of these are missing, operations
/// will be severely degraded.
const CRITICAL_TOOLS: &[(&str, &[&str])] = &[
    ("recon", &["nmap", "netexec"]),
    (
        "credential_access",
        &[
            "impacket-GetUserSPNs",
            "impacket-GetNPUsers",
            "impacket-secretsdump",
        ],
    ),
    ("privesc", &["impacket-findDelegation", "impacket-getST"]),
    (
        "lateral",
        &[
            "impacket-psexec",
            "impacket-smbexec",
            "impacket-secretsdump",
        ],
    ),
];

/// Query Redis for each worker's tool inventory and report any missing
/// critical tools. Returns a list of (role, missing_tools) pairs.
async fn preflight_tool_check(
    conn: &mut redis::aio::ConnectionManager,
) -> Vec<(String, Vec<String>)> {
    use redis::AsyncCommands;

    let mut problems = Vec::new();

    for &(role, critical) in CRITICAL_TOOLS {
        let agent_key = format!("ares:tools:ares-{role}-agent");
        let available: Vec<String> = match conn.get::<_, Option<String>>(&agent_key).await {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
            _ => {
                // No inventory published yet — worker may not have started
                warn!(
                    role = role,
                    "No tool inventory found — worker may not be running"
                );
                problems.push((
                    role.to_string(),
                    critical.iter().map(|s| s.to_string()).collect(),
                ));
                continue;
            }
        };

        let missing: Vec<String> = critical
            .iter()
            .filter(|&&tool| !available.iter().any(|a| a == tool))
            .map(|s| s.to_string())
            .collect();

        if !missing.is_empty() {
            problems.push((role.to_string(), missing));
        }
    }

    problems
}
