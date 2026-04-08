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
mod completion;
mod config;
mod cost_summary;
mod deferred;
mod dispatcher;
mod exploitation;
mod llm_runner;
mod monitoring;
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
use tracing::{info, warn};

use crate::config::OrchestratorConfig;
use crate::cost_summary::spawn_cost_summary;
use crate::deferred::DeferredQueue;
use crate::dispatcher::Dispatcher;
use crate::monitoring::{spawn_heartbeat_monitor, AgentRegistry};
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
    info!(
        operation_id = %config.operation_id,
        max_concurrent = config.max_concurrent_tasks,
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

    let tracker = ActiveTaskTracker::new();
    let registry = AgentRegistry::new();
    let throttler = Arc::new(Throttler::new(config.clone(), tracker.clone()));
    let deferred = Arc::new(DeferredQueue::new(queue.clone(), config.clone()));

    // --- Central dispatcher ---
    let mut dispatcher = Dispatcher::new(
        queue.clone(),
        tracker.clone(),
        throttler.clone(),
        deferred.clone(),
        shared_state.clone(),
        config.clone(),
    );

    // --- LLM runner (optional — enabled when ARES_LLM_MODEL is set) ---
    if let Ok(model_spec) = std::env::var("ARES_LLM_MODEL") {
        match ares_llm::create_provider(&model_spec) {
            Ok((provider, model_name)) => {
                let tool_disp = Arc::new(tool_dispatcher::RedisToolDispatcher::new(queue.clone()));
                let runner = Arc::new(llm_runner::LlmTaskRunner::new(
                    provider,
                    model_name.clone(),
                    tool_disp,
                    shared_state.clone(),
                ));
                dispatcher = dispatcher.with_llm_runner(runner);
                info!(
                    model = %model_name,
                    "LLM runner initialized — Rust will drive agent loops"
                );
            }
            Err(e) => {
                warn!(
                    model = %model_spec,
                    err = %e,
                    "Failed to create LLM provider — tasks will be pushed to Redis queue for workers"
                );
            }
        }
    } else {
        info!("ARES_LLM_MODEL not set — tasks will be pushed to Redis queue for workers");
    }

    let dispatcher = Arc::new(dispatcher);

    // --- Shutdown signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Spawn background tasks ---

    // Core infrastructure
    let hb_handle = spawn_heartbeat_monitor(
        queue.clone(),
        registry.clone(),
        tracker.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let (result_handle, mut result_rx) = spawn_result_consumer(
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

    // --- Main loop ---
    loop {
        tokio::select! {
            // Process completed task results
            Some(completed) = result_rx.recv() => {
                result_processing::process_completed_task(
                    &completed,
                    &dispatcher,
                    &throttler,
                ).await;
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
                hb_handle,
                result_handle,
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
        } => {
            info!("All background tasks stopped");
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("Background task shutdown timed out");
        }
    }

    info!("ares-orchestrator stopped");
    Ok(())
}

/// Spawn all automation background tasks. Returns their JoinHandles.
fn spawn_automation_tasks(
    dispatcher: Arc<Dispatcher>,
    shutdown_rx: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    macro_rules! spawn_auto {
        ($name:ident) => {{
            let d = dispatcher.clone();
            let s = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                automation::$name(d, s).await;
            }));
        }};
    }

    spawn_auto!(auto_crack_dispatch);
    spawn_auto!(auto_mssql_detection);
    spawn_auto!(auto_adcs_enumeration);
    spawn_auto!(auto_share_spider);
    spawn_auto!(auto_bloodhound);
    spawn_auto!(auto_delegation_enumeration);
    spawn_auto!(auto_coercion);
    spawn_auto!(auto_local_admin_secretsdump);
    spawn_auto!(auto_credential_access);
    spawn_auto!(auto_credential_expansion);
    spawn_auto!(auto_golden_ticket);
    spawn_auto!(auto_acl_chain_follow);

    info!(count = handles.len(), "Automation tasks spawned");
    handles
}
