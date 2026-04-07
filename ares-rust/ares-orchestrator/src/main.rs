// Orchestrator is scaffolded; most public APIs are not yet wired up.
#![allow(dead_code)]

//! Ares Orchestrator — Rust-native orchestration loop.
//!
//! Entry point for the `ares-orchestrator` binary. Rust owns the tokio event
//! loop and all Redis IO; Python (via PyO3) is called only for LLM agent
//! steps when the `python` feature is enabled.
//!
//! Startup sequence:
//!   1. Load config from env vars
//!   2. Connect to Redis
//!   3. Acquire the operation lock
//!   4. Initialize the Python bridge (if enabled)
//!   5. Spawn background tasks: heartbeat monitor, result consumer, deferred processor
//!   6. Enter the main orchestration loop

mod config;
mod cost_summary;
mod deferred;
mod monitoring;
mod python_bridge;
mod results;
mod routing;
mod task_queue;
mod throttling;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::signal;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::OrchestratorConfig;
use crate::cost_summary::spawn_cost_summary;
use crate::deferred::DeferredQueue;
use crate::monitoring::{spawn_heartbeat_monitor, AgentRegistry};
use crate::results::{spawn_result_consumer, CompletedTask};
use crate::routing::{ActiveTaskTracker, TaskRouter};
use crate::task_queue::TaskQueue;
use crate::throttling::Throttler;

#[tokio::main]
async fn main() -> Result<()> {
    // --- Tracing ---
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

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
        // Another orchestrator already holds the lock
        anyhow::bail!(
            "Operation {} is locked by another orchestrator",
            config.operation_id
        );
    }

    // --- Python bridge ---
    let bridge = python_bridge::create_bridge();
    bridge
        .initialize()
        .context("Failed to initialize Python bridge")?;
    info!("Python bridge ready");

    // --- Shared state ---
    let tracker = ActiveTaskTracker::new();
    let registry = AgentRegistry::new();
    let throttler = Arc::new(Throttler::new(config.clone(), tracker.clone()));
    let _router = TaskRouter::new(queue.clone(), tracker.clone(), config.clone());
    let deferred = Arc::new(DeferredQueue::new(queue.clone(), config.clone()));

    // --- Shutdown signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Spawn background tasks ---
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

    info!(
        operation_id = %config.operation_id,
        "Orchestration loop started — waiting for tasks and results"
    );

    // --- Main loop ---
    // In the full implementation this loop will:
    //   1. Receive completed results via result_rx
    //   2. Process results (extract credentials, hosts, vulns)
    //   3. Generate follow-up tasks by calling the Python agent bridge
    //   4. Submit new tasks through the router with throttling
    //
    // For now it handles results and graceful shutdown.
    loop {
        tokio::select! {
            // Process completed task results
            Some(completed) = result_rx.recv() => {
                handle_completed_task(&completed, &throttler).await;
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

    // Wait for background tasks (with timeout)
    let shutdown_timeout = std::time::Duration::from_secs(10);
    tokio::select! {
        _ = async {
            let _ = tokio::join!(hb_handle, result_handle, deferred_handle, cost_handle);
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

/// Process a completed task result.
async fn handle_completed_task(completed: &CompletedTask, throttler: &Throttler) {
    let task_id = &completed.task_id;
    let result = &completed.result;

    if result.success {
        info!(
            task_id = %task_id,
            agent = result.agent_name.as_deref().unwrap_or("unknown"),
            "Task completed successfully"
        );
        throttler.clear_rate_limit_error().await;
    } else {
        let err_msg = result.error.as_deref().unwrap_or("unknown error");
        warn!(task_id = %task_id, err = err_msg, "Task failed");

        // Check for rate-limit errors in the failure message
        if err_msg.to_lowercase().contains("rate limit") || err_msg.to_lowercase().contains("429") {
            throttler.record_rate_limit_error().await;
        }
    }

    // TODO: In the full implementation, this will:
    // 1. Parse the result payload for discovered credentials, hosts, vulns
    // 2. Update shared state in Redis
    // 3. Generate follow-up tasks based on new intelligence
    // 4. Call Python bridge for LLM-driven task generation
}
