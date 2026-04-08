//! Ares Worker — the Rust binary that runs on worker pods.
//!
//! Owns the task consumption loop:
//! 1. BLPOP from Redis queue (`ares:tasks:{role}`)
//! 2. Delegate to Python via PyO3 for the actual LLM agent step
//! 3. Push results back (`ares:results:{task_id}`)
//!
//! Single-threaded for LLM calls (GIL makes parallelism pointless for Python).
//! Heartbeat runs on a separate tokio task (no GIL needed).
//! Graceful shutdown: finish current task before exiting on SIGTERM.

mod config;
mod heartbeat;
mod python_bridge;
mod task_loop;

use std::sync::Arc;

use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize telemetry (console + OTLP when endpoint is configured)
    let _telemetry = ares_core::telemetry::init_telemetry(
        ares_core::telemetry::TelemetryConfig::new("ares-worker"),
    );

    // Parse config from environment
    let config = config::WorkerConfig::from_env()?;
    info!(
        agent = %config.agent_name,
        role = %config.worker_role,
        pod = %config.pod_name,
        operation_id = ?config.operation_id,
        task_timeout_secs = config.task_timeout.as_secs(),
        "Ares worker starting"
    );

    // Shared shutdown signal
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_heartbeat = Arc::clone(&shutdown);
    let shutdown_signal = Arc::clone(&shutdown);

    // Spawn background heartbeat
    let (_heartbeat_handle, status_tx) = heartbeat::spawn_heartbeat(
        config.redis_url.clone(),
        config.agent_name.clone(),
        config.pod_name.clone(),
        config.worker_role.clone(),
        config.operation_id.clone(),
        config.heartbeat_interval,
        config.heartbeat_ttl,
        shutdown_heartbeat,
    );

    // Spawn SIGTERM/SIGINT handler
    let shutdown_for_signal = Arc::clone(&shutdown_signal);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!("Shutdown signal received, draining...");
        shutdown_for_signal.notify_waiters();
    });

    // Run the task loop (blocks until shutdown)
    let result = task_loop::run_task_loop(&config, status_tx, shutdown_signal).await;

    match &result {
        Ok(()) => info!("Ares worker shut down cleanly"),
        Err(e) => error!("Ares worker exited with error: {e}"),
    }

    result
}

/// Wait for SIGTERM or SIGINT (Ctrl-C).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");
        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl-C handler");
        info!("Received Ctrl-C");
    }
}
