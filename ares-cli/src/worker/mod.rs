//! Ares Worker — task consumption loop.
//!
//! 1. BLPOP from Redis queue (`ares:tasks:{role}`)
//! 2. Execute agent tasks (native Rust tool execution)
//! 3. Push results back (`ares:results:{task_id}`)

#[cfg(feature = "blue")]
mod blue_task_loop;
mod config;
pub mod credential_resolver;
mod heartbeat;
mod hosts;
mod task_loop;
mod tool_check;
mod tool_executor;

use std::sync::Arc;

use tracing::{error, info};

pub async fn run() -> anyhow::Result<()> {
    // Parse config from environment FIRST so we can derive the service name
    let config = config::WorkerConfig::from_env()?;

    // Derive telemetry service name from worker config instead of hardcoding
    let service_name = match config.mode {
        #[cfg(feature = "blue")]
        config::WorkerMode::BlueTask => {
            format!("ares-blue-{}", config.worker_role.replace('_', "-"))
        }
        _ => config.agent_name.clone(),
    };

    // Initialize telemetry (console + OTLP when endpoint is configured)
    let _telemetry = ares_core::telemetry::init_telemetry(
        ares_core::telemetry::TelemetryConfig::new(&service_name),
    );
    let mode_str = match config.mode {
        config::WorkerMode::Task => "task",
        config::WorkerMode::ToolExec => "tool_exec",
        #[cfg(feature = "blue")]
        config::WorkerMode::BlueTask => "blue_task",
    };
    info!(
        agent = %config.agent_name,
        role = %config.worker_role,
        mode = mode_str,
        pod = %config.pod_name,
        operation_id = ?config.operation_id,
        task_timeout_secs = config.task_timeout.as_secs(),
        "Ares worker starting"
    );

    // Single shared Redis connection (state only — heartbeats, task status,
    // token usage, hosts sync). Queue traffic moved to NATS JetStream.
    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let cm_config = redis::aio::ConnectionManagerConfig::new()
        .set_response_timeout(Some(std::time::Duration::from_secs(30)));
    let conn = redis_client
        .get_connection_manager_with_config(cm_config)
        .await?;

    // Single shared NATS connection — multiplexes work-queue pulls, result
    // publishes, and tool-exec request/reply over one TCP connection.
    let nats = ares_core::nats::NatsBroker::connect(&config.nats_url).await?;

    // Shared shutdown signal
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_signal = Arc::clone(&shutdown);

    // Spawn background heartbeat
    let (_heartbeat_handle, status_tx) = heartbeat::spawn_heartbeat(
        conn.clone(),
        heartbeat::HeartbeatConfig {
            agent_name: config.agent_name.clone(),
            pod_name: config.pod_name.clone(),
            role: config.worker_role.clone(),
            operation_id: config.operation_id.clone(),
            interval: config.heartbeat_interval,
            ttl: config.heartbeat_ttl,
        },
        Arc::clone(&shutdown),
    );

    // Check tool availability for this role and publish inventory
    let inventory = tool_check::check_tools(&config.worker_role).await;
    tool_check::publish_inventory(&mut conn.clone(), &config.agent_name, &inventory).await;

    // Spawn /etc/hosts sync if we have an operation ID
    let _hosts_handle = config.operation_id.as_ref().map(|op_id| {
        hosts::spawn_hosts_sync(
            conn.clone(),
            op_id.clone(),
            config.agent_name.clone(),
            Arc::clone(&shutdown),
        )
    });

    // Spawn SIGTERM/SIGINT handler
    let shutdown_for_signal = Arc::clone(&shutdown_signal);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        info!("Shutdown signal received, draining...");
        shutdown_for_signal.notify_waiters();
    });

    // Run the appropriate loop based on worker mode
    let result = match config.mode {
        config::WorkerMode::Task => {
            task_loop::run_task_loop(&config, conn, nats.clone(), status_tx, shutdown_signal).await
        }
        config::WorkerMode::ToolExec => {
            tool_executor::run_tool_exec_loop(
                &config,
                conn,
                nats.clone(),
                status_tx,
                shutdown_signal,
            )
            .await
        }
        #[cfg(feature = "blue")]
        config::WorkerMode::BlueTask => {
            // Blue team mode requires an LLM provider
            let model_spec = std::env::var("ARES_LLM_MODEL")
                .unwrap_or_else(|_| "anthropic/claude-sonnet-4-20250514".to_string());
            let (provider, model_name) = match ares_llm::create_provider(&model_spec) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to create LLM provider for blue worker: {e}");
                    return Err(e);
                }
            };
            let dispatcher = std::sync::Arc::new(blue_task_loop::BlueLocalToolDispatcher::new());
            info!(model = %model_name, "Blue team worker using LLM");
            blue_task_loop::run_blue_task_loop(blue_task_loop::BlueTaskLoopDeps {
                config: &config,
                conn,
                nats: nats.clone(),
                provider,
                dispatcher,
                model_name,
                status_tx,
                shutdown: shutdown_signal,
            })
            .await
        }
    };

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
