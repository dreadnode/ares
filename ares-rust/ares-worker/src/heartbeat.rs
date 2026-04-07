//! Background heartbeat task.
//!
//! Spawns a tokio task that periodically writes to `ares:heartbeat:{agent_name}`
//! with a TTL, matching the Python `_threaded_heartbeat_loop` in `_worker.py`.
//!
//! The heartbeat runs independently of the GIL-bound task loop, ensuring the
//! orchestrator always knows the worker is alive even during long Python calls.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use redis::AsyncCommands;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

/// Heartbeat key prefix — matches `RedisTaskQueue.HEARTBEAT_PREFIX` in Python.
const HEARTBEAT_PREFIX: &str = "ares:heartbeat";

/// Current worker status, shared between the task loop and heartbeat task.
#[derive(Debug, Clone)]
pub struct WorkerStatus {
    /// "idle" or "busy"
    pub status: String,
    /// Current task ID if busy, None if idle.
    pub current_task: Option<String>,
}

impl Default for WorkerStatus {
    fn default() -> Self {
        Self {
            status: "idle".to_string(),
            current_task: None,
        }
    }
}

/// Handle to the background heartbeat task. Drop to stop.
pub struct HeartbeatHandle {
    _handle: JoinHandle<()>,
}

/// Spawn the background heartbeat loop.
///
/// Returns a `HeartbeatHandle` (drop it or abort to stop) and a `watch::Sender`
/// the task loop uses to update current status.
#[allow(clippy::too_many_arguments)]
pub fn spawn_heartbeat(
    redis_url: String,
    agent_name: String,
    pod_name: String,
    role: String,
    operation_id: Option<String>,
    interval: Duration,
    ttl: Duration,
    shutdown: Arc<tokio::sync::Notify>,
) -> (HeartbeatHandle, watch::Sender<WorkerStatus>) {
    let (status_tx, status_rx) = watch::channel(WorkerStatus::default());

    let handle = tokio::spawn(heartbeat_loop(
        redis_url,
        agent_name,
        pod_name,
        role,
        operation_id,
        interval,
        ttl,
        status_rx,
        shutdown,
    ));

    (HeartbeatHandle { _handle: handle }, status_tx)
}

#[allow(clippy::too_many_arguments)]
async fn heartbeat_loop(
    redis_url: String,
    agent_name: String,
    pod_name: String,
    role: String,
    operation_id: Option<String>,
    interval: Duration,
    ttl: Duration,
    status_rx: watch::Receiver<WorkerStatus>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    let heartbeat_key = format!("{HEARTBEAT_PREFIX}:{agent_name}");
    let ttl_secs = ttl.as_secs() as i64;

    // Connect to Redis with retry
    let mut conn = loop {
        match connect_redis(&redis_url).await {
            Ok(c) => break c,
            Err(e) => {
                warn!("Heartbeat: failed to connect to Redis, retrying in 5s: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = shutdown.notified() => {
                        debug!("Heartbeat: shutdown before initial connection");
                        return;
                    }
                }
            }
        }
    };

    debug!("Heartbeat: connected, writing to {heartbeat_key} every {interval:?}");

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.notified() => {
                // Send a final "offline" heartbeat before exiting
                let data = build_heartbeat_json("offline", None, &pod_name, &role, &operation_id);
                let _: Result<(), _> = redis::cmd("SET")
                    .arg(&heartbeat_key)
                    .arg(&data)
                    .arg("EX")
                    .arg(ttl_secs)
                    .query_async(&mut conn)
                    .await;
                debug!("Heartbeat: shutdown, sent offline heartbeat");
                return;
            }
        }

        let status = status_rx.borrow().clone();
        let data = build_heartbeat_json(
            &status.status,
            status.current_task.as_deref(),
            &pod_name,
            &role,
            &operation_id,
        );

        match conn
            .set_ex::<_, _, ()>(&heartbeat_key, &data, ttl_secs as u64)
            .await
        {
            Ok(()) => {
                debug!("Heartbeat: {agent_name} -> {}", status.status);
            }
            Err(e) => {
                warn!("Heartbeat: Redis write failed, reconnecting: {e}");
                match connect_redis(&redis_url).await {
                    Ok(new_conn) => conn = new_conn,
                    Err(re) => {
                        error!("Heartbeat: reconnect failed: {re}");
                    }
                }
            }
        }
    }
}

/// Build the heartbeat JSON payload matching Python's `send_heartbeat`.
fn build_heartbeat_json(
    status: &str,
    current_task: Option<&str>,
    pod_name: &str,
    role: &str,
    operation_id: &Option<String>,
) -> String {
    serde_json::json!({
        "status": status,
        "current_task": current_task,
        "pod_name": pod_name,
        "role": role,
        "operation_id": operation_id,
        "timestamp": Utc::now().to_rfc3339(),
    })
    .to_string()
}

/// Open a Redis connection from a URL string.
async fn connect_redis(url: &str) -> Result<redis::aio::MultiplexedConnection, redis::RedisError> {
    let client = redis::Client::open(url)?;
    client.get_multiplexed_async_connection().await
}
