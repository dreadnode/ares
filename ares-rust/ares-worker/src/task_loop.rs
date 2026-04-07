//! Core task consumption loop.
//!
//! Mirrors the Python `RedisWorkerAgent._worker_loop()` and `_process_task()`:
//!
//! ```text
//! loop {
//!     1. BRPOP from ares:tasks:{role}
//!     2. Deserialize TaskMessage
//!     3. Update task status to "running"
//!     4. Call into Python for LLM agent step (PyO3)
//!     5. Parse result
//!     6. Serialize TaskResult
//!     7. LPUSH to ares:results:{task_id}
//!     8. Update task status to "completed" or "failed"
//!     9. Refresh heartbeat status
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use ares_core::token_usage;

use crate::config::WorkerConfig;
use crate::heartbeat::WorkerStatus;
use crate::python_bridge;

// ─── Redis key prefixes (must match Python's RedisTaskQueue) ─────────────────

const TASK_QUEUE_PREFIX: &str = "ares:tasks";
const RESULT_QUEUE_PREFIX: &str = "ares:results";
const TASK_STATUS_PREFIX: &str = "ares:task_status";

/// TTL for task status keys — 24 hours, matches Python.
const TASK_STATUS_TTL: i64 = 60 * 60 * 24;

/// TTL for result keys — 24 hours, matches Python's `RESULT_TTL`.
const RESULT_TTL: i64 = 60 * 60 * 24;

// ─── Wire types (match Python's Pydantic models exactly) ─────────────────────

/// Task message from the queue. Matches `TaskMessage` in `task_queue.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMessage {
    pub task_id: String,
    pub task_type: String,
    pub source_agent: String,
    pub target_agent: String,
    pub payload: serde_json::Value,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub created_at: Option<String>,
    pub callback_queue: Option<String>,
}

fn default_priority() -> i32 {
    5
}

/// Task result pushed back to orchestrator. Matches `TaskResult` in `task_queue.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

impl TaskResult {
    fn success(task_id: &str, result: serde_json::Value, pod_name: &str, agent_name: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            success: true,
            result: Some(result),
            error: None,
            completed_at: Some(Utc::now().to_rfc3339()),
            worker_pod: Some(pod_name.to_string()),
            agent_name: Some(agent_name.to_string()),
        }
    }

    fn failure(
        task_id: &str,
        error: String,
        result: Option<serde_json::Value>,
        pod_name: &str,
        agent_name: &str,
    ) -> Self {
        Self {
            task_id: task_id.to_string(),
            success: false,
            result,
            error: Some(error),
            completed_at: Some(Utc::now().to_rfc3339()),
            worker_pod: Some(pod_name.to_string()),
            agent_name: Some(agent_name.to_string()),
        }
    }
}

// ─── Task loop ───────────────────────────────────────────────────────────────

/// Run the main task consumption loop until shutdown is signalled.
pub async fn run_task_loop(
    config: &WorkerConfig,
    status_tx: watch::Sender<WorkerStatus>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let queue_key = format!("{TASK_QUEUE_PREFIX}:{}", config.worker_role);
    info!(
        queue = %queue_key,
        agent = %config.agent_name,
        "Starting task loop"
    );

    let mut conn = connect_redis(&config.redis_url).await?;

    // Exponential backoff state for connection errors
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);

    loop {
        // Check for shutdown
        if is_shutdown_signalled(&shutdown) {
            info!("Task loop: shutdown signalled, finishing");
            break;
        }

        match poll_task(&mut conn, &queue_key, config.poll_timeout).await {
            Ok(Some(task)) => {
                // Reset backoff on successful poll
                retry_delay = Duration::from_secs(1);

                // Update heartbeat status to busy
                let _ = status_tx.send(WorkerStatus {
                    status: "busy".to_string(),
                    current_task: Some(task.task_id.clone()),
                });

                process_task(&mut conn, config, &task).await;

                // Update heartbeat status back to idle
                let _ = status_tx.send(WorkerStatus {
                    status: "idle".to_string(),
                    current_task: None,
                });
            }
            Ok(None) => {
                // No task available (BRPOP timeout), just loop
                retry_delay = Duration::from_secs(1);
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                let is_conn_error = [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
                .iter()
                .any(|kw| error_str.contains(kw));

                if is_conn_error {
                    warn!(
                        delay_secs = retry_delay.as_secs(),
                        "Task loop: connection error, retrying: {e}"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = shutdown.notified() => break,
                    }
                    retry_delay = (retry_delay * 2).min(max_retry_delay);

                    // Try to reconnect
                    match connect_redis(&config.redis_url).await {
                        Ok(new_conn) => {
                            conn = new_conn;
                            debug!("Task loop: reconnected to Redis");
                        }
                        Err(re) => {
                            error!("Task loop: reconnect failed: {re}");
                        }
                    }
                } else {
                    error!("Task loop: non-connection error: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    retry_delay = Duration::from_secs(1);
                }
            }
        }
    }

    Ok(())
}

/// BRPOP from the task queue with timeout.
/// Returns `Ok(None)` on timeout (no task available).
async fn poll_task(
    conn: &mut redis::aio::MultiplexedConnection,
    queue_key: &str,
    timeout: Duration,
) -> anyhow::Result<Option<TaskMessage>> {
    // BRPOP returns Option<(key, value)>
    let result: Option<(String, String)> = redis::cmd("BRPOP")
        .arg(queue_key)
        .arg(timeout.as_secs() as i64)
        .query_async(conn)
        .await?;

    match result {
        Some((_key, data)) => {
            let task: TaskMessage = serde_json::from_str(&data)?;
            debug!(task_id = %task.task_id, task_type = %task.task_type, "Received task");
            Ok(Some(task))
        }
        None => Ok(None),
    }
}

/// Process a single task: set status, run Python agent, push result.
async fn process_task(
    conn: &mut redis::aio::MultiplexedConnection,
    config: &WorkerConfig,
    task: &TaskMessage,
) {
    let started_at = Utc::now().to_rfc3339();

    info!(
        task_id = %task.task_id,
        task_type = %task.task_type,
        agent = %config.agent_name,
        "Processing task"
    );

    // 1. Set task status to "running"
    if let Err(e) = set_task_status(
        conn,
        &task.task_id,
        "running",
        &serde_json::json!({
            "operation_id": config.operation_id,
            "role": config.worker_role,
            "agent_name": config.agent_name,
            "pod_name": config.pod_name,
            "task_type": task.task_type,
            "payload": task.payload,
            "started_at": started_at,
        }),
    )
    .await
    {
        warn!(task_id = %task.task_id, "Failed to set task status to running: {e}");
    }

    // 2. Run the Python agent
    let agent_result =
        python_bridge::run_agent_task(&task.task_type, &task.payload, config.task_timeout).await;

    // 3. Extract token usage before consuming agent_result (for Redis tracking)
    let usage_for_tracking = agent_result.as_ref().ok().and_then(|ar| ar.usage.clone());

    // 4. Build the result
    let (task_result, final_status) = match agent_result {
        Ok(ar) => {
            if let Some(ref err) = ar.error {
                // Agent returned an error (e.g., unsupported task, max steps, model refusal)
                let result_payload = serde_json::json!({
                    "output": ar.output,
                    "task_type": task.task_type,
                });
                (
                    TaskResult::failure(
                        &task.task_id,
                        err.clone(),
                        Some(result_payload),
                        &config.pod_name,
                        &config.agent_name,
                    ),
                    "failed",
                )
            } else {
                let mut result_payload = serde_json::json!({
                    "output": ar.output,
                    "task_type": task.task_type,
                });
                // Include usage metrics if available
                if let Some(ref usage) = ar.usage {
                    result_payload["usage"] = serde_json::to_value(usage).unwrap_or_default();
                }
                (
                    TaskResult::success(
                        &task.task_id,
                        result_payload,
                        &config.pod_name,
                        &config.agent_name,
                    ),
                    "completed",
                )
            }
        }
        Err(e) => {
            let error_msg = format!("{e}");
            error!(
                task_id = %task.task_id,
                "Agent task failed: {error_msg}"
            );
            (
                TaskResult::failure(
                    &task.task_id,
                    error_msg,
                    None,
                    &config.pod_name,
                    &config.agent_name,
                ),
                "failed",
            )
        }
    };

    // 5. Accumulate token usage to Redis (best-effort, never fails the task)
    if let Some(ref usage) = usage_for_tracking {
        if usage.total_tokens > 0 {
            if let Some(ref op_id) = config.operation_id {
                let model = usage.model.as_deref().unwrap_or("");
                if let Err(e) = token_usage::increment_token_usage(
                    conn,
                    op_id,
                    usage.input_tokens,
                    usage.output_tokens,
                    model,
                )
                .await
                {
                    debug!(task_id = %task.task_id, "Failed to increment token usage: {e}");
                }
            }
        }
    }

    // 6. LPUSH result to ares:results:{task_id}
    let result_key = format!("{RESULT_QUEUE_PREFIX}:{}", task.task_id);
    match serde_json::to_string(&task_result) {
        Ok(result_json) => {
            if let Err(e) = push_result(conn, &result_key, &result_json).await {
                error!(task_id = %task.task_id, "Failed to push result: {e}");
            }
        }
        Err(e) => {
            error!(task_id = %task.task_id, "Failed to serialize result: {e}");
        }
    }

    // 7. Update task status to final state
    if let Err(e) = set_task_status(
        conn,
        &task.task_id,
        final_status,
        &serde_json::json!({
            "operation_id": config.operation_id,
            "role": config.worker_role,
            "agent_name": config.agent_name,
            "pod_name": config.pod_name,
            "task_type": task.task_type,
            "ended_at": Utc::now().to_rfc3339(),
        }),
    )
    .await
    {
        warn!(task_id = %task.task_id, "Failed to set task status to {final_status}: {e}");
    }

    match final_status {
        "completed" => info!(task_id = %task.task_id, "Task completed"),
        _ => warn!(task_id = %task.task_id, "Task failed"),
    }
}

/// Push a result to the result queue and set TTL.
async fn push_result(
    conn: &mut redis::aio::MultiplexedConnection,
    result_key: &str,
    result_json: &str,
) -> anyhow::Result<()> {
    conn.lpush::<_, _, ()>(result_key, result_json).await?;
    conn.expire::<_, ()>(result_key, RESULT_TTL).await?;
    Ok(())
}

/// Set task status in Redis with TTL.
/// Matches Python's `set_task_status` — writes JSON to `ares:task_status:{task_id}`.
async fn set_task_status(
    conn: &mut redis::aio::MultiplexedConnection,
    task_id: &str,
    status: &str,
    extra_fields: &serde_json::Value,
) -> anyhow::Result<()> {
    let key = format!("{TASK_STATUS_PREFIX}:{task_id}");
    let mut data = extra_fields.clone();
    if let Some(obj) = data.as_object_mut() {
        obj.insert(
            "status".to_string(),
            serde_json::Value::String(status.to_string()),
        );
        obj.insert(
            "updated_at".to_string(),
            serde_json::Value::String(Utc::now().to_rfc3339()),
        );
    }
    let json_str = serde_json::to_string(&data)?;
    conn.set_ex::<_, _, ()>(&key, &json_str, TASK_STATUS_TTL as u64)
        .await?;
    Ok(())
}

/// Open a Redis connection.
async fn connect_redis(url: &str) -> anyhow::Result<redis::aio::MultiplexedConnection> {
    let client = redis::Client::open(url)?;
    let conn = client.get_multiplexed_async_connection().await?;
    Ok(conn)
}

/// Non-blocking check if shutdown has been signalled.
/// Uses `Notify` — we peek by trying `notified()` with zero timeout.
fn is_shutdown_signalled(_shutdown: &Arc<tokio::sync::Notify>) -> bool {
    // Notify doesn't have a try_recv. We rely on the tokio::select! in the
    // connection-error branch and the BRPOP timeout to periodically give us
    // a chance to check. For a clean shutdown on SIGTERM, the main function
    // drops the task or aborts it.
    false
}
