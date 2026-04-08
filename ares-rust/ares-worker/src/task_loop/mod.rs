//! Core task consumption loop.
//!
//! ```text
//! loop {
//!     1. BRPOP from ares:tasks:{role}
//!     2. Deserialize TaskMessage
//!     3. Update task status to "running"
//!     4. Execute agent task (native Rust)
//!     5. Parse result
//!     6. Serialize TaskResult
//!     7. LPUSH to ares:results:{task_id}
//!     8. Update task status to "completed" or "failed"
//!     9. Refresh heartbeat status
//! }
//! ```

mod executor;
mod result_handler;
pub mod types;

use types::TaskMessage;

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::config::WorkerConfig;
use crate::heartbeat::WorkerStatus;

// ─── Redis key prefixes (must match Python's RedisTaskQueue) ─────────────────

const TASK_QUEUE_PREFIX: &str = "ares:tasks";
const RESULT_QUEUE_PREFIX: &str = "ares:results";
const TASK_STATUS_PREFIX: &str = "ares:task_status";

/// TTL for task status keys — 24 hours, matches Python.
const TASK_STATUS_TTL: i64 = 60 * 60 * 24;

/// TTL for result keys — 24 hours, matches Python's `RESULT_TTL`.
const RESULT_TTL: i64 = 60 * 60 * 24;

// ─── Task loop ───────────────────────────────────────────────────────────────

/// Run the main task consumption loop until shutdown is signalled.
pub async fn run_task_loop(
    config: &WorkerConfig,
    status_tx: tokio::sync::watch::Sender<WorkerStatus>,
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

                result_handler::process_task(&mut conn, config, &task).await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use types::TaskResult;

    #[test]
    fn task_message_roundtrip() {
        let msg = TaskMessage {
            task_id: "task-123".into(),
            task_type: "recon".into(),
            source_agent: "orchestrator".into(),
            target_agent: "ares-recon-0".into(),
            payload: serde_json::json!({"target_ip": "192.168.58.1"}),
            priority: 3,
            created_at: Some("2026-04-07T10:00:00Z".into()),
            callback_queue: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: TaskMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg.task_id, msg2.task_id);
        assert_eq!(msg.task_type, msg2.task_type);
        assert_eq!(msg.priority, msg2.priority);
    }

    #[test]
    fn task_message_default_priority() {
        let json = r#"{
            "task_id": "t1",
            "task_type": "recon",
            "source_agent": "orch",
            "target_agent": "recon-0",
            "payload": {}
        }"#;
        let msg: TaskMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.priority, 5); // default
    }

    #[test]
    fn task_result_success() {
        let r = TaskResult::success(
            "t1",
            serde_json::json!({"output": "done"}),
            "pod-0",
            "ares-recon",
        );
        assert!(r.success);
        assert!(r.error.is_none());
        assert!(r.result.is_some());
        assert!(r.completed_at.is_some());
        assert_eq!(r.worker_pod.as_deref(), Some("pod-0"));
    }

    #[test]
    fn task_result_failure() {
        let r = TaskResult::failure("t1", "timeout".into(), None, "pod-0", "ares-recon");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("timeout"));
        assert!(r.result.is_none());
    }

    #[test]
    fn task_result_skip_serializing_none() {
        let r = TaskResult::success("t1", serde_json::json!("ok"), "pod", "agent");
        let json = serde_json::to_string(&r).unwrap();
        // error field should be absent (skip_serializing_if = "Option::is_none")
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn redis_key_prefixes() {
        assert_eq!(TASK_QUEUE_PREFIX, "ares:tasks");
        assert_eq!(RESULT_QUEUE_PREFIX, "ares:results");
        assert_eq!(TASK_STATUS_PREFIX, "ares:task_status");
    }
}
