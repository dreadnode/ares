//! Core task consumption loop (NATS JetStream).
//!
//! ```text
//! loop {
//!     1. Pull batch from urgent + normal subjects on the role queue
//!     2. Deserialize TaskMessage
//!     3. Update task status to "running" (Redis)
//!     4. Execute agent task (native Rust)
//!     5. Parse result
//!     6. Serialize TaskResult
//!     7. JetStream publish to ares.tasks.results.{task_id}
//!     8. Update task status to "completed" or "failed" (Redis)
//!     9. Refresh heartbeat status (Redis)
//!     10. Ack JetStream message
//! }
//! ```

mod executor;
mod result_handler;
pub mod types;

use types::TaskMessage;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::consumer::{AckPolicy, Consumer};
use futures::StreamExt;
use tracing::{debug, error, info, warn};

use ares_core::nats::{self, NatsBroker};

use crate::worker::config::WorkerConfig;
use crate::worker::heartbeat::WorkerStatus;

/// TTL for task status keys — 24 hours.
const TASK_STATUS_TTL: i64 = 60 * 60 * 24;

// ─── Task loop ───────────────────────────────────────────────────────────────

/// Run the main task consumption loop until shutdown is signalled.
pub async fn run_task_loop(
    config: &WorkerConfig,
    redis_conn: redis::aio::ConnectionManager,
    nats: NatsBroker,
    status_tx: tokio::sync::watch::Sender<WorkerStatus>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let urgent_consumer = ensure_role_consumer(&nats, &config.worker_role, true).await?;
    let normal_consumer = ensure_role_consumer(&nats, &config.worker_role, false).await?;

    info!(
        role = %config.worker_role,
        agent = %config.agent_name,
        "Starting task loop (NATS JetStream)"
    );

    let mut redis_conn = redis_conn;
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);

    loop {
        let poll_result = tokio::select! {
            r = poll_one_task(&urgent_consumer, &normal_consumer, config.poll_timeout) => r,
            _ = shutdown.notified() => {
                info!("Task loop: shutdown signalled, finishing");
                break;
            }
        };

        match poll_result {
            Ok(Some((task, msg))) => {
                retry_delay = Duration::from_secs(1);

                let _ = status_tx.send(WorkerStatus {
                    status: "busy".to_string(),
                    current_task: Some(task.task_id.clone()),
                });

                result_handler::process_task(&mut redis_conn, &nats, config, &task).await;

                if let Err(e) = msg.ack().await {
                    warn!(task_id = %task.task_id, "Failed to ack JetStream message: {e}");
                }

                let _ = status_tx.send(WorkerStatus {
                    status: "idle".to_string(),
                    current_task: None,
                });
            }
            Ok(None) => {
                retry_delay = Duration::from_secs(1);
            }
            Err(e) => {
                let is_conn_error = is_transient_broker_error(&e.to_string());

                if is_conn_error {
                    warn!(
                        delay_secs = retry_delay.as_secs(),
                        "Task loop: transient broker error, retrying: {e}"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = shutdown.notified() => break,
                    }
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                } else {
                    error!("Task loop: error: {e}");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = shutdown.notified() => break,
                    }
                    retry_delay = Duration::from_secs(1);
                }
            }
        }
    }

    Ok(())
}

/// Re-export TTL constant for the result handler.
pub(crate) const fn task_status_ttl() -> i64 {
    TASK_STATUS_TTL
}

/// Classify a broker-side error as a transient connectivity/timeout failure
/// (worth retrying with backoff) versus a logic error (worth surfacing fast).
fn is_transient_broker_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    [
        "connection",
        "connect",
        "closed",
        "timeout",
        "broken pipe",
        "reset",
        "no responders",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

/// Ensure a durable pull consumer exists for the given (role, urgency).
async fn ensure_role_consumer(
    nats: &NatsBroker,
    role: &str,
    urgent: bool,
) -> anyhow::Result<Consumer<PullConfig>> {
    let (filter_subject, suffix) = if urgent {
        (nats::urgent_task_subject(role), "urgent")
    } else {
        (nats::task_subject(role), "normal")
    };

    let durable_name = format!("ares-worker-{role}-{suffix}");
    let stream = nats
        .jetstream()
        .get_stream(nats::TASKS_STREAM)
        .await
        .with_context(|| format!("get_stream({})", nats::TASKS_STREAM))?;

    let cfg = PullConfig {
        durable_name: Some(durable_name.clone()),
        filter_subject,
        ack_policy: AckPolicy::Explicit,
        ack_wait: Duration::from_secs(60 * 30),
        max_deliver: 5,
        ..Default::default()
    };

    let consumer = stream
        .get_or_create_consumer(&durable_name, cfg)
        .await
        .with_context(|| format!("ensure consumer {durable_name}"))?;
    Ok(consumer)
}

/// Pull one message, preferring urgent. Returns Ok(None) on idle timeout.
async fn poll_one_task(
    urgent: &Consumer<PullConfig>,
    normal: &Consumer<PullConfig>,
    timeout: Duration,
) -> anyhow::Result<Option<(TaskMessage, async_nats::jetstream::Message)>> {
    // Try urgent with a tiny expiry first; fall back to normal if empty.
    if let Some(item) = fetch_one(urgent, Duration::from_millis(50)).await? {
        return Ok(Some(item));
    }
    fetch_one(normal, timeout).await
}

async fn fetch_one(
    consumer: &Consumer<PullConfig>,
    expires: Duration,
) -> anyhow::Result<Option<(TaskMessage, async_nats::jetstream::Message)>> {
    let mut batch = consumer
        .fetch()
        .max_messages(1)
        .expires(expires.max(Duration::from_millis(50)))
        .messages()
        .await
        .context("start fetch")?;

    match batch.next().await {
        Some(Ok(msg)) => {
            let task: TaskMessage =
                serde_json::from_slice(&msg.payload).context("deserialize TaskMessage")?;
            debug!(task_id = %task.task_id, task_type = %task.task_type, "Received task");
            Ok(Some((task, msg)))
        }
        Some(Err(e)) => Err(anyhow::anyhow!("JetStream fetch error: {e}")),
        None => Ok(None),
    }
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
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn is_transient_broker_error_recognizes_connection_terms() {
        for kw in [
            "connection refused",
            "Connection reset by peer",
            "broken pipe",
            "request timeout",
            "stream closed unexpectedly",
            "no responders available",
            "Failed to connect to NATS",
        ] {
            assert!(
                is_transient_broker_error(kw),
                "expected {kw:?} to be classified as transient"
            );
        }
    }

    #[test]
    fn is_transient_broker_error_rejects_logic_errors() {
        for kw in [
            "deserialize TaskMessage: missing field",
            "JetStream consumer not found",
            "stream ARES_TASKS does not exist",
            "permission denied: not authorized",
            "ack returned NACK",
        ] {
            // None of these contain the transient keywords.
            assert!(
                !is_transient_broker_error(kw),
                "expected {kw:?} to be classified as non-transient"
            );
        }
    }

    #[test]
    fn is_transient_broker_error_is_case_insensitive() {
        assert!(is_transient_broker_error("BROKEN PIPE"));
        assert!(is_transient_broker_error("Timeout while waiting"));
        assert!(is_transient_broker_error("No Responders"));
    }

    #[test]
    fn task_status_ttl_is_24_hours() {
        assert_eq!(task_status_ttl(), 60 * 60 * 24);
    }

    #[test]
    fn task_message_with_explicit_priority_overrides_default() {
        let json = r#"{
            "task_id": "t1",
            "task_type": "recon",
            "source_agent": "orch",
            "target_agent": "recon-0",
            "payload": {},
            "priority": 1
        }"#;
        let msg: TaskMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.priority, 1);
    }

    #[test]
    fn task_result_success_carries_completed_at() {
        let r = TaskResult::success(
            "t1",
            serde_json::json!({"output": "done"}),
            "pod-0",
            "ares-recon",
        );
        let parsed_at = chrono::DateTime::parse_from_rfc3339(r.completed_at.as_deref().unwrap());
        assert!(parsed_at.is_ok());
    }

    #[test]
    fn task_result_failure_with_partial_output() {
        let partial = serde_json::json!({"partial_output": "ran 3/5 steps"});
        let r = TaskResult::failure(
            "t1",
            "agent crashed".into(),
            Some(partial.clone()),
            "pod-0",
            "ares-recon",
        );
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("agent crashed"));
        assert_eq!(r.result, Some(partial));
    }
}
