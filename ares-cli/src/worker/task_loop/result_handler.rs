//! Result processing — build TaskResult, publish to NATS, track token usage.

use bytes::Bytes;
use chrono::Utc;
use redis::aio::ConnectionLike;
use redis::AsyncCommands;
use tracing::{debug, error, info, warn};

use ares_core::nats::{self, NatsBroker};
use ares_core::token_usage;

use crate::worker::config::WorkerConfig;

use super::executor::run_agent_task;
use super::task_status_ttl;
use super::types::{TaskMessage, TaskResult};

const TASK_STATUS_PREFIX: &str = "ares:task_status";

/// Process a single task: set status, run agent, publish result.
pub async fn process_task(
    conn: &mut redis::aio::ConnectionManager,
    nats: &NatsBroker,
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

    let agent_result = run_agent_task(&task.task_type, &task.payload, config.task_timeout).await;

    let usage_for_tracking = agent_result.as_ref().ok().and_then(|ar| ar.usage.clone());

    let (task_result, final_status) = match agent_result {
        Ok(ar) => {
            if let Some(ref err) = ar.error {
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
                if let Some(ref usage) = ar.usage {
                    result_payload["usage"] = serde_json::to_value(usage).unwrap_or_default();
                }
                if let Some(ref disc) = ar.discoveries {
                    if let Some(obj) = disc.as_object() {
                        for (k, v) in obj {
                            result_payload[k] = v.clone();
                        }
                    }
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

    // Publish result to JetStream result subject
    match serde_json::to_vec(&task_result) {
        Ok(bytes) => {
            let subject = nats::task_result_subject(&task.task_id);
            match nats
                .jetstream()
                .publish(subject.clone(), Bytes::from(bytes))
                .await
            {
                Ok(ack) => {
                    if let Err(e) = ack.await {
                        error!(task_id = %task.task_id, subject = %subject, "JetStream ack failed: {e}");
                    }
                }
                Err(e) => {
                    error!(task_id = %task.task_id, subject = %subject, "Failed to publish result: {e}");
                }
            }
        }
        Err(e) => {
            error!(task_id = %task.task_id, "Failed to serialize result: {e}");
        }
    }

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

/// Set task status in Redis with TTL.
async fn set_task_status<C>(
    conn: &mut C,
    task_id: &str,
    status: &str,
    extra_fields: &serde_json::Value,
) -> anyhow::Result<()>
where
    C: ConnectionLike + Send + Sync,
{
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
    conn.set_ex::<_, _, ()>(&key, &json_str, task_status_ttl() as u64)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::state::mock_redis::MockRedisConnection;

    #[tokio::test]
    async fn set_task_status_writes_status_and_timestamps() {
        let mut conn = MockRedisConnection::new();
        let extra = serde_json::json!({
            "operation_id": "op-1",
            "role": "recon",
            "agent_name": "agent-0",
        });
        set_task_status(&mut conn, "task-123", "running", &extra)
            .await
            .unwrap();

        let raw: Option<String> = conn.get("ares:task_status:task-123").await.unwrap();
        let raw = raw.expect("status written");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "running");
        assert_eq!(v["operation_id"], "op-1");
        assert_eq!(v["role"], "recon");
        assert!(v["updated_at"].is_string());
    }

    #[tokio::test]
    async fn set_task_status_overwrites_status_field_in_extra() {
        let mut conn = MockRedisConnection::new();
        // If extra has a "status" key, set_task_status overrides it
        let extra = serde_json::json!({
            "status": "pending",
            "task_type": "recon",
        });
        set_task_status(&mut conn, "t-1", "completed", &extra)
            .await
            .unwrap();

        let raw: Option<String> = conn.get("ares:task_status:t-1").await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw.unwrap()).unwrap();
        assert_eq!(v["status"], "completed");
        assert_eq!(v["task_type"], "recon");
    }

    #[tokio::test]
    async fn set_task_status_handles_non_object_extra() {
        let mut conn = MockRedisConnection::new();
        // If extra isn't an object, status/updated_at can't be merged but
        // we should not panic — the value is serialized as-is.
        let extra = serde_json::json!("not-an-object");
        set_task_status(&mut conn, "t-2", "running", &extra)
            .await
            .unwrap();

        let raw: Option<String> = conn.get("ares:task_status:t-2").await.unwrap();
        // Stored as the raw string, no merge happened
        assert_eq!(raw.as_deref(), Some("\"not-an-object\""));
    }
}
