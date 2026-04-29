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

    let (task_result, final_status) = build_task_result_for_agent_outcome(
        &task.task_id,
        &config.pod_name,
        &config.agent_name,
        &task.task_type,
        agent_result,
    );

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

/// Build the final `TaskResult` and lifecycle status string from a single
/// agent execution. Pulled out as a free function so the branching logic
/// (success / agent-reported error / dispatch error) can be unit tested
/// without a NATS broker.
pub(super) fn build_task_result_for_agent_outcome(
    task_id: &str,
    pod_name: &str,
    agent_name: &str,
    task_type: &str,
    agent_outcome: anyhow::Result<super::types::AgentResult>,
) -> (TaskResult, &'static str) {
    match agent_outcome {
        Ok(ar) => {
            if let Some(ref err) = ar.error {
                let payload = serde_json::json!({
                    "output": ar.output,
                    "task_type": task_type,
                });
                (
                    TaskResult::failure(task_id, err.clone(), Some(payload), pod_name, agent_name),
                    "failed",
                )
            } else {
                let mut payload = serde_json::json!({
                    "output": ar.output,
                    "task_type": task_type,
                });
                if let Some(ref usage) = ar.usage {
                    payload["usage"] = serde_json::to_value(usage).unwrap_or_default();
                }
                if let Some(ref disc) = ar.discoveries {
                    if let Some(obj) = disc.as_object() {
                        for (k, v) in obj {
                            payload[k] = v.clone();
                        }
                    }
                }
                (
                    TaskResult::success(task_id, payload, pod_name, agent_name),
                    "completed",
                )
            }
        }
        Err(e) => {
            let msg = format!("{e}");
            error!(task_id = %task_id, "Agent task failed: {msg}");
            (
                TaskResult::failure(task_id, msg, None, pod_name, agent_name),
                "failed",
            )
        }
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
    use crate::worker::task_loop::types::{AgentResult, TokenUsage};
    use ares_core::state::mock_redis::MockRedisConnection;

    fn agent_ok(output: &str) -> AgentResult {
        AgentResult {
            output: output.to_string(),
            error: None,
            usage: None,
            discoveries: None,
        }
    }

    #[test]
    fn build_task_result_success_marks_completed_and_carries_payload() {
        let ar = agent_ok("nmap output");
        let (tr, status) =
            build_task_result_for_agent_outcome("t1", "pod-0", "ares-recon", "recon", Ok(ar));
        assert_eq!(status, "completed");
        assert!(tr.success);
        assert!(tr.error.is_none());
        let payload = tr.result.expect("result payload present");
        assert_eq!(payload["output"], "nmap output");
        assert_eq!(payload["task_type"], "recon");
        assert!(payload.get("usage").is_none());
    }

    #[test]
    fn build_task_result_success_includes_usage_when_present() {
        let ar = AgentResult {
            output: "out".into(),
            error: None,
            usage: Some(TokenUsage {
                input_tokens: 12,
                output_tokens: 34,
                total_tokens: 46,
                model: Some("openai/gpt-4.1-mini".into()),
            }),
            discoveries: None,
        };
        let (tr, status) =
            build_task_result_for_agent_outcome("t1", "pod-0", "ares-recon", "recon", Ok(ar));
        assert_eq!(status, "completed");
        let payload = tr.result.unwrap();
        assert_eq!(payload["usage"]["input_tokens"], 12);
        assert_eq!(payload["usage"]["total_tokens"], 46);
        assert_eq!(payload["usage"]["model"], "openai/gpt-4.1-mini");
    }

    #[test]
    fn build_task_result_success_merges_discoveries_into_payload() {
        let discoveries = serde_json::json!({
            "hosts": [{"ip": "10.0.0.1"}],
            "credentials": [{"username": "alice"}],
        });
        let ar = AgentResult {
            output: "scan".into(),
            error: None,
            usage: None,
            discoveries: Some(discoveries.clone()),
        };
        let (tr, status) =
            build_task_result_for_agent_outcome("t1", "pod-0", "ares-recon", "recon", Ok(ar));
        assert_eq!(status, "completed");
        let payload = tr.result.unwrap();
        assert_eq!(payload["hosts"], discoveries["hosts"]);
        assert_eq!(payload["credentials"], discoveries["credentials"]);
        assert_eq!(payload["task_type"], "recon");
    }

    #[test]
    fn build_task_result_success_ignores_non_object_discoveries() {
        let ar = AgentResult {
            output: "scan".into(),
            error: None,
            usage: None,
            discoveries: Some(serde_json::json!([1, 2, 3])),
        };
        let (tr, status) =
            build_task_result_for_agent_outcome("t1", "pod-0", "ares-recon", "recon", Ok(ar));
        assert_eq!(status, "completed");
        let payload = tr.result.unwrap();
        // Top-level keys remain just output + task_type
        assert!(payload.get("0").is_none());
        assert_eq!(payload["task_type"], "recon");
    }

    #[test]
    fn build_task_result_agent_reported_error_marks_failed_and_keeps_partial_output() {
        let ar = AgentResult {
            output: "ran 3 of 5 steps".into(),
            error: Some("one or more tools had errors".into()),
            usage: None,
            discoveries: None,
        };
        let (tr, status) =
            build_task_result_for_agent_outcome("t1", "pod-0", "ares-recon", "recon", Ok(ar));
        assert_eq!(status, "failed");
        assert!(!tr.success);
        assert_eq!(tr.error.as_deref(), Some("one or more tools had errors"));
        let payload = tr.result.expect("partial output preserved");
        assert_eq!(payload["output"], "ran 3 of 5 steps");
        assert_eq!(payload["task_type"], "recon");
    }

    #[test]
    fn build_task_result_dispatch_error_marks_failed_with_no_partial_payload() {
        let err: anyhow::Result<AgentResult> = Err(anyhow::anyhow!("tool spawn failed"));
        let (tr, status) =
            build_task_result_for_agent_outcome("t1", "pod-0", "ares-recon", "recon", err);
        assert_eq!(status, "failed");
        assert!(!tr.success);
        assert_eq!(tr.error.as_deref(), Some("tool spawn failed"));
        // No partial output preserved on dispatch failure
        assert!(tr.result.is_none());
        assert_eq!(tr.worker_pod.as_deref(), Some("pod-0"));
        assert_eq!(tr.agent_name.as_deref(), Some("ares-recon"));
    }

    #[test]
    fn build_task_result_passes_through_pod_and_agent_metadata() {
        let ar = agent_ok("hi");
        let (tr, _) = build_task_result_for_agent_outcome(
            "task-42",
            "pod-xyz",
            "ares-credential-access",
            "credential_access",
            Ok(ar),
        );
        assert_eq!(tr.task_id, "task-42");
        assert_eq!(tr.worker_pod.as_deref(), Some("pod-xyz"));
        assert_eq!(tr.agent_name.as_deref(), Some("ares-credential-access"));
        assert!(tr.completed_at.is_some());
    }

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
