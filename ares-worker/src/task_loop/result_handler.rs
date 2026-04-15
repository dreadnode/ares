//! Result processing — build TaskResult, push to Redis, track token usage.

use chrono::Utc;
use redis::AsyncCommands;
use tracing::{debug, error, info, warn};

use ares_core::token_usage;

use crate::config::WorkerConfig;

use super::executor::run_agent_task;
use super::types::{TaskMessage, TaskResult};
use super::{RESULT_QUEUE_PREFIX, RESULT_TTL, TASK_STATUS_PREFIX, TASK_STATUS_TTL};

/// Process a single task: set status, run agent, push result.
pub async fn process_task(
    conn: &mut redis::aio::ConnectionManager,
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

    // 2. Run the agent task
    let agent_result = run_agent_task(&task.task_type, &task.payload, config.task_timeout).await;

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
                // Include structured discoveries parsed from tool output
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
    conn: &mut redis::aio::ConnectionManager,
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
    conn: &mut redis::aio::ConnectionManager,
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
