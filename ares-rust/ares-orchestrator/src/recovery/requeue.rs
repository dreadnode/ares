//! Task requeuing (preserves original task_id).

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::info;

use ares_core::models::TaskInfo;

use crate::task_queue::{TaskMessage, TaskQueue, RESULT_QUEUE_PREFIX, TASK_QUEUE_PREFIX};

/// Requeue a task to its target role queue, preserving the original task_id.
///
/// Uses RPUSH so retried tasks are consumed before new ones (workers BRPOP
/// from the right).
pub async fn requeue_task(queue: &TaskQueue, task_id: &str, task: &TaskInfo) -> Result<()> {
    let mut payload = task
        .params
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<serde_json::Map<String, serde_json::Value>>();

    // Add retry metadata
    payload.insert(
        "_retry_count".to_string(),
        serde_json::Value::from(task.retry_count),
    );
    payload.insert("_is_retry".to_string(), serde_json::Value::Bool(true));

    let callback_queue = format!("{RESULT_QUEUE_PREFIX}:{task_id}");
    let msg = TaskMessage {
        task_id: task_id.to_string(),
        task_type: task.task_type.clone(),
        source_agent: "orchestrator".to_string(),
        target_agent: task.assigned_agent.clone(),
        payload: serde_json::Value::Object(payload),
        priority: 1, // High priority for retries
        created_at: Some(chrono::Utc::now()),
        callback_queue: Some(callback_queue),
    };

    let queue_key = format!("{TASK_QUEUE_PREFIX}:{}", task.assigned_agent);
    let json = serde_json::to_string(&msg).context("Failed to serialize requeue TaskMessage")?;

    let mut conn = queue.connection();
    conn.rpush::<_, _, ()>(&queue_key, &json)
        .await
        .with_context(|| format!("RPUSH to {} for requeue", queue_key))?;

    info!(
        task_id = %task_id,
        queue = %queue_key,
        retry_count = task.retry_count,
        "Requeued task (RPUSH)"
    );

    Ok(())
}
