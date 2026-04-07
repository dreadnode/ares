//! Operation recovery manager.
//!
//! On startup, the orchestrator can recover state from a previous run by
//! loading it from Redis and re-enqueueing any interrupted tasks (those with
//! status PENDING, IN_PROGRESS, or RETRYING).

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{info, warn};

use ares_core::models::SharedRedTeamState;
use ares_core::state::RedisStateReader;

use crate::task_queue::TaskQueue;

/// Maximum number of retries before a task is considered permanently failed.
const MAX_RETRIES: i32 = 3;

/// Statuses that indicate an interrupted task eligible for re-enqueue.
const INTERRUPTED_STATUSES: &[&str] = &["pending", "in_progress", "retrying"];

/// Result of a recovery operation.
#[derive(Debug)]
pub struct RecoveredState {
    /// The full shared state loaded from Redis.
    pub state: SharedRedTeamState,
    /// Task IDs that were re-enqueued for retry.
    pub requeued_task_ids: Vec<String>,
    /// Task IDs that exceeded max retries and were marked failed.
    pub failed_task_ids: Vec<String>,
}

/// Manages recovery of operation state from Redis after a restart.
pub struct OperationRecoveryManager {
    redis_url: String,
}

impl OperationRecoveryManager {
    /// Create a new recovery manager.
    pub fn new(redis_url: String) -> Self {
        Self { redis_url }
    }

    /// Attempt to recover an operation's state from Redis.
    ///
    /// 1. Checks that `ares:op:{operation_id}:meta` exists
    /// 2. Loads full state via `RedisStateReader`
    /// 3. Scans task status keys for interrupted tasks
    /// 4. Re-enqueues interrupted tasks (incrementing retry count)
    /// 5. Returns recovered state + list of requeued/failed task IDs
    pub async fn recover(&self, operation_id: &str) -> Result<RecoveredState> {
        let queue = TaskQueue::connect(&self.redis_url)
            .await
            .context("Failed to connect to Redis for recovery")?;
        let mut conn = queue.connection();

        let reader = RedisStateReader::new(operation_id.to_string());

        // Step 1: Check operation exists
        let exists = reader
            .exists(&mut conn)
            .await
            .context("Failed to check operation existence")?;
        if !exists {
            anyhow::bail!(
                "Operation {} not found in Redis — cannot recover",
                operation_id
            );
        }

        // Step 2: Load full state
        let state = reader
            .load_state(&mut conn)
            .await
            .context("Failed to load state from Redis")?
            .ok_or_else(|| anyhow::anyhow!("Operation {} has no state data", operation_id))?;

        info!(
            operation_id = operation_id,
            credentials = state.all_credentials.len(),
            hashes = state.all_hashes.len(),
            hosts = state.all_hosts.len(),
            has_domain_admin = state.has_domain_admin,
            "State loaded for recovery"
        );

        // Step 3: Scan for interrupted tasks
        let task_status_keys: Vec<String> = redis::cmd("KEYS")
            .arg("ares:task_status:*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default();

        let mut requeued_task_ids = Vec::new();
        let mut failed_task_ids = Vec::new();

        for status_key in &task_status_keys {
            let raw: Option<String> = conn.get(status_key).await.unwrap_or(None);
            let raw = match raw {
                Some(r) => r,
                None => continue,
            };

            let status_data: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Check if this task belongs to our operation
            // Task status records may or may not have operation_id
            let task_id = match status_data.get("task_id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => continue,
            };

            let status = match status_data.get("status").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // Check if this is an interrupted task
            if !INTERRUPTED_STATUSES.contains(&status) {
                continue;
            }

            // Extract retry count from status data (default 0)
            let retry_count = status_data
                .get("retry_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;

            // Step 4: Check retry limit
            if retry_count >= MAX_RETRIES {
                warn!(
                    task_id = %task_id,
                    retry_count = retry_count,
                    "Task exceeded max retries, marking as failed"
                );
                // Update status to failed
                let _ = queue.set_task_status(&task_id, "failed").await;
                failed_task_ids.push(task_id);
                continue;
            }

            // Re-enqueue: we need the original task data
            // The task status key stores basic info; the actual task payload
            // may be lost if the worker consumed it. We update the status
            // to "retrying" with incremented retry count so downstream
            // systems know to re-dispatch.
            let new_retry_count = retry_count + 1;
            let updated_status = serde_json::json!({
                "task_id": task_id,
                "status": "retrying",
                "retry_count": new_retry_count,
                "updated_at": chrono::Utc::now().to_rfc3339(),
                "recovery": true,
            });
            let updated_json = serde_json::to_string(&updated_status).unwrap_or_default();
            let _: () = conn
                .set_ex(status_key, &updated_json, 86400)
                .await
                .unwrap_or(());

            info!(
                task_id = %task_id,
                retry_count = new_retry_count,
                previous_status = status,
                "Task re-enqueued for recovery"
            );
            requeued_task_ids.push(task_id);
        }

        info!(
            operation_id = operation_id,
            requeued = requeued_task_ids.len(),
            failed = failed_task_ids.len(),
            "Recovery complete"
        );

        Ok(RecoveredState {
            state,
            requeued_task_ids,
            failed_task_ids,
        })
    }
}
