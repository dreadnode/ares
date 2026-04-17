//! Redis-backed task queue matching the Python `RedisTaskQueue`.
//!
//! Key patterns:
//!   - `ares:tasks:{role}`       — List, per-role task queue
//!   - `ares:results:{task_id}`  — List, per-task result mailbox (TTL 24h)
//!   - `ares:heartbeat:{agent}`  — String, agent heartbeat (TTL from config)
//!   - `ares:task_status:{task_id}` — String, task lifecycle JSON
//!   - `ares:lock:{op_id}`       — String, operation lock with TTL refresh
//!
//! Workers BRPOP from the right; the orchestrator pushes to the left (LPUSH)
//! for normal priority and to the right (RPUSH) for urgent priority, giving
//! FIFO semantics with priority bypass.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants — must match the Python RedisTaskQueue class attributes exactly.
// ---------------------------------------------------------------------------

pub const TASK_QUEUE_PREFIX: &str = "ares:tasks";
pub const RESULT_QUEUE_PREFIX: &str = "ares:results";
pub const HEARTBEAT_PREFIX: &str = "ares:heartbeat";
pub const TASK_STATUS_PREFIX: &str = "ares:task_status";
pub const LOCK_PREFIX: &str = "ares:lock";
pub const STATE_UPDATE_CHANNEL_PREFIX: &str = "ares:state:updates";

/// Result keys expire after 24 hours.
const RESULT_TTL_SECS: u64 = 60 * 60 * 24;

/// Task status keys expire after 24 hours.
const TASK_STATUS_TTL_SECS: u64 = 60 * 60 * 24;

// ---------------------------------------------------------------------------
// Wire types — JSON-compatible with the Python TaskMessage / TaskResult.
// ---------------------------------------------------------------------------

/// Task submitted to a role queue. Mirrors `ares.core.task_queue.TaskMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMessage {
    pub task_id: String,
    pub task_type: String,
    pub source_agent: String,
    pub target_agent: String,
    pub payload: serde_json::Value,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub created_at: Option<DateTime<Utc>>,
    pub callback_queue: Option<String>,
}

fn default_priority() -> i32 {
    5
}

/// Result returned by a worker. Mirrors `ares.core.task_queue.TaskResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub worker_pod: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
}

/// Heartbeat payload written by agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatData {
    pub agent: String,
    pub status: String,
    pub timestamp: String,
    #[serde(default)]
    pub current_task: Option<String>,
    #[serde(default)]
    pub pod_name: Option<String>,
}

// ---------------------------------------------------------------------------
// TaskQueue — thin async wrapper around a redis ConnectionManager.
// ---------------------------------------------------------------------------

/// Async Redis task queue implementing the Ares queue protocol.
#[derive(Clone)]
pub struct TaskQueue {
    conn: ConnectionManager,
}

#[allow(dead_code)]
impl TaskQueue {
    /// Create a new queue from an existing connection manager.
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    /// Connect to Redis and return a TaskQueue.
    pub async fn connect(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Invalid Redis URL: {redis_url}"))?;
        // Default response_timeout is 500ms which is too short for BRPOP
        // blocking calls (tool results can take minutes). Without this fix,
        // the client-side timeout cancels the future but the server-side
        // BRPOP remains registered, consuming results that are silently lost.
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(Some(Duration::from_secs(1800)));
        let conn = client
            .get_connection_manager_with_config(config)
            .await
            .with_context(|| format!("Failed to connect to Redis at {redis_url}"))?;
        info!(url = %redis_url, "Connected to Redis");
        Ok(Self { conn })
    }

    // === Key helpers ========================================================

    #[inline]
    fn task_queue_key(role: &str) -> String {
        format!("{TASK_QUEUE_PREFIX}:{role}")
    }

    #[inline]
    fn result_queue_key(task_id: &str) -> String {
        format!("{RESULT_QUEUE_PREFIX}:{task_id}")
    }

    #[inline]
    fn heartbeat_key(agent: &str) -> String {
        format!("{HEARTBEAT_PREFIX}:{agent}")
    }

    #[inline]
    fn task_status_key(task_id: &str) -> String {
        format!("{TASK_STATUS_PREFIX}:{task_id}")
    }

    // === Orchestrator methods ===============================================

    /// Submit a task to a role's queue.
    ///
    /// Priority <= 2 (urgent) uses RPUSH so the task is consumed first by
    /// workers that BRPOP from the right. All other priorities use LPUSH for
    /// FIFO order.
    pub async fn submit_task(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        source_agent: &str,
        priority: i32,
    ) -> Result<String> {
        let task_id = format!("{}_{}", task_type, &Uuid::new_v4().to_string()[..12]);
        let callback = Self::result_queue_key(&task_id);

        let msg = TaskMessage {
            task_id: task_id.clone(),
            task_type: task_type.to_string(),
            source_agent: source_agent.to_string(),
            target_agent: target_role.to_string(),
            payload,
            priority,
            created_at: Some(Utc::now()),
            callback_queue: Some(callback),
        };

        let queue_key = Self::task_queue_key(target_role);
        let json = serde_json::to_string(&msg).context("Failed to serialize TaskMessage")?;

        let mut conn = self.conn.clone();
        if priority <= 2 {
            conn.rpush::<_, _, ()>(&queue_key, &json)
                .await
                .with_context(|| format!("RPUSH to {queue_key}"))?;
            info!(task_id = %task_id, queue = %queue_key, priority, "Urgent task submitted (RPUSH)");
        } else {
            conn.lpush::<_, _, ()>(&queue_key, &json)
                .await
                .with_context(|| format!("LPUSH to {queue_key}"))?;
            info!(task_id = %task_id, queue = %queue_key, priority, "Task submitted (LPUSH)");
        }

        // Track status
        self.set_task_status(&task_id, "pending").await?;

        Ok(task_id)
    }

    /// Non-destructive peek: does a result exist for this task?
    pub async fn has_pending_result(&self, task_id: &str) -> Result<bool> {
        let key = Self::result_queue_key(task_id);
        let mut conn = self.conn.clone();
        let len: i64 = conn.llen(&key).await.unwrap_or(0);
        Ok(len > 0)
    }

    /// Non-blocking check for a task result (RPOP).
    pub async fn check_result(&self, task_id: &str) -> Result<Option<TaskResult>> {
        let key = Self::result_queue_key(task_id);
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.rpop(&key, None).await?;
        match data {
            Some(json) => {
                let result: TaskResult = serde_json::from_str(&json)
                    .with_context(|| format!("Bad TaskResult JSON for {task_id}"))?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Batch-check results for multiple task IDs using a pipeline.
    pub async fn check_results_batch(
        &self,
        task_ids: &[String],
    ) -> Result<HashMap<String, Option<TaskResult>>> {
        if task_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let mut pipe = redis::pipe();
        for tid in task_ids {
            let key = Self::result_queue_key(tid);
            pipe.cmd("RPOP").arg(key);
        }

        let mut conn = self.conn.clone();
        let raw: Vec<Option<String>> = pipe
            .query_async(&mut conn)
            .await
            .context("Pipeline check_results_batch failed")?;

        let mut out = HashMap::with_capacity(task_ids.len());
        for (tid, data) in task_ids.iter().zip(raw) {
            let parsed = match data {
                Some(json) => match serde_json::from_str::<TaskResult>(&json) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        warn!(task_id = %tid, err = %e, "Ignoring malformed TaskResult");
                        None
                    }
                },
                None => None,
            };
            out.insert(tid.clone(), parsed);
        }
        Ok(out)
    }

    /// Blocking wait for a result (BRPOP). Timeout in seconds.
    pub async fn poll_result(
        &self,
        task_id: &str,
        timeout_secs: f64,
    ) -> Result<Option<TaskResult>> {
        let key = Self::result_queue_key(task_id);
        let mut conn = self.conn.clone();
        let result: Option<(String, String)> = conn
            .brpop(&key, timeout_secs)
            .await
            .with_context(|| format!("BRPOP on {key}"))?;

        match result {
            Some((_key, json)) => {
                let tr: TaskResult = serde_json::from_str(&json)
                    .with_context(|| format!("Bad TaskResult JSON for {task_id}"))?;
                Ok(Some(tr))
            }
            None => Ok(None),
        }
    }

    /// Get the length of a role's task queue.
    pub async fn queue_length(&self, role: &str) -> Result<usize> {
        let key = Self::task_queue_key(role);
        let mut conn = self.conn.clone();
        let len: usize = conn.llen(&key).await?;
        Ok(len)
    }

    /// Read heartbeat data for an agent.
    pub async fn get_heartbeat(&self, agent: &str) -> Result<Option<HeartbeatData>> {
        let key = Self::heartbeat_key(agent);
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.get(&key).await?;
        match data {
            Some(json) => {
                let hb: HeartbeatData = serde_json::from_str(&json)?;
                Ok(Some(hb))
            }
            None => Ok(None),
        }
    }

    /// Write heartbeat for an agent (with TTL so stale entries self-expire).
    pub async fn send_heartbeat(
        &self,
        agent: &str,
        status: &str,
        current_task: Option<&str>,
        ttl: Duration,
    ) -> Result<()> {
        let key = Self::heartbeat_key(agent);
        let hb = HeartbeatData {
            agent: agent.to_string(),
            status: status.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            current_task: current_task.map(|s| s.to_string()),
            pod_name: std::env::var("POD_NAME").ok(),
        };
        let json = serde_json::to_string(&hb)?;
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(&key, &json, ttl.as_secs())
            .await
            .with_context(|| format!("SET EX heartbeat for {agent}"))?;
        debug!(agent, status, "Heartbeat sent");
        Ok(())
    }

    /// Publish a state-update notification on the PubSub channel.
    pub async fn publish_state_update(&self, operation_id: &str) -> Result<()> {
        let channel = format!("{STATE_UPDATE_CHANNEL_PREFIX}:{operation_id}");
        let mut conn = self.conn.clone();
        conn.publish::<_, _, ()>(&channel, "updated")
            .await
            .with_context(|| format!("PUBLISH to {channel}"))?;
        debug!(operation_id, "State update published");
        Ok(())
    }

    // === Operation lock =====================================================

    /// Try to acquire the operation lock. Returns true if acquired.
    pub async fn try_acquire_lock(&self, operation_id: &str, ttl: Duration) -> Result<bool> {
        let key = format!("{LOCK_PREFIX}:{operation_id}");
        let holder = format!(
            "orchestrator-{}",
            std::env::var("POD_NAME").unwrap_or_else(|_| Uuid::new_v4().to_string())
        );
        let mut conn = self.conn.clone();
        let acquired: bool = redis::cmd("SET")
            .arg(&key)
            .arg(&holder)
            .arg("NX")
            .arg("EX")
            .arg(ttl.as_secs())
            .query_async(&mut conn)
            .await
            .with_context(|| format!("SET NX lock for operation {operation_id}"))?;
        if acquired {
            info!(operation_id, "Operation lock acquired");
        }
        Ok(acquired)
    }

    /// Extend the operation lock TTL. Call periodically to keep it alive.
    pub async fn extend_lock(&self, operation_id: &str, ttl: Duration) -> Result<bool> {
        let key = format!("{LOCK_PREFIX}:{operation_id}");
        let mut conn = self.conn.clone();
        let ok: bool = conn.expire(&key, ttl.as_secs() as i64).await?;
        if !ok {
            warn!(operation_id, "Lock key missing — could not extend TTL");
        }
        Ok(ok)
    }

    // === Task status tracking ===============================================

    /// Set the status string for a task (with 24h TTL).
    ///
    /// If a record already exists for this task, preserves existing fields
    /// (operation_id, role, task_type, started_at, payload) and updates
    /// only the status and timestamps.
    pub async fn set_task_status(&self, task_id: &str, status: &str) -> Result<()> {
        let key = Self::task_status_key(task_id);
        let mut conn = self.conn.clone();

        // Read-modify-write: preserve existing fields
        let existing: Option<String> = match conn.get::<_, Option<String>>(&key).await {
            Ok(v) => v,
            Err(e) => {
                warn!(task_id = task_id, err = %e, "Failed to read existing task status");
                None
            }
        };
        let mut payload: serde_json::Value = existing
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| serde_json::json!({}));

        let now = Utc::now().to_rfc3339();
        payload["task_id"] = serde_json::json!(task_id);
        payload["status"] = serde_json::json!(status);
        payload["updated_at"] = serde_json::json!(now);

        if status == "in_progress" && payload.get("started_at").is_none() {
            payload["started_at"] = serde_json::json!(now);
        }
        if status == "completed" || status == "failed" {
            payload["ended_at"] = serde_json::json!(now);
        }

        let json = payload.to_string();
        conn.set_ex::<_, _, ()>(&key, &json, TASK_STATUS_TTL_SECS)
            .await?;
        Ok(())
    }

    /// Write a full task status record with all metadata.
    pub async fn set_task_status_full(
        &self,
        task_id: &str,
        status: &str,
        operation_id: &str,
        role: &str,
        task_type: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<()> {
        let key = Self::task_status_key(task_id);
        let now = Utc::now().to_rfc3339();
        let mut record = serde_json::json!({
            "task_id": task_id,
            "status": status,
            "operation_id": operation_id,
            "role": role,
            "task_type": task_type,
            "updated_at": now,
        });
        if status == "in_progress" {
            record["started_at"] = serde_json::json!(now);
        }
        if let Some(p) = payload {
            record["payload"] = p.clone();
        }
        let json = record.to_string();
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(&key, &json, TASK_STATUS_TTL_SECS)
            .await?;
        Ok(())
    }

    /// Read task status.
    pub async fn get_task_status(&self, task_id: &str) -> Result<Option<String>> {
        let key = Self::task_status_key(task_id);
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.get(&key).await?;
        Ok(data)
    }

    /// Get a clone of the underlying connection manager.
    ///
    /// Used by the deferred queue to run ZSET commands directly.
    pub fn connection(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// Send a result to the task's result queue (worker side).
    pub async fn send_result(&self, task_id: &str, result: &TaskResult) -> Result<()> {
        let key = Self::result_queue_key(task_id);
        let json = serde_json::to_string(result)?;
        let mut conn = self.conn.clone();
        conn.lpush::<_, _, ()>(&key, &json).await?;
        conn.expire::<_, ()>(&key, RESULT_TTL_SECS as i64).await?;
        let final_status = if result.success {
            "completed"
        } else {
            "failed"
        };
        debug!(
            task_id = task_id,
            status = final_status,
            "Updating task status after send_result"
        );
        self.set_task_status(task_id, final_status).await?;
        debug!(task_id = task_id, "Task status updated to {}", final_status);
        Ok(())
    }
}
