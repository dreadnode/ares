//! Blue team task queue for distributed investigation workers.
//!
//! Matches the Python `BlueTaskQueue` key patterns for task submission,
//! result polling, heartbeat, and investigation registration.

use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::keys::*;

/// A task message submitted to a blue team worker queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueTaskMessage {
    pub task_id: String,
    pub investigation_id: String,
    pub task_type: String,
    pub role: String,
    pub params: serde_json::Value,
    pub created_at: String,
}

/// A result returned from a blue team worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueTaskResult {
    pub task_id: String,
    pub investigation_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_agent: Option<String>,
}

impl BlueTaskResult {
    pub fn success(
        task_id: &str,
        investigation_id: &str,
        result: serde_json::Value,
        agent: &str,
    ) -> Self {
        Self {
            task_id: task_id.to_string(),
            investigation_id: investigation_id.to_string(),
            success: true,
            result: Some(result),
            error: None,
            completed_at: Utc::now().to_rfc3339(),
            worker_agent: Some(agent.to_string()),
        }
    }

    pub fn failure(task_id: &str, investigation_id: &str, error: String, agent: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            investigation_id: investigation_id.to_string(),
            success: false,
            result: None,
            error: Some(error),
            completed_at: Utc::now().to_rfc3339(),
            worker_agent: Some(agent.to_string()),
        }
    }
}

/// Blue team task queue backed by Redis.
///
/// Queue naming:
///   ares:blue:tasks:global:{role}          Global queue per role
///   ares:blue:results:{task_id}            Result queue (TTL)
///   ares:blue:heartbeat:{agent}            Agent heartbeat (TTL 60s)
///   ares:blue:active_investigations        Active investigation IDs (SET, TTL 24h)
///   ares:blue:inv:{id}:queue_meta          Investigation queue metadata (HASH, TTL 24h)
pub struct BlueTaskQueue {
    conn: redis::aio::ConnectionManager,
}

impl BlueTaskQueue {
    pub async fn connect(redis_url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let conn = client.get_connection_manager().await?;
        Ok(Self { conn })
    }

    pub fn from_conn(conn: redis::aio::ConnectionManager) -> Self {
        Self { conn }
    }

    pub fn conn_mut(&mut self) -> &mut redis::aio::ConnectionManager {
        &mut self.conn
    }

    /// Submit a task to the global role queue.
    pub async fn submit_task(&mut self, task: &BlueTaskMessage) -> anyhow::Result<()> {
        let queue_key = format!("{BLUE_TASK_QUEUE_PREFIX}:global:{}", task.role);
        let data = serde_json::to_string(task)?;

        debug!(
            task_id = %task.task_id,
            role = %task.role,
            task_type = %task.task_type,
            "submitting blue team task"
        );

        let _: () = self.conn.lpush(&queue_key, &data).await?;
        let _: () = self.conn.expire(&queue_key, 86400).await?;
        Ok(())
    }

    /// Poll for a task from the global role queue (blocking).
    pub async fn poll_global_task(
        &mut self,
        role: &str,
        timeout_secs: f64,
    ) -> anyhow::Result<Option<BlueTaskMessage>> {
        let queue_key = format!("{BLUE_TASK_QUEUE_PREFIX}:global:{role}");
        let result: Option<(String, String)> = redis::cmd("BRPOP")
            .arg(&queue_key)
            .arg(timeout_secs)
            .query_async(&mut self.conn)
            .await?;

        match result {
            Some((_key, data)) => {
                let task: BlueTaskMessage = serde_json::from_str(&data)?;
                Ok(Some(task))
            }
            None => Ok(None),
        }
    }

    /// Send a task result.
    pub async fn send_result(&mut self, result: &BlueTaskResult) -> anyhow::Result<()> {
        let result_key = format!("{BLUE_RESULT_QUEUE_PREFIX}:{}", result.task_id);
        let data = serde_json::to_string(result)?;

        let _: () = self.conn.lpush(&result_key, &data).await?;
        let _: () = self.conn.expire(&result_key, 3600).await?; // 1h TTL
        Ok(())
    }

    /// Wait for a task result (blocking).
    pub async fn wait_for_result(
        &mut self,
        task_id: &str,
        timeout_secs: f64,
    ) -> anyhow::Result<Option<BlueTaskResult>> {
        let result_key = format!("{BLUE_RESULT_QUEUE_PREFIX}:{task_id}");
        let result: Option<(String, String)> = redis::cmd("BRPOP")
            .arg(&result_key)
            .arg(timeout_secs)
            .query_async(&mut self.conn)
            .await?;

        match result {
            Some((_key, data)) => {
                let task_result: BlueTaskResult = serde_json::from_str(&data)?;
                Ok(Some(task_result))
            }
            None => Ok(None),
        }
    }

    /// Check for a result without blocking.
    pub async fn check_result(&mut self, task_id: &str) -> anyhow::Result<Option<BlueTaskResult>> {
        let result_key = format!("{BLUE_RESULT_QUEUE_PREFIX}:{task_id}");
        let result: Option<String> = self.conn.rpop(&result_key, None).await?;

        match result {
            Some(data) => {
                let task_result: BlueTaskResult = serde_json::from_str(&data)?;
                Ok(Some(task_result))
            }
            None => Ok(None),
        }
    }

    /// Send a heartbeat for a blue team agent.
    pub async fn send_heartbeat(
        &mut self,
        agent_name: &str,
        status: &str,
        current_task: Option<&str>,
        role: &str,
        investigation_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let key = format!("{BLUE_HEARTBEAT_PREFIX}:{agent_name}");
        let payload = serde_json::json!({
            "status": status,
            "current_task": current_task,
            "role": role,
            "investigation_id": investigation_id,
            "timestamp": Utc::now().to_rfc3339(),
        });
        let data = serde_json::to_string(&payload)?;
        let _: () = self.conn.set_ex(&key, &data, 60).await?;
        Ok(())
    }

    /// Get a heartbeat for an agent.
    pub async fn get_heartbeat(
        &mut self,
        agent_name: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let key = format!("{BLUE_HEARTBEAT_PREFIX}:{agent_name}");
        let data: Option<String> = self.conn.get(&key).await?;
        match data {
            Some(json_str) => match serde_json::from_str(&json_str) {
                Ok(val) => Ok(Some(val)),
                Err(e) => {
                    warn!("Failed to parse heartbeat for {agent_name}: {e}");
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Register an investigation as active for worker discovery.
    pub async fn register_investigation(
        &mut self,
        investigation_id: &str,
        alert: &serde_json::Value,
        model: &str,
    ) -> anyhow::Result<()> {
        // Add to active set
        let _: () = self
            .conn
            .sadd(BLUE_ACTIVE_INVESTIGATIONS, investigation_id)
            .await?;
        let _: () = self.conn.expire(BLUE_ACTIVE_INVESTIGATIONS, 86400).await?;

        // Store investigation metadata
        let meta_key = format!("{BLUE_KEY_PREFIX}:{investigation_id}:queue_meta");
        let _: () = self
            .conn
            .hset(
                &meta_key,
                "alert",
                serde_json::to_string(alert).unwrap_or_default(),
            )
            .await?;
        let _: () = self.conn.hset(&meta_key, "model", model).await?;
        let _: () = self
            .conn
            .hset(&meta_key, "registered_at", Utc::now().to_rfc3339())
            .await?;
        let _: () = self.conn.expire(&meta_key, 86400).await?;
        Ok(())
    }

    /// Discover the active investigation (for workers that need to find their work).
    pub async fn discover_active_investigation(&mut self) -> anyhow::Result<Option<String>> {
        let members: Vec<String> = self.conn.smembers(BLUE_ACTIVE_INVESTIGATIONS).await?;
        Ok(members.into_iter().next())
    }

    /// Get the alert for an investigation.
    pub async fn get_investigation_alert(
        &mut self,
        investigation_id: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let meta_key = format!("{BLUE_KEY_PREFIX}:{investigation_id}:queue_meta");
        let data: Option<String> = self.conn.hget(&meta_key, "alert").await?;
        match data {
            Some(json_str) => Ok(serde_json::from_str(&json_str).ok()),
            None => Ok(None),
        }
    }

    /// Get the LLM model for an investigation.
    pub async fn get_investigation_model(
        &mut self,
        investigation_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let meta_key = format!("{BLUE_KEY_PREFIX}:{investigation_id}:queue_meta");
        let model: Option<String> = self.conn.hget(&meta_key, "model").await?;
        Ok(model)
    }

    /// Pop an investigation request from the queue.
    pub async fn pop_investigation_request(
        &mut self,
        timeout_secs: f64,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let result: Option<(String, String)> = redis::cmd("BRPOP")
            .arg(BLUE_INVESTIGATION_QUEUE)
            .arg(timeout_secs)
            .query_async(&mut self.conn)
            .await?;

        match result {
            Some((_key, data)) => match serde_json::from_str(&data) {
                Ok(val) => Ok(Some(val)),
                Err(e) => {
                    warn!("Failed to parse investigation request: {e}");
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Get the global role queue length.
    pub async fn queue_length(&mut self, role: &str) -> anyhow::Result<usize> {
        let queue_key = format!("{BLUE_TASK_QUEUE_PREFIX}:global:{role}");
        let len: usize = self.conn.llen(&queue_key).await?;
        Ok(len)
    }
}
