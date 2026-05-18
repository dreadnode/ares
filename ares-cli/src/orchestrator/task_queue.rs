//! Hybrid Redis + NATS JetStream task queue.
//!
//! Work queues and result mailboxes live in NATS JetStream. Operation lock,
//! agent heartbeats, and task-status records stay in Redis (the right tool
//! for ephemeral KV with TTL).
//!
//! NATS subjects:
//!   - `ares.tasks.{role}`               work queue, normal priority
//!   - `ares.tasks.urgent.{role}`        work queue, urgent (priority ≤ 2)
//!   - `ares.tasks.results.{task_id}`    durable result, one per task
//!
//! Redis keys (state only):
//!   - `ares:heartbeat:{agent}`          string, agent heartbeat (TTL)
//!   - `ares:task_status:{task_id}`      string, task lifecycle JSON (TTL 24h)
//!   - `ares:lock:{op_id}`               string, operation lock (TTL refresh)
//!
//! The work queue uses JetStream pull consumers with explicit acks and
//! bounded redelivery, replacing the silent-loss `BRPOP` pattern.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use redis::aio::{ConnectionLike, ConnectionManager};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use ares_core::nats::{self, NatsBroker};

pub const HEARTBEAT_PREFIX: &str = "ares:heartbeat";
pub const TASK_STATUS_PREFIX: &str = "ares:task_status";
pub const LOCK_PREFIX: &str = "ares:lock";

/// Task status keys expire after 24 hours.
const TASK_STATUS_TTL_SECS: u64 = 60 * 60 * 24;

/// Task submitted to a role queue. Mirrors `ares.core.task_queue.TaskMessage`.
///
/// Construction is exercised by tests; production red-team dispatch goes through
/// the in-process LLM runner instead, so the bin build sees this as unused.
#[cfg(test)]
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

#[cfg(test)]
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

/// Hybrid task queue: NATS for queues, Redis for state.
///
/// Generic over the Redis backend so unit tests can use a mock; `nats` is
/// `None` in tests that don't exercise queue methods.
#[derive(Clone)]
pub struct TaskQueueCore<C> {
    conn: C,
    nats: Option<NatsBroker>,
    result_demux: Option<Arc<ResultDemux>>,
}

/// Production task queue.
pub type TaskQueue = TaskQueueCore<ConnectionManager>;

/// Single long-lived JetStream consumer that drains every `ares.tasks.results.*`
/// subject and stashes parsed results in a per-`task_id` cache.
struct ResultDemux {
    cache: Arc<Mutex<HashMap<String, TaskResult>>>,
}

impl ResultDemux {
    /// Create the consumer and spawn the drain loop. Lives for the lifetime
    /// of the process; the spawned task only exits if the JetStream message
    /// stream ends (which only happens on shutdown / connection loss).
    async fn start(nats: &NatsBroker) -> Result<Arc<Self>> {
        use async_nats::jetstream::consumer::pull::Config as PullConfig;
        use async_nats::jetstream::consumer::{AckPolicy, Consumer};

        let stream = nats
            .jetstream()
            .get_stream(nats::TASKS_STREAM)
            .await
            .with_context(|| format!("get_stream({})", nats::TASKS_STREAM))?;

        let filter = format!("{}.>", nats::TASK_RESULT_SUBJECT_PREFIX);
        let cfg = PullConfig {
            filter_subject: filter.clone(),
            ack_policy: AckPolicy::Explicit,
            ..Default::default()
        };
        let consumer: Consumer<PullConfig> = stream
            .create_consumer(cfg)
            .await
            .context("create result-demux consumer")?;

        let cache: Arc<Mutex<HashMap<String, TaskResult>>> = Arc::default();
        let cache_bg = cache.clone();
        let prefix = format!("{}.", nats::TASK_RESULT_SUBJECT_PREFIX);

        tokio::spawn(async move {
            let mut messages = match consumer.messages().await {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "result-demux: consumer.messages() failed");
                    return;
                }
            };
            while let Some(item) = messages.next().await {
                let msg = match item {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(error = %e, "result-demux: stream error");
                        continue;
                    }
                };
                let task_id = msg
                    .subject
                    .as_str()
                    .strip_prefix(&prefix)
                    .unwrap_or("")
                    .to_string();
                if task_id.is_empty() {
                    warn!(subject = %msg.subject, "result-demux: subject without task_id; dropping");
                    let _ = msg.ack().await;
                    continue;
                }
                match serde_json::from_slice::<TaskResult>(&msg.payload) {
                    Ok(parsed) => {
                        cache_bg.lock().await.insert(task_id, parsed);
                        let _ = msg.ack().await;
                    }
                    Err(e) => {
                        warn!(error = %e, subject = %msg.subject, "result-demux: bad TaskResult JSON; dropping");
                        let _ = msg.ack().await;
                    }
                }
            }
            warn!("result-demux: message stream ended");
        });

        info!(filter = %filter, "result-demux started");
        Ok(Arc::new(Self { cache }))
    }

    async fn take(&self, task_id: &str) -> Option<TaskResult> {
        self.cache.lock().await.remove(task_id)
    }
}

impl TaskQueue {
    /// Connect to Redis + NATS and return a TaskQueue.
    ///
    /// Ensures the standard JetStream streams exist before returning.
    pub async fn connect(redis_url: &str, nats_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Invalid Redis URL: {redis_url}"))?;
        let conn = client
            .get_connection_manager()
            .await
            .with_context(|| format!("Failed to connect to Redis at {redis_url}"))?;
        info!(url = %redis_url, "Connected to Redis (state)");

        let nats = NatsBroker::connect(nats_url).await?;
        nats.ensure_streams().await?;

        let result_demux = ResultDemux::start(&nats).await?;

        Ok(Self {
            conn,
            nats: Some(nats),
            result_demux: Some(result_demux),
        })
    }
}

/// Build the [`TaskMessage`] that `submit_task` publishes to JetStream.
///
/// Pulled out so the wire shape (priority → subject mapping, callback queue
/// generation, default field values) can be unit-tested without a broker.
#[cfg(test)]
pub(crate) fn build_task_message(
    task_id: &str,
    task_type: &str,
    target_role: &str,
    payload: serde_json::Value,
    source_agent: &str,
    priority: i32,
) -> TaskMessage {
    TaskMessage {
        task_id: task_id.to_string(),
        task_type: task_type.to_string(),
        source_agent: source_agent.to_string(),
        target_agent: target_role.to_string(),
        payload,
        priority,
        created_at: Some(Utc::now()),
        callback_queue: Some(nats::task_result_subject(task_id)),
    }
}

/// Choose the work subject for a task based on its priority.
///
/// Priority ≤ 2 publishes to the urgent subject so workers that bind two
/// consumers can prefer urgent work; everything else goes to the normal
/// subject.
#[cfg(test)]
pub(crate) fn task_subject_for_priority(target_role: &str, priority: i32) -> String {
    if priority <= 2 {
        nats::urgent_task_subject(target_role)
    } else {
        nats::task_subject(target_role)
    }
}

/// Lifecycle status string written to Redis after a result is published.
pub(crate) const fn final_status_for(success: bool) -> &'static str {
    if success {
        "completed"
    } else {
        "failed"
    }
}

// The generic impl exposes both the production NATS path and a Redis-only
// path used by unit tests with a mock connection. The `submit_task` helper
// is gated to `cfg(test)` since production red-team dispatch runs in-process.
impl<C: ConnectionLike + Clone + Send + Sync + 'static> TaskQueueCore<C> {
    /// Construct from a Redis backend only — used by unit tests that don't
    /// exercise queue methods. Queue methods will return an error.
    #[cfg(test)]
    pub fn from_connection(conn: C) -> Self {
        Self {
            conn,
            nats: None,
            result_demux: None,
        }
    }

    fn nats(&self) -> Result<&NatsBroker> {
        self.nats
            .as_ref()
            .context("TaskQueue has no NATS broker configured")
    }

    // === Key helpers ========================================================

    #[inline]
    fn heartbeat_key(agent: &str) -> String {
        format!("{HEARTBEAT_PREFIX}:{agent}")
    }

    #[inline]
    fn task_status_key(task_id: &str) -> String {
        format!("{TASK_STATUS_PREFIX}:{task_id}")
    }

    // === Queue methods (NATS JetStream) =====================================

    /// Submit a task to a role's queue.
    ///
    /// Priority ≤ 2 publishes to `ares.tasks.urgent.{role}`, otherwise
    /// `ares.tasks.{role}`. Workers bind two consumers and prefer urgent.
    #[cfg(test)]
    pub async fn submit_task(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        source_agent: &str,
        priority: i32,
    ) -> Result<String> {
        let task_id = format!("{}_{}", task_type, &Uuid::new_v4().to_string()[..12]);

        let msg = build_task_message(
            &task_id,
            task_type,
            target_role,
            payload,
            source_agent,
            priority,
        );

        let subject = task_subject_for_priority(target_role, priority);
        let bytes = Bytes::from(serde_json::to_vec(&msg).context("serialize TaskMessage")?);

        let ack = self
            .nats()?
            .jetstream()
            .publish(subject.clone(), bytes)
            .await
            .with_context(|| format!("JetStream publish to {subject}"))?;
        ack.await
            .with_context(|| format!("Awaiting JetStream ack for {subject}"))?;

        info!(task_id = %task_id, subject = %subject, priority, "Task submitted");
        self.set_task_status(&task_id, "pending").await?;
        Ok(task_id)
    }

    /// Non-blocking check for a task result.
    ///
    /// Reads from the in-process result cache populated by [`ResultDemux`]'s
    /// background drain loop. If the result has arrived since the last check,
    /// it is returned (and removed from the cache); otherwise `None`.
    pub async fn check_result(&self, task_id: &str) -> Result<Option<TaskResult>> {
        let demux = self
            .result_demux
            .as_ref()
            .context("result demux not initialized (TaskQueue built without NATS)")?;
        Ok(demux.take(task_id).await)
    }

    /// Batch-check results for multiple task IDs.
    ///
    /// Iterates per-task; JetStream consumers are per-filter-subject so we
    /// can't pipeline like Redis. Callers should not rely on this being a
    /// single round-trip.
    pub async fn check_results_batch(
        &self,
        task_ids: &[String],
    ) -> Result<HashMap<String, Option<TaskResult>>> {
        let mut out = HashMap::with_capacity(task_ids.len());
        for tid in task_ids {
            let r = self.check_result(tid).await.unwrap_or_else(|e| {
                warn!(task_id = %tid, err = %e, "check_result failed in batch");
                None
            });
            out.insert(tid.clone(), r);
        }
        Ok(out)
    }

    /// Send a result to the task's result subject (worker side).
    pub async fn send_result(&self, task_id: &str, result: &TaskResult) -> Result<()> {
        let subject = nats::task_result_subject(task_id);
        let bytes = Bytes::from(serde_json::to_vec(result).context("serialize TaskResult")?);
        let ack = self
            .nats()?
            .jetstream()
            .publish(subject.clone(), bytes)
            .await
            .with_context(|| format!("JetStream publish to {subject}"))?;
        ack.await
            .with_context(|| format!("Awaiting ack for {subject}"))?;

        let final_status = final_status_for(result.success);
        debug!(
            task_id,
            status = final_status,
            "Result published; updating status"
        );
        self.set_task_status(task_id, final_status).await?;
        Ok(())
    }

    /// Publish a state-update notification (NATS core, fire-and-forget).
    pub async fn publish_state_update(&self, operation_id: &str) -> Result<()> {
        let subject = nats::state_update_subject(operation_id);
        self.nats()?
            .client()
            .publish(subject.clone(), Bytes::from_static(b"updated"))
            .await
            .with_context(|| format!("PUBLISH to {subject}"))?;
        debug!(operation_id, "State update published");
        Ok(())
    }

    // === Redis-backed state methods (unchanged) ============================

    /// Read heartbeat data for an agent.
    pub async fn get_heartbeat(&self, agent: &str) -> Result<Option<HeartbeatData>> {
        let key = Self::heartbeat_key(agent);
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.get(&key).await?;
        match data {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Write heartbeat for an agent (with TTL so stale entries self-expire).
    #[cfg(test)]
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

    // === Operation lock =====================================================

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

    pub async fn extend_lock(&self, operation_id: &str, ttl: Duration) -> Result<bool> {
        let key = format!("{LOCK_PREFIX}:{operation_id}");
        let mut conn = self.conn.clone();
        let ok: bool = conn.expire(&key, ttl.as_secs() as i64).await?;
        if !ok {
            warn!(operation_id, "Lock key missing — could not extend TTL");
        }
        Ok(ok)
    }

    // === Task status tracking ==============================================

    /// Update only status + timestamps; preserves any existing fields.
    pub async fn set_task_status(&self, task_id: &str, status: &str) -> Result<()> {
        let key = Self::task_status_key(task_id);
        let mut conn = self.conn.clone();

        let existing: Option<String> = match conn.get::<_, Option<String>>(&key).await {
            Ok(v) => v,
            Err(e) => {
                warn!(task_id, err = %e, "Failed to read existing task status");
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

    #[cfg(test)]
    pub async fn get_task_status(&self, task_id: &str) -> Result<Option<String>> {
        let key = Self::task_status_key(task_id);
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.get(&key).await?;
        Ok(data)
    }

    /// Get a clone of the underlying Redis connection.
    pub fn connection(&self) -> C {
        self.conn.clone()
    }

    /// Get a clone of the NATS broker (for callers that need direct access).
    pub fn nats_broker(&self) -> Option<NatsBroker> {
        self.nats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[tokio::test]
    async fn heartbeat_roundtrip() {
        let q = mock_queue();
        q.send_heartbeat("agent-1", "idle", None, Duration::from_secs(60))
            .await
            .unwrap();

        let hb = q.get_heartbeat("agent-1").await.unwrap().unwrap();
        assert_eq!(hb.agent, "agent-1");
        assert_eq!(hb.status, "idle");
        assert!(hb.current_task.is_none());
    }

    #[tokio::test]
    async fn heartbeat_with_task() {
        let q = mock_queue();
        q.send_heartbeat("agent-2", "busy", Some("task-99"), Duration::from_secs(30))
            .await
            .unwrap();

        let hb = q.get_heartbeat("agent-2").await.unwrap().unwrap();
        assert_eq!(hb.status, "busy");
        assert_eq!(hb.current_task.as_deref(), Some("task-99"));
    }

    #[tokio::test]
    async fn heartbeat_returns_none_when_missing() {
        let q = mock_queue();
        assert!(q.get_heartbeat("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn try_acquire_lock_succeeds() {
        let q = mock_queue();
        let acquired = q
            .try_acquire_lock("op-1", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(acquired);
    }

    #[tokio::test]
    async fn try_acquire_lock_fails_if_held() {
        let q = mock_queue();
        q.try_acquire_lock("op-1", Duration::from_secs(30))
            .await
            .unwrap();
        let acquired = q
            .try_acquire_lock("op-1", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(!acquired);
    }

    #[tokio::test]
    async fn extend_lock_succeeds_when_held() {
        let q = mock_queue();
        q.try_acquire_lock("op-1", Duration::from_secs(30))
            .await
            .unwrap();
        let ok = q
            .extend_lock("op-1", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn set_task_status_creates_record() {
        let q = mock_queue();
        q.set_task_status("task-1", "pending").await.unwrap();

        let raw = q.get_task_status("task-1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["task_id"], "task-1");
        assert_eq!(v["status"], "pending");
        assert!(v.get("updated_at").is_some());
    }

    #[tokio::test]
    async fn set_task_status_preserves_fields() {
        let q = mock_queue();
        q.set_task_status_full("task-1", "pending", "op-1", "scanner", "recon", None)
            .await
            .unwrap();
        q.set_task_status("task-1", "in_progress").await.unwrap();

        let raw = q.get_task_status("task-1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "in_progress");
        assert_eq!(v["operation_id"], "op-1");
        assert_eq!(v["role"], "scanner");
        assert!(v.get("started_at").is_some());
    }

    #[tokio::test]
    async fn set_task_status_completed_adds_ended_at() {
        let q = mock_queue();
        q.set_task_status("task-1", "completed").await.unwrap();
        let raw = q.get_task_status("task-1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "completed");
        assert!(v.get("ended_at").is_some());
    }

    #[tokio::test]
    async fn set_task_status_failed_adds_ended_at() {
        let q = mock_queue();
        q.set_task_status("task-1", "failed").await.unwrap();
        let raw = q.get_task_status("task-1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "failed");
        assert!(v.get("ended_at").is_some());
    }

    #[tokio::test]
    async fn set_task_status_full_with_payload() {
        let q = mock_queue();
        let payload = serde_json::json!({"target": "192.168.58.1"});
        q.set_task_status_full(
            "task-1",
            "in_progress",
            "op-1",
            "scanner",
            "recon",
            Some(&payload),
        )
        .await
        .unwrap();

        let raw = q.get_task_status("task-1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "in_progress");
        assert_eq!(v["payload"]["target"], "192.168.58.1");
        assert!(v.get("started_at").is_some());
    }

    #[tokio::test]
    async fn get_task_status_returns_none_when_missing() {
        let q = mock_queue();
        assert!(q.get_task_status("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn task_message_serialization() {
        let msg = TaskMessage {
            task_id: "test_abc".to_string(),
            task_type: "recon".to_string(),
            source_agent: "orchestrator".to_string(),
            target_agent: "scanner".to_string(),
            payload: serde_json::json!({"host": "192.168.58.1"}),
            priority: 5,
            created_at: None,
            callback_queue: Some("ares.tasks.results.test_abc".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: TaskMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id, "test_abc");
        assert_eq!(parsed.priority, 5);
    }

    #[tokio::test]
    async fn task_result_serialization() {
        let result = TaskResult {
            task_id: "t1".to_string(),
            success: true,
            result: Some(serde_json::json!({"data": 42})),
            error: None,
            completed_at: Some(Utc::now()),
            worker_pod: Some("pod-1".to_string()),
            agent_name: Some("agent-1".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: TaskResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id, "t1");
        assert!(parsed.success);
        assert_eq!(parsed.worker_pod.as_deref(), Some("pod-1"));
    }

    #[tokio::test]
    async fn task_result_deserialization_defaults() {
        let json = r#"{"task_id":"t1","success":false,"completed_at":null}"#;
        let parsed: TaskResult = serde_json::from_str(json).unwrap();
        assert!(!parsed.success);
        assert!(parsed.result.is_none());
        assert!(parsed.error.is_none());
        assert!(parsed.worker_pod.is_none());
    }

    #[tokio::test]
    async fn heartbeat_data_serialization() {
        let hb = HeartbeatData {
            agent: "agent-1".to_string(),
            status: "idle".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            current_task: None,
            pod_name: Some("pod-x".to_string()),
        };
        let json = serde_json::to_string(&hb).unwrap();
        let parsed: HeartbeatData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent, "agent-1");
        assert!(parsed.current_task.is_none());
        assert_eq!(parsed.pod_name.as_deref(), Some("pod-x"));
    }

    #[tokio::test]
    async fn nats_required_for_queue_methods() {
        let q = mock_queue();
        let err = q
            .submit_task("recon", "scanner", serde_json::json!({}), "orch", 5)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn check_result_errors_without_nats() {
        let q = mock_queue();
        let err = q.check_result("t1").await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn check_results_batch_empty_returns_empty_map() {
        let q = mock_queue();
        let map = q.check_results_batch(&[]).await.unwrap();
        assert!(map.is_empty());
    }

    #[tokio::test]
    async fn check_results_batch_swallows_per_task_errors() {
        // Without NATS, each per-task fetch errors. The batch method logs
        // and treats those as None rather than propagating.
        let q = mock_queue();
        let ids = vec!["t1".to_string(), "t2".to_string(), "t3".to_string()];
        let map = q.check_results_batch(&ids).await.unwrap();
        assert_eq!(map.len(), 3);
        for id in &ids {
            assert!(map.contains_key(id));
            assert!(map.get(id).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn send_result_errors_without_nats() {
        let q = mock_queue();
        let r = TaskResult {
            task_id: "t1".into(),
            success: true,
            result: None,
            error: None,
            completed_at: Some(Utc::now()),
            worker_pod: None,
            agent_name: None,
        };
        let err = q.send_result("t1", &r).await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn publish_state_update_errors_without_nats() {
        let q = mock_queue();
        let err = q.publish_state_update("op-1").await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn nats_broker_is_none_for_mock_queue() {
        let q = mock_queue();
        assert!(q.nats_broker().is_none());
    }

    #[tokio::test]
    async fn connection_returns_independent_clone() {
        // The connection() accessor should hand back a clone the caller can
        // hold without invalidating the queue's own conn.
        let q = mock_queue();
        let mut c = q.connection();
        let _: () = c.set_ex::<_, _, ()>("x", "y", 30).await.unwrap();
        // queue still works after caller used the cloned conn
        q.set_task_status("after", "pending").await.unwrap();
        let raw = q.get_task_status("after").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "pending");
    }

    #[tokio::test]
    async fn set_task_status_pending_does_not_set_started_or_ended() {
        let q = mock_queue();
        q.set_task_status("t1", "pending").await.unwrap();
        let raw = q.get_task_status("t1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["status"], "pending");
        assert!(v.get("started_at").is_none());
        assert!(v.get("ended_at").is_none());
    }

    #[tokio::test]
    async fn set_task_status_in_progress_does_not_overwrite_started_at() {
        let q = mock_queue();
        // First in_progress sets started_at
        q.set_task_status("t1", "in_progress").await.unwrap();
        let raw1 = q.get_task_status("t1").await.unwrap().unwrap();
        let v1: serde_json::Value = serde_json::from_str(&raw1).unwrap();
        let started_first = v1["started_at"].as_str().unwrap().to_string();

        // sleep briefly so timestamps would differ
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Second in_progress preserves the original started_at
        q.set_task_status("t1", "in_progress").await.unwrap();
        let raw2 = q.get_task_status("t1").await.unwrap().unwrap();
        let v2: serde_json::Value = serde_json::from_str(&raw2).unwrap();
        assert_eq!(v2["started_at"].as_str().unwrap(), started_first);
        assert_ne!(v1["updated_at"], v2["updated_at"]);
    }

    #[tokio::test]
    async fn set_task_status_full_without_payload_omits_payload_field() {
        let q = mock_queue();
        q.set_task_status_full("t1", "pending", "op-1", "scanner", "recon", None)
            .await
            .unwrap();
        let raw = q.get_task_status("t1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(v.get("payload").is_none());
        assert!(v.get("started_at").is_none()); // pending != in_progress
    }

    #[tokio::test]
    async fn extend_lock_against_mock_redis_succeeds() {
        // Mock EXPIRE always reports success; this test pins the call shape
        // (i64 TTL conversion, Result<bool> return type).
        let q = mock_queue();
        let ok = q
            .extend_lock("op-1", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn try_acquire_lock_uses_separate_keys_per_operation() {
        let q = mock_queue();
        assert!(q
            .try_acquire_lock("op-a", Duration::from_secs(30))
            .await
            .unwrap());
        // Different op id is independent of op-a
        assert!(q
            .try_acquire_lock("op-b", Duration::from_secs(30))
            .await
            .unwrap());
    }

    #[test]
    fn task_message_default_priority_in_constants() {
        assert_eq!(default_priority(), 5);
    }

    #[test]
    fn task_message_serialize_includes_callback_queue() {
        let msg = TaskMessage {
            task_id: "t".into(),
            task_type: "recon".into(),
            source_agent: "orch".into(),
            target_agent: "scanner".into(),
            payload: serde_json::json!({}),
            priority: 5,
            created_at: None,
            callback_queue: Some("ares.tasks.results.t".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ares.tasks.results.t"));
    }

    #[test]
    fn task_subject_for_priority_routes_urgent_below_threshold() {
        // Priority ≤ 2 ⇒ urgent subject, otherwise the normal subject
        assert_eq!(
            task_subject_for_priority("scanner", 1),
            "ares.tasks.urgent.scanner"
        );
        assert_eq!(
            task_subject_for_priority("scanner", 2),
            "ares.tasks.urgent.scanner"
        );
        assert_eq!(
            task_subject_for_priority("scanner", 3),
            "ares.tasks.scanner"
        );
        assert_eq!(
            task_subject_for_priority("scanner", 5),
            "ares.tasks.scanner"
        );
        assert_eq!(
            task_subject_for_priority("scanner", 10),
            "ares.tasks.scanner"
        );
    }

    #[test]
    fn final_status_for_maps_success_flag() {
        assert_eq!(final_status_for(true), "completed");
        assert_eq!(final_status_for(false), "failed");
    }

    #[test]
    fn build_task_message_populates_callback_queue_with_result_subject() {
        let msg = build_task_message(
            "recon_abcdef123456",
            "recon",
            "scanner",
            serde_json::json!({"target": "192.168.58.10"}),
            "orchestrator",
            5,
        );
        assert_eq!(msg.task_id, "recon_abcdef123456");
        assert_eq!(msg.task_type, "recon");
        assert_eq!(msg.source_agent, "orchestrator");
        assert_eq!(msg.target_agent, "scanner");
        assert_eq!(msg.priority, 5);
        assert_eq!(
            msg.callback_queue.as_deref(),
            Some("ares.tasks.results.recon_abcdef123456"),
        );
        assert!(msg.created_at.is_some());
        assert_eq!(msg.payload["target"], "192.168.58.10");
    }

    #[test]
    fn build_task_message_preserves_priority_zero() {
        // Priority 0 is allowed (super urgent); make sure we don't clamp.
        let msg = build_task_message(
            "t",
            "exploit",
            "exploiter",
            serde_json::json!({}),
            "orch",
            0,
        );
        assert_eq!(msg.priority, 0);
    }

    #[test]
    fn build_task_message_serializes_round_trip_with_callback() {
        let msg = build_task_message(
            "lateral_xyz",
            "lateral_movement",
            "lateral",
            serde_json::json!({"host": "dc01"}),
            "orch",
            2,
        );
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ares.tasks.results.lateral_xyz"));
        let parsed: TaskMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.priority, 2);
        assert_eq!(parsed.task_type, "lateral_movement");
    }

    #[test]
    fn task_result_serializes_none_fields_as_null() {
        let r = TaskResult {
            task_id: "t".into(),
            success: true,
            result: None,
            error: None,
            completed_at: None,
            worker_pod: None,
            agent_name: None,
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert!(v["result"].is_null());
        assert!(v["error"].is_null());
        assert!(v["worker_pod"].is_null());
        assert!(v["agent_name"].is_null());
    }
}
