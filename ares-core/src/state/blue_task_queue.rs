//! Blue team task queue.
//!
//! Hybrid Redis + NATS JetStream. Queues live on JetStream; heartbeats and
//! investigation registration stay on Redis.
//!
//! NATS subjects:
//!   - `ares.blue.tasks.{role}`              global per-role work queue
//!   - `ares.blue.tasks.results.{task_id}`   durable per-task result subject
//!   - `ares.blue.investigations`            investigation request queue
//!
//! Redis keys (state only):
//!   - `ares:blue:heartbeat:{agent}`         agent heartbeat (TTL 60s)
//!   - `ares:blue:active_investigations`     SET of active investigation IDs
//!   - `ares:blue:inv:{id}:queue_meta`       investigation metadata (HASH)

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use redis::aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::nats::{self, NatsBroker};

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

/// Blue team task queue — NATS for queues, Redis for state.
///
/// Generic over the Redis backend so unit tests can use a mock; `nats` is
/// `None` in tests that don't exercise queue methods.
pub struct BlueTaskQueueCore<C> {
    conn: C,
    nats: Option<NatsBroker>,
}

/// Production blue team task queue.
pub type BlueTaskQueue = BlueTaskQueueCore<ConnectionManager>;

impl BlueTaskQueue {
    /// Connect to Redis only (state methods work, queue methods will error).
    /// Used by callers that only need heartbeat/investigation registration.
    pub async fn connect(redis_url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let config =
            ConnectionManagerConfig::new().set_response_timeout(Some(Duration::from_secs(30)));
        let conn = client.get_connection_manager_with_config(config).await?;
        Ok(Self { conn, nats: None })
    }

    /// Connect to both Redis (state) and NATS (queues).
    pub async fn connect_with_nats(redis_url: &str, nats_url: &str) -> anyhow::Result<Self> {
        let mut q = Self::connect(redis_url).await?;
        let nats = NatsBroker::connect(nats_url).await?;
        nats.ensure_streams().await?;
        q.nats = Some(nats);
        Ok(q)
    }

    pub fn from_conn(conn: ConnectionManager) -> Self {
        Self { conn, nats: None }
    }

    pub fn from_parts(conn: ConnectionManager, nats: NatsBroker) -> Self {
        Self {
            conn,
            nats: Some(nats),
        }
    }

    pub fn conn_mut(&mut self) -> &mut ConnectionManager {
        &mut self.conn
    }
}

/// Serialize a [`BlueTaskMessage`] into the `(subject, payload)` pair that
/// [`BlueTaskQueueCore::submit_task`] hands to JetStream. Pulled out as a
/// free function so the wire shape can be unit-tested without a broker.
pub(crate) fn prepare_blue_task_publish(task: &BlueTaskMessage) -> Result<(String, Bytes)> {
    let subject = nats::blue_task_subject(&task.role);
    let bytes = Bytes::from(serde_json::to_vec(task).context("serialize BlueTaskMessage")?);
    Ok((subject, bytes))
}

/// Serialize a [`BlueTaskResult`] into the `(subject, payload)` pair that
/// [`BlueTaskQueueCore::send_result`] hands to JetStream.
pub(crate) fn prepare_blue_result_publish(result: &BlueTaskResult) -> Result<(String, Bytes)> {
    let subject = nats::blue_task_result_subject(&result.task_id);
    let bytes = Bytes::from(serde_json::to_vec(result).context("serialize BlueTaskResult")?);
    Ok((subject, bytes))
}

/// Parse a JetStream message payload into a [`BlueTaskMessage`].
pub(crate) fn parse_blue_task_payload(payload: &[u8], subject: &str) -> Result<BlueTaskMessage> {
    serde_json::from_slice(payload)
        .with_context(|| format!("Bad BlueTaskMessage JSON on {subject}"))
}

/// Parse a JetStream message payload into a [`BlueTaskResult`].
pub(crate) fn parse_blue_result_payload(payload: &[u8], task_id: &str) -> Result<BlueTaskResult> {
    serde_json::from_slice(payload)
        .with_context(|| format!("Bad BlueTaskResult JSON for {task_id}"))
}

impl<C: ConnectionLike + Clone + Send + Sync + 'static> BlueTaskQueueCore<C> {
    /// Construct from a Redis backend only — used by unit tests that don't
    /// exercise queue methods. Queue methods will return an error.
    pub fn from_connection(conn: C) -> Self {
        Self { conn, nats: None }
    }

    fn nats(&self) -> Result<&NatsBroker> {
        self.nats
            .as_ref()
            .context("BlueTaskQueue has no NATS broker configured")
    }

    // === Queue methods (NATS JetStream) =====================================

    /// Submit a task to the global role queue.
    pub async fn submit_task(&mut self, task: &BlueTaskMessage) -> anyhow::Result<()> {
        let (subject, bytes) = prepare_blue_task_publish(task)?;

        debug!(
            task_id = %task.task_id,
            role = %task.role,
            task_type = %task.task_type,
            "submitting blue team task"
        );

        let ack = self
            .nats()?
            .jetstream()
            .publish(subject.clone(), bytes)
            .await
            .with_context(|| format!("JetStream publish to {subject}"))?;
        ack.await
            .with_context(|| format!("Awaiting JetStream ack for {subject}"))?;
        Ok(())
    }

    /// Poll for a task from the global role queue (blocking up to `timeout_secs`).
    pub async fn poll_global_task(
        &mut self,
        role: &str,
        timeout_secs: f64,
    ) -> anyhow::Result<Option<BlueTaskMessage>> {
        let nats = self.nats()?;
        let subject = nats::blue_task_subject(role);
        let consumer_name = format!("blue-tasks-{role}");
        nats.ensure_pull_consumer(nats::BLUE_TASKS_STREAM, &consumer_name, &subject)
            .await?;

        let stream = nats.jetstream().get_stream(nats::BLUE_TASKS_STREAM).await?;
        let consumer = stream
            .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&consumer_name)
            .await
            .map_err(|e| anyhow::anyhow!("get_consumer({consumer_name}): {e}"))?;

        let timeout = Duration::from_secs_f64(timeout_secs.max(0.05));
        let mut fetch = consumer
            .fetch()
            .max_messages(1)
            .expires(timeout)
            .messages()
            .await
            .context("start fetch")?;

        match fetch.next().await {
            Some(Ok(m)) => {
                let task = parse_blue_task_payload(&m.payload, &subject)?;
                m.ack().await.map_err(|e| anyhow::anyhow!("ack: {e}")).ok();
                Ok(Some(task))
            }
            Some(Err(e)) => Err(anyhow::anyhow!("JetStream fetch error: {e}")),
            None => Ok(None),
        }
    }

    /// Send a task result to its dedicated result subject.
    pub async fn send_result(&mut self, result: &BlueTaskResult) -> anyhow::Result<()> {
        let (subject, bytes) = prepare_blue_result_publish(result)?;

        let ack = self
            .nats()?
            .jetstream()
            .publish(subject.clone(), bytes)
            .await
            .with_context(|| format!("JetStream publish to {subject}"))?;
        ack.await
            .with_context(|| format!("Awaiting ack for {subject}"))?;
        Ok(())
    }

    /// Wait for a task result (blocking).
    pub async fn wait_for_result(
        &mut self,
        task_id: &str,
        timeout_secs: f64,
    ) -> anyhow::Result<Option<BlueTaskResult>> {
        self.fetch_result(task_id, Duration::from_secs_f64(timeout_secs.max(0.0)))
            .await
    }

    /// Check for a result without blocking.
    pub async fn check_result(&mut self, task_id: &str) -> anyhow::Result<Option<BlueTaskResult>> {
        self.fetch_result(task_id, Duration::from_millis(100)).await
    }

    async fn fetch_result(
        &mut self,
        task_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<Option<BlueTaskResult>> {
        use async_nats::jetstream::consumer::pull::Config as PullConfig;
        use async_nats::jetstream::consumer::AckPolicy;

        let nats = self.nats()?;
        let stream = nats.jetstream().get_stream(nats::BLUE_TASKS_STREAM).await?;

        let cfg = PullConfig {
            filter_subject: nats::blue_task_result_subject(task_id),
            ack_policy: AckPolicy::Explicit,
            inactive_threshold: Duration::from_secs(60),
            ..Default::default()
        };

        let consumer = stream
            .create_consumer(cfg)
            .await
            .context("create ephemeral blue result consumer")?;

        let mut fetch = consumer
            .fetch()
            .max_messages(1)
            .expires(timeout.max(Duration::from_millis(50)))
            .messages()
            .await
            .context("start fetch")?;

        match fetch.next().await {
            Some(Ok(m)) => {
                let parsed = parse_blue_result_payload(&m.payload, task_id)?;
                m.ack().await.map_err(|e| anyhow::anyhow!("ack: {e}")).ok();
                Ok(Some(parsed))
            }
            Some(Err(e)) => Err(anyhow::anyhow!("JetStream fetch error: {e}")),
            None => Ok(None),
        }
    }

    /// Pop an investigation request from the queue.
    pub async fn pop_investigation_request(
        &mut self,
        timeout_secs: f64,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let nats = self.nats()?;
        let consumer_name = "blue-investigations";
        nats.ensure_pull_consumer(
            nats::BLUE_TASKS_STREAM,
            consumer_name,
            nats::BLUE_INVESTIGATION_SUBJECT,
        )
        .await?;

        let stream = nats.jetstream().get_stream(nats::BLUE_TASKS_STREAM).await?;
        let consumer = stream
            .get_consumer::<async_nats::jetstream::consumer::pull::Config>(consumer_name)
            .await
            .map_err(|e| anyhow::anyhow!("get_consumer({consumer_name}): {e}"))?;

        let timeout = Duration::from_secs_f64(timeout_secs.max(0.05));
        let mut fetch = consumer
            .fetch()
            .max_messages(1)
            .expires(timeout)
            .messages()
            .await
            .context("start fetch")?;

        match fetch.next().await {
            Some(Ok(m)) => {
                match serde_json::from_slice::<serde_json::Value>(&m.payload) {
                    Ok(val) => {
                        m.ack().await.map_err(|e| anyhow::anyhow!("ack: {e}")).ok();
                        Ok(Some(val))
                    }
                    Err(e) => {
                        warn!("Failed to parse investigation request: {e}");
                        // Ack and skip the malformed message
                        m.ack().await.map_err(|e| anyhow::anyhow!("ack: {e}")).ok();
                        Ok(None)
                    }
                }
            }
            Some(Err(e)) => Err(anyhow::anyhow!("JetStream fetch error: {e}")),
            None => Ok(None),
        }
    }

    /// Submit an investigation request via the supplied NATS broker. No Redis
    /// connection required — used by CLI submission paths (`ares blue submit`,
    /// `ares blue from-operation`, auto-submit) which only need to publish.
    pub async fn submit_investigation_request(
        broker: &NatsBroker,
        request: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let bytes = Bytes::from(serde_json::to_vec(request).context("serialize request")?);
        let ack = broker
            .jetstream()
            .publish(nats::BLUE_INVESTIGATION_SUBJECT, bytes)
            .await
            .with_context(|| {
                format!("JetStream publish to {}", nats::BLUE_INVESTIGATION_SUBJECT)
            })?;
        ack.await.context("ack investigation request")?;
        Ok(())
    }

    /// Get the global role queue length (best-effort; returns total stream depth).
    pub async fn queue_length(&mut self, _role: &str) -> anyhow::Result<usize> {
        let stream = self
            .nats()?
            .jetstream()
            .get_stream(nats::BLUE_TASKS_STREAM)
            .await?;
        let info = stream.cached_info();
        Ok(info.state.messages as usize)
    }

    // === Redis-backed state methods ========================================

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
        let _: () = self
            .conn
            .sadd(BLUE_ACTIVE_INVESTIGATIONS, investigation_id)
            .await?;
        let _: () = self.conn.expire(BLUE_ACTIVE_INVESTIGATIONS, 86400).await?;

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

        info!(investigation_id, "Investigation registered as active");
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> BlueTaskQueueCore<MockRedisConnection> {
        BlueTaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[test]
    fn success_sets_success_true_and_stores_result() {
        let result_payload = serde_json::json!({"found": 42});
        let r = BlueTaskResult::success("task-1", "inv-1", result_payload.clone(), "agent-alpha");
        assert!(r.success);
        assert_eq!(r.task_id, "task-1");
        assert_eq!(r.investigation_id, "inv-1");
        assert_eq!(r.result, Some(result_payload));
        assert!(r.error.is_none());
        assert_eq!(r.worker_agent.as_deref(), Some("agent-alpha"));
    }

    #[test]
    fn failure_sets_success_false_and_stores_error() {
        let r = BlueTaskResult::failure(
            "task-2",
            "inv-2",
            "connection timeout".to_string(),
            "agent-beta",
        );
        assert!(!r.success);
        assert_eq!(r.task_id, "task-2");
        assert_eq!(r.investigation_id, "inv-2");
        assert!(r.result.is_none());
        assert_eq!(r.error.as_deref(), Some("connection timeout"));
        assert_eq!(r.worker_agent.as_deref(), Some("agent-beta"));
    }

    #[test]
    fn completed_at_is_populated_by_both_constructors() {
        let success = BlueTaskResult::success("t", "i", serde_json::Value::Null, "a");
        let failure = BlueTaskResult::failure("t", "i", "err".to_string(), "a");

        assert!(!success.completed_at.is_empty());
        assert!(!failure.completed_at.is_empty());
        assert!(chrono::DateTime::parse_from_rfc3339(&success.completed_at).is_ok());
        assert!(chrono::DateTime::parse_from_rfc3339(&failure.completed_at).is_ok());
    }

    #[test]
    fn blue_task_message_serialization_roundtrip() {
        let msg = BlueTaskMessage {
            task_id: "btask-1".into(),
            investigation_id: "inv-1".into(),
            task_type: "log_search".into(),
            role: "triage".into(),
            params: serde_json::json!({"query": "alertname=Foo"}),
            created_at: "2026-04-29T20:00:00Z".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: BlueTaskMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id, "btask-1");
        assert_eq!(parsed.investigation_id, "inv-1");
        assert_eq!(parsed.role, "triage");
        assert_eq!(parsed.params["query"], "alertname=Foo");
    }

    #[test]
    fn blue_task_result_skips_none_fields_in_serialization() {
        let r = BlueTaskResult::success("t", "i", serde_json::json!({"ok": true}), "a");
        let json = serde_json::to_string(&r).unwrap();
        // error is None and has skip_serializing_if
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn blue_task_result_failure_omits_result_field() {
        let r = BlueTaskResult::failure("t", "i", "boom".into(), "a");
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"result\""));
        assert!(json.contains("\"error\""));
    }

    #[tokio::test]
    async fn send_heartbeat_roundtrip() {
        let mut q = mock_queue();
        q.send_heartbeat("blue-agent-1", "idle", None, "triage", None)
            .await
            .unwrap();

        let hb = q
            .get_heartbeat("blue-agent-1")
            .await
            .unwrap()
            .expect("heartbeat present");
        assert_eq!(hb["status"], "idle");
        assert_eq!(hb["role"], "triage");
        assert!(hb["current_task"].is_null());
        assert!(hb["timestamp"].is_string());
    }

    #[tokio::test]
    async fn send_heartbeat_with_current_task_and_investigation() {
        let mut q = mock_queue();
        q.send_heartbeat(
            "blue-agent-2",
            "busy",
            Some("btask-9"),
            "log_analyst",
            Some("inv-42"),
        )
        .await
        .unwrap();

        let hb = q.get_heartbeat("blue-agent-2").await.unwrap().unwrap();
        assert_eq!(hb["status"], "busy");
        assert_eq!(hb["current_task"], "btask-9");
        assert_eq!(hb["investigation_id"], "inv-42");
    }

    #[tokio::test]
    async fn get_heartbeat_returns_none_when_missing() {
        let mut q = mock_queue();
        assert!(q.get_heartbeat("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn register_investigation_then_discover() {
        let mut q = mock_queue();
        let alert = serde_json::json!({"alertname": "SuspiciousLogon"});
        q.register_investigation("inv-100", &alert, "openai/gpt-4.1-mini")
            .await
            .unwrap();

        let active = q.discover_active_investigation().await.unwrap();
        assert_eq!(active.as_deref(), Some("inv-100"));
    }

    #[tokio::test]
    async fn discover_active_investigation_returns_none_when_empty() {
        let mut q = mock_queue();
        assert!(q.discover_active_investigation().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_investigation_alert_returns_registered_alert() {
        let mut q = mock_queue();
        let alert = serde_json::json!({
            "alertname": "FailedLogons",
            "severity": "high",
        });
        q.register_investigation("inv-200", &alert, "openai/gpt-4.1-mini")
            .await
            .unwrap();

        let stored = q.get_investigation_alert("inv-200").await.unwrap().unwrap();
        assert_eq!(stored["alertname"], "FailedLogons");
        assert_eq!(stored["severity"], "high");
    }

    #[tokio::test]
    async fn get_investigation_alert_returns_none_for_unknown_id() {
        let mut q = mock_queue();
        assert!(q
            .get_investigation_alert("nonexistent")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn get_investigation_model_returns_registered_model() {
        let mut q = mock_queue();
        q.register_investigation(
            "inv-300",
            &serde_json::json!({}),
            "anthropic/claude-sonnet-4-5",
        )
        .await
        .unwrap();

        let model = q.get_investigation_model("inv-300").await.unwrap();
        assert_eq!(model.as_deref(), Some("anthropic/claude-sonnet-4-5"));
    }

    #[tokio::test]
    async fn get_investigation_model_returns_none_for_unknown_id() {
        let mut q = mock_queue();
        assert!(q
            .get_investigation_model("nonexistent")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn submit_task_errors_when_no_nats_configured() {
        let mut q = mock_queue();
        let task = BlueTaskMessage {
            task_id: "t".into(),
            investigation_id: "i".into(),
            task_type: "log_search".into(),
            role: "triage".into(),
            params: serde_json::json!({}),
            created_at: "2026-04-29T00:00:00Z".into(),
        };
        let err = q.submit_task(&task).await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn poll_global_task_errors_when_no_nats_configured() {
        let mut q = mock_queue();
        let err = q.poll_global_task("triage", 1.0).await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn send_result_errors_when_no_nats_configured() {
        let mut q = mock_queue();
        let r = BlueTaskResult::success("t", "i", serde_json::Value::Null, "a");
        let err = q.send_result(&r).await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn check_result_errors_when_no_nats_configured() {
        let mut q = mock_queue();
        let err = q.check_result("t").await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn pop_investigation_request_errors_when_no_nats_configured() {
        let mut q = mock_queue();
        let err = q.pop_investigation_request(1.0).await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    #[tokio::test]
    async fn queue_length_errors_when_no_nats_configured() {
        let mut q = mock_queue();
        let err = q.queue_length("triage").await.unwrap_err();
        assert!(err.to_string().contains("NATS"));
    }

    fn sample_task() -> BlueTaskMessage {
        BlueTaskMessage {
            task_id: "btask-1".into(),
            investigation_id: "inv-1".into(),
            task_type: "log_search".into(),
            role: "triage".into(),
            params: serde_json::json!({"q": "alertname=Foo"}),
            created_at: "2026-04-29T20:00:00Z".into(),
        }
    }

    #[test]
    fn prepare_blue_task_publish_uses_role_subject_and_full_message() {
        let task = sample_task();
        let (subject, bytes) = prepare_blue_task_publish(&task).unwrap();
        assert_eq!(subject, "ares.blue.tasks.triage");
        let parsed: BlueTaskMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.task_id, "btask-1");
        assert_eq!(parsed.investigation_id, "inv-1");
        assert_eq!(parsed.role, "triage");
        assert_eq!(parsed.params["q"], "alertname=Foo");
    }

    #[test]
    fn prepare_blue_task_publish_subject_changes_with_role() {
        let mut t = sample_task();
        t.role = "log_analyst".into();
        let (subject, _) = prepare_blue_task_publish(&t).unwrap();
        assert_eq!(subject, "ares.blue.tasks.log_analyst");
    }

    #[test]
    fn prepare_blue_result_publish_uses_task_result_subject() {
        let r = BlueTaskResult::success(
            "btask-9",
            "inv-1",
            serde_json::json!({"hits": 3}),
            "agent-x",
        );
        let (subject, bytes) = prepare_blue_result_publish(&r).unwrap();
        assert_eq!(subject, "ares.blue.tasks.results.btask-9");
        let parsed: BlueTaskResult = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.task_id, "btask-9");
        assert_eq!(parsed.result.unwrap()["hits"], 3);
    }

    #[test]
    fn prepare_blue_result_publish_uses_distinct_subject_per_task_id() {
        let a = BlueTaskResult::failure("a", "inv-1", "err".into(), "agent");
        let b = BlueTaskResult::failure("b", "inv-1", "err".into(), "agent");
        let (sa, _) = prepare_blue_result_publish(&a).unwrap();
        let (sb, _) = prepare_blue_result_publish(&b).unwrap();
        assert_ne!(sa, sb);
        assert!(sa.ends_with(".a"));
        assert!(sb.ends_with(".b"));
    }

    #[test]
    fn parse_blue_task_payload_round_trips_a_published_message() {
        let task = sample_task();
        let (subject, bytes) = prepare_blue_task_publish(&task).unwrap();
        let parsed = parse_blue_task_payload(&bytes, &subject).unwrap();
        assert_eq!(parsed.task_id, task.task_id);
        assert_eq!(parsed.role, task.role);
    }

    #[test]
    fn parse_blue_task_payload_surfaces_subject_in_context_on_error() {
        let err = parse_blue_task_payload(b"not json", "ares.blue.tasks.triage").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ares.blue.tasks.triage"), "got {msg}");
    }

    #[test]
    fn parse_blue_result_payload_round_trips_a_published_result() {
        let r = BlueTaskResult::success("btask-1", "inv-1", serde_json::json!({"x": 1}), "agent");
        let (_, bytes) = prepare_blue_result_publish(&r).unwrap();
        let parsed = parse_blue_result_payload(&bytes, "btask-1").unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.task_id, "btask-1");
    }

    #[test]
    fn parse_blue_result_payload_surfaces_task_id_in_context_on_error() {
        let err = parse_blue_result_payload(b"garbage", "btask-7").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("btask-7"), "got {msg}");
    }
}
