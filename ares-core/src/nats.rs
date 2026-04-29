//! NATS / JetStream broker integration for the Ares queue protocol.
//!
//! Replaces the Redis List + BRPOP work queue and per-call mailbox patterns:
//!
//! | Old Redis key                          | New NATS subject                 | Persistence  |
//! |----------------------------------------|----------------------------------|--------------|
//! | `ares:tasks:{role}`                    | `ares.tasks.{role}`              | JetStream    |
//! | `ares:results:{task_id}`               | NATS reply inbox (per request)   | core (sync)  |
//! | `ares:tool_exec:{role}`                | `ares.tools.exec.{role}`         | core         |
//! | `ares:tool_results:{call_id}`          | NATS reply inbox                 | core (sync)  |
//! | `ares:blue:tasks:global:{role}`        | `ares.blue.tasks.{role}`         | JetStream    |
//! | `ares:blue:results:{task_id}`          | NATS reply inbox                 | core (sync)  |
//! | `ares:deferred:{op}:{type}` (ZSET)     | `ares.deferred.{op}.{type}`      | JetStream KV |
//! | `ares:state:updates:{op}` (PUBLISH)    | `ares.state.updates.{op}`        | core         |
//!
//! Tool calls and result mailboxes use NATS request/reply, which removes the
//! "BRPOP needs a dedicated TCP connection" workaround in the Redis path
//! (a single multiplexed NATS connection handles arbitrary concurrent
//! request/reply pairs because each reply uses its own auto-generated inbox
//! subject).
//!
//! Work queues use JetStream with a pull consumer per worker role. Acks are
//! explicit and `max_deliver` triggers redelivery on worker crash, replacing
//! the silent message loss of `BRPOP`.

use std::time::Duration;

use anyhow::{Context, Result};
use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::stream::{Config as StreamConfig, RetentionPolicy, StorageType};
use async_nats::jetstream::{self, Context as JetStreamContext};
use async_nats::Client;
use tracing::{info, warn};

/// Default NATS URL used when neither `ARES_NATS_URL` nor an explicit URL is provided.
pub const DEFAULT_NATS_URL: &str = "nats://127.0.0.1:4222";

// === Subject taxonomy =====================================================

/// Red team task work queue. `ares.tasks.{role}` (e.g. `ares.tasks.recon`).
pub const TASK_SUBJECT_PREFIX: &str = "ares.tasks";
/// Tool dispatch RPC. `ares.tools.exec.{role}`.
pub const TOOL_EXEC_SUBJECT_PREFIX: &str = "ares.tools.exec";
/// Blue team task work queue. `ares.blue.tasks.{role}`.
pub const BLUE_TASK_SUBJECT_PREFIX: &str = "ares.blue.tasks";
/// Blue investigation request queue. `ares.blue.investigations`.
pub const BLUE_INVESTIGATION_SUBJECT: &str = "ares.blue.investigations";
/// Deferred (delayed re-dispatch) tasks. `ares.deferred.{op}.{type}`.
pub const DEFERRED_SUBJECT_PREFIX: &str = "ares.deferred";
/// State change notifications. `ares.state.updates.{op}` (core, fire-and-forget).
pub const STATE_UPDATE_SUBJECT_PREFIX: &str = "ares.state.updates";
/// Real-time discovery forwarding. `ares.discoveries.{op}`.
pub const DISCOVERY_SUBJECT_PREFIX: &str = "ares.discoveries";
/// Per-task result subject. `ares.tasks.results.{task_id}`.
/// Lives on the `ARES_TASKS` stream so results survive orchestrator restart.
pub const TASK_RESULT_SUBJECT_PREFIX: &str = "ares.tasks.results";
/// Urgent task subject (priority ≤ 2). `ares.tasks.urgent.{role}`.
pub const URGENT_TASK_SUBJECT_PREFIX: &str = "ares.tasks.urgent";
/// Blue task result subject. `ares.blue.tasks.results.{task_id}`.
pub const BLUE_TASK_RESULT_SUBJECT_PREFIX: &str = "ares.blue.tasks.results";

// === Stream names =========================================================

/// JetStream stream containing all red-team task subjects.
pub const TASKS_STREAM: &str = "ARES_TASKS";
/// JetStream stream containing all blue-team task subjects.
pub const BLUE_TASKS_STREAM: &str = "ARES_BLUE_TASKS";
/// JetStream stream containing deferred-task subjects.
pub const DEFERRED_STREAM: &str = "ARES_DEFERRED";
/// JetStream stream containing real-time discoveries.
pub const DISCOVERIES_STREAM: &str = "ARES_DISCOVERIES";

// === Subject builders =====================================================

#[inline]
pub fn task_subject(role: &str) -> String {
    format!("{TASK_SUBJECT_PREFIX}.{role}")
}

#[inline]
pub fn urgent_task_subject(role: &str) -> String {
    format!("{URGENT_TASK_SUBJECT_PREFIX}.{role}")
}

#[inline]
pub fn task_result_subject(task_id: &str) -> String {
    format!("{TASK_RESULT_SUBJECT_PREFIX}.{task_id}")
}

#[inline]
pub fn blue_task_result_subject(task_id: &str) -> String {
    format!("{BLUE_TASK_RESULT_SUBJECT_PREFIX}.{task_id}")
}

#[inline]
pub fn tool_exec_subject(role: &str) -> String {
    format!("{TOOL_EXEC_SUBJECT_PREFIX}.{role}")
}

#[inline]
pub fn blue_task_subject(role: &str) -> String {
    format!("{BLUE_TASK_SUBJECT_PREFIX}.{role}")
}

#[inline]
pub fn deferred_subject(operation_id: &str, task_type: &str) -> String {
    format!("{DEFERRED_SUBJECT_PREFIX}.{operation_id}.{task_type}")
}

#[inline]
pub fn state_update_subject(operation_id: &str) -> String {
    format!("{STATE_UPDATE_SUBJECT_PREFIX}.{operation_id}")
}

#[inline]
pub fn discovery_subject(operation_id: &str) -> String {
    format!("{DISCOVERY_SUBJECT_PREFIX}.{operation_id}")
}

// === Connection ===========================================================

/// Shared NATS broker handle.
///
/// `async_nats::Client` is already cheaply cloneable and multiplexes all
/// subscriptions and requests over a single TCP connection — we just keep
/// the JetStream context alongside it for convenience.
#[derive(Clone)]
pub struct NatsBroker {
    client: Client,
    jetstream: JetStreamContext,
}

impl NatsBroker {
    /// Connect to NATS at the given URL (e.g. `nats://nats.attack-simulation.svc:4222`).
    pub async fn connect(url: &str) -> Result<Self> {
        let client = async_nats::connect(url)
            .await
            .with_context(|| format!("Failed to connect to NATS at {url}"))?;
        let jetstream = jetstream::new(client.clone());
        info!(url, "Connected to NATS");
        Ok(Self { client, jetstream })
    }

    /// Resolve URL from `ARES_NATS_URL` then `NATS_URL`, falling back to localhost.
    pub fn url_from_env() -> String {
        std::env::var("ARES_NATS_URL")
            .or_else(|_| std::env::var("NATS_URL"))
            .unwrap_or_else(|_| DEFAULT_NATS_URL.to_string())
    }

    /// Connect using `ARES_NATS_URL` / `NATS_URL` / default.
    pub async fn connect_from_env() -> Result<Self> {
        Self::connect(&Self::url_from_env()).await
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn jetstream(&self) -> &JetStreamContext {
        &self.jetstream
    }

    /// Ensure the standard Ares streams exist with sensible defaults.
    ///
    /// Idempotent — safe to call from every process on startup. The
    /// orchestrator typically calls this; workers can rely on the stream
    /// already existing but calling again is harmless.
    pub async fn ensure_streams(&self) -> Result<()> {
        self.ensure_stream(StreamSpec::tasks()).await?;
        self.ensure_stream(StreamSpec::blue_tasks()).await?;
        self.ensure_stream(StreamSpec::deferred()).await?;
        self.ensure_stream(StreamSpec::discoveries()).await?;
        Ok(())
    }

    /// Create or update a single stream.
    pub async fn ensure_stream(&self, spec: StreamSpec) -> Result<()> {
        match self.jetstream.get_or_create_stream(spec.to_config()).await {
            Ok(_) => {
                info!(stream = spec.name, "JetStream ready");
                Ok(())
            }
            Err(e) => {
                warn!(stream = spec.name, err = %e, "Failed to create/get stream");
                Err(anyhow::anyhow!(
                    "JetStream stream {} unavailable: {e}",
                    spec.name
                ))
            }
        }
    }

    /// Ensure a durable pull consumer exists on the given stream + filter.
    ///
    /// Returns the consumer name. Idempotent on repeated calls with the same
    /// configuration.
    pub async fn ensure_pull_consumer(
        &self,
        stream: &str,
        durable_name: &str,
        filter_subject: &str,
    ) -> Result<String> {
        let stream_handle = self
            .jetstream
            .get_stream(stream)
            .await
            .with_context(|| format!("get_stream({stream})"))?;

        let cfg = PullConfig {
            durable_name: Some(durable_name.to_string()),
            filter_subject: filter_subject.to_string(),
            ack_policy: AckPolicy::Explicit,
            ack_wait: Duration::from_secs(60 * 30), // tools can take minutes
            max_deliver: 5,                         // bounded redelivery on worker crash
            ..Default::default()
        };

        stream_handle
            .get_or_create_consumer(durable_name, cfg)
            .await
            .with_context(|| format!("ensure consumer {durable_name} on {stream}"))?;
        Ok(durable_name.to_string())
    }
}

/// Stream definition. One per logical broker workload.
pub struct StreamSpec {
    pub name: &'static str,
    pub subjects: Vec<String>,
    pub max_age: Duration,
    pub storage: StorageType,
}

impl StreamSpec {
    /// Red team task queue stream.
    pub fn tasks() -> Self {
        Self {
            name: TASKS_STREAM,
            subjects: vec![format!("{TASK_SUBJECT_PREFIX}.>")],
            max_age: Duration::from_secs(60 * 60 * 24), // 24h
            storage: StorageType::File,
        }
    }

    /// Blue team task queue stream.
    pub fn blue_tasks() -> Self {
        Self {
            name: BLUE_TASKS_STREAM,
            subjects: vec![
                format!("{BLUE_TASK_SUBJECT_PREFIX}.>"),
                BLUE_INVESTIGATION_SUBJECT.to_string(),
            ],
            max_age: Duration::from_secs(60 * 60 * 24),
            storage: StorageType::File,
        }
    }

    /// Deferred-task stream. Messages here carry a `Nats-Expected-Stream`-
    /// independent delay; consumers fetch and re-publish to the live
    /// `ares.tasks.{role}` subject when their deadline arrives.
    pub fn deferred() -> Self {
        Self {
            name: DEFERRED_STREAM,
            subjects: vec![format!("{DEFERRED_SUBJECT_PREFIX}.>")],
            max_age: Duration::from_secs(60 * 60 * 6), // shorter — deferred tasks are short-lived
            storage: StorageType::File,
        }
    }

    /// Real-time discovery forwarding stream.
    pub fn discoveries() -> Self {
        Self {
            name: DISCOVERIES_STREAM,
            subjects: vec![format!("{DISCOVERY_SUBJECT_PREFIX}.>")],
            max_age: Duration::from_secs(60 * 60 * 12),
            storage: StorageType::File,
        }
    }

    fn to_config(&self) -> StreamConfig {
        StreamConfig {
            name: self.name.to_string(),
            subjects: self.subjects.clone(),
            retention: RetentionPolicy::WorkQueue,
            max_age: self.max_age,
            storage: self.storage,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_subject_format() {
        assert_eq!(task_subject("recon"), "ares.tasks.recon");
        assert_eq!(task_subject("lateral"), "ares.tasks.lateral");
    }

    #[test]
    fn tool_exec_subject_format() {
        assert_eq!(tool_exec_subject("recon"), "ares.tools.exec.recon");
    }

    #[test]
    fn blue_task_subject_format() {
        assert_eq!(blue_task_subject("triage"), "ares.blue.tasks.triage");
    }

    #[test]
    fn deferred_subject_format() {
        assert_eq!(
            deferred_subject("op-1", "recon"),
            "ares.deferred.op-1.recon"
        );
    }

    #[test]
    fn state_update_subject_format() {
        assert_eq!(state_update_subject("op-1"), "ares.state.updates.op-1");
    }

    #[test]
    fn discovery_subject_format() {
        assert_eq!(discovery_subject("op-1"), "ares.discoveries.op-1");
    }

    #[test]
    fn url_from_env_default() {
        // Must not panic when neither var is set; we don't assert exact value
        // because the test environment may have one set.
        let url = NatsBroker::url_from_env();
        assert!(!url.is_empty());
    }

    #[test]
    fn tasks_stream_spec_covers_all_roles() {
        let spec = StreamSpec::tasks();
        assert_eq!(spec.name, "ARES_TASKS");
        assert_eq!(spec.subjects, vec!["ares.tasks.>"]);
    }

    #[test]
    fn blue_tasks_stream_includes_investigation_subject() {
        let spec = StreamSpec::blue_tasks();
        assert_eq!(spec.name, "ARES_BLUE_TASKS");
        assert!(spec
            .subjects
            .iter()
            .any(|s| s == "ares.blue.investigations"));
        assert!(spec.subjects.iter().any(|s| s == "ares.blue.tasks.>"));
    }

    #[test]
    fn deferred_stream_subject_pattern() {
        let spec = StreamSpec::deferred();
        assert_eq!(spec.subjects, vec!["ares.deferred.>"]);
    }

    #[test]
    fn discoveries_stream_subject_pattern() {
        let spec = StreamSpec::discoveries();
        assert_eq!(spec.subjects, vec!["ares.discoveries.>"]);
    }
}
