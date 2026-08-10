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
use async_nats::header::{HeaderMap, NATS_EXPECTED_LAST_SUBJECT_SEQUENCE, NATS_MESSAGE_ID};
use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::context::{PublishError, PublishErrorKind};
use async_nats::jetstream::stream::{
    Config as StreamConfig, DiscardPolicy, RetentionPolicy, StorageType,
};
use async_nats::jetstream::{self, Context as JetStreamContext};
use async_nats::Client;
use tracing::{info, warn};

use crate::models::OpStateEvent;

/// Default NATS URL used when neither `ARES_NATS_URL` nor an explicit URL is provided.
pub const DEFAULT_NATS_URL: &str = "nats://127.0.0.1:4222";

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
/// Operation state event log. `ares.ops.{op_id}.{entity}.{action}`.
/// Backed by [`OP_STATE_STREAM`]; the durable source of truth for live op state.
pub const OP_STATE_SUBJECT_PREFIX: &str = "ares.ops";
/// Per-task result subject. `ares.tasks.results.{task_id}`.
/// Lives on the `ARES_TASKS` stream so results survive orchestrator restart.
pub const TASK_RESULT_SUBJECT_PREFIX: &str = "ares.tasks.results";
/// Urgent task subject (priority ≤ 2). `ares.tasks.urgent.{role}`.
pub const URGENT_TASK_SUBJECT_PREFIX: &str = "ares.tasks.urgent";
/// Blue task result subject. `ares.blue.tasks.results.{task_id}`.
pub const BLUE_TASK_RESULT_SUBJECT_PREFIX: &str = "ares.blue.tasks.results";

/// JetStream stream containing all red-team task subjects.
pub const TASKS_STREAM: &str = "ARES_TASKS";
/// JetStream stream containing all blue-team task subjects.
pub const BLUE_TASKS_STREAM: &str = "ARES_BLUE_TASKS";
/// JetStream stream containing deferred-task subjects.
pub const DEFERRED_STREAM: &str = "ARES_DEFERRED";
/// JetStream stream containing real-time discoveries.
pub const DISCOVERIES_STREAM: &str = "ARES_DISCOVERIES";
/// JetStream stream containing the durable operation state event log.
/// Pattern B: this is the source of truth, Redis is a derived cache.
pub const OP_STATE_STREAM: &str = "ARES_OPSTATE";

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

/// Build the op-state subject for a given operation and entity-action suffix
/// (e.g. `cred.captured`). Suffix typically comes from
/// [`crate::models::OpStateEvent::subject_suffix`].
#[inline]
pub fn op_state_subject(operation_id: &str, suffix: &str) -> String {
    format!("{OP_STATE_SUBJECT_PREFIX}.{operation_id}.{suffix}")
}

/// Subject filter that matches every op-state event for a single operation.
#[inline]
pub fn op_state_filter_for_op(operation_id: &str) -> String {
    format!("{OP_STATE_SUBJECT_PREFIX}.{operation_id}.>")
}

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
        // Default async_nats request_timeout is 10s — far too short for
        // long-running tool dispatches (nmap full-port, secretsdump DRSUAPI,
        // ESC8 relay chains, AES Kerberoast). Keep this above the orchestrator's
        // outer tool-dispatch timeout so the NATS client's internal deadline is
        // not the first one to fire.
        let request_timeout_secs = std::env::var("ARES_NATS_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(6000);
        let client = async_nats::ConnectOptions::new()
            .request_timeout(Some(std::time::Duration::from_secs(request_timeout_secs)))
            .connect(url)
            .await
            .with_context(|| format!("Failed to connect to NATS at {url}"))?;
        let jetstream = jetstream::new(client.clone());
        info!(url, request_timeout_secs, "Connected to NATS");
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
        self.ensure_stream(StreamSpec::op_state()).await?;
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

    /// Publish an [`OpStateEvent`] to the `ARES_OPSTATE` stream.
    ///
    /// - Subject is `ares.ops.{op_id}.{event.subject_suffix()}` (granular).
    /// - `Nats-Msg-Id` header is set to `event.event_id` so JetStream dedups
    ///   transient at-least-once retries.
    /// - If `expected_last_subject_seq` is `Some(n)`, the publish carries
    ///   `Nats-Expected-Last-Subject-Sequence` for per-subject optimistic
    ///   concurrency; a mismatch surfaces as [`OpStatePublishError::Conflict`].
    ///
    /// Awaits the JetStream ack. Callers in hot agent paths should treat a
    /// transient failure as non-fatal and log
    pub async fn publish_op_state_event(
        &self,
        event: &OpStateEvent,
        expected_last_subject_seq: Option<u64>,
    ) -> Result<u64, OpStatePublishError> {
        let subject = op_state_subject(&event.op_id, event.subject_suffix());

        let payload = serde_json::to_vec(event).map_err(OpStatePublishError::Serialize)?;

        let mut headers = HeaderMap::new();
        headers.insert(NATS_MESSAGE_ID, event.event_id.as_str());
        if let Some(seq) = expected_last_subject_seq {
            headers.insert(
                NATS_EXPECTED_LAST_SUBJECT_SEQUENCE,
                seq.to_string().as_str(),
            );
        }

        let ack_future = self
            .jetstream
            .publish_with_headers(subject.clone(), headers, payload.into())
            .await
            .map_err(|e| classify_publish_error(&subject, e))?;

        let ack = ack_future
            .await
            .map_err(|e| classify_publish_error(&subject, e))?;

        Ok(ack.sequence)
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

/// Error returned by [`NatsBroker::publish_op_state_event`].
#[derive(Debug, thiserror::Error)]
pub enum OpStatePublishError {
    /// Event serialization failed before any publish was attempted.
    #[error("serialize event: {0}")]
    Serialize(#[source] serde_json::Error),
    /// JetStream rejected the publish because the expected-last-subject-sequence
    /// header did not match the server's view — another publisher won the race.
    /// Callers can reload state and retry.
    #[error("optimistic concurrency conflict on subject {subject}")]
    Conflict { subject: String },
    /// Any other publish or ack failure.
    #[error("publish to {subject} failed: {message}")]
    Publish { subject: String, message: String },
}

fn classify_publish_error(subject: &str, err: PublishError) -> OpStatePublishError {
    match err.kind() {
        PublishErrorKind::WrongLastSequence => OpStatePublishError::Conflict {
            subject: subject.to_string(),
        },
        _ => OpStatePublishError::Publish {
            subject: subject.to_string(),
            message: err.to_string(),
        },
    }
}

/// Stream definition. One per logical broker workload.
pub struct StreamSpec {
    pub name: &'static str,
    pub subjects: Vec<String>,
    pub max_age: Duration,
    pub storage: StorageType,
    pub retention: RetentionPolicy,
    pub discard: DiscardPolicy,
}

impl StreamSpec {
    /// Red team task queue stream.
    pub fn tasks() -> Self {
        Self {
            name: TASKS_STREAM,
            subjects: vec![format!("{TASK_SUBJECT_PREFIX}.>")],
            max_age: Duration::from_secs(60 * 60 * 24), // 24h
            storage: StorageType::File,
            retention: RetentionPolicy::WorkQueue,
            discard: DiscardPolicy::Old,
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
            retention: RetentionPolicy::WorkQueue,
            discard: DiscardPolicy::Old,
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
            retention: RetentionPolicy::WorkQueue,
            discard: DiscardPolicy::Old,
        }
    }

    /// Real-time discovery forwarding stream.
    pub fn discoveries() -> Self {
        Self {
            name: DISCOVERIES_STREAM,
            subjects: vec![format!("{DISCOVERY_SUBJECT_PREFIX}.>")],
            max_age: Duration::from_secs(60 * 60 * 12),
            storage: StorageType::File,
            retention: RetentionPolicy::WorkQueue,
            discard: DiscardPolicy::Old,
        }
    }

    /// Operation state event log. Pattern B source-of-truth:
    /// every credential / host / user / vuln / timeline mutation is appended
    /// here and projected into Postgres + live caches by downstream consumers.
    ///
    /// `Limits` retention (not `WorkQueue`) so multiple consumers can replay
    /// independently. 30 day window — old enough for forensics, bounded
    /// enough for `File` storage to stay reasonable.
    pub fn op_state() -> Self {
        Self {
            name: OP_STATE_STREAM,
            subjects: vec![format!("{OP_STATE_SUBJECT_PREFIX}.>")],
            max_age: Duration::from_secs(60 * 60 * 24 * 30), // 30 days
            storage: StorageType::File,
            retention: RetentionPolicy::Limits,
            discard: DiscardPolicy::Old,
        }
    }

    fn to_config(&self) -> StreamConfig {
        StreamConfig {
            name: self.name.to_string(),
            subjects: self.subjects.clone(),
            retention: self.retention,
            discard: self.discard,
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

    #[test]
    fn urgent_task_subject_format() {
        assert_eq!(urgent_task_subject("recon"), "ares.tasks.urgent.recon");
        assert_eq!(urgent_task_subject("lateral"), "ares.tasks.urgent.lateral");
    }

    #[test]
    fn task_result_subject_format() {
        assert_eq!(
            task_result_subject("recon_abc123"),
            "ares.tasks.results.recon_abc123"
        );
    }

    #[test]
    fn blue_task_result_subject_format() {
        assert_eq!(
            blue_task_result_subject("btask_abc"),
            "ares.blue.tasks.results.btask_abc"
        );
    }

    #[test]
    fn subject_prefixes_are_unique() {
        // Sanity check that the subject namespaces don't overlap, which would
        // cause cross-stream collisions.
        let prefixes = [
            TASK_SUBJECT_PREFIX,
            TOOL_EXEC_SUBJECT_PREFIX,
            BLUE_TASK_SUBJECT_PREFIX,
            DEFERRED_SUBJECT_PREFIX,
            STATE_UPDATE_SUBJECT_PREFIX,
            DISCOVERY_SUBJECT_PREFIX,
            OP_STATE_SUBJECT_PREFIX,
        ];
        for (i, p1) in prefixes.iter().enumerate() {
            for p2 in &prefixes[i + 1..] {
                assert!(
                    !p1.starts_with(p2) && !p2.starts_with(p1),
                    "subject prefixes {p1} and {p2} overlap"
                );
            }
        }
    }

    #[test]
    fn tasks_stream_uses_work_queue_retention_and_file_storage() {
        let spec = StreamSpec::tasks();
        let cfg = spec.to_config();
        assert_eq!(cfg.name, "ARES_TASKS");
        assert!(matches!(cfg.retention, RetentionPolicy::WorkQueue));
        assert!(matches!(cfg.storage, StorageType::File));
        // 24h retention
        assert_eq!(cfg.max_age, Duration::from_secs(60 * 60 * 24));
    }

    #[test]
    fn blue_tasks_stream_to_config_carries_subjects() {
        let cfg = StreamSpec::blue_tasks().to_config();
        assert_eq!(cfg.name, "ARES_BLUE_TASKS");
        assert!(cfg.subjects.iter().any(|s| s == BLUE_INVESTIGATION_SUBJECT));
        assert!(cfg.subjects.iter().any(|s| s == "ares.blue.tasks.>"));
        assert!(matches!(cfg.retention, RetentionPolicy::WorkQueue));
    }

    #[test]
    fn deferred_stream_max_age_is_six_hours() {
        let spec = StreamSpec::deferred();
        assert_eq!(spec.max_age, Duration::from_secs(60 * 60 * 6));
        assert!(matches!(spec.storage, StorageType::File));
    }

    #[test]
    fn discoveries_stream_max_age_is_twelve_hours() {
        let spec = StreamSpec::discoveries();
        assert_eq!(spec.max_age, Duration::from_secs(60 * 60 * 12));
        assert!(matches!(spec.storage, StorageType::File));
    }

    #[test]
    fn url_from_env_falls_back_to_default_when_unset() {
        // We can't safely toggle process-wide env vars in parallel tests, so
        // this only asserts that the function returns a non-empty URL string.
        let url = NatsBroker::url_from_env();
        assert!(!url.is_empty());
        // Default contains nats:// scheme
        if std::env::var("ARES_NATS_URL").is_err() && std::env::var("NATS_URL").is_err() {
            assert_eq!(url, DEFAULT_NATS_URL);
            assert!(url.starts_with("nats://"));
        }
    }

    #[test]
    fn task_subject_distinguishes_urgent_from_normal() {
        let normal = task_subject("recon");
        let urgent = urgent_task_subject("recon");
        assert_ne!(normal, urgent);
        // Both must start with the task prefix
        assert!(normal.starts_with(TASK_SUBJECT_PREFIX));
        assert!(urgent.starts_with(TASK_SUBJECT_PREFIX));
    }

    #[test]
    fn deferred_subject_includes_both_op_and_type() {
        let s = deferred_subject("op-20260429-abc", "lateral");
        assert!(s.contains("op-20260429-abc"));
        assert!(s.contains("lateral"));
        assert!(s.starts_with(DEFERRED_SUBJECT_PREFIX));
    }

    #[test]
    fn op_state_subject_format() {
        assert_eq!(
            op_state_subject("op-42", "cred.captured"),
            "ares.ops.op-42.cred.captured"
        );
        assert_eq!(
            op_state_subject("op-42", "host.owned"),
            "ares.ops.op-42.host.owned"
        );
    }

    #[test]
    fn op_state_filter_for_op_uses_wildcard() {
        assert_eq!(op_state_filter_for_op("op-42"), "ares.ops.op-42.>");
    }

    #[test]
    fn op_state_stream_spec_uses_limits_and_thirty_day_retention() {
        let spec = StreamSpec::op_state();
        assert_eq!(spec.name, "ARES_OPSTATE");
        assert_eq!(spec.subjects, vec!["ares.ops.>"]);
        assert!(matches!(spec.retention, RetentionPolicy::Limits));
        assert!(matches!(spec.storage, StorageType::File));
        assert!(matches!(spec.discard, DiscardPolicy::Old));
        assert_eq!(spec.max_age, Duration::from_secs(60 * 60 * 24 * 30));
    }

    #[test]
    fn op_state_stream_to_config_carries_subjects_and_limits_retention() {
        let cfg = StreamSpec::op_state().to_config();
        assert_eq!(cfg.name, "ARES_OPSTATE");
        assert!(cfg.subjects.iter().any(|s| s == "ares.ops.>"));
        assert!(matches!(cfg.retention, RetentionPolicy::Limits));
        assert!(matches!(cfg.discard, DiscardPolicy::Old));
    }

    #[test]
    fn op_state_subject_disjoint_from_other_streams() {
        // Catches accidental overlap between the new op-state subject hierarchy
        // and any of the existing streams' subjects.
        let op_state = StreamSpec::op_state();
        let others = [
            StreamSpec::tasks(),
            StreamSpec::blue_tasks(),
            StreamSpec::deferred(),
            StreamSpec::discoveries(),
        ];
        for s in &op_state.subjects {
            let s_prefix = s.trim_end_matches(".>");
            for other in &others {
                for o in &other.subjects {
                    let o_prefix = o.trim_end_matches(".>");
                    assert!(
                        !s_prefix.starts_with(o_prefix) && !o_prefix.starts_with(s_prefix),
                        "op-state subject {s} overlaps with {o} from {}",
                        other.name
                    );
                }
            }
        }
    }

    #[test]
    fn stream_names_are_uppercase_and_distinct() {
        let names = [
            TASKS_STREAM,
            BLUE_TASKS_STREAM,
            DEFERRED_STREAM,
            DISCOVERIES_STREAM,
            OP_STATE_STREAM,
        ];
        for n in &names {
            assert_eq!(*n, n.to_uppercase(), "stream name {n} must be uppercase");
        }
        // All distinct
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
