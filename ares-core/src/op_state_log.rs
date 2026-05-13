//! Recorder abstraction for the operation state event log.
//!
//! `OpStateRecorder` is the sink that [`crate::models::OpStateEvent`] values
//! are pushed into. Production uses the [`OpStateRecorder::Nats`] variant which
//! publishes to the `ARES_OPSTATE` JetStream stream. Tests use
//! [`OpStateRecorder::Capturing`] to assert what was emitted without spinning
//! up a NATS server. Components that have not been wired into the event log
//! yet hold [`OpStateRecorder::Disabled`] and the recorder becomes a no-op.
//!
//! Phase 2 of the JetStream-as-source-of-truth rollout: publish failures are
//! logged at the call site but never abort the operation, because Redis is
//! still authoritative until the Phase 4 cutover.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::models::OpStateEvent;
use crate::nats::{NatsBroker, OpStatePublishError};

/// Sink for [`OpStateEvent`] values emitted by `SharedState` publishers.
///
/// Cheap to clone — variants either hold an `Arc<NatsBroker>` (clone-friendly
/// already) or an `Arc<Mutex<...>>` capture buffer. Default constructed as
/// [`OpStateRecorder::Disabled`] when callers have not opted into the event
/// log yet.
#[derive(Clone, Default)]
pub enum OpStateRecorder {
    /// No-op sink. Used in tests and in code paths not yet wired into the log.
    #[default]
    Disabled,
    /// Publishes each event to the `ARES_OPSTATE` JetStream stream.
    Nats(Arc<NatsBroker>),
    /// Test sink that appends events to an in-memory buffer.
    Capturing(Arc<Mutex<Vec<OpStateEvent>>>),
}

impl OpStateRecorder {
    /// Construct a disabled recorder. Cheap; equivalent to `Self::Disabled`.
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Construct a Nats-backed recorder. Phase-2 dual-write entry point.
    pub fn nats(broker: Arc<NatsBroker>) -> Self {
        Self::Nats(broker)
    }

    /// Construct a fresh capturing recorder for tests.
    pub fn capturing() -> Self {
        Self::Capturing(Arc::new(Mutex::new(Vec::new())))
    }

    /// `true` when this recorder will actually emit anything. Lets call sites
    /// skip serialization work entirely when disabled.
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Record an event. Returns the JetStream sequence number on success, or
    /// the publish error so the caller can decide how to react.
    ///
    /// For [`Self::Disabled`] this is a successful no-op and returns sequence
    /// `0`. For [`Self::Capturing`] the event is pushed onto the buffer and
    /// the returned sequence is the buffer index (1-based, matching how
    /// JetStream sequences begin at 1).
    pub async fn record(&self, event: OpStateEvent) -> Result<u64, OpStatePublishError> {
        match self {
            Self::Disabled => Ok(0),
            Self::Nats(broker) => broker.publish_op_state_event(&event, None).await,
            Self::Capturing(buf) => {
                let mut guard = buf.lock().await;
                guard.push(event);
                Ok(guard.len() as u64)
            }
        }
    }

    /// Snapshot of all events captured so far. Returns empty for non-capturing
    /// variants. Test-only helper.
    pub async fn captured(&self) -> Vec<OpStateEvent> {
        match self {
            Self::Capturing(buf) => buf.lock().await.clone(),
            _ => Vec::new(),
        }
    }
}

impl std::fmt::Debug for OpStateRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("OpStateRecorder::Disabled"),
            Self::Nats(_) => f.write_str("OpStateRecorder::Nats(..)"),
            Self::Capturing(_) => f.write_str("OpStateRecorder::Capturing(..)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::OpStateEventPayload;

    fn timeline_payload(text: &str) -> OpStateEventPayload {
        OpStateEventPayload::TimelineEvent {
            event: serde_json::json!({ "description": text }),
        }
    }

    #[test]
    fn disabled_is_default_and_inactive() {
        let r = OpStateRecorder::default();
        assert!(!r.is_active());
        assert!(matches!(r, OpStateRecorder::Disabled));
    }

    #[test]
    fn capturing_reports_active() {
        let r = OpStateRecorder::capturing();
        assert!(r.is_active());
    }

    #[tokio::test]
    async fn disabled_record_is_noop() {
        let r = OpStateRecorder::Disabled;
        let seq = r
            .record(OpStateEvent::new("op-1", timeline_payload("hi")))
            .await
            .unwrap();
        assert_eq!(seq, 0);
        assert!(r.captured().await.is_empty());
    }

    #[tokio::test]
    async fn capturing_appends_events_in_order() {
        let r = OpStateRecorder::capturing();
        let s1 = r
            .record(OpStateEvent::new("op-1", timeline_payload("first")))
            .await
            .unwrap();
        let s2 = r
            .record(OpStateEvent::new("op-1", timeline_payload("second")))
            .await
            .unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        let evs = r.captured().await;
        assert_eq!(evs.len(), 2);
        match &evs[0].payload {
            OpStateEventPayload::TimelineEvent { event } => {
                assert_eq!(event["description"], "first");
            }
            _ => panic!("wrong payload variant"),
        }
    }

    #[tokio::test]
    async fn capturing_buffer_is_shared_across_clones() {
        let r = OpStateRecorder::capturing();
        let r2 = r.clone();
        r.record(OpStateEvent::new("op-1", timeline_payload("a")))
            .await
            .unwrap();
        r2.record(OpStateEvent::new("op-1", timeline_payload("b")))
            .await
            .unwrap();
        // Both clones see both events.
        assert_eq!(r.captured().await.len(), 2);
        assert_eq!(r2.captured().await.len(), 2);
    }

    #[test]
    fn debug_does_not_leak_event_contents() {
        let r = OpStateRecorder::Capturing(Arc::new(Mutex::new(Vec::new())));
        let s = format!("{r:?}");
        assert_eq!(s, "OpStateRecorder::Capturing(..)");
    }
}
