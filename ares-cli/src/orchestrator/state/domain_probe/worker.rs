//! Periodic worker that drains candidate domains and probes them.
//!
//! Spawned once at orchestrator startup. Every 30 seconds it pulls the
//! current candidate set, probes each entry concurrently, and:
//! - Confirmed → `promote_domain`
//! - Rejected  → `drop_candidate_domain`
//! - Indeterminate → `mark_candidate_probed` (back off; promotion can still
//!   come from a stronger source landing later)
//!
//! Tick cadence is deliberately slow (30s vs 5s for `discovery_poller`):
//! domain promotion is not on the hot path of attack flow, and we don't want
//! to hammer DNS for transient resolution failures. The worker is also
//! resilient to shutdown — it joins the existing `watch::Receiver<bool>`
//! pattern used by every other background task.

use std::sync::Arc;
use std::time::Duration;

use redis::aio::ConnectionManager;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use super::{DomainProber, ProbeOutcome};
use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

/// Wired-up dependencies for the probe worker.
pub struct DomainProbeContext {
    pub state: SharedState,
    pub queue: TaskQueueCore<ConnectionManager>,
    pub prober: Arc<dyn DomainProber>,
}

/// Tick interval. Long enough to avoid DNS hammering, short enough that a
/// candidate landing mid-operation gets confirmed within tens of seconds.
const TICK_SECS: u64 = 30;

/// Spawn the candidate-domain probe worker on a Tokio task.
pub fn spawn_domain_probe_worker(
    ctx: DomainProbeContext,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run(ctx, shutdown).await;
    })
}

async fn run(ctx: DomainProbeContext, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(TICK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!("Domain probe worker started");
    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }
        drain_once(&ctx).await;
    }
    info!("Domain probe worker stopped");
}

async fn drain_once(ctx: &DomainProbeContext) {
    let pending = ctx.state.pending_candidate_domains().await;
    if pending.is_empty() {
        return;
    }
    debug!(count = pending.len(), "Probing candidate domains");
    for cand in pending {
        let outcome = ctx.prober.probe(&cand.fqdn).await;
        match outcome {
            ProbeOutcome::Confirmed => {
                if let Err(e) = ctx.state.promote_domain(&ctx.queue, &cand.fqdn).await {
                    debug!(domain = %cand.fqdn, err = %e, "Promote after probe failed");
                } else {
                    info!(domain = %cand.fqdn, "Promoted candidate domain after DNS SRV probe");
                }
            }
            ProbeOutcome::Rejected(reason) => {
                if let Err(e) = ctx
                    .state
                    .drop_candidate_domain(&ctx.queue, &cand.fqdn)
                    .await
                {
                    debug!(domain = %cand.fqdn, err = %e, "Drop candidate failed");
                } else {
                    debug!(domain = %cand.fqdn, reason = %reason, "Dropped candidate domain (probe rejected)");
                }
            }
            ProbeOutcome::Indeterminate => {
                if let Err(e) = ctx
                    .state
                    .mark_candidate_probed(&ctx.queue, &cand.fqdn)
                    .await
                {
                    debug!(domain = %cand.fqdn, err = %e, "Mark probed failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::models::DomainEvidence;
    use ares_core::state::mock_redis::MockRedisConnection;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    /// Test prober that returns a fixed outcome per FQDN.
    struct StubProber {
        results: Mutex<std::collections::HashMap<String, ProbeOutcome>>,
    }

    impl StubProber {
        fn new(entries: Vec<(&str, ProbeOutcome)>) -> Self {
            let mut map = std::collections::HashMap::new();
            for (k, v) in entries {
                map.insert(k.to_string(), v);
            }
            Self {
                results: Mutex::new(map),
            }
        }
    }

    #[async_trait]
    impl DomainProber for StubProber {
        async fn probe(&self, fqdn: &str) -> ProbeOutcome {
            self.results
                .lock()
                .unwrap()
                .get(fqdn)
                .cloned()
                .unwrap_or(ProbeOutcome::Indeterminate)
        }
    }

    /// Internal helper that runs one drain pass against a mock-backed state.
    /// We can't call `drain_once` directly because the public `DomainProbeContext`
    /// is parameterized on `ConnectionManager`, but the test substitutes
    /// `MockRedisConnection`. Instead we replicate the loop body by hand.
    async fn drain_with_mock(
        state: &SharedState,
        queue: &TaskQueueCore<MockRedisConnection>,
        prober: &dyn DomainProber,
    ) {
        let pending = state.pending_candidate_domains().await;
        for cand in pending {
            match prober.probe(&cand.fqdn).await {
                ProbeOutcome::Confirmed => {
                    state.promote_domain(queue, &cand.fqdn).await.unwrap();
                }
                ProbeOutcome::Rejected(_) => {
                    state
                        .drop_candidate_domain(queue, &cand.fqdn)
                        .await
                        .unwrap();
                }
                ProbeOutcome::Indeterminate => {
                    state
                        .mark_candidate_probed(queue, &cand.fqdn)
                        .await
                        .unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn confirmed_candidate_is_promoted() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        let prober = StubProber::new(vec![("contoso.local", ProbeOutcome::Confirmed)]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(s.domains.iter().any(|d| d == "contoso.local"));
        assert!(s.candidate_domains.is_empty());
    }

    #[tokio::test]
    async fn rejected_candidate_is_dropped() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "fake.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        let prober = StubProber::new(vec![("fake.contoso.local", ProbeOutcome::Rejected("nx"))]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        assert!(s.candidate_domains.is_empty());
    }

    #[tokio::test]
    async fn indeterminate_candidate_marked_probed_but_kept() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "transient.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        let prober = StubProber::new(vec![]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        let cand = s.candidate_domains.get("transient.contoso.local").unwrap();
        assert!(cand.probed);
    }

    #[tokio::test]
    async fn probed_candidates_are_not_repolled() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "transient.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        // First pass: indeterminate → marked probed.
        let prober = StubProber::new(vec![]);
        drain_with_mock(&state, &q, &prober).await;
        // Second pass should now skip the already-probed candidate.
        let pending = state.pending_candidate_domains().await;
        assert!(pending.is_empty());
    }
}
