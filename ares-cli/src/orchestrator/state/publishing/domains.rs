//! Domain candidate publishing and promotion.
//!
//! AD discovery tools that we trust (BloodHound, NetExec, runZero) never
//! promote a hostname-derived suffix to an authoritative domain without
//! corroborating evidence. We follow the same rule: hostname-inferred
//! suffixes land in `state.candidate_domains` and only graduate to
//! `state.domains` when they match a stronger source (`TargetConfig`,
//! `DcSelfReport`, `AuthenticatedAd`, `DnsSrv`) or when an external probe
//! confirms them.

use anyhow::Result;
use chrono::Utc;
use redis::aio::ConnectionLike;
use redis::AsyncCommands;

use ares_core::models::{CandidateDomain, DomainEvidence};
use ares_core::state;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

use super::looks_like_real_domain;

/// Retry transient candidate-domain probes on the next worker tick instead of
/// permanently stranding the candidate after one DNS hiccup.
const CANDIDATE_PROBE_RETRY_SECS: i64 = 30;

/// Result of attempting to publish a discovered domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPublishOutcome {
    /// Domain entered (or was already in) `state.domains`.
    Promoted,
    /// Recorded as a candidate; awaiting probe or stronger evidence.
    Held,
    /// Dropped; cannot be a real AD domain.
    Rejected(&'static str),
}

impl SharedState {
    /// Publish a discovered domain with provenance.
    ///
    /// - Drops shapes that are never AD domains (cloud suffixes, default-OS
    ///   hostnames, bare TLDs, mDNS link-local).
    /// - Auto-promotes when `evidence` is authoritative on its own.
    /// - For weaker evidence (`HostnameInference`), promotes only if the
    ///   candidate corroborates an existing strong source — matching the
    ///   operation's `target.domain`, a domain already in `state.domains`,
    ///   or sharing a suffix-parent that's already in `state.domains` (so a
    ///   child like `child.contoso.local` rides on its known forest root).
    /// - Otherwise records the candidate for later confirmation.
    pub async fn publish_candidate_domain(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        fqdn: impl Into<String>,
        evidence: DomainEvidence,
        source_host_ip: Option<String>,
    ) -> Result<DomainPublishOutcome> {
        let fqdn = fqdn.into().trim().trim_end_matches('.').to_lowercase();
        if !looks_like_real_domain(&fqdn) {
            tracing::debug!(
                fqdn = %fqdn,
                ?evidence,
                "Rejected candidate domain (cheap pre-filter)"
            );
            return Ok(DomainPublishOutcome::Rejected("not a plausible AD domain"));
        }

        // Authoritative evidence promotes immediately.
        if evidence.is_authoritative() {
            self.promote_domain(queue, &fqdn).await?;
            tracing::info!(domain = %fqdn, ?evidence, "Promoted authoritative domain");
            return Ok(DomainPublishOutcome::Promoted);
        }

        // Weaker evidence — check for corroboration before promoting.
        let corroborated = {
            let state = self.inner.read().await;
            let already_known = state.domains.iter().any(|d| d.eq_ignore_ascii_case(&fqdn));
            let matches_target = state
                .target
                .as_ref()
                .map(|t| t.domain.eq_ignore_ascii_case(&fqdn))
                .unwrap_or(false);
            // A multi-label child whose suffix-parent is already authoritative
            // (e.g. `child.contoso.local` when `contoso.local` is known)
            // inherits corroboration. FQDNs from host observation can't be
            // typo-injected by an LLM the way credential realms can.
            let parent_known = fqdn
                .split_once('.')
                .map(|(_, parent)| {
                    !parent.is_empty()
                        && parent.contains('.')
                        && state.domains.iter().any(|d| d.eq_ignore_ascii_case(parent))
                })
                .unwrap_or(false);
            already_known || matches_target || parent_known
        };

        if corroborated {
            self.promote_domain(queue, &fqdn).await?;
            tracing::info!(
                domain = %fqdn,
                ?evidence,
                "Promoted candidate domain (corroborated by target/known domain)"
            );
            return Ok(DomainPublishOutcome::Promoted);
        }

        // Hold as a candidate for the probe worker to evaluate.
        let mut candidate = CandidateDomain::new(&fqdn, evidence);
        if let Some(ip) = source_host_ip {
            candidate = candidate.with_source(ip);
        }
        self.record_candidate(queue, candidate).await?;
        Ok(DomainPublishOutcome::Held)
    }

    /// Record a hostname-derived FQDN as a probe-only candidate.
    ///
    /// Unlike [`publish_candidate_domain`], this never applies the
    /// `parent_known` corroboration shortcut, so an ordinary host FQDN
    /// (`dc01.contoso.local`) won't get falsely promoted just because its
    /// parent domain is in `state.domains`. Used by [`publish_host`] when a
    /// DC's reported hostname might *itself* be the domain (zone-apex
    /// alias) — e.g. SMB hostname query returns `child.contoso.local`
    /// for the IP of the `dc02` child DC. The DNS SRV probe is the only
    /// path to promotion: real child domains pass, host FQDNs get rejected.
    pub async fn record_hostname_candidate(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        fqdn: impl Into<String>,
        source_host_ip: Option<String>,
    ) -> Result<DomainPublishOutcome> {
        let fqdn = fqdn.into().trim().trim_end_matches('.').to_lowercase();
        if !looks_like_real_domain(&fqdn) {
            return Ok(DomainPublishOutcome::Rejected("not a plausible AD domain"));
        }
        {
            let state = self.inner.read().await;
            if state.domains.iter().any(|d| d.eq_ignore_ascii_case(&fqdn)) {
                return Ok(DomainPublishOutcome::Promoted);
            }
        }
        let mut candidate = CandidateDomain::new(&fqdn, DomainEvidence::HostnameInference);
        if let Some(ip) = source_host_ip {
            candidate = candidate.with_source(ip);
        }
        self.record_candidate(queue, candidate).await?;
        Ok(DomainPublishOutcome::Held)
    }

    /// Insert the domain into authoritative state. Idempotent.
    pub(crate) async fn promote_domain(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        fqdn: &str,
    ) -> Result<()> {
        let fqdn_lower = fqdn.to_lowercase();
        let op_id = self.inner.read().await.operation_id.clone();
        let mut state = self.inner.write().await;
        // Drop any existing candidate row — promotion supersedes it.
        state.candidate_domains.remove(&fqdn_lower);
        if state
            .domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&fqdn_lower))
        {
            return Ok(());
        }
        state.domains.push(fqdn_lower.clone());
        drop(state);

        let domain_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_DOMAINS);
        let candidate_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            op_id,
            state::KEY_CANDIDATE_DOMAINS
        );
        let mut conn = queue.connection();
        let _: Result<(), _> = conn.sadd(&domain_key, &fqdn_lower).await;
        let _: Result<(), _> = conn.expire(&domain_key, 86400i64).await;
        let _: Result<(), _> = conn.hdel(&candidate_key, &fqdn_lower).await;
        Ok(())
    }

    /// Snapshot of candidate domains awaiting probe. Returns FQDNs in
    /// arbitrary order; callers should not rely on ordering.
    pub async fn pending_candidate_domains(&self) -> Vec<CandidateDomain> {
        let now = Utc::now();
        let state = self.inner.read().await;
        state
            .candidate_domains
            .values()
            .filter(|c| {
                if c.confirmed {
                    return false;
                }
                if !c.probed {
                    return true;
                }
                c.last_probed_at
                    .map(|ts| (now - ts).num_seconds() >= CANDIDATE_PROBE_RETRY_SECS)
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Mark a candidate as probed without promoting it (e.g. probe was
    /// indeterminate but the worker wants to back off retries). Persists the
    /// updated row so it survives orchestrator restart.
    pub async fn mark_candidate_probed(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        fqdn: &str,
    ) -> Result<()> {
        let fqdn_lower = fqdn.to_lowercase();
        let (op_id, candidate_json) = {
            let mut state = self.inner.write().await;
            let Some(candidate) = state.candidate_domains.get_mut(&fqdn_lower) else {
                return Ok(());
            };
            candidate.probed = true;
            candidate.last_probed_at = Some(Utc::now());
            candidate.probe_failures = candidate.probe_failures.saturating_add(1);
            let json = serde_json::to_string(candidate).unwrap_or_default();
            (state.operation_id.clone(), json)
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            op_id,
            state::KEY_CANDIDATE_DOMAINS
        );
        let mut conn = queue.connection();
        let _: Result<(), _> = conn.hset(&key, &fqdn_lower, &candidate_json).await;
        Ok(())
    }

    /// Drop a rejected candidate from in-memory + Redis. Idempotent.
    pub async fn drop_candidate_domain(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        fqdn: &str,
    ) -> Result<()> {
        let fqdn_lower = fqdn.to_lowercase();
        let op_id = {
            let mut state = self.inner.write().await;
            state.candidate_domains.remove(&fqdn_lower);
            state.operation_id.clone()
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            op_id,
            state::KEY_CANDIDATE_DOMAINS
        );
        let mut conn = queue.connection();
        let _: Result<(), _> = conn.hdel(&key, &fqdn_lower).await;
        Ok(())
    }

    /// Persist a candidate domain to in-memory + Redis without promoting it.
    async fn record_candidate(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        candidate: CandidateDomain,
    ) -> Result<()> {
        let op_id = self.inner.read().await.operation_id.clone();
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            op_id,
            state::KEY_CANDIDATE_DOMAINS
        );
        let json = serde_json::to_string(&candidate).unwrap_or_default();
        let fqdn = candidate.fqdn.clone();

        {
            let mut state = self.inner.write().await;
            // Don't overwrite a previously-probed candidate with a fresh one.
            if state.candidate_domains.contains_key(&fqdn) {
                return Ok(());
            }
            state.candidate_domains.insert(fqdn.clone(), candidate);
        }

        tracing::debug!(domain = %fqdn, "Recorded candidate domain (awaiting probe)");
        let mut conn = queue.connection();
        let _: Result<(), _> = conn.hset(&key, &fqdn, &json).await;
        let _: Result<(), _> = conn.expire(&key, 86400i64).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::models::Target;
    use ares_core::state::mock_redis::MockRedisConnection;
    use chrono::Duration;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[tokio::test]
    async fn authoritative_evidence_promotes_immediately() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        let outcome = state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::DcSelfReport, None)
            .await
            .unwrap();
        assert_eq!(outcome, DomainPublishOutcome::Promoted);
        let s = state.inner.read().await;
        assert!(s.domains.iter().any(|d| d == "contoso.local"));
        assert!(s.candidate_domains.is_empty());
    }

    #[tokio::test]
    async fn hostname_inference_held_without_corroboration() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        let outcome = state
            .publish_candidate_domain(
                &q,
                "unknown.contoso.local",
                DomainEvidence::HostnameInference,
                Some("192.168.58.5".into()),
            )
            .await
            .unwrap();
        assert_eq!(outcome, DomainPublishOutcome::Held);
        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        assert!(s.candidate_domains.contains_key("unknown.contoso.local"));
    }

    #[tokio::test]
    async fn hostname_inference_promotes_when_matches_target() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.target = Some(Target {
                ip: "192.168.58.10".into(),
                hostname: String::new(),
                domain: "contoso.local".into(),
                environment: String::new(),
            });
        }
        let outcome = state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        assert_eq!(outcome, DomainPublishOutcome::Promoted);
    }

    #[tokio::test]
    async fn hostname_inference_promotes_when_already_known() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".into());
        }
        let outcome = state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        assert_eq!(outcome, DomainPublishOutcome::Promoted);
    }

    #[tokio::test]
    async fn hostname_inference_promotes_child_of_known_forest_root() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".into());
        }
        let outcome = state
            .publish_candidate_domain(
                &q,
                "child.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        assert_eq!(outcome, DomainPublishOutcome::Promoted);
        let s = state.inner.read().await;
        assert!(s.domains.iter().any(|d| d == "child.contoso.local"));
    }

    #[tokio::test]
    async fn hostname_inference_does_not_promote_via_bare_tld_parent() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".into());
        }
        let outcome = state
            .publish_candidate_domain(&q, "evil.local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        assert_eq!(outcome, DomainPublishOutcome::Held);
    }

    #[tokio::test]
    async fn rejects_default_windows_oobe_fqdn() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        let outcome = state
            .publish_candidate_domain(
                &q,
                "win-hvtt4f8yn5n.ttb0.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, DomainPublishOutcome::Rejected(_)));
        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        assert!(s.candidate_domains.is_empty());
    }

    #[tokio::test]
    async fn rejects_aws_internal_suffix() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        let outcome = state
            .publish_candidate_domain(
                &q,
                "us-west-2.compute.internal",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, DomainPublishOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn rejects_bare_local_tld() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        let outcome = state
            .publish_candidate_domain(&q, "local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        assert!(matches!(outcome, DomainPublishOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn rejects_bonjour_localhost_suffix() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        let outcome = state
            .publish_candidate_domain(
                &q,
                "bobs-mac.localhost",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, DomainPublishOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn promote_drops_existing_candidate_row() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        // Seed a candidate, then publish authoritatively for the same name.
        state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        // No corroboration yet → held as candidate.
        {
            let s = state.inner.read().await;
            assert!(s.candidate_domains.contains_key("contoso.local"));
        }
        // Now an authoritative source confirms it.
        state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::DcSelfReport, None)
            .await
            .unwrap();
        let s = state.inner.read().await;
        assert!(s.domains.iter().any(|d| d == "contoso.local"));
        assert!(!s.candidate_domains.contains_key("contoso.local"));
    }

    #[tokio::test]
    async fn transient_probe_candidates_become_pending_again_after_cooldown() {
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
        state
            .mark_candidate_probed(&q, "transient.contoso.local")
            .await
            .unwrap();
        {
            let pending = state.pending_candidate_domains().await;
            assert!(pending.is_empty());
        }
        {
            let mut s = state.inner.write().await;
            let cand = s
                .candidate_domains
                .get_mut("transient.contoso.local")
                .unwrap();
            cand.last_probed_at =
                Some(Utc::now() - Duration::seconds(CANDIDATE_PROBE_RETRY_SECS + 1));
        }
        let pending = state.pending_candidate_domains().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].fqdn, "transient.contoso.local");
    }
}
