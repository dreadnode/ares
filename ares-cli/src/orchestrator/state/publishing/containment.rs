//! Publish methods for containment observations.
//!
//! Consumed by the red-side failure classifier (see
//! `orchestrator/result_processing/containment_recovery.rs`) — when a tool
//! call fails in a way that looks like blue took action against us, the
//! classifier calls into these methods so the observation lands in state,
//! becomes visible to the LLM on the next task, and lets the exploitation
//! queue drop entries whose preconditions have been invalidated.
//!
//! Each method dedups on the identity key (principal / IP / domain / serial)
//! so re-classification of the same failure signal does not double-emit.
//!
//! The classifier never sees blue; it reads red's own tool output. Every log
//! line here therefore carries the operation's
//! [`ContainmentAttribution`], so an observation raised with blue switched
//! off is never written down as a blue action.

use chrono::Utc;

use ares_core::blue_invalidation::ContainmentAttribution;
use ares_core::models::OpStateEventPayload;

use crate::orchestrator::state::SharedState;

use super::emit_op_state;

impl SharedState {
    /// Record that a principal we hold has been revoked (disabled by blue,
    /// password rotated out from under us, or account locked long past the
    /// normal quarantine window). Idempotent: a second call for the same
    /// `user@domain` is a no-op.
    ///
    /// Returns `true` when this was the first observation and an event was
    /// emitted, `false` when the principal was already known revoked.
    pub async fn publish_credential_revoked(
        &self,
        username: &str,
        domain: &str,
        source: &str,
    ) -> bool {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        let kdc_declared = source.contains(
            crate::orchestrator::result_processing::containment_recovery::KDC_CLIENT_REVOKED_MARKER,
        );
        let (added, attribution) = {
            let mut state = self.inner.write().await;
            let attribution = state.containment_attribution();
            if kdc_declared {
                state.kdc_declared_revocations.insert(key.clone());
            }
            (
                state.revoked_principals.insert(key, Utc::now()).is_none(),
                attribution,
            )
        };
        if !added {
            return false;
        }
        let op_id = self.operation_id().await;
        emit_op_state(
            self.recorder(),
            &op_id,
            OpStateEventPayload::CredentialRevoked {
                username: username.to_string(),
                domain: domain.to_string(),
                source: source.to_string(),
            },
        )
        .await;
        match attribution {
            ContainmentAttribution::BlueActive => tracing::info!(
                username = %username,
                domain = %domain,
                source = %source,
                "Blue containment observed: credential revoked"
            ),
            ContainmentAttribution::RedInferred => tracing::info!(
                username = %username,
                domain = %domain,
                source = %source,
                "Credential rejected — inferred dead, NOT attributed to blue (blue not running)"
            ),
        }
        true
    }

    /// Record that blue firewalled a host we were pivoting through.
    /// Idempotent per-IP.
    pub async fn publish_host_isolated(&self, ip: &str, hostname: &str, source: &str) -> bool {
        let (added, attribution) = {
            let mut state = self.inner.write().await;
            let attribution = state.containment_attribution();
            (
                state
                    .isolated_hosts
                    .insert(ip.to_string(), Utc::now())
                    .is_none(),
                attribution,
            )
        };
        if !added {
            return false;
        }
        let op_id = self.operation_id().await;
        emit_op_state(
            self.recorder(),
            &op_id,
            OpStateEventPayload::HostIsolated {
                ip: ip.to_string(),
                hostname: hostname.to_string(),
                source: source.to_string(),
            },
        )
        .await;
        match attribution {
            ContainmentAttribution::BlueActive => {
                tracing::info!(ip = %ip, hostname = %hostname, source = %source, "Blue containment observed: host isolated")
            }
            ContainmentAttribution::RedInferred => {
                tracing::info!(ip = %ip, hostname = %hostname, source = %source, "Host unreachable — inferred dead, NOT attributed to blue (blue not running)")
            }
        }
        true
    }

    /// Record that blue rotated krbtgt in the given realm. Idempotent per
    /// realm; forest-wide `KRB_AP_ERR_MODIFIED` should collapse to one event.
    pub async fn publish_krbtgt_rotated(&self, domain: &str, source: &str) -> bool {
        let key = domain.to_lowercase();
        let (added, attribution) = {
            let mut state = self.inner.write().await;
            let attribution = state.containment_attribution();
            (
                state.krbtgt_rotated_at.insert(key, Utc::now()).is_none(),
                attribution,
            )
        };
        if !added {
            return false;
        }
        let op_id = self.operation_id().await;
        emit_op_state(
            self.recorder(),
            &op_id,
            OpStateEventPayload::KrbtgtRotated {
                domain: domain.to_string(),
                source: source.to_string(),
            },
        )
        .await;
        match attribution {
            ContainmentAttribution::BlueActive => tracing::warn!(
                domain = %domain,
                source = %source,
                "Blue containment observed: krbtgt rotated (all TGTs and forged tickets in this realm are now dead)"
            ),
            ContainmentAttribution::RedInferred => tracing::warn!(
                domain = %domain,
                source = %source,
                "Kerberos key mismatch — tickets in this realm are dead, NOT attributed to blue (blue not running)"
            ),
        }
        true
    }

    /// Record that blue revoked a certificate we were using. Idempotent per
    /// serial (case-insensitive on the hex).
    pub async fn publish_certificate_revoked(&self, serial: &str, ca: &str, source: &str) -> bool {
        let key = serial.to_lowercase();
        let (added, attribution) = {
            let mut state = self.inner.write().await;
            let attribution = state.containment_attribution();
            (
                state.revoked_certificates.insert(key, Utc::now()).is_none(),
                attribution,
            )
        };
        if !added {
            return false;
        }
        let op_id = self.operation_id().await;
        emit_op_state(
            self.recorder(),
            &op_id,
            OpStateEventPayload::CertificateRevoked {
                serial: serial.to_string(),
                ca: ca.to_string(),
                source: source.to_string(),
            },
        )
        .await;
        match attribution {
            ContainmentAttribution::BlueActive => tracing::info!(
                serial = %serial,
                ca = %ca,
                source = %source,
                "Blue containment observed: certificate revoked"
            ),
            ContainmentAttribution::RedInferred => tracing::info!(
                serial = %serial,
                ca = %ca,
                source = %source,
                "Certificate rejected — inferred dead, NOT attributed to blue (blue not running)"
            ),
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::op_state_log::OpStateRecorder;
    use std::sync::Arc;

    fn capturing_state(op_id: &str) -> (SharedState, Arc<OpStateRecorder>) {
        let recorder = Arc::new(OpStateRecorder::capturing());
        let state = SharedState::with_recorder(op_id.to_string(), recorder.clone());
        (state, recorder)
    }

    #[tokio::test]
    async fn credential_revoked_records_and_emits() {
        let (state, recorder) = capturing_state("op-1");
        let first = state
            .publish_credential_revoked("svc_mssql", "contoso.local", "STATUS_LOGON_FAILURE")
            .await;
        assert!(first);

        let s = state.inner.read().await;
        assert!(s.is_credential_revoked("svc_mssql", "contoso.local"));
        drop(s);

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        matches!(
            evs[0].payload,
            OpStateEventPayload::CredentialRevoked { .. }
        );
    }

    #[tokio::test]
    async fn credential_revoked_dedups_on_repeat() {
        let (state, recorder) = capturing_state("op-1");
        assert!(
            state
                .publish_credential_revoked("svc_mssql", "contoso.local", "STATUS_LOGON_FAILURE")
                .await
        );
        assert!(
            !state
                .publish_credential_revoked("svc_mssql", "contoso.local", "LDAP INVALID_CREDS")
                .await
        );

        assert_eq!(recorder.captured().await.len(), 1);
    }

    #[tokio::test]
    async fn credential_revoked_case_insensitive() {
        let (state, _r) = capturing_state("op-1");
        state
            .publish_credential_revoked("SVC_MSSQL", "CONTOSO.LOCAL", "s")
            .await;
        let s = state.inner.read().await;
        assert!(s.is_credential_revoked("svc_mssql", "contoso.local"));
        assert!(s.is_credential_revoked("Svc_MsSql", "Contoso.Local"));
    }

    #[tokio::test]
    async fn host_isolated_records_by_ip() {
        let (state, recorder) = capturing_state("op-1");
        assert!(
            state
                .publish_host_isolated("192.168.58.20", "web01.contoso.local", "timeout")
                .await
        );
        assert!(state.inner.read().await.is_host_isolated("192.168.58.20"));
        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        matches!(evs[0].payload, OpStateEventPayload::HostIsolated { .. });
    }

    #[tokio::test]
    async fn krbtgt_rotated_records_lowercase() {
        let (state, _r) = capturing_state("op-1");
        assert!(
            state
                .publish_krbtgt_rotated("CONTOSO.LOCAL", "KRB_AP_ERR_MODIFIED")
                .await
        );
        let s = state.inner.read().await;
        assert!(s.is_krbtgt_rotated("contoso.local"));
        assert!(s.is_krbtgt_rotated("CONTOSO.LOCAL"));
    }

    #[tokio::test]
    async fn certificate_revoked_records_lowercase_serial() {
        let (state, _r) = capturing_state("op-1");
        assert!(
            state
                .publish_certificate_revoked(
                    "1A2B3C",
                    "ca01.contoso.local",
                    "KDC_ERR_CLIENT_REVOKED"
                )
                .await
        );
        let s = state.inner.read().await;
        assert!(s.is_certificate_revoked("1a2b3c"));
        assert!(s.is_certificate_revoked("1A2B3C"));
    }

    #[tokio::test]
    async fn attribution_defaults_to_red_inferred_until_blue_is_declared() {
        let (state, _r) = capturing_state("op-1");
        assert_eq!(
            state.containment_attribution().await,
            ContainmentAttribution::RedInferred
        );
        state.set_blue_enabled(true).await;
        assert_eq!(
            state.containment_attribution().await,
            ContainmentAttribution::BlueActive
        );
    }

    #[tokio::test]
    async fn publishing_still_invalidates_the_principal_with_blue_off() {
        let (state, recorder) = capturing_state("op-1");
        assert!(
            state
                .publish_credential_revoked("svc_mssql", "contoso.local", "STATUS_LOGON_FAILURE")
                .await
        );
        assert!(state
            .inner
            .read()
            .await
            .is_credential_revoked("svc_mssql", "contoso.local"));
        assert_eq!(recorder.captured().await.len(), 1);
    }

    #[tokio::test]
    async fn no_emission_when_recorder_disabled() {
        let state = SharedState::new("op-noop".to_string());
        // Just ensuring no panic on the no-op record path.
        state
            .publish_credential_revoked("alice", "contoso.local", "s")
            .await;
        let s = state.inner.read().await;
        assert!(s.is_credential_revoked("alice", "contoso.local"));
    }
}
