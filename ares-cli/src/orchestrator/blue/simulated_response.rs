//! Blue-side "simulated response action" spans and their optional projection
//! into the red op-state log.
//!
//! The Black Hat demo dashboard's `Simulated Response Actions` panel reads
//! spans emitted by the blue orchestrator with `attack_team=blue` and groups
//! them by `span_name`. Each escalate/confirm/downgrade lifecycle callback
//! emits one span via [`emit_simulated_response_span`]; the span name is the
//! literal `blue.simulated_response.<action_type>` so the dashboard picks it
//! up without further config.
//!
//! When a `confirm_escalation` names a concrete containment action, the same
//! call also publishes the matching [`ares_core::models::OpStateEventPayload`]
//! variant through the recorder — so the red-side projector observes it and
//! the exploitation queue-filter drops entries whose preconditions are now
//! invalid. The blue callback owns the recorder; it does not touch red's
//! in-memory `SharedState` directly.

use ares_core::models::{OpStateEvent, OpStateEventPayload};
use ares_core::op_state_log::OpStateRecorder;
use tracing::{info_span, warn, Span};

pub const BLUE_SIMULATED_SOURCE_PREFIX: &str = "blue_simulated:";

/// Action-type slugs used both in the tool schema enum and as the span-name
/// suffix. Keep the two in sync: adding a new variant here requires updating
/// the `confirm_escalation` schema in `ares-llm::tool_registry::blue::callbacks`.
pub(super) const ACTION_ESCALATE_TO_HUMAN: &str = "escalate_to_human";
pub(super) const ACTION_DISABLE_AD_ACCOUNT: &str = "disable_ad_account";
pub(super) const ACTION_ISOLATE_HOST_FIREWALL: &str = "isolate_host_firewall";
pub(super) const ACTION_REVOKE_KRBTGT: &str = "revoke_krbtgt";
pub(super) const ACTION_REVOKE_CERTIFICATE: &str = "revoke_certificate";
pub(super) const ACTION_DOWNGRADE_ESCALATION: &str = "downgrade_escalation";

/// Emit a single blue-team `simulated_response` span.
///
/// `action_type` is the trailing segment of the span name (so the dashboard
/// panel groups actions distinctly) and is also attached as a
/// `simulated_response.action_type` attribute for consumers that read spans
/// directly. `target` is optional context — the affected principal, host,
/// realm, or certificate serial — copied verbatim into
/// `simulated_response.target`.
///
/// The span is entered and immediately dropped: these are point-in-time
/// decision markers, not durations. Tempo's spanmetrics processor still
/// counts each one in `traces_spanmetrics_calls_total{attack_team="blue"}`
/// which is what the demo dashboard graphs.
pub(super) fn emit_simulated_response_span(
    action_type: &str,
    target: &str,
    investigation_id: &str,
    operation_id: &str,
    reasoning: &str,
) -> Span {
    let span_name = format!("blue.simulated_response.{action_type}");
    info_span!(
        "ares.blue.simulated_response",
        otel.name = %span_name,
        otel.kind = "internal",
        otel.status_code = "OK",
        attack_team = "blue",
        attack_operation_id = %operation_id,
        "op.id" = %operation_id,
        "investigation.id" = %investigation_id,
        "simulated_response.action_type" = %action_type,
        "simulated_response.target" = %target,
        "simulated_response.reasoning" = %reasoning,
    )
}

/// Translate a confirmed containment action + target into the matching
/// red-side op-state event payload. Returns `None` when the action is
/// `escalate_to_human` (no containment side-effect) or when a required
/// field for the specific variant is missing.
pub(super) fn payload_for_containment(
    action_type: &str,
    target: &str,
    investigation_id: &str,
) -> Option<OpStateEventPayload> {
    if target.trim().is_empty() {
        return None;
    }
    let source = format!("{BLUE_SIMULATED_SOURCE_PREFIX}{investigation_id}");
    match action_type {
        ACTION_DISABLE_AD_ACCOUNT => {
            let (username, domain) = split_user_at_domain(target)?;
            Some(OpStateEventPayload::CredentialRevoked {
                username: username.to_string(),
                domain: domain.to_string(),
                source,
            })
        }
        ACTION_ISOLATE_HOST_FIREWALL => {
            // `target` is either an IP or a hostname; hosts stored by IP so
            // we split on the first-parse: if it parses as an IP, use it as
            // the IP; otherwise treat it as the hostname and leave IP blank.
            let (ip, hostname) = if target.parse::<std::net::IpAddr>().is_ok() {
                (target.to_string(), String::new())
            } else {
                (String::new(), target.to_string())
            };
            Some(OpStateEventPayload::HostIsolated {
                ip,
                hostname,
                source,
            })
        }
        ACTION_REVOKE_KRBTGT => Some(OpStateEventPayload::KrbtgtRotated {
            domain: target.to_string(),
            source,
        }),
        ACTION_REVOKE_CERTIFICATE => Some(OpStateEventPayload::CertificateRevoked {
            serial: target.to_string(),
            ca: String::new(),
            source,
        }),
        _ => None,
    }
}

/// Publish a containment event to the op-state log. No-op when the recorder
/// is disabled; warn (not fail) on publish errors — the tracing span has
/// already been emitted for the dashboard so the demo still reads correctly
/// even if the durable observation misses.
pub(super) async fn publish_containment(
    recorder: &OpStateRecorder,
    op_id: &str,
    payload: OpStateEventPayload,
) {
    if !recorder.is_active() {
        return;
    }
    let event = OpStateEvent::new(op_id, payload);
    if let Err(e) = recorder.record(event).await {
        warn!(err = %e, "blue simulated-response containment publish failed");
    }
}

/// Split a `user@domain` UPN into its two parts. Returns `None` when the
/// input has no `@` or when either side is empty after trimming.
fn split_user_at_domain(upn: &str) -> Option<(&str, &str)> {
    let (u, d) = upn.split_once('@')?;
    let u = u.trim();
    let d = d.trim();
    if u.is_empty() || d.is_empty() {
        None
    } else {
        Some((u, d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_upn_ok() {
        assert_eq!(
            split_user_at_domain("alice@contoso.local"),
            Some(("alice", "contoso.local"))
        );
    }

    #[test]
    fn split_upn_trims() {
        assert_eq!(
            split_user_at_domain("  alice  @  contoso.local  "),
            Some(("alice", "contoso.local"))
        );
    }

    #[test]
    fn split_upn_rejects_missing_at() {
        assert!(split_user_at_domain("alice").is_none());
    }

    #[test]
    fn split_upn_rejects_empty_sides() {
        assert!(split_user_at_domain("@contoso.local").is_none());
        assert!(split_user_at_domain("alice@").is_none());
        assert!(split_user_at_domain("@").is_none());
    }

    #[test]
    fn payload_disable_ad_account() {
        let p = payload_for_containment(
            ACTION_DISABLE_AD_ACCOUNT,
            "svc_mssql@contoso.local",
            "inv-1",
        )
        .unwrap();
        match p {
            OpStateEventPayload::CredentialRevoked {
                username,
                domain,
                source,
            } => {
                assert_eq!(username, "svc_mssql");
                assert_eq!(domain, "contoso.local");
                assert_eq!(source, "blue_simulated:inv-1");
            }
            other => panic!("expected CredentialRevoked, got {other:?}"),
        }
    }

    #[test]
    fn payload_isolate_host_ip() {
        let p = payload_for_containment(ACTION_ISOLATE_HOST_FIREWALL, "192.168.58.20", "inv-1")
            .unwrap();
        match p {
            OpStateEventPayload::HostIsolated {
                ip,
                hostname,
                source,
            } => {
                assert_eq!(ip, "192.168.58.20");
                assert_eq!(hostname, "");
                assert_eq!(source, "blue_simulated:inv-1");
            }
            other => panic!("expected HostIsolated, got {other:?}"),
        }
    }

    #[test]
    fn payload_isolate_host_hostname() {
        let p =
            payload_for_containment(ACTION_ISOLATE_HOST_FIREWALL, "dc01.contoso.local", "inv-1")
                .unwrap();
        match p {
            OpStateEventPayload::HostIsolated { ip, hostname, .. } => {
                assert_eq!(ip, "");
                assert_eq!(hostname, "dc01.contoso.local");
            }
            other => panic!("expected HostIsolated, got {other:?}"),
        }
    }

    #[test]
    fn payload_krbtgt() {
        let p = payload_for_containment(ACTION_REVOKE_KRBTGT, "contoso.local", "inv-1").unwrap();
        match p {
            OpStateEventPayload::KrbtgtRotated { domain, source } => {
                assert_eq!(domain, "contoso.local");
                assert_eq!(source, "blue_simulated:inv-1");
            }
            other => panic!("expected KrbtgtRotated, got {other:?}"),
        }
    }

    #[test]
    fn payload_certificate() {
        let p = payload_for_containment(ACTION_REVOKE_CERTIFICATE, "1A2B3C", "inv-1").unwrap();
        match p {
            OpStateEventPayload::CertificateRevoked { serial, ca, .. } => {
                assert_eq!(serial, "1A2B3C");
                assert!(ca.is_empty());
            }
            other => panic!("expected CertificateRevoked, got {other:?}"),
        }
    }

    #[test]
    fn payload_escalate_to_human_is_none() {
        assert!(payload_for_containment(ACTION_ESCALATE_TO_HUMAN, "anything", "inv-1").is_none());
    }

    #[test]
    fn payload_empty_target_is_none() {
        assert!(payload_for_containment(ACTION_REVOKE_KRBTGT, "", "inv-1").is_none());
        assert!(payload_for_containment(ACTION_REVOKE_KRBTGT, "   ", "inv-1").is_none());
    }

    #[test]
    fn payload_unknown_action_is_none() {
        assert!(payload_for_containment("nuke_datacenter", "anything", "inv-1").is_none());
    }

    #[test]
    fn emit_span_does_not_panic_without_subscriber() {
        // No subscriber attached in unit tests — the span will be
        // `Disabled` at runtime; the smoke assertion is only that
        // construction doesn't panic. Subscriber-driven attribute
        // recording is exercised by the integration/dashboard path,
        // not here.
        let _ = emit_simulated_response_span(
            ACTION_DISABLE_AD_ACCOUNT,
            "svc_mssql@contoso.local",
            "inv-42",
            "op-42",
            "kerberoast target confirmed",
        );
    }
}
