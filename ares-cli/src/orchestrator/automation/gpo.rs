//! auto_gpo_abuse -- exploit GPO write access for code execution.
//!
//! When a controlled user has write access to a Group Policy Object
//! (e.g., a user has write on a GPO linked to contoso.local),
//! this automation dispatches `pyGPOAbuse` to inject a scheduled task that
//! runs as SYSTEM on all hosts where the GPO applies.
//!
//! GPO vulns are typically discovered via BloodHound edges (WriteProperty,
//! WriteDacl, GenericAll on GPO objects).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for GPO abuse attacks.
const DEDUP_GPO_ABUSE: &str = "gpo_abuse";

/// Monitors for GPO write access vulnerabilities and dispatches exploitation.
/// Interval: 30s.
pub async fn auto_gpo_abuse(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("gpo_abuse") {
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

        let work: Vec<GpoWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    if !is_gpo_candidate(&vuln.vuln_type) {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("{DEDUP_GPO_ABUSE}:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_GPO_ABUSE, &dedup_key) {
                        return None;
                    }

                    let source_user = vuln
                        .details
                        .get("source")
                        .or_else(|| vuln.details.get("source_user"))
                        .or_else(|| vuln.details.get("account_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let gpo_id = vuln
                        .details
                        .get("gpo_id")
                        .or_else(|| vuln.details.get("gpo_guid"))
                        .or_else(|| vuln.details.get("object_id"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let gpo_name = vuln
                        .details
                        .get("gpo_name")
                        .or_else(|| vuln.details.get("gpo_display_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

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

                    if credential.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            source = %source_user,
                            "GPO abuse skipped: no credential for source user"
                        );
                        return None;
                    }

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    Some(GpoWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        source_user,
                        gpo_id,
                        gpo_name,
                        domain,
                        dc_ip,
                        credential,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "gpo_abuse",
                "vuln_type": "gpo_abuse",
                "vuln_id": item.vuln_id,
                "domain": item.domain,
            });

            if let Some(ref gpo_id) = item.gpo_id {
                payload["gpo_id"] = json!(gpo_id);
            }
            if let Some(ref name) = item.gpo_name {
                payload["gpo_name"] = json!(name);
            }
            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
                payload["dc_ip"] = json!(dc);
            }

            if let Some(ref cred) = item.credential {
                payload["username"] = json!(cred.username);
                payload["password"] = json!(cred.password);
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            }

            let priority = dispatcher.effective_priority("gpo_abuse");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        gpo = ?item.gpo_name,
                        "GPO abuse dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GPO_ABUSE, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GPO_ABUSE, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch GPO abuse")
                }
            }
        }
    }
}

struct GpoWork {
    vuln_id: String,
    dedup_key: String,
    source_user: String,
    gpo_id: Option<String>,
    gpo_name: Option<String>,
    domain: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
}

/// Returns `true` if a vulnerability type represents a GPO abuse candidate.
fn is_gpo_candidate(vuln_type: &str) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "gpo_abuse"
        || vtype == "gpo_write"
        || vtype == "gpo_genericall"
        || vtype == "gpo_genericwrite"
        || vtype == "gpo_writedacl"
        || vtype == "gpo_writeowner"
        || vtype.starts_with("gpo_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn is_gpo_candidate_basic() {
        assert!(is_gpo_candidate("gpo_abuse"));
        assert!(is_gpo_candidate("GPO_ABUSE"));
        assert!(is_gpo_candidate("gpo_write"));
        assert!(is_gpo_candidate("gpo_genericall"));
        assert!(is_gpo_candidate("gpo_writedacl"));
        assert!(!is_gpo_candidate("genericall"));
        assert!(!is_gpo_candidate("rbcd"));
        assert!(!is_gpo_candidate("esc1"));
    }

    #[test]
    fn is_gpo_candidate_all_explicit_types() {
        // Verify every explicitly listed GPO vuln type
        let gpo_types = vec![
            "gpo_abuse",
            "gpo_write",
            "gpo_genericall",
            "gpo_genericwrite",
            "gpo_writedacl",
            "gpo_writeowner",
        ];
        for vtype in &gpo_types {
            assert!(is_gpo_candidate(vtype), "{vtype} should be GPO candidate");
        }
        // Also verify case-insensitive matching
        for vtype in &gpo_types {
            let upper = vtype.to_uppercase();
            assert!(
                is_gpo_candidate(&upper),
                "{upper} should be GPO candidate (case-insensitive)"
            );
        }
    }

    #[test]
    fn is_gpo_candidate_wildcard_prefix() {
        // Anything starting with gpo_ should match via starts_with
        assert!(is_gpo_candidate("gpo_custom_edge"));
        assert!(is_gpo_candidate("GPO_something_new"));
        assert!(is_gpo_candidate("gpo_"));
    }

    #[test]
    fn is_gpo_candidate_non_gpo_types() {
        // Exhaustive negative cases
        let non_gpo = vec![
            "rbcd",
            "esc1",
            "esc4",
            "esc8",
            "shadow_credentials",
            "constrained_delegation",
            "unconstrained_delegation",
            "genericall",
            "genericwrite",
            "writedacl",
            "dcsync",
            "mssql_impersonation",
            "",
        ];
        for vtype in non_gpo {
            assert!(
                !is_gpo_candidate(vtype),
                "{vtype:?} should NOT be GPO candidate"
            );
        }
    }

    #[test]
    fn dedup_key_format() {
        let vuln_id = "vuln-gpo-001";
        let dedup_key = format!("{DEDUP_GPO_ABUSE}:{vuln_id}");
        assert_eq!(dedup_key, "gpo_abuse:vuln-gpo-001");
    }

    #[test]
    fn dedup_key_constant() {
        assert_eq!(DEDUP_GPO_ABUSE, "gpo_abuse");
    }

    /// Helper: simulate the source_user extraction logic from auto_gpo_abuse
    fn extract_gpo_source_user(details: &HashMap<String, Value>) -> Option<String> {
        details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("account_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Helper: simulate the gpo_id extraction logic from auto_gpo_abuse
    fn extract_gpo_id(details: &HashMap<String, Value>) -> Option<String> {
        details
            .get("gpo_id")
            .or_else(|| details.get("gpo_guid"))
            .or_else(|| details.get("object_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Helper: simulate the gpo_name extraction logic from auto_gpo_abuse
    fn extract_gpo_name(details: &HashMap<String, Value>) -> Option<String> {
        details
            .get("gpo_name")
            .or_else(|| details.get("gpo_display_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    #[test]
    fn extract_source_user_from_source_key() {
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!("jdoe"));
        assert_eq!(extract_gpo_source_user(&details), Some("jdoe".to_string()));
    }

    #[test]
    fn extract_source_user_from_source_user_key() {
        let mut details = HashMap::new();
        details.insert("source_user".to_string(), json!("admin"));
        assert_eq!(extract_gpo_source_user(&details), Some("admin".to_string()));
    }

    #[test]
    fn extract_source_user_from_account_name_key() {
        let mut details = HashMap::new();
        details.insert("account_name".to_string(), json!("svc_gpo"));
        assert_eq!(
            extract_gpo_source_user(&details),
            Some("svc_gpo".to_string())
        );
    }

    #[test]
    fn extract_source_user_prefers_source_over_account_name() {
        // "source" takes priority over "account_name"
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!("primary_user"));
        details.insert("account_name".to_string(), json!("fallback_user"));
        assert_eq!(
            extract_gpo_source_user(&details),
            Some("primary_user".to_string())
        );
    }

    #[test]
    fn extract_source_user_prefers_source_over_source_user() {
        // "source" takes priority over "source_user"
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!("first"));
        details.insert("source_user".to_string(), json!("second"));
        assert_eq!(extract_gpo_source_user(&details), Some("first".to_string()));
    }

    #[test]
    fn extract_source_user_none_when_empty() {
        let details = HashMap::new();
        assert_eq!(extract_gpo_source_user(&details), None);
    }

    #[test]
    fn extract_source_user_none_when_non_string() {
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!(42));
        assert_eq!(extract_gpo_source_user(&details), None);
    }

    #[test]
    fn extract_gpo_id_from_gpo_id_key() {
        let mut details = HashMap::new();
        details.insert(
            "gpo_id".to_string(),
            json!("{6AC1786C-016F-11D2-945F-00C04fB984F9}"),
        );
        assert_eq!(
            extract_gpo_id(&details),
            Some("{6AC1786C-016F-11D2-945F-00C04fB984F9}".to_string())
        );
    }

    #[test]
    fn extract_gpo_id_from_gpo_guid_key() {
        let mut details = HashMap::new();
        details.insert(
            "gpo_guid".to_string(),
            json!("{31B2F340-016D-11D2-945F-00C04FB984F9}"),
        );
        assert_eq!(
            extract_gpo_id(&details),
            Some("{31B2F340-016D-11D2-945F-00C04FB984F9}".to_string())
        );
    }

    #[test]
    fn extract_gpo_id_from_object_id_key() {
        let mut details = HashMap::new();
        details.insert("object_id".to_string(), json!("S-1-5-21-abc-123"));
        assert_eq!(
            extract_gpo_id(&details),
            Some("S-1-5-21-abc-123".to_string())
        );
    }

    #[test]
    fn extract_gpo_id_prefers_gpo_id_over_gpo_guid() {
        let mut details = HashMap::new();
        details.insert("gpo_id".to_string(), json!("primary-gpo"));
        details.insert("gpo_guid".to_string(), json!("fallback-guid"));
        assert_eq!(extract_gpo_id(&details), Some("primary-gpo".to_string()));
    }

    #[test]
    fn extract_gpo_id_none_when_empty() {
        let details = HashMap::new();
        assert_eq!(extract_gpo_id(&details), None);
    }

    #[test]
    fn extract_gpo_name_from_gpo_name_key() {
        let mut details = HashMap::new();
        details.insert("gpo_name".to_string(), json!("Default Domain Policy"));
        assert_eq!(
            extract_gpo_name(&details),
            Some("Default Domain Policy".to_string())
        );
    }

    #[test]
    fn extract_gpo_name_from_display_name_key() {
        let mut details = HashMap::new();
        details.insert(
            "gpo_display_name".to_string(),
            json!("Server Hardening Policy"),
        );
        assert_eq!(
            extract_gpo_name(&details),
            Some("Server Hardening Policy".to_string())
        );
    }

    #[test]
    fn extract_gpo_name_prefers_gpo_name_over_display_name() {
        let mut details = HashMap::new();
        details.insert("gpo_name".to_string(), json!("Primary Name"));
        details.insert("gpo_display_name".to_string(), json!("Display Name"));
        assert_eq!(extract_gpo_name(&details), Some("Primary Name".to_string()));
    }

    #[test]
    fn extract_gpo_name_none_when_empty() {
        let details = HashMap::new();
        assert_eq!(extract_gpo_name(&details), None);
    }

    #[test]
    fn extract_gpo_name_none_when_non_string() {
        let mut details = HashMap::new();
        details.insert("gpo_name".to_string(), json!(true));
        assert_eq!(extract_gpo_name(&details), None);
    }

    #[test]
    fn domain_extraction_from_details() {
        // Simulate the domain extraction logic from auto_gpo_abuse
        let mut details = HashMap::new();
        details.insert("domain".to_string(), json!("contoso.local"));
        let domain = details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_extraction_missing_defaults_empty() {
        let details: HashMap<String, Value> = HashMap::new();
        let domain = details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(domain, "");
    }
}
