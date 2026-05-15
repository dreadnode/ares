//! auto_certipy_auth -- authenticate using obtained certificates.
//!
//! After ADCS exploitation (ESC1/ESC4/ESC8) obtains a certificate (.pfx),
//! this automation dispatches `certipy auth` to convert the certificate
//! into an NT hash, enabling pass-the-hash for the impersonated user.
//!
//! Watches for `certificate_obtained` vulnerability type in discovered_vulnerabilities
//! which is registered by the ADCS exploitation result processor.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Authenticates with obtained certificates to extract NT hashes.
/// Interval: 30s.
pub async fn auto_certipy_auth(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("certipy_auth") {
            continue;
        }

        let work: Vec<CertAuthWork> = {
            let state = dispatcher.state.read().await;
            collect_cert_auth_work(&state)
        };

        for item in work {
            let mut payload = json!({
                "technique": "certipy_auth",
                "vuln_id": item.vuln_id,
                "pfx_path": item.pfx_path,
                "domain": item.domain,
                "target_user": item.target_user,
            });

            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
                payload["dc_ip"] = json!(dc);
            }

            let priority = dispatcher.effective_priority("certipy_auth");
            // Route to `privesc` — `certipy_auth` is registered in the
            // privesc toolset (alongside the rest of the ADCS chain). The
            // `credential_access` role does NOT carry certipy_auth, so the
            // old routing produced an immediate "tool not available in
            // this agent's toolset" assist-abandon every dispatch, wasting
            // ~30k input tokens per attempt while leaking the captured
            // .pfx. The task_type stays `credential_access` because the
            // semantic goal is to surface an NT hash.
            match dispatcher
                .throttled_submit("credential_access", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        user = %item.target_user,
                        "Certificate authentication dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CERTIPY_AUTH, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CERTIPY_AUTH, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(vuln_id = %item.vuln_id, "Certificate auth deferred");
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch cert auth");
                }
            }
        }
    }
}

/// Pure logic extracted from `auto_certipy_auth` so it can be unit-tested without
/// needing a `Dispatcher` or async runtime (beyond state construction).
fn collect_cert_auth_work(state: &crate::orchestrator::state::StateInner) -> Vec<CertAuthWork> {
    state
        .discovered_vulnerabilities
        .values()
        .filter_map(|vuln| {
            let vtype = vuln.vuln_type.to_lowercase();
            if vtype != "certificate_obtained" && vtype != "adcs_certificate" {
                return None;
            }

            if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                return None;
            }

            let dedup_key = format!("cert_auth:{}", vuln.vuln_id);
            if state.is_processed(DEDUP_CERTIPY_AUTH, &dedup_key) {
                return None;
            }

            let pfx_path = vuln
                .details
                .get("pfx_path")
                .or_else(|| vuln.details.get("certificate_path"))
                .or_else(|| vuln.details.get("cert_file"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())?;

            let domain = vuln
                .details
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let target_user = vuln
                .details
                .get("target_user")
                .or_else(|| vuln.details.get("upn"))
                .or_else(|| vuln.details.get("account_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("administrator")
                .to_string();

            let dc_ip = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned();

            Some(CertAuthWork {
                vuln_id: vuln.vuln_id.clone(),
                dedup_key,
                pfx_path,
                domain,
                target_user,
                dc_ip,
            })
        })
        .collect()
}

struct CertAuthWork {
    vuln_id: String,
    dedup_key: String,
    pfx_path: String,
    domain: String,
    target_user: String,
    dc_ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("cert_auth:{}", "vuln-cert-001");
        assert_eq!(key, "cert_auth:vuln-cert-001");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_CERTIPY_AUTH, "certipy_auth");
    }

    #[test]
    fn cert_vuln_types_accepted() {
        let types = [
            "certificate_obtained",
            "adcs_certificate",
            "CERTIFICATE_OBTAINED",
        ];
        for t in &types {
            let lower = t.to_lowercase();
            assert!(
                lower == "certificate_obtained" || lower == "adcs_certificate",
                "{t} should match"
            );
        }
    }

    #[test]
    fn non_cert_vuln_types_rejected() {
        let non_cert = ["esc1", "smb_signing_disabled", "mssql_access"];
        for t in &non_cert {
            let lower = t.to_lowercase();
            assert!(lower != "certificate_obtained" && lower != "adcs_certificate");
        }
    }

    #[test]
    fn pfx_path_fallback_chain() {
        // Primary key
        let details = serde_json::json!({"pfx_path": "/tmp/cert.pfx"});
        let path = details
            .get("pfx_path")
            .or_else(|| details.get("certificate_path"))
            .or_else(|| details.get("cert_file"))
            .and_then(|v| v.as_str());
        assert_eq!(path, Some("/tmp/cert.pfx"));

        // Fallback to certificate_path
        let details2 = serde_json::json!({"certificate_path": "/tmp/alt.pfx"});
        let path2 = details2
            .get("pfx_path")
            .or_else(|| details2.get("certificate_path"))
            .or_else(|| details2.get("cert_file"))
            .and_then(|v| v.as_str());
        assert_eq!(path2, Some("/tmp/alt.pfx"));

        // Fallback to cert_file
        let details3 = serde_json::json!({"cert_file": "/tmp/other.pfx"});
        let path3 = details3
            .get("pfx_path")
            .or_else(|| details3.get("certificate_path"))
            .or_else(|| details3.get("cert_file"))
            .and_then(|v| v.as_str());
        assert_eq!(path3, Some("/tmp/other.pfx"));

        // No key returns None
        let details4 = serde_json::json!({});
        let path4 = details4
            .get("pfx_path")
            .or_else(|| details4.get("certificate_path"))
            .or_else(|| details4.get("cert_file"))
            .and_then(|v| v.as_str());
        assert!(path4.is_none());
    }

    #[test]
    fn target_user_fallback() {
        let details = serde_json::json!({"target_user": "admin"});
        let user = details
            .get("target_user")
            .or_else(|| details.get("upn"))
            .or_else(|| details.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("administrator");
        assert_eq!(user, "admin");

        // Falls back to "administrator" when no key present
        let details2 = serde_json::json!({});
        let user2 = details2
            .get("target_user")
            .or_else(|| details2.get("upn"))
            .or_else(|| details2.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("administrator");
        assert_eq!(user2, "administrator");
    }

    #[test]
    fn cert_auth_payload_structure() {
        let payload = serde_json::json!({
            "technique": "certipy_auth",
            "vuln_id": "cert-001",
            "pfx_path": "/tmp/cert.pfx",
            "domain": "contoso.local",
            "target_user": "administrator",
        });
        assert_eq!(payload["technique"], "certipy_auth");
        assert_eq!(payload["pfx_path"], "/tmp/cert.pfx");
        assert_eq!(payload["target_user"], "administrator");
    }

    #[test]
    fn cert_auth_payload_with_dc() {
        let mut payload = serde_json::json!({
            "technique": "certipy_auth",
            "vuln_id": "cert-001",
            "pfx_path": "/tmp/cert.pfx",
            "domain": "contoso.local",
            "target_user": "administrator",
        });
        let dc_ip = Some("192.168.58.10".to_string());
        if let Some(ref dc) = dc_ip {
            payload["target_ip"] = serde_json::json!(dc);
            payload["dc_ip"] = serde_json::json!(dc);
        }
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["dc_ip"], "192.168.58.10");
    }

    #[test]
    fn cert_auth_payload_without_dc() {
        let payload = serde_json::json!({
            "technique": "certipy_auth",
            "vuln_id": "cert-001",
            "pfx_path": "/tmp/cert.pfx",
            "domain": "contoso.local",
            "target_user": "administrator",
        });
        assert!(payload.get("target_ip").is_none());
        assert!(payload.get("dc_ip").is_none());
    }

    #[test]
    fn target_user_upn_fallback() {
        let details = serde_json::json!({"upn": "admin@contoso.local"});
        let user = details
            .get("target_user")
            .or_else(|| details.get("upn"))
            .or_else(|| details.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("administrator");
        assert_eq!(user, "admin@contoso.local");
    }

    #[test]
    fn target_user_account_name_fallback() {
        let details = serde_json::json!({"account_name": "svc_sql"});
        let user = details
            .get("target_user")
            .or_else(|| details.get("upn"))
            .or_else(|| details.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("administrator");
        assert_eq!(user, "svc_sql");
    }

    #[test]
    fn cert_auth_work_construction() {
        let work = CertAuthWork {
            vuln_id: "cert-001".into(),
            dedup_key: "cert_auth:cert-001".into(),
            pfx_path: "/tmp/cert.pfx".into(),
            domain: "contoso.local".into(),
            target_user: "administrator".into(),
            dc_ip: Some("192.168.58.10".into()),
        };
        assert_eq!(work.vuln_id, "cert-001");
        assert_eq!(work.dc_ip, Some("192.168.58.10".into()));
    }

    #[test]
    fn cert_auth_work_no_dc() {
        let work = CertAuthWork {
            vuln_id: "cert-002".into(),
            dedup_key: "cert_auth:cert-002".into(),
            pfx_path: "/tmp/cert2.pfx".into(),
            domain: "fabrikam.local".into(),
            target_user: "admin".into(),
            dc_ip: None,
        };
        assert!(work.dc_ip.is_none());
    }

    // -- Tests exercising the extracted `collect_cert_auth_work` function --

    use crate::orchestrator::state::SharedState;

    fn make_vuln(
        vuln_id: &str,
        vuln_type: &str,
        details: std::collections::HashMap<String, serde_json::Value>,
    ) -> ares_core::models::VulnerabilityInfo {
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.into(),
            vuln_type: vuln_type.into(),
            target: "192.168.58.10".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    #[tokio::test]
    async fn collect_empty_state_returns_no_work() {
        let shared = SharedState::new("test".into());
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_certificate_obtained_vuln_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/admin.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            details.insert("target_user".into(), serde_json::json!("administrator"));
            s.discovered_vulnerabilities.insert(
                "cert-001".into(),
                make_vuln("cert-001", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_id, "cert-001");
        assert_eq!(work[0].pfx_path, "/tmp/admin.pfx");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].target_user, "administrator");
        assert_eq!(work[0].dedup_key, "cert_auth:cert-001");
        assert!(work[0].dc_ip.is_none());
    }

    #[tokio::test]
    async fn collect_adcs_certificate_vuln_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/svc.pfx"));
            details.insert("domain".into(), serde_json::json!("fabrikam.local"));
            details.insert("target_user".into(), serde_json::json!("svc_sql"));
            s.discovered_vulnerabilities.insert(
                "cert-002".into(),
                make_vuln("cert-002", "adcs_certificate", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_id, "cert-002");
        assert_eq!(work[0].domain, "fabrikam.local");
        assert_eq!(work[0].target_user, "svc_sql");
    }

    #[tokio::test]
    async fn collect_ignores_non_cert_vuln_types() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            s.discovered_vulnerabilities
                .insert("vuln-esc1".into(), make_vuln("vuln-esc1", "esc1", details));
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_skips_exploited_vulnerabilities() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-010".into(),
                make_vuln("cert-010", "certificate_obtained", details),
            );
            s.exploited_vulnerabilities.insert("cert-010".into());
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_skips_already_deduped() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-020".into(),
                make_vuln("cert-020", "certificate_obtained", details),
            );
            s.mark_processed(DEDUP_CERTIPY_AUTH, "cert_auth:cert-020".into());
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_skips_vuln_without_pfx_path() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            // No pfx_path, certificate_path, or cert_file key at all
            let mut details = std::collections::HashMap::new();
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-030".into(),
                make_vuln("cert-030", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_pfx_fallback_to_certificate_path() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("certificate_path".into(), serde_json::json!("/tmp/alt.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-040".into(),
                make_vuln("cert-040", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].pfx_path, "/tmp/alt.pfx");
    }

    #[tokio::test]
    async fn collect_pfx_fallback_to_cert_file() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("cert_file".into(), serde_json::json!("/tmp/other.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-050".into(),
                make_vuln("cert-050", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].pfx_path, "/tmp/other.pfx");
    }

    #[tokio::test]
    async fn collect_target_user_defaults_to_administrator() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            // No target_user, upn, or account_name
            s.discovered_vulnerabilities.insert(
                "cert-060".into(),
                make_vuln("cert-060", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_user, "administrator");
    }

    #[tokio::test]
    async fn collect_target_user_from_upn() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            details.insert("upn".into(), serde_json::json!("admin@contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-070".into(),
                make_vuln("cert-070", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_user, "admin@contoso.local");
    }

    #[tokio::test]
    async fn collect_target_user_from_account_name() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            details.insert("account_name".into(), serde_json::json!("svc_web"));
            s.discovered_vulnerabilities.insert(
                "cert-080".into(),
                make_vuln("cert-080", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_user, "svc_web");
    }

    #[tokio::test]
    async fn collect_resolves_dc_ip_from_domain_controllers() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-090".into(),
                make_vuln("cert-090", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip, Some("192.168.58.10".into()));
    }

    #[tokio::test]
    async fn collect_dc_ip_none_when_domain_not_mapped() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            // DC registered for a different domain
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-100".into(),
                make_vuln("cert-100", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert!(work[0].dc_ip.is_none());
    }

    #[tokio::test]
    async fn collect_domain_defaults_to_empty_string() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            // No domain key in details
            s.discovered_vulnerabilities.insert(
                "cert-110".into(),
                make_vuln("cert-110", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "");
    }

    #[tokio::test]
    async fn collect_case_insensitive_vuln_type() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            details.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-120".into(),
                make_vuln("cert-120", "CERTIFICATE_OBTAINED", details.clone()),
            );
            s.discovered_vulnerabilities.insert(
                "cert-121".into(),
                make_vuln("cert-121", "Adcs_Certificate", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[tokio::test]
    async fn collect_multiple_vulns_mixed_types() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            // Valid cert vuln
            let mut d1 = std::collections::HashMap::new();
            d1.insert("pfx_path".into(), serde_json::json!("/tmp/a.pfx"));
            d1.insert("domain".into(), serde_json::json!("contoso.local"));
            s.discovered_vulnerabilities.insert(
                "cert-200".into(),
                make_vuln("cert-200", "certificate_obtained", d1),
            );

            // Non-cert vuln (should be ignored)
            let mut d2 = std::collections::HashMap::new();
            d2.insert("target_ip".into(), serde_json::json!("192.168.58.22"));
            s.discovered_vulnerabilities.insert(
                "vuln-smb".into(),
                make_vuln("vuln-smb", "smb_signing_disabled", d2),
            );

            // Another valid cert vuln
            let mut d3 = std::collections::HashMap::new();
            d3.insert("pfx_path".into(), serde_json::json!("/tmp/b.pfx"));
            d3.insert("domain".into(), serde_json::json!("fabrikam.local"));
            s.discovered_vulnerabilities.insert(
                "cert-201".into(),
                make_vuln("cert-201", "adcs_certificate", d3),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 2);
        let ids: std::collections::HashSet<_> = work.iter().map(|w| w.vuln_id.as_str()).collect();
        assert!(ids.contains("cert-200"));
        assert!(ids.contains("cert-201"));
    }

    #[tokio::test]
    async fn collect_dc_ip_lookup_is_case_insensitive() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            // DC stored under lowercase
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            let mut details = std::collections::HashMap::new();
            details.insert("pfx_path".into(), serde_json::json!("/tmp/cert.pfx"));
            // Domain in mixed case in vuln details
            details.insert("domain".into(), serde_json::json!("CONTOSO.LOCAL"));
            s.discovered_vulnerabilities.insert(
                "cert-130".into(),
                make_vuln("cert-130", "certificate_obtained", details),
            );
        }
        let state = shared.read().await;
        let work = collect_cert_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip, Some("192.168.58.10".into()));
    }
}
