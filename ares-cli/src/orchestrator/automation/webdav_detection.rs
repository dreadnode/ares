//! auto_webdav_detection -- detect WebDAV on hosts for NTLM relay.
//!
//! Hosts running WebClient service (WebDAV) accept HTTP-based NTLM auth,
//! which bypasses SMB signing requirements. This enables relay attacks
//! (HTTP→LDAP/SMB) even when SMB signing is enforced. WebDAV is commonly
//! enabled on IIS servers and member servers with WebClient service.
//!
//! This is a bridge module (like smb_signing.rs): it checks discovered hosts
//! for WebDAV indicators and registers `webdav_enabled` vulnerabilities
//! that downstream modules (ntlm_relay) can target.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::state::*;

/// Collect WebDAV work items from state (pure logic, no async).
fn collect_webdav_work(state: &StateInner) -> Vec<WebDavWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for host in &state.hosts {
        // Skip DCs (WebDAV relay is for member servers)
        if host.is_dc {
            continue;
        }

        // Check if host has WebDAV indicators in services
        let has_webdav = host.services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });

        if !has_webdav {
            continue;
        }

        let dedup_key = format!("webdav:{}", host.ip);
        if state.is_processed(DEDUP_WEBDAV_DETECTION, &dedup_key) {
            continue;
        }

        // Check if vuln already registered
        let vuln_id = format!("webdav_enabled_{}", host.ip.replace('.', "_"));
        if state.discovered_vulnerabilities.contains_key(&vuln_id) {
            continue;
        }

        let domain = host
            .hostname
            .find('.')
            .map(|i| host.hostname[i + 1..].to_lowercase())
            .unwrap_or_default();

        let cred = state
            .credentials
            .iter()
            .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain)
            .or_else(|| state.credentials.first())
            .cloned();

        let Some(cred) = cred else {
            continue;
        };

        items.push(WebDavWork {
            dedup_key,
            vuln_id,
            target_ip: host.ip.clone(),
            hostname: host.hostname.clone(),
            domain,
            credential: cred,
        });
    }

    items
}

use crate::orchestrator::dispatcher::Dispatcher;

/// Checks discovered hosts for WebDAV service and registers vulnerabilities.
/// Interval: 45s.
pub async fn auto_webdav_detection(
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

        if !dispatcher.is_technique_allowed("webdav_detection") {
            continue;
        }

        let work: Vec<WebDavWork> = {
            let state = dispatcher.state.read().await;
            collect_webdav_work(&state)
        };

        for item in work {
            // Dispatch a recon task to verify WebDAV is accessible
            let payload = json!({
                "technique": "webdav_check",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("webdav_detection");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "WebDAV detection check dispatched"
                    );

                    // Also register the vuln proactively (service tag is strong signal)
                    let vuln = ares_core::models::VulnerabilityInfo {
                        vuln_id: item.vuln_id,
                        vuln_type: "webdav_enabled".to_string(),
                        target: item.target_ip.clone(),
                        discovered_by: "auto_webdav_detection".to_string(),
                        discovered_at: chrono::Utc::now(),
                        details: {
                            let mut d = std::collections::HashMap::new();
                            d.insert(
                                "hostname".to_string(),
                                serde_json::Value::String(item.hostname.clone()),
                            );
                            d.insert(
                                "domain".to_string(),
                                serde_json::Value::String(item.domain.clone()),
                            );
                            d.insert(
                                "target_ip".to_string(),
                                serde_json::Value::String(item.target_ip.clone()),
                            );
                            d
                        },
                        recommended_agent: "coercion".to_string(),
                        priority: 4,
                    };

                    let _ = dispatcher
                        .state
                        .publish_vulnerability_with_strategy(
                            &dispatcher.queue,
                            vuln,
                            Some(&dispatcher.config.strategy),
                        )
                        .await;

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_WEBDAV_DETECTION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_WEBDAV_DETECTION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "WebDAV detection deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch WebDAV detection");
                }
            }
        }
    }
}

struct WebDavWork {
    dedup_key: String,
    vuln_id: String,
    target_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("webdav:{}", "192.168.58.22");
        assert_eq!(key, "webdav:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_WEBDAV_DETECTION, "webdav_detection");
    }

    #[test]
    fn webdav_service_detection_webdav() {
        let services = ["80/tcp webdav".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_detection_iis() {
        let services = ["80/tcp iis httpd".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_detection_http() {
        let services = ["80/tcp http".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn no_webdav_service() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "3389/tcp ms-wbt-server".to_string(),
        ];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(!has_webdav);
    }

    #[test]
    fn vuln_id_format() {
        let ip = "192.168.58.22";
        let vuln_id = format!("webdav_enabled_{}", ip.replace('.', "_"));
        assert_eq!(vuln_id, "webdav_enabled_192_168_58_22");
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "web01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn webdav_service_detection_webclient() {
        let services = ["WebClient service running".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_detection_case_insensitive() {
        let services = ["80/TCP WEBDAV".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_not_port_80_without_http() {
        // Port 80 alone without "http" keyword should not match
        let services = ["80/tcp other_service".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(!has_webdav);
    }

    #[test]
    fn domain_from_hostname_bare() {
        let hostname = "web01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn domain_from_hostname_subdomain() {
        let hostname = "web01.child.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "child.contoso.local");
    }

    #[test]
    fn vuln_id_format_various_ips() {
        let ips = ["192.168.58.10", "192.168.58.22", "192.168.58.240"];
        for ip in ips {
            let vuln_id = format!("webdav_enabled_{}", ip.replace('.', "_"));
            assert!(vuln_id.starts_with("webdav_enabled_"));
            assert!(!vuln_id.contains('.'));
        }
    }

    #[test]
    fn credential_domain_matching() {
        let domain = "contoso.local".to_string();
        let cred_domain = "CONTOSO.LOCAL";
        assert_eq!(cred_domain.to_lowercase(), domain);
    }

    #[test]
    fn credential_domain_matching_empty_domain() {
        let domain = "".to_string();
        let cred_domain = "contoso.local";
        // When domain is empty, the first branch should fail and fall through
        let matches = !domain.is_empty() && cred_domain.to_lowercase() == domain;
        assert!(!matches);
    }

    #[test]
    fn webdav_vuln_details_construction() {
        let hostname = "web01.contoso.local".to_string();
        let domain = "contoso.local".to_string();
        let target_ip = "192.168.58.22".to_string();
        let mut d = std::collections::HashMap::new();
        d.insert("hostname".to_string(), serde_json::Value::String(hostname));
        d.insert("domain".to_string(), serde_json::Value::String(domain));
        d.insert(
            "target_ip".to_string(),
            serde_json::Value::String(target_ip),
        );
        assert_eq!(d.len(), 3);
        assert_eq!(d["hostname"], serde_json::json!("web01.contoso.local"));
        assert_eq!(d["domain"], serde_json::json!("contoso.local"));
        assert_eq!(d["target_ip"], serde_json::json!("192.168.58.22"));
    }

    #[test]
    fn webdav_payload_structure() {
        let payload = serde_json::json!({
            "technique": "webdav_check",
            "target_ip": "192.168.58.22",
            "hostname": "web01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "webdav_check");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["hostname"], "web01.contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
    }

    #[test]
    fn empty_services_no_webdav() {
        let services: Vec<String> = vec![];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(!has_webdav);
    }

    // --- collect_webdav_work tests ---

    use crate::orchestrator::state::StateInner;

    fn make_host(
        ip: &str,
        hostname: &str,
        is_dc: bool,
        services: Vec<String>,
    ) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services,
            is_dc,
            owned: false,
        }
    }

    fn make_cred(username: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn collect_empty_state_produces_no_work() {
        let state = StateInner::new("test".into());
        let work = collect_webdav_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_produces_no_work() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        let work = collect_webdav_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_host_with_webdav_and_creds_produces_work() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_webdav_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.22");
        assert_eq!(work[0].hostname, "web01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dedup_key, "webdav:192.168.58.22");
        assert_eq!(work[0].vuln_id, "webdav_enabled_192_168_58_22");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_dc_hosts() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.10",
            "dc01.contoso.local",
            true,
            vec!["80/tcp webdav".to_string()],
        ));
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_webdav_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_host_without_webdav_services() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["445/tcp microsoft-ds".to_string()],
        ));
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_webdav_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_already_processed_dedup() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.mark_processed(DEDUP_WEBDAV_DETECTION, "webdav:192.168.58.22".into());
        let work = collect_webdav_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_already_registered_vuln() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.discovered_vulnerabilities.insert(
            "webdav_enabled_192_168_58_22".to_string(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "webdav_enabled_192_168_58_22".to_string(),
                vuln_type: "webdav_enabled".to_string(),
                target: "192.168.58.22".to_string(),
                discovered_by: "test".to_string(),
                discovered_at: chrono::Utc::now(),
                details: std::collections::HashMap::new(),
                recommended_agent: "coercion".to_string(),
                priority: 4,
            },
        );
        let work = collect_webdav_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_extracts_domain_from_hostname() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.30",
            "web01.fabrikam.local",
            false,
            vec!["80/tcp iis httpd".to_string()],
        ));
        state
            .credentials
            .push(make_cred("svc_web", "fabrikam.local"));
        let work = collect_webdav_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["WebClient service running".to_string()],
        ));
        // First cred is fabrikam, second is contoso (matching host domain)
        state
            .credentials
            .push(make_cred("user_fab", "fabrikam.local"));
        state
            .credentials
            .push(make_cred("user_con", "contoso.local"));
        let work = collect_webdav_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "user_con");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_falls_back_to_first_cred_when_no_domain_match() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        // Only fabrikam creds, host is contoso
        state
            .credentials
            .push(make_cred("user_fab", "fabrikam.local"));
        let work = collect_webdav_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "user_fab");
    }

    #[test]
    fn collect_bare_hostname_falls_back_to_first_cred() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        state
            .credentials
            .push(make_cred("fallback_user", "contoso.local"));
        let work = collect_webdav_work(&state);
        assert_eq!(work.len(), 1);
        // bare hostname has empty domain, so domain match fails; falls back to first
        assert_eq!(work[0].credential.username, "fallback_user");
        assert_eq!(work[0].domain, "");
    }

    #[test]
    fn collect_multiple_hosts_mixed() {
        let mut state = StateInner::new("test".into());
        // Good: member server with webdav
        state.hosts.push(make_host(
            "192.168.58.22",
            "web01.contoso.local",
            false,
            vec!["80/tcp webdav".to_string()],
        ));
        // Skipped: DC
        state.hosts.push(make_host(
            "192.168.58.10",
            "dc01.contoso.local",
            true,
            vec!["80/tcp webdav".to_string()],
        ));
        // Skipped: no webdav service
        state.hosts.push(make_host(
            "192.168.58.40",
            "sql01.contoso.local",
            false,
            vec!["1433/tcp ms-sql-s".to_string()],
        ));
        // Good: IIS server
        state.hosts.push(make_host(
            "192.168.58.50",
            "ws01.fabrikam.local",
            false,
            vec!["80/tcp iis httpd".to_string()],
        ));
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_webdav_work(&state);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].target_ip, "192.168.58.22");
        assert_eq!(work[1].target_ip, "192.168.58.50");
    }
}
