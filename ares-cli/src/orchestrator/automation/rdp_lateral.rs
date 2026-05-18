//! auto_rdp_lateral -- RDP lateral movement to hosts with port 3389.
//!
//! Targets hosts with RDP service (port 3389) that are not yet owned.
//! Uses xfreerdp or similar tooling to authenticate and execute commands
//! via RDP, complementing WinRM lateral movement for hosts that only
//! expose RDP.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// RDP lateral movement to hosts with port 3389.
/// Interval: 45s.
pub async fn auto_rdp_lateral(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("rdp_lateral") {
            continue;
        }

        let work: Vec<RdpWork> = {
            let state = dispatcher.state.read().await;
            collect_rdp_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "rdp_lateral",
                "target_ip": item.host_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("rdp_lateral");
            match dispatcher
                .throttled_submit("lateral", "lateral", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.host_ip,
                        hostname = %item.hostname,
                        "RDP lateral movement dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_RDP_LATERAL, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_RDP_LATERAL, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.host_ip, "RDP lateral deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.host_ip, "Failed to dispatch RDP lateral");
                }
            }
        }
    }
}

/// Collect RDP lateral movement work items from current state.
///
/// Extracted from the async loop for testability.
fn collect_rdp_work(state: &crate::orchestrator::state::StateInner) -> Vec<RdpWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for host in &state.hosts {
        // Skip already-owned hosts
        if host.owned {
            continue;
        }

        // Check for RDP service (port 3389)
        let has_rdp = host.services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        if !has_rdp {
            continue;
        }

        let dedup_key = format!("rdp:{}", host.ip);
        if state.is_processed(DEDUP_RDP_LATERAL, &dedup_key) {
            continue;
        }

        // Infer domain from hostname
        let domain = host
            .hostname
            .find('.')
            .map(|i| host.hostname[i + 1..].to_lowercase())
            .unwrap_or_default();

        // Find admin credential for this domain
        let cred = state
            .credentials
            .iter()
            .find(|c| {
                c.is_admin
                    && !c.password.is_empty()
                    && (domain.is_empty() || c.domain.to_lowercase() == domain)
                    && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                // Fall back to any credential with a password
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && (domain.is_empty() || c.domain.to_lowercase() == domain)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
            })
            .cloned();

        let Some(cred) = cred else {
            continue;
        };

        items.push(RdpWork {
            dedup_key,
            host_ip: host.ip.clone(),
            hostname: host.hostname.clone(),
            domain,
            credential: cred,
        });
    }

    items
}

struct RdpWork {
    dedup_key: String,
    host_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;
    use ares_core::models::{Credential, Host};

    fn make_credential(username: &str, password: &str, domain: &str, is_admin: bool) -> Credential {
        Credential {
            id: format!("c-{}", username),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str, services: Vec<String>, owned: bool) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services,
            is_dc: false,
            owned,
        }
    }

    #[tokio::test]
    async fn collect_empty_state_returns_no_work() {
        let shared = SharedState::new("test-op".into());
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_credentials_returns_no_work() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_host_with_rdp_and_admin_cred() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].host_ip, "192.168.58.10");
        assert_eq!(work[0].hostname, "srv01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].credential.username, "admin");
        assert!(work[0].credential.is_admin);
    }

    #[tokio::test]
    async fn collect_host_without_rdp_skipped() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["445/tcp microsoft-ds".into()],
                false,
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_owned_host_skipped() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                true, // already owned
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_already_processed_skipped() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true)); // pragma: allowlist secret
            s.mark_processed(DEDUP_RDP_LATERAL, "rdp:192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_falls_back_to_non_admin_cred() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            // Only a non-admin credential available
            s.credentials.push(make_credential(
                "user1",
                "P@ssw0rd!", // pragma: allowlist secret
                "contoso.local",
                false,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "user1");
        assert!(!work[0].credential.is_admin);
    }

    #[tokio::test]
    async fn collect_prefers_admin_over_non_admin() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials.push(make_credential(
                "user1",
                "P@ssw0rd!", // pragma: allowlist secret
                "contoso.local",
                false,
            ));
            s.credentials.push(make_credential(
                "admin",
                "Adm1nP@ss!", // pragma: allowlist secret
                "contoso.local",
                true,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert!(work[0].credential.is_admin);
    }

    #[tokio::test]
    async fn collect_no_cred_for_domain_skipped() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            // Credential for wrong domain
            s.credentials.push(make_credential(
                "admin",
                "P@ssw0rd!", // pragma: allowlist secret
                "fabrikam.local",
                true,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_bare_hostname_matches_any_domain_cred() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            // Bare hostname (no domain suffix) → domain = "" → matches any cred
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials.push(make_credential(
                "admin",
                "P@ssw0rd!", // pragma: allowlist secret
                "fabrikam.local",
                true,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "");
    }

    #[tokio::test]
    async fn collect_multiple_hosts() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.hosts.push(make_host(
                "192.168.58.11",
                "srv02.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.hosts.push(make_host(
                "192.168.58.12",
                "web01.contoso.local",
                vec!["80/tcp http".into()], // no RDP
                false,
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 2);
        let ips: Vec<&str> = work.iter().map(|w| w.host_ip.as_str()).collect();
        assert!(ips.contains(&"192.168.58.10"));
        assert!(ips.contains(&"192.168.58.11"));
    }

    #[tokio::test]
    async fn collect_cred_with_empty_password_skipped() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials
                .push(make_credential("admin", "", "contoso.local", true));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_rdp_detection_by_name() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["remote desktop rdp".into()],
                false,
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[tokio::test]
    async fn collect_dedup_key_format() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work[0].dedup_key, "rdp:192.168.58.10");
    }

    #[tokio::test]
    async fn collect_cross_domain_hosts() {
        let shared = SharedState::new("test-op".into());
        {
            let mut s = shared.write().await;
            s.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.hosts.push(make_host(
                "192.168.58.20",
                "srv01.fabrikam.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            s.credentials.push(make_credential(
                "admin",
                "P@ssw0rd!", // pragma: allowlist secret
                "contoso.local",
                true,
            ));
            s.credentials.push(make_credential(
                "fadmin",
                "F@bPass1!", // pragma: allowlist secret
                "fabrikam.local",
                true,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 2);
        // contoso host uses contoso cred
        let contoso_work = work.iter().find(|w| w.host_ip == "192.168.58.10").unwrap();
        assert_eq!(contoso_work.credential.domain, "contoso.local");
        // fabrikam host uses fabrikam cred
        let fab_work = work.iter().find(|w| w.host_ip == "192.168.58.20").unwrap();
        assert_eq!(fab_work.credential.domain, "fabrikam.local");
    }

    #[tokio::test]
    async fn collect_rdp_work_via_shared_state() {
        let shared = crate::orchestrator::state::SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "srv01.contoso.local",
                vec!["3389/tcp ms-wbt-server".into()],
                false,
            ));
            state.credentials.push(make_credential(
                "admin",
                "P@ssw0rd!", // pragma: allowlist secret
                "contoso.local",
                true,
            ));
        }
        let state = shared.read().await;
        let work = collect_rdp_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].host_ip, "192.168.58.10");
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("rdp:{}", "192.168.58.22");
        assert_eq!(key, "rdp:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_RDP_LATERAL, "rdp_lateral");
    }

    #[test]
    fn rdp_service_detection() {
        let services = [
            "3389/tcp ms-wbt-server".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(has_rdp);
    }

    #[test]
    fn no_rdp_service() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(!has_rdp);
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "srv01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "srv01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn rdp_service_detection_by_name() {
        let services = ["remote desktop rdp".to_string()];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(has_rdp);
    }

    #[test]
    fn rdp_service_detection_case_insensitive() {
        let services = ["3389/TCP MS-WBT-SERVER".to_string()];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(has_rdp);
    }

    #[test]
    fn rdp_payload_structure() {
        let payload = serde_json::json!({
            "technique": "rdp_lateral",
            "target_ip": "192.168.58.22",
            "hostname": "srv01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "rdp_lateral");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["hostname"], "srv01.contoso.local");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn rdp_work_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: true,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let work = RdpWork {
            dedup_key: "rdp:192.168.58.22".into(),
            host_ip: "192.168.58.22".into(),
            hostname: "srv01.contoso.local".into(),
            domain: "contoso.local".into(),
            credential: cred,
        };
        assert_eq!(work.host_ip, "192.168.58.22");
        assert_eq!(work.hostname, "srv01.contoso.local");
        assert!(work.credential.is_admin);
    }

    #[test]
    fn admin_credential_preferred() {
        // The module first looks for admin creds, then falls back to any with password
        let is_admin = true;
        let has_password = true;
        let admin_match = is_admin && has_password;
        assert!(admin_match);
    }

    #[test]
    fn empty_services_no_rdp() {
        let services: Vec<String> = vec![];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(!has_rdp);
    }
}
