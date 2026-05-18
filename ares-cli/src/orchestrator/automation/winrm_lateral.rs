//! auto_winrm_lateral -- attempt WinRM lateral movement with owned credentials.
//!
//! WinRM (port 5985/5986) is a common lateral movement vector in AD environments.
//! evil-winrm provides PowerShell remoting access when credentials are valid and
//! the user has remote management rights. This module dispatches WinRM access
//! attempts against hosts where we have credentials but haven't tried WinRM yet.
//!
//! WinRM complements SMB-based lateral movement (psexec/wmiexec) by working even
//! when SMB is restricted or firewall-filtered.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect WinRM lateral movement work items from current state.
///
/// Pure logic extracted from `auto_winrm_lateral` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_winrm_lateral_work(state: &StateInner) -> Vec<WinRmWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for host in &state.hosts {
        // Check if host has WinRM indicators in services
        let has_winrm = host.services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
        });

        if !has_winrm {
            continue;
        }

        // Skip hosts we already own via secretsdump
        if state.is_processed(DEDUP_SECRETSDUMP, &host.ip) {
            continue;
        }

        let dedup_key = format!("winrm:{}", host.ip);
        if state.is_processed(DEDUP_WINRM_LATERAL, &dedup_key) {
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

        items.push(WinRmWork {
            dedup_key,
            target_ip: host.ip.clone(),
            hostname: host.hostname.clone(),
            domain,
            credential: cred,
        });
    }

    items
}

/// Attempts WinRM lateral movement against hosts with owned credentials.
/// Interval: 45s.
pub async fn auto_winrm_lateral(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("winrm_lateral") {
            continue;
        }

        let work: Vec<WinRmWork> = {
            let state = dispatcher.state.read().await;
            collect_winrm_lateral_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "winrm_exec",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("winrm_lateral");
            match dispatcher
                .throttled_submit("lateral", "lateral", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "WinRM lateral movement dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_WINRM_LATERAL, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_WINRM_LATERAL, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "WinRM lateral deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch WinRM lateral");
                }
            }
        }
    }
}

struct WinRmWork {
    dedup_key: String,
    target_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::StateInner;
    use ares_core::models::{Credential, Host};

    fn make_credential(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str, services: Vec<String>) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services,
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("winrm:{}", "192.168.58.22");
        assert_eq!(key, "winrm:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_WINRM_LATERAL, "winrm_lateral");
    }

    #[test]
    fn winrm_service_detection() {
        let services = [
            "5985/tcp microsoft-httpapi".to_string(),
            "445/tcp microsoft-ds".to_string(),
        ];
        let has_winrm = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
        });
        assert!(has_winrm);
    }

    #[test]
    fn winrm_https_service_detection() {
        let services = ["5986/tcp ssl/http".to_string()];
        let has_winrm = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
        });
        assert!(has_winrm);
    }

    #[test]
    fn no_winrm_service() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "3389/tcp ms-wbt-server".to_string(),
        ];
        let has_winrm = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
        });
        assert!(!has_winrm);
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
    fn payload_structure_validation() {
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

        let payload = serde_json::json!({
            "technique": "winrm_exec",
            "target_ip": "192.168.58.30",
            "hostname": "srv01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "winrm_exec");
        assert_eq!(payload["target_ip"], "192.168.58.30");
        assert_eq!(payload["hostname"], "srv01.contoso.local");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "testuser".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let work = WinRmWork {
            dedup_key: "winrm:192.168.58.30".into(),
            target_ip: "192.168.58.30".into(),
            hostname: "srv01.contoso.local".into(),
            domain: "contoso.local".into(),
            credential: cred,
        };

        assert_eq!(work.dedup_key, "winrm:192.168.58.30");
        assert_eq!(work.target_ip, "192.168.58.30");
        assert_eq!(work.hostname, "srv01.contoso.local");
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.credential.username, "testuser");
    }

    #[test]
    fn winrm_service_detection_variations() {
        let test_cases = vec![
            (vec!["5985/tcp http".to_string()], true),
            (vec!["5986/tcp ssl/http".to_string()], true),
            (vec!["winrm-service".to_string()], true),
            (vec!["WinRM".to_string()], true),
            (vec!["445/tcp smb".to_string()], false),
            (vec!["3389/tcp rdp".to_string()], false),
        ];

        for (services, expected) in test_cases {
            let has_winrm = services.iter().any(|s| {
                let sl = s.to_lowercase();
                sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
            });
            assert_eq!(
                has_winrm, expected,
                "Services {:?} should have winrm={expected}",
                services
            );
        }
    }

    #[test]
    fn domain_from_fabrikam_host() {
        let hostname = "web01.fabrikam.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "fabrikam.local");
    }

    #[test]
    fn empty_services() {
        let services: Vec<String> = vec![];
        let has_winrm = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
        });
        assert!(!has_winrm, "Empty services should not detect WinRM");
    }

    // --- collect_winrm_lateral_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_winrm_lateral_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["5985/tcp http".into()],
        ));
        let work = collect_winrm_lateral_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_winrm_hosts_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["445/tcp smb".into()],
        ));
        let work = collect_winrm_lateral_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_winrm_host_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["5985/tcp http".into()],
        ));
        let work = collect_winrm_lateral_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.30");
        assert_eq!(work[0].hostname, "srv01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dedup_key, "winrm:192.168.58.30");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_already_secretsdumped_host() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["5985/tcp http".into()],
        ));
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.30".into());
        let work = collect_winrm_lateral_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["5985/tcp http".into()],
        ));
        state.mark_processed(DEDUP_WINRM_LATERAL, "winrm:192.168.58.30".into());
        let work = collect_winrm_lateral_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_multiple_hosts_produces_work_for_each() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["5985/tcp http".into()],
        ));
        state.hosts.push(make_host(
            "192.168.58.31",
            "web01.contoso.local",
            vec!["5986/tcp ssl/http".into()],
        ));
        let work = collect_winrm_lateral_work(&state);
        assert_eq!(work.len(), 2);
        let ips: Vec<&str> = work.iter().map(|w| w.target_ip.as_str()).collect();
        assert!(ips.contains(&"192.168.58.30"));
        assert!(ips.contains(&"192.168.58.31"));
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01.contoso.local",
            vec!["5985/tcp http".into()],
        ));
        let work = collect_winrm_lateral_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_falls_back_to_first_credential_bare_hostname() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.hosts.push(make_host(
            "192.168.58.30",
            "srv01",
            vec!["5985/tcp http".into()],
        ));
        let work = collect_winrm_lateral_work(&state);
        assert_eq!(work.len(), 1);
        // Bare hostname -> empty domain -> falls back to first cred
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].domain, "");
    }

    #[tokio::test]
    async fn collect_via_shared_state() {
        let shared = SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
            state.hosts.push(make_host(
                "192.168.58.30",
                "srv01.contoso.local",
                vec!["5985/tcp http".into()],
            ));
        }
        let state = shared.read().await;
        let work = collect_winrm_lateral_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.30");
    }
}
