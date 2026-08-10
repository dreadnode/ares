//! auto_smbclient_enum -- authenticated SMB share listing per domain.
//!
//! Complements auto_share_enumeration by using authenticated sessions to
//! discover shares that require credentials. Uses smbclient or netexec
//! to list shares on all known hosts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect SMB enumeration work items from current state.
///
/// Pure logic extracted from the async loop so it can be unit-tested
/// without a Dispatcher or runtime.
fn collect_smbclient_work(state: &crate::orchestrator::state::StateInner) -> Vec<SmbEnumWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for host in &state.hosts {
        let has_smb = host.services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        if !has_smb {
            continue;
        }

        let dedup_key = format!("smb_auth_enum:{}", host.ip);
        if state.is_processed(DEDUP_SMBCLIENT_ENUM, &dedup_key) {
            continue;
        }

        let domain = host
            .hostname
            .find('.')
            .map(|i| host.hostname[i + 1..].to_string())
            .unwrap_or_default();

        let cred = match state
            .credentials
            .iter()
            .find(|c| {
                !domain.is_empty()
                    && c.domain.to_lowercase() == domain.to_lowercase()
                    && !c.password.is_empty()
                    && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
            }) {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(SmbEnumWork {
            dedup_key,
            target_ip: host.ip.clone(),
            hostname: host.hostname.clone(),
            domain,
            credential: cred,
        });
    }

    items
}

/// Dispatches authenticated SMB share enumeration per host.
/// Interval: 45s.
pub async fn auto_smbclient_enum(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("smbclient_enum") {
            continue;
        }

        let work: Vec<SmbEnumWork> = {
            let state = dispatcher.state.read().await;
            let items = collect_smbclient_work(&state);
            if items.is_empty() {
                continue;
            }
            items
        };

        for item in work {
            let payload = json!({
                "technique": "authenticated_share_enumeration",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("smbclient_enum");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.target_ip,
                        "Authenticated SMB share enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SMBCLIENT_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SMBCLIENT_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.target_ip, "SMB auth enum deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.target_ip, "Failed to dispatch SMB auth enum");
                }
            }
        }
    }
}

struct SmbEnumWork {
    dedup_key: String,
    target_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;

    /// Helper: create a credential for tests.
    fn make_cred(user: &str, pass: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}"),
            username: user.into(),
            password: pass.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    /// Helper: create a host with given services.
    fn make_host(ip: &str, hostname: &str, services: Vec<&str>) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: vec![],
            services: services.into_iter().map(String::from).collect(),
            is_dc: false,
            owned: false,
        }
    }

    #[tokio::test]
    async fn collect_empty_state_returns_nothing() {
        let shared = SharedState::new("op-test".into());
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_credentials_returns_nothing() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_smb_hosts_returns_nothing() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "web01.contoso.local",
                vec!["80/tcp http", "443/tcp https"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_single_host_single_cred() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.10");
        assert_eq!(work[0].hostname, "dc01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].dedup_key, "smb_auth_enum:192.168.58.10");
    }

    #[tokio::test]
    async fn collect_multiple_hosts() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state.hosts.push(make_host(
                "192.168.58.20",
                "srv01.contoso.local",
                vec!["445/tcp smb", "80/tcp http"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 2);
        let ips: Vec<&str> = work.iter().map(|w| w.target_ip.as_str()).collect();
        assert!(ips.contains(&"192.168.58.10"));
        assert!(ips.contains(&"192.168.58.20"));
    }

    #[tokio::test]
    async fn collect_dedup_skips_already_processed() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state.hosts.push(make_host(
                "192.168.58.20",
                "srv01.contoso.local",
                vec!["445/tcp smb"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
            state.mark_processed(DEDUP_SMBCLIENT_ENUM, "smb_auth_enum:192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.20");
    }

    #[tokio::test]
    async fn collect_prefers_same_domain_credential() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state
                .credentials
                .push(make_cred("fab_user", "Fab123!", "fabrikam.local")); // pragma: allowlist secret
            state
                .credentials
                .push(make_cred("con_user", "Con123!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "con_user");
    }

    #[tokio::test]
    async fn collect_falls_back_to_any_credential_when_no_domain_match() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state
                .credentials
                .push(make_cred("fab_user", "Fab123!", "fabrikam.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fab_user");
    }

    #[tokio::test]
    async fn collect_skips_empty_password_credentials() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state
                .credentials
                .push(make_cred("admin", "", "contoso.local"));
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_skips_empty_password_falls_back() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds"],
            ));
            state
                .credentials
                .push(make_cred("admin", "", "contoso.local"));
            state
                .credentials
                .push(make_cred("fab_user", "Fab123!", "fabrikam.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fab_user");
    }

    #[tokio::test]
    async fn collect_bare_hostname_empty_domain() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state
                .hosts
                .push(make_host("192.168.58.10", "srv01", vec!["445/tcp smb"]));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[tokio::test]
    async fn collect_cifs_service_detected() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "nas01.contoso.local",
                vec!["cifs file share"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[tokio::test]
    async fn collect_case_insensitive_domain_matching() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.CONTOSO.LOCAL",
                vec!["445/tcp smb"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "CONTOSO.LOCAL");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[tokio::test]
    async fn collect_mixed_smb_and_non_smb_hosts() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp microsoft-ds", "88/tcp kerberos"],
            ));
            state.hosts.push(make_host(
                "192.168.58.20",
                "web01.contoso.local",
                vec!["80/tcp http", "443/tcp https"],
            ));
            state.hosts.push(make_host(
                "192.168.58.30",
                "sql01.contoso.local",
                vec!["1433/tcp mssql", "445/tcp smb"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 2);
        let ips: Vec<&str> = work.iter().map(|w| w.target_ip.as_str()).collect();
        assert!(ips.contains(&"192.168.58.10"));
        assert!(!ips.contains(&"192.168.58.20"));
        assert!(ips.contains(&"192.168.58.30"));
    }

    #[tokio::test]
    async fn collect_all_deduped_returns_nothing() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp smb"],
            ));
            state.hosts.push(make_host(
                "192.168.58.20",
                "srv01.contoso.local",
                vec!["445/tcp smb"],
            ));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
            state.mark_processed(DEDUP_SMBCLIENT_ENUM, "smb_auth_enum:192.168.58.10".into());
            state.mark_processed(DEDUP_SMBCLIENT_ENUM, "smb_auth_enum:192.168.58.20".into());
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_cross_domain_hosts_get_correct_creds() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp smb"],
            ));
            state.hosts.push(make_host(
                "192.168.58.20",
                "dc02.fabrikam.local",
                vec!["445/tcp smb"],
            ));
            state
                .credentials
                .push(make_cred("con_admin", "ConPass!", "contoso.local")); // pragma: allowlist secret
            state
                .credentials
                .push(make_cred("fab_admin", "FabPass!", "fabrikam.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert_eq!(work.len(), 2);

        let contoso_work = work
            .iter()
            .find(|w| w.target_ip == "192.168.58.10")
            .unwrap();
        assert_eq!(contoso_work.credential.username, "con_admin");

        let fabrikam_work = work
            .iter()
            .find(|w| w.target_ip == "192.168.58.20")
            .unwrap();
        assert_eq!(fabrikam_work.credential.username, "fab_admin");
    }

    #[tokio::test]
    async fn collect_only_empty_password_creds_returns_nothing() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state.hosts.push(make_host(
                "192.168.58.10",
                "dc01.contoso.local",
                vec!["445/tcp smb"],
            ));
            state
                .credentials
                .push(make_cred("user1", "", "contoso.local"));
            state
                .credentials
                .push(make_cred("user2", "", "fabrikam.local"));
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_host_with_empty_services() {
        let shared = SharedState::new("op-test".into());
        {
            let mut state = shared.write().await;
            state
                .hosts
                .push(make_host("192.168.58.10", "dc01.contoso.local", vec![]));
            state
                .credentials
                .push(make_cred("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_smbclient_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("smb_auth_enum:{}", "192.168.58.10");
        assert_eq!(key, "smb_auth_enum:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SMBCLIENT_ENUM, "smbclient_enum");
    }

    #[test]
    fn smb_service_detection() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn smb_service_detection_by_name() {
        let services = ["microsoft-ds smb".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn no_smb_service() {
        let services = [
            "3389/tcp ms-wbt-server".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(!has_smb);
    }

    #[test]
    fn domain_from_hostname_preserves_case() {
        // smbclient_enum uses to_string() not to_lowercase() for domain
        let hostname = "srv01.CONTOSO.LOCAL";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_string())
            .unwrap_or_default();
        assert_eq!(domain, "CONTOSO.LOCAL");
    }

    #[test]
    fn smb_service_detection_cifs() {
        let services = ["cifs share".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "srv01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_string())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn smb_enum_payload_structure() {
        let payload = serde_json::json!({
            "technique": "authenticated_share_enumeration",
            "target_ip": "192.168.58.22",
            "hostname": "srv01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "authenticated_share_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["credential"]["username"], "admin");
    }

    #[test]
    fn credential_domain_matching_case_insensitive() {
        let domain = "contoso.local";
        let cred_domain = "CONTOSO.LOCAL";
        assert_eq!(cred_domain.to_lowercase(), domain.to_lowercase());
    }

    #[test]
    fn credential_domain_matching_empty_skips() {
        let domain = "".to_string();
        let cred_domain = "contoso.local";
        let matches = !domain.is_empty() && cred_domain.to_lowercase() == domain.to_lowercase();
        assert!(!matches);
    }

    #[test]
    fn smb_enum_work_construction() {
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
        let work = SmbEnumWork {
            dedup_key: "smb_auth_enum:192.168.58.22".into(),
            target_ip: "192.168.58.22".into(),
            hostname: "srv01.contoso.local".into(),
            domain: "contoso.local".into(),
            credential: cred,
        };
        assert_eq!(work.target_ip, "192.168.58.22");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn empty_services_no_smb() {
        let services: Vec<String> = vec![];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(!has_smb);
    }
}
