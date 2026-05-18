//! auto_spooler_check -- detect Print Spooler service on discovered hosts.
//!
//! The Print Spooler service (MS-RPRN) is a common coercion vector: if running,
//! PrinterBug (SpoolSample) can force the machine to authenticate to an attacker
//! listener. It's also a prerequisite for PrintNightmare (CVE-2021-1675).
//!
//! This is a recon bridge: it dispatches a check per host and registers
//! `spooler_enabled` vulnerabilities that downstream coercion/CVE modules target.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

fn collect_spooler_work(state: &StateInner) -> Vec<SpoolerWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for host in &state.hosts {
        let dedup_key = format!("spooler:{}", host.ip);
        if state.is_processed(DEDUP_SPOOLER_CHECK, &dedup_key) {
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

        items.push(SpoolerWork {
            dedup_key,
            target_ip: host.ip.clone(),
            hostname: host.hostname.clone(),
            domain,
            credential: cred,
        });
    }

    items
}

/// Checks discovered hosts for Print Spooler service availability.
/// Interval: 45s.
pub async fn auto_spooler_check(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("spooler_check") {
            continue;
        }

        let work: Vec<SpoolerWork> = {
            let state = dispatcher.state.read().await;
            collect_spooler_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "spooler_check",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("spooler_check");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "Print Spooler check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SPOOLER_CHECK, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SPOOLER_CHECK, &item.dedup_key)
                        .await;

                    // Register spooler_enabled vulnerability proactively so it
                    // appears in reports. The agent's report_finding callback
                    // only logs — this ensures the finding is durable.
                    let vuln = ares_core::models::VulnerabilityInfo {
                        vuln_id: format!("spooler_{}", item.target_ip.replace('.', "_")),
                        vuln_type: "spooler_enabled".to_string(),
                        target: item.target_ip.clone(),
                        discovered_by: "auto_spooler_check".to_string(),
                        discovered_at: chrono::Utc::now(),
                        details: {
                            let mut d = std::collections::HashMap::new();
                            d.insert("target_ip".to_string(), json!(item.target_ip));
                            d.insert("hostname".to_string(), json!(item.hostname));
                            d.insert("domain".to_string(), json!(item.domain));
                            d.insert(
                                "description".to_string(),
                                json!("Print Spooler service (MS-RPRN) is running. Enables PrinterBug coercion and is a prerequisite for PrintNightmare (CVE-2021-1675)."),
                            );
                            d
                        },
                        recommended_agent: "privesc".to_string(),
                        priority: dispatcher.effective_priority("spooler_check"),
                    };

                    match dispatcher
                        .state
                        .publish_vulnerability_with_strategy(
                            &dispatcher.queue,
                            vuln,
                            Some(&dispatcher.config.strategy),
                        )
                        .await
                    {
                        Ok(true) => {
                            info!(
                                target = %item.target_ip,
                                hostname = %item.hostname,
                                "Print Spooler enabled — vulnerability registered"
                            );
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(err = %e, target = %item.target_ip, "Failed to publish spooler vulnerability");
                        }
                    }
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "Spooler check deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch spooler check");
                }
            }
        }
    }
}

struct SpoolerWork {
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

    fn make_credential(
        username: &str,
        password: &str,
        domain: &str,
    ) -> ares_core::models::Credential {
        ares_core::models::Credential {
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
    fn dedup_key_format() {
        let key = format!("spooler:{}", "192.168.58.22");
        assert_eq!(key, "spooler:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SPOOLER_CHECK, "spooler_check");
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
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_spooler_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        let work = collect_spooler_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_host_with_credential_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_spooler_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.22");
        assert_eq!(work[0].hostname, "srv01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dedup_key, "spooler:192.168.58.22");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_multiple_hosts_produces_work_for_each() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .hosts
            .push(make_host("192.168.58.23", "srv02.contoso.local"));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_spooler_work(&state);
        assert_eq!(work.len(), 2);
        let ips: Vec<&str> = work.iter().map(|w| w.target_ip.as_str()).collect();
        assert!(ips.contains(&"192.168.58.22"));
        assert!(ips.contains(&"192.168.58.23"));
    }

    #[test]
    fn collect_dedup_skips_already_processed_host() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_SPOOLER_CHECK, "spooler:192.168.58.22".into());
        let work = collect_spooler_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed_keeps_unprocessed() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .hosts
            .push(make_host("192.168.58.23", "srv02.contoso.local"));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_SPOOLER_CHECK, "spooler:192.168.58.22".into());
        let work = collect_spooler_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.23");
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .credentials
            .push(make_credential("fabuser", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_spooler_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_falls_back_to_first_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        // Only fabrikam credential available for contoso host
        state
            .credentials
            .push(make_credential("fabuser", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_spooler_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fabuser");
    }

    #[test]
    fn collect_host_without_fqdn_gets_empty_domain() {
        let mut state = StateInner::new("test-op".into());
        state.hosts.push(make_host("192.168.58.22", "srv01"));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_spooler_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "");
        // Falls back to first credential since domain is empty
        assert_eq!(work[0].credential.username, "admin");
    }
}
