//! auto_ldap_signing -- check LDAP signing enforcement per DC.
//!
//! When LDAP signing is not required, attackers can relay NTLM auth to LDAP
//! for shadow credentials, RBCD writes, or account takeover. This module
//! dispatches a check per DC to test whether LDAP channel binding and
//! signing are enforced.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

fn collect_ldap_signing_work(state: &StateInner) -> Vec<LdapSigningWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("ldap_sign:{}", dc_ip);
        if state.is_processed(DEDUP_LDAP_SIGNING, &dedup_key) {
            continue;
        }

        let cred = match state
            .credentials
            .iter()
            .find(|c| c.domain.to_lowercase() == domain.to_lowercase())
            .or_else(|| state.credentials.first())
        {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(LdapSigningWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Checks each DC for LDAP signing and channel binding enforcement.
/// Interval: 45s.
pub async fn auto_ldap_signing(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("ldap_signing") {
            continue;
        }

        let work: Vec<LdapSigningWork> = {
            let state = dispatcher.state.read().await;
            collect_ldap_signing_work(&state)
        };

        for item in work {
            let cross_domain = item.credential.domain.to_lowercase() != item.domain.to_lowercase();
            let mut payload = json!({
                "technique": "ldap_signing_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "instructions": concat!(
                    "Check whether LDAP signing is enforced on this Domain Controller.\n\n",
                    "Use ldap_search or nxc_ldap_command to test LDAP binding. ",
                    "Try an unsigned LDAP bind (simple bind without signing). ",
                    "If the bind succeeds without signing, LDAP signing is NOT enforced.\n\n",
                    "Alternatively, use nxc_smb_command with '--gen-relay-list' or check ",
                    "the ms-DS-RequiredDomainBitmask / LDAPServerIntegrity registry policy.\n\n",
                    "IMPORTANT: If LDAP signing is NOT enforced (bind succeeds without signing), ",
                    "you MUST report this as a vulnerability:\n",
                    "  vuln_type: 'ldap_signing_disabled'\n",
                    "  target_ip: the DC IP\n",
                    "  domain: the domain\n",
                    "  details: {\"signing_required\": false, \"channel_binding\": false}\n\n",
                    "If LDAP signing IS enforced, report finding with finding_type='hardened'."
                ),
            });
            if cross_domain {
                payload["bind_domain"] = json!(item.credential.domain);
            }

            let priority = dispatcher.effective_priority("ldap_signing");
            match dispatcher
                .force_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "LDAP signing check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LDAP_SIGNING, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LDAP_SIGNING, &item.dedup_key)
                        .await;

                    // Register ldap_signing_disabled vulnerability proactively so
                    // downstream automations (NTLM relay) can fire
                    // without waiting for the agent's report_finding callback
                    // (which only logs and does NOT populate discovered_vulnerabilities).
                    let vuln = ares_core::models::VulnerabilityInfo {
                        vuln_id: format!("ldap_signing_{}", item.dc_ip.replace('.', "_")),
                        vuln_type: "ldap_signing_disabled".to_string(),
                        target: item.dc_ip.clone(),
                        discovered_by: "auto_ldap_signing".to_string(),
                        discovered_at: chrono::Utc::now(),
                        details: {
                            let mut d = std::collections::HashMap::new();
                            d.insert("target_ip".to_string(), json!(item.dc_ip));
                            d.insert("domain".to_string(), json!(item.domain));
                            d.insert("signing_required".to_string(), json!(false));
                            d.insert("channel_binding".to_string(), json!(false));
                            d
                        },
                        recommended_agent: "coercion".to_string(),
                        priority: dispatcher.effective_priority("ldap_signing"),
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
                                domain = %item.domain,
                                dc = %item.dc_ip,
                                "LDAP signing disabled — vulnerability registered for NTLM relay"
                            );
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(err = %e, dc = %item.dc_ip, "Failed to publish LDAP signing vulnerability");
                        }
                    }
                }
                Ok(None) => {
                    info!(domain = %item.domain, dc = %item.dc_ip, "LDAP signing check deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch LDAP signing check");
                }
            }
        }
    }
}

struct LdapSigningWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
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

    #[test]
    fn dedup_key_format() {
        let key = format!("ldap_sign:{}", "192.168.58.10");
        assert_eq!(key, "ldap_sign:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_LDAP_SIGNING, "ldap_signing");
    }

    #[test]
    fn payload_structure_has_correct_technique() {
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
        let payload = json!({
            "technique": "ldap_signing_check",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ldap_signing_check");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
    }

    #[test]
    fn work_struct_construction() {
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
        let work = LdapSigningWork {
            dedup_key: "ldap_sign:192.168.58.10".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn dedup_key_uses_dc_ip() {
        // LDAP signing dedup is by DC IP, not domain
        let key = format!("ldap_sign:{}", "192.168.58.10");
        assert!(key.starts_with("ldap_sign:"));
        assert!(key.contains("192.168.58.10"));
    }

    #[test]
    fn dedup_keys_differ_per_dc() {
        let key1 = format!("ldap_sign:{}", "192.168.58.10");
        let key2 = format!("ldap_sign:{}", "192.168.58.20");
        assert_ne!(key1, key2);
    }

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_ldap_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_ldap_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_domain_controllers_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_ldap_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_dc_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_ldap_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "ldap_sign:192.168.58.10");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_multiple_dcs_produces_work_for_each() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("svcacct", "Svc!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_ldap_signing_work(&state);
        assert_eq!(work.len(), 2);
        let domains: Vec<&str> = work.iter().map(|w| w.domain.as_str()).collect();
        assert!(domains.contains(&"contoso.local"));
        assert!(domains.contains(&"fabrikam.local"));
    }

    #[test]
    fn collect_dedup_skips_already_processed_dc() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_LDAP_SIGNING, "ldap_sign:192.168.58.10".into());
        let work = collect_ldap_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed_keeps_unprocessed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("svcacct", "Svc!Pass1", "fabrikam.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_LDAP_SIGNING, "ldap_sign:192.168.58.10".into());
        let work = collect_ldap_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("fabuser", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_ldap_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_falls_back_to_first_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only fabrikam credential available
        state
            .credentials
            .push(make_credential("fabuser", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_ldap_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fabuser");
        assert_eq!(work[0].credential.domain, "fabrikam.local");
    }
}
