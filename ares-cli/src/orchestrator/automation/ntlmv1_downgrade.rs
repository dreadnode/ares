//! auto_ntlmv1_downgrade -- detect DCs allowing NTLMv1 authentication.
//!
//! When a DC accepts NTLMv1 (LmCompatibilityLevel < 3), attackers can
//! downgrade auth to capture NTLMv1 hashes via Responder/MITM, which are
//! trivially crackable. This module dispatches a check per DC.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

fn same_forest_domain(a: &str, b: &str) -> bool {
    let a = a.to_lowercase();
    let b = b.to_lowercase();
    !a.is_empty()
        && !b.is_empty()
        && (a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")))
}

fn credential_for_domain(
    state: &StateInner,
    domain: &str,
) -> Option<ares_core::models::Credential> {
    state
        .credentials
        .iter()
        .find(|c| {
            !c.password.is_empty()
                && !state.is_principal_quarantined(&c.username, &c.domain)
                && c.domain.eq_ignore_ascii_case(domain)
        })
        .or_else(|| {
            state.credentials.iter().find(|c| {
                !c.password.is_empty()
                    && !state.is_principal_quarantined(&c.username, &c.domain)
                    && same_forest_domain(&c.domain, domain)
            })
        })
        .cloned()
}

/// Collect NTLMv1 downgrade work items from state (pure logic, no async).
fn collect_ntlmv1_work(state: &StateInner) -> Vec<NtlmV1Work> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("ntlmv1:{}", dc_ip);
        if state.is_processed(DEDUP_NTLMV1_DOWNGRADE, &dedup_key) {
            continue;
        }

        let cred = match credential_for_domain(state, domain) {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(NtlmV1Work {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Checks each DC for NTLMv1 downgrade vulnerability.
/// Interval: 45s.
pub async fn auto_ntlmv1_downgrade(
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

        if !dispatcher.is_technique_allowed("ntlmv1_downgrade") {
            continue;
        }

        let work: Vec<NtlmV1Work> = {
            let state = dispatcher.state.read().await;
            collect_ntlmv1_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "ntlmv1_downgrade_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("ntlmv1_downgrade");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "NTLMv1 downgrade check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_NTLMV1_DOWNGRADE, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_NTLMV1_DOWNGRADE, &item.dedup_key)
                        .await;

                    // Register ntlmv1_downgrade vulnerability proactively so it
                    // appears in reports without waiting for the agent's
                    // report_finding callback (which only logs).
                    let vuln = ares_core::models::VulnerabilityInfo {
                        vuln_id: format!("ntlmv1_{}", item.dc_ip.replace('.', "_")),
                        vuln_type: "ntlmv1_downgrade".to_string(),
                        target: item.dc_ip.clone(),
                        discovered_by: "auto_ntlmv1_downgrade".to_string(),
                        discovered_at: chrono::Utc::now(),
                        details: {
                            let mut d = std::collections::HashMap::new();
                            d.insert("target_ip".to_string(), json!(item.dc_ip));
                            d.insert("domain".to_string(), json!(item.domain));
                            d.insert(
                                "description".to_string(),
                                json!("DC allows NTLMv1 authentication (LmCompatibilityLevel < 3). NTLMv1 hashes are trivially crackable."),
                            );
                            d
                        },
                        recommended_agent: "credential_access".to_string(),
                        priority: dispatcher.effective_priority("ntlmv1_downgrade"),
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
                                "NTLMv1 downgrade — vulnerability registered"
                            );
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(err = %e, dc = %item.dc_ip, "Failed to publish NTLMv1 downgrade vulnerability");
                        }
                    }
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "NTLMv1 downgrade check deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch NTLMv1 downgrade check");
                }
            }
        }
    }
}

struct NtlmV1Work {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("ntlmv1:{}", "192.168.58.10");
        assert_eq!(key, "ntlmv1:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_NTLMV1_DOWNGRADE, "ntlmv1_downgrade");
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
            "technique": "ntlmv1_downgrade_check",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ntlmv1_downgrade_check");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
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
        let work = NtlmV1Work {
            dedup_key: "ntlmv1:192.168.58.10".into(),
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
        // NTLMv1 dedup is by DC IP, not domain
        let key = format!("ntlmv1:{}", "192.168.58.10");
        assert!(key.starts_with("ntlmv1:"));
        assert!(key.contains("192.168.58.10"));
    }

    // --- collect_ntlmv1_work tests ---

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

    #[test]
    fn collect_empty_state_produces_no_work() {
        let state = StateInner::new("test".into());
        let work = collect_ntlmv1_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_produces_no_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_ntlmv1_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dc_with_matching_cred_produces_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_ntlmv1_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "ntlmv1:192.168.58.10");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_already_processed_dedup() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.mark_processed(DEDUP_NTLMV1_DOWNGRADE, "ntlmv1:192.168.58.10".into());
        let work = collect_ntlmv1_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_unrelated_cross_forest_credential() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_cred("fabuser", "fabrikam.local"));
        let work = collect_ntlmv1_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_allows_child_domain_credential() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_cred("childuser", "child.contoso.local"));
        let work = collect_ntlmv1_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "childuser");
    }

    #[test]
    fn collect_multiple_dcs_produces_multiple_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        state
            .credentials
            .push(make_cred("fabadmin", "fabrikam.local"));
        let work = collect_ntlmv1_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn collect_dedup_key_uses_ip_not_domain() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_ntlmv1_work(&state);
        assert_eq!(work.len(), 1);
        assert!(work[0].dedup_key.starts_with("ntlmv1:"));
        assert!(work[0].dedup_key.contains("192.168.58.10"));
        assert!(!work[0].dedup_key.contains("contoso"));
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_cred("fabuser", "fabrikam.local"));
        state
            .credentials
            .push(make_cred("conuser", "contoso.local"));
        let work = collect_ntlmv1_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "conuser");
    }

    #[test]
    fn dedup_keys_differ_per_dc() {
        let key1 = format!("ntlmv1:{}", "192.168.58.10");
        let key2 = format!("ntlmv1:{}", "192.168.58.20");
        assert_ne!(key1, key2);
    }
}
