//! auto_gpp_sysvol -- search for GPP passwords and credential artifacts in SYSVOL.
//!
//! Group Policy Preferences (GPP) XML files can contain encrypted passwords
//! using a publicly known AES key (MS14-025). SYSVOL scripts (.bat, .ps1, .vbs)
//! often contain hardcoded credentials.
//!
//! Dispatches two techniques per DC:
//!   1. `gpp_password_finder` — searches SYSVOL for Groups.xml, Scheduledtasks.xml, etc.
//!   2. `sysvol_script_search` — greps SYSVOL scripts for passwords/credentials

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

/// Collect GPP/SYSVOL work items from state (pure logic, no async).
fn collect_gpp_sysvol_work(state: &StateInner) -> Vec<GppSysvolWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("gpp:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_GPP_SYSVOL, &dedup_key) {
            continue;
        }

        let cred = match credential_for_domain(state, domain) {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(GppSysvolWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Searches SYSVOL for GPP passwords and script credentials.
/// Interval: 45s.
pub async fn auto_gpp_sysvol(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("gpp_sysvol") {
            continue;
        }

        let work: Vec<GppSysvolWork> = {
            let state = dispatcher.state.read().await;
            collect_gpp_sysvol_work(&state)
        };

        for item in work {
            let payload = json!({
                "techniques": ["gpp_password_finder", "sysvol_script_search"],
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("gpp_sysvol");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "GPP/SYSVOL credential search dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GPP_SYSVOL, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GPP_SYSVOL, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "GPP/SYSVOL task deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch GPP/SYSVOL search");
                }
            }
        }
    }
}

struct GppSysvolWork {
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
        let key = format!("gpp:{}", "contoso.local");
        assert_eq!(key, "gpp:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_GPP_SYSVOL, "gpp_sysvol");
    }

    #[test]
    fn payload_contains_both_techniques() {
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
            "techniques": ["gpp_password_finder", "sysvol_script_search"],
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        let techniques = payload["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), 2);
        assert_eq!(techniques[0], "gpp_password_finder");
        assert_eq!(techniques[1], "sysvol_script_search");
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
        let work = GppSysvolWork {
            dedup_key: "gpp:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.dedup_key, "gpp:contoso.local");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("gpp:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "gpp:contoso.local");
    }

    #[test]
    fn two_tasks_per_domain() {
        // The payload dispatches two techniques in a single submission per domain
        let techniques = ["gpp_password_finder", "sysvol_script_search"];
        assert_eq!(techniques.len(), 2);
    }

    // --- collect_gpp_sysvol_work tests ---

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
        let work = collect_gpp_sysvol_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_produces_no_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_gpp_sysvol_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dc_with_matching_cred_produces_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_gpp_sysvol_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "gpp:contoso.local");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_already_processed_dedup() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.mark_processed(DEDUP_GPP_SYSVOL, "gpp:contoso.local".into());
        let work = collect_gpp_sysvol_work(&state);
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
        let work = collect_gpp_sysvol_work(&state);
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
        let work = collect_gpp_sysvol_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "childuser");
    }

    #[test]
    fn collect_multiple_domains_produces_multiple_work() {
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
        let work = collect_gpp_sysvol_work(&state);
        assert_eq!(work.len(), 2);
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
        let work = collect_gpp_sysvol_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "conuser");
    }

    #[test]
    fn collect_case_insensitive_domain_match() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_gpp_sysvol_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "gpp:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("gpp:{}", "contoso.local");
        let key2 = format!("gpp:{}", "fabrikam.local");
        assert_ne!(key1, key2);
    }
}
