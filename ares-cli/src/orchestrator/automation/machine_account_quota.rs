//! auto_machine_account_quota -- check MachineAccountQuota (MAQ) per domain.
//!
//! The default MAQ of 10 allows any authenticated user to create computer
//! accounts. This is a prerequisite for noPac (CVE-2021-42287) and RBCD
//! attacks. If MAQ > 0, downstream modules can proceed with machine account
//! creation-based attacks.
//!
//! Dispatches a recon check per domain to query the ms-DS-MachineAccountQuota
//! attribute from the domain root.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect MAQ work items from state (pure logic, no async).
fn collect_maq_work(state: &StateInner) -> Vec<MaqWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("maq:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_MACHINE_ACCOUNT_QUOTA, &dedup_key) {
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

        items.push(MaqWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Checks MAQ setting per domain via LDAP query.
/// Interval: 45s.
pub async fn auto_machine_account_quota(
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

        if !dispatcher.is_technique_allowed("machine_account_quota") {
            continue;
        }

        let work: Vec<MaqWork> = {
            let state = dispatcher.state.read().await;
            collect_maq_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "machine_account_quota_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("machine_account_quota");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "MachineAccountQuota check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_MACHINE_ACCOUNT_QUOTA, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(
                            &dispatcher.queue,
                            DEDUP_MACHINE_ACCOUNT_QUOTA,
                            &item.dedup_key,
                        )
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "MAQ check deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch MAQ check");
                }
            }
        }
    }
}

struct MaqWork {
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
        let key = format!("maq:{}", "contoso.local");
        assert_eq!(key, "maq:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_MACHINE_ACCOUNT_QUOTA, "machine_account_quota");
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
            "technique": "machine_account_quota_check",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "machine_account_quota_check");
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
        let work = MaqWork {
            dedup_key: "maq:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.dedup_key, "maq:contoso.local");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("maq:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "maq:contoso.local");
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

    #[test]
    fn collect_empty_state_produces_no_work() {
        let state = StateInner::new("test".into());
        let work = collect_maq_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_produces_no_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_maq_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dc_with_matching_cred_produces_work() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        let work = collect_maq_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "maq:contoso.local");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_already_processed_dedup() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_cred("admin", "contoso.local"));
        state.mark_processed(DEDUP_MACHINE_ACCOUNT_QUOTA, "maq:contoso.local".into());
        let work = collect_maq_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_falls_back_to_first_credential() {
        let mut state = StateInner::new("test".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only fabrikam cred available, should fall back to first
        state
            .credentials
            .push(make_cred("fabuser", "fabrikam.local"));
        let work = collect_maq_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fabuser");
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
        let work = collect_maq_work(&state);
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
        let work = collect_maq_work(&state);
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
        let work = collect_maq_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "maq:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("maq:{}", "contoso.local");
        let key2 = format!("maq:{}", "fabrikam.local");
        assert_ne!(key1, key2);
    }
}
