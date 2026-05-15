//! auto_password_policy -- enumerate password policy per domain.
//!
//! Password policies reveal lockout thresholds, complexity requirements, and
//! minimum lengths. This information is critical for planning password spray
//! attacks without triggering lockouts.
//!
//! Dispatches `password_policy` recon tasks per discovered domain+DC pair.

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

fn collect_password_policy_work(state: &StateInner) -> Vec<PasswordPolicyWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("policy:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_PASSWORD_POLICY, &dedup_key) {
            continue;
        }

        let cred = match credential_for_domain(state, domain) {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(PasswordPolicyWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Enumerates password policy on each domain controller.
/// Interval: 30s.
pub async fn auto_password_policy(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("password_policy") {
            continue;
        }

        let work: Vec<PasswordPolicyWork> = {
            let state = dispatcher.state.read().await;
            collect_password_policy_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "password_policy",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("password_policy");
            match dispatcher
                .throttled_submit("recon", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Password policy enumeration dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_PASSWORD_POLICY, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_PASSWORD_POLICY, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Password policy task deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch password policy enum");
                }
            }
        }
    }
}

struct PasswordPolicyWork {
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
        let key = format!("policy:{}", "contoso.local");
        assert_eq!(key, "policy:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_PASSWORD_POLICY, "password_policy");
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
            "technique": "password_policy",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "password_policy");
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
        let work = PasswordPolicyWork {
            dedup_key: "policy:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.dedup_key, "policy:contoso.local");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("policy:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "policy:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("policy:{}", "contoso.local");
        let key2 = format!("policy:{}", "fabrikam.local");
        assert_ne!(key1, key2);
    }

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_password_policy_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_password_policy_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_domain_controllers_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_password_policy_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_password_policy_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "policy:contoso.local");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_multiple_domains_produces_work_for_each() {
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
        let work = collect_password_policy_work(&state);
        assert_eq!(work.len(), 2);
        let domains: Vec<&str> = work.iter().map(|w| w.domain.as_str()).collect();
        assert!(domains.contains(&"contoso.local"));
        assert!(domains.contains(&"fabrikam.local"));
    }

    #[test]
    fn collect_dedup_skips_already_processed_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_PASSWORD_POLICY, "policy:contoso.local".into());
        let work = collect_password_policy_work(&state);
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
        state.mark_processed(DEDUP_PASSWORD_POLICY, "policy:contoso.local".into());
        let work = collect_password_policy_work(&state);
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
        let work = collect_password_policy_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_skips_unrelated_cross_forest_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only fabrikam credential available
        state
            .credentials
            .push(make_credential("fabuser", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_password_policy_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_allows_child_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_credential(
            "childuser",
            "Child!Pass1",
            "child.contoso.local",
        )); // pragma: allowlist secret
        let work = collect_password_policy_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "childuser");
        assert_eq!(work[0].credential.domain, "child.contoso.local");
    }

    #[test]
    fn collect_dedup_key_lowercased() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_password_policy_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "policy:contoso.local");
    }
}
