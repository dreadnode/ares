//! auto_foreign_group_enum -- enumerate cross-domain/cross-forest group memberships.
//!
//! Discovers foreign security principals (FSPs) — users/groups from one domain
//! that are members of groups in another domain. This reveals cross-forest and
//! cross-domain attack paths that BloodHound's intra-domain analysis might miss.
//!
//! Dispatches LDAP queries per trust relationship to find:
//! - Foreign users in local groups (e.g., FABRIKAM\jdoe in CONTOSO\TrustedAdmins)
//! - Foreign groups nested in local groups
//! - Domain Local groups with foreign members (the primary FSP container)

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect foreign group enumeration work items from current state.
///
/// Pure logic extracted from `auto_foreign_group_enum` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_foreign_group_work(state: &StateInner) -> Vec<ForeignGroupWork> {
    if state.credentials.is_empty() || state.domains.len() < 2 {
        return Vec::new();
    }

    let mut items = Vec::new();

    // For each domain, enumerate foreign security principals
    for domain in &state.domains {
        let dedup_key = format!("foreign_group:{domain}");
        if state.is_processed(DEDUP_FOREIGN_GROUP_ENUM, &dedup_key) {
            continue;
        }

        let Some(dc_ip) = state.resolve_dc_ip(domain) else {
            continue;
        };

        // Find a credential for this domain
        let cred = state
            .credentials
            .iter()
            .find(|c| {
                !c.password.is_empty()
                    && c.domain.to_lowercase() == domain.to_lowercase()
                    && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
            })
            .cloned();

        let Some(cred) = cred else {
            continue;
        };

        items.push(ForeignGroupWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip,
            credential: cred,
        });
    }

    items
}

/// Enumerate cross-domain foreign group memberships.
/// Interval: 45s.
pub async fn auto_foreign_group_enum(
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

        if !dispatcher.is_technique_allowed("foreign_group_enum") {
            continue;
        }

        let work: Vec<ForeignGroupWork> = {
            let state = dispatcher.state.read().await;
            collect_foreign_group_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "foreign_group_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "filters": [
                    "(objectClass=foreignSecurityPrincipal)",
                    "(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=4))"
                ],
                "attributes": [
                    "sAMAccountName", "member", "memberOf", "objectSid",
                    "groupType", "cn", "distinguishedName"
                ],
                "instructions": concat!(
                    "Enumerate Foreign Security Principals and cross-domain group memberships. ",
                    "1) Query CN=ForeignSecurityPrincipals,DC=... to list all foreign SIDs. ",
                    "2) Resolve each SID to its source domain user/group using ldapsearch against ",
                    "the source domain's DC. ",
                    "3) Query Domain Local groups (groupType bit 4) and check for foreign members. ",
                    "4) Report each cross-domain membership: source_domain\\source_user -> target_group ",
                    "(target_domain). These are critical for cross-forest attack paths. ",
                    "5) Register any discovered cross-domain memberships as vulnerabilities with ",
                    "vuln_type='foreign_group_membership', source=foreign_user, target=local_group, ",
                    "domain=target_domain, source_domain=foreign_domain.\n\n",
                    "IMPORTANT: For each user discovered during FSP enumeration, include them in the ",
                    "discovered_users array with EXACTLY this JSON format:\n",
                    "  {\"username\": \"samaccountname\", \"domain\": \"contoso.local\", ",
                    "\"source\": \"foreign_group_enumeration\", \"memberOf\": [\"Group1\"]}\n",
                    "Include ALL users found — both foreign principals and local group members."
                ),
            });

            let priority = dispatcher.effective_priority("foreign_group_enum");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Foreign group enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_FOREIGN_GROUP_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_FOREIGN_GROUP_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Foreign group enum deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch foreign group enum");
                }
            }
        }
    }
}

struct ForeignGroupWork {
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
        let key = format!("foreign_group:{}", "contoso.local");
        assert_eq!(key, "foreign_group:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_FOREIGN_GROUP_ENUM, "foreign_group_enum");
    }

    #[test]
    fn requires_multiple_domains() {
        let domains: Vec<String> = vec!["contoso.local".to_string()];
        assert!(
            domains.len() < 2,
            "Single domain should skip foreign group enum"
        );
    }

    #[test]
    fn two_domains_meets_requirement() {
        let domains: Vec<String> = vec!["contoso.local".to_string(), "fabrikam.local".to_string()];
        assert!(domains.len() >= 2);
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
            "technique": "foreign_group_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "foreign_group_enumeration");
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
        let work = ForeignGroupWork {
            dedup_key: "foreign_group:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn dedup_key_per_domain() {
        let key1 = format!("foreign_group:{}", "contoso.local");
        let key2 = format!("foreign_group:{}", "fabrikam.local");
        assert_ne!(key1, key2);
    }

    #[test]
    fn foreign_security_principal_resolution() {
        // The payload includes credential for cross-domain FSP resolution
        let payload = json!({
            "technique": "foreign_group_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        // FSP resolution happens via the credential against the target domain
        assert!(payload.get("credential").is_some());
        assert_eq!(payload["technique"], "foreign_group_enumeration");
    }

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
    fn collect_empty_state_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_foreign_group_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_no_work() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_foreign_group_work(&state);
        // Requires at least 2 domains
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_no_work() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        let work = collect_foreign_group_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_two_domains_with_creds() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
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
            .push(make_credential("fadmin", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_foreign_group_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn collect_dedup_skips_processed() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(
            DEDUP_FOREIGN_GROUP_ENUM,
            "foreign_group:contoso.local".into(),
        );
        let work = collect_foreign_group_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_skips_domain_without_dc() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        // Only contoso has a DC
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_foreign_group_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn collect_quarantined_credential_falls_back() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("gooduser", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        state.quarantine_principal("baduser", "contoso.local");
        let work = collect_foreign_group_work(&state);
        // Both domains should still get work (gooduser fallback for contoso)
        assert_eq!(work.len(), 2);
        // contoso should fall back to gooduser
        let contoso_work = work.iter().find(|w| w.domain == "contoso.local").unwrap();
        assert_eq!(contoso_work.credential.username, "gooduser");
    }

    #[test]
    fn collect_skips_empty_password() {
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state
            .credentials
            .push(make_credential("admin", "", "contoso.local"));
        let work = collect_foreign_group_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_via_shared_state() {
        let shared = SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state.domains.push("contoso.local".into());
            state.domains.push("fabrikam.local".into());
            state
                .domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            state
                .domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            state
                .credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_foreign_group_work(&state);
        assert_eq!(work.len(), 2);
    }
}
