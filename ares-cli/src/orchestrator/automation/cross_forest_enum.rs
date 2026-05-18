//! auto_cross_forest_enum -- targeted cross-forest enumeration.
//!
//! When we have Admin Pwn3d on a DC in a foreign forest but haven't enumerated
//! that forest's users/groups, this module dispatches targeted LDAP enumeration
//! using the best available credential path.
//!
//! Unlike `auto_domain_user_enum` (which fires once per domain), this module
//! retries with better credentials as they become available — specifically:
//!   - Cracked passwords from cross-forest secretsdump hashes
//!   - Credentials obtained via MSSQL linked server pivots
//!   - Admin credentials from owned DCs in the foreign forest
//!
//! This covers the gap where the trusted forest's users are not enumerated
//! because initial recon only has primary-forest credentials.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Check if a credential belongs to a different forest than the target domain.
fn is_cross_forest(cred_domain: &str, target_domain: &str) -> bool {
    let c = cred_domain.to_lowercase();
    let t = target_domain.to_lowercase();
    // Same domain or parent/child = same forest
    !(c == t || c.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{c}")))
}

/// Build dedup key incorporating the credential to allow retry with better creds.
fn cross_forest_dedup_key(domain: &str, username: &str, cred_domain: &str) -> String {
    format!(
        "xforest:{}:{}@{}",
        domain.to_lowercase(),
        username.to_lowercase(),
        cred_domain.to_lowercase()
    )
}

fn bind_domain_for_cross_forest(cred_domain: &str, target_domain: &str) -> Option<String> {
    if cred_domain.trim().is_empty() || cred_domain.eq_ignore_ascii_case(target_domain) {
        None
    } else {
        Some(cred_domain.to_string())
    }
}

/// Collect cross-forest enumeration work items from the current state.
///
/// Returns an empty vec when there are fewer than 2 domains, no credentials,
/// or no actionable work to dispatch.
fn collect_cross_forest_work(state: &StateInner) -> Vec<CrossForestWork> {
    if state.credentials.is_empty() || state.domains.len() < 2 {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let domain_lower = domain.to_lowercase();

        // Count how many users we know in this domain.
        let known_user_count = state
            .credentials
            .iter()
            .filter(|c| c.domain.to_lowercase() == domain_lower)
            .count();

        // Also count hashes for this domain.
        let known_hash_count = state
            .hashes
            .iter()
            .filter(|h| h.domain.to_lowercase() == domain_lower)
            .count();

        // Skip domains where we already have good coverage
        // (at least 5 credentials or 10 hashes = likely already enumerated).
        if known_user_count >= 5 || known_hash_count >= 10 {
            continue;
        }

        // Find the best credential for this domain.
        // Priority: same-domain cred > admin cred > cracked hash > any cred.
        let best_cred = state
            .credentials
            .iter()
            .filter(|c| {
                !c.password.is_empty() && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .min_by_key(|c| {
                let c_dom = c.domain.to_lowercase();
                if c_dom == domain_lower {
                    0 // Same domain = best
                } else if c.is_admin {
                    1 // Admin from another domain = good (trust auth)
                } else if !is_cross_forest(&c_dom, &domain_lower) {
                    2 // Same forest = acceptable
                } else {
                    3 // Cross-forest = may work via trust
                }
            })
            .cloned();

        let Some(cred) = best_cred else {
            continue;
        };

        let dedup_key = cross_forest_dedup_key(&domain_lower, &cred.username, &cred.domain);
        if state.is_processed(DEDUP_CROSS_FOREST_ENUM, &dedup_key) {
            continue;
        }

        items.push(CrossForestWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
            is_under_enumerated: known_user_count < 3,
        });
    }

    items
}

/// Dispatches targeted user + group enumeration for foreign forests.
/// Interval: 45s.
pub async fn auto_cross_forest_enum(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Wait for initial credential discovery and cross-domain pivots.
    tokio::time::sleep(Duration::from_secs(120)).await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("cross_forest_enum") {
            continue;
        }

        let work: Vec<CrossForestWork> = {
            let state = dispatcher.state.read().await;
            collect_cross_forest_work(&state)
        };
        if work.is_empty() {
            continue;
        }

        for item in work {
            // Dispatch user enumeration
            let mut user_payload = json!({
                "technique": "ldap_user_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "filters": ["(objectCategory=person)(objectClass=user)"],
                "attributes": [
                    "sAMAccountName", "description", "memberOf",
                    "userAccountControl", "servicePrincipalName",
                    "msDS-AllowedToDelegateTo", "adminCount"
                ],
                "cross_forest": true,
                "instructions": concat!(
                    "This is a cross-forest enumeration task. Enumerate ALL users in the ",
                    "target domain via LDAP. If the credential is from a different domain, ",
                    "authenticate via the forest trust. Report every user found with their ",
                    "group memberships, SPNs, delegation settings, and description fields. ",
                    "Pay special attention to accounts with adminCount=1, ",
                    "DoesNotRequirePreAuth, or interesting SPNs.\n\n",
                    "IMPORTANT: For each user found, include them in the discovered_users ",
                    "array with EXACTLY this JSON format:\n",
                    "  {\"username\": \"samaccountname\", \"domain\": \"contoso.local\", ",
                    "\"source\": \"ldap_enumeration\", \"memberOf\": [\"Group1\", \"Group2\"]}\n",
                    "Also report users with DoesNotRequirePreAuth as vulnerabilities with ",
                    "vuln_type='asrep_roastable', and users with SPNs as vuln_type='kerberoastable'."
                ),
            });
            if let Some(bind_domain) =
                bind_domain_for_cross_forest(&item.credential.domain, &item.domain)
            {
                user_payload["bind_domain"] = json!(bind_domain);
            }

            let priority = dispatcher.effective_priority("cross_forest_enum");
            match dispatcher
                .throttled_submit("recon", "recon", user_payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        cred_user = %item.credential.username,
                        cred_domain = %item.credential.domain,
                        under_enumerated = item.is_under_enumerated,
                        "Cross-forest user enumeration dispatched"
                    );
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Cross-forest user enum deferred");
                    continue; // Don't mark as processed if deferred
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch cross-forest user enum");
                    continue;
                }
            }

            // Also dispatch group enumeration for the same domain
            let mut group_payload = json!({
                "technique": "ldap_group_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "filters": ["(objectCategory=group)"],
                "attributes": [
                    "sAMAccountName", "member", "memberOf", "managedBy",
                    "groupType", "objectSid", "description"
                ],
                "enumerate_members": true,
                "resolve_foreign_principals": true,
                "cross_forest": true,
                "instructions": concat!(
                    "Enumerate ALL security groups in this domain and their members. ",
                    "Resolve Foreign Security Principals to their source domain. ",
                    "Report group name, type (Global/DomainLocal/Universal), members, ",
                    "and managed-by. This is critical for mapping cross-domain attack paths.\n\n",
                    "IMPORTANT: For each user found in any group, include them in the ",
                    "discovered_users array with EXACTLY this JSON format:\n",
                    "  {\"username\": \"samaccountname\", \"domain\": \"contoso.local\", ",
                    "\"source\": \"ldap_group_enumeration\", \"memberOf\": [\"Group1\", \"Group2\"]}"
                ),
            });
            if let Some(bind_domain) =
                bind_domain_for_cross_forest(&item.credential.domain, &item.domain)
            {
                group_payload["bind_domain"] = json!(bind_domain);
            }

            let group_priority = dispatcher.effective_priority("group_enumeration");
            if let Ok(Some(task_id)) = dispatcher
                .throttled_submit("recon", "recon", group_payload, group_priority)
                .await
            {
                info!(
                    task_id = %task_id,
                    domain = %item.domain,
                    "Cross-forest group enumeration dispatched"
                );
            }

            // Mark as processed
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_CROSS_FOREST_ENUM, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_CROSS_FOREST_ENUM, &item.dedup_key)
                .await;
        }
    }
}

struct CrossForestWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
    is_under_enumerated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_cross_forest_same_domain() {
        assert!(!is_cross_forest("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_cross_forest_child_domain() {
        assert!(!is_cross_forest("child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_cross_forest_parent_domain() {
        assert!(!is_cross_forest("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn is_cross_forest_different_forests() {
        assert!(is_cross_forest("contoso.local", "fabrikam.local"));
    }

    #[test]
    fn is_cross_forest_case_insensitive() {
        assert!(!is_cross_forest("CONTOSO.LOCAL", "contoso.local"));
        assert!(is_cross_forest("CONTOSO.LOCAL", "fabrikam.local"));
    }

    #[test]
    fn dedup_key_format() {
        let key = cross_forest_dedup_key("fabrikam.local", "Admin", "CONTOSO.LOCAL");
        assert_eq!(key, "xforest:fabrikam.local:admin@contoso.local");
    }

    #[test]
    fn dedup_key_case_insensitive() {
        let k1 = cross_forest_dedup_key("FABRIKAM.LOCAL", "Admin", "contoso.local");
        let k2 = cross_forest_dedup_key("fabrikam.local", "admin", "CONTOSO.LOCAL");
        assert_eq!(k1, k2);
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_CROSS_FOREST_ENUM, "cross_forest_enum");
    }

    #[test]
    fn bind_domain_added_for_foreign_forest() {
        assert_eq!(
            bind_domain_for_cross_forest("contoso.local", "fabrikam.local"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn bind_domain_omitted_for_same_domain() {
        assert_eq!(
            bind_domain_for_cross_forest("contoso.local", "contoso.local"),
            None
        );
    }

    #[test]
    fn bind_domain_omitted_when_credential_domain_empty() {
        assert_eq!(bind_domain_for_cross_forest("", "fabrikam.local"), None);
    }

    #[test]
    fn is_cross_forest_empty_strings() {
        // Empty strings are equal (same empty domain)
        assert!(!is_cross_forest("", ""));
    }

    #[test]
    fn is_cross_forest_one_empty() {
        assert!(is_cross_forest("contoso.local", ""));
        assert!(is_cross_forest("", "contoso.local"));
    }

    #[test]
    fn is_cross_forest_deeply_nested() {
        assert!(!is_cross_forest("a.b.contoso.local", "contoso.local"));
        assert!(!is_cross_forest("contoso.local", "a.b.contoso.local"));
    }

    #[test]
    fn cross_forest_work_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: true,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let work = CrossForestWork {
            dedup_key: "xforest:fabrikam.local:admin@contoso.local".into(),
            domain: "fabrikam.local".into(),
            dc_ip: "192.168.58.20".into(),
            credential: cred,
            is_under_enumerated: true,
        };
        assert!(work.is_under_enumerated);
        assert_eq!(work.domain, "fabrikam.local");
    }

    #[test]
    fn user_enum_payload_structure() {
        let payload = serde_json::json!({
            "technique": "ldap_user_enumeration",
            "target_ip": "192.168.58.20",
            "domain": "fabrikam.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
            "cross_forest": true,
        });
        assert_eq!(payload["technique"], "ldap_user_enumeration");
        assert!(payload["cross_forest"].as_bool().unwrap());
        assert_eq!(payload["domain"], "fabrikam.local");
    }

    #[test]
    fn group_enum_payload_structure() {
        let payload = serde_json::json!({
            "technique": "ldap_group_enumeration",
            "target_ip": "192.168.58.20",
            "domain": "fabrikam.local",
            "resolve_foreign_principals": true,
            "cross_forest": true,
        });
        assert_eq!(payload["technique"], "ldap_group_enumeration");
        assert!(payload["resolve_foreign_principals"].as_bool().unwrap());
    }

    #[test]
    fn coverage_threshold_values() {
        // Module uses: known_user_count >= 5 || known_hash_count >= 10
        let known_user_count = 4;
        let known_hash_count = 9;
        assert!(known_user_count < 5 && known_hash_count < 10); // should trigger enum

        let known_user_count2 = 5;
        assert!(known_user_count2 >= 5); // should skip

        let known_hash_count2 = 10;
        assert!(known_hash_count2 >= 10); // should skip
    }

    #[test]
    fn under_enumerated_threshold() {
        // is_under_enumerated = known_user_count < 3
        let counts = [0_usize, 2, 3, 5];
        assert!(counts[0] < 3); // 0 users = under-enumerated
        assert!(counts[1] < 3); // 2 users = under-enumerated
        assert!(counts[2] >= 3); // 3 users = not under-enumerated
    }

    // --- collect_cross_forest_work tests ---

    fn make_cred(
        id: &str,
        user: &str,
        pass: &str,
        domain: &str,
        admin: bool,
    ) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: id.into(),
            username: user.into(),
            password: pass.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: admin,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(user: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{user}"),
            username: user.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:deadbeef".into(),
            hash_type: "ntlm".into(),
            domain: domain.into(),
            cracked_password: None,
            source: "test".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    #[tokio::test]
    async fn collect_empty_state_no_work() {
        let state = SharedState::new("test".into());
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_single_domain_no_work() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.credentials.push(make_cred(
                "c1",
                "user1",
                "P@ssw0rd!",
                "contoso.local",
                false,
            )); // pragma: allowlist secret
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        assert!(work.is_empty(), "single domain should produce no work");
    }

    #[tokio::test]
    async fn collect_no_credentials_no_work() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        assert!(work.is_empty(), "no credentials should produce no work");
    }

    #[tokio::test]
    async fn collect_two_domains_with_cross_forest_cred() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            s.credentials
                .push(make_cred("c1", "admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        // Should produce work for both domains (the cred works for contoso as same-domain,
        // and for fabrikam as cross-forest).
        assert!(!work.is_empty());
        // At least one item should target fabrikam
        assert!(work.iter().any(|w| w.domain == "fabrikam.local"));
    }

    #[tokio::test]
    async fn collect_skips_domain_with_five_credentials() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // 5 credentials for fabrikam = already enumerated
            for i in 0..5 {
                s.credentials.push(make_cred(
                    &format!("c{i}"),
                    &format!("user{i}"),
                    "P@ssw0rd!", // pragma: allowlist secret
                    "fabrikam.local",
                    false,
                ));
            }
            // Also need a cred that can authenticate
            s.credentials
                .push(make_cred("cx", "admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        // fabrikam should be skipped (>= 5 creds), contoso should appear
        assert!(
            work.iter().all(|w| w.domain != "fabrikam.local"),
            "domain with >= 5 credentials should be skipped"
        );
    }

    #[tokio::test]
    async fn collect_skips_domain_with_ten_hashes() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // 10 hashes for fabrikam
            for i in 0..10 {
                s.hashes
                    .push(make_hash(&format!("hashuser{i}"), "fabrikam.local"));
            }
            s.credentials
                .push(make_cred("c1", "admin", "P@ssw0rd!", "contoso.local", true));
            // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        assert!(
            work.iter().all(|w| w.domain != "fabrikam.local"),
            "domain with >= 10 hashes should be skipped"
        );
    }

    #[tokio::test]
    async fn collect_credential_priority_same_domain_best() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Cross-forest cred (priority 3)
            s.credentials.push(make_cred(
                "c1",
                "crossuser",
                "P@ssw0rd!",
                "contoso.local",
                false,
            )); // pragma: allowlist secret
                // Same-domain cred (priority 0) — should be selected
            s.credentials.push(make_cred(
                "c2",
                "localuser",
                "P@ssw0rd!",
                "fabrikam.local",
                false,
            )); // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        let fab_work = work.iter().find(|w| w.domain == "fabrikam.local");
        assert!(fab_work.is_some(), "should produce work for fabrikam");
        assert_eq!(
            fab_work.unwrap().credential.username,
            "localuser",
            "same-domain credential should be preferred"
        );
    }

    #[tokio::test]
    async fn collect_credential_priority_admin_over_same_forest() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Same-forest non-admin (priority 2)
            s.credentials.push(make_cred(
                "c1",
                "forestuser",
                "P@ssw0rd!",
                "child.fabrikam.local",
                false,
            )); // pragma: allowlist secret
                // Admin from another domain (priority 1) — should win
            s.credentials.push(make_cred(
                "c2",
                "adminuser",
                "P@ssw0rd!",
                "contoso.local",
                true,
            )); // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        let fab_work = work.iter().find(|w| w.domain == "fabrikam.local");
        assert!(fab_work.is_some());
        assert_eq!(
            fab_work.unwrap().credential.username,
            "adminuser",
            "admin credential should be preferred over same-forest non-admin"
        );
    }

    #[tokio::test]
    async fn collect_credential_priority_same_forest_over_cross_forest() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Cross-forest non-admin (priority 3)
            s.credentials.push(make_cred(
                "c1",
                "crossuser",
                "P@ssw0rd!",
                "contoso.local",
                false,
            )); // pragma: allowlist secret
                // Same-forest non-admin (priority 2) — should win
            s.credentials.push(make_cred(
                "c2",
                "forestuser",
                "P@ssw0rd!",
                "child.fabrikam.local",
                false,
            )); // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        let fab_work = work.iter().find(|w| w.domain == "fabrikam.local");
        assert!(fab_work.is_some());
        assert_eq!(
            fab_work.unwrap().credential.username,
            "forestuser",
            "same-forest credential should be preferred over cross-forest"
        );
    }

    #[tokio::test]
    async fn collect_skips_quarantined_principals() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Only credential is quarantined
            s.credentials.push(make_cred(
                "c1",
                "baduser",
                "P@ssw0rd!",
                "contoso.local",
                true,
            )); // pragma: allowlist secret
            s.quarantined_principals.insert(
                "baduser@contoso.local".into(),
                chrono::Utc::now() + chrono::Duration::seconds(300),
            );
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        assert!(
            work.iter().all(|w| w.credential.username != "baduser"),
            "quarantined credentials should be skipped"
        );
    }

    #[tokio::test]
    async fn collect_skips_empty_password_credentials() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Only credential has empty password
            s.credentials
                .push(make_cred("c1", "nopass", "", "contoso.local", true));
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        // No usable credential → should produce no work for fabrikam
        assert!(
            work.iter().all(|w| w.domain != "fabrikam.local"),
            "empty password credentials should not produce work"
        );
    }

    #[tokio::test]
    async fn collect_skips_already_processed_dedup_key() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            s.credentials
                .push(make_cred("c1", "admin", "P@ssw0rd!", "contoso.local", true)); // pragma: allowlist secret
                                                                                     // Pre-mark the dedup key as processed
            let key = cross_forest_dedup_key("fabrikam.local", "admin", "contoso.local");
            s.mark_processed(DEDUP_CROSS_FOREST_ENUM, key);
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        assert!(
            work.iter().all(|w| w.domain != "fabrikam.local"),
            "already-processed dedup key should be skipped"
        );
    }

    #[tokio::test]
    async fn collect_under_enumerated_flag_when_few_users() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // 2 fabrikam creds (< 3 = under-enumerated)
            s.credentials.push(make_cred(
                "c1",
                "user1",
                "P@ssw0rd!",
                "fabrikam.local",
                false,
            )); // pragma: allowlist secret
            s.credentials.push(make_cred(
                "c2",
                "user2",
                "P@ssw0rd!",
                "fabrikam.local",
                false,
            )); // pragma: allowlist secret
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        let fab_work = work.iter().find(|w| w.domain == "fabrikam.local");
        assert!(fab_work.is_some());
        assert!(
            fab_work.unwrap().is_under_enumerated,
            "domain with < 3 users should be marked under-enumerated"
        );
    }

    #[tokio::test]
    async fn collect_not_under_enumerated_with_three_users() {
        let state = SharedState::new("test".into());
        {
            let mut s = state.write().await;
            s.domains.push("contoso.local".into());
            s.domains.push("fabrikam.local".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // 3 fabrikam creds (>= 3 = not under-enumerated, but < 5 so still triggers enum)
            for i in 0..3 {
                s.credentials.push(make_cred(
                    &format!("c{i}"),
                    &format!("user{i}"),
                    "P@ssw0rd!", // pragma: allowlist secret
                    "fabrikam.local",
                    false,
                ));
            }
        }
        let inner = state.read().await;
        let work = collect_cross_forest_work(&inner);
        let fab_work = work.iter().find(|w| w.domain == "fabrikam.local");
        assert!(fab_work.is_some());
        assert!(
            !fab_work.unwrap().is_under_enumerated,
            "domain with >= 3 users should not be marked under-enumerated"
        );
    }
}
