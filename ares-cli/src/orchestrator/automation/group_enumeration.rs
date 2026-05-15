//! auto_group_enumeration -- enumerate domain groups and memberships via LDAP.
//!
//! Dispatches per-domain LDAP group enumeration to discover security groups,
//! their members, and cross-domain memberships. This covers a large gap in
//! attack surface mapping — group membership determines ACL attack paths,
//! privilege escalation chains, and cross-domain lateral movement.
//!
//! The recon agent queries `(objectCategory=group)` and resolves membership
//! recursively, including Foreign Security Principals for cross-domain groups.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect group enumeration work items from current state.
///
/// Pure logic extracted from `auto_group_enumeration` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_group_enum_work(state: &StateInner) -> Vec<GroupEnumWork> {
    if state.credentials.is_empty() && state.hashes.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    let all_dcs = state.all_domains_with_dcs();
    if all_dcs.is_empty() {
        return Vec::new();
    }
    debug!(
        domains = ?all_dcs.iter().map(|(d,_)| d.as_str()).collect::<Vec<_>>(),
        trusted = ?state.trusted_domains.keys().collect::<Vec<_>>(),
        creds = state.credentials.len(),
        hashes = state.hashes.len(),
        "Group enum state check"
    );
    for (domain, dc_ip) in &all_dcs {
        // Use separate dedup keys for cred vs hash attempts so a failed
        // password-based attempt (e.g., mislabeled credential domain)
        // doesn't permanently block the hash-based path.
        let dedup_key_cred = format!("group_enum:{}:cred", domain.to_lowercase());
        let dedup_key_hash = format!("group_enum:{}:hash", domain.to_lowercase());
        let dedup_key_trust = format!("group_enum:{}:trust", domain.to_lowercase());

        // Prefer same-domain cleartext cred, then fall back to trust-compatible
        // cred (child→parent or cross-forest). Trust-based attempts use a
        // separate dedup key so they don't block hash-based fallback.
        let (cred, using_trust_cred) =
            if !state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key_cred) {
                let c = state
                    .credentials
                    .iter()
                    .find(|c| c.domain.to_lowercase() == domain.to_lowercase())
                    .cloned();
                (c, false)
            } else {
                (None, false)
            };
        let (cred, using_trust_cred) =
            if cred.is_none() && !state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key_trust) {
                match state.find_trust_credential(domain) {
                    Some(c) => (Some(c), true),
                    None => (None, using_trust_cred),
                }
            } else {
                (cred, using_trust_cred)
            };

        // Look for NTLM hash (PTH) — fires independently of cred attempt
        let (ntlm_hash, ntlm_hash_username) =
            if cred.is_none() && !state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key_hash) {
                state
                    .hashes
                    .iter()
                    .find(|h| {
                        h.hash_type.to_lowercase() == "ntlm"
                            && h.domain.to_lowercase() == domain.to_lowercase()
                            && h.username.to_lowercase() == "administrator"
                    })
                    .or_else(|| {
                        state.hashes.iter().find(|h| {
                            h.hash_type.to_lowercase() == "ntlm"
                                && h.domain.to_lowercase() == domain.to_lowercase()
                                && !state.is_delegation_account(&h.username)
                        })
                    })
                    .map(|h| (Some(h.hash_value.clone()), Some(h.username.clone())))
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };

        // Need at least a credential or an NTLM hash
        if cred.is_none() && ntlm_hash.is_none() {
            debug!(
                domain = %domain,
                cred_dedup = state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key_cred),
                trust_dedup = state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key_trust),
                hash_dedup = state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key_hash),
                "Group enum: no credential/hash found for domain"
            );
            continue;
        }

        let dedup_key = if ntlm_hash.is_some() {
            dedup_key_hash
        } else if using_trust_cred {
            dedup_key_trust
        } else {
            dedup_key_cred
        };

        items.push(GroupEnumWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred.unwrap_or_else(|| ares_core::models::Credential {
                id: String::new(),
                username: ntlm_hash_username.clone().unwrap_or_default(),
                password: String::new(),
                domain: domain.clone(),
                source: "hash_fallback".into(),
                is_admin: false,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
            }),
            ntlm_hash,
            ntlm_hash_username,
        });
    }

    items
}

/// Dispatches group enumeration per domain.
/// Interval: 45s.
pub async fn auto_group_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("group_enumeration") {
            continue;
        }

        let work: Vec<GroupEnumWork> = {
            let state = dispatcher.state.read().await;
            collect_group_enum_work(&state)
        };

        if !work.is_empty() {
            info!(
                count = work.len(),
                domains = ?work.iter().map(|w| w.domain.as_str()).collect::<Vec<_>>(),
                "Group enumeration work items collected"
            );
        }
        for item in work {
            // When PTH hash is available, use the hash user's identity for the target domain
            // instead of a cross-domain credential that will fail LDAP simple bind.
            let (cred_user, cred_pass, cred_domain) = if item.ntlm_hash.is_some() {
                (
                    item.ntlm_hash_username
                        .clone()
                        .unwrap_or_else(|| item.credential.username.clone()),
                    String::new(),       // empty password forces PTH path
                    item.domain.clone(), // target domain, not cross-domain
                )
            } else {
                (
                    item.credential.username.clone(),
                    item.credential.password.clone(),
                    item.credential.domain.clone(),
                )
            };
            let cross_domain = cred_domain.to_lowercase() != item.domain.to_lowercase();
            let mut payload = json!({
                "technique": "ldap_group_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": cred_user,
                    "password": cred_pass,
                    "domain": cred_domain,
                },
                "filters": ["(objectCategory=group)"],
                "attributes": [
                    "sAMAccountName", "member", "memberOf", "managedBy",
                    "groupType", "objectSid", "description", "cn"
                ],
                "enumerate_members": true,
                "resolve_foreign_principals": true,
                "instructions": concat!(
                    "Enumerate ALL security groups in this domain.\n\n",
                    "AUTHENTICATION: If the password field is EMPTY and an NTLM hash is provided, ",
                    "you MUST use pass-the-hash. Do NOT attempt LDAP simple bind with empty password.\n",
                    "  Use rpcclient_command with the hash parameter: rpcclient_command(target=dc_ip, ",
                    "username=user, domain=domain, hash=<ntlm_hash>, command='enumdomgroups') — ",
                    "then for each group RID: 'querygroupmem <rid>' and 'queryuser <rid>' to resolve members.\n",
                    "  IMPORTANT: Pass the hash via the 'hash' parameter, NOT as the password.\n\n",
                    "If a password IS provided, use ldap_search with filter (objectCategory=group) ",
                    "to enumerate groups, members, and Foreign Security Principals.\n\n",
                    "CROSS-DOMAIN AUTH: If the credential domain differs from the target domain ",
                    "(e.g. credential from child.domain.local querying parent domain.local), ",
                    "you MUST pass bind_domain=<credential_domain> to ldap_search. ",
                    "Check the 'bind_domain' field in the task payload — if present, always pass it ",
                    "to ldap_search so the LDAP bind uses user@bind_domain while querying the target domain.\n\n",
                    "For EACH group found, report it as a vulnerability:\n",
                    "  vuln_type: 'group_enumerated'\n",
                    "  target: the group sAMAccountName\n",
                    "  target_ip: the DC IP\n",
                    "  domain: the domain\n",
                    "  details: {\"group_type\": \"Global/DomainLocal/Universal\", ",
                    "\"members\": [\"user1\", \"user2\"], \"managed_by\": \"manager\", ",
                    "\"admin_count\": true/false}\n\n",
                    "Pay special attention to: Domain Admins, Enterprise Admins, Administrators, ",
                    "Backup Operators, Server Operators, Account Operators, DnsAdmins, ",
                    "and any custom groups with adminCount=1.\n\n",
                    "Report cross-domain memberships as vuln_type='foreign_group_membership'.\n\n",
                    "IMPORTANT: For each user found, include in discovered_users array:\n",
                    "  {\"username\": \"samaccountname\", \"domain\": \"domain.local\", ",
                    "\"source\": \"ldap_group_enumeration\", \"memberOf\": [\"Group1\", \"Group2\"]}"
                ),
            });
            if cross_domain {
                payload["bind_domain"] = json!(item.credential.domain);
            }
            // Attach NTLM hash for PTH when no cleartext cred for target domain
            if let Some(ref hash) = item.ntlm_hash {
                payload["ntlm_hash"] = json!(hash);
            }
            if let Some(ref user) = item.ntlm_hash_username {
                payload["hash_username"] = json!(user);
            }

            let priority = dispatcher.effective_priority("group_enumeration");
            match dispatcher
                .force_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Group enumeration dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GROUP_ENUMERATION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GROUP_ENUMERATION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    info!(domain = %item.domain, dc = %item.dc_ip, "Group enumeration deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch group enumeration");
                }
            }
        }
    }
}

struct GroupEnumWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
    ntlm_hash: Option<String>,
    ntlm_hash_username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key_cred = format!("group_enum:{}:cred", "contoso.local");
        let key_hash = format!("group_enum:{}:hash", "contoso.local");
        assert_eq!(key_cred, "group_enum:contoso.local:cred");
        assert_eq!(key_hash, "group_enum:contoso.local:hash");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_GROUP_ENUMERATION, "group_enumeration");
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
            "technique": "ldap_group_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
            "filters": ["(objectCategory=group)"],
            "attributes": [
                "sAMAccountName", "member", "memberOf", "managedBy",
                "groupType", "objectSid", "description", "cn"
            ],
            "enumerate_members": true,
            "resolve_foreign_principals": true,
        });
        assert_eq!(payload["technique"], "ldap_group_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert!(payload["enumerate_members"].as_bool().unwrap());
        assert!(payload["resolve_foreign_principals"].as_bool().unwrap());
    }

    #[test]
    fn ldap_attributes_list() {
        let attrs = [
            "sAMAccountName",
            "member",
            "memberOf",
            "managedBy",
            "groupType",
            "objectSid",
            "description",
            "cn",
        ];
        assert_eq!(attrs.len(), 8);
        assert!(attrs.contains(&"sAMAccountName"));
        assert!(attrs.contains(&"objectSid"));
        assert!(attrs.contains(&"managedBy"));
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
        let work = GroupEnumWork {
            dedup_key: "group_enum:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
            ntlm_hash: None,
            ntlm_hash_username: None,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("group_enum:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "group_enum:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("group_enum:{}:cred", "contoso.local");
        let key2 = format!("group_enum:{}:cred", "fabrikam.local");
        assert_ne!(key1, key2);
    }

    #[test]
    fn collect_hash_fires_after_cred_dedup_burned() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Cred-based attempt already dispatched (may have failed)
        state.mark_processed(
            DEDUP_GROUP_ENUMERATION,
            "group_enum:contoso.local:cred".into(),
        );
        // Add an NTLM hash — should still generate work via hash path
        state.hashes.push(ares_core::models::Hash {
            id: "h1".into(),
            username: "Administrator".into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            hash_type: "ntlm".into(),
            domain: "contoso.local".into(),
            source: "secretsdump".into(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
            attack_step: 0,
        });
        let work = collect_group_enum_work(&state);
        assert_eq!(
            work.len(),
            1,
            "hash path should fire even after cred dedup burned"
        );
        assert_eq!(work[0].dedup_key, "group_enum:contoso.local:hash");
        assert!(work[0].ntlm_hash.is_some());
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
        let work = collect_group_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_group_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_with_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_dedup_skips_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(
            DEDUP_GROUP_ENUMERATION,
            "group_enum:contoso.local:cred".into(),
        );
        state.mark_processed(
            DEDUP_GROUP_ENUMERATION,
            "group_enum:contoso.local:hash".into(),
        );
        let work = collect_group_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_cross_domain_cred_skipped_without_hash() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only fabrikam cred — should NOT fall back cross-domain (burns dedup slot)
        state
            .credentials
            .push(make_credential("crossuser", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 0, "cross-domain cred should not produce work");
    }

    #[test]
    fn collect_multiple_domains() {
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
            .push(make_credential("fadmin", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 2);
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
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "group_enum:contoso.local:cred");
    }

    #[test]
    fn collect_prefers_same_domain_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("localadmin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "localadmin");
    }

    #[test]
    fn collect_child_cred_falls_back_for_parent_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Child-domain cred should work for parent-domain via trust
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "child.contoso.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(
            work.len(),
            1,
            "child-domain cred should fall back for parent"
        );
        assert_eq!(work[0].dedup_key, "group_enum:contoso.local:trust");
        assert_eq!(work[0].credential.domain, "child.contoso.local");
    }

    #[tokio::test]
    async fn collect_via_shared_state() {
        let shared = SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state
                .domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            state
                .credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }
}
