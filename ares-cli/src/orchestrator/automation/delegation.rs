//! auto_delegation_enumeration -- find delegation for new creds.
//!
//! Dispatches `find_delegation` as a **direct tool call** (no LLM in the loop).
//! Previous versions submitted an LLM task, but the agent often used LDAP
//! queries + `report_finding` instead of calling the tool — so the parser
//! never fired and vulnerabilities never reached `discovered_vulnerabilities`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Resolve a DC IP for a delegation-enumeration attempt against
/// `cred_domain`. Tries exact match in `state.domain_controllers` first,
/// then child-domain fallback (`d.ends_with(".{cred_domain}")`), then
/// parent-domain fallback (`cred_domain.ends_with(".{d}")`).
/// Returns `None` when no DC is reachable for this cred's forest.
pub(crate) fn resolve_delegation_dc(state: &StateInner, cred_domain: &str) -> Option<String> {
    let cred_domain = cred_domain.to_lowercase();
    state
        .domain_controllers
        .get(&cred_domain)
        .cloned()
        .or_else(|| {
            let suffix = format!(".{cred_domain}");
            state
                .domain_controllers
                .iter()
                .find(|(d, _)| d.ends_with(&suffix))
                .map(|(_, ip)| ip.clone())
        })
        .or_else(|| {
            state
                .domain_controllers
                .iter()
                .find(|(d, _)| cred_domain.ends_with(&format!(".{d}")))
                .map(|(_, ip)| ip.clone())
        })
}

/// Select delegation-enumeration work items for this tick.
///
/// Walks `state.credentials` keeping only non-delegation, non-quarantined,
/// non-empty-domain creds whose dedup key (`{domain_lc}:{user_lc}`) is
/// unprocessed AND whose forest has a resolvable DC IP.
///
/// Returns `(dedup_key, credential_domain, dc_ip, credential)` tuples.
/// Pure — extracted so the cred filter + DC fallback chain can be tested
/// without a Dispatcher.
pub(crate) fn select_delegation_work(
    state: &StateInner,
) -> Vec<(String, String, String, ares_core::models::Credential)> {
    state
        .credentials
        .iter()
        .filter(|c| !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
        .filter_map(|cred| {
            if cred.domain.is_empty() {
                return None;
            }
            let cred_domain = cred.domain.to_lowercase();
            let dedup = format!("{}:{}", cred_domain, cred.username.to_lowercase());
            if state.is_processed(DEDUP_DELEGATION_CREDS, &dedup) {
                return None;
            }
            let dc_ip = resolve_delegation_dc(state, &cred_domain)?;
            Some((dedup, cred.domain.clone(), dc_ip, cred.clone()))
        })
        .collect()
}

/// Dispatches delegation enumeration for new credentials.
/// Interval: 30s.
pub async fn auto_delegation_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.delegation_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            select_delegation_work(&state)
        };

        for (dedup_key, domain, dc_ip, cred) in work {
            // Dispatch find_delegation as a DIRECT tool call so the parser
            // always fires and vulnerabilities get registered in state.
            let tool_args = json!({
                "dc_ip": dc_ip,
                "domain": domain,
                "username": cred.username,
                "password": cred.password,
            });
            let call = ToolCall {
                id: format!("deleg_{}", uuid::Uuid::new_v4().simple()),
                name: "find_delegation".to_string(),
                arguments: tool_args,
            };
            let task_id = format!("delegation_enum_{}", uuid::Uuid::new_v4().simple());

            match dispatcher
                .llm_runner
                .tool_dispatcher()
                .dispatch_tool("privesc", &task_id, &call)
                .await
            {
                Ok(result) => {
                    info!(
                        domain = %domain,
                        dc_ip = %dc_ip,
                        has_discoveries = result.discoveries.is_some(),
                        "Direct find_delegation completed"
                    );
                    // Discoveries are already pushed to the real-time discovery
                    // list by the tool dispatcher — the poller will publish them
                    // to state including any constrained_delegation vulns.
                    if let Some(ref disc) = result.discoveries {
                        if let Some(vulns) = disc.get("vulnerabilities").and_then(|v| v.as_array())
                        {
                            info!(
                                count = vulns.len(),
                                domain = %domain,
                                "Delegation vulnerabilities discovered"
                            );
                        }
                    }
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DELEGATION_CREDS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DELEGATION_CREDS, &dedup_key)
                        .await;
                }
                Err(e) => {
                    warn!(err = %e, domain = %domain, "Direct find_delegation failed");
                    // Still mark as processed to avoid retry storms on auth errors
                    if e.to_string().contains("Invalid Credentials")
                        || e.to_string().contains("LOGON_FAILURE")
                    {
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_DELEGATION_CREDS, dedup_key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_DELEGATION_CREDS, &dedup_key)
                            .await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- resolve_delegation_dc -----------------------------------------

    #[test]
    fn resolve_dc_exact_match() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert_eq!(
            resolve_delegation_dc(&s, "contoso.local").as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn resolve_dc_child_fallback() {
        let mut s = StateInner::new("op".into());
        // cred=parent, registered DC=child.parent.local — parent cred can
        // still find the child DC via the suffix fallback.
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        assert_eq!(
            resolve_delegation_dc(&s, "contoso.local").as_deref(),
            Some("192.168.58.11")
        );
    }

    #[test]
    fn resolve_dc_parent_fallback() {
        let mut s = StateInner::new("op".into());
        // cred=child, only parent DC known.
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert_eq!(
            resolve_delegation_dc(&s, "child.contoso.local").as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn resolve_dc_returns_none_for_unrelated_forest() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(resolve_delegation_dc(&s, "contoso.local").is_none());
    }

    #[test]
    fn resolve_dc_case_insensitive_on_input() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert_eq!(
            resolve_delegation_dc(&s, "CONTOSO.LOCAL").as_deref(),
            Some("192.168.58.10")
        );
    }

    // --- select_delegation_work ---------------------------------------

    #[test]
    fn select_delegation_emits_when_cred_dc_match() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_delegation_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].0, "contoso.local:alice");
        assert_eq!(work[0].1, "contoso.local");
        assert_eq!(work[0].2, "192.168.58.10");
    }

    #[test]
    fn select_delegation_skips_empty_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "Pw", ""));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_delegation_work(&s).is_empty());
    }

    #[test]
    fn select_delegation_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        assert!(select_delegation_work(&s).is_empty());
    }

    #[test]
    fn select_delegation_skips_when_no_dc_for_forest() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        // No domain_controllers entry → no DC IP → skip.
        assert!(select_delegation_work(&s).is_empty());
    }

    #[test]
    fn select_delegation_skips_quarantined_principal() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_delegation_work(&s).is_empty());
    }

    #[test]
    fn select_delegation_skips_delegation_account_principal() {
        let mut s = StateInner::new("op".into());
        // Mark svc_sql as delegation account via vuln entry.
        let mut details = std::collections::HashMap::new();
        details.insert("account_name".into(), serde_json::json!("svc_sql"));
        s.discovered_vulnerabilities.insert(
            "v1".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "v1".into(),
                vuln_type: "constrained_delegation".into(),
                target: "192.168.58.10".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 1,
            },
        );
        s.credentials
            .push(make_cred("svc_sql", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_delegation_work(&s).is_empty());
    }

    #[test]
    fn select_delegation_emits_one_per_credential() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_delegation_work(&s);
        assert_eq!(work.len(), 2);
    }
}
