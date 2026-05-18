//! auto_bloodhound -- BloodHound collection per domain.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use ares_llm::routing::find_domain_credential;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Select per-domain BloodHound collection work items.
///
/// For each `state.domains` entry that hasn't been processed yet, picks
/// the best credential via `find_domain_credential` (which enforces
/// same-domain preference and trust-scope correctness) and resolves the
/// domain's DC IP. Domains with no usable DC IP OR no usable credential
/// are skipped.
///
/// Pure — no Redis, no Dispatcher. Used by `auto_bloodhound`.
pub(crate) fn select_bloodhound_work(
    state: &StateInner,
) -> Vec<(String, String, ares_core::models::Credential)> {
    if state.credentials.is_empty() {
        return Vec::new();
    }
    state
        .domains
        .iter()
        .filter(|d| !state.is_processed(DEDUP_BLOODHOUND_DOMAINS, d))
        .filter_map(|domain| {
            let dc_ip = state.resolve_dc_ip(domain)?;
            let cred = find_domain_credential(
                domain,
                &state.credentials,
                &state.netbios_to_fqdn,
                &state.trusted_domains,
            )?;
            Some((domain.clone(), dc_ip, cred.clone()))
        })
        .collect()
}

/// Dispatches BloodHound collection for each discovered domain.
/// Interval: 30s.
///
/// Selects the best credential per domain (same-domain preferred, with
/// trust-scope enforcement) instead of using a single global credential.
pub async fn auto_bloodhound(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            select_bloodhound_work(&state)
        };
        if work.is_empty() {
            continue;
        }

        for (domain, dc_ip, cred) in work {
            match dispatcher.request_bloodhound(&domain, &dc_ip, &cred).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "BloodHound collection dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_BLOODHOUND_DOMAINS, domain.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_BLOODHOUND_DOMAINS, &domain)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch BloodHound"),
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

    #[test]
    fn select_bloodhound_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_bloodhound_work(&s).is_empty());
    }

    #[test]
    fn select_bloodhound_empty_when_no_credentials() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No credentials → no work even when domains+DCs are present.
        assert!(select_bloodhound_work(&s).is_empty());
    }

    #[test]
    fn select_bloodhound_emits_when_cred_and_dc_present() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_bloodhound_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].0, "contoso.local");
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2.username, "alice");
    }

    #[test]
    fn select_bloodhound_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_BLOODHOUND_DOMAINS, "contoso.local".into());
        assert!(select_bloodhound_work(&s).is_empty());
    }

    #[test]
    fn select_bloodhound_skips_domain_without_dc() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        // No domain_controllers entry → no DC IP → skip.
        assert!(select_bloodhound_work(&s).is_empty());
    }

    #[test]
    fn select_bloodhound_skips_domain_without_credential() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Credential for a different domain — find_domain_credential won't
        // return it without a matching trust path.
        s.credentials
            .push(make_cred("alice", "Pw", "fabrikam.local"));
        assert!(select_bloodhound_work(&s).is_empty());
    }

    #[test]
    fn select_bloodhound_emits_one_per_domain() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domains.push("fabrikam.local".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw", "fabrikam.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let mut work = select_bloodhound_work(&s);
        work.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].0, "contoso.local");
        assert_eq!(work[1].0, "fabrikam.local");
    }
}
