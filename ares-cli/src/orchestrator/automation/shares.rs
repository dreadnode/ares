//! auto_share_spider -- spider readable shares for credentials.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

fn resolve_share_host_domain(state: &StateInner, share_host: &str) -> String {
    if let Some(host) = state
        .hosts
        .iter()
        .find(|h| h.ip == share_host || h.hostname.eq_ignore_ascii_case(share_host))
    {
        if let Some((_, domain)) = host.hostname.to_lowercase().split_once('.') {
            return domain.to_string();
        }
    }

    if let Some((domain, _)) = state
        .domain_controllers
        .iter()
        .find(|(_, ip)| ip.as_str() == share_host)
    {
        return domain.to_lowercase();
    }

    share_host
        .to_lowercase()
        .split_once('.')
        .map(|(_, domain)| domain.to_string())
        .unwrap_or_default()
}

/// Select share-spider work items.
///
/// Picks the first non-delegation, non-quarantined credential (or any cred
/// as a fallback) and walks `state.shares` for READable, non-administrative
/// shares whose dedup key is unprocessed. Caps the batch at `max_items`.
///
/// Returns `(dedup_key, host, share_name, credential)` tuples. Empty when
/// no credentials are present.
///
/// Pure — extracted from `auto_share_spider` so the credential-selection +
/// share-filter rules can be tested without a Dispatcher.
pub(crate) fn select_share_spider_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<(String, String, String, ares_core::models::Credential)> {
    let cred = match state
        .credentials
        .iter()
        .find(|c| {
            !state.is_delegation_account(&c.username)
                && !state.is_principal_quarantined(&c.username, &c.domain)
        })
        .or_else(|| state.credentials.first())
    {
        Some(c) => c.clone(),
        None => return Vec::new(),
    };

    state
        .shares
        .iter()
        .filter(|s| {
            let perms = s.permissions.to_uppercase();
            perms.contains("READ") && !s.name.to_uppercase().ends_with('$')
        })
        .filter(|s| {
            let domain = resolve_share_host_domain(state, &s.host);
            domain.is_empty() || !state.is_domain_dominated(&domain)
        })
        .filter_map(|s| {
            let dedup = format!("{}:{}:{}:{}", s.host, s.name, cred.username, cred.domain);
            if state.is_processed(DEDUP_SPIDERED_SHARES, &dedup) {
                None
            } else {
                Some((dedup, s.host.clone(), s.name.clone(), cred.clone()))
            }
        })
        .take(max_items)
        .collect()
}

/// Spiders readable shares for credentials using available creds.
/// Interval: 30s.
pub async fn auto_share_spider(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            select_share_spider_work(&state, 3)
        };
        if work.is_empty() {
            continue;
        }

        for (dedup_key, host, share, cred) in work {
            match dispatcher.request_share_spider(&host, &share, &cred).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, host = %host, share = %share, "Share spider dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SPIDERED_SHARES, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SPIDERED_SHARES, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch share spider"),
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

    fn make_share(host: &str, name: &str, perms: &str) -> ares_core::models::Share {
        ares_core::models::Share {
            host: host.to_string(),
            name: name.to_string(),
            permissions: perms.to_string(),
            authenticated_as: None,
            comment: String::new(),
        }
    }

    fn make_host(hostname: &str, ip: &str) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn select_share_spider_empty_without_credentials() {
        let mut s = StateInner::new("op".into());
        s.shares.push(make_share("dc01", "Shared", "READ"));
        assert!(select_share_spider_work(&s, 3).is_empty());
    }

    #[test]
    fn select_share_spider_emits_readable_share() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.shares.push(make_share("dc01", "Shared", "READ,WRITE"));
        let work = select_share_spider_work(&s, 3);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "dc01");
        assert_eq!(work[0].2, "Shared");
        assert_eq!(work[0].3.username, "alice");
    }

    #[test]
    fn select_share_spider_excludes_administrative_shares() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        // Administrative shares end with '$' (C$, ADMIN$, IPC$) → skipped.
        s.shares.push(make_share("dc01", "C$", "READ"));
        s.shares.push(make_share("dc01", "ADMIN$", "READ,WRITE"));
        s.shares.push(make_share("dc01", "Shared", "READ"));
        let work = select_share_spider_work(&s, 3);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].2, "Shared");
    }

    #[test]
    fn select_share_spider_skips_shares_without_read_perm() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.shares.push(make_share("dc01", "Public", "WRITE_ONLY"));
        assert!(select_share_spider_work(&s, 3).is_empty());
    }

    #[test]
    fn select_share_spider_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.shares.push(make_share("dc01", "Shared", "READ"));
        s.mark_processed(
            DEDUP_SPIDERED_SHARES,
            "dc01:Shared:alice:contoso.local".into(),
        );
        assert!(select_share_spider_work(&s, 3).is_empty());
    }

    #[test]
    fn select_share_spider_skips_dominated_share_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.shares.push(make_share("192.168.58.10", "Shared", "READ"));
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_share_spider_work(&s, 3).is_empty());
    }

    #[test]
    fn select_share_spider_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        for n in 0..10 {
            s.shares
                .push(make_share("dc01", &format!("share{n}"), "READ"));
        }
        assert_eq!(select_share_spider_work(&s, 3).len(), 3);
        assert_eq!(select_share_spider_work(&s, 5).len(), 5);
    }

    #[test]
    fn select_share_spider_prefers_non_delegation_credential() {
        let mut s = StateInner::new("op".into());
        // Mark svc_sql as a delegation account via a vuln.
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
        assert!(s.is_delegation_account("svc_sql"));

        s.credentials
            .push(make_cred("svc_sql", "Pw", "contoso.local"));
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.shares.push(make_share("dc01", "Shared", "READ"));
        let work = select_share_spider_work(&s, 3);
        // alice should win over svc_sql.
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].3.username, "alice");
    }

    #[test]
    fn select_share_spider_fallback_to_delegation_cred_when_only_option() {
        let mut s = StateInner::new("op".into());
        // svc_sql is the ONLY credential — fallback path returns it.
        s.credentials
            .push(make_cred("svc_sql", "Pw", "contoso.local"));
        s.shares.push(make_share("dc01", "Shared", "READ"));
        let work = select_share_spider_work(&s, 3);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].3.username, "svc_sql");
    }
}
