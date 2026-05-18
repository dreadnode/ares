//! auto_share_enumeration -- enumerate SMB shares on discovered hosts using credentials.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Extract the AD domain suffix from a host's FQDN hostname. Returns
/// `Some("contoso.local")` for `"dc01.contoso.local"`, `None` for bare or
/// empty hostnames. Used to pair each host with a credential whose domain
/// is likely to authenticate against it — a cross-forest credential gets
/// access-denied on SMB and surfaces no shares, masking real attack surface.
fn host_domain_from_fqdn(hostname: &str) -> Option<String> {
    let trimmed = hostname.trim().to_lowercase();
    let (_, domain) = trimmed.split_once('.')?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

/// Dispatches share enumeration on each known host when credentials are available.
///
/// Per-host credential selection: for each host whose FQDN reveals its AD
/// domain, prefer a credential whose `domain` matches. Falls back to any
/// non-delegation credential when the host's domain is unknown or when no
/// same-domain credential exists. This unblocks cross-forest CA enumeration
/// — a single global credential was failing SMB auth against other-forest
/// hosts, leaving the CertEnroll share unknown and silently disabling ADCS
/// enumeration there.
///
/// Interval: 20s. Dedup key: "{host_ip}:{cred_user}:{cred_domain}".
/// Select share-enumeration work items for this tick.
///
/// Walks `state.target_ips ∪ state.hosts.ip`, pairing each IP with the
/// best-matching credential:
///   1. If the host has an FQDN hostname, prefer a same-domain credential
///      from the per-domain index.
///   2. Otherwise (or no same-domain cred), fall back to the first
///      non-delegation/non-quarantined cred, then any cred.
///
/// Returns `(dedup_key, ip, credential)` tuples skipping already-processed
/// entries, capped at `max_items`. Empty when no credentials are available.
///
/// Pure — extracted from `auto_share_enumeration` so the credential
/// selection per host and the dedup gate can be unit-tested without a
/// Dispatcher.
pub(crate) fn select_share_enumeration_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<(String, String, ares_core::models::Credential)> {
    let mut creds_by_domain: HashMap<String, ares_core::models::Credential> = HashMap::new();
    for c in &state.credentials {
        if state.is_delegation_account(&c.username)
            || state.is_principal_quarantined(&c.username, &c.domain)
        {
            continue;
        }
        let key = c.domain.to_lowercase();
        creds_by_domain.entry(key).or_insert_with(|| c.clone());
    }

    let fallback = state
        .credentials
        .iter()
        .find(|c| {
            !state.is_delegation_account(&c.username)
                && !state.is_principal_quarantined(&c.username, &c.domain)
        })
        .or_else(|| state.credentials.first())
        .cloned();

    let Some(fallback) = fallback else {
        return Vec::new();
    };

    let mut hostname_by_ip: HashMap<String, String> = HashMap::new();
    for h in &state.hosts {
        if !h.hostname.is_empty() {
            hostname_by_ip.insert(h.ip.clone(), h.hostname.clone());
        }
    }

    let mut ips: Vec<String> = state.target_ips.clone();
    for host in &state.hosts {
        if !ips.contains(&host.ip) {
            ips.push(host.ip.clone());
        }
    }

    ips.into_iter()
        .filter_map(|ip| {
            let host_domain = hostname_by_ip
                .get(&ip)
                .and_then(|n| host_domain_from_fqdn(n));
            let cred = host_domain
                .as_deref()
                .and_then(|d| creds_by_domain.get(d).cloned())
                .unwrap_or_else(|| fallback.clone());
            let dedup = format!(
                "{}:{}:{}",
                ip,
                cred.username.to_lowercase(),
                cred.domain.to_lowercase()
            );
            if state.is_processed(DEDUP_SHARE_ENUM, &dedup) {
                None
            } else {
                Some((dedup, ip, cred))
            }
        })
        .take(max_items)
        .collect()
}

pub async fn auto_share_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut no_cred_logged = false;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let (work, no_creds) = {
            let state = dispatcher.state.read().await;
            let no_creds = state
                .credentials
                .iter()
                .find(|c| {
                    !state.is_delegation_account(&c.username)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
                .or_else(|| state.credentials.first())
                .is_none();
            (select_share_enumeration_work(&state, 5), no_creds)
        };

        if no_creds {
            if !no_cred_logged {
                info!("Share enum: no credentials in memory yet, waiting");
                no_cred_logged = true;
            }
            continue;
        }
        no_cred_logged = false;

        for (dedup_key, host_ip, cred) in work {
            match dispatcher.request_share_enumeration(&host_ip, &cred).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, host = %host_ip, "Share enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SHARE_ENUM, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SHARE_ENUM, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch share enumeration"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_domain_extracts_suffix() {
        assert_eq!(
            host_domain_from_fqdn("dc01.contoso.local"),
            Some("contoso.local".to_string())
        );
        assert_eq!(
            host_domain_from_fqdn("WEB01.fabrikam.local"),
            Some("fabrikam.local".to_string())
        );
    }

    #[test]
    fn host_domain_handles_subdomains() {
        // child.parent.local → "child.parent.local" minus the first label
        assert_eq!(
            host_domain_from_fqdn("ws01.child.fabrikam.local"),
            Some("child.fabrikam.local".to_string())
        );
    }

    #[test]
    fn host_domain_returns_none_for_bare_hostname() {
        assert_eq!(host_domain_from_fqdn("dc01"), None);
        assert_eq!(host_domain_from_fqdn(""), None);
        assert_eq!(host_domain_from_fqdn("   "), None);
    }

    // ── select_share_enumeration_work ───────────────────────────────────

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

    fn make_host(ip: &str, hostname: &str) -> ares_core::models::Host {
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
    fn select_share_enum_empty_when_no_credentials() {
        let mut s = StateInner::new("op".into());
        s.target_ips.push("192.168.58.10".into());
        assert!(select_share_enumeration_work(&s, 5).is_empty());
    }

    #[test]
    fn select_share_enum_emits_work_for_target_ip() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.target_ips.push("192.168.58.10".into());
        let work = select_share_enumeration_work(&s, 5);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.10");
    }

    #[test]
    fn select_share_enum_pairs_with_same_domain_credential() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw", "fabrikam.local"));
        s.hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local"));
        s.hosts
            .push(make_host("192.168.58.40", "dc01.fabrikam.local"));
        let mut work = select_share_enumeration_work(&s, 5);
        work.sort_by(|a, b| a.1.cmp(&b.1));
        // dc01.contoso.local → alice's contoso cred
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2.username, "alice");
        // dc01.fabrikam.local → bob's fabrikam cred
        assert_eq!(work[1].1, "192.168.58.40");
        assert_eq!(work[1].2.username, "bob");
    }

    #[test]
    fn select_share_enum_falls_back_to_global_cred_when_domain_unknown() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        // Host with no FQDN → host_domain is None → use fallback.
        s.hosts.push(make_host("192.168.58.10", "dc01"));
        s.target_ips.push("192.168.58.10".into());
        let work = select_share_enumeration_work(&s, 5);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].2.username, "alice");
    }

    #[test]
    fn select_share_enum_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.target_ips.push("192.168.58.10".into());
        s.mark_processed(DEDUP_SHARE_ENUM, "192.168.58.10:alice:contoso.local".into());
        assert!(select_share_enumeration_work(&s, 5).is_empty());
    }

    #[test]
    fn select_share_enum_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        for n in 1..=10 {
            s.target_ips.push(format!("192.168.58.{n}"));
        }
        assert_eq!(select_share_enumeration_work(&s, 3).len(), 3);
        assert_eq!(select_share_enumeration_work(&s, 7).len(), 7);
    }

    #[test]
    fn select_share_enum_dedupes_ip_from_targets_and_hosts() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.target_ips.push("192.168.58.10".into());
        s.hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local"));
        // IP appears in both lists — must emit exactly one work item.
        assert_eq!(select_share_enumeration_work(&s, 5).len(), 1);
    }
}
