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

        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;

            // Build a per-domain credential index. The first non-delegation,
            // non-quarantined cred per domain wins. Avoids burning auth budget
            // on accounts reserved for S4U exploitation.
            let mut creds_by_domain: HashMap<String, ares_core::models::Credential> =
                HashMap::new();
            for c in &state.credentials {
                if state.is_delegation_account(&c.username)
                    || state.is_principal_quarantined(&c.username, &c.domain)
                {
                    continue;
                }
                let key = c.domain.to_lowercase();
                creds_by_domain.entry(key).or_insert_with(|| c.clone());
            }

            // Global fallback for hosts with unknown domain or no same-domain cred.
            let fallback = state
                .credentials
                .iter()
                .find(|c| {
                    !state.is_delegation_account(&c.username)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
                .or_else(|| state.credentials.first())
                .cloned();

            if fallback.is_none() {
                if !no_cred_logged {
                    info!(
                        hosts = state.hosts.len(),
                        target_ips = state.target_ips.len(),
                        "Share enum: no credentials in memory yet, waiting"
                    );
                    no_cred_logged = true;
                }
                continue;
            }
            no_cred_logged = false;

            // Pair each known IP with the best-matching credential. Same-domain
            // match wins; fall back to the global cred when host's domain is
            // unknown (no FQDN hostname yet) or no cred matches its domain.
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
                        .or_else(|| fallback.clone())?;
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
                .take(5)
                .collect()
        };

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
}
