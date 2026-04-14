//! auto_delegation_enumeration -- find delegation for new creds.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Dispatches delegation enumeration for new credentials.
/// Interval: 30s. Matches Python `_auto_delegation_enumeration`.
pub async fn auto_delegation_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.delegation_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
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

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                // Skip delegation accounts — delegation enum is already done
                // with other creds, and using a delegation account's cred
                // burns auth budget reserved for S4U.
                .filter(|c| !state.is_delegation_account(&c.username))
                .filter_map(|cred| {
                    if cred.domain.is_empty() {
                        return None;
                    }
                    let dedup = format!(
                        "{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_DELEGATION_CREDS, &dedup) {
                        return None;
                    }
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned()?;
                    Some((dedup, cred.domain.clone(), dc_ip, cred.clone()))
                })
                .collect()
        };

        for (dedup_key, domain, dc_ip, cred) in work {
            match dispatcher
                .request_delegation_enum(&domain, &dc_ip, &cred)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %domain, "Delegation enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DELEGATION_CREDS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DELEGATION_CREDS, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch delegation enumeration"),
            }
        }
    }
}
