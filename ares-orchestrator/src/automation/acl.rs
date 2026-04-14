//! auto_acl_chain_follow -- dispatch ACL chain steps using available creds.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Follows ACL chains from BloodHound results, dispatching each step when
/// credentials for the source user are available.
/// Interval: 30s. Each chain is a JSON array of steps; we find the first
/// undispatched step whose source user has known credentials and dispatch it.
pub async fn auto_acl_chain_follow(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
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

        // Skip if domain admin already achieved
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin {
                continue;
            }
        }

        // Collect work items: (dedup_key, chain_step, credential)
        let work: Vec<(String, serde_json::Value, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;

            if state.acl_chains.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (chain_idx, chain) in state.acl_chains.iter().enumerate() {
                // Each chain is expected to be a JSON array of step objects
                let steps = match chain.as_array() {
                    Some(s) => s,
                    None => {
                        // Or it might be an object with a "steps" field
                        match chain.get("steps").and_then(|v| v.as_array()) {
                            Some(s) => s,
                            None => continue,
                        }
                    }
                };

                for (step_idx, step) in steps.iter().enumerate() {
                    let dedup_key = format!("chain:{}:step:{}", chain_idx, step_idx);

                    // Skip already dispatched steps
                    if state.dispatched_acl_steps.contains(&dedup_key) {
                        continue;
                    }
                    if state.is_processed(DEDUP_ACL_STEPS, &dedup_key) {
                        continue;
                    }

                    // Get the source user for this step
                    let source_user = step
                        .get("source")
                        .or_else(|| step.get("source_user"))
                        .or_else(|| step.get("from"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let source_domain = step
                        .get("source_domain")
                        .or_else(|| step.get("domain"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if source_user.is_empty() {
                        continue;
                    }

                    // Find credential for the source user
                    let cred = state.credentials.iter().find(|c| {
                        c.username.to_lowercase() == source_user.to_lowercase()
                            && (source_domain.is_empty()
                                || c.domain.to_lowercase() == source_domain.to_lowercase())
                    });

                    if let Some(cred) = cred {
                        items.push((dedup_key, step.clone(), cred.clone()));
                    }

                    // Only dispatch the first undispatched step per chain
                    break;
                }
            }

            items
        };

        // Dispatch each collected step
        for (dedup_key, step, cred) in work {
            let payload = json!({
                "technique": "acl_chain_step",
                "step": step,
                "credential": {
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                },
            });

            match dispatcher
                .throttled_submit("acl_chain_step", "acl", payload, 4)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        step_key = %dedup_key,
                        "ACL chain step dispatched"
                    );
                    // Mark as dispatched in both in-memory set and dedup
                    {
                        let mut state = dispatcher.state.write().await;
                        state.dispatched_acl_steps.insert(dedup_key.clone());
                        state.mark_processed(DEDUP_ACL_STEPS, dedup_key.clone());
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ACL_STEPS, &dedup_key)
                        .await;
                }
                Ok(None) => {} // deferred or throttled
                Err(e) => warn!(err = %e, "Failed to dispatch ACL chain step"),
            }
        }
    }
}
