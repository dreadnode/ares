//! auto_acl_chain_follow -- dispatch ACL chain steps using available creds.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::{Dispatcher, SubmissionOutcome};
use crate::orchestrator::state::*;

/// Extract steps from an ACL chain JSON value.
/// The chain can be a direct array or an object with a "steps" field.
fn extract_chain_steps(chain: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    chain
        .as_array()
        .or_else(|| chain.get("steps").and_then(|v| v.as_array()))
}

/// Extract source user from an ACL chain step.
/// Tries "source", "source_user", "from" keys in order.
fn extract_source_user(step: &serde_json::Value) -> &str {
    step.get("source")
        .or_else(|| step.get("source_user"))
        .or_else(|| step.get("from"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Extract source domain from an ACL chain step.
/// Tries "source_domain", "domain" keys.
fn extract_source_domain(step: &serde_json::Value) -> &str {
    step.get("source_domain")
        .or_else(|| step.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Build ACL chain step dedup key.
fn acl_step_dedup_key(chain_idx: usize, step_idx: usize) -> String {
    format!("chain:{}:step:{}", chain_idx, step_idx)
}

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

        // Skip only when ALL forests are dominated AND strategy says to stop.
        // When continue_after_da is true, keep following ACL chains for path diversity.
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
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
                let Some(steps) = extract_chain_steps(chain) else {
                    continue;
                };

                for (step_idx, step) in steps.iter().enumerate() {
                    let dedup_key = acl_step_dedup_key(chain_idx, step_idx);

                    // Skip already dispatched steps
                    if state.dispatched_acl_steps.contains(&dedup_key) {
                        continue;
                    }
                    if state.is_processed(DEDUP_ACL_STEPS, &dedup_key) {
                        continue;
                    }

                    // Get the source user for this step
                    let source_user = extract_source_user(step);
                    let source_domain = extract_source_domain(step);

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

            let priority = dispatcher.effective_priority("acl_abuse");
            // Mark dedup on Submitted OR Deferred — Deferred means the task is
            // safely in the deferred ZSET and the drain will retry it. Without
            // this, the next 30s tick re-emits the same step and the deferred
            // ZSET hits its per-type cap, silently dropping work.
            let mark_dedup = match dispatcher
                .throttled_submit_outcome("acl_chain_step", "acl", payload, priority)
                .await
            {
                Ok(SubmissionOutcome::Submitted(task_id)) => {
                    info!(
                        task_id = %task_id,
                        step_key = %dedup_key,
                        "ACL chain step dispatched"
                    );
                    true
                }
                Ok(SubmissionOutcome::Deferred) => {
                    debug!(step_key = %dedup_key, "ACL chain step deferred (will retry via deferred drain)");
                    true
                }
                Ok(SubmissionOutcome::Dropped) => {
                    debug!(step_key = %dedup_key, "ACL chain step dropped (will reconsider next tick)");
                    false
                }
                Err(e) => {
                    warn!(err = %e, "Failed to dispatch ACL chain step");
                    false
                }
            };
            if mark_dedup {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- extract_chain_steps ---

    #[test]
    fn extract_chain_steps_from_array() {
        let chain = json!([{"source": "a"}, {"source": "b"}]);
        let steps = extract_chain_steps(&chain).unwrap();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn extract_chain_steps_from_object_with_steps_field() {
        let chain = json!({"steps": [{"source": "a"}]});
        let steps = extract_chain_steps(&chain).unwrap();
        assert_eq!(steps.len(), 1);
    }

    #[test]
    fn extract_chain_steps_empty_array() {
        let chain = json!([]);
        let steps = extract_chain_steps(&chain).unwrap();
        assert!(steps.is_empty());
    }

    #[test]
    fn extract_chain_steps_invalid_returns_none() {
        let chain = json!({"other": "value"});
        assert!(extract_chain_steps(&chain).is_none());
    }

    #[test]
    fn extract_chain_steps_null_returns_none() {
        let chain = json!(null);
        assert!(extract_chain_steps(&chain).is_none());
    }

    #[test]
    fn extract_chain_steps_string_returns_none() {
        let chain = json!("not a chain");
        assert!(extract_chain_steps(&chain).is_none());
    }

    // --- extract_source_user ---

    #[test]
    fn extract_source_user_from_source_key() {
        let step = json!({"source": "admin"});
        assert_eq!(extract_source_user(&step), "admin");
    }

    #[test]
    fn extract_source_user_from_source_user_key() {
        let step = json!({"source_user": "jdoe"});
        assert_eq!(extract_source_user(&step), "jdoe");
    }

    #[test]
    fn extract_source_user_from_from_key() {
        let step = json!({"from": "svc_account"});
        assert_eq!(extract_source_user(&step), "svc_account");
    }

    #[test]
    fn extract_source_user_prefers_source_over_from() {
        let step = json!({"source": "admin", "from": "other"});
        assert_eq!(extract_source_user(&step), "admin");
    }

    #[test]
    fn extract_source_user_missing_returns_empty() {
        let step = json!({"target": "dc01"});
        assert_eq!(extract_source_user(&step), "");
    }

    #[test]
    fn extract_source_user_non_string_returns_empty() {
        let step = json!({"source": 42});
        assert_eq!(extract_source_user(&step), "");
    }

    // --- extract_source_domain ---

    #[test]
    fn extract_source_domain_from_source_domain_key() {
        let step = json!({"source_domain": "contoso.local"});
        assert_eq!(extract_source_domain(&step), "contoso.local");
    }

    #[test]
    fn extract_source_domain_from_domain_key() {
        let step = json!({"domain": "corp.net"});
        assert_eq!(extract_source_domain(&step), "corp.net");
    }

    #[test]
    fn extract_source_domain_prefers_source_domain() {
        let step = json!({"source_domain": "contoso.local", "domain": "other.local"});
        assert_eq!(extract_source_domain(&step), "contoso.local");
    }

    #[test]
    fn extract_source_domain_missing_returns_empty() {
        let step = json!({"source": "admin"});
        assert_eq!(extract_source_domain(&step), "");
    }

    #[test]
    fn extract_source_domain_non_string_returns_empty() {
        let step = json!({"source_domain": 123});
        assert_eq!(extract_source_domain(&step), "");
    }

    // --- acl_step_dedup_key ---

    #[test]
    fn acl_step_dedup_key_basic() {
        assert_eq!(acl_step_dedup_key(0, 0), "chain:0:step:0");
    }

    #[test]
    fn acl_step_dedup_key_large_indices() {
        assert_eq!(acl_step_dedup_key(42, 7), "chain:42:step:7");
    }
}
