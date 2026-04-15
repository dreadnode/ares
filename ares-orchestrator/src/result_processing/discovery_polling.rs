//! Background discovery polling.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_core::models::{Credential, Hash, Host, Share, User, VulnerabilityInfo};

use super::parsing::resolve_parent_id;
use super::LOCKOUT_PATTERNS;
use crate::dispatcher::Dispatcher;

pub async fn discovery_poller(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }
        if let Err(e) = poll_discoveries(&dispatcher).await {
            debug!(err = %e, "Discovery poll error");
        }
    }
}

async fn poll_discoveries(dispatcher: &Dispatcher) -> Result<()> {
    let key = dispatcher.state.discovery_key().await;
    let mut conn = dispatcher.queue.connection();
    let discoveries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap_or_default();
    if discoveries.is_empty() {
        return Ok(());
    }
    let _: () = conn.del(&key).await?;
    info!(
        count = discoveries.len(),
        "Processing real-time discoveries"
    );
    for json_str in &discoveries {
        let discovery: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "Bad discovery JSON");
                continue;
            }
        };
        let disc_type = discovery
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let data = match discovery.get("data") {
            Some(d) => d,
            None => continue,
        };
        let input_username = discovery.get("input_username").and_then(|v| v.as_str());
        let input_domain = discovery.get("input_domain").and_then(|v| v.as_str());
        match disc_type {
            "credential" => match serde_json::from_value::<Credential>(data.clone()) {
                Ok(mut cred) => {
                    if cred.parent_id.is_none() {
                        let state = dispatcher.state.read().await;
                        let (pid, step) = resolve_parent_id(
                            &state.credentials,
                            &state.hashes,
                            &cred.source,
                            &cred.username,
                            &cred.domain,
                            input_username,
                            input_domain,
                        );
                        cred.parent_id = pid;
                        cred.attack_step = step;
                        drop(state);
                    }
                    let user_domain = format!("{}@{}", cred.username, cred.domain);
                    match dispatcher
                        .state
                        .publish_credential(&dispatcher.queue, cred)
                        .await
                    {
                        Ok(true) => {
                            info!(credential = %user_domain, "Discovery: credential published")
                        }
                        Ok(false) => {
                            debug!(credential = %user_domain, "Discovery: credential already known")
                        }
                        Err(e) => {
                            warn!(err = %e, credential = %user_domain, "Failed to publish discovered credential")
                        }
                    }
                }
                Err(e) => warn!(err = %e, "Failed to deserialize credential discovery"),
            },
            "hash" => {
                if let Ok(mut hash) = serde_json::from_value::<Hash>(data.clone()) {
                    if hash.parent_id.is_none() {
                        let state = dispatcher.state.read().await;
                        let (pid, step) = resolve_parent_id(
                            &state.credentials,
                            &state.hashes,
                            &hash.source,
                            &hash.username,
                            &hash.domain,
                            input_username,
                            input_domain,
                        );
                        hash.parent_id = pid;
                        hash.attack_step = step;
                        drop(state);
                    }
                    let _ = dispatcher.state.publish_hash(&dispatcher.queue, hash).await;
                }
            }
            "vulnerability" | "delegation" => {
                if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(data.clone()) {
                    let _ = dispatcher
                        .state
                        .publish_vulnerability(&dispatcher.queue, vuln)
                        .await;
                }
            }
            "host" => match serde_json::from_value::<Host>(data.clone()) {
                Ok(host) => {
                    let _ = dispatcher.state.publish_host(&dispatcher.queue, host).await;
                }
                Err(e) => {
                    warn!(err = %e, data = %data, "Failed to deserialize host discovery");
                }
            },
            "share" => {
                if let Ok(share) = serde_json::from_value::<Share>(data.clone()) {
                    let _ = dispatcher
                        .state
                        .publish_share(&dispatcher.queue, share)
                        .await;
                }
            }
            "user" => {
                if let Ok(user) = serde_json::from_value::<User>(data.clone()) {
                    if ["kerberos_enum", "netexec_user_enum"].contains(&user.source.as_str()) {
                        let _ = dispatcher.state.publish_user(&dispatcher.queue, user).await;
                    }
                }
            }
            other => {
                debug!(disc_type = other, "Unknown discovery type, ignoring");
            }
        }
    }
    dispatcher.credential_access_notify.notify_waiters();
    dispatcher.delegation_notify.notify_waiters();
    let _ = dispatcher.notify_state_update().await;
    Ok(())
}

/// Check if a task result contains lockout error indicators.
pub(crate) fn has_lockout_in_result(result: &crate::task_queue::TaskResult) -> bool {
    if let Some(ref err) = result.error {
        if LOCKOUT_PATTERNS.iter().any(|p| err.contains(p)) {
            return true;
        }
    }
    if let Some(ref payload) = result.result {
        if let Some(outputs) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
            for output in outputs {
                if let Some(text) = output.as_str() {
                    if LOCKOUT_PATTERNS.iter().any(|p| text.contains(p)) {
                        return true;
                    }
                }
            }
        }
        for key in &["summary", "output", "tool_output"] {
            if let Some(text) = payload.get(*key).and_then(|v| v.as_str()) {
                if LOCKOUT_PATTERNS.iter().any(|p| text.contains(p)) {
                    return true;
                }
            }
        }
    }
    false
}
