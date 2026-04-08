//! Result processing and discovery polling.
//!
//! Handles completed task results: extracts discovered credentials, hashes,
//! hosts, and vulnerabilities from result payloads and publishes them to
//! shared state and Redis.
//!
//! Also polls the `ares:discoveries:{op_id}` LIST for real-time worker
//! discoveries that arrive outside the task result flow.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_core::models::{Credential, Hash, Host, User, VulnerabilityInfo};

use crate::dispatcher::Dispatcher;
use crate::results::CompletedTask;
use crate::throttling::Throttler;

/// Process a completed task result: extract discoveries and update state.
pub async fn process_completed_task(
    completed: &CompletedTask,
    dispatcher: &Arc<Dispatcher>,
    throttler: &Throttler,
) {
    let task_id = &completed.task_id;
    let result = &completed.result;

    if result.success {
        info!(
            task_id = %task_id,
            agent = result.agent_name.as_deref().unwrap_or("unknown"),
            "Task completed successfully"
        );
        throttler.clear_rate_limit_error().await;
    } else {
        let err_msg = result.error.as_deref().unwrap_or("unknown error");
        warn!(task_id = %task_id, err = err_msg, "Task failed");

        if err_msg.to_lowercase().contains("rate limit") || err_msg.to_lowercase().contains("429") {
            throttler.record_rate_limit_error().await;
        }
        return; // Don't extract discoveries from failed tasks
    }

    // Extract discoveries from the result payload
    if let Some(ref payload) = result.result {
        if let Err(e) = extract_discoveries(payload, dispatcher).await {
            warn!(task_id = %task_id, err = %e, "Failed to extract discoveries from result");
        }
    }

    // Check for domain admin indicators
    if let Some(ref payload) = result.result {
        check_domain_admin_indicators(payload, dispatcher).await;
    }

    // Notify credential access to wake up for potential new creds
    dispatcher.credential_access_notify.notify_one();

    // Publish state update to workers
    let _ = dispatcher.notify_state_update().await;
}

/// Extract credentials, hashes, hosts, and vulns from a result payload.
async fn extract_discoveries(payload: &Value, dispatcher: &Arc<Dispatcher>) -> Result<()> {
    // Extract credentials
    if let Some(creds) = payload.get("credentials").and_then(|v| v.as_array()) {
        for cred_val in creds {
            if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
                match dispatcher
                    .state
                    .publish_credential(&dispatcher.queue, cred)
                    .await
                {
                    Ok(true) => debug!("Published new credential from result"),
                    Ok(false) => {} // duplicate
                    Err(e) => warn!(err = %e, "Failed to publish credential"),
                }
            }
        }
    }

    // Single credential (some tasks return one instead of array)
    if let Some(cred_val) = payload.get("credential") {
        if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
            let _ = dispatcher
                .state
                .publish_credential(&dispatcher.queue, cred)
                .await;
        }
    }

    // Extract hashes
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Ok(hash) = serde_json::from_value::<Hash>(hash_val.clone()) {
                match dispatcher.state.publish_hash(&dispatcher.queue, hash).await {
                    Ok(true) => debug!("Published new hash from result"),
                    Ok(false) => {}
                    Err(e) => warn!(err = %e, "Failed to publish hash"),
                }
            }
        }
    }

    // Extract hosts
    if let Some(hosts) = payload.get("hosts").and_then(|v| v.as_array()) {
        for host_val in hosts {
            if let Ok(host) = serde_json::from_value::<Host>(host_val.clone()) {
                let _ = dispatcher.state.publish_host(&dispatcher.queue, host).await;
            }
        }
    }

    // Extract users
    if let Some(users) = payload.get("discovered_users").and_then(|v| v.as_array()) {
        for user_val in users {
            if let Ok(user) = serde_json::from_value::<User>(user_val.clone()) {
                match dispatcher.state.publish_user(&dispatcher.queue, user).await {
                    Ok(true) => debug!("Published new user from result"),
                    Ok(false) => {} // duplicate
                    Err(e) => warn!(err = %e, "Failed to publish user"),
                }
            }
        }
    }

    // Extract vulnerabilities
    if let Some(vulns) = payload.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln_val in vulns {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                let _ = dispatcher
                    .state
                    .publish_vulnerability(&dispatcher.queue, vuln)
                    .await;
            }
        }
    }

    // Extract cracked passwords (from crack results)
    if let Some(cracked) = payload.get("cracked_password").and_then(|v| v.as_str()) {
        if let Some(username) = payload.get("username").and_then(|v| v.as_str()) {
            let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let cred = Credential {
                id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                password: cracked.to_string(),
                domain: domain.to_string(),
                source: "cracked".to_string(),
                discovered_at: Some(chrono::Utc::now()),
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            };
            let _ = dispatcher
                .state
                .publish_credential(&dispatcher.queue, cred)
                .await;
        }
    }

    Ok(())
}

/// Check result for domain admin indicators and update state.
async fn check_domain_admin_indicators(payload: &Value, dispatcher: &Arc<Dispatcher>) {
    // Check for explicit domain admin flag
    if let Some(true) = payload.get("has_domain_admin").and_then(|v| v.as_bool()) {
        let path = payload
            .get("domain_admin_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Err(e) = dispatcher
            .state
            .set_domain_admin(&dispatcher.queue, path)
            .await
        {
            warn!(err = %e, "Failed to set domain admin flag");
        } else {
            info!("🎯 Domain Admin achieved!");
        }
    }

    // Check for krbtgt hash (indicates DA)
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Some(username) = hash_val.get("username").and_then(|v| v.as_str()) {
                if username.to_lowercase() == "krbtgt" {
                    let path = Some("secretsdump -> krbtgt hash".to_string());
                    let _ = dispatcher
                        .state
                        .set_domain_admin(&dispatcher.queue, path)
                        .await;
                    info!("🎯 Domain Admin achieved via krbtgt hash!");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery polling — consume real-time discoveries from workers
// ---------------------------------------------------------------------------

/// Poll `ares:discoveries:{op_id}` for real-time worker discoveries.
/// Interval: 5s.
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

/// One cycle of discovery polling: LRANGE + LTRIM to consume all pending discoveries.
async fn poll_discoveries(dispatcher: &Dispatcher) -> Result<()> {
    let key = dispatcher.state.discovery_key().await;
    let mut conn = dispatcher.queue.connection();

    // Atomically read and clear: LRANGE 0 -1 then DEL
    let discoveries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap_or_default();
    if discoveries.is_empty() {
        return Ok(());
    }

    // Clear the list
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

        match disc_type {
            "credential" => {
                if let Ok(cred) = serde_json::from_value::<Credential>(data.clone()) {
                    let _ = dispatcher
                        .state
                        .publish_credential(&dispatcher.queue, cred)
                        .await;
                }
            }
            "hash" => {
                if let Ok(hash) = serde_json::from_value::<Hash>(data.clone()) {
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
            "host" => {
                if let Ok(host) = serde_json::from_value::<Host>(data.clone()) {
                    let _ = dispatcher.state.publish_host(&dispatcher.queue, host).await;
                }
            }
            other => {
                debug!(disc_type = other, "Unknown discovery type, ignoring");
            }
        }
    }

    // Notify credential access after processing discoveries
    dispatcher.credential_access_notify.notify_one();
    let _ = dispatcher.notify_state_update().await;

    Ok(())
}
