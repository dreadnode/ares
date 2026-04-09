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
        // Also extract from nested "discoveries" key (structured parser output
        // from the LLM runner is placed under result.discoveries)
        if let Some(disc) = payload.get("discoveries") {
            if let Err(e) = extract_discoveries(disc, dispatcher).await {
                warn!(task_id = %task_id, err = %e, "Failed to extract nested discoveries");
            }
            check_domain_admin_indicators(disc, dispatcher).await;
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
    let parsed = parse_discoveries(payload);

    for cred in parsed.credentials {
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

    for hash in parsed.hashes {
        match dispatcher.state.publish_hash(&dispatcher.queue, hash).await {
            Ok(true) => debug!("Published new hash from result"),
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish hash"),
        }
    }

    for host in parsed.hosts {
        let _ = dispatcher.state.publish_host(&dispatcher.queue, host).await;
    }

    for user in parsed.users {
        match dispatcher.state.publish_user(&dispatcher.queue, user).await {
            Ok(true) => debug!("Published new user from result"),
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish user"),
        }
    }

    for vuln in parsed.vulnerabilities {
        let _ = dispatcher
            .state
            .publish_vulnerability(&dispatcher.queue, vuln)
            .await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pure parsing (testable without Redis)
// ---------------------------------------------------------------------------

/// Parsed discoveries from a JSON result payload.
#[derive(Debug, Default)]
pub(crate) struct ParsedDiscoveries {
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}

/// Parse discoveries from a JSON payload into typed structs.
///
/// Pure function — no IO, no Redis. The caller publishes the results.
pub(crate) fn parse_discoveries(payload: &Value) -> ParsedDiscoveries {
    let mut result = ParsedDiscoveries::default();

    // Credentials (array)
    if let Some(creds) = payload.get("credentials").and_then(|v| v.as_array()) {
        for cred_val in creds {
            if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
                result.credentials.push(cred);
            }
        }
    }

    // Single credential
    if let Some(cred_val) = payload.get("credential") {
        if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
            result.credentials.push(cred);
        }
    }

    // Cracked password → credential
    if let Some(cracked) = payload.get("cracked_password").and_then(|v| v.as_str()) {
        if let Some(username) = payload.get("username").and_then(|v| v.as_str()) {
            let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            result.credentials.push(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                password: cracked.to_string(),
                domain: domain.to_string(),
                source: "cracked".to_string(),
                discovered_at: Some(chrono::Utc::now()),
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            });
        }
    }

    // Hashes
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Ok(hash) = serde_json::from_value::<Hash>(hash_val.clone()) {
                result.hashes.push(hash);
            }
        }
    }

    // Hosts
    if let Some(hosts) = payload.get("hosts").and_then(|v| v.as_array()) {
        for host_val in hosts {
            if let Ok(host) = serde_json::from_value::<Host>(host_val.clone()) {
                result.hosts.push(host);
            }
        }
    }

    // Users
    if let Some(users) = payload.get("discovered_users").and_then(|v| v.as_array()) {
        for user_val in users {
            if let Ok(user) = serde_json::from_value::<User>(user_val.clone()) {
                result.users.push(user);
            }
        }
    }

    // Vulnerabilities
    if let Some(vulns) = payload.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln_val in vulns {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }

    result
}

/// Check if a payload contains domain admin indicators. Pure function.
pub(crate) fn has_domain_admin_indicator(payload: &Value) -> bool {
    // Explicit flag
    if payload.get("has_domain_admin").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    // krbtgt hash present
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Some(username) = hash_val.get("username").and_then(|v| v.as_str()) {
                if username.to_lowercase() == "krbtgt" {
                    return true;
                }
            }
        }
    }
    false
}

/// Check result for domain admin indicators and update state.
async fn check_domain_admin_indicators(payload: &Value, dispatcher: &Arc<Dispatcher>) {
    if !has_domain_admin_indicator(payload) {
        return;
    }

    // Determine the path description
    let path = if payload.get("has_domain_admin").and_then(|v| v.as_bool()) == Some(true) {
        payload
            .get("domain_admin_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        // Must be krbtgt hash
        Some("secretsdump -> krbtgt hash".to_string())
    };

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

// ---------------------------------------------------------------------------
// Tests (pure parsing — no Redis needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_credentials_array() {
        let payload = json!({
            "credentials": [
                {
                    "id": "c1",
                    "username": "admin",
                    "password": "P@ss1",
                    "domain": "contoso.local",
                    "source": "kerberoast",
                    "is_admin": false,
                    "attack_step": 0
                },
                {
                    "id": "c2",
                    "username": "svc_sql",
                    "password": "SqlPass1",
                    "domain": "contoso.local",
                    "source": "secretsdump",
                    "is_admin": false,
                    "attack_step": 0
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.credentials.len(), 2);
        assert_eq!(parsed.credentials[0].username, "admin");
        assert_eq!(parsed.credentials[1].username, "svc_sql");
    }

    #[test]
    fn test_parse_single_credential() {
        let payload = json!({
            "credential": {
                "id": "c1",
                "username": "admin",
                "password": "P@ss1",
                "domain": "contoso.local",
                "source": "ntlm_relay",
                "is_admin": false,
                "attack_step": 0
            }
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.credentials[0].source, "ntlm_relay");
    }

    #[test]
    fn test_parse_cracked_password() {
        let payload = json!({
            "cracked_password": "Summer2024!",
            "username": "jdoe",
            "domain": "contoso.local"
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.credentials[0].username, "jdoe");
        assert_eq!(parsed.credentials[0].password, "Summer2024!");
        assert_eq!(parsed.credentials[0].source, "cracked");
    }

    #[test]
    fn test_parse_cracked_password_without_username_ignored() {
        let payload = json!({
            "cracked_password": "Summer2024!"
        });
        let parsed = parse_discoveries(&payload);
        assert!(parsed.credentials.is_empty());
    }

    #[test]
    fn test_parse_hashes() {
        let payload = json!({
            "hashes": [
                {
                    "id": "h1",
                    "username": "Administrator",
                    "hash_value": "aad3b435:abcdef123456",
                    "hash_type": "NTLM",
                    "domain": "contoso.local",
                    "source": "secretsdump",
                    "is_cracked": false,
                    "attack_step": 0
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.hashes.len(), 1);
        assert_eq!(parsed.hashes[0].username, "Administrator");
        assert_eq!(parsed.hashes[0].hash_type, "NTLM");
    }

    #[test]
    fn test_parse_hosts() {
        let payload = json!({
            "hosts": [
                {
                    "ip": "192.168.58.10",
                    "hostname": "dc01.contoso.local",
                    "os": "Windows Server 2019",
                    "is_dc": true,
                    "open_ports": [88, 389, 445]
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].ip, "192.168.58.10");
        assert!(parsed.hosts[0].is_dc);
    }

    #[test]
    fn test_parse_users() {
        let payload = json!({
            "discovered_users": [
                {
                    "username": "jdoe",
                    "domain": "contoso.local",
                    "groups": ["Domain Users"],
                    "is_admin": false,
                    "is_enabled": true
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.users.len(), 1);
        assert_eq!(parsed.users[0].username, "jdoe");
    }

    #[test]
    fn test_parse_vulnerabilities() {
        let payload = json!({
            "vulnerabilities": [
                {
                    "vuln_id": "vuln-001",
                    "vuln_type": "constrained_delegation",
                    "target": "192.168.58.20",
                    "discovered_by": "recon",
                    "details": {"account": "svc_sql"},
                    "recommended_agent": "privesc",
                    "priority": 3
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.vulnerabilities.len(), 1);
        assert_eq!(
            parsed.vulnerabilities[0].vuln_type,
            "constrained_delegation"
        );
    }

    #[test]
    fn test_parse_empty_payload() {
        let payload = json!({});
        let parsed = parse_discoveries(&payload);
        assert!(parsed.credentials.is_empty());
        assert!(parsed.hashes.is_empty());
        assert!(parsed.hosts.is_empty());
        assert!(parsed.users.is_empty());
        assert!(parsed.vulnerabilities.is_empty());
    }

    #[test]
    fn test_parse_malformed_entries_skipped() {
        let payload = json!({
            "credentials": [
                {"username": "valid", "id": "c1", "password": "x", "domain": "d",
                 "source": "s", "is_admin": false, "attack_step": 0},
                {"bad_field": "not a credential"}
            ],
            "hashes": [
                {"not_a_hash": true}
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.credentials.len(), 1);
        assert!(parsed.hashes.is_empty()); // malformed entry skipped
    }

    #[test]
    fn test_parse_mixed_payload() {
        let payload = json!({
            "credentials": [{
                "id": "c1", "username": "admin", "password": "P@ss",
                "domain": "contoso.local", "source": "test",
                "is_admin": true, "attack_step": 0
            }],
            "hashes": [{
                "id": "h1", "username": "krbtgt",
                "hash_value": "abc123", "hash_type": "NTLM",
                "domain": "contoso.local", "source": "secretsdump",
                "is_cracked": false, "attack_step": 0
            }],
            "hosts": [{
                "ip": "192.168.58.10", "hostname": "dc01.contoso.local",
                "is_dc": true
            }],
            "has_domain_admin": true,
            "domain_admin_path": "secretsdump -> Administrator"
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.hashes.len(), 1);
        assert_eq!(parsed.hosts.len(), 1);
    }

    // --- Domain admin indicator tests ---

    #[test]
    fn test_da_indicator_explicit_flag() {
        let payload = json!({"has_domain_admin": true});
        assert!(has_domain_admin_indicator(&payload));
    }

    #[test]
    fn test_da_indicator_false_flag() {
        let payload = json!({"has_domain_admin": false});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn test_da_indicator_krbtgt_hash() {
        let payload = json!({
            "hashes": [{"username": "krbtgt", "hash_value": "abc"}]
        });
        assert!(has_domain_admin_indicator(&payload));
    }

    #[test]
    fn test_da_indicator_krbtgt_case_insensitive() {
        let payload = json!({
            "hashes": [{"username": "KRBTGT", "hash_value": "abc"}]
        });
        assert!(has_domain_admin_indicator(&payload));
    }

    #[test]
    fn test_da_indicator_non_krbtgt_hash() {
        let payload = json!({
            "hashes": [{"username": "Administrator", "hash_value": "abc"}]
        });
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn test_da_indicator_empty_payload() {
        let payload = json!({});
        assert!(!has_domain_admin_indicator(&payload));
    }
}
