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

use ares_core::models::{Credential, Hash, Host, Share, User, VulnerabilityInfo};

use crate::dispatcher::Dispatcher;
use crate::output_extraction;
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

    // Persist task completion to Redis (pending → completed) for recovery.
    // Matches Python's write to ares:op:{id}:completed_tasks HASH.
    {
        let core_result = ares_core::models::TaskResult {
            task_id: task_id.clone(),
            success: result.success,
            result: result.result.clone(),
            error: result.error.clone(),
            completed_at: result.completed_at.unwrap_or_else(chrono::Utc::now),
        };
        let _ = dispatcher
            .state
            .complete_task(&dispatcher.queue, task_id, core_result)
            .await;
    }

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

    // Secondary pass: regex-based extraction from raw text in the result.
    // This catches discoveries that the per-tool parsers or LLM may have missed.
    if let Some(ref payload) = result.result {
        let default_domain = get_default_domain(dispatcher).await;
        extract_from_raw_text(payload, dispatcher, &default_domain).await;
    }

    // S4U auto-chain: detect .ccache in output and dispatch secretsdump with ticket.
    // Mirrors Python's _auto_chain_s4u_lateral_movement — when a task produces a
    // Kerberos ticket (.ccache), chain a secretsdump using that ticket for
    // immediate credential extraction.
    if let Some(ref payload) = result.result {
        auto_chain_s4u_secretsdump(payload, dispatcher, &completed.task_id).await;
    }

    // Notify credential access and delegation enumeration to wake up for potential new creds
    dispatcher.credential_access_notify.notify_one();
    dispatcher.delegation_notify.notify_one();

    // Publish state update to workers
    let _ = dispatcher.notify_state_update().await;
}

/// Get the default domain from state (first domain, or empty string).
async fn get_default_domain(dispatcher: &Arc<Dispatcher>) -> String {
    let state = dispatcher.state.read().await;
    state.domains.first().cloned().unwrap_or_default()
}

/// S4U auto-chain: detect .ccache ticket in task output and dispatch secretsdump.
///
/// Mirrors Python's `_auto_chain_s4u_lateral_movement` — when a task produces a
/// Kerberos ticket file (.ccache), automatically dispatch a secretsdump task using
/// that ticket. This chains S4U/delegation → secretsdump without waiting for the
/// next automation cycle.
async fn auto_chain_s4u_secretsdump(payload: &Value, dispatcher: &Arc<Dispatcher>, task_id: &str) {
    // Collect all text fields to search for .ccache references
    let mut text_parts: Vec<&str> = Vec::new();
    for key in &["summary", "output", "result", "tool_output"] {
        if let Some(s) = payload.get(*key).and_then(|v| v.as_str()) {
            text_parts.push(s);
        }
    }
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                text_parts.push(s);
            } else if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
                text_parts.push(s);
            }
        }
    }

    let combined = text_parts.join("\n");
    let ticket_path = match ares_llm::routing::extract_ticket_path(&combined) {
        Some(p) => p,
        None => return, // No .ccache found
    };

    info!(
        task_id = %task_id,
        ticket_path = %ticket_path,
        "Detected .ccache ticket — chaining secretsdump"
    );

    // Try to extract target from the task params (target_spn → host) or ccache filename
    let target_ip = payload
        .get("target_spn")
        .and_then(|v| v.as_str())
        .and_then(ares_llm::routing::extract_host_from_spn)
        .or_else(|| {
            // Try to parse target from ccache filename:
            // Administrator@cifs_dc01.contoso.local@CONTOSO.LOCAL.ccache
            let fname = ticket_path.rsplit('/').next().unwrap_or(&ticket_path);
            if let Some(at_pos) = fname.find('@') {
                let after = &fname[at_pos + 1..];
                // Extract hostname: cifs_dc01.contoso.local@REALM.ccache
                let host_part = after.split('@').next().unwrap_or(after).replace('_', ".");
                // Remove the service prefix (cifs. → dc01.contoso.local)
                if let Some(dot_pos) = host_part.find('.') {
                    let candidate = &host_part[dot_pos + 1..];
                    if candidate.contains('.') {
                        return Some(candidate.to_string());
                    }
                }
            }
            None
        })
        .or_else(|| {
            // Fallback: use target_ip from the task payload
            payload
                .get("target_ip")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            payload
                .get("target")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

    let target_ip = match target_ip {
        Some(ip) => ip,
        None => {
            warn!(task_id = %task_id, "S4U auto-chain: .ccache found but no target could be determined");
            return;
        }
    };

    // Resolve target IP if it's a hostname
    let resolved_ip = {
        let state = dispatcher.state.read().await;
        // Check if target_ip is actually an IP already
        if target_ip.parse::<std::net::Ipv4Addr>().is_ok() {
            target_ip.clone()
        } else {
            // It's a hostname — look up in hosts
            state
                .hosts
                .iter()
                .find(|h| h.hostname.to_lowercase() == target_ip.to_lowercase())
                .map(|h| h.ip.clone())
                .unwrap_or(target_ip.clone())
        }
    };

    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    // Dispatch secretsdump with ticket (no password needed)
    let sd_payload = serde_json::json!({
        "technique": "secretsdump",
        "techniques": ["secretsdump"],
        "target_ip": resolved_ip,
        "domain": domain,
        "ticket_path": ticket_path,
        "no_pass": true,
    });

    match dispatcher
        .throttled_submit("credential_access", "credential_access", sd_payload, 2)
        .await
    {
        Ok(Some(new_task_id)) => {
            info!(
                parent_task = %task_id,
                chained_task = %new_task_id,
                target = %resolved_ip,
                ticket = %ticket_path,
                "S4U auto-chain: secretsdump dispatched with ticket"
            );
        }
        Ok(None) => {}
        Err(e) => warn!(err = %e, "S4U auto-chain: failed to dispatch secretsdump"),
    }
}

/// Extract discoveries from raw text fields in the result payload.
///
/// Collects text from "summary", "output", "result", and "tool_outputs" fields
/// and runs regex-based extraction on the combined text. This mirrors Python's
/// `_process_output_text()` — a safety net that catches discoveries the per-tool
/// parsers or LLM-reported structured data may have missed.
async fn extract_from_raw_text(
    payload: &Value,
    dispatcher: &Arc<Dispatcher>,
    default_domain: &str,
) {
    // Collect all text fields from the result payload
    let mut text_parts: Vec<&str> = Vec::new();

    for key in &["summary", "output", "result", "tool_output"] {
        if let Some(s) = payload.get(*key).and_then(|v| v.as_str()) {
            text_parts.push(s);
        }
    }

    // Also check array-valued tool_outputs
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                text_parts.push(s);
            } else if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
                text_parts.push(s);
            }
        }
    }

    if text_parts.is_empty() {
        return;
    }

    let combined = text_parts.join("\n");
    let extracted = output_extraction::extract_from_output_text(&combined, default_domain);

    if extracted.is_empty() {
        return;
    }

    let mut new_count = 0usize;

    for cred in extracted.credentials {
        match dispatcher
            .state
            .publish_credential(&dispatcher.queue, cred)
            .await
        {
            Ok(true) => new_count += 1,
            Ok(false) => {} // duplicate
            Err(e) => warn!(err = %e, "Failed to publish text-extracted credential"),
        }
    }

    for hash in extracted.hashes {
        match dispatcher.state.publish_hash(&dispatcher.queue, hash).await {
            Ok(true) => new_count += 1,
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish text-extracted hash"),
        }
    }

    for host in extracted.hosts {
        let _ = dispatcher.state.publish_host(&dispatcher.queue, host).await;
    }

    for user in extracted.users {
        match dispatcher.state.publish_user(&dispatcher.queue, user).await {
            Ok(true) => new_count += 1,
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish text-extracted user"),
        }
    }

    for share in extracted.shares {
        match dispatcher
            .state
            .publish_share(&dispatcher.queue, share)
            .await
        {
            Ok(true) => new_count += 1,
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish text-extracted share"),
        }
    }

    if new_count > 0 {
        info!(
            count = new_count,
            "Published new discoveries from raw text extraction"
        );
    }
}

/// Extract credentials, hashes, hosts, vulns, and shares from a result payload.
async fn extract_discoveries(payload: &Value, dispatcher: &Arc<Dispatcher>) -> Result<()> {
    let parsed = parse_discoveries(payload);

    for cred in parsed.credentials {
        // Capture fields before move for timeline event
        let source = cred.source.clone();
        let username = cred.username.clone();
        let domain = cred.domain.clone();
        let is_admin = cred.is_admin;
        match dispatcher
            .state
            .publish_credential(&dispatcher.queue, cred)
            .await
        {
            Ok(true) => {
                debug!("Published new credential from result");
                create_credential_timeline_event(dispatcher, &source, &username, &domain, is_admin)
                    .await;
            }
            Ok(false) => {} // duplicate
            Err(e) => warn!(err = %e, "Failed to publish credential"),
        }
    }

    for hash in parsed.hashes {
        // Capture fields before move for timeline event
        let username = hash.username.clone();
        let domain = hash.domain.clone();
        let hash_type = hash.hash_type.clone();
        let hash_value = hash.hash_value.clone();
        let source = hash.source.clone();
        match dispatcher.state.publish_hash(&dispatcher.queue, hash).await {
            Ok(true) => {
                debug!("Published new hash from result");
                create_hash_timeline_event(
                    dispatcher,
                    &username,
                    &domain,
                    &hash_type,
                    &hash_value,
                    &source,
                )
                .await;
            }
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

    for share in parsed.shares {
        match dispatcher
            .state
            .publish_share(&dispatcher.queue, share)
            .await
        {
            Ok(true) => debug!("Published new share from result"),
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish share"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Timeline event helpers — create events with MITRE technique mapping
// ---------------------------------------------------------------------------

/// Create a timeline event when a credential is published.
///
/// MITRE techniques:
/// - T1078 (Valid Accounts) for admin creds, T1552 (Unsecured Credentials) otherwise
/// - T1558.003 (Kerberoasting) if source contains "kerberoast"
/// - T1558.004 (AS-REP Roasting) if source contains "asrep"/"as-rep"
/// - T1110 (Brute Force) if source contains "cracked"
async fn create_credential_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    source: &str,
    username: &str,
    domain: &str,
    is_admin: bool,
) {
    let mut techniques: Vec<String> = vec![if is_admin {
        "T1078".to_string()
    } else {
        "T1552".to_string()
    }];
    let source_lower = source.to_lowercase();
    if source_lower.contains("kerberoast") {
        techniques.push("T1558.003".to_string());
    }
    if source_lower.contains("asrep") || source_lower.contains("as-rep") {
        techniques.push("T1558.004".to_string());
    }
    if source_lower.contains("cracked") {
        techniques.push("T1110".to_string());
    }

    let event_id = format!(
        "evt-cred-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": source,
        "description": format!("Credential discovered: {domain}\\{username} via {source}"),
        "mitre_techniques": techniques,
    });

    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

/// Create a timeline event when a hash is published.
///
/// MITRE techniques:
/// - T1003 (OS Credential Dumping) always
/// - T1558.003 (Kerberoasting) for TGS-REP / kerberoast hashes
/// - T1558.004 (AS-REP Roasting) for AS-REP hashes
/// - T1003.006 (DCSync) for NTLM hashes from secretsdump/dcsync
async fn create_hash_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    username: &str,
    domain: &str,
    hash_type: &str,
    hash_value: &str,
    source: &str,
) {
    let mut techniques: Vec<String> = vec!["T1003".to_string()];
    let hash_value_lower = hash_value.to_lowercase();
    let hash_type_lower = hash_type.to_lowercase();
    let source_lower = source.to_lowercase();

    // Kerberoasting: TGS-REP hashes
    if hash_value_lower.contains("$krb5tgs$")
        || matches!(
            hash_type_lower.as_str(),
            "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
        )
        || source_lower.contains("kerberoast")
    {
        techniques.push("T1558.003".to_string());
    }

    // AS-REP Roasting
    if hash_value_lower.contains("$krb5asrep$")
        || matches!(hash_type_lower.as_str(), "asrep" | "as-rep" | "krb5asrep")
        || source_lower.contains("asrep")
        || source_lower.contains("as-rep")
    {
        techniques.push("T1558.004".to_string());
    }

    // DCSync / secretsdump for NTLM hashes
    if hash_type_lower == "ntlm"
        && (source_lower.contains("secretsdump") || source_lower.contains("dcsync"))
    {
        techniques.push("T1003.006".to_string());
    }

    let is_critical = matches!(username.to_lowercase().as_str(), "krbtgt" | "administrator");
    let description = if is_critical {
        format!("CRITICAL: Hash discovered: {domain}\\{username} ({hash_type})")
    } else {
        format!("Hash discovered: {domain}\\{username} ({hash_type})")
    };

    let event_id = format!(
        "evt-hash-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": source,
        "description": description,
        "mitre_techniques": techniques,
    });

    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
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
    pub shares: Vec<Share>,
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

    // Vulnerabilities (array)
    if let Some(vulns) = payload.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln_val in vulns {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }
    // Single vulnerability fallback (agents may report one vuln not wrapped in array)
    if result.vulnerabilities.is_empty() {
        if let Some(vuln_val) = payload.get("vulnerability") {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }

    // Shares
    if let Some(shares) = payload.get("shares").and_then(|v| v.as_array()) {
        for share_val in shares {
            if let Ok(share) = serde_json::from_value::<Share>(share_val.clone()) {
                result.shares.push(share);
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
            "credential" => match serde_json::from_value::<Credential>(data.clone()) {
                Ok(cred) => {
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
                    let _ = dispatcher.state.publish_user(&dispatcher.queue, user).await;
                }
            }
            other => {
                debug!(disc_type = other, "Unknown discovery type, ignoring");
            }
        }
    }

    // Notify credential access and delegation enumeration after processing discoveries
    dispatcher.credential_access_notify.notify_one();
    dispatcher.delegation_notify.notify_one();
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
    fn test_parse_shares() {
        let payload = json!({
            "shares": [
                {
                    "host": "192.168.58.10",
                    "name": "SYSVOL",
                    "permissions": "READ",
                    "comment": "Logon server share"
                },
                {
                    "host": "192.168.58.10",
                    "name": "ADMIN$",
                    "permissions": "READ,WRITE"
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.shares.len(), 2);
        assert_eq!(parsed.shares[0].name, "SYSVOL");
        assert_eq!(parsed.shares[0].permissions, "READ");
        assert_eq!(parsed.shares[1].name, "ADMIN$");
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
        assert!(parsed.shares.is_empty());
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
