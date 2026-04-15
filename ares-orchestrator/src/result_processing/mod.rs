//! Result processing and discovery polling.
//!
//! Handles completed task results: extracts discovered credentials, hashes,
//! hosts, and vulnerabilities from result payloads and publishes them to
//! shared state and Redis.
//!
//! Also polls the `ares:discoveries:{op_id}` LIST for real-time worker
//! discoveries that arrive outside the task result flow.

pub mod admin_checks;
pub mod discovery_polling;
pub mod parsing;
#[cfg(test)]
mod tests;
pub mod timeline;

// Re-exports consumed by callers outside this module
pub use discovery_polling::discovery_poller;

use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::output_extraction;
use crate::results::CompletedTask;
use crate::throttling::Throttler;

use self::admin_checks::{
    check_domain_admin_indicators, check_golden_ticket_completion,
    detect_and_upgrade_admin_credentials, extract_and_cache_domain_sid,
};
use self::discovery_polling::has_lockout_in_result;
use self::parsing::{parse_discoveries, resolve_parent_id};
use self::timeline::{create_credential_timeline_event, create_hash_timeline_event};

/// Kerberos/SMB errors that indicate a credential is locked out.
pub(crate) const LOCKOUT_PATTERNS: &[&str] =
    &["KDC_ERR_CLIENT_REVOKED", "STATUS_ACCOUNT_LOCKED_OUT"];

/// Process a completed task result: extract discoveries and update state.
pub async fn process_completed_task(
    completed: &CompletedTask,
    dispatcher: &Arc<Dispatcher>,
    throttler: &Throttler,
) {
    let task_id = &completed.task_id;
    let result = &completed.result;

    let cred_key = {
        let state = dispatcher.state.read().await;
        state
            .pending_tasks
            .get(task_id.as_str())
            .and_then(|t| t.params.get("credential_key"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

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
        // Don't return early — failed tasks (MaxSteps, Error) may still carry
        // parser-extracted discoveries from tool calls that ran before failure.
        // All discoveries now come from regex parsers, not LLM hallucination.
    }

    // Extract discoveries ONLY from the "discoveries" key — populated exclusively
    // by ares-tools parsers in submission.rs. The top-level payload is LLM-generated
    // and must never be fed into parse_discoveries() (hallucination risk).
    if let Some(ref payload) = result.result {
        if let Some(disc) = payload.get("discoveries") {
            if let Err(e) = extract_discoveries(disc, dispatcher).await {
                warn!(task_id = %task_id, err = %e, "Failed to extract parser discoveries");
            }
            check_domain_admin_indicators(disc, dispatcher).await;
        }
    }

    // Secondary pass: regex-based extraction from raw text in the result.
    // This catches discoveries that the per-tool parsers or LLM may have missed.
    if let Some(ref payload) = result.result {
        let default_domain = get_default_domain(dispatcher).await;
        extract_from_raw_text(payload, dispatcher, &default_domain).await;
    }

    // Domain SID extraction: scan raw text for S-1-5-21-... patterns (from secretsdump).
    // Caches the SID for golden ticket generation without needing lookupsid.
    if let Some(ref payload) = result.result {
        extract_and_cache_domain_sid(payload, dispatcher).await;
    }

    // S4U auto-chain: detect .ccache in output and dispatch secretsdump with ticket.
    // Mirrors Python's _auto_chain_s4u_lateral_movement — when a task produces a
    // Kerberos ticket (.ccache), chain a secretsdump using that ticket for
    // immediate credential extraction.
    if let Some(ref payload) = result.result {
        auto_chain_s4u_secretsdump(payload, dispatcher, &completed.task_id).await;
    }

    if result.success {
        if let Some(ref payload) = result.result {
            check_golden_ticket_completion(payload, &completed.task_id, dispatcher).await;
        }
    }

    if result.success {
        if let Some(vuln_id) = completed
            .task_id
            .starts_with("exploit_")
            .then(|| {
                result
                    .result
                    .as_ref()
                    .and_then(|r| r.get("vuln_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .flatten()
        {
            info!(vuln_id = %vuln_id, task_id = %task_id, "Marking vulnerability as exploited");
            if let Err(e) = dispatcher
                .state
                .mark_exploited(&dispatcher.queue, &vuln_id)
                .await
            {
                warn!(err = %e, vuln_id = %vuln_id, "Failed to mark vulnerability exploited");
            }
        }
    }

    if let Some(ref key) = cred_key {
        if has_lockout_in_result(result) {
            if let Some((username, domain)) = key.split_once('@') {
                warn!(
                    credential = %key,
                    task_id = %task_id,
                    "Credential quarantined for 5 min: lockout detected"
                );
                dispatcher
                    .state
                    .write()
                    .await
                    .quarantine_credential(username, domain);
            }
        }
    }

    dispatcher.credential_access_notify.notify_waiters();
    dispatcher.delegation_notify.notify_waiters();

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
    // Collect ONLY raw tool output fields — never LLM-generated summaries.
    let mut text_parts: Vec<&str> = Vec::new();
    for key in &["tool_output", "output"] {
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

    // Dispatch secretsdump with ticket (no password needed).
    // Must include username — secretsdump requires it even with -k -no-pass.
    // The S4U impersonates Administrator, so use that as default.
    let username = payload
        .get("impersonate")
        .and_then(|v| v.as_str())
        .unwrap_or("Administrator");
    let sd_payload = serde_json::json!({
        "technique": "secretsdump",
        "techniques": ["secretsdump"],
        "target_ip": resolved_ip,
        "username": username,
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
/// Collects text from raw tool output fields ("tool_output", "output", "tool_outputs")
/// and runs regex-based extraction on the combined text. This mirrors Python's
/// `_process_output_text()` — a safety net that catches discoveries the per-tool
/// parsers or LLM-reported structured data may have missed.
async fn extract_from_raw_text(
    payload: &Value,
    dispatcher: &Arc<Dispatcher>,
    default_domain: &str,
) {
    // Only parse tool_outputs — actual tool stdout collected by the agent loop.
    // The result payload's "summary", "result", and "output" fields are all
    // LLM-generated prose and MUST NOT be fed into regex extractors (they produce
    // false positives like "Password : only" from conversational text).
    //
    // Structured discoveries from tool-call parsers are already handled by
    // extract_discoveries() via the "discoveries" key — this pass is a secondary
    // safety net for raw tool stdout that parsers may have missed.
    let mut text_parts: Vec<&str> = Vec::new();

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

    // Process each tool output independently to prevent stateful parsers
    // (e.g. extract_plaintext_passwords's current_user tracker) from leaking
    // context across unrelated tool calls — a joined string caused false
    // credential attribution (e.g. john.smith:Summer2025 from stale context).
    let mut extracted = output_extraction::TextExtractions::default();
    for part in &text_parts {
        let partial = output_extraction::extract_from_output_text(part, default_domain);
        extracted.credentials.extend(partial.credentials);
        extracted.hashes.extend(partial.hashes);
        extracted.hosts.extend(partial.hosts);
        extracted.users.extend(partial.users);
        extracted.shares.extend(partial.shares);
    }

    if extracted.is_empty() {
        return;
    }

    let mut new_count = 0usize;

    for cred in extracted.credentials {
        let is_cracked = cred.source.starts_with("cracked:");
        let cracked_username = cred.username.clone();
        let cracked_domain = cred.domain.clone();
        let cracked_password = cred.password.clone();
        match dispatcher
            .state
            .publish_credential(&dispatcher.queue, cred)
            .await
        {
            Ok(true) => {
                new_count += 1;
                // When a cracked credential is published, update the corresponding
                // hash's cracked_password field in state and Redis.
                if is_cracked {
                    let _ = dispatcher
                        .state
                        .update_hash_cracked_password(
                            &dispatcher.queue,
                            &cracked_username,
                            &cracked_domain,
                            &cracked_password,
                        )
                        .await;
                }
            }
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

    // Users intentionally NOT published from raw text extraction.
    // The DOMAIN\user regex matches every wordlist entry in kerbrute/ASREProast
    // output (e.g. "[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set").
    // Only per-tool parsers (kerberos_enum, netexec_user_enum) produce verified
    // users gated by KDC response patterns.

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

    // Pwn3d! detection: scan raw text for admin indicators and upgrade credentials.
    // netexec output like "[+] DOMAIN\user:password (Pwn3d!)" means the credential
    // has local admin rights. Mark existing credentials as is_admin and trigger
    // immediate high-priority secretsdump.
    // Check each tool output independently (joining is safe here — Pwn3d! is a
    // standalone marker with no stateful context to leak).
    for part in &text_parts {
        if part.contains("Pwn3d!") {
            detect_and_upgrade_admin_credentials(part, dispatcher).await;
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
    let mut parsed = parse_discoveries(payload);

    // Resolve credential lineage (parent_id / attack_step) before publishing.
    // Read lock is released before any publish calls (which take write locks).
    {
        let state = dispatcher.state.read().await;
        for cred in &mut parsed.credentials {
            if cred.parent_id.is_none() {
                let (pid, step) = resolve_parent_id(
                    &state.credentials,
                    &state.hashes,
                    &cred.source,
                    &cred.username,
                    &cred.domain,
                    None,
                    None,
                );
                cred.parent_id = pid;
                cred.attack_step = step;
            }
        }
        for hash in &mut parsed.hashes {
            if hash.parent_id.is_none() {
                let (pid, step) = resolve_parent_id(
                    &state.credentials,
                    &state.hashes,
                    &hash.source,
                    &hash.username,
                    &hash.domain,
                    None,
                    None,
                );
                hash.parent_id = pid;
                hash.attack_step = step;
            }
        }
    }

    for cred in parsed.credentials {
        // Capture fields before move for timeline event
        let source = cred.source.clone();
        let username = cred.username.clone();
        let domain = cred.domain.clone();
        let password = cred.password.clone();
        let is_admin = cred.is_admin;
        let is_cracked = source.starts_with("cracked");
        match dispatcher
            .state
            .publish_credential(&dispatcher.queue, cred)
            .await
        {
            Ok(true) => {
                debug!("Published new credential from result");
                create_credential_timeline_event(dispatcher, &source, &username, &domain, is_admin)
                    .await;
                // When a cracked credential is published, update the corresponding
                // hash's cracked_password field in state and Redis.
                if is_cracked {
                    let _ = dispatcher
                        .state
                        .update_hash_cracked_password(
                            &dispatcher.queue,
                            &username,
                            &domain,
                            &password,
                        )
                        .await;
                }
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

    // Extract trusted_domains from parser output
    if let Some(trusts) = payload.get("trusted_domains").and_then(|v| v.as_array()) {
        for trust_val in trusts {
            if let Ok(trust) =
                serde_json::from_value::<ares_core::models::TrustInfo>(trust_val.clone())
            {
                match dispatcher
                    .state
                    .publish_trust_info(&dispatcher.queue, trust)
                    .await
                {
                    Ok(true) => info!("Published new trust relationship from result"),
                    Ok(false) => {}
                    Err(e) => warn!(err = %e, "Failed to publish trust info"),
                }
            }
        }
    }

    Ok(())
}
