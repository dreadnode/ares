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

/// Kerberos/SMB errors that indicate a credential is locked out.
const LOCKOUT_PATTERNS: &[&str] = &["KDC_ERR_CLIENT_REVOKED", "STATUS_ACCOUNT_LOCKED_OUT"];

/// Process a completed task result: extract discoveries and update state.
pub async fn process_completed_task(
    completed: &CompletedTask,
    dispatcher: &Arc<Dispatcher>,
    throttler: &Throttler,
) {
    let task_id = &completed.task_id;
    let result = &completed.result;

    // Grab credential key from pending task BEFORE complete_task removes it.
    let cred_key = {
        let state = dispatcher.state.read().await;
        state
            .pending_tasks
            .get(task_id.as_str())
            .and_then(|t| t.params.get("credential_key"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

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

    // Golden ticket detection: when a golden ticket task completes successfully,
    // set the has_golden_ticket flag. Matches Python's announce_golden_ticket().
    if result.success {
        if let Some(ref payload) = result.result {
            check_golden_ticket_completion(payload, &completed.task_id, dispatcher).await;
        }
    }

    // Mark exploited: if this was a successful exploit task with a vuln_id, mark it
    // so the exploitation workflow stops re-dispatching it.
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

    // Credential lockout quarantine: if the task result contains lockout
    // indicators, quarantine the credential so automation stops scheduling it.
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

    // Notify all listeners (credential access, delegation enum, S4U automation)
    // to wake up for potential new creds. Use notify_waiters to wake ALL listeners.
    dispatcher.credential_access_notify.notify_waiters();
    dispatcher.delegation_notify.notify_waiters();

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
    // credential attribution (e.g. jon.snow:Heartsbane from stale context).
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

/// Detect Pwn3d! in raw output and upgrade matching credentials to is_admin=true.
/// Triggers immediate high-priority secretsdump against all DCs for admin credentials.
async fn detect_and_upgrade_admin_credentials(text: &str, dispatcher: &Arc<Dispatcher>) {
    // Pattern: [+] DOMAIN\user:password (Pwn3d!) or DOMAIN\user (Pwn3d!)
    for line in text.lines() {
        if !line.contains("Pwn3d!") || !line.contains("[+]") {
            continue;
        }

        // Extract domain\user from the line
        if let Some(after_plus) = line.split("[+]").nth(1) {
            let after_plus = after_plus.trim();
            if let Some(backslash) = after_plus.find('\\') {
                let domain_part = after_plus[..backslash].trim();
                let rest = &after_plus[backslash + 1..];
                let username = if let Some(colon) = rest.find(':') {
                    &rest[..colon]
                } else {
                    rest.split_whitespace().next().unwrap_or("")
                };
                let username = username.trim();
                let domain = domain_part.to_lowercase();

                if username.is_empty() || domain.is_empty() {
                    continue;
                }

                info!(
                    username = %username,
                    domain = %domain,
                    "Pwn3d! detected — upgrading credential to admin"
                );

                // Upgrade the credential in state
                let upgraded = {
                    let mut state = dispatcher.state.write().await;
                    let mut found = false;
                    for cred in state.credentials.iter_mut() {
                        if cred.username.to_lowercase() == username.to_lowercase()
                            && cred.domain.to_lowercase() == domain
                            && !cred.is_admin
                        {
                            cred.is_admin = true;
                            found = true;
                        }
                    }
                    found
                };

                if upgraded {
                    // Extract the target IP from the Pwn3d! line. NetExec format:
                    // SMB  10.1.2.51  445  CASTELBLACK  [+] NORTH\user:pass (Pwn3d!)
                    let pwned_ip = line
                        .split_whitespace()
                        .find(|w| {
                            w.split('.').count() == 4
                                && w.split('.').all(|o| o.parse::<u8>().is_ok())
                        })
                        .map(|s| s.to_string());

                    info!(
                        username = %username,
                        domain = %domain,
                        pwned_host = ?pwned_ip,
                        "Credential upgraded to admin — dispatching priority secretsdump"
                    );

                    // Dispatch secretsdump against all DCs AND the Pwn3d host.
                    // The Pwn3d host may not be a DC but can yield cached domain
                    // creds, service account hashes, and LSA secrets.
                    let work: Vec<(String, ares_core::models::Credential)> = {
                        let state = dispatcher.state.read().await;
                        let dc_ips: Vec<String> =
                            state.domain_controllers.values().cloned().collect();
                        let mut targets: Vec<String> = dc_ips;
                        if let Some(ref ip) = pwned_ip {
                            if !targets.contains(ip) {
                                targets.push(ip.clone());
                            }
                        }
                        state
                            .credentials
                            .iter()
                            .filter(|c| {
                                c.username.to_lowercase() == username.to_lowercase()
                                    && c.domain.to_lowercase() == domain
                                    && c.is_admin
                            })
                            .flat_map(|cred| {
                                targets
                                    .iter()
                                    .map(|ip| (ip.clone(), cred.clone()))
                                    .collect::<Vec<_>>()
                            })
                            .collect()
                    };

                    for (target_ip, cred) in work {
                        match dispatcher.request_secretsdump(&target_ip, &cred, 1).await {
                            Ok(Some(task_id)) => {
                                info!(
                                    task_id = %task_id,
                                    target = %target_ip,
                                    username = %username,
                                    "Admin Pwn3d! secretsdump dispatched (priority 1)"
                                );
                            }
                            Ok(None) => {}
                            Err(e) => warn!(err = %e, "Failed to dispatch Pwn3d! secretsdump"),
                        }
                    }
                }
            }
        }
    }
}

/// Extract domain SID from raw text (secretsdump output) and cache it.
///
/// Secretsdump prints `[*] Domain SID is: S-1-5-21-...` early in its output.
/// Caching this allows golden ticket generation without needing lookupsid
/// (which often fails with STATUS_NETLOGON_NOT_STARTED in lab environments).
async fn extract_and_cache_domain_sid(payload: &Value, dispatcher: &Arc<Dispatcher>) {
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

    if text_parts.is_empty() {
        return;
    }

    let combined = text_parts.join("\n");
    if let Some(sid) = ares_core::parsing::extract_domain_sid(&combined) {
        // Determine which domain this SID belongs to.
        // Use the domain from the payload or fall back to the first known domain.
        let domain = payload
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|d| d.to_lowercase())
            .filter(|d| !d.is_empty());

        let domain = match domain {
            Some(d) => d,
            None => {
                let state = dispatcher.state.read().await;
                match state.domains.first() {
                    Some(d) => d.to_lowercase(),
                    None => return,
                }
            }
        };

        // Check if we already have this SID cached
        let already_cached = {
            let state = dispatcher.state.read().await;
            state
                .domain_sids
                .get(&domain)
                .map(|s| s == &sid)
                .unwrap_or(false)
        };

        if !already_cached {
            // Write to Redis
            let op_id = {
                let state = dispatcher.state.read().await;
                state.operation_id.clone()
            };
            let reader = ares_core::state::RedisStateReader::new(op_id);
            let mut conn = dispatcher.queue.connection();
            if let Err(e) = reader.set_domain_sid(&mut conn, &domain, &sid).await {
                warn!(err = %e, domain = %domain, "Failed to persist domain SID to Redis");
            } else {
                info!(domain = %domain, sid = %sid, "Domain SID cached from task output");
                // Update in-memory state
                dispatcher
                    .state
                    .write()
                    .await
                    .domain_sids
                    .insert(domain.clone(), sid);
            }
        }

        // Also extract RID-500 account name from lookupsid output (if present).
        if let Some(admin_name) = ares_core::parsing::extract_rid500_name(&combined) {
            let already_known = {
                let state = dispatcher.state.read().await;
                state.admin_names.contains_key(&domain)
            };
            if !already_known {
                let op_id = {
                    let state = dispatcher.state.read().await;
                    state.operation_id.clone()
                };
                let reader = ares_core::state::RedisStateReader::new(op_id);
                let mut conn = dispatcher.queue.connection();
                if let Err(e) = reader.set_admin_name(&mut conn, &domain, &admin_name).await {
                    warn!(err = %e, domain = %domain, "Failed to persist admin name to Redis");
                } else {
                    info!(domain = %domain, name = %admin_name, "RID-500 account name cached from task output");
                    dispatcher
                        .state
                        .write()
                        .await
                        .admin_names
                        .insert(domain, admin_name);
                }
            }
        }
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

/// Resolve the parent credential or hash for a newly discovered item.
///
/// Establishes credential lineage by finding which existing credential/hash
/// was used as input to discover this new item. Returns `(parent_id, attack_step)`.
///
/// Resolution strategy:
/// 1. **Cracked passwords**: parent is the hash with matching username+domain
/// 2. **Input credential context** (from tool arguments): parent is the credential/hash
///    that authenticated the tool invocation
/// 3. **No context**: returns `(None, 0)`
pub(crate) fn resolve_parent_id(
    credentials: &[Credential],
    hashes: &[Hash],
    source: &str,
    username: &str,
    domain: &str,
    input_username: Option<&str>,
    input_domain: Option<&str>,
) -> (Option<String>, i32) {
    // Case 1: Cracked password → parent is the original hash
    if source.starts_with("cracked") {
        if let Some(h) = hashes.iter().rev().find(|h| {
            h.username.eq_ignore_ascii_case(username)
                && (domain.is_empty() || h.domain.eq_ignore_ascii_case(domain))
        }) {
            return (Some(h.id.clone()), h.attack_step + 1);
        }
    }

    // Case 2: Explicit input credential context (from tool arguments)
    if let Some(in_user) = input_username.filter(|u| !u.is_empty()) {
        let in_domain = input_domain.unwrap_or("");

        // Don't self-reference (same user discovered by itself)
        let is_same = in_user.eq_ignore_ascii_case(username)
            && (in_domain.eq_ignore_ascii_case(domain)
                || in_domain.is_empty()
                || domain.is_empty());

        if !is_same {
            // Try credentials first (password auth)
            if let Some(c) = credentials.iter().rev().find(|c| {
                c.username.eq_ignore_ascii_case(in_user)
                    && (in_domain.is_empty()
                        || c.domain.is_empty()
                        || c.domain.eq_ignore_ascii_case(in_domain))
            }) {
                return (Some(c.id.clone()), c.attack_step + 1);
            }
            // Then hashes (pass-the-hash auth)
            if let Some(h) = hashes.iter().rev().find(|h| {
                h.username.eq_ignore_ascii_case(in_user)
                    && (in_domain.is_empty()
                        || h.domain.is_empty()
                        || h.domain.eq_ignore_ascii_case(in_domain))
            }) {
                return (Some(h.id.clone()), h.attack_step + 1);
            }
        }
    }

    (None, 0)
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

    // Users — defense-in-depth: only accept entries with a parser-verified source.
    // The primary gate is in submission.rs (strips LLM-provided discovered_users
    // before merge), but this filter catches any remaining path where an LLM
    // could inject a user with a spoofed source tag.
    // output_extraction is intentionally excluded — its DOMAIN\user regex
    // matches every wordlist entry in kerbrute/ASREProast output, not just
    // KDC-confirmed users.
    const TRUSTED_USER_SOURCES: &[&str] = &["kerberos_enum", "netexec_user_enum"];
    if let Some(users) = payload.get("discovered_users").and_then(|v| v.as_array()) {
        for user_val in users {
            if let Ok(user) = serde_json::from_value::<User>(user_val.clone()) {
                if TRUSTED_USER_SOURCES.contains(&user.source.as_str()) {
                    result.users.push(user);
                }
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

/// Detect golden ticket completion from task output.
///
/// impacket-ticketer outputs "Saving ticket in Administrator.ccache" on success.
/// When detected in a golden_ticket task, set `has_golden_ticket = true`.
/// Matches Python's `announce_golden_ticket()`.
async fn check_golden_ticket_completion(
    payload: &Value,
    task_id: &str,
    dispatcher: &Arc<Dispatcher>,
) {
    // Only check tasks that look like golden ticket tasks
    if !task_id.contains("exploit") && !task_id.contains("golden") {
        return;
    }

    // Already set?
    {
        let state = dispatcher.state.read().await;
        if state.has_golden_ticket {
            return;
        }
    }

    // Scan raw tool outputs for ticketer success indicators
    let mut found_ticket = false;
    let mut domain = String::new();

    // Check tool_outputs array
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            let text = item
                .as_str()
                .or_else(|| item.get("output").and_then(|v| v.as_str()))
                .unwrap_or("");
            if text.contains("Saving ticket in") && text.contains(".ccache") {
                found_ticket = true;
                break;
            }
        }
    }

    // Check single output fields
    if !found_ticket {
        for key in &["tool_output", "output", "summary"] {
            if let Some(text) = payload.get(*key).and_then(|v| v.as_str()) {
                if text.contains("Saving ticket in") && text.contains(".ccache") {
                    found_ticket = true;
                    break;
                }
            }
        }
    }

    // Also check if the payload explicitly marks golden ticket
    if !found_ticket && payload.get("has_golden_ticket").and_then(|v| v.as_bool()) == Some(true) {
        found_ticket = true;
    }

    if !found_ticket {
        return;
    }

    // Extract domain from payload
    if let Some(d) = payload.get("domain").and_then(|v| v.as_str()) {
        domain = d.to_string();
    }
    if domain.is_empty() {
        let state = dispatcher.state.read().await;
        domain = state.domains.first().cloned().unwrap_or_default();
    }

    if let Err(e) = dispatcher
        .state
        .set_golden_ticket(&dispatcher.queue, &domain)
        .await
    {
        warn!(err = %e, "Failed to set golden ticket flag");
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

        // Extract input credential context for lineage tracking
        let input_username = discovery.get("input_username").and_then(|v| v.as_str());
        let input_domain = discovery.get("input_domain").and_then(|v| v.as_str());

        match disc_type {
            "credential" => match serde_json::from_value::<Credential>(data.clone()) {
                Ok(mut cred) => {
                    // Resolve parent lineage from input credential context
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
                    // Only publish users with a parser-verified source
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

    // Notify all listeners after processing discoveries
    dispatcher.credential_access_notify.notify_waiters();
    dispatcher.delegation_notify.notify_waiters();
    let _ = dispatcher.notify_state_update().await;

    Ok(())
}

/// Check if a task result contains lockout error indicators.
///
/// Scans the error text, tool_outputs array, and summary/output fields
/// for patterns indicating the credential was locked out or revoked.
fn has_lockout_in_result(result: &crate::task_queue::TaskResult) -> bool {
    // Check error text
    if let Some(ref err) = result.error {
        if LOCKOUT_PATTERNS.iter().any(|p| err.contains(p)) {
            return true;
        }
    }

    // Check result payload
    if let Some(ref payload) = result.result {
        // Check tool_outputs array (raw tool stdout/stderr)
        if let Some(outputs) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
            for output in outputs {
                if let Some(text) = output.as_str() {
                    if LOCKOUT_PATTERNS.iter().any(|p| text.contains(p)) {
                        return true;
                    }
                }
            }
        }

        // Check summary/output text
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
    fn test_parse_users_with_trusted_source() {
        let payload = json!({
            "discovered_users": [
                {
                    "username": "jdoe",
                    "domain": "contoso.local",
                    "source": "kerberos_enum",
                    "is_admin": false,
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.users.len(), 1);
        assert_eq!(parsed.users[0].username, "jdoe");
    }

    #[test]
    fn test_parse_users_rejects_untrusted_source() {
        // LLM-fabricated users (no source or unknown source) must be rejected
        let payload = json!({
            "discovered_users": [
                {
                    "username": "fake_admin",
                    "domain": "contoso.local",
                    "is_admin": false,
                },
                {
                    "username": "also_fake",
                    "domain": "contoso.local",
                    "source": "llm_hallucination",
                    "is_admin": false,
                }
            ]
        });
        let parsed = parse_discoveries(&payload);
        assert_eq!(parsed.users.len(), 0);
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
