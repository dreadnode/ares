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
pub mod impacket_recovery;
pub mod parsing;
#[cfg(test)]
mod tests;
pub mod timeline;

// Re-exports consumed by callers outside this module
pub use discovery_polling::discovery_poller;

use std::sync::Arc;

use anyhow::Result;
use redis::aio::ConnectionLike;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::output_extraction;
use crate::orchestrator::results::CompletedTask;
use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;
use crate::orchestrator::throttling::Throttler;

use self::admin_checks::{
    check_domain_admin_indicators, check_golden_ticket_completion,
    detect_and_upgrade_admin_credentials, extract_and_cache_domain_sid,
};
use self::discovery_polling::has_lockout_in_result;
use self::parsing::{parse_discoveries, resolve_parent_id};
use self::timeline::{
    create_credential_timeline_event, create_exploitation_timeline_event,
    create_hash_timeline_event, create_lateral_movement_timeline_event,
};

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

    // Extract task-level metadata from pending_tasks before complete_task removes it.
    // The full params snapshot is captured so the Impacket failure classifier
    // (called on the failure path below) can rebuild a corrected re-dispatch
    // without re-reading the already-cleared pending_tasks entry.
    let (cred_key, task_domain, task_target_ip, task_username, task_params_snapshot) = {
        let state = dispatcher.state.read().await;
        let task = state.pending_tasks.get(task_id.as_str());
        let ck = task
            .and_then(|t| t.params.get("credential_key"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let td = task
            .and_then(|t| t.params.get("domain"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let tip = task
            .and_then(|t| t.params.get("target_ip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let tu = task
            .and_then(|t| t.params.get("username"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let params = task.map(|t| t.params.clone()).unwrap_or_default();
        (ck, td, tip, tu, params)
    };

    // Pre-compute the "DOMAIN\\username" label for share authentication
    // tagging — captured from this task's auth params so the renderer can
    // show which credential opened READ/WRITE on each share.
    let share_auth_label: Option<String> = match (&task_domain, &task_username) {
        (Some(d), Some(u)) if !d.is_empty() && !u.is_empty() => Some(format!("{d}\\{u}")),
        (None, Some(u)) if !u.is_empty() => Some(u.clone()),
        _ => None,
    };

    {
        let core_result = ares_core::models::TaskResult {
            task_id: task_id.clone(),
            success: result.success,
            result: result.result.clone(),
            error: result.error.clone(),
            worker_pod: result.worker_pod.clone(),
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

        // Impacket failure classifier: re-dispatch credential_access tasks
        // that failed because of one of the known Impacket constraints
        // (CLAUDE.md). Gated on credential-is-known-good so genuinely bad
        // passwords don't trigger retries. One-shot per (target, cred, class).
        if task_id.starts_with("credential_access_") {
            impacket_recovery::attempt_recovery(
                dispatcher,
                task_id,
                &task_params_snapshot,
                &result.result,
                result.error.as_deref(),
            )
            .await;
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
            if let Err(e) = extract_discoveries(
                disc,
                dispatcher,
                task_target_ip.as_deref(),
                share_auth_label.as_deref(),
            )
            .await
            {
                warn!(task_id = %task_id, err = %e, "Failed to extract parser discoveries");
            }
            check_domain_admin_indicators(disc, dispatcher).await;
        }
    }

    // Secondary pass: regex-based extraction from raw text in the result.
    // This catches discoveries that the per-tool parsers or LLM may have missed.
    if let Some(ref payload) = result.result {
        let default_domain = if let Some(ref td) = task_domain {
            td.clone()
        } else {
            // Resolve domain from the task's target IP (e.g. secretsdump against a
            // specific DC). Falls back to state.domains.first() only as last resort.
            resolve_domain_from_ip(dispatcher, task_target_ip.as_deref()).await
        };
        extract_from_raw_text(
            payload,
            dispatcher,
            &default_domain,
            task_target_ip.as_deref(),
            share_auth_label.as_deref(),
        )
        .await;
    }

    // Mark host as owned when a credential_access task succeeds AND parser
    // evidence proves credentials/hashes were extracted. The LLM's
    // `task_complete(success=true)` is not sufficient on its own — without
    // parser-grounded credential evidence we treat the claim as unverified
    // and skip the state write.
    if result.success {
        if let Some(ref ip) = task_target_ip {
            if task_id.starts_with("credential_access_")
                && result_has_credential_evidence(&result.result)
            {
                let _ = dispatcher
                    .state
                    .mark_host_owned(&dispatcher.queue, ip)
                    .await;
            } else if task_id.starts_with("credential_access_") {
                debug!(
                    task_id = %task_id,
                    ip = %ip,
                    "Skipping mark_host_owned: no parser-extracted credential/hash evidence"
                );
            }
        }
    }

    // Domain SID extraction: scan raw text for S-1-5-21-... patterns (from secretsdump).
    // Caches the SID for golden ticket generation without needing lookupsid.
    if let Some(ref payload) = result.result {
        extract_and_cache_domain_sid(payload, task_domain.as_deref(), dispatcher).await;
    }

    // S4U auto-chain: when a task produces a Kerberos ticket (.ccache), chain a
    // secretsdump using that ticket for immediate credential extraction.
    if let Some(ref payload) = result.result {
        auto_chain_s4u_secretsdump(
            payload,
            dispatcher,
            &completed.task_id,
            &task_params_snapshot,
            task_domain.as_deref(),
            task_target_ip.as_deref(),
        )
        .await;
    }

    if result.success {
        if let Some(ref payload) = result.result {
            check_golden_ticket_completion(
                payload,
                &completed.task_id,
                task_domain.as_deref(),
                dispatcher,
            )
            .await;
        }
    }

    // Handle exploit task outcomes — create timeline events for both success and failure
    if completed.task_id.starts_with("exploit_") {
        if let Some(vuln_id) = result
            .result
            .as_ref()
            .and_then(|r| r.get("vuln_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            // Guard: LLM may call task_complete (success=true) with a result
            // that actually describes a failure. Don't mark as exploited if the
            // result summary contains clear failure indicators OR if no parser
            // evidence (discoveries from real tool stdout) corroborates the
            // exploit. The text heuristic catches obvious lies; the parser
            // check catches silent fabrication.
            // Default evidence gate (parser-extracted discoveries). For
            // ticket-only exploit chains (constrained/unconstrained
            // delegation, RBCD) `getST` writes a `.ccache` to disk and
            // emits a "Saving ticket in …" line — neither produces a
            // credential/hash/host the regex parsers can attach to
            // `discoveries`. Treat the ticket save as the success signal
            // for those vuln types so the scoreboard credits the
            // primitive on getST exit-0.
            let has_ticket_evidence =
                is_ticket_grant_vuln(&vuln_id) && result_has_ccache_evidence(&result.result);
            // Stall-tolerance: when the LLM ends its turn without calling
            // task_complete (LoopEndReason::MaxSteps or budget exhaustion),
            // submission.rs stamps `success=false` with an error string
            // identifying the stall. The exploit may still have landed —
            // certipy_shadow, secretsdump, getST routinely produce parser-
            // grounded credentials/hashes/tickets before the LLM stalls on
            // the wrap-up call. Without this carve-out, every stalled
            // exploit appears as "failed" even when the primitive worked.
            // The carve-out is narrow: only stalls (recognised by the
            // canonical error strings) bypass the `success` check, and the
            // parser-evidence gate still has to pass.
            let stalled_with_evidence = !result.success
                && error_indicates_stall(result.error.as_deref())
                && !result_text_indicates_failure(&result.result)
                && (result_has_parser_evidence(&result.result) || has_ticket_evidence);
            let actually_succeeded = (result.success
                && !result_text_indicates_failure(&result.result)
                && (result_has_parser_evidence(&result.result) || has_ticket_evidence))
                || stalled_with_evidence;

            if actually_succeeded {
                info!(vuln_id = %vuln_id, task_id = %task_id, "Marking vulnerability as exploited");
                if let Err(e) = dispatcher
                    .state
                    .mark_exploited(&dispatcher.queue, &vuln_id)
                    .await
                {
                    warn!(err = %e, vuln_id = %vuln_id, "Failed to mark vulnerability exploited");
                }
                create_exploitation_timeline_event(dispatcher, &vuln_id, task_id).await;
            } else {
                // Record failed exploit attempts as timeline events so they appear
                // in reports (e.g. noPac patched, PrintNightmare patched, Certifried
                // tool missing). This closes the "dispatched but no report evidence" gap.
                let err_msg = result.error.as_deref().unwrap_or("unknown error");
                let event_id = format!(
                    "evt-exploit-fail-{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..8]
                );
                let event = serde_json::json!({
                    "id": event_id,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "exploit_failed",
                    "description": format!("Exploit attempted but failed: {vuln_id} — {err_msg}"),
                    "mitre_techniques": ["T1210"],
                });
                let _ = dispatcher
                    .state
                    .persist_timeline_event(&dispatcher.queue, &event, &["T1210".to_string()])
                    .await;
                info!(
                    vuln_id = %vuln_id,
                    task_id = %task_id,
                    err = err_msg,
                    "Exploit failure recorded as timeline event"
                );
                // Increment per-vuln failure counter; the exploitation workflow
                // skips the vuln once it crosses MAX_EXPLOIT_FAILURES, so a
                // stuck vuln (e.g. mssql_access with 0 creds) cannot loop
                // forever.
                let count = dispatcher.state.record_exploit_failure(&vuln_id).await;
                if count >= crate::orchestrator::state::MAX_EXPLOIT_FAILURES {
                    warn!(
                        vuln_id = %vuln_id,
                        failure_count = count,
                        "Vuln abandoned — exceeded max exploit failures"
                    );
                }
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
                    .quarantine_principal(username, domain);
            }
        }
    }

    // Per-user lockout quarantine for enumeration paths (no cred_key set).
    // username_as_password and password_spray test multiple users in one
    // task — when a specific user trips STATUS_ACCOUNT_LOCKED_OUT we
    // remember that principal so future enum tasks can skip it.
    if has_lockout_in_result(result) {
        let locked = extract_locked_usernames_from_result(&result.result);
        if !locked.is_empty() {
            let resolved_domain = if let Some(ref td) = task_domain {
                td.clone()
            } else {
                resolve_domain_from_ip(dispatcher, task_target_ip.as_deref()).await
            };
            if !resolved_domain.is_empty() {
                let mut state = dispatcher.state.write().await;
                for (user, dom_hint) in &locked {
                    let dom = dom_hint.as_deref().unwrap_or(&resolved_domain);
                    warn!(
                        user = %user,
                        domain = %dom,
                        task_id = %task_id,
                        "User quarantined for 5 min: enumeration lockout detected"
                    );
                    state.quarantine_principal(user, dom);
                }
            }
        }
    }

    // SeImpersonate primitive detection. When a task's output captures a
    // `whoami /priv` (or equivalent) showing SeImpersonatePrivilege held
    // (and enabled), we have everything needed to escalate to SYSTEM via
    // PrintSpoofer / GodPotato. Surface this as `seimpersonate_<host>` and
    // mark exploited so the scoreboard credits the primitive. The follow-on
    // potato dispatch is left for the existing privesc agent (already wired
    // with godpotato / printspoofer tools) to consume opportunistically.
    if result_has_seimpersonate_signal(&result.result) {
        let host_label =
            derive_seimpersonate_host_label(dispatcher, task_target_ip.as_deref()).await;
        let vuln_id = format!("seimpersonate_{}", host_label);
        let mut details = std::collections::HashMap::new();
        details.insert("host".into(), Value::String(host_label.clone()));
        if let Some(ref ip) = task_target_ip {
            details.insert("target_ip".into(), Value::String(ip.clone()));
        }
        details.insert(
            "note".into(),
            Value::String(
                "SeImpersonatePrivilege observed enabled — \
                 escalation path via PrintSpoofer / GodPotato to SYSTEM."
                    .into(),
            ),
        );
        let vuln = ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.clone(),
            vuln_type: "seimpersonate".to_string(),
            target: task_target_ip.clone().unwrap_or_else(|| host_label.clone()),
            discovered_by: "result_processing".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: "privesc".to_string(),
            priority: 2,
        };
        let _ = dispatcher
            .state
            .publish_vulnerability(&dispatcher.queue, vuln)
            .await;
        if let Err(e) = dispatcher
            .state
            .mark_exploited(&dispatcher.queue, &vuln_id)
            .await
        {
            warn!(
                err = %e,
                vuln_id = %vuln_id,
                "Failed to mark seimpersonate primitive exploited"
            );
        } else {
            info!(
                vuln_id = %vuln_id,
                host = %host_label,
                task_id = %task_id,
                "SeImpersonate primitive observed in task output — exploit token emitted"
            );
        }
    }

    // NTLM Relay tokenization. The auto_ntlm_relay chain dispatches relay
    // attacks (SMB→LDAP for shadow creds / RBCD, or SMB→ADCS for ESC8) as
    // coercion-type tasks. When a relay succeeds the parser surfaces real
    // credentials/hashes/tickets in `discoveries`, but no `ntlm_relay_*`
    // token ever lands in `:exploited` because (a) the task_id starts with
    // `coercion_`, not `exploit_`, and (b) the payload has no `vuln_id`.
    // Recognise the relay technique here and emit a synthetic token so the
    // scoreboard credits the primitive.
    let task_technique = task_technique_from_pending(dispatcher, task_id).await;
    if let Some(ref tech) = task_technique {
        if (tech == "ntlm_relay_ldap" || tech == "ntlm_relay_adcs")
            && result.success
            && result_has_credential_evidence(&result.result)
        {
            let relay_target = task_relay_target_from_pending(dispatcher, task_id).await;
            let target_label = relay_target
                .clone()
                .or_else(|| task_target_ip.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let vuln_id = format!("ntlm_relay_{}", target_label.replace(['.', ':'], "_"));
            let mut details = std::collections::HashMap::new();
            details.insert("relay_target".into(), Value::String(target_label.clone()));
            details.insert("relay_type".into(), Value::String(tech.clone()));
            details.insert(
                "note".into(),
                Value::String(
                    "NTLM relay succeeded — credentials/hashes captured from \
                     coerced authentication. Scoreboard primitive credited."
                        .into(),
                ),
            );
            let vuln = ares_core::models::VulnerabilityInfo {
                vuln_id: vuln_id.clone(),
                vuln_type: "ntlm_relay".to_string(),
                target: target_label.clone(),
                discovered_by: "result_processing".to_string(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: "coercion".to_string(),
                priority: 1,
            };
            let _ = dispatcher
                .state
                .publish_vulnerability(&dispatcher.queue, vuln)
                .await;
            if let Err(e) = dispatcher
                .state
                .mark_exploited(&dispatcher.queue, &vuln_id)
                .await
            {
                warn!(err = %e, vuln_id = %vuln_id, "Failed to mark ntlm_relay exploited");
            } else {
                info!(
                    vuln_id = %vuln_id,
                    relay_target = %target_label,
                    relay_type = %tech,
                    task_id = %task_id,
                    "NTLM relay succeeded — exploit token emitted"
                );
            }
        }

        // NTLMv1 downgrade tokenization. The `ntlmv1_downgrade_check` task is
        // a read-only LDAP/registry probe — when its output confirms the DC
        // permits NTLMv1 (LmCompatibilityLevel ≤ 2 / "NTLMv1 allowed"),
        // discovery IS the achievement (the lab is misconfigured and the
        // hash is trivially crackable). Tokenize on positive observation.
        if tech == "ntlmv1_downgrade_check"
            && result.success
            && result_has_ntlmv1_signal(&result.result)
        {
            let dc_label = task_target_ip
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let vuln_id = format!("ntlmv1_{}", dc_label.replace(['.', ':'], "_"));
            let mut details = std::collections::HashMap::new();
            details.insert("target_ip".into(), Value::String(dc_label.clone()));
            if let Some(ref td) = task_domain {
                details.insert("domain".into(), Value::String(td.clone()));
            }
            details.insert(
                "note".into(),
                Value::String(
                    "DC permits NTLMv1 authentication — captured challenge \
                     responses are crackable offline."
                        .into(),
                ),
            );
            let vuln = ares_core::models::VulnerabilityInfo {
                vuln_id: vuln_id.clone(),
                vuln_type: "ntlmv1_downgrade".to_string(),
                target: dc_label.clone(),
                discovered_by: "result_processing".to_string(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: "credential_access".to_string(),
                priority: 3,
            };
            let _ = dispatcher
                .state
                .publish_vulnerability(&dispatcher.queue, vuln)
                .await;
            if let Err(e) = dispatcher
                .state
                .mark_exploited(&dispatcher.queue, &vuln_id)
                .await
            {
                warn!(err = %e, vuln_id = %vuln_id, "Failed to mark ntlmv1 exploited");
            } else {
                info!(
                    vuln_id = %vuln_id,
                    dc = %dc_label,
                    task_id = %task_id,
                    "NTLMv1 downgrade confirmed — exploit token emitted"
                );
            }
        }
    }

    dispatcher.credential_access_notify.notify_waiters();
    dispatcher.delegation_notify.notify_waiters();

    let _ = dispatcher.notify_state_update().await;
}

/// Look up the `technique` field on a pending task's params. The orchestrator
/// removes the task from `pending_tasks` once `complete_task` finishes, so
/// callers must read this before that happens — but in `process_completed_task`
/// we deliberately call this after the state.complete_task block, when the
/// task is gone; therefore the helper falls back to the task's result payload,
/// which automation modules also stamp with `technique` for downstream
/// recognition.
async fn task_technique_from_pending(
    dispatcher: &Arc<Dispatcher>,
    task_id: &str,
) -> Option<String> {
    let state = dispatcher.state.read().await;
    state
        .pending_tasks
        .get(task_id)
        .and_then(|t| t.params.get("technique"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Look up the `relay_target` field on a pending task's params. Returns
/// `None` when the task isn't a relay task or when the field is missing.
async fn task_relay_target_from_pending(
    dispatcher: &Arc<Dispatcher>,
    task_id: &str,
) -> Option<String> {
    let state = dispatcher.state.read().await;
    state
        .pending_tasks
        .get(task_id)
        .and_then(|t| t.params.get("relay_target"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// True when any text payload on the result indicates the DC permits NTLMv1
/// authentication. Recognises both the explicit "NTLMv1 allowed" / "NTLM
/// downgrade" prose forms and the canonical `LmCompatibilityLevel: <0..2>`
/// registry probe output.
fn collect_result_text_parts(payload: &Value) -> Vec<String> {
    let mut texts: Vec<String> = Vec::new();
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                texts.push(s.to_string());
            } else if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
                texts.push(s.to_string());
            }
        }
    }
    texts
}

fn result_has_ntlmv1_signal(result: &Option<Value>) -> bool {
    let Some(payload) = result.as_ref() else {
        return false;
    };
    let texts = collect_result_text_parts(payload);
    for text in texts {
        let lower = text.to_lowercase();
        // Explicit positive verdict lines. Kept narrow on purpose — the
        // loose "ntlm downgrade" form would false-positive on agent plans
        // and recon commentary that merely names the technique.
        if lower.contains("ntlmv1 allowed")
            || lower.contains("ntlmv1 is allowed")
            || lower.contains("ntlmv1_allowed")
            || lower.contains("lmcompatibilitylevel is vulnerable")
            || lower.contains("ntlmv1 downgrade confirmed")
        {
            return true;
        }
        // Registry probe: LmCompatibilityLevel <= 2 permits NTLMv1. Only
        // consider digits that appear AFTER the key on the same line —
        // otherwise commentary like "check whether NTLMv1 (LmCompatibilityLevel)
        // is set" would false-positive on the `1` in "NTLMv1".
        for line in text.lines() {
            let ll = line.to_lowercase();
            let Some(idx) = ll.find("lmcompatibilitylevel") else {
                continue;
            };
            let tail = &line[idx + "lmcompatibilitylevel".len()..];
            if let Some(digit) = tail.chars().find(|c| c.is_ascii_digit()) {
                if matches!(digit, '0' | '1' | '2') {
                    return true;
                }
            }
        }
    }
    false
}

/// Resolve a host label for a `seimpersonate_<label>` vuln_id. Prefers the
/// host's `hostname` (e.g. `web01`) when known so the scoreboard token is
/// stable across runs, falls back to the IP. Hostname is lowercased and the
/// AD suffix stripped (`web01.contoso.local` → `web01`) so two runs that
/// see the same machine produce the same token.
async fn derive_seimpersonate_host_label(
    dispatcher: &Arc<Dispatcher>,
    target_ip: Option<&str>,
) -> String {
    if let Some(ip) = target_ip {
        let state = dispatcher.state.read().await;
        if let Some(host) = state.hosts.iter().find(|h| h.ip == ip) {
            if !host.hostname.is_empty() {
                let lower = host.hostname.to_lowercase();
                return lower
                    .split_once('.')
                    .map(|(short, _)| short.to_string())
                    .unwrap_or(lower);
            }
        }
        return ip.replace('.', "_");
    }
    "unknown".to_string()
}

/// Returns `true` when trusted tool-output payloads contain a recognised
/// SeImpersonate signal. Conservative — only matches `SeImpersonatePrivilege`
/// alongside an `Enabled` token (the format `whoami /priv` uses). This avoids
/// false positives from output that merely *mentions* the privilege name.
fn result_has_seimpersonate_signal(result: &Option<Value>) -> bool {
    let Some(payload) = result else {
        return false;
    };

    let texts = collect_result_text_parts(payload);

    for text in texts {
        for line in text.lines() {
            let lower = line.to_lowercase();
            if !lower.contains("seimpersonateprivilege") {
                continue;
            }
            // `whoami /priv` table rows look like:
            //   SeImpersonatePrivilege        Impersonate a client after authentication  Enabled
            // We require an `enabled` (case-insensitive) token on the same
            // line. `Disabled` rows are also reported by whoami but are not
            // exploitable.
            if lower.contains("enabled") && !lower.contains("disabled") {
                return true;
            }
        }
    }
    false
}

/// Extract `(username, optional domain)` pairs from a tool result that
/// reported a per-user lockout. Looks at trusted `tool_outputs`, `output`,
/// and `tool_output` fields for netexec-style lines such as:
///
///   `[-] DOMAIN\\username:password STATUS_ACCOUNT_LOCKED_OUT`
///   `[-] username:password KDC_ERR_CLIENT_REVOKED`
///
/// Returns lower-cased usernames; the domain (if present in the prefix) is
/// also lowercased. Used by `process_completed_task` to populate
/// `quarantined_principals` for enumeration tasks that lack a `cred_key`.
pub(crate) fn extract_locked_usernames_from_result(
    result: &Option<Value>,
) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let Some(payload) = result else {
        return out;
    };

    let texts = collect_result_text_parts(payload);

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for text in texts {
        for line in text.lines() {
            if !LOCKOUT_PATTERNS.iter().any(|p| line.contains(p)) {
                continue;
            }
            let Some((user, domain)) = parse_lockout_principal(line) else {
                continue;
            };
            let user_l = user.to_lowercase();
            // Skip accounts that ship disabled — already filtered at
            // dispatch time; quarantining them adds noise, not safety.
            if matches!(
                user_l.as_str(),
                "guest" | "krbtgt" | "defaultaccount" | "wdagutilityaccount"
            ) {
                continue;
            }
            let dom_l = domain.map(|d| d.to_lowercase());
            let dedup_key = format!("{user_l}@{}", dom_l.as_deref().unwrap_or(""));
            if seen.insert(dedup_key) {
                out.push((user_l, dom_l));
            }
        }
    }
    out
}

/// Pull `(username, Option<domain>)` from a netexec line that mentions a
/// lockout. Requires the canonical `DOMAIN\user:pass` token preceding the
/// lockout marker — this is the only form netexec emits for auth events.
/// Bare `user:pass` (or `Welcome1:` style narrative tokens) are rejected
/// because LLM summary text frequently contains `word:` tokens that are
/// not principals (e.g. `Notable:`, `username_as_password:`).
/// True when `username` looks like a Group Managed Service Account principal:
/// trailing `$` (machine/service account convention) and the SAM name (with
/// the trailing `$` stripped) contains the substring `gmsa`. Case-insensitive.
/// Matches the same heuristic `auto_gmsa_extraction` uses to recognise gMSA
/// accounts surfaced by enumeration.
fn is_gmsa_principal(username: &str) -> bool {
    let trimmed = username.trim_end_matches('$');
    !trimmed.is_empty() && trimmed.len() < username.len() && trimmed.to_lowercase().contains("gmsa")
}

/// `gmsa_{name}` scoreboard token for a gMSA principal — the trailing `$`
/// is stripped and the name lowercased so secretsdump-surfaced and
/// enumeration-surfaced paths converge on a single exploited-set entry.
fn gmsa_exploit_token(username: &str) -> String {
    format!("gmsa_{}", username.trim_end_matches('$').to_lowercase())
}

/// gMSA managed-password recovery side-effect: when secretsdump returns a
/// Group Managed Service Account hash (account ends with `$` and name
/// contains "gmsa"), credit the gMSA primitive even though we never went
/// through `auto_gmsa_extraction`. Without this, gMSA hashes captured
/// incidentally via DCSync never emit a `gmsa_*` token to the exploited
/// set and the scoreboard understates progress.
///
/// No-op for non-gMSA usernames. Errors from `mark_exploited` are logged
/// but not propagated — credit emission is best-effort and shouldn't
/// fail the surrounding hash-publish flow.
async fn emit_gmsa_exploit_token_if_gmsa<C>(
    state: &SharedState,
    queue: &TaskQueueCore<C>,
    username: &str,
) where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    if !is_gmsa_principal(username) {
        return;
    }
    let vuln_id = gmsa_exploit_token(username);
    if let Err(e) = state.mark_exploited(queue, &vuln_id).await {
        warn!(
            err = %e,
            vuln_id = %vuln_id,
            "Failed to mark gMSA hash as exploited"
        );
    } else {
        info!(
            vuln_id = %vuln_id,
            account = %username,
            "gMSA hash captured via secretsdump — emitted exploit token"
        );
    }
}

fn parse_lockout_principal(line: &str) -> Option<(String, Option<String>)> {
    let marker_pos = LOCKOUT_PATTERNS.iter().filter_map(|p| line.find(p)).min()?;
    let prefix = &line[..marker_pos];
    let token = prefix
        .split_whitespace()
        .rev()
        .find(|t| t.contains('\\') && t.contains(':'))?;
    let principal = token.split(':').next()?;
    let (dom, user) = principal.split_once('\\')?;
    if user.is_empty() || dom.is_empty() {
        return None;
    }
    Some((user.to_string(), Some(dom.to_string())))
}

/// Return true if the task result carries any parser-extracted discoveries.
/// "Parser-extracted" means populated by ares-tools parsers running on real
/// tool stdout — never LLM-fabricated. Used to ground state writes (e.g.
/// `mark_exploited`) against actual evidence.
/// True when `vuln_id` belongs to a primitive whose success is a saved
/// Kerberos ticket rather than a structured discovery. `getST` /
/// `impacket-ticketer` for these flows emit a "Saving ticket in
/// `<principal>.ccache`" line and return exit-0 — no credential/hash/host
/// the regex parsers can attach to `discoveries`. Used alongside
/// `result_has_ccache_evidence` so the scoreboard credits the primitive
/// on a clean getST run.
fn is_ticket_grant_vuln(vuln_id: &str) -> bool {
    let v = vuln_id.to_lowercase();
    v.starts_with("constrained_delegation_")
        || v.starts_with("unconstrained_delegation_")
        || v.starts_with("rbcd_")
        || v.starts_with("s4u_")
}

/// True when the result's raw tool output indicates a Kerberos ticket was
/// successfully saved to disk. Recognises impacket's canonical line
/// (`Saving ticket in <principal>.ccache`) and bare `.ccache` filenames in
/// output blobs. Conservative — requires either the explicit "Saving
/// ticket" preamble or a `.ccache` token to avoid crediting tasks that
/// merely *reference* a ticket path in commentary.
fn result_has_ccache_evidence(result: &Option<Value>) -> bool {
    let Some(payload) = result.as_ref() else {
        return false;
    };
    let texts = collect_result_text_parts(payload);
    for text in texts {
        let lower = text.to_lowercase();
        if lower.contains("saving ticket in") && lower.contains(".ccache") {
            return true;
        }
    }
    false
}

/// Returns `true` when the task's error string is one of the agent-loop
/// stall conditions (LoopEndReason::MaxSteps, MaxTokens, BudgetExceeded,
/// or "ended turn without task_complete"). These conditions indicate the
/// LLM ran out of budget mid-task — they're not failures of the primitive
/// itself. Used to relax the `success` gate in mark_exploited so an
/// exploit that produced parser evidence before the agent stalled still
/// gets scoreboard credit.
fn error_indicates_stall(err: Option<&str>) -> bool {
    let Some(e) = err else {
        return false;
    };
    let lower = e.to_lowercase();
    lower.contains("ended turn without task_complete")
        || lower.contains("agent hit max steps")
        || lower.contains("max steps")
        || lower.contains("agent hit max tokens")
        || lower.contains("budget exceeded")
}

fn result_has_parser_evidence(result: &Option<Value>) -> bool {
    let Some(payload) = result.as_ref() else {
        return false;
    };
    let Some(disc) = payload.get("discoveries") else {
        return false;
    };
    const KEYS: &[&str] = &[
        "credentials",
        "hashes",
        "hosts",
        "shares",
        "vulnerabilities",
        "delegations",
        "trusts",
        "users",
        "spns",
    ];
    KEYS.iter().any(|k| {
        disc.get(*k)
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    })
}

/// Return true if the task produced parser-extracted credential or hash
/// evidence — the grounding signal for `mark_host_owned` on
/// `credential_access_*` tasks.
fn result_has_credential_evidence(result: &Option<Value>) -> bool {
    let Some(payload) = result.as_ref() else {
        return false;
    };
    let Some(disc) = payload.get("discoveries") else {
        return false;
    };
    ["credentials", "hashes"].iter().any(|k| {
        disc.get(*k)
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    })
}

/// Check whether a task result's text indicates the LLM reported a failure,
/// even though the task technically completed (task_complete was called).
fn result_text_indicates_failure(result: &Option<Value>) -> bool {
    let text = match result {
        Some(v) => {
            // Check both "summary" field and full JSON string
            let summary = v.get("summary").and_then(|s| s.as_str()).unwrap_or("");
            if !summary.is_empty() {
                summary.to_string()
            } else {
                v.to_string()
            }
        }
        None => return false,
    };
    let lower = text.to_lowercase();
    lower.starts_with("failed")
        || lower.contains("\"failed:")
        || lower.contains("\"failed ")
        || lower.contains("failed to exploit")
        || lower.contains("failed esc")
        || lower.contains("missing required")
        || lower.contains("missing ca")
        || lower.contains("without ca name")
        || lower.contains("cannot attempt")
        || lower.contains("cannot execute")
        || lower.contains("not available in")
        || lower.contains("ept_s_not_registered")
        || lower.contains("blocked:")
        || lower.contains("invalidcredentials")
        || lower.contains("status_account_locked")
        || lower.contains("rpc_s_access_denied")
}

/// Resolve the domain for hash/credential attribution from the task's target IP.
///
/// Priority:
///   1. Match target_ip to a known host's domain (hostname suffix → domain)
///   2. Match target_ip to a domain controller entry
///   3. Fall back to state.domains.first()
async fn resolve_domain_from_ip(dispatcher: &Arc<Dispatcher>, target_ip: Option<&str>) -> String {
    let state = dispatcher.state.read().await;
    if let Some(ip) = target_ip {
        // Check domain_controllers map first — most reliable
        for (domain, dc_ip) in &state.domain_controllers {
            if dc_ip == ip {
                return domain.clone();
            }
        }
        // Derive domain from FQDN hostname (e.g. dc01.child.contoso.local
        // → child.contoso.local)
        for host in &state.hosts {
            if host.ip == ip {
                if let Some(dot) = host.hostname.find('.') {
                    return host.hostname[dot + 1..].to_string();
                }
            }
        }
    }
    state.domains.first().cloned().unwrap_or_default()
}

/// Prefer the directory-attested domain for a text-extracted credential.
///
/// `extract_plaintext_passwords` (and the cracked-password / hash extractors)
/// stamp every credential with `default_domain` — the *task target's* domain,
/// resolved from the target IP via the `domain_controllers` map — whenever the
/// captured line doesn't carry an explicit `DOMAIN\user` or `user@domain`
/// prefix. That's wrong for foreign-realm principals that surface in the
/// stdout of a tool run against a different DC: e.g. an LDAP search hitting
/// the parent DC returns child-domain users in description/sysvol blobs and
/// they get stored under the parent realm, after which every downstream auth
/// attempt fails with `STATUS_LOGON_FAILURE` against any DC.
///
/// `state.users` is populated by trusted enumeration parsers
/// (`kerberos_enum`, `ldap_group_enumeration`, `ldap_enumeration`, …) where
/// the realm is whatever the directory itself returned — directory-attested
/// rather than IP-inferred. When the extracted username matches exactly one
/// such entry with a non-empty domain that differs from the IP-resolved
/// fallback, prefer the state.users domain.
///
/// Returns `None` when:
/// - no matching user exists in state (nothing to correct against);
/// - the username is associated with multiple domains in state (can't
///   disambiguate — keep the extractor's guess);
/// - the only known domain already matches the extracted one (no-op).
pub(crate) fn reconcile_extracted_credential_domain(
    users: &[ares_core::models::User],
    username: &str,
    extracted_domain: &str,
) -> Option<String> {
    let user_lc = username.to_lowercase();
    let mut domains: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for u in users {
        if u.username.to_lowercase() == user_lc && !u.domain.is_empty() {
            domains.insert(u.domain.to_lowercase());
        }
    }
    if domains.len() != 1 {
        return None;
    }
    let only = domains.into_iter().next().unwrap();
    if only.eq_ignore_ascii_case(extracted_domain) {
        return None;
    }
    Some(only)
}

fn is_low_trust_realm_inferred_credential_source(source: &str) -> bool {
    matches!(
        source,
        "description_field"
            | "autologon_registry"
            | "sysvol_script"
            | "user_description_leak"
            | "netexec_password"
            | "ldap_description"
    )
}

pub(crate) fn reconcile_low_trust_credential_domain(
    cred: &mut ares_core::models::Credential,
    users: &[ares_core::models::User],
) -> Option<String> {
    if !is_low_trust_realm_inferred_credential_source(&cred.source) {
        return None;
    }
    let corrected = reconcile_extracted_credential_domain(users, &cred.username, &cred.domain)?;
    cred.domain = corrected.clone();
    Some(corrected)
}

/// `kerberoast_{username}` or `asrep_roast_{domain}` token when the
/// captured hash carries the canonical impacket / hashcat prefix
/// (`$krb5tgs$`, `$krb5asrep$`). Returns `None` for other hash types so
/// the caller emits exactly one token per captured roast hash. Token
/// values match dreadgoad's `transport_ares.aresExploitedToTechniqueIDs`
/// prefix matchers — anything starting with `kerberoast_` / `asrep_roast_`
/// credits the corresponding scoreboard primitive.
fn roast_exploit_token(hash_value: &str, username: &str, domain: &str) -> Option<String> {
    let user_lc = username.trim().to_lowercase();
    let dom_lc = domain.trim().to_lowercase();
    if hash_value.starts_with("$krb5tgs$") {
        // Kerberoast: token-per-account so multiple SPN hashes don't
        // collapse on a single entry.
        if user_lc.is_empty() {
            return None;
        }
        Some(format!("kerberoast_{user_lc}"))
    } else if hash_value.starts_with("$krb5asrep$") {
        // AS-REP roast: dreadgoad's objective is per-domain (any
        // preauth-disabled account demonstrates the primitive); token-
        // per-domain lets the inferred-hint path and the explicit-capture
        // path converge on the same entry.
        let key = if !dom_lc.is_empty() { dom_lc } else { user_lc };
        if key.is_empty() {
            return None;
        }
        Some(format!("asrep_roast_{key}"))
    } else {
        None
    }
}

async fn auto_chain_s4u_secretsdump(
    payload: &Value,
    dispatcher: &Arc<Dispatcher>,
    task_id: &str,
    task_params: &std::collections::HashMap<String, Value>,
    task_domain: Option<&str>,
    task_target_ip: Option<&str>,
) {
    let combined = collect_result_text_parts(payload).join("\n");
    let Some(ticket_path) = ares_llm::routing::extract_ticket_path(&combined) else {
        return;
    };

    info!(
        task_id = %task_id,
        ticket_path = %ticket_path,
        "Detected .ccache ticket — chaining secretsdump"
    );

    let get_param = |key: &str| -> Option<&str> { task_params.get(key).and_then(|v| v.as_str()) };

    let target_ip = get_param("target_spn")
        .and_then(ares_llm::routing::extract_host_from_spn)
        .or_else(|| get_param("target_ip").map(|s| s.to_string()))
        .or_else(|| get_param("target").map(|s| s.to_string()))
        .or_else(|| {
            // Try to parse target from ccache filename:
            // Administrator@CIFS_dc01@CHILD.CONTOSO.LOCAL.ccache
            let fname = ticket_path.rsplit('/').next().unwrap_or(&ticket_path);
            if let Some(at_pos) = fname.find('@') {
                let after = &fname[at_pos + 1..];
                // Extract hostname: CIFS_dc01@REALM.ccache → CIFS.dc01
                let host_part = after.split('@').next().unwrap_or(after).replace('_', ".");
                // Remove the service prefix (CIFS. → dc01)
                if let Some(dot_pos) = host_part.find('.') {
                    let candidate = &host_part[dot_pos + 1..];
                    if !candidate.is_empty() {
                        return Some(candidate.to_string());
                    }
                }
            }
            None
        })
        .or_else(|| task_target_ip.map(|s| s.to_string()));

    let Some(target_ip) = target_ip else {
        warn!(task_id = %task_id, "S4U auto-chain: .ccache found but no target could be determined");
        return;
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

    let domain = task_domain
        .filter(|d| !d.is_empty())
        .or_else(|| get_param("domain"))
        .unwrap_or("");

    // Dispatch secretsdump with ticket (no password needed).
    // Must include username — secretsdump requires it even with -k -no-pass.
    // The S4U impersonates Administrator, so use that as default.
    let username = get_param("impersonate")
        .or_else(|| get_param("username"))
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
            create_lateral_movement_timeline_event(dispatcher, &resolved_ip, &ticket_path).await;
        }
        Ok(None) => {}
        Err(e) => warn!(err = %e, "S4U auto-chain: failed to dispatch secretsdump"),
    }
}

/// Extract discoveries from raw text fields in the result payload.
///
/// Collects text from raw tool output fields ("tool_output", "output", "tool_outputs")
/// and runs regex-based extraction on the combined text. Safety net that catches
/// discoveries the per-tool parsers or LLM-reported structured data may have missed.
async fn extract_from_raw_text(
    payload: &Value,
    dispatcher: &Arc<Dispatcher>,
    default_domain: &str,
    task_target_ip: Option<&str>,
    share_auth_label: Option<&str>,
) {
    // Only parse tool_outputs — actual tool stdout collected by the agent loop.
    // The result payload's "summary", "result", and "output" fields are all
    // LLM-generated prose and MUST NOT be fed into regex extractors (they produce
    // false positives like "Password : only" from conversational text).
    //
    // Structured discoveries from tool-call parsers are already handled by
    // extract_discoveries() via the "discoveries" key — this pass is a secondary
    // safety net for raw tool stdout that parsers may have missed.
    // Each item is either an object {name, arguments, output} (preferred — see
    // `dispatcher::submission`) or a bare string (legacy / blue-team paths).
    // Bare strings carry no tool context, so extractors fall back to untyped
    // behavior; the structured form lets extractors gate on tool name + args
    // (e.g. skip credential regex for hash-auth invocations of nxc).
    let mut tool_outputs: Vec<output_extraction::ToolOutputCtx> = Vec::new();

    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                tool_outputs.push(output_extraction::ToolOutputCtx {
                    arguments: None,
                    output: s,
                });
            } else if let Some(obj) = item.as_object() {
                let Some(s) = obj.get("output").and_then(|v| v.as_str()) else {
                    continue;
                };
                tool_outputs.push(output_extraction::ToolOutputCtx {
                    arguments: obj.get("arguments"),
                    output: s,
                });
            }
        }
    }

    if tool_outputs.is_empty() {
        return;
    }

    // Process each tool output independently to prevent stateful parsers
    // (e.g. extract_plaintext_passwords's current_user tracker) from leaking
    // context across unrelated tool calls — a joined string caused false
    // credential attribution (e.g. john.smith:Summer2025 from stale context).
    let mut extracted = output_extraction::TextExtractions::default();
    for ctx in &tool_outputs {
        let partial = output_extraction::extract_from_output_text(ctx, default_domain);
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

    for mut cred in extracted.credentials {
        let corrected = {
            let state = dispatcher.state.read().await;
            reconcile_extracted_credential_domain(&state.users, &cred.username, &cred.domain)
        };
        if let Some(corrected) = corrected {
            warn!(
                username = %cred.username,
                extracted_domain = %cred.domain,
                corrected_domain = %corrected,
                source = %cred.source,
                "Reassigning text-extracted credential to directory-attested domain from state.users",
            );
            cred.domain = corrected;
        }
        let is_cracked = cred.source.starts_with("cracked:");
        let source = cred.source.clone();
        let username = cred.username.clone();
        let domain = cred.domain.clone();
        let password = cred.password.clone();
        let is_admin = cred.is_admin;
        match dispatcher
            .state
            .publish_credential(&dispatcher.queue, cred)
            .await
        {
            Ok(true) => {
                new_count += 1;
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
            Err(e) => warn!(err = %e, "Failed to publish text-extracted credential"),
        }
    }

    for mut hash in extracted.hashes {
        // Local-SAM rows (no realm) come back without source_host context.
        // The dispatcher knows the target IP — stamp it so multiple hosts'
        // Administrator/Guest/ssm-user rows stay distinct on dedup.
        if hash.domain.is_empty() && hash.source_host.is_none() {
            hash.source_host = task_target_ip.map(|s| s.to_string());
        }
        let username = hash.username.clone();
        let domain = hash.domain.clone();
        let hash_type = hash.hash_type.clone();
        let hash_value = hash.hash_value.clone();
        let source = hash.source.clone();
        match dispatcher.state.publish_hash(&dispatcher.queue, hash).await {
            Ok(true) => {
                new_count += 1;
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
            Err(e) => warn!(err = %e, "Failed to publish text-extracted hash"),
        }
    }

    for host in extracted.hosts {
        let _ = dispatcher.state.publish_host(&dispatcher.queue, host).await;
    }

    // Users from raw text extraction are gated by source. The DOMAIN\user /
    // UPN / user:[name] regexes match wordlist iterations in kerbrute/ASREProast
    // output (e.g. "[-] User svc_sql doesn't have UF_DONT_REQUIRE_PREAUTH set"),
    // so users tagged `output_extraction` are dropped here. Users tagged
    // `ldap_extraction` came from the `sAMAccountName:` regex — that attribute
    // is only emitted by an LDAP server (ldapsearch/bloodyAD), so it survives
    // as a verified discovery. Without this, cross-forest LDAP enum via a
    // forged inter-realm Kerberos ticket discovers users but never persists
    // them — blocking downstream AS-REP roasting and targeted_kerberoast
    // against the foreign forest.
    for user in extracted.users {
        if user.source != "ldap_extraction" {
            continue;
        }
        match dispatcher.state.publish_user(&dispatcher.queue, user).await {
            Ok(true) => new_count += 1,
            Ok(false) => {}
            Err(e) => warn!(err = %e, "Failed to publish text-extracted user"),
        }
    }

    for mut share in extracted.shares {
        if share.authenticated_as.is_none() {
            share.authenticated_as = share_auth_label.map(|s| s.to_string());
        }
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
    for ctx in &tool_outputs {
        if ctx.output.contains("Pwn3d!") {
            detect_and_upgrade_admin_credentials(ctx.output, dispatcher).await;
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
async fn extract_discoveries(
    payload: &Value,
    dispatcher: &Arc<Dispatcher>,
    task_target_ip: Option<&str>,
    share_auth_label: Option<&str>,
) -> Result<()> {
    let mut parsed = parse_discoveries(payload);

    // Resolve credential lineage (parent_id / attack_step) before publishing.
    // Read lock is released before any publish calls (which take write locks).
    {
        let state = dispatcher.state.read().await;
        let mut user_hints = state.users.clone();
        user_hints.extend(parsed.users.iter().cloned());

        for cred in &mut parsed.credentials {
            let extracted_domain = cred.domain.clone();
            if let Some(corrected) = reconcile_low_trust_credential_domain(cred, &user_hints) {
                warn!(
                    username = %cred.username,
                    extracted_domain = %extracted_domain,
                    corrected_domain = %corrected,
                    source = %cred.source,
                    "Reassigning parser-extracted credential to directory-attested domain from state.users",
                );
            }
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

    for mut hash in parsed.hashes {
        // Local-SAM rows (no realm) come back without source_host context.
        // The parser strips the host prefix; the dispatcher knows the target
        // IP — stamp it so per-host Administrator/Guest/ssm-user rows stay
        // distinct on dedup. Domain-qualified (NTDS) rows have a realm to
        // disambiguate; we leave their source_host empty.
        if hash.domain.is_empty() && hash.source_host.is_none() {
            hash.source_host = task_target_ip.map(|s| s.to_string());
        }
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

                emit_gmsa_exploit_token_if_gmsa(&dispatcher.state, &dispatcher.queue, &username)
                    .await;

                // AS-REP / Kerberoast primitive credit on hash capture.
                // dreadgoad's scoreboard otherwise infers `asrep_roast` /
                // `kerberoast` from the cracked-credential hint, which only
                // fires AFTER the hash crack succeeds. The crack may fail
                // (insufficient wordlist coverage, AES instead of RC4) yet
                // the capture itself already proves the primitive. Emit the
                // token at capture time so credit is independent of crack
                // outcome.
                if let Some(token) = roast_exploit_token(&hash_value, &username, &domain) {
                    if let Err(e) = dispatcher
                        .state
                        .mark_exploited(&dispatcher.queue, &token)
                        .await
                    {
                        warn!(
                            err = %e,
                            vuln_id = %token,
                            "Failed to mark roast hash as exploited"
                        );
                    } else {
                        info!(
                            vuln_id = %token,
                            account = %username,
                            domain = %domain,
                            "Kerberos roast hash captured — emitted exploit token"
                        );
                    }
                }
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

    for mut share in parsed.shares {
        if share.authenticated_as.is_none() {
            share.authenticated_as = share_auth_label.map(|s| s.to_string());
        }
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
