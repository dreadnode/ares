//! Impacket failure classifier and recovery dispatcher.
//!
//! Background: a credential_access task using a known-good Administrator NTLM
//! hash against the target DC routinely fails with STATUS_LOGON_FAILURE when
//! the LLM agent constructs the impacket `DOMAIN/user@host` auth string with a
//! mismatched realm (CLAUDE.md "Impacket Kerberos Constraints" #3), and the
//! agent then bails instead of retrying with corrected syntax. The same pattern
//! traps ccache-dependent chains (constraint #4) and cross-realm referrals
//! (constraint #1). This module classifies the failure from raw tool output,
//! gates re-dispatch on "credential is known-good" (so we never retry against
//! a real bad password), and re-emits a corrected task at priority 1.
//!
//! One-shot per (task_id, failure_class) — the dedup key is persisted alongside
//! the secretsdump dedup set so a recovery attempt cannot loop.
//!
//! Scope today: secretsdump hash-auth realm mismatches (the failure mode that
//! kept us 2 tool calls from a Golden Ticket for an entire op). Stubs are in
//! place for the other 3 impacket constraints; extend `attempt_recovery` when
//! we observe those classes in real ops.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::orchestrator::automation::is_cross_forest;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::DEDUP_SECRETSDUMP;

/// Classifications recovered from raw tool output. Maps 1:1 to the 4 Impacket
/// constraints documented in CLAUDE.md. `Unknown` short-circuits recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpacketFailureClass {
    /// `STATUS_LOGON_FAILURE` / `KDC_ERR_S_PRINCIPAL_UNKNOWN` /
    /// `KDC_ERR_WRONG_REALM` — credential is good elsewhere, but the
    /// `DOMAIN/user@host` syntax (or the cross-realm referral) is wrong.
    RealmMismatch,
    /// Tool wrote a ccache (`Saving ticket in *.ccache`) but a subsequent
    /// invocation can't see it — separate `run_tool` calls land on
    /// different pods. Fix: chain commands with `&&` in one bash call.
    NoCcachePersist,
    /// `-hashes` formatting error: impacket expects `LM:NT` or `:NT`.
    MissingHashArg,
}

impl ImpacketFailureClass {
    fn label(&self) -> &'static str {
        match self {
            Self::RealmMismatch => "realm_mismatch",
            Self::NoCcachePersist => "no_ccache_persist",
            Self::MissingHashArg => "missing_hash_arg",
        }
    }
}

/// Classify a failed task result from its raw tool output and error string.
/// Returns `None` when no recognised Impacket failure pattern is present —
/// genuinely bad credentials (with the same status code) fall through here and
/// are filtered out by `credential_is_known_good`, not the classifier.
pub fn classify_impacket_failure(
    result: &Option<Value>,
    error: Option<&str>,
) -> Option<ImpacketFailureClass> {
    let text = collect_failure_text(result, error);
    if text.is_empty() {
        return None;
    }
    let lower = text.to_lowercase();

    // Hash formatting failures must be checked before the generic logon
    // failure pattern — impacket emits both messages in the same run when
    // the `-hashes` arg is malformed.
    if lower.contains("hashes must be of the form")
        || lower.contains("invalid hash format")
        || lower.contains("non-hexadecimal digit found")
    {
        return Some(ImpacketFailureClass::MissingHashArg);
    }

    if (lower.contains("krb5ccname") || lower.contains(".ccache") || lower.contains("ccache file"))
        && (lower.contains("no such file")
            || lower.contains("not found")
            || lower.contains("cannot find"))
    {
        return Some(ImpacketFailureClass::NoCcachePersist);
    }

    if lower.contains("status_logon_failure")
        || lower.contains("kdc_err_s_principal_unknown")
        || lower.contains("kdc_err_wrong_realm")
        || lower.contains("kdc_err_c_principal_unknown")
    {
        return Some(ImpacketFailureClass::RealmMismatch);
    }

    None
}

/// Gather raw text from `tool_outputs` plus the top-level error string.
/// Mirrors the conservative collection pattern used by
/// `result_has_seimpersonate_signal` — only structured tool stdout, never LLM
/// commentary (LLM summaries can include status codes copied from a *prior*
/// tool call and would false-positive the classifier).
fn collect_failure_text(result: &Option<Value>, error: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(err) = error {
        parts.push(err.to_string());
    }
    let Some(payload) = result else {
        return parts.join("\n");
    };
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                parts.push(s.to_string());
            } else if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
                parts.push(s.to_string());
            }
        }
    }
    parts.join("\n")
}

/// True when the credential the failing task used is verifiably in operation
/// state — i.e. we dumped this hash ourselves, or this password came from a
/// successful prior auth. This is the gate that prevents the classifier from
/// burning auth budget retrying genuinely wrong credentials.
async fn credential_is_known_good(
    dispatcher: &Arc<Dispatcher>,
    task_params: &HashMap<String, Value>,
) -> bool {
    let hash_value = task_params
        .get("hash_value")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let cred = task_params.get("credential");
    let username = cred
        .and_then(|c| c.get("username"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let password = cred
        .and_then(|c| c.get("password"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    if let Some(hash) = hash_value.as_deref() {
        let target_nt = nt_half(hash);
        let state = dispatcher.state.read().await;
        return state.hashes.iter().any(|h| {
            let h_nt = nt_half(&h.hash_value);
            !h_nt.is_empty()
                && h_nt.eq_ignore_ascii_case(&target_nt)
                && username
                    .as_deref()
                    .is_none_or(|u| h.username.eq_ignore_ascii_case(u))
        });
    }

    if let (Some(u), Some(p)) = (username.as_deref(), password.as_deref()) {
        let state = dispatcher.state.read().await;
        return state
            .credentials
            .iter()
            .any(|c| c.username.eq_ignore_ascii_case(u) && c.password == p);
    }

    false
}

/// Extract the NT half from a hash value that may be in `LM:NT` form. Returns
/// the bare hash unchanged when it doesn't look like an LM:NT pair.
fn nt_half(hash: &str) -> String {
    if let Some((lhs, rhs)) = hash.split_once(':') {
        if lhs.len() == 32 && rhs.len() == 32 && lhs.bytes().all(|b| b.is_ascii_hexdigit()) {
            return rhs.to_string();
        }
    }
    hash.to_string()
}

/// Resolve the realm of the DC at `target_ip` from operation state. Matches the
/// IP against the DC map first (`domain → dc_ip`), then falls back to a host
/// whose FQDN hostname yields a dotted suffix. Returns `None` when the target's
/// realm can't be determined — the caller then proceeds with normal recovery
/// rather than skipping on a guess.
async fn resolve_target_realm(dispatcher: &Arc<Dispatcher>, target_ip: &str) -> Option<String> {
    let state = dispatcher.state.read().await;
    for (domain, ip) in state.all_domains_with_dcs() {
        if ip == target_ip && !domain.is_empty() {
            return Some(domain);
        }
    }
    for h in &state.hosts {
        if h.ip == target_ip && !h.hostname.is_empty() {
            if let Some((_, suffix)) = h.hostname.split_once('.') {
                let s = suffix.trim().to_lowercase();
                if s.contains('.') {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Top-level entry point. Called by `process_completed_task` immediately after
/// a failed credential_access task is logged. Classifies, gates on
/// known-good-credential, then re-dispatches with corrected arguments.
///
/// Returns `true` when a recovery task was queued.
pub async fn attempt_recovery(
    dispatcher: &Arc<Dispatcher>,
    task_id: &str,
    task_params: &HashMap<String, Value>,
    result: &Option<Value>,
    error: Option<&str>,
) -> bool {
    // Cheap exit: we only recover credential_access secretsdump tasks today.
    // Extending to lateral-movement / kerberoast lives behind the same gate.
    let technique = task_params
        .get("technique")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if technique != "secretsdump" {
        return false;
    }

    let Some(class) = classify_impacket_failure(result, error) else {
        return false;
    };

    if !credential_is_known_good(dispatcher, task_params).await {
        debug!(
            task_id = %task_id,
            class = class.label(),
            "Impacket recovery skipped: credential is not known-good (avoiding retry of real bad cred)"
        );
        return false;
    }

    // One-shot dedup so a re-dispatched task that fails the same way doesn't
    // loop. Keyed on (target, cred, class) rather than task_id so two tasks
    // hitting the same misconfig don't both get a free retry.
    let target_ip = task_params
        .get("target_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cred_username = task_params
        .get("credential")
        .and_then(|c| c.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cred_domain = task_params
        .get("credential")
        .and_then(|c| c.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let recovery_key = format!(
        "impacket_recovery:{}:{}:{}:{}",
        target_ip,
        cred_domain.to_lowercase(),
        cred_username.to_lowercase(),
        class.label()
    );
    {
        let state = dispatcher.state.read().await;
        if state.is_processed(DEDUP_SECRETSDUMP, &recovery_key) {
            debug!(
                task_id = %task_id,
                key = %recovery_key,
                "Impacket recovery already attempted — skipping"
            );
            return false;
        }
    }

    match class {
        ImpacketFailureClass::RealmMismatch => {
            recover_realm_mismatch(dispatcher, task_id, task_params, &recovery_key).await
        }
        ImpacketFailureClass::NoCcachePersist | ImpacketFailureClass::MissingHashArg => {
            // Mark anyway so we don't repeatedly classify and log. The
            // actual remediation for these classes lives behind future
            // work — log loudly so an operator can spot them.
            warn!(
                task_id = %task_id,
                class = class.label(),
                "Impacket failure classified but no recovery handler implemented yet"
            );
            let mut state = dispatcher.state.write().await;
            state.mark_processed(DEDUP_SECRETSDUMP, recovery_key.clone());
            drop(state);
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &recovery_key)
                .await;
            false
        }
    }
}

/// Re-dispatch a secretsdump with the credential's NATIVE realm as the auth
/// domain. The original task already passed `credential.domain` through, but
/// the LLM agent's tool-call construction is what trips constraint #3 — by
/// re-dispatching at priority 1 with the corrected fields explicitly named in
/// the payload, the prompt template surfaces them in the example signature
/// (`secretsdump(..., domain='{cred_domain}', just_dc_user='krbtgt')`) and the
/// agent has less room to vary syntax.
async fn recover_realm_mismatch(
    dispatcher: &Arc<Dispatcher>,
    task_id: &str,
    task_params: &HashMap<String, Value>,
    recovery_key: &str,
) -> bool {
    let target_ip = task_params
        .get("target_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cred = task_params.get("credential");
    let username = cred
        .and_then(|c| c.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cred_domain = cred
        .and_then(|c| c.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash_value = task_params
        .get("hash_value")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let just_dc_user = task_params
        .get("just_dc_user")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    if target_ip.is_empty()
        || username.is_empty()
        || cred_domain.is_empty()
        || hash_value.is_empty()
    {
        debug!(
            task_id = %task_id,
            "Impacket recovery skipped: missing one of target_ip/username/cred_domain/hash_value"
        );
        return false;
    }

    // Cross-forest guard: KDC_ERR_WRONG_REALM against a DC in a *different
    // forest* is not a `DOMAIN/user@host` syntax slip — it means native
    // home-realm creds are being presented to a KDC in a disjoint namespace,
    // which no realm string can fix. Re-dispatching secretsdump with the
    // credential's native realm just re-hits the same error. The working path
    // is the inter-realm forge (`auto_trust_follow`); mark this attempt
    // processed and defer to that machinery instead of burning a retry.
    if let Some(target_realm) = resolve_target_realm(dispatcher, target_ip).await {
        if is_cross_forest(cred_domain, &target_realm) {
            info!(
                task_id = %task_id,
                target_ip = %target_ip,
                cred_domain = %cred_domain,
                target_realm = %target_realm,
                "Impacket recovery skipped: cross-forest target — native-cred re-dispatch is doomed, deferring to inter-realm forge"
            );
            {
                let mut state = dispatcher.state.write().await;
                state.mark_processed(DEDUP_SECRETSDUMP, recovery_key.to_string());
            }
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, recovery_key)
                .await;
            return false;
        }
    }

    info!(
        task_id = %task_id,
        target_ip = %target_ip,
        cred_domain = %cred_domain,
        username = %username,
        just_dc_user = ?just_dc_user,
        "Impacket recovery: re-dispatching secretsdump with corrected realm at priority 1"
    );

    match dispatcher
        .request_secretsdump_hash(
            target_ip,
            username,
            cred_domain,
            hash_value,
            1,
            just_dc_user,
        )
        .await
    {
        Ok(Some(new_task_id)) => {
            info!(
                original_task_id = %task_id,
                recovery_task_id = %new_task_id,
                "Impacket realm-mismatch recovery dispatched"
            );
            {
                let mut state = dispatcher.state.write().await;
                state.mark_processed(DEDUP_SECRETSDUMP, recovery_key.to_string());
            }
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, recovery_key)
                .await;
            true
        }
        Ok(None) => {
            debug!(task_id = %task_id, "Recovery secretsdump deferred by throttler");
            false
        }
        Err(e) => {
            warn!(task_id = %task_id, err = %e, "Failed to dispatch recovery secretsdump");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_status_logon_failure_as_realm_mismatch() {
        let result = Some(json!({
            "tool_outputs": [
                "[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid.)"
            ]
        }));
        assert_eq!(
            classify_impacket_failure(&result, None),
            Some(ImpacketFailureClass::RealmMismatch)
        );
    }

    #[test]
    fn classifies_kdc_err_s_principal_unknown_as_realm_mismatch() {
        let result = Some(json!({
            "tool_outputs": [
                "Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN"
            ]
        }));
        assert_eq!(
            classify_impacket_failure(&result, None),
            Some(ImpacketFailureClass::RealmMismatch)
        );
    }

    #[test]
    fn classifies_hash_format_before_logon_failure() {
        let result = Some(json!({
            "tool_outputs": [
                "Error: hashes must be of the form LM:NT\nSTATUS_LOGON_FAILURE"
            ]
        }));
        assert_eq!(
            classify_impacket_failure(&result, None),
            Some(ImpacketFailureClass::MissingHashArg)
        );
    }

    #[test]
    fn classifies_missing_ccache_file() {
        let result = Some(json!({
            "tool_outputs": [
                "KRB5CCNAME=/tmp/admin.ccache: No such file or directory"
            ]
        }));
        assert_eq!(
            classify_impacket_failure(&result, None),
            Some(ImpacketFailureClass::NoCcachePersist)
        );
    }

    #[test]
    fn returns_none_for_unrelated_failure() {
        let result = Some(json!({
            "tool_outputs": ["Connection refused"]
        }));
        assert_eq!(classify_impacket_failure(&result, None), None);
    }

    #[test]
    fn returns_none_for_empty_result() {
        assert_eq!(classify_impacket_failure(&None, None), None);
    }

    #[test]
    fn falls_back_to_error_string_when_no_payload() {
        assert_eq!(
            classify_impacket_failure(&None, Some("STATUS_LOGON_FAILURE")),
            Some(ImpacketFailureClass::RealmMismatch)
        );
    }

    #[test]
    fn nt_half_strips_lm_prefix() {
        let lm_nt = "aad3b435b51404eeaad3b435b51404ee:0287e7feb9fe51ed6d3a41fcd446bc24";
        assert_eq!(nt_half(lm_nt), "0287e7feb9fe51ed6d3a41fcd446bc24");
    }

    #[test]
    fn nt_half_returns_bare_hash_unchanged() {
        let bare = "0287e7feb9fe51ed6d3a41fcd446bc24";
        assert_eq!(nt_half(bare), bare);
    }

    #[test]
    fn nt_half_ignores_non_hex_lhs() {
        // foo:bar shouldn't be split — not a valid LM:NT pair.
        let weird = "foo:bar";
        assert_eq!(nt_half(weird), "foo:bar");
    }

    #[test]
    fn collect_failure_text_merges_error_and_tool_outputs() {
        let result = Some(json!({
            "tool_output": "stdout text",
            "tool_outputs": [
                "first",
                {"output": "second"}
            ]
        }));
        let text = collect_failure_text(&result, Some("task error"));
        assert!(text.contains("task error"));
        assert!(!text.contains("stdout text"));
        assert!(text.contains("first"));
        assert!(text.contains("second"));
    }
}
