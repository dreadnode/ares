//! auto_s4u_exploitation -- exploit delegation vulnerabilities via S4U.
//!
//! When constrained or RBCD delegation vulnerabilities are discovered (via
//! `find_delegation` or BloodHound), this automation dispatches S4U attacks
//! using available credentials for the delegating account.
//!
//! NOTE: Unconstrained delegation is handled by `auto_unconstrained_exploitation`
//! which orchestrates the coerce → dump → secretsdump chain.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::StateInner;

/// Cooldown after a failed S4U attempt before retrying the same vuln.
/// Set to 5 minutes to wait for AD account lockout to expire.
const S4U_FAILURE_COOLDOWN: Duration = Duration::from_secs(300);

/// Maximum consecutive failures before giving up on a vuln.
/// Set higher than the expected number of spray-induced lockouts
/// so that S4U can eventually succeed once sprays stop re-locking.
const S4U_MAX_FAILURES: u32 = 6;

/// Kerberos/SMB errors that indicate an account is permanently disabled/revoked.
/// These should permanently block the vuln — no point retrying.
const PERMANENT_REVOCATION_PATTERNS: &[&str] = &["STATUS_ACCOUNT_DISABLED", "KDC_ERR_KEY_EXPIRED"];

/// Kerberos/SMB errors that indicate a temporary lockout.
/// These should count as failures but NOT permanently block — the lockout expires.
const LOCKOUT_PATTERNS: &[&str] = &["KDC_ERR_CLIENT_REVOKED", "STATUS_ACCOUNT_LOCKED_OUT"];

/// Monitors for delegation vulnerabilities and dispatches S4U attacks.
/// Interval: 20s.
pub async fn auto_s4u_exploitation(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let deleg_notify = dispatcher.delegation_notify.clone();
    let cred_notify = dispatcher.credential_access_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Track dispatch attempts per vuln to prevent infinite retry loops.
    // Maps vuln_id -> (last_dispatch_time, failure_count)
    let mut dispatch_tracker: HashMap<String, (Instant, u32)> = HashMap::new();

    // Track task_id -> vuln_id so we can check completed task results for
    // revocation errors and immediately stop retrying those vulns.
    let mut task_vuln_map: HashMap<String, String> = HashMap::new();

    loop {
        // Wake on: timer tick, new delegation vuln, OR new credential (so S4U fires
        // immediately when a constrained delegation account's password is cracked).
        tokio::select! {
            _ = interval.tick() => {},
            _ = deleg_notify.notified() => {},
            _ = cred_notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Check completed tasks for revocation/lockout errors.
        // - Permanent revocation (disabled account) → block forever.
        // - Temporary lockout → just count the failure, let cooldown handle retry.
        {
            let state = dispatcher.state.read().await;
            let finished: Vec<String> = task_vuln_map
                .keys()
                .filter(|tid| state.completed_tasks.contains_key(tid.as_str()))
                .cloned()
                .collect();
            for tid in finished {
                if let Some(result) = state.completed_tasks.get(&tid) {
                    if has_permanent_revocation(result) {
                        if let Some(vid) = task_vuln_map.remove(&tid) {
                            warn!(
                                task_id = %tid,
                                vuln_id = %vid,
                                "S4U blocked: account permanently disabled — no further retries"
                            );
                            dispatch_tracker.entry(vid).or_insert((Instant::now(), 0)).1 =
                                S4U_MAX_FAILURES;
                        }
                    } else if has_lockout_error(result) {
                        if let Some(vid) = task_vuln_map.remove(&tid) {
                            debug!(
                                task_id = %tid,
                                vuln_id = %vid,
                                "S4U lockout detected — will retry after cooldown"
                            );
                            // Don't increment failure count beyond what dispatch already counted.
                            // The cooldown timer is already set from dispatch time.
                        }
                    } else if should_reset_failure_count(result) {
                        // Only reset the failure count on actual success.
                        // Generic failures (wrong SPN, delegation edge is
                        // stale, service rejects S4U, etc.) must keep their
                        // accumulated count so deterministic dead-ends
                        // eventually stop retrying.
                        if let Some(vid) = task_vuln_map.remove(&tid) {
                            if let Some(entry) = dispatch_tracker.get_mut(&vid) {
                                entry.1 = 0;
                            }
                        }
                    } else {
                        // Non-lockout, non-success failure: preserve the
                        // existing failure count that was incremented on
                        // dispatch. Remove the task mapping so future result
                        // scans do not reprocess it.
                        task_vuln_map.remove(&tid);
                    }
                }
            }
        }

        let work: Vec<S4uWork> = {
            let state = dispatcher.state.read().await;

            // Skip only when ALL forests are dominated AND strategy says to stop.
            // When continue_after_da is true, keep exploiting delegation vulns
            // for path diversity even after full domination.
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }

            select_s4u_work_items(&state, &dispatch_tracker, Instant::now())
        };

        for item in work {
            let vuln_id = item.vuln.vuln_id.clone();
            let payload = build_s4u_payload(&item);

            // Priority 10 = highest — S4U must run before other agents use the
            // credential and potentially lock out the account.
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, 10)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %vuln_id,
                        vuln_type = %item.vuln.vuln_type,
                        "S4U exploitation dispatched"
                    );
                    // Record dispatch — increment failure count (reset on next success).
                    // The cooldown prevents rapid re-dispatch if it fails.
                    let entry = dispatch_tracker
                        .entry(vuln_id.clone())
                        .or_insert((Instant::now(), 0));
                    entry.0 = Instant::now();
                    entry.1 += 1;
                    // Track task → vuln so we can check for revocation on completion.
                    task_vuln_map.insert(task_id, vuln_id);
                }
                Ok(None) => {
                    debug!(vuln_id = %vuln_id, "S4U task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %vuln_id, "Failed to dispatch S4U exploit")
                }
            }
        }
    }
}

pub(crate) struct S4uWork {
    pub vuln: ares_core::models::VulnerabilityInfo,
    pub credential: Option<ares_core::models::Credential>,
    pub hash: Option<ares_core::models::Hash>,
    pub target_spn: Option<String>,
    pub domain: String,
    pub dc_ip: Option<String>,
}

/// Build the work queue of S4U attacks to dispatch this tick.
///
/// Iterates `state.discovered_vulnerabilities`, keeping only
/// constrained-delegation / RBCD vulns that are not already exploited,
/// not in dispatch cooldown, and have a credential or NTLM hash for the
/// delegating account. The result is consumed by the dispatch loop in
/// [`auto_s4u_exploitation`].
///
/// Extracted from the inline closure for unit testing — the filter has
/// many overlapping gates (vuln type, exploited set, failure tracker,
/// cooldown, account name extraction, credential matching) and asserting
/// each one against a synthetic state is dramatically simpler than
/// stubbing the entire Dispatcher.
pub(crate) fn select_s4u_work_items(
    state: &StateInner,
    dispatch_tracker: &HashMap<String, (Instant, u32)>,
    now: Instant,
) -> Vec<S4uWork> {
    state
        .discovered_vulnerabilities
        .values()
        .filter_map(|vuln| {
            let vtype = vuln.vuln_type.to_lowercase();
            if vtype != "constrained_delegation" && vtype != "rbcd" {
                return None;
            }

            if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                return None;
            }

            if let Some((last_time, failures)) = dispatch_tracker.get(&vuln.vuln_id) {
                if *failures >= S4U_MAX_FAILURES {
                    return None;
                }
                if now.duration_since(*last_time) < S4U_FAILURE_COOLDOWN {
                    return None;
                }
            }

            let account_name = vuln
                .details
                .get("account_name")
                .and_then(|v| v.as_str())
                .or_else(|| vuln.details.get("AccountName").and_then(|v| v.as_str()))
                .map(|s| s.to_string());

            let target_spn = vuln
                .details
                .get("delegation_target")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    vuln.details
                        .get("AllowedToDelegate")
                        .and_then(|v| v.as_str())
                })
                .map(|s| s.to_string());

            let credential = account_name.as_ref().and_then(|acct| {
                state
                    .credentials
                    .iter()
                    .find(|c| c.username.to_lowercase() == acct.to_lowercase())
                    .cloned()
            });

            let hash = account_name.as_ref().and_then(|acct| {
                state
                    .hashes
                    .iter()
                    .find(|h| {
                        h.username.to_lowercase() == acct.to_lowercase()
                            && h.hash_type.to_uppercase() == "NTLM"
                    })
                    .cloned()
            });

            if credential.is_none() && hash.is_none() {
                return None;
            }

            let domain = credential
                .as_ref()
                .map(|c| c.domain.clone())
                .or_else(|| hash.as_ref().map(|h| h.domain.clone()))
                .unwrap_or_default();

            let dc_ip = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned();

            Some(S4uWork {
                vuln: vuln.clone(),
                credential,
                hash,
                target_spn,
                domain,
                dc_ip,
            })
        })
        .collect()
}

/// Build the JSON payload submitted to the `exploit` queue for a single
/// S4U attack. Pure — no dispatcher, no IO. Always emits flat fields and
/// — when a credential is attached — a nested `credential` object so
/// downstream structured extraction picks it up.
pub(crate) fn build_s4u_payload(item: &S4uWork) -> Value {
    let mut payload = json!({
        "technique": "s4u_attack",
        "vuln_type": item.vuln.vuln_type,
        "target": item.vuln.target,
        "domain": item.domain,
        "impersonate": "Administrator",
    });

    if let Some(ref spn) = item.target_spn {
        payload["target_spn"] = json!(spn);
    }
    if let Some(ref dc) = item.dc_ip {
        payload["target_ip"] = json!(dc);
    }

    if let Some(ref cred) = item.credential {
        payload["username"] = json!(cred.username);
        payload["password"] = json!(cred.password);
        payload["account_name"] = json!(cred.username);
        payload["credential"] = json!({
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        });
    } else if let Some(ref hash) = item.hash {
        payload["hash"] = json!(hash.hash_value);
        payload["username"] = json!(hash.username);
        payload["auth_method"] = json!("hash");
        payload["note"] = json!(
            "Use --hashes with the NTLM hash for authentication. Do NOT pass an empty password or impacket will prompt interactively and crash."
        );
        if let Some(ref aes) = hash.aes_key {
            payload["aes_key"] = json!(aes);
        }
    }

    payload["vuln_id"] = json!(item.vuln.vuln_id);
    payload
}

/// Check whether a task result matches any of the given error patterns.
///
/// Scans only structured `tool_outputs`. The top-level `error` field carries
/// LLM loop-control/status strings, and scalar `output`/`tool_output` fields
/// are model-authored narrative — neither must drive retry control.
fn result_matches_patterns(result: &ares_core::models::TaskResult, patterns: &[&str]) -> bool {
    let Some(payload) = &result.result else {
        return false;
    };

    if let Some(outputs) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for output in outputs {
            if let Some(text) = output
                .as_str()
                .or_else(|| output.get("output").and_then(|v| v.as_str()))
            {
                if patterns.iter().any(|p| text.contains(p)) {
                    return true;
                }
            }
        }
    }

    false
}

/// Account is permanently disabled — no point retrying.
fn has_permanent_revocation(result: &ares_core::models::TaskResult) -> bool {
    result_matches_patterns(result, PERMANENT_REVOCATION_PATTERNS)
}

/// Account is temporarily locked out — will unlock after AD lockout duration.
fn has_lockout_error(result: &ares_core::models::TaskResult) -> bool {
    result_matches_patterns(result, LOCKOUT_PATTERNS)
}

/// Only a successful S4U task should clear the accumulated failure count.
fn should_reset_failure_count(result: &ares_core::models::TaskResult) -> bool {
    result.success
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::TaskResult;
    use chrono::Utc;
    use serde_json::json;

    fn make_result(result: Option<serde_json::Value>, error: Option<String>) -> TaskResult {
        TaskResult {
            task_id: "t-test".to_string(),
            success: false,
            result,
            error,
            worker_pod: Some("rust-llm-runner".to_string()),
            completed_at: Utc::now(),
        }
    }

    #[test]
    fn s4u_failure_cooldown_is_five_minutes() {
        assert_eq!(S4U_FAILURE_COOLDOWN, Duration::from_secs(300));
    }

    #[test]
    fn s4u_max_failures_value() {
        assert_eq!(S4U_MAX_FAILURES, 6);
    }

    #[test]
    fn permanent_revocation_patterns_contents() {
        assert!(PERMANENT_REVOCATION_PATTERNS.contains(&"STATUS_ACCOUNT_DISABLED"));
        assert!(PERMANENT_REVOCATION_PATTERNS.contains(&"KDC_ERR_KEY_EXPIRED"));
        assert_eq!(PERMANENT_REVOCATION_PATTERNS.len(), 2);
    }

    #[test]
    fn lockout_patterns_contents() {
        assert!(LOCKOUT_PATTERNS.contains(&"KDC_ERR_CLIENT_REVOKED"));
        assert!(LOCKOUT_PATTERNS.contains(&"STATUS_ACCOUNT_LOCKED_OUT"));
        assert_eq!(LOCKOUT_PATTERNS.len(), 2);
    }

    #[test]
    fn result_matches_patterns_no_result_returns_false() {
        let tr = make_result(None, None);
        assert!(!result_matches_patterns(&tr, &["STATUS_ACCOUNT_DISABLED"]));
    }

    #[test]
    fn result_matches_patterns_ignores_error_field() {
        let tr = make_result(
            Some(json!({})),
            Some("Kerberos error: STATUS_ACCOUNT_DISABLED on dc01.contoso.local".to_string()),
        );
        assert!(!result_matches_patterns(&tr, &["STATUS_ACCOUNT_DISABLED"]));
    }

    #[test]
    fn result_matches_patterns_tool_outputs_match() {
        let tr = make_result(
            Some(json!({
                "tool_outputs": [
                    "getST.py completed",
                    "Error from KDC: KDC_ERR_CLIENT_REVOKED for svc_sql@contoso.local"
                ]
            })),
            None,
        );
        assert!(result_matches_patterns(&tr, &["KDC_ERR_CLIENT_REVOKED"]));
    }

    #[test]
    fn result_matches_patterns_tool_outputs_object_match() {
        let tr = make_result(
            Some(json!({
                "tool_outputs": [
                    {"output": "S4U attack failed: STATUS_ACCOUNT_LOCKED_OUT for svc_sql$@contoso.local"}
                ]
            })),
            None,
        );
        assert!(result_matches_patterns(&tr, &["STATUS_ACCOUNT_LOCKED_OUT"]));
    }

    #[test]
    fn result_matches_patterns_ignores_summary_text() {
        let tr = make_result(
            Some(json!({
                "summary": "S4U attack failed: STATUS_ACCOUNT_LOCKED_OUT for svc_sql$@contoso.local"
            })),
            None,
        );
        assert!(!result_matches_patterns(
            &tr,
            &["STATUS_ACCOUNT_LOCKED_OUT"]
        ));
    }

    #[test]
    fn result_matches_patterns_ignores_scalar_output_key() {
        let tr = make_result(
            Some(json!({
                "output": "KDC_ERR_KEY_EXPIRED when requesting TGT for svc_web$@contoso.local"
            })),
            None,
        );
        assert!(!result_matches_patterns(&tr, &["KDC_ERR_KEY_EXPIRED"]));
    }

    #[test]
    fn result_matches_patterns_ignores_scalar_tool_output_key() {
        let tr = make_result(
            Some(json!({
                "tool_output": "STATUS_ACCOUNT_DISABLED: svc_sql@contoso.local disabled in AD"
            })),
            None,
        );
        assert!(!result_matches_patterns(&tr, &["STATUS_ACCOUNT_DISABLED"]));
    }

    #[test]
    fn result_matches_patterns_no_match() {
        let tr = make_result(
            Some(json!({
                "summary": "S4U attack succeeded, got ticket for Administrator@contoso.local",
                "tool_outputs": ["getST.py completed successfully"],
                "output": "Ticket written to /tmp/admin.ccache"
            })),
            Some("timeout after 60s".to_string()),
        );
        assert!(!result_matches_patterns(
            &tr,
            &["STATUS_ACCOUNT_DISABLED", "KDC_ERR_KEY_EXPIRED"]
        ));
    }

    #[test]
    fn result_matches_patterns_tool_outputs_non_string_ignored() {
        // tool_outputs with non-string elements should not panic
        let tr = make_result(
            Some(json!({
                "tool_outputs": [42, null, true, "KDC_ERR_CLIENT_REVOKED"]
            })),
            None,
        );
        assert!(result_matches_patterns(&tr, &["KDC_ERR_CLIENT_REVOKED"]));
    }

    #[test]
    fn has_permanent_revocation_status_account_disabled() {
        let tr = make_result(
            Some(json!({
                "tool_outputs": [
                    {"output": "STATUS_ACCOUNT_DISABLED for svc_sql$@contoso.local"}
                ]
            })),
            None,
        );
        assert!(has_permanent_revocation(&tr));
    }

    #[test]
    fn has_permanent_revocation_kdc_err_key_expired() {
        let tr = make_result(
            Some(json!({
                "tool_outputs": [
                    {"output": "KDC_ERR_KEY_EXPIRED requesting TGT for svc_web$@contoso.local"}
                ]
            })),
            None,
        );
        assert!(has_permanent_revocation(&tr));
    }

    #[test]
    fn has_permanent_revocation_false_for_lockout() {
        let tr = make_result(
            Some(json!({
                "summary": "KDC_ERR_CLIENT_REVOKED for svc_sql@contoso.local"
            })),
            None,
        );
        assert!(!has_permanent_revocation(&tr));
    }

    #[test]
    fn has_lockout_error_kdc_err_client_revoked() {
        let tr = make_result(
            Some(json!({
                "tool_outputs": [
                    {"output": "KDC_ERR_CLIENT_REVOKED requesting TGT for svc_sql@contoso.local"}
                ]
            })),
            None,
        );
        assert!(has_lockout_error(&tr));
    }

    #[test]
    fn has_lockout_error_status_account_locked_out() {
        let tr = make_result(
            Some(json!({
                "tool_outputs": [
                    {"output": "SMB error: STATUS_ACCOUNT_LOCKED_OUT on 192.168.58.10"}
                ]
            })),
            None,
        );
        assert!(has_lockout_error(&tr));
    }

    #[test]
    fn has_lockout_error_false_for_permanent() {
        let tr = make_result(
            Some(json!({
                "summary": "STATUS_ACCOUNT_DISABLED for svc_sql$@contoso.local"
            })),
            None,
        );
        assert!(!has_lockout_error(&tr));
    }

    #[test]
    fn has_lockout_error_false_for_success() {
        let tr = make_result(
            Some(json!({
                "summary": "S4U attack succeeded, ticket for Administrator@contoso.local"
            })),
            None,
        );
        assert!(!has_lockout_error(&tr));
    }

    #[test]
    fn successful_task_resets_failure_count() {
        let tr = TaskResult {
            task_id: "t-ok".to_string(),
            success: true,
            result: Some(json!({"summary": "ticket obtained"})),
            error: None,
            worker_pod: None,
            completed_at: Utc::now(),
        };
        assert!(should_reset_failure_count(&tr));
    }

    #[test]
    fn generic_failure_does_not_reset_failure_count() {
        let tr = TaskResult {
            task_id: "t-fail".to_string(),
            success: false,
            result: Some(json!({"summary": "S4U failed: KRB_AP_ERR_MODIFIED"})),
            error: None,
            worker_pod: None,
            completed_at: Utc::now(),
        };
        assert!(!should_reset_failure_count(&tr));
    }

    // -- helpers for select_s4u_work_items / build_s4u_payload tests --

    fn make_delegation_vuln(
        vuln_id: &str,
        vuln_type: &str,
        account_name: Option<&str>,
        target_spn: Option<&str>,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        if let Some(a) = account_name {
            details.insert("account_name".into(), json!(a));
        }
        if let Some(s) = target_spn {
            details.insert("delegation_target".into(), json!(s));
        }
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: "192.168.58.50".to_string(),
            discovered_by: "test".to_string(),
            discovered_at: Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(user: &str, value: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{user}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    // --- select_s4u_work_items -------------------------------------------

    #[test]
    fn select_skips_non_delegation_vuln_types() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln(
            "v-kerberoast",
            "kerberoastable_account",
            Some("svc_sql"),
            None,
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("svc_sql", "Pw!", "contoso.local"));
        let work = select_s4u_work_items(&s, &HashMap::new(), Instant::now());
        assert!(work.is_empty());
    }

    #[test]
    fn select_skips_already_exploited_vuln() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln(
            "v-constdeleg-svc_sql",
            "constrained_delegation",
            Some("svc_sql"),
            None,
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities
            .insert("v-constdeleg-svc_sql".into());
        s.credentials
            .push(make_cred("svc_sql", "Pw!", "contoso.local"));
        assert!(select_s4u_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_skips_vuln_at_max_failures() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln(
            "v-rbcd-svc_web",
            "rbcd",
            Some("svc_web"),
            Some("CIFS/host.contoso.local"),
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("svc_web", "Pw!", "contoso.local"));
        let mut tracker = HashMap::new();
        tracker.insert("v-rbcd-svc_web".into(), (Instant::now(), S4U_MAX_FAILURES));
        assert!(select_s4u_work_items(&s, &tracker, Instant::now()).is_empty());
    }

    #[test]
    fn select_respects_cooldown_window() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln("v-rbcd-svc_web", "rbcd", Some("svc_web"), None);
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("svc_web", "Pw!", "contoso.local"));
        let now = Instant::now();
        let mut tracker = HashMap::new();
        // Failure 5s ago — well within the 5-minute cooldown.
        tracker.insert("v-rbcd-svc_web".into(), (now - Duration::from_secs(5), 2));
        assert!(select_s4u_work_items(&s, &tracker, now).is_empty());
    }

    #[test]
    fn select_allows_after_cooldown_expires() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln("v-rbcd-svc_web", "rbcd", Some("svc_web"), None);
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("svc_web", "Pw!", "contoso.local"));
        let now = Instant::now();
        let mut tracker = HashMap::new();
        tracker.insert(
            "v-rbcd-svc_web".into(),
            (now - (S4U_FAILURE_COOLDOWN + Duration::from_secs(1)), 2),
        );
        let work = select_s4u_work_items(&s, &tracker, now);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln.vuln_id, "v-rbcd-svc_web");
    }

    #[test]
    fn select_skips_when_no_credential_or_hash_available() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln(
            "v-constdeleg-svc_sql",
            "constrained_delegation",
            Some("svc_sql"),
            None,
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        // No matching credential or hash.
        assert!(select_s4u_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_uses_capitalized_account_name_fallback() {
        let mut s = StateInner::new("op-test".into());
        let mut details = std::collections::HashMap::new();
        details.insert("AccountName".into(), json!("svc_sql"));
        details.insert("AllowedToDelegate".into(), json!("CIFS/host.contoso.local"));
        let v = ares_core::models::VulnerabilityInfo {
            vuln_id: "v-cap".into(),
            vuln_type: "constrained_delegation".into(),
            target: "192.168.58.50".into(),
            discovered_by: "test".into(),
            discovered_at: Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("svc_sql", "Pw!", "contoso.local"));
        let work = select_s4u_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 1);
        assert_eq!(
            work[0].target_spn.as_deref(),
            Some("CIFS/host.contoso.local")
        );
    }

    #[test]
    fn select_picks_credential_case_insensitively() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln("v-rbcd-SvcSql", "rbcd", Some("SvcSql"), None);
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("svcsql", "Pw!", "contoso.local"));
        let work = select_s4u_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.as_ref().unwrap().username, "svcsql");
    }

    #[test]
    fn select_falls_back_to_ntlm_hash_when_no_password_cred() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln("v-rbcd-svc", "rbcd", Some("svc"), None);
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hashes.push(make_hash("svc", "deadbeef", "contoso.local"));
        let work = select_s4u_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 1);
        assert!(work[0].credential.is_none());
        assert!(work[0].hash.is_some());
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn select_skips_non_ntlm_hashes() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln("v-rbcd-svc", "rbcd", Some("svc"), None);
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let mut h = make_hash("svc", "deadbeef", "contoso.local");
        h.hash_type = "AES256".into();
        s.hashes.push(h);
        assert!(select_s4u_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_populates_dc_ip_from_domain_controllers() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln("v-rbcd-svc", "rbcd", Some("svc"), None);
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials.push(make_cred("svc", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_s4u_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work[0].dc_ip.as_deref(), Some("192.168.58.10"));
    }

    #[test]
    fn select_skips_vuln_without_account_name() {
        let mut s = StateInner::new("op-test".into());
        let v = make_delegation_vuln(
            "v-rbcd-no-acct",
            "rbcd",
            None,
            Some("CIFS/host.contoso.local"),
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        // No account_name → can't match a credential → skipped.
        assert!(select_s4u_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_accepts_constrained_delegation_and_rbcd_only() {
        let mut s = StateInner::new("op-test".into());
        let cd = make_delegation_vuln("v-cd", "Constrained_Delegation", Some("svc1"), None);
        let rbcd = make_delegation_vuln("v-rb", "RBCD", Some("svc2"), None);
        s.discovered_vulnerabilities.insert(cd.vuln_id.clone(), cd);
        s.discovered_vulnerabilities
            .insert(rbcd.vuln_id.clone(), rbcd);
        s.credentials
            .push(make_cred("svc1", "Pw1", "contoso.local"));
        s.credentials
            .push(make_cred("svc2", "Pw2", "contoso.local"));
        let work = select_s4u_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 2);
    }

    // --- build_s4u_payload -----------------------------------------------

    fn work_with_credential() -> S4uWork {
        let vuln = make_delegation_vuln(
            "v-cd",
            "constrained_delegation",
            Some("svc_sql"),
            Some("CIFS/dc01.contoso.local"),
        );
        S4uWork {
            vuln,
            credential: Some(make_cred("svc_sql", "P@ssw0rd!", "contoso.local")),
            hash: None,
            target_spn: Some("CIFS/dc01.contoso.local".to_string()),
            domain: "contoso.local".into(),
            dc_ip: Some("192.168.58.10".into()),
        }
    }

    #[test]
    fn build_payload_emits_credential_fields() {
        let p = build_s4u_payload(&work_with_credential());
        assert_eq!(p["technique"], "s4u_attack");
        assert_eq!(p["vuln_type"], "constrained_delegation");
        assert_eq!(p["target"], "192.168.58.50");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["impersonate"], "Administrator");
        assert_eq!(p["target_spn"], "CIFS/dc01.contoso.local");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["username"], "svc_sql");
        assert_eq!(p["password"], "P@ssw0rd!");
        assert_eq!(p["account_name"], "svc_sql");
        assert_eq!(p["credential"]["username"], "svc_sql");
        assert_eq!(p["credential"]["domain"], "contoso.local");
        assert_eq!(p["vuln_id"], "v-cd");
        assert!(p.get("hash").is_none());
        assert!(p.get("auth_method").is_none());
    }

    #[test]
    fn build_payload_emits_hash_fields_when_no_credential() {
        let mut w = work_with_credential();
        w.credential = None;
        w.hash = Some(make_hash("svc_sql", "deadbeef", "contoso.local"));
        let p = build_s4u_payload(&w);
        assert_eq!(p["username"], "svc_sql");
        assert_eq!(p["hash"], "deadbeef");
        assert_eq!(p["auth_method"], "hash");
        assert!(p["note"].as_str().unwrap().contains("--hashes"));
        assert!(p.get("password").is_none());
        assert!(p.get("credential").is_none());
    }

    #[test]
    fn build_payload_includes_aes_key_from_hash() {
        let mut w = work_with_credential();
        w.credential = None;
        let mut h = make_hash("svc_sql", "deadbeef", "contoso.local");
        h.aes_key = Some("a".repeat(64));
        w.hash = Some(h);
        let p = build_s4u_payload(&w);
        assert_eq!(p["aes_key"], "a".repeat(64));
    }

    #[test]
    fn build_payload_omits_target_spn_when_unknown() {
        let mut w = work_with_credential();
        w.target_spn = None;
        let p = build_s4u_payload(&w);
        assert!(p.get("target_spn").is_none());
    }

    #[test]
    fn build_payload_omits_target_ip_when_no_dc_ip() {
        let mut w = work_with_credential();
        w.dc_ip = None;
        let p = build_s4u_payload(&w);
        assert!(p.get("target_ip").is_none());
    }

    #[test]
    fn build_payload_prefers_credential_over_hash() {
        let mut w = work_with_credential();
        // Both present — credential branch must win and hash field must not appear.
        w.hash = Some(make_hash("svc_sql", "deadbeef", "contoso.local"));
        let p = build_s4u_payload(&w);
        assert_eq!(p["password"], "P@ssw0rd!");
        assert!(p.get("hash").is_none());
        assert!(p.get("auth_method").is_none());
    }
}
