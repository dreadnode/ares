//! NATS-backed tool dispatcher for the LLM agent loop.
//!
//! Implements `ares_llm::ToolDispatcher` by issuing a NATS request to
//! `ares.tools.exec.{role}` and awaiting the worker reply on the
//! auto-generated reply inbox.
//!
//! Rust workers subscribe to `ares.tools.exec.{role}` as a queue group,
//! invoke the tool via `ares_tools::dispatch`, and reply on the inbox.
//!
//! Also provides [`LocalToolDispatcher`] for in-process execution without
//! going through NATS, useful for testing or single-binary deployments.

use redis::aio::ConnectionLike;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::orchestrator::state::{SharedState, DISCOVERY_KEY_PREFIX};
use crate::orchestrator::task_queue::TaskQueueCore;

mod auth_throttle;
mod domain_validator;
mod local;
mod redis_dispatcher;
#[cfg(test)]
mod tests;

pub use auth_throttle::AuthThrottle;
pub use local::LocalToolDispatcher;
pub use redis_dispatcher::RedisToolDispatcher;

/// Message pushed to the tool execution queue.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolExecRequest {
    pub call_id: String,
    pub task_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// W3C traceparent header for cross-service span linking.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub traceparent: Option<String>,
    /// Operation ID for span correlation with dashboards.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation_id: Option<String>,
}

/// Message returned by the worker on the result mailbox.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolExecResponse {
    pub call_id: String,
    pub output: String,
    pub error: Option<String>,
    /// Structured discoveries parsed by the worker from tool output.
    #[serde(default)]
    pub discoveries: Option<serde_json::Value>,
    /// Typed classification of a failure, when the worker resolved one.
    /// `None` on success and for legacy workers that predate the field —
    /// the runner's pruning check falls back to string matching in that
    /// case (see `runner.rs` around the ENOENT prune site).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<ares_llm::ToolFailureKind>,
}

/// Default timeout waiting for a tool result (95 minutes).
/// Must exceed queue wait time + longest tool runtime. AES Kerberoast defaults
/// to a 45-minute pass and can queue behind one AES-exclusive job, so this is
/// 2x runtime plus buffer.
pub(super) const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 95 * 60;

/// Tools that require netexec/ldapsearch and must be routed to the recon
/// worker queue regardless of the calling agent's role.
const RECON_ROUTED_TOOLS: &[&str] = &[
    "ldap_search_descriptions",
    "password_spray",
    "username_as_password",
    "gpp_password_finder",
    "sysvol_script_search",
    "password_policy",
    "laps_dump",
    "smbclient_spider",
    "check_credman_entries",
    "check_autologon_registry",
    "smb_login_check",
    "domain_admin_checker",
    "gmsa_dump_passwords",
];

/// Tools that authenticate against AD targets. Tool calls with these names
/// are subject to per-credential rate limiting to avoid account lockout.
const AUTH_BEARING_TOOLS: &[&str] = &[
    // netexec tools (each invocation is a separate SMB/LDAP auth)
    "ldap_search_descriptions",
    "password_spray",
    "username_as_password",
    "gpp_password_finder",
    "sysvol_script_search",
    "password_policy",
    "laps_dump",
    "smbclient_spider",
    "check_credman_entries",
    "check_autologon_registry",
    "smb_login_check",
    "domain_admin_checker",
    "gmsa_dump_passwords",
    // impacket tools
    "secretsdump",
    "secretsdump_kerberos",
    "kerberoast",
    "asrep_roast",
    "lsassy",
    "ntds_dit_extract",
    // lateral tools (auth per target)
    "smbexec",
    "psexec",
    "wmiexec",
    "dcomexec",
    "atexec",
    "smbclient_kerberos_shares",
];

/// Spray-style tools that accept `excluded_users` to skip already-locked
/// accounts. The dispatcher auto-injects the current quarantine list so the
/// LLM cannot omit it (or pass a stale value) and re-lock those accounts.
const SPRAY_TOOLS: &[&str] = &["password_spray", "username_as_password"];

/// Merge the current per-domain quarantine list into `excluded_users` on
/// spray-style tool calls. Mutates `arguments` in place; no-op for tools
/// outside `SPRAY_TOOLS`, when `state` is unset, or when no domain arg is
/// present. Preserves any LLM-supplied `excluded_users` by union-merging.
pub(super) async fn inject_excluded_users(
    state: &Option<SharedState>,
    tool_name: &str,
    arguments: &mut serde_json::Value,
) {
    if !SPRAY_TOOLS.contains(&tool_name) {
        return;
    }
    let Some(state) = state else { return };
    let Some(domain) = arguments
        .get("domain")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return;
    };
    let quarantined = state.read().await.quarantined_principals_in_domain(&domain);
    if quarantined.is_empty() {
        return;
    }

    let existing = arguments
        .get("excluded_users")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut set: std::collections::BTreeSet<String> =
        quarantined.iter().map(|u| u.to_lowercase()).collect();
    for u in existing.split(',') {
        let trimmed = u.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_lowercase());
        }
    }
    let merged: Vec<String> = set.into_iter().collect();
    if let Some(obj) = arguments.as_object_mut() {
        obj.insert(
            "excluded_users".to_string(),
            serde_json::Value::String(merged.join(",")),
        );
        debug!(
            tool = %tool_name,
            domain = %domain,
            count = merged.len(),
            "Auto-injected excluded_users from quarantine"
        );
    }
}

/// Observation window to hold spray attempts against, in seconds.
///
/// Prefers the domain's real `lockoutObservationWindow` when `password_policy`
/// supplied it, because that is the only value AD actually resets on.
fn spray_window_secs(arguments: &serde_json::Value) -> i64 {
    if let Some(mins) = arguments
        .get("lockout_observation_window_mins")
        .and_then(|v| v.as_i64())
        .filter(|m| *m > 0)
    {
        return mins * 60;
    }
    super::config::parse_env("ARES_SPRAY_WINDOW_SECS", 1800)
}

/// Enforce the per-domain lockout budget across spray calls.
///
/// `password_spray` caps the passwords it tries per call, but the cap is
/// computed from `attempts_used_per_account` — an argument the LLM supplies
/// and, in practice, re-reports as 0 on every call. Several capped sprays in
/// one observation window then sum past the lockout threshold, which is what
/// locked the range out. This overrides that argument with the server-side
/// tally and debits the tally by what the call is about to spend.
///
/// Mutates `arguments` in place; no-op for tools outside `SPRAY_TOOLS`, when
/// `state` is unset, or when no domain arg is present.
pub(super) async fn inject_spray_attempts(
    state: &Option<SharedState>,
    tool_name: &str,
    arguments: &mut serde_json::Value,
) {
    if !SPRAY_TOOLS.contains(&tool_name) {
        return;
    }
    let Some(state) = state else { return };
    let Some(domain) = arguments
        .get("domain")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return;
    };

    // One exclusive guard spans the read and the debit. Taking a read lock,
    // computing, then taking a write lock leaves a window where every
    // concurrent agent observes the same stale tally, each believes it has the
    // full budget, and their sprays sum past the threshold — the exact race
    // the tally exists to close. `spray_attempt_cost` is pure and sync, so
    // nothing awaits while the guard is held.
    let mut guard = state.write().await;
    let tallied = guard.spray_attempts_used(&domain);

    // The observed policy outranks the agent's argument. `check_spray_budget`
    // reads `lockout_threshold <= 0` as "this domain has no lockout, spray
    // freely", so an agent that guesses 0 — or omits the field after a policy
    // read already landed — removes the only guard against locking out a live
    // domain. Overriding here is the same move `attempts_used_per_account`
    // already makes: the server-side observation wins over the claim.
    if let Some(observed) = guard.password_policy_threshold(&domain) {
        let claimed_threshold = arguments.get("lockout_threshold").and_then(|v| v.as_i64());
        if claimed_threshold != Some(observed) {
            if let Some(obj) = arguments.as_object_mut() {
                obj.insert(
                    "lockout_threshold".to_string(),
                    serde_json::Value::from(observed),
                );
            }
            debug!(
                tool = %tool_name,
                domain = %domain,
                claimed = ?claimed_threshold,
                observed,
                "Overrode lockout_threshold with the observed password policy"
            );
        }
    }

    // Every spray-style tool gets the tally injected, so each one can refuse
    // itself once the budget is spent. Injecting for only some of them is what
    // let `username_as_password` spend budget it could never be denied: the
    // dispatcher debited it, nothing could decline it, and it quietly tightened
    // `password_spray`'s allowance while staying free itself.
    //
    // Keep the LLM's figure when it is the larger one: it may know about
    // attempts this tally never saw (a prior operation, a manual spray).
    let claimed = arguments
        .get("attempts_used_per_account")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let effective = tallied.max(claimed);
    if let Some(obj) = arguments.as_object_mut() {
        obj.insert(
            "attempts_used_per_account".to_string(),
            serde_json::Value::from(effective),
        );
    }

    let cost = if tool_name == "password_spray" {
        ares_tools::credential_access::spray_attempt_cost(arguments, effective) as i64
    } else {
        // `username_as_password` tries exactly one password per account (the
        // account's own name). It costs 1 when it will actually run, and 0
        // once the budget is spent — the tool refuses at that point, and a
        // refused call authenticates against nothing.
        i64::from(ares_tools::credential_access::spray_budget_allows(
            arguments, effective,
        ))
    };

    if cost > 0 {
        let window = spray_window_secs(arguments);
        guard.record_spray_attempts(&domain, cost, window);
        drop(guard);
        debug!(
            tool = %tool_name,
            domain = %domain,
            tallied,
            cost,
            window_secs = window,
            "Debited per-domain spray lockout budget"
        );
    }
}

/// Extract a credential key from tool call arguments for rate limiting.
/// Returns `Some("user@domain")` if the tool authenticates with credentials.
pub(super) fn extract_credential_key(call: &ares_llm::ToolCall) -> Option<String> {
    if !AUTH_BEARING_TOOLS.contains(&call.name.as_str()) {
        return None;
    }
    let username = call.arguments.get("username").and_then(|v| v.as_str())?;
    let domain = call
        .arguments
        .get("domain")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");
    Some(format!(
        "{}@{}",
        username.to_lowercase(),
        domain.to_lowercase()
    ))
}

/// Resolve the actual worker queue for a tool call.
///
/// Most tools go to the calling agent's role queue. Netexec-dependent tools
/// are cross-routed to the `recon` queue where the binary exists.
pub(super) fn resolve_queue_role<'a>(role: &'a str, tool_name: &str) -> &'a str {
    if role != "recon" && RECON_ROUTED_TOOLS.contains(&tool_name) {
        "recon"
    } else {
        role
    }
}

/// Push structured discoveries from a tool result to the real-time
/// discovery list so the discovery poller publishes them to state.
///
/// `tool_args` carries the tool call's input arguments — used to extract
/// the authenticating credential (username/domain) for lineage tracking.
pub(super) async fn push_realtime_discoveries<C>(
    queue: &TaskQueueCore<C>,
    operation_id: &str,
    discoveries: &serde_json::Value,
    tool_name: &str,
    tool_args: &serde_json::Value,
) where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    let discovery_key = format!("{DISCOVERY_KEY_PREFIX}:{operation_id}");
    let mut conn = queue.connection();

    // Extract input credential context for lineage tracking
    let input_username = tool_args
        .get("username")
        .or_else(|| tool_args.get("user"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input_domain = tool_args
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Push each discovery type as individual entries
    let type_map: &[(&str, &str)] = &[
        ("hosts", "host"),
        ("credentials", "credential"),
        ("hashes", "hash"),
        ("vulnerabilities", "vulnerability"),
        ("shares", "share"),
        ("discovered_users", "user"),
        ("trusted_domains", "trust"),
    ];

    let mut pushed = 0usize;
    for &(key, disc_type) in type_map {
        if let Some(items) = discoveries.get(key).and_then(|v| v.as_array()) {
            for item in items {
                let mut entry = serde_json::json!({
                    "type": disc_type,
                    "data": item,
                    "source_tool": tool_name,
                });
                // Attach input credential context for lineage resolution
                if !input_username.is_empty() {
                    entry["input_username"] = serde_json::Value::String(input_username.to_string());
                    entry["input_domain"] = serde_json::Value::String(input_domain.to_string());
                }
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _: anyhow::Result<(), _> = conn.lpush(&discovery_key, &json).await;
                    pushed += 1;
                }
            }
        }
    }

    if pushed > 0 {
        debug!(
            count = pushed,
            tool = tool_name,
            "Pushed real-time discoveries"
        );
    }
}
