//! Redis-backed tool dispatcher for the LLM agent loop.
//!
//! Implements `ares_llm::ToolDispatcher` by pushing individual tool calls
//! to a Redis queue (`ares:tool_exec:{role}`) and waiting for results
//! on a per-call mailbox (`ares:tool_results:{call_id}`).
//!
//! Rust workers run a tool executor that BRPOPs from `tool_exec`,
//! invokes the tool via `ares_tools::dispatch`, and LPUSHes the result.
//!
//! Also provides [`LocalToolDispatcher`] for in-process execution without
//! going through Redis, useful for testing or single-binary deployments.

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::state::DISCOVERY_KEY_PREFIX;
use crate::task_queue::TaskQueue;

mod auth_throttle;
mod local;
mod redis_dispatcher;
#[cfg(test)]
mod tests;

pub use auth_throttle::AuthThrottle;
pub use local::LocalToolDispatcher;
pub use redis_dispatcher::RedisToolDispatcher;

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

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
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix for tool execution request queues.
pub(super) const TOOL_EXEC_PREFIX: &str = "ares:tool_exec";

/// Prefix for per-call result mailboxes.
pub(super) const TOOL_RESULT_PREFIX: &str = "ares:tool_results";

/// TTL for result keys (1 hour).
pub(super) const RESULT_TTL_SECS: u64 = 3600;

/// Default timeout waiting for a tool result (25 minutes).
/// Must exceed queue wait time + longest tool runtime (hashcat can queue
/// behind another hashcat, so 2x runtime + buffer).
pub(super) const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 1500;

// ---------------------------------------------------------------------------
// Dispatcher helpers
// ---------------------------------------------------------------------------

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
pub(super) async fn push_realtime_discoveries(
    queue: &TaskQueue,
    operation_id: &str,
    discoveries: &serde_json::Value,
    tool_name: &str,
    tool_args: &serde_json::Value,
) {
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
