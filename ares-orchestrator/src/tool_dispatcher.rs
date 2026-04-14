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

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, warn, Instrument};

use ares_core::telemetry::propagation::inject_traceparent;
use ares_core::telemetry::spans::{producer_span, Team};
use ares_llm::{ToolCall, ToolExecResult};

use crate::state::DISCOVERY_KEY_PREFIX;
use crate::task_queue::TaskQueue;

/// Prefix for tool execution request queues.
const TOOL_EXEC_PREFIX: &str = "ares:tool_exec";

/// Prefix for per-call result mailboxes.
const TOOL_RESULT_PREFIX: &str = "ares:tool_results";

/// TTL for result keys (1 hour).
const RESULT_TTL_SECS: u64 = 3600;

/// Default timeout waiting for a tool result (25 minutes).
/// Must exceed queue wait time + longest tool runtime (hashcat can queue
/// behind another hashcat, so 2x runtime + buffer).
const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 1500;

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
// Dispatcher implementation
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

// ---------------------------------------------------------------------------
// Credential auth throttle — prevents AD account lockout
// ---------------------------------------------------------------------------

/// Per-credential auth attempt tracker.
///
/// Tracks timestamps of auth-bearing tool dispatches keyed by `user@domain`.
/// Before dispatching, callers must call `acquire()` which sleeps if the
/// credential has been used too many times within the observation window.
///
/// Default policy: max 3 auth attempts per credential per 60-second window.
/// This stays well under the typical AD lockout threshold (5 in 5 min).
#[derive(Clone)]
pub struct AuthThrottle {
    inner: Arc<Mutex<AuthThrottleInner>>,
}

struct AuthThrottleInner {
    /// `credential_key` → Vec of timestamps
    attempts: std::collections::HashMap<String, Vec<Instant>>,
    /// Max auth attempts per credential within the observation window.
    max_attempts: usize,
    /// Observation window for rate limiting.
    window: Duration,
}

impl AuthThrottle {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuthThrottleInner {
                attempts: std::collections::HashMap::new(),
                max_attempts,
                window,
            })),
        }
    }

    /// Acquire permission to dispatch an auth-bearing tool call.
    /// Sleeps if the credential has hit the rate limit within the window.
    pub async fn acquire(&self, credential_key: &str) {
        loop {
            let sleep_dur = {
                let mut inner = self.inner.lock().await;
                let now = Instant::now();
                let max_attempts = inner.max_attempts;
                let window = inner.window;

                let timestamps = inner
                    .attempts
                    .entry(credential_key.to_string())
                    .or_default();

                // Prune expired entries
                timestamps.retain(|t| now.duration_since(*t) < window);

                if timestamps.len() < max_attempts {
                    // Under the limit — record this attempt and proceed
                    timestamps.push(now);
                    return;
                }

                // Over the limit — calculate how long to wait until the oldest
                // attempt falls outside the window
                let oldest = timestamps[0];
                let elapsed = now.duration_since(oldest);
                if elapsed >= window {
                    // Edge case: already expired, prune and retry
                    timestamps.remove(0);
                    timestamps.push(now);
                    return;
                }

                window - elapsed + Duration::from_millis(100)
            };

            debug!(
                credential = credential_key,
                wait_secs = sleep_dur.as_secs_f32(),
                "Auth throttle: delaying tool dispatch to avoid account lockout"
            );
            tokio::time::sleep(sleep_dur).await;
        }
    }
}

/// Extract a credential key from tool call arguments for rate limiting.
/// Returns `Some("user@domain")` if the tool authenticates with credentials.
fn extract_credential_key(call: &ToolCall) -> Option<String> {
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
fn resolve_queue_role<'a>(role: &'a str, tool_name: &str) -> &'a str {
    if role != "recon" && RECON_ROUTED_TOOLS.contains(&tool_name) {
        "recon"
    } else {
        role
    }
}

/// Dispatches tool calls to workers via Redis queues.
///
/// When tool results contain structured discoveries (hosts, credentials, etc.),
/// they are pushed to the `ares:discoveries:{op_id}` list for real-time
/// processing by the discovery poller — ensuring discoveries reach state
/// immediately rather than waiting for the task result consumer.
pub struct RedisToolDispatcher {
    queue: TaskQueue,
    tool_timeout: Duration,
    operation_id: String,
    auth_throttle: AuthThrottle,
}

impl RedisToolDispatcher {
    pub fn new(queue: TaskQueue, operation_id: String, auth_throttle: AuthThrottle) -> Self {
        Self {
            queue,
            tool_timeout: Duration::from_secs(DEFAULT_TOOL_TIMEOUT_SECS),
            operation_id,
            auth_throttle,
        }
    }

    #[allow(dead_code)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.tool_timeout = timeout;
        self
    }

    /// Push structured discoveries from a tool result to the real-time
    /// discovery list so the discovery poller publishes them to state.
    ///
    /// `tool_args` carries the tool call's input arguments — used to extract
    /// the authenticating credential (username/domain) for lineage tracking.
    async fn push_realtime_discoveries(
        &self,
        discoveries: &serde_json::Value,
        tool_name: &str,
        tool_args: &serde_json::Value,
    ) {
        let discovery_key = format!("{DISCOVERY_KEY_PREFIX}:{}", self.operation_id);
        let mut conn = self.queue.connection();

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
                        entry["input_username"] =
                            serde_json::Value::String(input_username.to_string());
                        entry["input_domain"] = serde_json::Value::String(input_domain.to_string());
                    }
                    if let Ok(json) = serde_json::to_string(&entry) {
                        let _: Result<(), _> = conn.lpush(&discovery_key, &json).await;
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
}

#[async_trait::async_trait]
impl ares_llm::ToolDispatcher for RedisToolDispatcher {
    async fn dispatch_tool(
        &self,
        role: &str,
        task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        let effective_role = resolve_queue_role(role, &call.name);
        let span = producer_span(
            &format!("dispatch.{}", call.name),
            role,
            Team::Red,
            &format!("ares-worker-{effective_role}"),
        );

        async {
            // Rate-limit auth-bearing tools to prevent AD account lockout
            if let Some(cred_key) = extract_credential_key(call) {
                self.auth_throttle.acquire(&cred_key).await;
            }

            let call_id = format!("{}_{}", call.name, uuid::Uuid::new_v4().simple());

            // Inject trace context for cross-service span linking
            let traceparent = inject_traceparent(&tracing::Span::current());

            let request = ToolExecRequest {
                call_id: call_id.clone(),
                task_id: task_id.to_string(),
                tool_name: call.name.clone(),
                arguments: call.arguments.clone(),
                traceparent,
            };

            let queue_key = format!("{TOOL_EXEC_PREFIX}:{effective_role}");
            let result_key = format!("{TOOL_RESULT_PREFIX}:{call_id}");
            let payload =
                serde_json::to_string(&request).context("Failed to serialize tool exec request")?;

            debug!(
                tool = %call.name,
                call_id = %call_id,
                queue = %queue_key,
                effective_role = %effective_role,
                "Dispatching tool call to worker"
            );

            // Push request to worker queue
            let mut conn = self.queue.connection();
            conn.lpush::<_, _, ()>(&queue_key, &payload)
                .await
                .context("Failed to push tool exec request to Redis")?;

            // Wait for result with timeout
            let timeout_secs = self.tool_timeout.as_secs().max(1) as f64;
            let brpop_result: Option<(String, String)> = redis::cmd("BRPOP")
                .arg(&result_key)
                .arg(timeout_secs)
                .query_async(&mut conn)
                .await
                .context("BRPOP failed for tool result")?;

            match brpop_result {
                Some((_key, value)) => {
                    let response: ToolExecResponse = serde_json::from_str(&value)
                        .context("Failed to deserialize tool exec response")?;

                    debug!(
                        tool = %call.name,
                        call_id = %call_id,
                        has_error = response.error.is_some(),
                        "Tool result received"
                    );

                    // Push discoveries to the real-time discovery list so
                    // the discovery poller publishes them to state immediately,
                    // independent of the task result consumer.
                    if let Some(ref disc) = response.discoveries {
                        self.push_realtime_discoveries(disc, &call.name, &call.arguments)
                            .await;
                    }

                    Ok(ToolExecResult {
                        output: response.output,
                        error: response.error,
                        discoveries: response.discoveries,
                    })
                }
                None => {
                    warn!(
                        tool = %call.name,
                        call_id = %call_id,
                        timeout_secs = timeout_secs,
                        "Tool execution timed out"
                    );

                    // Clean up any late result
                    let _: Result<(), _> = conn
                        .expire::<_, ()>(&result_key, RESULT_TTL_SECS as i64)
                        .await;

                    Ok(ToolExecResult {
                        output: String::new(),
                        error: Some(format!(
                            "Tool '{}' timed out after {timeout_secs}s",
                            call.name
                        )),
                        discoveries: None,
                    })
                }
            }
        }
        .instrument(span)
        .await
    }
}

// ---------------------------------------------------------------------------
// Local (in-process) tool dispatcher
// ---------------------------------------------------------------------------

/// Dispatches tool calls directly via `ares_tools::dispatch` without Redis.
///
/// Useful for testing, single-binary deployments, or when workers are
/// colocated in the same process as the orchestrator.
pub struct LocalToolDispatcher {
    queue: TaskQueue,
    operation_id: String,
    auth_throttle: AuthThrottle,
}

impl LocalToolDispatcher {
    pub fn new(queue: TaskQueue, operation_id: String, auth_throttle: AuthThrottle) -> Self {
        Self {
            queue,
            operation_id,
            auth_throttle,
        }
    }

    /// Push discoveries to the real-time discovery list (same as RedisToolDispatcher).
    async fn push_realtime_discoveries(
        &self,
        discoveries: &serde_json::Value,
        tool_name: &str,
        tool_args: &serde_json::Value,
    ) {
        let discovery_key = format!("{DISCOVERY_KEY_PREFIX}:{}", self.operation_id);
        let mut conn = self.queue.connection();

        let input_username = tool_args
            .get("username")
            .or_else(|| tool_args.get("user"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let input_domain = tool_args
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("");

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
                    if !input_username.is_empty() {
                        entry["input_username"] =
                            serde_json::Value::String(input_username.to_string());
                        entry["input_domain"] = serde_json::Value::String(input_domain.to_string());
                    }
                    if let Ok(json) = serde_json::to_string(&entry) {
                        let _: Result<(), _> = conn.lpush(&discovery_key, &json).await;
                        pushed += 1;
                    }
                }
            }
        }

        if pushed > 0 {
            debug!(
                count = pushed,
                tool = tool_name,
                "Pushed real-time discoveries (local)"
            );
        }
    }
}

#[async_trait::async_trait]
impl ares_llm::ToolDispatcher for LocalToolDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        // Rate-limit auth-bearing tools to prevent AD account lockout
        if let Some(cred_key) = extract_credential_key(call) {
            self.auth_throttle.acquire(&cred_key).await;
        }

        debug!(tool = %call.name, "Executing tool locally");

        match ares_tools::dispatch(&call.name, &call.arguments).await {
            Ok(output) => {
                let raw = output.combined_raw();
                let combined = output.combined();
                let error = if output.success {
                    None
                } else {
                    Some(format!("tool exited with code {:?}", output.exit_code))
                };

                // Parse structured discoveries from raw (unfiltered) output
                let discoveries =
                    ares_tools::parsers::parse_tool_output(&call.name, &raw, &call.arguments);
                let discoveries = if discoveries.as_object().is_none_or(|o| o.is_empty()) {
                    None
                } else {
                    Some(discoveries)
                };

                // Push discoveries to real-time list immediately (like RedisToolDispatcher)
                if let Some(ref disc) = discoveries {
                    self.push_realtime_discoveries(disc, &call.name, &call.arguments)
                        .await;
                }

                Ok(ToolExecResult {
                    output: combined,
                    error,
                    discoveries,
                })
            }
            Err(e) => Ok(ToolExecResult {
                output: String::new(),
                error: Some(e.to_string()),
                discoveries: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_exec_request_serialization() {
        let req = ToolExecRequest {
            call_id: "nmap_scan_abc123".into(),
            task_id: "recon_def456".into(),
            tool_name: "nmap_scan".into(),
            arguments: serde_json::json!({"target": "192.168.1.0/24"}),
            traceparent: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: ToolExecRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.call_id, "nmap_scan_abc123");
        assert_eq!(parsed.tool_name, "nmap_scan");
    }

    #[test]
    fn test_tool_exec_response_deserialization() {
        let json = r#"{"call_id":"nmap_scan_abc","output":"Found 5 hosts","error":null}"#;
        let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.output, "Found 5 hosts");
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_tool_exec_response_with_error() {
        let json = r#"{"call_id":"x","output":"","error":"Connection refused"}"#;
        let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error.as_deref(), Some("Connection refused"));
    }

    #[test]
    fn test_cross_role_routing_netexec_tools() {
        // Netexec tools called from credential_access should route to recon
        assert_eq!(
            resolve_queue_role("credential_access", "password_spray"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "username_as_password"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "ldap_search_descriptions"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "gpp_password_finder"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "sysvol_script_search"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "laps_dump"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "smbclient_spider"),
            "recon"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "password_policy"),
            "recon"
        );
    }

    #[test]
    fn test_cross_role_routing_native_tools_stay() {
        // Tools native to credential_access should stay on credential_access
        assert_eq!(
            resolve_queue_role("credential_access", "secretsdump"),
            "credential_access"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "kerberoast"),
            "credential_access"
        );
        assert_eq!(
            resolve_queue_role("credential_access", "lsassy"),
            "credential_access"
        );
    }

    #[test]
    fn test_cross_role_routing_recon_stays_recon() {
        // When recon itself calls these tools, they stay on recon
        assert_eq!(resolve_queue_role("recon", "password_spray"), "recon");
        assert_eq!(resolve_queue_role("recon", "nmap_scan"), "recon");
        assert_eq!(
            resolve_queue_role("recon", "ldap_search_descriptions"),
            "recon"
        );
    }
}
