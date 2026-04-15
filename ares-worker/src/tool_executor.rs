//! Thin tool executor loop for LLM-driven orchestration.
//!
//! When the Rust orchestrator drives agent loops via `ARES_LLM_MODEL`, it
//! dispatches individual tool calls to `ares:tool_exec:{role}` and waits
//! for results on `ares:tool_results:{call_id}`.
//!
//! This module implements the worker-side consumer:
//!
//! ```text
//! loop {
//!     1. BRPOP from ares:tool_exec:{role}
//!     2. Deserialize ToolExecRequest
//!     3. Execute tool via ares_tools::dispatch()
//!     4. Serialize ToolExecResponse
//!     5. LPUSH to ares:tool_results:{call_id}
//! }
//! ```
//!

use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn, Instrument};

use ares_core::telemetry::propagation::set_span_parent;
use ares_core::telemetry::spans::{trace_discovery, AgentSpanBuilder, SpanKind, Team};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

use crate::config::WorkerConfig;
use crate::heartbeat::WorkerStatus;

// ─── Redis key prefixes (must match orchestrator's tool_dispatcher.rs) ───────

const TOOL_EXEC_PREFIX: &str = "ares:tool_exec";
const TOOL_RESULT_PREFIX: &str = "ares:tool_results";

/// TTL for result keys (1 hour) — matches orchestrator's RESULT_TTL_SECS.
const RESULT_TTL: i64 = 3600;

// ─── Wire types (match orchestrator's tool_dispatcher.rs exactly) ────────────

/// Request from the orchestrator's RedisToolDispatcher.
#[derive(Debug, Deserialize)]
struct ToolExecRequest {
    call_id: String,
    task_id: String,
    tool_name: String,
    arguments: serde_json::Value,
    /// W3C traceparent header for cross-service span linking.
    #[serde(default)]
    traceparent: Option<String>,
    /// Operation ID for span correlation with dashboards.
    #[serde(default)]
    operation_id: Option<String>,
}

/// Response pushed back to the orchestrator.
#[derive(Debug, Serialize)]
struct ToolExecResponse {
    call_id: String,
    output: String,
    error: Option<String>,
    /// Structured discoveries parsed from the tool output.
    #[serde(skip_serializing_if = "Option::is_none")]
    discoveries: Option<serde_json::Value>,
}

// ─── Tool executor loop ─────────────────────────────────────────────────────

/// Run the tool execution loop until shutdown is signalled.
///
/// Consumes individual tool call requests from `ares:tool_exec:{role}` and
/// dispatches them directly to `ares_tools::dispatch()`. Results are pushed
/// back to the per-call mailbox `ares:tool_results:{call_id}`.
pub async fn run_tool_exec_loop(
    config: &WorkerConfig,
    conn: redis::aio::ConnectionManager,
    status_tx: tokio::sync::watch::Sender<WorkerStatus>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let queue_key = format!("{TOOL_EXEC_PREFIX}:{}", config.worker_role);
    info!(
        queue = %queue_key,
        agent = %config.agent_name,
        "Starting tool executor loop"
    );

    let mut conn = conn;

    // Track tools that failed with "not installed" so we can short-circuit
    // future calls immediately without attempting to spawn the binary.
    let mut unavailable_tools: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Exponential backoff state for connection errors
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);

    loop {
        // Check for shutdown via select with zero-timeout
        let poll_result = tokio::select! {
            result = poll_tool_request(&mut conn, &queue_key, config.poll_timeout) => result,
            _ = shutdown.notified() => {
                info!("Tool executor: shutdown signalled, finishing");
                return Ok(());
            }
        };

        match poll_result {
            Ok(Some(request)) => {
                retry_delay = Duration::from_secs(1);

                // Update heartbeat to busy
                let _ = status_tx.send(WorkerStatus {
                    status: "busy".to_string(),
                    current_task: Some(format!("{}:{}", request.tool_name, request.call_id)),
                });

                let ti = extract_target_info(&request.arguments);
                let tt = infer_target_type_from_info(&ti);
                let mut span_builder =
                    AgentSpanBuilder::new("tool_exec", &config.worker_role, Team::Red)
                        .tool(&request.tool_name)
                        .kind(SpanKind::Consumer);
                if let Some(ref ip) = ti.target_ip {
                    span_builder = span_builder.target_ip(ip);
                }
                if let Some(ref fqdn) = ti.target_fqdn {
                    span_builder = span_builder.target_fqdn(fqdn);
                }
                if let Some(ref user) = ti.target_user {
                    span_builder = span_builder.target_user(user);
                }
                if let Some(target_type) = tt {
                    span_builder = span_builder.target_type(target_type);
                }
                if let Some(ref op) = request.operation_id {
                    span_builder = span_builder.operation_id(op);
                }
                let exec_span = span_builder.build();
                if let Some(ref tp) = request.traceparent {
                    set_span_parent(&exec_span, tp);
                }
                execute_and_respond(&mut conn, &request, &mut unavailable_tools)
                    .instrument(exec_span)
                    .await;

                // Back to idle
                let _ = status_tx.send(WorkerStatus {
                    status: "idle".to_string(),
                    current_task: None,
                });
            }
            Ok(None) => {
                // BRPOP timeout, no request — just loop
                retry_delay = Duration::from_secs(1);
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                let is_conn_error = [
                    "connection",
                    "connect",
                    "closed",
                    "timeout",
                    "broken pipe",
                    "reset",
                ]
                .iter()
                .any(|kw| error_str.contains(kw));

                if is_conn_error {
                    // ConnectionManager auto-reconnects; just back off before retrying
                    warn!(
                        delay_secs = retry_delay.as_secs(),
                        "Tool executor: connection error, retrying: {e}"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = shutdown.notified() => return Ok(()),
                    }
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                } else {
                    error!("Tool executor: non-connection error: {e}");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = shutdown.notified() => return Ok(()),
                    }
                    retry_delay = Duration::from_secs(1);
                }
            }
        }
    }
}

/// BRPOP a single tool execution request from the queue.
async fn poll_tool_request(
    conn: &mut redis::aio::ConnectionManager,
    queue_key: &str,
    timeout: Duration,
) -> anyhow::Result<Option<ToolExecRequest>> {
    let result: Option<(String, String)> = redis::cmd("BRPOP")
        .arg(queue_key)
        .arg(timeout.as_secs() as i64)
        .query_async(conn)
        .await?;

    match result {
        Some((_key, data)) => {
            let request: ToolExecRequest = serde_json::from_str(&data)?;
            debug!(
                tool = %request.tool_name,
                call_id = %request.call_id,
                task_id = %request.task_id,
                "Received tool exec request"
            );
            Ok(Some(request))
        }
        None => Ok(None),
    }
}

/// Execute a tool call and push the result to Redis.
///
/// If the tool has previously failed with "not installed", short-circuits
/// immediately without attempting to spawn the binary.
async fn execute_and_respond(
    conn: &mut redis::aio::ConnectionManager,
    request: &ToolExecRequest,
    unavailable_tools: &mut std::collections::HashSet<String>,
) {
    // Short-circuit if this tool is known to be unavailable
    if unavailable_tools.contains(&request.tool_name) {
        debug!(
            tool = %request.tool_name,
            call_id = %request.call_id,
            "Skipping unavailable tool (previously failed to spawn)"
        );
        let response = ToolExecResponse {
            call_id: request.call_id.clone(),
            output: String::new(),
            error: Some(format!(
                "Tool '{}' is not installed on this worker. \
                 Do not call this tool again — it failed to spawn previously.",
                request.tool_name
            )),
            discoveries: None,
        };
        let result_key = format!("{TOOL_RESULT_PREFIX}:{}", request.call_id);
        if let Ok(json) = serde_json::to_string(&response) {
            let _ = push_result(conn, &result_key, &json).await;
        }
        return;
    }

    info!(
        tool = %request.tool_name,
        call_id = %request.call_id,
        task_id = %request.task_id,
        "Executing tool"
    );

    let di = extract_target_info(&request.arguments);
    let dt = infer_target_type_from_info(&di);

    let response = match ares_tools::dispatch(&request.tool_name, &request.arguments).await {
        Ok(output) => {
            // Raw output for structured parsers (need unfiltered data)
            let raw = output.combined_raw();
            // Filtered output for LLM (strips MOTD, noise, etc.)
            let combined = output.combined();
            let error = if output.success {
                None
            } else {
                Some(format!("tool exited with code {:?}", output.exit_code))
            };

            // Parse structured discoveries from raw (unfiltered) tool output
            let discoveries = ares_tools::parsers::parse_tool_output(
                &request.tool_name,
                &raw,
                &request.arguments,
            );
            let discoveries = if discoveries.as_object().is_none_or(|o| o.is_empty()) {
                None
            } else {
                Some(discoveries)
            };

            // Emit discovery spans for observability
            if let Some(ref disc) = discoveries {
                if let Some(obj) = disc.as_object() {
                    for (disc_type, items) in obj {
                        let count = items.as_array().map(|a| a.len()).unwrap_or(0);
                        if count > 0 {
                            let span = trace_discovery(
                                disc_type,
                                &request.tool_name,
                                di.target_user.as_deref(),
                                None,
                                di.target_ip.as_deref(),
                                di.target_fqdn.as_deref(),
                                dt,
                                request.operation_id.as_deref(),
                            );
                            let _guard = span.enter();
                        }
                    }
                }
            }

            ToolExecResponse {
                call_id: request.call_id.clone(),
                output: combined,
                error,
                discoveries,
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            // Track tools that fail because the binary is missing
            if err_str.contains("failed to spawn") || err_str.contains("not installed") {
                warn!(
                    tool = %request.tool_name,
                    "Tool binary not found — marking as unavailable for this session"
                );
                unavailable_tools.insert(request.tool_name.clone());
            }
            warn!(
                tool = %request.tool_name,
                call_id = %request.call_id,
                err = %e,
                "Tool execution failed"
            );
            ToolExecResponse {
                call_id: request.call_id.clone(),
                output: String::new(),
                error: Some(err_str),
                discoveries: None,
            }
        }
    };

    let has_error = response.error.is_some();
    let result_key = format!("{TOOL_RESULT_PREFIX}:{}", request.call_id);

    match serde_json::to_string(&response) {
        Ok(json) => {
            if let Err(e) = push_result(conn, &result_key, &json).await {
                error!(
                    call_id = %request.call_id,
                    "Failed to push tool result: {e}"
                );
            } else {
                debug!(
                    tool = %request.tool_name,
                    call_id = %request.call_id,
                    has_error = has_error,
                    "Tool result pushed"
                );
            }
        }
        Err(e) => {
            error!(
                call_id = %request.call_id,
                "Failed to serialize tool result: {e}"
            );
        }
    }
}

/// LPUSH result and set TTL.
async fn push_result(
    conn: &mut redis::aio::ConnectionManager,
    result_key: &str,
    result_json: &str,
) -> anyhow::Result<()> {
    conn.lpush::<_, _, ()>(result_key, result_json).await?;
    conn.expire::<_, ()>(result_key, RESULT_TTL).await?;
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_exec_request_deserialize() {
        let json = r#"{
            "call_id": "nmap_scan_abc123",
            "task_id": "recon_def456",
            "tool_name": "nmap_scan",
            "arguments": {"target": "192.168.58.0/24"}
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.call_id, "nmap_scan_abc123");
        assert_eq!(req.tool_name, "nmap_scan");
        assert_eq!(req.task_id, "recon_def456");
    }

    #[test]
    fn tool_exec_response_serialize() {
        let resp = ToolExecResponse {
            call_id: "nmap_scan_abc123".into(),
            output: "Found 5 hosts".into(),
            error: None,
            discoveries: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("nmap_scan_abc123"));
        assert!(json.contains("Found 5 hosts"));
        // discoveries omitted when None
        assert!(!json.contains("discoveries"));
    }

    #[test]
    fn tool_exec_response_with_error() {
        let resp = ToolExecResponse {
            call_id: "x".into(),
            output: String::new(),
            error: Some("Connection refused".into()),
            discoveries: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"], "Connection refused");
    }

    #[test]
    fn tool_exec_response_with_discoveries() {
        let resp = ToolExecResponse {
            call_id: "nmap_abc".into(),
            output: "scan output".into(),
            error: None,
            discoveries: Some(serde_json::json!({
                "hosts": [{"ip": "192.168.58.10", "services": ["445/tcp"]}]
            })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("discoveries"));
        assert!(json.contains("192.168.58.10"));
    }

    #[test]
    fn redis_key_prefixes_match_orchestrator() {
        // These must match tool_dispatcher.rs in ares-orchestrator
        assert_eq!(TOOL_EXEC_PREFIX, "ares:tool_exec");
        assert_eq!(TOOL_RESULT_PREFIX, "ares:tool_results");
    }
}
