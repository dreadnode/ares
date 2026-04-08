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
//! This is the Phase 3 "thin executor" pattern from the LLM architecture.

use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

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

                execute_and_respond(&mut conn, &request).await;

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
                    tokio::time::sleep(Duration::from_secs(5)).await;
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
async fn execute_and_respond(conn: &mut redis::aio::ConnectionManager, request: &ToolExecRequest) {
    info!(
        tool = %request.tool_name,
        call_id = %request.call_id,
        task_id = %request.task_id,
        "Executing tool"
    );

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

            ToolExecResponse {
                call_id: request.call_id.clone(),
                output: combined,
                error,
                discoveries,
            }
        }
        Err(e) => {
            warn!(
                tool = %request.tool_name,
                call_id = %request.call_id,
                err = %e,
                "Tool execution failed"
            );
            ToolExecResponse {
                call_id: request.call_id.clone(),
                output: String::new(),
                error: Some(e.to_string()),
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
            "arguments": {"target": "192.168.1.0/24"}
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
