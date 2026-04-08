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

use std::time::Duration;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use ares_llm::{ToolCall, ToolExecResult};

use crate::task_queue::TaskQueue;

/// Prefix for tool execution request queues.
const TOOL_EXEC_PREFIX: &str = "ares:tool_exec";

/// Prefix for per-call result mailboxes.
const TOOL_RESULT_PREFIX: &str = "ares:tool_results";

/// TTL for result keys (1 hour).
const RESULT_TTL_SECS: u64 = 3600;

/// Default timeout waiting for a tool result (5 minutes).
const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 300;

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

/// Dispatches tool calls to workers via Redis queues.
pub struct RedisToolDispatcher {
    queue: TaskQueue,
    tool_timeout: Duration,
}

impl RedisToolDispatcher {
    pub fn new(queue: TaskQueue) -> Self {
        Self {
            queue,
            tool_timeout: Duration::from_secs(DEFAULT_TOOL_TIMEOUT_SECS),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.tool_timeout = timeout;
        self
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
        let call_id = format!("{}_{}", call.name, uuid::Uuid::new_v4().simple());

        let request = ToolExecRequest {
            call_id: call_id.clone(),
            task_id: task_id.to_string(),
            tool_name: call.name.clone(),
            arguments: call.arguments.clone(),
        };

        let queue_key = format!("{TOOL_EXEC_PREFIX}:{role}");
        let result_key = format!("{TOOL_RESULT_PREFIX}:{call_id}");
        let payload =
            serde_json::to_string(&request).context("Failed to serialize tool exec request")?;

        debug!(
            tool = %call.name,
            call_id = %call_id,
            queue = %queue_key,
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
}

// ---------------------------------------------------------------------------
// Local (in-process) tool dispatcher
// ---------------------------------------------------------------------------

/// Dispatches tool calls directly via `ares_tools::dispatch` without Redis.
///
/// Useful for testing, single-binary deployments, or when workers are
/// colocated in the same process as the orchestrator.
pub struct LocalToolDispatcher;

impl LocalToolDispatcher {
    pub fn new() -> Self {
        Self
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
}
