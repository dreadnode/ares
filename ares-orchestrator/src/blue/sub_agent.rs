//! Infrastructure wrapper types for blue team sub-agent dispatch.
//!
//! - [`BlueToolDispatcher`] — wraps the red-team dispatcher and routes blue
//!   tool names to `ares_tools::blue::dispatch_blue()` for local execution.
//! - [`SubAgentCallbackHandler`] — minimal callback handler for blue
//!   sub-agents that handles lifecycle completion tools and tracks token usage.

use std::sync::Arc;

use anyhow::Result;
use tracing::{debug, warn};

use ares_llm::agent_loop::CallbackResult;
use ares_llm::{CallbackHandler, TokenUsage, ToolCall, ToolDispatcher, ToolExecResult};

use super::callbacks::BlueCallbackHandler;

// ---------------------------------------------------------------------------
// Blue-aware tool dispatcher wrapper
// ---------------------------------------------------------------------------

/// Timeout for individual blue tool executions (e.g. Loki/Grafana queries).
const BLUE_TOOL_TIMEOUT_SECS: u64 = 120;

/// Wraps an existing (red-team) dispatcher and intercepts blue tool names,
/// routing them to `ares_tools::blue::dispatch_blue()` for local execution.
/// Non-blue tools fall through to the inner dispatcher.
pub(super) struct BlueToolDispatcher {
    pub(super) inner: Arc<dyn ToolDispatcher>,
}

#[async_trait::async_trait]
impl ToolDispatcher for BlueToolDispatcher {
    async fn dispatch_tool(
        &self,
        role: &str,
        task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        if ares_tools::blue::is_blue_tool(&call.name) {
            debug!(tool = %call.name, "Executing blue tool locally");
            match tokio::time::timeout(
                std::time::Duration::from_secs(BLUE_TOOL_TIMEOUT_SECS),
                ares_tools::blue::dispatch_blue(&call.name, &call.arguments),
            )
            .await
            {
                Ok(Ok(output)) => Ok(ToolExecResult {
                    output: output.combined(),
                    error: if output.success {
                        None
                    } else {
                        Some(format!("tool exited with code {:?}", output.exit_code))
                    },
                    discoveries: None,
                }),
                Ok(Err(e)) => Ok(ToolExecResult {
                    output: String::new(),
                    error: Some(e.to_string()),
                    discoveries: None,
                }),
                Err(_elapsed) => {
                    warn!(
                        tool = %call.name,
                        timeout_secs = BLUE_TOOL_TIMEOUT_SECS,
                        "Blue tool execution timed out"
                    );
                    Ok(ToolExecResult {
                        output: format!(
                            "Tool execution timed out after {BLUE_TOOL_TIMEOUT_SECS}s. \
                             The data source may be unreachable. Try a simpler query or skip this step."
                        ),
                        error: Some("timeout".to_string()),
                        discoveries: None,
                    })
                }
            }
        } else {
            self.inner.dispatch_tool(role, task_id, call).await
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-agent callback handler (lifecycle callbacks only)
// ---------------------------------------------------------------------------

/// Minimal callback handler for blue sub-agents (triage, threat_hunter, etc.).
///
/// Recognizes lifecycle completion tools (`triage_complete`, `hunt_complete`,
/// `lateral_complete`, etc.) so they end the sub-agent loop with `TaskComplete`
/// instead of falling through to the Redis dispatcher.
///
/// Also tracks token usage per-investigation so blue team cost is visible.
pub(super) struct SubAgentCallbackHandler {
    pub(super) investigation_id: String,
    pub(super) redis_url: String,
}

#[async_trait::async_trait]
impl CallbackHandler for SubAgentCallbackHandler {
    fn is_callback(&self, tool_name: &str) -> bool {
        matches!(
            tool_name,
            "triage_complete"
                | "hunt_complete"
                | "lateral_complete"
                | "complete_investigation"
                | "confirm_escalation"
                | "downgrade_escalation"
                | "request_reinvestigation"
                | "route_to_team"
        )
    }

    async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>> {
        BlueCallbackHandler::handle_lifecycle_callback(call).map(Ok)
    }

    async fn on_token_usage(&self, usage: &TokenUsage, model: &str) {
        if usage.input_tokens == 0 && usage.output_tokens == 0 {
            return;
        }
        if let Ok(client) = redis::Client::open(self.redis_url.as_str()) {
            if let Ok(mut conn) = client.get_connection_manager().await {
                if let Err(e) = ares_core::token_usage::increment_blue_token_usage(
                    &mut conn,
                    &self.investigation_id,
                    usage.input_tokens.into(),
                    usage.output_tokens.into(),
                    model,
                )
                .await
                {
                    warn!(err = %e, "Failed to record blue sub-agent token usage");
                }
            }
        }
    }
}
