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

/// Timeout for individual blue tool executions (e.g. Loki/Grafana queries).
/// `execute_parallel_queries` runs up to 5 queries (2 concurrent), each with
/// a 90s HTTP timeout and up to 2 retries — worst-case ~540s.  Give headroom.
const BLUE_TOOL_TIMEOUT_SECS: u64 = 600;

/// Wraps an existing (red-team) dispatcher and intercepts blue tool names,
/// routing them to `ares_tools::blue::dispatch_blue()` for local execution.
/// Non-blue tools fall through to the inner dispatcher.
pub(super) struct BlueToolDispatcher {
    pub(super) inner: Arc<dyn ToolDispatcher>,
    pub(super) investigation_id: String,
}

impl BlueToolDispatcher {
    fn pin_investigation_id(&self, call: &ToolCall) -> Option<serde_json::Value> {
        let obj = call.arguments.as_object()?;
        let current = obj.get("investigation_id").and_then(|v| v.as_str());
        if current == Some(self.investigation_id.as_str()) {
            return None;
        }
        let mut patched = obj.clone();
        let supplied = patched.insert(
            "investigation_id".to_string(),
            serde_json::Value::String(self.investigation_id.clone()),
        );
        if let Some(supplied) = supplied {
            warn!(
                tool = %call.name,
                supplied = %supplied,
                investigation_id = %self.investigation_id,
                "Overriding sub-agent-supplied investigation_id"
            );
        }
        Some(serde_json::Value::Object(patched))
    }
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
            let patched = self.pin_investigation_id(call);
            let arguments = patched.as_ref().unwrap_or(&call.arguments);
            match tokio::time::timeout(
                std::time::Duration::from_secs(BLUE_TOOL_TIMEOUT_SECS),
                ares_tools::blue::dispatch_blue(&call.name, arguments),
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
                    failure_kind: if output.success {
                        None
                    } else {
                        Some(ares_llm::ToolFailureKind::ToolError)
                    },
                }),
                Ok(Err(e)) => {
                    // Classify via the ares-tools spawn marker so blue
                    // sub-agents match the red path's ENOENT/transient
                    // discrimination.
                    let failure_kind = ares_tools::spawn_error_kind(&e).map(|kind| {
                        if kind.is_not_found() {
                            ares_llm::ToolFailureKind::BinaryNotFound
                        } else {
                            ares_llm::ToolFailureKind::TransientSpawn
                        }
                    });
                    Ok(ToolExecResult {
                        output: String::new(),
                        error: Some(e.to_string()),
                        discoveries: None,
                        failure_kind,
                    })
                }
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
                        failure_kind: None,
                    })
                }
            }
        } else {
            self.inner.dispatch_tool(role, task_id, call).await
        }
    }
}

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

    async fn handle_callback(
        &self,
        call: &ToolCall,
        _role: &str,
    ) -> Option<Result<CallbackResult>> {
        BlueCallbackHandler::handle_lifecycle_callback(call).map(Ok)
    }

    async fn on_token_usage(&self, usage: &TokenUsage, model: &str, role: &str) {
        if usage.input_tokens == 0 && usage.output_tokens == 0 {
            return;
        }
        if let Ok(client) = redis::Client::open(self.redis_url.as_str()) {
            if let Ok(mut conn) = client.get_connection_manager().await {
                if let Err(e) = ares_core::token_usage::increment_blue_token_usage(
                    &mut conn,
                    &self.investigation_id,
                    usage.input_tokens.into(),
                    usage.cache_read_input_tokens.into(),
                    usage.output_tokens.into(),
                    model,
                    role,
                )
                .await
                {
                    warn!(err = %e, "Failed to record blue sub-agent token usage");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct NoopDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for NoopDispatcher {
        async fn dispatch_tool(&self, _: &str, _: &str, _: &ToolCall) -> Result<ToolExecResult> {
            unreachable!("blue tools never reach the inner dispatcher")
        }
    }

    fn dispatcher() -> BlueToolDispatcher {
        BlueToolDispatcher {
            inner: Arc::new(NoopDispatcher),
            investigation_id: "inv-real".into(),
        }
    }

    fn call(name: &str, arguments: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "c1".into(),
            name: name.into(),
            arguments,
        }
    }

    #[test]
    fn overrides_hallucinated_investigation_id() {
        let call = call(
            "add_technique",
            json!({"investigation_id": "AUTO-CHAINED", "technique_id": "T1021.002"}),
        );
        let patched = dispatcher().pin_investigation_id(&call).unwrap();
        assert_eq!(patched["investigation_id"], "inv-real");
        assert_eq!(patched["technique_id"], "T1021.002");
    }

    #[test]
    fn supplies_omitted_investigation_id() {
        let call = call("add_technique", json!({"technique_id": "T1021.002"}));
        let patched = dispatcher().pin_investigation_id(&call).unwrap();
        assert_eq!(patched["investigation_id"], "inv-real");
    }

    #[test]
    fn leaves_correct_investigation_id_untouched() {
        let call = call(
            "add_technique",
            json!({"investigation_id": "inv-real", "technique_id": "T1021.002"}),
        );
        assert!(dispatcher().pin_investigation_id(&call).is_none());
    }
}
