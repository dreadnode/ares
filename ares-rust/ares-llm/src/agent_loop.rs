//! Multi-step LLM agent loop with tool_use dispatch.
//!
//! The `AgentLoop` drives a conversation between the LLM and tool executors:
//!
//! 1. Build system prompt from template + task prompt from PromptBuilder
//! 2. Call LLM via the provider
//! 3. If the LLM requests tool_use:
//!    a. Callback tools (task_complete, report_finding) → handled in Rust
//!    b. External tools (nmap_scan, secretsdump) → dispatched to worker via Redis
//! 4. Feed tool result back to LLM, repeat
//! 5. Stop when: task_complete called, max steps reached, or end_turn with no tools

use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::provider::{
    ChatMessage, LlmProvider, LlmRequest, Role, StopReason, TokenUsage, ToolCall,
};
use crate::tool_registry;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for an agent loop execution.
#[derive(Debug, Clone)]
pub struct AgentLoopConfig {
    /// LLM model identifier (e.g. "claude-sonnet-4-20250514").
    pub model: String,
    /// Maximum number of LLM steps before forcefully ending.
    pub max_steps: u32,
    /// Maximum tokens per LLM response.
    pub max_tokens: u32,
    /// Optional temperature override.
    pub temperature: Option<f32>,
}

impl Default for AgentLoopConfig {
    fn default() -> Self {
        Self {
            model: "claude-sonnet-4-20250514".to_string(),
            max_steps: 75,
            max_tokens: 4096,
            temperature: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tool execution interface
// ---------------------------------------------------------------------------

/// Result of executing an external tool on a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecResult {
    pub output: String,
    pub error: Option<String>,
    /// Structured discoveries parsed from the tool output (hosts, creds, hashes, vulns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discoveries: Option<serde_json::Value>,
}

/// Trait for dispatching tool calls to external executors (Python workers).
///
/// Implementers handle the Redis queue mechanics (LPUSH to tool_exec queue,
/// BRPOP for result).
#[async_trait::async_trait]
pub trait ToolDispatcher: Send + Sync {
    /// Dispatch a tool call to a worker and wait for the result.
    ///
    /// `role` is the agent role (e.g. "recon") used for queue routing.
    /// `task_id` is the parent task being executed.
    async fn dispatch_tool(
        &self,
        role: &str,
        task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult>;
}

// ---------------------------------------------------------------------------
// Callback handling
// ---------------------------------------------------------------------------

/// Result of handling a callback tool.
#[derive(Debug)]
pub enum CallbackResult {
    /// Task is complete — stop the loop.
    TaskComplete { task_id: String, result: String },
    /// Agent needs help — stop the loop.
    RequestAssistance { issue: String, context: String },
    /// Callback processed, continue the loop with this response.
    Continue(String),
}

fn handle_callback(call: &ToolCall) -> Result<CallbackResult> {
    match call.name.as_str() {
        "task_complete" => {
            let task_id = call.arguments["task_id"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let result = call.arguments["result"].as_str().unwrap_or("").to_string();
            Ok(CallbackResult::TaskComplete { task_id, result })
        }
        "request_assistance" => {
            let issue = call.arguments["issue"]
                .as_str()
                .unwrap_or("unknown issue")
                .to_string();
            let context = call.arguments["context"].as_str().unwrap_or("").to_string();
            Ok(CallbackResult::RequestAssistance { issue, context })
        }
        "report_cracked_credential" => {
            let username = call.arguments["username"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let _password = call.arguments["password"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(username = %username, "Cracked credential reported");
            Ok(CallbackResult::Continue(format!(
                "Credential recorded: {username} with cracked password"
            )))
        }
        "report_finding" => {
            let finding_type = call.arguments["finding_type"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let description = call.arguments["description"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(finding_type = %finding_type, "Finding reported: {description}");
            Ok(CallbackResult::Continue(format!(
                "Finding recorded: {finding_type}"
            )))
        }
        _ => anyhow::bail!("Unknown callback tool: {}", call.name),
    }
}

// ---------------------------------------------------------------------------
// Tool dispatch helper
// ---------------------------------------------------------------------------

/// Result of dispatching a single tool call.
struct DispatchResult {
    call_id: String,
    output: String,
    discoveries: Option<serde_json::Value>,
}

/// Dispatch a single external tool call.
async fn dispatch_one(
    dispatcher: Arc<dyn ToolDispatcher>,
    role: String,
    task_id: String,
    call: ToolCall,
) -> DispatchResult {
    match dispatcher.dispatch_tool(&role, &task_id, &call).await {
        Ok(result) => {
            let output = if let Some(err) = &result.error {
                format!("Error: {err}\n\nPartial output:\n{}", result.output)
            } else {
                result.output
            };
            DispatchResult {
                call_id: call.id,
                output,
                discoveries: result.discoveries,
            }
        }
        Err(e) => {
            warn!(
                tool = %call.name,
                err = %e,
                "Tool dispatch failed"
            );
            DispatchResult {
                call_id: call.id,
                output: format!("Tool execution failed: {e}"),
                discoveries: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Agent loop outcome
// ---------------------------------------------------------------------------

/// Outcome of running the agent loop.
#[derive(Debug)]
pub struct AgentLoopOutcome {
    /// How the loop ended.
    pub reason: LoopEndReason,
    /// Total token usage across all LLM calls.
    pub total_usage: TokenUsage,
    /// Number of LLM steps taken.
    pub steps: u32,
    /// Number of tool calls dispatched.
    pub tool_calls_dispatched: u32,
    /// Accumulated structured discoveries from all tool results.
    pub discoveries: Vec<serde_json::Value>,
}

/// Why the agent loop stopped.
#[derive(Debug)]
pub enum LoopEndReason {
    /// Agent called task_complete.
    TaskComplete { task_id: String, result: String },
    /// Agent called request_assistance.
    RequestAssistance { issue: String, context: String },
    /// Max steps reached.
    MaxSteps,
    /// LLM returned end_turn with no tool calls.
    EndTurn { content: String },
    /// LLM hit max_tokens.
    MaxTokens,
    /// Error during execution.
    Error(String),
}

// ---------------------------------------------------------------------------
// Agent loop execution
// ---------------------------------------------------------------------------

/// Execute the multi-step LLM agent loop.
///
/// This is the core function that drives a task from start to completion:
/// 1. Builds the system prompt and task prompt
/// 2. Calls the LLM in a loop
/// 3. Dispatches tool calls to workers or handles callbacks
/// 4. Returns when the task completes or max steps reached
#[allow(clippy::too_many_arguments)]
pub async fn run_agent_loop(
    provider: &dyn LlmProvider,
    dispatcher: Arc<dyn ToolDispatcher>,
    config: &AgentLoopConfig,
    system_prompt: &str,
    task_prompt: &str,
    role: &str,
    task_id: &str,
    tools: &[crate::ToolDefinition],
) -> AgentLoopOutcome {
    let mut messages: Vec<ChatMessage> = vec![ChatMessage::text(Role::User, task_prompt)];

    let mut total_usage = TokenUsage::default();
    let mut steps: u32 = 0;
    let mut tool_calls_dispatched: u32 = 0;
    let mut all_discoveries: Vec<serde_json::Value> = Vec::new();

    loop {
        if steps >= config.max_steps {
            warn!(task_id = task_id, steps = steps, "Agent loop hit max steps");
            return AgentLoopOutcome {
                reason: LoopEndReason::MaxSteps,
                total_usage,
                steps,
                tool_calls_dispatched,
                discoveries: all_discoveries,
            };
        }

        steps += 1;

        // Build LLM request
        let mut request = LlmRequest::new(&config.model);
        request.system = Some(system_prompt.to_string());
        request.messages.clone_from(&messages);
        request.tools = tools.to_vec();
        request.max_tokens = config.max_tokens;
        request.temperature = config.temperature;

        debug!(
            task_id = task_id,
            step = steps,
            messages = messages.len(),
            "Agent loop step"
        );

        // Call LLM
        let response = match provider.chat(&request).await {
            Ok(r) => r,
            Err(e) => {
                warn!(err = %e, task_id = task_id, "LLM call failed");
                return AgentLoopOutcome {
                    reason: LoopEndReason::Error(e.to_string()),
                    total_usage,
                    steps,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                };
            }
        };

        // Accumulate token usage
        total_usage.input_tokens += response.usage.input_tokens;
        total_usage.output_tokens += response.usage.output_tokens;
        total_usage.cache_creation_input_tokens += response.usage.cache_creation_input_tokens;
        total_usage.cache_read_input_tokens += response.usage.cache_read_input_tokens;

        // Handle based on stop reason
        match response.stop_reason {
            StopReason::EndTurn if response.tool_calls.is_empty() => {
                return AgentLoopOutcome {
                    reason: LoopEndReason::EndTurn {
                        content: response.content,
                    },
                    total_usage,
                    steps,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                };
            }
            StopReason::MaxTokens if response.tool_calls.is_empty() => {
                return AgentLoopOutcome {
                    reason: LoopEndReason::MaxTokens,
                    total_usage,
                    steps,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                };
            }
            _ => {}
        }

        if response.tool_calls.is_empty() {
            // No tool calls and not EndTurn/MaxTokens — add as assistant message and continue
            messages.push(ChatMessage::text(Role::Assistant, &response.content));
            continue;
        }

        // Add assistant message with tool calls to conversation history
        messages.push(ChatMessage::assistant_tool_use(
            if response.content.is_empty() {
                None
            } else {
                Some(response.content.clone())
            },
            response.tool_calls.clone(),
        ));

        // Partition into external tools (dispatched to workers) and callbacks
        // (handled in Rust). External tools are dispatched first so their
        // results are available before callbacks like task_complete fire.
        let mut external: Vec<&ToolCall> = Vec::new();
        let mut callbacks: Vec<&ToolCall> = Vec::new();
        for call in &response.tool_calls {
            if tool_registry::is_callback_tool(&call.name) {
                callbacks.push(call);
            } else {
                external.push(call);
            }
        }

        // Dispatch external tools to workers concurrently
        if !external.is_empty() {
            tool_calls_dispatched += external.len() as u32;

            let mut join_set = tokio::task::JoinSet::new();
            for call in &external {
                let disp = Arc::clone(&dispatcher);
                let r = role.to_string();
                let tid = task_id.to_string();
                let c = (*call).clone();
                join_set.spawn(dispatch_one(disp, r, tid, c));
            }

            // Collect results preserving call ordering
            let mut results: Vec<DispatchResult> = Vec::with_capacity(external.len());
            while let Some(res) = join_set.join_next().await {
                match res {
                    Ok(dr) => results.push(dr),
                    Err(e) => {
                        warn!(err = %e, "Tool dispatch task panicked");
                    }
                }
            }

            // Add tool results to messages in the original call order
            // and accumulate any structured discoveries
            for call in &external {
                if let Some(dr) = results.iter().find(|r| r.call_id == call.id) {
                    messages.push(ChatMessage::tool_result(&call.id, &dr.output));
                    if let Some(disc) = &dr.discoveries {
                        all_discoveries.push(disc.clone());
                    }
                }
            }
        }

        // Handle callbacks (may short-circuit the loop)
        for call in &callbacks {
            match handle_callback(call) {
                Ok(CallbackResult::TaskComplete { task_id, result }) => {
                    info!(
                        task_id = %task_id,
                        steps = steps,
                        "Task completed"
                    );
                    messages.push(ChatMessage::tool_result(
                        &call.id,
                        "Task marked as complete.",
                    ));
                    return AgentLoopOutcome {
                        reason: LoopEndReason::TaskComplete { task_id, result },
                        total_usage,
                        steps,
                        tool_calls_dispatched,
                        discoveries: all_discoveries,
                    };
                }
                Ok(CallbackResult::RequestAssistance { issue, context }) => {
                    info!(issue = %issue, "Assistance requested");
                    return AgentLoopOutcome {
                        reason: LoopEndReason::RequestAssistance { issue, context },
                        total_usage,
                        steps,
                        tool_calls_dispatched,
                        discoveries: all_discoveries,
                    };
                }
                Ok(CallbackResult::Continue(msg)) => {
                    messages.push(ChatMessage::tool_result(&call.id, &msg));
                }
                Err(e) => {
                    messages.push(ChatMessage::tool_result(
                        &call.id,
                        format!("Callback error: {e}"),
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_task_complete_callback() {
        let call = ToolCall {
            id: "call_1".into(),
            name: "task_complete".into(),
            arguments: serde_json::json!({
                "task_id": "task-001",
                "result": "Found 5 hosts"
            }),
        };
        let result = handle_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { task_id, result } => {
                assert_eq!(task_id, "task-001");
                assert_eq!(result, "Found 5 hosts");
            }
            _ => panic!("Expected TaskComplete"),
        }
    }

    #[test]
    fn test_handle_request_assistance_callback() {
        let call = ToolCall {
            id: "call_2".into(),
            name: "request_assistance".into(),
            arguments: serde_json::json!({
                "issue": "Cannot reach target",
                "context": "Tried 3 times"
            }),
        };
        let result = handle_callback(&call).unwrap();
        match result {
            CallbackResult::RequestAssistance { issue, context } => {
                assert_eq!(issue, "Cannot reach target");
                assert_eq!(context, "Tried 3 times");
            }
            _ => panic!("Expected RequestAssistance"),
        }
    }

    #[test]
    fn test_handle_report_finding_callback() {
        let call = ToolCall {
            id: "call_3".into(),
            name: "report_finding".into(),
            arguments: serde_json::json!({
                "finding_type": "smb_signing_disabled",
                "description": "SMB signing not required on 192.168.58.20"
            }),
        };
        let result = handle_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("smb_signing_disabled"));
            }
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_unknown_callback() {
        let call = ToolCall {
            id: "call_x".into(),
            name: "unknown_callback".into(),
            arguments: serde_json::json!({}),
        };
        assert!(handle_callback(&call).is_err());
    }

    #[test]
    fn test_agent_loop_config_defaults() {
        let config = AgentLoopConfig::default();
        assert_eq!(config.max_steps, 75);
        assert_eq!(config.max_tokens, 4096);
    }
}
