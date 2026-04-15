use std::sync::Arc;

use tracing::{debug, info, warn, Instrument};

use ares_core::telemetry::spans::{trace_decision, trace_tool_call, Team};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

use crate::provider::{
    ChatMessage, LlmProvider, LlmRequest, Role, StopReason, TokenUsage, ToolCall,
};
use crate::tool_registry;

use super::callbacks::handle_callback;
use super::config::AgentLoopConfig;
use super::context::{trim_conversation, truncate_tool_output};
use super::retry::call_with_retry;
use super::types::{
    AgentLoopOutcome, CallbackHandler, CallbackResult, LoopEndReason, ToolDispatcher,
};

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

/// Execute the multi-step LLM agent loop.
///
/// This is the core function that drives a task from start to completion:
/// 1. Builds the system prompt and task prompt
/// 2. Calls the LLM in a loop
/// 3. Dispatches tool calls to workers or handles callbacks
/// 4. Returns when the task completes or max steps reached
///
/// `callback_handler` — optional custom handler for role-specific callback
/// tools (e.g. orchestrator state queries). Pass `None` for worker tasks.
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
    callback_handler: Option<Arc<dyn CallbackHandler>>,
) -> AgentLoopOutcome {
    let mut messages: Vec<ChatMessage> = vec![ChatMessage::text(Role::User, task_prompt)];

    let mut total_usage = TokenUsage::default();
    let mut steps: u32 = 0;
    let mut tool_calls_dispatched: u32 = 0;
    let mut all_discoveries: Vec<serde_json::Value> = Vec::new();
    let mut all_tool_outputs: Vec<String> = Vec::new();

    // Dynamic tool filtering: track unavailable tools and per-tool call counts
    // to prevent infinite retry loops on missing binaries and runaway tool calls.
    let mut active_tools: Vec<crate::ToolDefinition> = tools.to_vec();
    let mut tool_call_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let max_tool_calls_per_name = config.max_tool_calls_per_name;

    loop {
        if steps >= config.max_steps {
            warn!(task_id = task_id, steps = steps, "Agent loop hit max steps");
            return AgentLoopOutcome {
                reason: LoopEndReason::MaxSteps,
                total_usage,
                steps,
                tool_calls_dispatched,
                discoveries: all_discoveries,
                tool_outputs: all_tool_outputs,
            };
        }

        steps += 1;

        // Trim conversation if approaching context limit
        trim_conversation(&mut messages, system_prompt, &active_tools, &config.context);

        // Build LLM request
        let mut request = LlmRequest::new(&config.model);
        request.system = Some(system_prompt.to_string());
        request.messages.clone_from(&messages);
        request.tools = active_tools.clone();
        request.max_tokens = config.max_tokens;
        request.temperature = config.temperature;

        debug!(
            task_id = task_id,
            step = steps,
            messages = messages.len(),
            "Agent loop step"
        );

        // Call LLM with retry on transient errors
        let response = match call_with_retry(provider, &request, &config.retry, task_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(err = %e, task_id = task_id, "LLM call failed after retries");
                return AgentLoopOutcome {
                    reason: LoopEndReason::Error(e.to_string()),
                    total_usage,
                    steps,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                    tool_outputs: all_tool_outputs,
                };
            }
        };

        // Accumulate token usage
        total_usage.input_tokens += response.usage.input_tokens;
        total_usage.output_tokens += response.usage.output_tokens;
        total_usage.cache_creation_input_tokens += response.usage.cache_creation_input_tokens;
        total_usage.cache_read_input_tokens += response.usage.cache_read_input_tokens;

        // Report incremental token usage to callback handler (persists to Redis)
        if let Some(ref handler) = callback_handler {
            handler.on_token_usage(&response.usage, &config.model).await;
        }

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
                    tool_outputs: all_tool_outputs,
                };
            }
            StopReason::MaxTokens if response.tool_calls.is_empty() => {
                return AgentLoopOutcome {
                    reason: LoopEndReason::MaxTokens,
                    total_usage,
                    steps,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                    tool_outputs: all_tool_outputs,
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

        // Record LLM tool selection decisions for observability
        {
            let available: Vec<String> = active_tools.iter().map(|t| t.name.clone()).collect();
            for tc in &response.tool_calls {
                let span =
                    trace_decision(role, Team::Red, &tc.name, &available, None, Some(task_id));
                let _guard = span.enter();
            }
        }

        // Partition into external tools (dispatched to workers) and callbacks
        // (handled in Rust). External tools are dispatched first so their
        // results are available before callbacks like task_complete fire.
        let cb_handler_ref = callback_handler.as_deref();
        let mut external: Vec<&ToolCall> = Vec::new();
        let mut callbacks: Vec<&ToolCall> = Vec::new();
        for call in &response.tool_calls {
            if tool_registry::is_callback_tool(&call.name)
                || cb_handler_ref.is_some_and(|h| h.is_callback(&call.name))
            {
                callbacks.push(call);
            } else {
                external.push(call);
            }
        }

        // Dispatch external tools to workers concurrently
        if !external.is_empty() {
            tool_calls_dispatched = tool_calls_dispatched.saturating_add(external.len() as u32);

            let mut join_set = tokio::task::JoinSet::new();
            for call in &external {
                let disp = Arc::clone(&dispatcher);
                let r = role.to_string();
                let tid = task_id.to_string();
                let c = (*call).clone();
                let ti = extract_target_info(&call.arguments);
                let tt = infer_target_type_from_info(&ti);
                let span = trace_tool_call(
                    role,
                    Team::Red,
                    &call.name,
                    ti.target_ip.as_deref(),
                    ti.target_fqdn.as_deref(),
                    ti.target_user.as_deref(),
                    tt,
                    Some(task_id),
                    false,
                    None,
                );
                join_set.spawn(dispatch_one(disp, r, tid, c).instrument(span));
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
            // and accumulate any structured discoveries.
            // Truncate large outputs to prevent context window exhaustion.
            let mut tools_to_remove: Vec<String> = Vec::new();
            for call in &external {
                // Track per-tool call counts for retry limiting
                let count = tool_call_counts.entry(call.name.clone()).or_insert(0);
                *count += 1;

                if let Some(dr) = results.iter().find(|r| r.call_id == call.id) {
                    // Detect spawn failures (binary not found) and mark tool for removal.
                    // Only match the executor's own error message pattern — NOT arbitrary
                    // tool output that happens to contain "not installed" (e.g., a target
                    // host saying some service is "not installed" in its response).
                    let is_spawn_failure = dr.output.contains("failed to spawn");
                    if is_spawn_failure {
                        warn!(
                            tool = %call.name,
                            task_id = task_id,
                            "Tool binary not found (spawn failed) — removing from available tools"
                        );
                        tools_to_remove.push(call.name.clone());
                    }

                    let output =
                        truncate_tool_output(&dr.output, config.context.max_tool_output_chars);
                    // Collect raw tool output for secondary regex extraction
                    all_tool_outputs.push(dr.output.clone());
                    messages.push(ChatMessage::tool_result(&call.id, &output));
                    if let Some(disc) = &dr.discoveries {
                        all_discoveries.push(disc.clone());
                    }
                } else {
                    // No result for this call — dispatch panicked or errored.
                    // Must still push a tool result to keep the message sequence valid
                    // (OpenAI requires every tool_call_id to have a matching result).
                    warn!(
                        tool = %call.name,
                        call_id = %call.id,
                        task_id = task_id,
                        "No dispatch result for tool call — inserting error placeholder"
                    );
                    messages.push(ChatMessage::tool_result(
                        &call.id,
                        "Tool execution failed: no result received (dispatch error)",
                    ));
                }

                // Check if tool has exceeded max call count
                if *tool_call_counts.get(&call.name).unwrap_or(&0) >= max_tool_calls_per_name
                    && !tools_to_remove.contains(&call.name)
                {
                    warn!(
                        tool = %call.name,
                        count = *tool_call_counts.get(&call.name).unwrap_or(&0),
                        task_id = task_id,
                        "Tool exceeded max call limit — removing from available tools"
                    );
                    tools_to_remove.push(call.name.clone());
                }
            }

            // Remove exhausted/unavailable tools from active definitions
            if !tools_to_remove.is_empty() {
                let before = active_tools.len();
                active_tools.retain(|t| !tools_to_remove.contains(&t.name));
                let removed = before - active_tools.len();
                if removed > 0 {
                    info!(
                        removed_count = removed,
                        remaining = active_tools.len(),
                        tools = ?tools_to_remove,
                        "Removed tools from active definitions"
                    );
                    // Inject a system-like message so the LLM knows these tools are gone
                    let removed_list = tools_to_remove.join(", ");
                    messages.push(ChatMessage::text(
                        Role::User,
                        format!(
                            "[SYSTEM] The following tools have been removed and are no longer \
                             available: {removed_list}. Do not attempt to call them. \
                             Use alternative approaches or different tools."
                        ),
                    ));
                }
            }
        }

        // Handle callbacks (may short-circuit the loop)
        let cb_handler = callback_handler.as_deref();
        for call in &callbacks {
            let cb_span = trace_tool_call(
                role,
                Team::Red,
                &call.name,
                None,
                None,
                None,
                None,
                Some(task_id),
                false,
                None,
            );
            match handle_callback(call, cb_handler).instrument(cb_span).await {
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
                        tool_outputs: all_tool_outputs,
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
                        tool_outputs: all_tool_outputs,
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
