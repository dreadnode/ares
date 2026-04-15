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
use tracing::{debug, info, warn, Instrument};

use ares_core::telemetry::spans::{trace_decision, trace_tool_call, Team};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

use crate::provider::{
    ChatMessage, ContentPart, LlmError, LlmProvider, LlmRequest, LlmResponse, Role, StopReason,
    TokenUsage, ToolCall,
};
use crate::tool_registry;

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
    /// Retry configuration for transient LLM errors (rate limits, network).
    pub retry: RetryConfig,
    /// Context window management configuration.
    pub context: ContextConfig,
    /// Maximum times a single tool can be called within one agent loop before
    /// it is removed from the tool definitions to force the LLM to try
    /// a different approach. Blue investigations need higher limits since
    /// detection queries are the primary tool.
    pub max_tool_calls_per_name: u32,
}

impl Default for AgentLoopConfig {
    fn default() -> Self {
        Self {
            model: "claude-sonnet-4-20250514".to_string(),
            max_steps: 75,
            max_tokens: 4096,
            temperature: None,
            retry: RetryConfig::default(),
            context: ContextConfig::default(),
            max_tool_calls_per_name: 10,
        }
    }
}

/// Context window management to prevent unbounded message growth.
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Maximum context budget in estimated tokens (0 = no limit).
    /// When the conversation exceeds this, older messages in the middle are dropped.
    pub max_context_tokens: u32,
    /// Maximum chars for a single tool result before truncation.
    /// Large tool outputs (nmap scans, secretsdump) are truncated to this limit.
    pub max_tool_output_chars: usize,
    /// Minimum number of recent messages to always keep (never truncated).
    pub min_recent_messages: usize,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: 180_000,   // Conservative for 200k models
            max_tool_output_chars: 30_000, // ~7,500 tokens per tool output
            min_recent_messages: 10,
        }
    }
}

/// Retry configuration for LLM calls with exponential backoff + jitter.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries for retryable errors.
    pub max_retries: u32,
    /// Base delay in milliseconds (doubles each retry).
    pub base_delay_ms: u64,
    /// Maximum delay cap in milliseconds.
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
        }
    }
}

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

/// Trait for providing custom callback handlers to the agent loop.
///
/// The orchestrator implements this to handle state query tools
/// (get_hash_summary, get_all_credentials, etc.) and dispatch tools
/// (dispatch_recon, dispatch_lateral, etc.) that need Redis access.
///
/// Return `None` if the handler doesn't recognize the tool — the
/// built-in handler will be tried next.
#[async_trait::async_trait]
pub trait CallbackHandler: Send + Sync {
    async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>>;

    /// Check if a tool name should be routed as a callback rather than
    /// dispatched to a worker. Default returns false for all tools.
    fn is_callback(&self, _tool_name: &str) -> bool {
        false
    }

    /// Called after each LLM API response with the incremental token usage.
    /// Default implementation is a no-op. Override this to record per-call
    /// token usage (e.g. persist to Redis so CLI shows live cost data).
    async fn on_token_usage(&self, _usage: &TokenUsage, _model: &str) {}
}

fn handle_builtin_callback(call: &ToolCall) -> Result<CallbackResult> {
    match call.name.as_str() {
        "task_complete" => {
            let task_id = call.arguments["task_id"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            // The LLM may pass result as a string or a JSON object — handle both.
            let result = match &call.arguments["result"] {
                serde_json::Value::String(s) => s.clone(),
                other if !other.is_null() => serde_json::to_string(other).unwrap_or_default(),
                _ => String::new(),
            };
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
            // This tool was removed. Cracked passwords are auto-extracted from
            // hashcat/john stdout. Tell the LLM to just call task_complete.
            warn!("report_cracked_credential called but removed — passwords are auto-extracted from tool output");
            Ok(CallbackResult::Continue(
                "This tool no longer exists. Cracked passwords are automatically extracted from \
                 hashcat/john stdout. Just call task_complete with a summary."
                    .to_string(),
            ))
        }
        "report_crack_failed" => {
            let hash_type = call.arguments["hash_type"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let username = call.arguments["username"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(username = %username, hash_type = %hash_type, "Crack failed reported");
            Ok(CallbackResult::Continue(format!(
                "Crack failure recorded for {username} ({hash_type})"
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
        "report_lateral_success" => {
            let target = call.arguments["target_ip"]
                .as_str()
                .or_else(|| call.arguments["target"].as_str())
                .unwrap_or("")
                .to_string();
            let technique = call.arguments["technique"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(target = %target, technique = %technique, "Lateral movement succeeded");
            Ok(CallbackResult::Continue(format!(
                "Lateral movement recorded: {technique} → {target}"
            )))
        }
        "report_lateral_failed" => {
            let target = call.arguments["target_ip"]
                .as_str()
                .or_else(|| call.arguments["target"].as_str())
                .unwrap_or("")
                .to_string();
            let technique = call.arguments["technique"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let reason = call.arguments["reason"].as_str().unwrap_or("").to_string();
            info!(target = %target, technique = %technique, "Lateral movement failed: {reason}");
            Ok(CallbackResult::Continue(format!(
                "Lateral failure recorded: {technique} → {target}: {reason}"
            )))
        }
        "complete_operation" => {
            let summary = call.arguments["summary"]
                .as_str()
                .unwrap_or("Operation completed")
                .to_string();
            info!("Operation marked complete: {summary}");
            Ok(CallbackResult::TaskComplete {
                task_id: "operation".to_string(),
                result: summary,
            })
        }
        // record_credential is deprecated — credentials are extracted automatically
        // from tool output via regex parsing. This handler exists only as a safety net.
        "record_credential" => {
            warn!("record_credential called but tool is disabled — credentials are auto-extracted from tool output");
            Ok(CallbackResult::Continue(
                "This tool is disabled. Credentials are automatically extracted from tool output. \
                 Focus on running tools that produce credential data (secretsdump, lsassy, netexec, etc.) \
                 and the system will parse and store credentials automatically.".to_string()
            ))
        }
        "record_compromised_host" => {
            let ip = call.arguments["ip"].as_str().unwrap_or("").to_string();
            let hostname = call.arguments["hostname"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let access = call.arguments["access_level"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(ip = %ip, hostname = %hostname, access = %access, "Compromised host recorded");
            Ok(CallbackResult::Continue(format!(
                "Compromised host recorded: {ip} ({hostname}) — {access}"
            )))
        }
        "record_timeline_event" => {
            let desc = call.arguments["description"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!("Timeline event recorded: {desc}");
            Ok(CallbackResult::Continue(format!(
                "Timeline event recorded: {desc}"
            )))
        }
        "list_credentials" => {
            // Minimal response — real data comes from OrchestratorCallbackHandler
            Ok(CallbackResult::Continue(
                "Use get_all_credentials for full credential listing.".to_string(),
            ))
        }
        // Orchestrator-only tools — these require a custom CallbackHandler
        // (OrchestratorCallbackHandler) to provide meaningful state. When called
        // without one (e.g., by a worker), return a generic message.
        "get_credential_summary"
        | "get_hash_summary"
        | "get_all_credentials"
        | "get_all_hashes"
        | "get_hash_value"
        | "get_pending_tasks"
        | "get_agent_status"
        | "get_operation_summary"
        | "dispatch_recon"
        | "dispatch_credential_access"
        | "dispatch_lateral_movement"
        | "dispatch_privesc_exploit"
        | "dispatch_coercion"
        | "dispatch_crack" => Ok(CallbackResult::Continue(
            "This tool requires the orchestrator callback handler.".to_string(),
        )),
        _ => anyhow::bail!("Unknown callback tool: {}", call.name),
    }
}

/// Handle a callback tool, trying the custom handler first then built-in.
async fn handle_callback(
    call: &ToolCall,
    custom: Option<&dyn CallbackHandler>,
) -> Result<CallbackResult> {
    // Try custom handler first (orchestrator state queries, dispatch tools)
    if let Some(handler) = custom {
        if let Some(result) = handler.handle_callback(call).await {
            return result;
        }
    }
    // Fall back to built-in handlers
    handle_builtin_callback(call)
}

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
    /// Raw tool output strings for secondary regex extraction.
    pub tool_outputs: Vec<String>,
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

/// Estimate token count for a string using the chars/4 heuristic.
/// This approximation works well for English text and code with
/// Anthropic and OpenAI tokenizers.
fn estimate_tokens(text: &str) -> u32 {
    // chars/4 is a widely-used approximation; slightly conservative.
    // Clamp to u32::MAX before casting to avoid silent truncation on
    // strings larger than ~4 GiB (possible in theory for tool outputs).
    let len = text.len().min(u32::MAX as usize) as u32;
    len.div_ceil(4)
}

/// Estimate total tokens for a message.
fn estimate_message_tokens(msg: &ChatMessage) -> u32 {
    let mut tokens = 4u32; // Role overhead
    if let Some(ref content) = msg.content {
        tokens += estimate_tokens(content);
    }
    if let Some(ref parts) = msg.parts {
        for part in parts {
            tokens += match part {
                crate::provider::ContentPart::Text { text } => estimate_tokens(text),
                crate::provider::ContentPart::ToolResult { content, .. } => {
                    estimate_tokens(content) + 10
                }
                crate::provider::ContentPart::ToolUse { input, .. } => {
                    estimate_tokens(&input.to_string()) + 10
                }
            };
        }
    }
    tokens
}

/// Estimate total tokens for the full context (system + messages + tools).
fn estimate_context_tokens(
    system: &str,
    messages: &[ChatMessage],
    tools: &[crate::ToolDefinition],
) -> u32 {
    let mut total = estimate_tokens(system);
    for msg in messages {
        total += estimate_message_tokens(msg);
    }
    // Tool definitions contribute to context (~50 tokens per tool avg)
    total = total.saturating_add(tools.len().min(u32::MAX as usize) as u32 * 50);
    total
}

/// Truncate a tool output string to fit within the character limit.
/// Keeps the beginning and end, inserting a truncation notice in the middle.
/// Uses char indices (not byte offsets) to avoid slicing mid-UTF-8.
fn truncate_tool_output(output: &str, max_chars: usize) -> String {
    let char_count = output.chars().count();
    if char_count <= max_chars || max_chars == 0 {
        return output.to_string();
    }

    let keep = max_chars.saturating_sub(80); // Reserve space for notice
    let head_chars = keep * 2 / 3;
    let tail_chars = keep - head_chars;

    // Find byte offset of the head_chars-th character
    let head_byte = output
        .char_indices()
        .nth(head_chars)
        .map(|(i, _)| i)
        .unwrap_or(output.len());
    // Find byte offset of the (char_count - tail_chars)-th character
    let tail_byte = output
        .char_indices()
        .nth(char_count.saturating_sub(tail_chars))
        .map(|(i, _)| i)
        .unwrap_or(output.len());

    let head_str = &output[..head_byte];
    let tail_str = &output[tail_byte..];
    let omitted = char_count - head_chars - tail_chars;
    format!(
        "{head_str}\n\n[... {omitted} characters truncated — showing first {head_chars} and last {tail_chars} chars ...]\n\n{tail_str}"
    )
}

/// Trim the conversation to fit within the token budget.
///
/// Strategy: keep the first message (task prompt) and the last N messages
/// (most recent context). Drop messages in the middle, replacing them with
/// a summary marker.
///
/// Tool-call groups (an assistant message with tool_calls followed by its
/// tool-result messages) are treated as atomic units — we never split them,
/// since OpenAI rejects orphaned tool_call_ids with a 400 "invalid JSON" error.
fn trim_conversation(
    messages: &mut Vec<ChatMessage>,
    system: &str,
    tools: &[crate::ToolDefinition],
    config: &ContextConfig,
) {
    if config.max_context_tokens == 0 {
        return;
    }

    let total = estimate_context_tokens(system, messages, tools);
    if total <= config.max_context_tokens {
        return;
    }

    let min_keep = config.min_recent_messages;
    if messages.len() <= min_keep + 1 {
        // Not enough messages to trim
        return;
    }

    // Keep first message + last min_keep messages, drop the middle
    let mut drop_end = messages.len().saturating_sub(min_keep);
    if drop_end <= 1 {
        return;
    }

    // Adjust drop_end so we don't sever tool-call / tool-result pairs.
    // If the first kept message (at drop_end) is a tool-result, walk backward
    // to include the preceding assistant tool-call message in the kept set.
    while drop_end > 1 && is_tool_result(&messages[drop_end]) {
        drop_end -= 1;
    }

    // If after adjustment there's nothing left to drop, bail out.
    if drop_end <= 1 {
        return;
    }

    // If the last dropped message (at drop_end - 1) is an assistant message
    // with tool_calls, we must also drop the subsequent tool-result messages,
    // so advance drop_end past them.
    if has_tool_calls(&messages[drop_end - 1]) {
        while drop_end < messages.len() && is_tool_result(&messages[drop_end]) {
            drop_end += 1;
        }
    }

    if drop_end <= 1 || drop_end >= messages.len() {
        return;
    }

    let dropped = drop_end - 1;
    let summary = format!(
        "[Context trimmed: {dropped} earlier messages removed to stay within token budget. \
         The conversation continues from the most recent exchanges.]"
    );

    // Replace middle section with summary
    messages.splice(
        1..drop_end,
        std::iter::once(ChatMessage::text(crate::provider::Role::User, &summary)),
    );

    debug!(
        dropped = dropped,
        remaining = messages.len(),
        estimated_tokens = estimate_context_tokens(system, messages, tools),
        "Trimmed conversation context"
    );
}

/// Check if a message is a tool result (role=Tool or User with ToolResult parts).
fn is_tool_result(msg: &ChatMessage) -> bool {
    if msg.role == Role::Tool {
        return true;
    }
    if let Some(ref parts) = msg.parts {
        return parts
            .iter()
            .any(|p| matches!(p, ContentPart::ToolResult { .. }));
    }
    false
}

/// Check if a message is an assistant message with tool_use calls.
fn has_tool_calls(msg: &ChatMessage) -> bool {
    if msg.role != Role::Assistant {
        return false;
    }
    if let Some(ref parts) = msg.parts {
        return parts
            .iter()
            .any(|p| matches!(p, ContentPart::ToolUse { .. }));
    }
    false
}

/// Call the LLM with retry on transient errors (rate limits, network failures).
///
/// Uses exponential backoff with jitter. Respects `Retry-After` headers from
/// rate-limited responses. Non-retryable errors (auth, context too long) fail
/// immediately.
async fn call_with_retry(
    provider: &dyn LlmProvider,
    request: &LlmRequest,
    config: &RetryConfig,
    task_id: &str,
) -> Result<LlmResponse, LlmError> {
    let mut last_err: Option<LlmError> = None;

    for attempt in 0..=config.max_retries {
        match provider.chat(request).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                if !e.is_retryable() || attempt == config.max_retries {
                    return Err(e);
                }

                // Calculate delay: use Retry-After if available, otherwise exponential backoff
                let backoff_ms = config.base_delay_ms.saturating_mul(1u64 << attempt.min(10));
                let delay_ms = e
                    .retry_after_ms()
                    .unwrap_or(backoff_ms)
                    .min(config.max_delay_ms);

                // Add jitter: ±25% of the delay
                let jitter = delay_ms / 4;
                let jittered = if jitter > 0 {
                    let offset =
                        (simple_hash(attempt, task_id) % (jitter * 2)) as i64 - jitter as i64;
                    (delay_ms as i64 + offset).max(100) as u64
                } else {
                    delay_ms
                };

                warn!(
                    err = %e,
                    attempt = attempt + 1,
                    max_retries = config.max_retries,
                    delay_ms = jittered,
                    task_id = task_id,
                    "LLM call failed, retrying"
                );

                tokio::time::sleep(tokio::time::Duration::from_millis(jittered)).await;
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| LlmError::Other(anyhow::anyhow!("retry exhausted"))))
}

/// Simple deterministic hash for jitter (avoids rand dependency).
fn simple_hash(attempt: u32, task_id: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in task_id.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= attempt as u64;
    h = h.wrapping_mul(0x100000001b3);
    h
}

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
        let result = handle_builtin_callback(&call).unwrap();
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
        let result = handle_builtin_callback(&call).unwrap();
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
        let result = handle_builtin_callback(&call).unwrap();
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
        assert!(handle_builtin_callback(&call).is_err());
    }

    #[test]
    fn test_agent_loop_config_defaults() {
        let config = AgentLoopConfig::default();
        assert_eq!(config.max_steps, 75);
        assert_eq!(config.max_tokens, 4096);
        assert_eq!(config.retry.max_retries, 5);
        assert_eq!(config.retry.base_delay_ms, 1_000);
        assert_eq!(config.retry.max_delay_ms, 60_000);
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.base_delay_ms, 1_000);
        assert_eq!(config.max_delay_ms, 60_000);
    }

    #[test]
    fn test_llm_error_retryable() {
        assert!(LlmError::RateLimited {
            retry_after_ms: Some(1000)
        }
        .is_retryable());
        assert!(LlmError::Network("timeout".into()).is_retryable());
        assert!(LlmError::ApiError {
            status: 500,
            message: "internal error".into()
        }
        .is_retryable());
        assert!(LlmError::ApiError {
            status: 502,
            message: "bad gateway".into()
        }
        .is_retryable());
        assert!(!LlmError::AuthError("bad key".into()).is_retryable());
        assert!(!LlmError::ContextTooLong("too big".into()).is_retryable());
        assert!(!LlmError::ApiError {
            status: 400,
            message: "bad request".into()
        }
        .is_retryable());
    }

    #[test]
    fn test_llm_error_retry_after() {
        assert_eq!(
            LlmError::RateLimited {
                retry_after_ms: Some(5000)
            }
            .retry_after_ms(),
            Some(5000)
        );
        assert_eq!(
            LlmError::RateLimited {
                retry_after_ms: None
            }
            .retry_after_ms(),
            None
        );
        assert_eq!(LlmError::Network("err".into()).retry_after_ms(), None);
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash(0, "task-001");
        let h2 = simple_hash(0, "task-001");
        assert_eq!(h1, h2);

        let h3 = simple_hash(1, "task-001");
        assert_ne!(h1, h3);

        let h4 = simple_hash(0, "task-002");
        assert_ne!(h1, h4);
    }

    // Context management tests

    #[test]
    fn test_estimate_tokens() {
        assert_eq!(estimate_tokens(""), 0); // (0 + 3) / 4 = 0
        assert_eq!(estimate_tokens("hello"), 2); // (5 + 3) / 4 = 2
        assert_eq!(estimate_tokens(&"a".repeat(400)), 100); // (400 + 3) / 4 = 100
    }

    #[test]
    fn test_truncate_tool_output_short() {
        let output = "short output";
        assert_eq!(truncate_tool_output(output, 100), output);
    }

    #[test]
    fn test_truncate_tool_output_no_limit() {
        let output = "a".repeat(100_000);
        assert_eq!(truncate_tool_output(&output, 0), output);
    }

    #[test]
    fn test_truncate_tool_output_long() {
        let output = "a".repeat(50_000);
        let truncated = truncate_tool_output(&output, 1000);
        assert!(truncated.len() < 1200); // Slightly over due to notice
        assert!(truncated.contains("truncated"));
        assert!(truncated.starts_with("aaa")); // Head preserved
        assert!(truncated.ends_with("aaa")); // Tail preserved
    }

    #[test]
    fn test_context_config_defaults() {
        let config = ContextConfig::default();
        assert_eq!(config.max_context_tokens, 180_000);
        assert_eq!(config.max_tool_output_chars, 30_000);
        assert_eq!(config.min_recent_messages, 10);
    }

    #[test]
    fn test_trim_conversation_under_limit() {
        let mut messages = vec![
            ChatMessage::text(Role::User, "task prompt"),
            ChatMessage::text(Role::Assistant, "I'll scan."),
            ChatMessage::tool_result("call_1", "scan result"),
        ];
        let config = ContextConfig {
            max_context_tokens: 1_000_000,
            max_tool_output_chars: 0,
            min_recent_messages: 10,
        };
        let original_len = messages.len();
        trim_conversation(&mut messages, "system", &[], &config);
        assert_eq!(messages.len(), original_len); // No change
    }

    #[test]
    fn test_trim_conversation_disabled() {
        let mut messages = vec![ChatMessage::text(
            Role::User,
            "a".repeat(1_000_000).as_str(),
        )];
        let config = ContextConfig {
            max_context_tokens: 0, // Disabled
            max_tool_output_chars: 0,
            min_recent_messages: 10,
        };
        trim_conversation(&mut messages, "system", &[], &config);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_trim_conversation_drops_middle() {
        // Create a conversation that exceeds the limit
        let mut messages = Vec::new();
        messages.push(ChatMessage::text(Role::User, "task prompt"));
        for i in 0..20 {
            messages.push(ChatMessage::text(
                Role::Assistant,
                format!("Step {i}: {}", "x".repeat(500)),
            ));
            messages.push(ChatMessage::tool_result(
                format!("call_{i}"),
                "y".repeat(500),
            ));
        }
        // 1 + 40 = 41 messages

        let config = ContextConfig {
            max_context_tokens: 100, // Very low limit to force trimming
            max_tool_output_chars: 0,
            min_recent_messages: 4,
        };

        trim_conversation(&mut messages, "system", &[], &config);

        // Should have: first message + summary + last 4 messages = 6
        assert_eq!(messages.len(), 6);
        // First message preserved
        assert_eq!(messages[0].text_content().unwrap(), "task prompt");
        // Summary marker inserted
        assert!(messages[1]
            .text_content()
            .unwrap()
            .contains("Context trimmed"));
    }
}
