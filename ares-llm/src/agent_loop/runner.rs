use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info, warn, Instrument};

use ares_core::telemetry::spans::{trace_decision, trace_tool_call, Team};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

/// Optional IP→FQDN map for enriching span `destination.address` with hostnames
/// discovered during the operation (e.g. from SMB/DNS enumeration).
pub type HostnameMap = Arc<HashMap<String, String>>;

use crate::provider::{
    ChatMessage, LlmProvider, LlmRequest, Role, StopReason, TokenUsage, ToolCall,
};
use crate::tool_registry;

use super::callbacks::handle_callback;
use super::config::AgentLoopConfig;
use super::context::{maybe_compact, truncate_tool_output, CompactionDecision};
use super::retry::call_with_retry;
use super::session_log::SessionLog;
use super::types::{
    AgentLoopOutcome, CallbackHandler, CallbackResult, LoopEndReason, ToolDispatcher,
    ToolExecResult,
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
            let ToolExecResult {
                output,
                error,
                discoveries,
            } = result;
            let output = if let Some(err) = error {
                format!("Error: {err}\n\nPartial output:\n{output}")
            } else {
                output
            };
            DispatchResult {
                call_id: call.id,
                output,
                discoveries,
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
    hostname_map: Option<HostnameMap>,
) -> AgentLoopOutcome {
    let op_id = resolve_operation_id_from_env();

    // Single parent span for the entire agent task. Every tool call, decision,
    // and LLM round-trip nested below inherits `op.id`/`task.id` so Tempo
    // queries can scope by operation or by individual task without relying on
    // each child span re-emitting the IDs.
    let span = tracing::info_span!(
        "agent.loop",
        "op.id" = %op_id,
        "task.id" = task_id,
        "agent.role" = role,
        "agent.model" = %config.model,
    );

    run_agent_loop_inner(
        provider,
        dispatcher,
        config,
        system_prompt,
        task_prompt,
        role,
        &op_id,
        task_id,
        tools,
        callback_handler,
        hostname_map,
    )
    .instrument(span)
    .await
}

fn resolve_operation_id_from_env() -> String {
    std::env::var("ARES_OPERATION_ID")
        .ok()
        .and_then(|v| {
            // ARES_OPERATION_ID may be a plain ID or a JSON envelope; try
            // to extract `operation_id` if it parses as JSON, else use raw.
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_str::<serde_json::Value>(&v)
            {
                map.get("operation_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            } else {
                Some(v)
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[allow(clippy::too_many_arguments)]
async fn run_agent_loop_inner(
    provider: &dyn LlmProvider,
    dispatcher: Arc<dyn ToolDispatcher>,
    config: &AgentLoopConfig,
    system_prompt: &str,
    task_prompt: &str,
    role: &str,
    op_id: &str,
    task_id: &str,
    tools: &[crate::ToolDefinition],
    callback_handler: Option<Arc<dyn CallbackHandler>>,
    hostname_map: Option<HostnameMap>,
) -> AgentLoopOutcome {
    let session_log = SessionLog::open(&config.session_log, op_id, task_id, role, &config.model);
    if session_log.enabled() {
        let tool_names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
        session_log.record_start(system_prompt, task_prompt, &tool_names);
    }

    let mut messages: Vec<ChatMessage> = vec![ChatMessage::text(Role::User, task_prompt)];
    if session_log.enabled() {
        session_log.record_message(0, &messages[0]);
    }

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
            return finish(
                &session_log,
                steps,
                LoopEndReason::MaxSteps,
                total_usage,
                tool_calls_dispatched,
                all_discoveries,
                all_tool_outputs,
            );
        }

        // Token budget circuit breaker: gate every iteration on cumulative usage.
        // This is the per-call gate squad has via MaxCost / ErrBudgetExceeded.
        if let Some(reason) = config
            .budget
            .check(total_usage.input_tokens, total_usage.output_tokens)
        {
            warn!(
                task_id = task_id,
                steps = steps,
                input_tokens = total_usage.input_tokens,
                output_tokens = total_usage.output_tokens,
                "Agent loop tripped budget breaker: {reason}"
            );
            return finish(
                &session_log,
                steps,
                LoopEndReason::BudgetExceeded { reason },
                total_usage,
                tool_calls_dispatched,
                all_discoveries,
                all_tool_outputs,
            );
        }

        steps += 1;

        // Proactive compaction (rolling): fires at the configured utilization
        // ratio (default 60%) on the cadence tick, with a hard ceiling fallback.
        let decision = maybe_compact(
            &mut messages,
            system_prompt,
            &active_tools,
            &config.context,
            steps,
        );
        match decision {
            CompactionDecision::Proactive | CompactionDecision::Reactive => {
                if session_log.enabled() {
                    let kind = match decision {
                        CompactionDecision::Proactive => "proactive",
                        CompactionDecision::Reactive => "reactive",
                        CompactionDecision::Skipped => "skipped",
                    };
                    session_log.record_compaction(steps, kind, 0, 0);
                }
            }
            CompactionDecision::Skipped => {}
        }

        // Build LLM request
        let mut request = LlmRequest::new(&config.model);
        request.system = Some(system_prompt.to_string());
        request.messages.clone_from(&messages);
        request.tools = active_tools.clone();
        request.max_tokens = config.max_tokens;
        request.temperature = config.temperature;
        request.enable_prompt_cache = config.enable_prompt_cache;

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
                return finish(
                    &session_log,
                    steps,
                    LoopEndReason::Error(e.to_string()),
                    total_usage,
                    tool_calls_dispatched,
                    all_discoveries,
                    all_tool_outputs,
                );
            }
        };

        // Accumulate token usage
        total_usage.input_tokens += response.usage.input_tokens;
        total_usage.output_tokens += response.usage.output_tokens;
        total_usage.cache_creation_input_tokens += response.usage.cache_creation_input_tokens;
        total_usage.cache_read_input_tokens += response.usage.cache_read_input_tokens;

        if session_log.enabled() {
            session_log.record_usage(steps, &response.usage);
        }

        // Report incremental token usage to callback handler (persists to Redis)
        if let Some(ref handler) = callback_handler {
            handler.on_token_usage(&response.usage, &config.model).await;
        }

        // Handle based on stop reason
        match response.stop_reason {
            StopReason::EndTurn if response.tool_calls.is_empty() => {
                let assistant_msg = ChatMessage::text(Role::Assistant, &response.content);
                if session_log.enabled() {
                    session_log.record_message(steps, &assistant_msg);
                }
                return finish(
                    &session_log,
                    steps,
                    LoopEndReason::EndTurn {
                        content: response.content,
                    },
                    total_usage,
                    tool_calls_dispatched,
                    all_discoveries,
                    all_tool_outputs,
                );
            }
            StopReason::MaxTokens if response.tool_calls.is_empty() => {
                return finish(
                    &session_log,
                    steps,
                    LoopEndReason::MaxTokens,
                    total_usage,
                    tool_calls_dispatched,
                    all_discoveries,
                    all_tool_outputs,
                );
            }
            _ => {}
        }

        if response.tool_calls.is_empty() {
            // No tool calls and not EndTurn/MaxTokens — add as assistant message and continue
            let m = ChatMessage::text(Role::Assistant, &response.content);
            if session_log.enabled() {
                session_log.record_message(steps, &m);
            }
            messages.push(m);
            continue;
        }

        let assistant_msg = ChatMessage::assistant_tool_use(
            if response.content.is_empty() {
                None
            } else {
                Some(response.content.clone())
            },
            response.tool_calls.clone(),
        );
        if session_log.enabled() {
            session_log.record_message(steps, &assistant_msg);
        }
        messages.push(assistant_msg);

        // Record LLM tool selection decisions for observability
        {
            let available: Vec<String> = active_tools.iter().map(|t| t.name.clone()).collect();
            for tc in &response.tool_calls {
                let span = trace_decision(
                    role,
                    Team::Red,
                    &tc.name,
                    &available,
                    None,
                    Some(op_id),
                    Some(task_id),
                );
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
                let mut ti = extract_target_info(&call.arguments);
                // Enrich: resolve IP→FQDN from discovered hosts when the
                // LLM only passed an IP in the tool arguments.
                if ti.target_fqdn.is_none() {
                    if let Some(ref map) = hostname_map {
                        if let Some(ip) = ti.target_ip.as_deref() {
                            if let Some(fqdn) = map.get(ip) {
                                ti.target_fqdn = Some(fqdn.clone());
                            }
                        }
                    }
                }
                let tt = infer_target_type_from_info(&ti);
                let span = trace_tool_call(
                    role,
                    Team::Red,
                    &call.name,
                    ti.target_ip.as_deref(),
                    ti.target_fqdn.as_deref(),
                    ti.target_user.as_deref(),
                    tt,
                    Some(op_id),
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
                    let tr = ChatMessage::tool_result(&call.id, &output);
                    if session_log.enabled() {
                        session_log.record_message(steps, &tr);
                    }
                    messages.push(tr);
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
                    let tr = ChatMessage::tool_result(
                        &call.id,
                        "Tool execution failed: no result received (dispatch error)",
                    );
                    if session_log.enabled() {
                        session_log.record_message(steps, &tr);
                    }
                    messages.push(tr);
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
                    let m = ChatMessage::text(
                        Role::User,
                        format!(
                            "[SYSTEM] The following tools have been removed and are no longer \
                             available: {removed_list}. Do not attempt to call them. \
                             Use alternative approaches or different tools."
                        ),
                    );
                    if session_log.enabled() {
                        session_log.record_message(steps, &m);
                    }
                    messages.push(m);
                }
            }
        }

        // Handle callbacks — dispatch tools (sub-agent loops) run in parallel,
        // lifecycle callbacks run sequentially after since they may short-circuit.
        if !callbacks.is_empty() {
            // Partition: dispatch_* tools can run concurrently; everything else is sequential
            let mut dispatch_calls: Vec<&ToolCall> = Vec::new();
            let mut sequential_calls: Vec<&ToolCall> = Vec::new();
            for call in &callbacks {
                if call.name.starts_with("dispatch_") {
                    dispatch_calls.push(call);
                } else {
                    sequential_calls.push(call);
                }
            }

            // Run dispatch callbacks concurrently via JoinSet when >1
            if dispatch_calls.len() > 1 {
                if let Some(ref handler) = callback_handler {
                    let mut join_set = tokio::task::JoinSet::new();
                    for call in &dispatch_calls {
                        let h = Arc::clone(handler);
                        let c = (*call).clone();
                        let r = role.to_string();
                        let tid = task_id.to_string();
                        let oid = op_id.to_string();
                        join_set.spawn(async move {
                            let cb_span = trace_tool_call(
                                &r,
                                Team::Red,
                                &c.name,
                                None,
                                None,
                                None,
                                None,
                                Some(&oid),
                                Some(&tid),
                                false,
                                None,
                            );
                            let result = handle_callback(&c, Some(h.as_ref()))
                                .instrument(cb_span)
                                .await;
                            (c.id.clone(), result)
                        });
                    }

                    while let Some(res) = join_set.join_next().await {
                        let (call_id, cb_result) = match res {
                            Ok(r) => r,
                            Err(e) => {
                                warn!(error = %e, "Dispatch callback join error");
                                continue;
                            }
                        };
                        match cb_result {
                            Ok(CallbackResult::TaskComplete {
                                task_id: tid,
                                result,
                            }) => {
                                info!(task_id = %tid, steps = steps, "Task completed");
                                let tr =
                                    ChatMessage::tool_result(&call_id, "Task marked as complete.");
                                if session_log.enabled() {
                                    session_log.record_message(steps, &tr);
                                }
                                messages.push(tr);
                                return finish(
                                    &session_log,
                                    steps,
                                    LoopEndReason::TaskComplete {
                                        task_id: tid,
                                        result,
                                    },
                                    total_usage,
                                    tool_calls_dispatched,
                                    all_discoveries,
                                    all_tool_outputs,
                                );
                            }
                            Ok(CallbackResult::RequestAssistance { issue, context }) => {
                                info!(issue = %issue, "Assistance requested");
                                return finish(
                                    &session_log,
                                    steps,
                                    LoopEndReason::RequestAssistance { issue, context },
                                    total_usage,
                                    tool_calls_dispatched,
                                    all_discoveries,
                                    all_tool_outputs,
                                );
                            }
                            Ok(CallbackResult::Continue(msg)) => {
                                let tr = ChatMessage::tool_result(&call_id, &msg);
                                if session_log.enabled() {
                                    session_log.record_message(steps, &tr);
                                }
                                messages.push(tr);
                            }
                            Err(e) => {
                                let tr = ChatMessage::tool_result(
                                    &call_id,
                                    format!("Callback error: {e}"),
                                );
                                if session_log.enabled() {
                                    session_log.record_message(steps, &tr);
                                }
                                messages.push(tr);
                            }
                        }
                    }
                }
            } else {
                // Single dispatch or no dispatches: run sequentially
                for call in &dispatch_calls {
                    let cb_span = trace_tool_call(
                        role,
                        Team::Red,
                        &call.name,
                        None,
                        None,
                        None,
                        None,
                        Some(op_id),
                        Some(task_id),
                        false,
                        None,
                    );
                    match handle_callback(call, callback_handler.as_deref())
                        .instrument(cb_span)
                        .await
                    {
                        Ok(CallbackResult::TaskComplete {
                            task_id: tid,
                            result,
                        }) => {
                            info!(task_id = %tid, steps = steps, "Task completed");
                            let tr = ChatMessage::tool_result(&call.id, "Task marked as complete.");
                            if session_log.enabled() {
                                session_log.record_message(steps, &tr);
                            }
                            messages.push(tr);
                            return finish(
                                &session_log,
                                steps,
                                LoopEndReason::TaskComplete {
                                    task_id: tid,
                                    result,
                                },
                                total_usage,
                                tool_calls_dispatched,
                                all_discoveries,
                                all_tool_outputs,
                            );
                        }
                        Ok(CallbackResult::RequestAssistance { issue, context }) => {
                            info!(issue = %issue, "Assistance requested");
                            return finish(
                                &session_log,
                                steps,
                                LoopEndReason::RequestAssistance { issue, context },
                                total_usage,
                                tool_calls_dispatched,
                                all_discoveries,
                                all_tool_outputs,
                            );
                        }
                        Ok(CallbackResult::Continue(msg)) => {
                            let tr = ChatMessage::tool_result(&call.id, &msg);
                            if session_log.enabled() {
                                session_log.record_message(steps, &tr);
                            }
                            messages.push(tr);
                        }
                        Err(e) => {
                            let tr =
                                ChatMessage::tool_result(&call.id, format!("Callback error: {e}"));
                            if session_log.enabled() {
                                session_log.record_message(steps, &tr);
                            }
                            messages.push(tr);
                        }
                    }
                }
            }

            // Handle sequential callbacks (lifecycle tools that may short-circuit)
            for call in &sequential_calls {
                let cb_span = trace_tool_call(
                    role,
                    Team::Red,
                    &call.name,
                    None,
                    None,
                    None,
                    None,
                    Some(op_id),
                    Some(task_id),
                    false,
                    None,
                );
                match handle_callback(call, callback_handler.as_deref())
                    .instrument(cb_span)
                    .await
                {
                    Ok(CallbackResult::TaskComplete {
                        task_id: tid,
                        result,
                    }) => {
                        info!(task_id = %tid, steps = steps, "Task completed");
                        let tr = ChatMessage::tool_result(&call.id, "Task marked as complete.");
                        if session_log.enabled() {
                            session_log.record_message(steps, &tr);
                        }
                        messages.push(tr);
                        return finish(
                            &session_log,
                            steps,
                            LoopEndReason::TaskComplete {
                                task_id: tid,
                                result,
                            },
                            total_usage,
                            tool_calls_dispatched,
                            all_discoveries,
                            all_tool_outputs,
                        );
                    }
                    Ok(CallbackResult::RequestAssistance { issue, context }) => {
                        info!(issue = %issue, "Assistance requested");
                        return finish(
                            &session_log,
                            steps,
                            LoopEndReason::RequestAssistance { issue, context },
                            total_usage,
                            tool_calls_dispatched,
                            all_discoveries,
                            all_tool_outputs,
                        );
                    }
                    Ok(CallbackResult::Continue(msg)) => {
                        let tr = ChatMessage::tool_result(&call.id, &msg);
                        if session_log.enabled() {
                            session_log.record_message(steps, &tr);
                        }
                        messages.push(tr);
                    }
                    Err(e) => {
                        let tr = ChatMessage::tool_result(&call.id, format!("Callback error: {e}"));
                        if session_log.enabled() {
                            session_log.record_message(steps, &tr);
                        }
                        messages.push(tr);
                    }
                }
            }
        }
    }
}

/// Centralized exit path: writes the terminal `outcome` record to the
/// session log and assembles the `AgentLoopOutcome`.
fn finish(
    session_log: &SessionLog,
    steps: u32,
    reason: LoopEndReason,
    total_usage: TokenUsage,
    tool_calls_dispatched: u32,
    discoveries: Vec<serde_json::Value>,
    tool_outputs: Vec<String>,
) -> AgentLoopOutcome {
    if session_log.enabled() {
        let (label, detail) = describe_reason(&reason);
        session_log.record_outcome(steps, label, detail);
    }
    AgentLoopOutcome {
        reason,
        total_usage,
        steps,
        tool_calls_dispatched,
        discoveries,
        tool_outputs,
    }
}

fn describe_reason(reason: &LoopEndReason) -> (&'static str, serde_json::Value) {
    match reason {
        LoopEndReason::TaskComplete { task_id, result } => (
            "TaskComplete",
            serde_json::json!({"task_id": task_id, "result": result}),
        ),
        LoopEndReason::RequestAssistance { issue, context } => (
            "RequestAssistance",
            serde_json::json!({"issue": issue, "context": context}),
        ),
        LoopEndReason::MaxSteps => ("MaxSteps", serde_json::Value::Null),
        LoopEndReason::EndTurn { content } => ("EndTurn", serde_json::json!({"content": content})),
        LoopEndReason::MaxTokens => ("MaxTokens", serde_json::Value::Null),
        LoopEndReason::BudgetExceeded { reason } => {
            ("BudgetExceeded", serde_json::json!({"reason": reason}))
        }
        LoopEndReason::Error(err) => ("Error", serde_json::json!({"err": err})),
    }
}

#[cfg(test)]
mod runner_tests {
    use super::*;

    #[test]
    fn describe_reason_task_complete() {
        let r = LoopEndReason::TaskComplete {
            task_id: "t-1".into(),
            result: "done".into(),
        };
        let (kind, payload) = describe_reason(&r);
        assert_eq!(kind, "TaskComplete");
        assert_eq!(payload["task_id"], "t-1");
        assert_eq!(payload["result"], "done");
    }

    #[test]
    fn describe_reason_request_assistance() {
        let r = LoopEndReason::RequestAssistance {
            issue: "stuck".into(),
            context: "tried 3 things".into(),
        };
        let (kind, payload) = describe_reason(&r);
        assert_eq!(kind, "RequestAssistance");
        assert_eq!(payload["issue"], "stuck");
        assert_eq!(payload["context"], "tried 3 things");
    }

    #[test]
    fn describe_reason_max_steps_and_max_tokens() {
        let (k, p) = describe_reason(&LoopEndReason::MaxSteps);
        assert_eq!(k, "MaxSteps");
        assert!(p.is_null());

        let (k, p) = describe_reason(&LoopEndReason::MaxTokens);
        assert_eq!(k, "MaxTokens");
        assert!(p.is_null());
    }

    #[test]
    fn describe_reason_end_turn_carries_content() {
        let r = LoopEndReason::EndTurn {
            content: "all done".into(),
        };
        let (k, p) = describe_reason(&r);
        assert_eq!(k, "EndTurn");
        assert_eq!(p["content"], "all done");
    }

    #[test]
    fn describe_reason_budget_exceeded_carries_reason() {
        let r = LoopEndReason::BudgetExceeded {
            reason: "input token budget exhausted (12000 >= 10000)".into(),
        };
        let (k, p) = describe_reason(&r);
        assert_eq!(k, "BudgetExceeded");
        assert!(p["reason"]
            .as_str()
            .unwrap()
            .contains("input token budget exhausted"));
    }

    #[test]
    fn describe_reason_error_carries_message() {
        let r = LoopEndReason::Error("network timeout".into());
        let (k, p) = describe_reason(&r);
        assert_eq!(k, "Error");
        assert_eq!(p["err"], "network timeout");
    }
}
