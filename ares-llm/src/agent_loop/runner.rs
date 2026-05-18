use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info, warn, Instrument};

use ares_core::telemetry::spans::{
    trace_decision, trace_tool_call, Team, TraceDecisionParams, TraceToolCallParams,
};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

/// Optional IP→FQDN map for enriching span `destination.address` with hostnames
/// discovered during the operation (e.g. from SMB/DNS enumeration).
pub type HostnameMap = Arc<HashMap<String, String>>;

/// Inject a wrap-up nudge into the conversation when the agent has this
/// many (or fewer) steps remaining before MaxSteps. The nudge tells the
/// LLM to call `task_complete` with current findings rather than
/// chasing more sub-objectives. Five steps is enough room for the agent
/// to read the reminder, make ONE final tool call if it wants
/// (e.g. `report_finding`), and then close out — but small enough that
/// the warning isn't premature.
const WRAPUP_THRESHOLD_STEPS: u32 = 5;

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

pub struct RunAgentLoopParams<'a> {
    pub provider: &'a dyn LlmProvider,
    pub dispatcher: Arc<dyn ToolDispatcher>,
    pub config: &'a AgentLoopConfig,
    pub system_prompt: &'a str,
    pub task_prompt: &'a str,
    pub role: &'a str,
    pub task_id: &'a str,
    pub tools: &'a [crate::ToolDefinition],
    pub callback_handler: Option<Arc<dyn CallbackHandler>>,
    pub hostname_map: Option<HostnameMap>,
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
pub async fn run_agent_loop(p: RunAgentLoopParams<'_>) -> AgentLoopOutcome {
    let op_id = resolve_operation_id_from_env();

    // Single parent span for the entire agent task. Every tool call, decision,
    // and LLM round-trip nested below inherits `op.id`/`task.id` so Tempo
    // queries can scope by operation or by individual task without relying on
    // each child span re-emitting the IDs.
    let span = tracing::info_span!(
        "agent.loop",
        "op.id" = %op_id,
        "task.id" = p.task_id,
        "agent.role" = p.role,
        "agent.model" = %p.config.model,
    );

    let inner_params = RunAgentLoopInnerParams {
        provider: p.provider,
        dispatcher: p.dispatcher,
        config: p.config,
        system_prompt: p.system_prompt,
        task_prompt: p.task_prompt,
        role: p.role,
        op_id: &op_id,
        task_id: p.task_id,
        tools: p.tools,
        callback_handler: p.callback_handler,
        hostname_map: p.hostname_map,
    };

    run_agent_loop_inner(inner_params).instrument(span).await
}

fn resolve_operation_id_from_env() -> String {
    std::env::var("ARES_OPERATION_ID")
        .ok()
        .map(|v| parse_operation_id_envelope(&v))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Pull the operation id out of an `ARES_OPERATION_ID` value, which may be a
/// plain string or a JSON envelope with `{ "operation_id": "..." }`.
fn parse_operation_id_envelope(raw: &str) -> String {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(id) = map.get("operation_id").and_then(|x| x.as_str()) {
            return id.to_string();
        }
    }
    raw.to_string()
}

struct RunAgentLoopInnerParams<'a> {
    provider: &'a dyn LlmProvider,
    dispatcher: Arc<dyn ToolDispatcher>,
    config: &'a AgentLoopConfig,
    system_prompt: &'a str,
    task_prompt: &'a str,
    role: &'a str,
    op_id: &'a str,
    task_id: &'a str,
    tools: &'a [crate::ToolDefinition],
    callback_handler: Option<Arc<dyn CallbackHandler>>,
    hostname_map: Option<HostnameMap>,
}

async fn run_agent_loop_inner(p: RunAgentLoopInnerParams<'_>) -> AgentLoopOutcome {
    let RunAgentLoopInnerParams {
        provider,
        dispatcher,
        config,
        system_prompt,
        task_prompt,
        role,
        op_id,
        task_id,
        tools,
        callback_handler,
        hostname_map,
    } = p;
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
    let mut all_llm_findings: Vec<serde_json::Value> = Vec::new();
    let mut all_tool_outputs: Vec<crate::ToolOutput> = Vec::new();

    // Dynamic tool filtering: track unavailable tools and per-tool call counts
    // to prevent infinite retry loops on missing binaries and runaway tool calls.
    let mut active_tools: Vec<crate::ToolDefinition> = tools.to_vec();
    let mut tool_call_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let max_tool_calls_per_name = config.max_tool_calls_per_name;
    // Wrap-up nudge state: when `steps` reaches `max_steps - WRAPUP_THRESHOLD`,
    // inject ONE user-role reminder that tells the agent to call
    // task_complete with current findings before MaxSteps trips. Tracking
    // injection with a bool keeps the nudge to exactly one message so we
    // don't pollute the conversation if the agent keeps tool-calling after
    // the warning.
    let mut wrapup_nudge_injected = false;

    loop {
        if steps >= config.max_steps {
            warn!(task_id = task_id, steps = steps, "Agent loop hit max steps");
            return finish(FinishArgs {
                session_log: &session_log,
                steps,
                reason: LoopEndReason::MaxSteps,
                total_usage,
                tool_calls_dispatched,
                discoveries: all_discoveries,
                llm_findings: all_llm_findings,
                tool_outputs: all_tool_outputs,
            });
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
            return finish(FinishArgs {
                session_log: &session_log,
                steps,
                reason: LoopEndReason::BudgetExceeded { reason },
                total_usage,
                tool_calls_dispatched,
                discoveries: all_discoveries,
                llm_findings: all_llm_findings,
                tool_outputs: all_tool_outputs,
            });
        }

        steps += 1;

        // Wrap-up nudge: when we're WRAPUP_THRESHOLD steps from the cap,
        // inject one user-role reminder telling the agent to call
        // task_complete with current findings IMMEDIATELY. The goal is to
        // convert MaxSteps stalls (op evidence: mssql_deep_exploitation,
        // long ESC8 LLM-routed chains) into structured task completions
        // even when the agent hasn't finished every objective.
        //
        // Injected exactly once per loop run, gated by
        // `wrapup_nudge_injected`. The agent may still ignore it — that's
        // fine, MaxSteps + Tier 12's stalled-evidence credit still cover
        // the credit side. The nudge just gives the agent a chance to
        // converge cleanly.
        if !wrapup_nudge_injected
            && config.max_steps > WRAPUP_THRESHOLD_STEPS
            && steps >= config.max_steps.saturating_sub(WRAPUP_THRESHOLD_STEPS)
        {
            wrapup_nudge_injected = true;
            let nudge = format!(
                "STEP BUDGET ALMOST EXHAUSTED — {} steps remaining out of {}. \
                 Call `task_complete` NOW with whatever evidence you have: \
                 cracked credentials, NTLM hashes, captured tickets, \
                 confirmed remote SELECT rows, sysadmin pivot — anything \
                 parser-grounded is enough. The orchestrator chains follow-on \
                 automations from your discoveries; you do NOT need to chase \
                 remaining objectives in this task. Ending without \
                 task_complete marks the task as failed and forfeits the \
                 work you've already done.",
                config.max_steps.saturating_sub(steps),
                config.max_steps,
            );
            messages.push(ChatMessage::text(Role::User, nudge));
            warn!(
                task_id = task_id,
                steps = steps,
                max_steps = config.max_steps,
                "Agent loop injected MaxSteps wrap-up nudge"
            );
        }

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
                return finish(FinishArgs {
                    session_log: &session_log,
                    steps,
                    reason: LoopEndReason::Error(e.to_string()),
                    total_usage,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                    llm_findings: all_llm_findings,
                    tool_outputs: all_tool_outputs,
                });
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
                return finish(FinishArgs {
                    session_log: &session_log,
                    steps,
                    reason: LoopEndReason::EndTurn {
                        content: response.content,
                    },
                    total_usage,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                    llm_findings: all_llm_findings,
                    tool_outputs: all_tool_outputs,
                });
            }
            StopReason::MaxTokens if response.tool_calls.is_empty() => {
                return finish(FinishArgs {
                    session_log: &session_log,
                    steps,
                    reason: LoopEndReason::MaxTokens,
                    total_usage,
                    tool_calls_dispatched,
                    discoveries: all_discoveries,
                    llm_findings: all_llm_findings,
                    tool_outputs: all_tool_outputs,
                });
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
                let span = trace_decision(TraceDecisionParams {
                    role,
                    team: Team::Red,
                    tool_chosen: &tc.name,
                    tools_considered: &available,
                    confidence: None,
                    operation_id: Some(op_id),
                    task_id: Some(task_id),
                });
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
                let span = trace_tool_call(TraceToolCallParams {
                    role,
                    team: Team::Red,
                    tool_name: &call.name,
                    target_ip: ti.target_ip.as_deref(),
                    target_fqdn: ti.target_fqdn.as_deref(),
                    target_user: ti.target_user.as_deref(),
                    target_type: tt,
                    operation_id: Some(op_id),
                    task_id: Some(task_id),
                    is_error: false,
                    error_message: None,
                });
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
                    // Collect raw tool output (with tool name + args) for secondary
                    // regex extraction. Tool-aware extractors use the args to skip
                    // patterns that would misclassify echoed inputs (e.g. nxc -H
                    // echoes the hash on the same `[+] DOMAIN\user:secret` line that
                    // password-auth would emit, so the secret must not be ingested
                    // as a credential when args carry hash flags).
                    all_tool_outputs.push(crate::ToolOutput {
                        name: call.name.clone(),
                        arguments: call.arguments.clone(),
                        output: dr.output.clone(),
                    });
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
                            let cb_span = trace_tool_call(TraceToolCallParams {
                                role: &r,
                                team: Team::Red,
                                tool_name: &c.name,
                                target_ip: None,
                                target_fqdn: None,
                                target_user: None,
                                target_type: None,
                                operation_id: Some(&oid),
                                task_id: Some(&tid),
                                is_error: false,
                                error_message: None,
                            });
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
                                return finish(FinishArgs {
                                    session_log: &session_log,
                                    steps,
                                    reason: LoopEndReason::TaskComplete {
                                        task_id: tid,
                                        result,
                                    },
                                    total_usage,
                                    tool_calls_dispatched,
                                    discoveries: all_discoveries,
                                    llm_findings: all_llm_findings,
                                    tool_outputs: all_tool_outputs,
                                });
                            }
                            Ok(CallbackResult::RequestAssistance { issue, context }) => {
                                info!(issue = %issue, "Assistance requested");
                                return finish(FinishArgs {
                                    session_log: &session_log,
                                    steps,
                                    reason: LoopEndReason::RequestAssistance { issue, context },
                                    total_usage,
                                    tool_calls_dispatched,
                                    discoveries: all_discoveries,
                                    llm_findings: all_llm_findings,
                                    tool_outputs: all_tool_outputs,
                                });
                            }
                            Ok(CallbackResult::Continue(msg)) => {
                                let tr = ChatMessage::tool_result(&call_id, &msg);
                                if session_log.enabled() {
                                    session_log.record_message(steps, &tr);
                                }
                                messages.push(tr);
                            }
                            Ok(CallbackResult::LlmFinding { response, finding }) => {
                                all_llm_findings.push(finding);
                                messages.push(ChatMessage::tool_result(&call_id, &response));
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
                    let cb_span = trace_tool_call(TraceToolCallParams {
                        role,
                        team: Team::Red,
                        tool_name: &call.name,
                        target_ip: None,
                        target_fqdn: None,
                        target_user: None,
                        target_type: None,
                        operation_id: Some(op_id),
                        task_id: Some(task_id),
                        is_error: false,
                        error_message: None,
                    });
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
                            return finish(FinishArgs {
                                session_log: &session_log,
                                steps,
                                reason: LoopEndReason::TaskComplete {
                                    task_id: tid,
                                    result,
                                },
                                total_usage,
                                tool_calls_dispatched,
                                discoveries: all_discoveries,
                                llm_findings: all_llm_findings,
                                tool_outputs: all_tool_outputs,
                            });
                        }
                        Ok(CallbackResult::RequestAssistance { issue, context }) => {
                            info!(issue = %issue, "Assistance requested");
                            return finish(FinishArgs {
                                session_log: &session_log,
                                steps,
                                reason: LoopEndReason::RequestAssistance { issue, context },
                                total_usage,
                                tool_calls_dispatched,
                                discoveries: all_discoveries,
                                llm_findings: all_llm_findings,
                                tool_outputs: all_tool_outputs,
                            });
                        }
                        Ok(CallbackResult::Continue(msg)) => {
                            let tr = ChatMessage::tool_result(&call.id, &msg);
                            if session_log.enabled() {
                                session_log.record_message(steps, &tr);
                            }
                            messages.push(tr);
                        }
                        Ok(CallbackResult::LlmFinding { response, finding }) => {
                            all_llm_findings.push(finding);
                            messages.push(ChatMessage::tool_result(&call.id, &response));
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
                let cb_span = trace_tool_call(TraceToolCallParams {
                    role,
                    team: Team::Red,
                    tool_name: &call.name,
                    target_ip: None,
                    target_fqdn: None,
                    target_user: None,
                    target_type: None,
                    operation_id: Some(op_id),
                    task_id: Some(task_id),
                    is_error: false,
                    error_message: None,
                });
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
                        return finish(FinishArgs {
                            session_log: &session_log,
                            steps,
                            reason: LoopEndReason::TaskComplete {
                                task_id: tid,
                                result,
                            },
                            total_usage,
                            tool_calls_dispatched,
                            discoveries: all_discoveries,
                            llm_findings: all_llm_findings,
                            tool_outputs: all_tool_outputs,
                        });
                    }
                    Ok(CallbackResult::RequestAssistance { issue, context }) => {
                        info!(issue = %issue, "Assistance requested");
                        return finish(FinishArgs {
                            session_log: &session_log,
                            steps,
                            reason: LoopEndReason::RequestAssistance { issue, context },
                            total_usage,
                            tool_calls_dispatched,
                            discoveries: all_discoveries,
                            llm_findings: all_llm_findings,
                            tool_outputs: all_tool_outputs,
                        });
                    }
                    Ok(CallbackResult::Continue(msg)) => {
                        let tr = ChatMessage::tool_result(&call.id, &msg);
                        if session_log.enabled() {
                            session_log.record_message(steps, &tr);
                        }
                        messages.push(tr);
                    }
                    Ok(CallbackResult::LlmFinding { response, finding }) => {
                        all_llm_findings.push(finding);
                        messages.push(ChatMessage::tool_result(&call.id, &response));
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

struct FinishArgs<'a> {
    session_log: &'a SessionLog,
    steps: u32,
    reason: LoopEndReason,
    total_usage: TokenUsage,
    tool_calls_dispatched: u32,
    discoveries: Vec<serde_json::Value>,
    llm_findings: Vec<serde_json::Value>,
    tool_outputs: Vec<crate::ToolOutput>,
}

/// Centralized exit path: writes the terminal `outcome` record to the
/// session log and assembles the `AgentLoopOutcome`.
fn finish(args: FinishArgs<'_>) -> AgentLoopOutcome {
    let FinishArgs {
        session_log,
        steps,
        reason,
        total_usage,
        tool_calls_dispatched,
        discoveries,
        llm_findings,
        tool_outputs,
    } = args;
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
        llm_findings,
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

    // --- wrap-up nudge ---------------------------------------------------
    //
    // The full nudge-injection path lives inside `run_agent_loop`, which
    // is end-to-end (provider + dispatcher + tool registry). The unit
    // covered here is the gate predicate — pulled out as `should_inject_wrapup_nudge`
    // so we can verify the boundary math without firing the loop.

    fn should_inject_wrapup_nudge(steps: u32, max_steps: u32, already_injected: bool) -> bool {
        // Mirrors the gate at runner.rs:~265 — keeps the math testable
        // even though the side-effect (messages.push) is inside the loop.
        !already_injected
            && max_steps > super::WRAPUP_THRESHOLD_STEPS
            && steps >= max_steps.saturating_sub(super::WRAPUP_THRESHOLD_STEPS)
    }

    #[test]
    fn wrapup_nudge_fires_within_threshold_window() {
        // Default max_steps is 75; threshold is 5 ⇒ nudge at steps 70, 71, ...
        assert!(should_inject_wrapup_nudge(70, 75, false));
        assert!(should_inject_wrapup_nudge(71, 75, false));
        assert!(should_inject_wrapup_nudge(74, 75, false));
        assert!(should_inject_wrapup_nudge(75, 75, false));
    }

    #[test]
    fn wrapup_nudge_does_not_fire_before_threshold() {
        // 69 steps with 75 cap and threshold=5 → 6 steps remaining, no nudge.
        assert!(!should_inject_wrapup_nudge(69, 75, false));
        assert!(!should_inject_wrapup_nudge(50, 75, false));
        assert!(!should_inject_wrapup_nudge(0, 75, false));
    }

    #[test]
    fn wrapup_nudge_fires_at_most_once() {
        // Once the flag is set, subsequent ticks within the window must
        // not re-inject — duplicate reminders bloat the conversation
        // without helping the agent converge.
        assert!(!should_inject_wrapup_nudge(71, 75, true));
        assert!(!should_inject_wrapup_nudge(74, 75, true));
    }

    #[test]
    fn parse_operation_id_envelope_plain_string() {
        assert_eq!(parse_operation_id_envelope("op-12345"), "op-12345");
    }

    #[test]
    fn parse_operation_id_envelope_json_with_operation_id() {
        let raw = r#"{"operation_id":"op-json-99","other":"ignored"}"#;
        assert_eq!(parse_operation_id_envelope(raw), "op-json-99");
    }

    #[test]
    fn parse_operation_id_envelope_json_missing_field_returns_raw() {
        // Valid JSON object without `operation_id` falls back to the raw string
        // so callers can still trace it back to the original env value.
        let raw = r#"{"target_domain":"contoso.local"}"#;
        assert_eq!(parse_operation_id_envelope(raw), raw);
    }

    #[test]
    fn parse_operation_id_envelope_malformed_json_returns_raw() {
        assert_eq!(parse_operation_id_envelope("{not json"), "{not json");
    }

    #[test]
    fn parse_operation_id_envelope_json_non_object_returns_raw() {
        // JSON arrays / scalars are not envelopes — treat as opaque.
        assert_eq!(parse_operation_id_envelope("[1,2,3]"), "[1,2,3]");
        assert_eq!(
            parse_operation_id_envelope("\"op-quoted\""),
            "\"op-quoted\""
        );
    }

    #[test]
    fn wrapup_nudge_skipped_when_max_steps_too_small() {
        // For pathological configs (max_steps <= threshold) the math
        // would saturate to zero and fire at step 1 — uncomfortable
        // behavior for small caps. Gate keeps the nudge to runs with
        // breathing room.
        assert!(!should_inject_wrapup_nudge(0, 3, false));
        assert!(!should_inject_wrapup_nudge(0, 5, false));
        // Boundary: max_steps == threshold+1 → first valid case.
        assert!(should_inject_wrapup_nudge(1, 6, false));
    }
}
