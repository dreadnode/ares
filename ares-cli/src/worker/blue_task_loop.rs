//! Blue team task consumption loop.
//!
//! Consumes tasks from `ares:blue:tasks:global:{role}`, runs the blue
//! team LLM agent loop with appropriate tools, and pushes results back
//! to `ares:blue:results:{task_id}`.
//!
//! This parallels the red team `task_loop` but uses:
//! - Blue task queue keys (`ares:blue:tasks:*`)
//! - Blue tool definitions from `ares_llm::tool_registry::blue`
//! - Blue prompt templates
//! - Blue state writer for investigation state mutations
//! - HTTP-based tools (Loki, Prometheus) instead of CLI wrappers

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, error, info, warn};

use ares_core::nats::NatsBroker;
use ares_core::state::blue_task_queue::{BlueTaskMessage, BlueTaskQueue, BlueTaskResult};
use ares_llm::tool_registry::blue::{self, BlueAgentRole};
use ares_llm::{
    run_agent_loop, AgentLoopConfig, LlmProvider, LoopEndReason, RunAgentLoopParams, ToolDispatcher,
};

use crate::worker::config::WorkerConfig;
use crate::worker::heartbeat::WorkerStatus;

pub struct BlueTaskLoopDeps<'a> {
    pub config: &'a WorkerConfig,
    pub conn: redis::aio::ConnectionManager,
    pub nats: NatsBroker,
    pub provider: Box<dyn LlmProvider>,
    pub dispatcher: Arc<dyn ToolDispatcher>,
    pub model_name: String,
    pub status_tx: tokio::sync::watch::Sender<WorkerStatus>,
    pub shutdown: Arc<tokio::sync::Notify>,
}

/// Run the blue team task consumption loop until shutdown.
pub async fn run_blue_task_loop(deps: BlueTaskLoopDeps<'_>) -> Result<()> {
    let BlueTaskLoopDeps {
        config,
        conn,
        nats,
        provider,
        dispatcher,
        model_name,
        status_tx,
        shutdown,
    } = deps;

    let role = parse_blue_role(&config.worker_role);
    let role_str = role.as_str();

    info!(
        role = role_str,
        agent = %config.agent_name,
        "Starting blue team task loop"
    );

    let mut task_queue = BlueTaskQueue::from_parts(conn, nats);

    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(60);

    loop {
        let poll_result = tokio::select! {
            result = task_queue.poll_global_task(role_str, config.poll_timeout.as_secs_f64()) => result,
            _ = shutdown.notified() => {
                info!("Blue task loop: shutdown signalled");
                return Ok(());
            }
        };

        match poll_result {
            Ok(Some(task)) => {
                retry_delay = Duration::from_secs(1);

                let _ = status_tx.send(WorkerStatus {
                    status: "busy".to_string(),
                    current_task: Some(task.task_id.clone()),
                });

                // Send blue team heartbeat
                let _ = task_queue
                    .send_heartbeat(
                        &config.agent_name,
                        "busy",
                        Some(&task.task_id),
                        role_str,
                        Some(&task.investigation_id),
                    )
                    .await;

                // Execute the blue team task
                let result = execute_blue_task(
                    &task,
                    role,
                    provider.as_ref(),
                    Arc::clone(&dispatcher),
                    &model_name,
                    &config.agent_name,
                )
                .await;

                // Push result
                if let Err(e) = task_queue.send_result(&result).await {
                    error!(
                        task_id = %task.task_id,
                        err = %e,
                        "Failed to send blue task result"
                    );
                }

                let _ = status_tx.send(WorkerStatus {
                    status: "idle".to_string(),
                    current_task: None,
                });

                let _ = task_queue
                    .send_heartbeat(
                        &config.agent_name,
                        "idle",
                        None,
                        role_str,
                        Some(&task.investigation_id),
                    )
                    .await;
            }
            Ok(None) => {
                retry_delay = Duration::from_secs(1);
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                let is_conn_error = ["connection", "closed", "timeout", "broken", "reset"]
                    .iter()
                    .any(|kw| error_str.contains(kw));

                if is_conn_error {
                    warn!(
                        delay_secs = retry_delay.as_secs(),
                        "Blue task loop: connection error, retrying: {e}"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = shutdown.notified() => return Ok(()),
                    }
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                } else {
                    error!("Blue task loop: non-connection error: {e}");
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

/// Execute a single blue team task through the LLM agent loop.
async fn execute_blue_task(
    task: &BlueTaskMessage,
    role: BlueAgentRole,
    provider: &dyn LlmProvider,
    dispatcher: Arc<dyn ToolDispatcher>,
    model_name: &str,
    agent_name: &str,
) -> BlueTaskResult {
    info!(
        task_id = %task.task_id,
        task_type = %task.task_type,
        role = role.as_str(),
        investigation_id = %task.investigation_id,
        "Executing blue team task"
    );

    // Build tools for this role
    let tools = blue::blue_tools_for_role(role);
    let capabilities: Vec<String> = tools
        .iter()
        .filter(|t| !blue::is_blue_callback_tool(&t.name))
        .map(|t| t.name.clone())
        .collect();

    // Build system prompt
    let system_prompt = match ares_llm::prompt::blue::build_blue_system_prompt(
        role.as_str(),
        &capabilities,
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            return BlueTaskResult::failure(
                &task.task_id,
                &task.investigation_id,
                format!("Failed to build system prompt: {e}"),
                agent_name,
            );
        }
    };

    // Build task prompt
    // First try to load investigation state summary (best-effort)
    let state_summary = "Investigation in progress.".to_string();

    let task_prompt = match ares_llm::prompt::blue::generate_blue_task_prompt(
        &task.task_type,
        &task.task_id,
        &task.params,
        &state_summary,
    ) {
        Some(p) => p,
        None => {
            // Fallback: use raw params as prompt
            format!(
                "## Task: {}\n\nType: {}\nInvestigation: {}\n\nParameters:\n```json\n{}\n```\n\n\
                 Complete this task and call the appropriate completion callback.",
                task.task_id,
                task.task_type,
                task.investigation_id,
                serde_json::to_string_pretty(&task.params).unwrap_or_default()
            )
        }
    };

    let config = AgentLoopConfig {
        model: model_name.to_string(),
        max_steps: 50,
        max_tool_calls_per_name: 25,
        ..AgentLoopConfig::default()
    };

    // Run the agent loop
    let outcome = run_agent_loop(RunAgentLoopParams {
        provider,
        dispatcher,
        config: &config,
        system_prompt: &system_prompt,
        task_prompt: &task_prompt,
        role: role.as_str(),
        task_id: &task.task_id,
        tools: &tools,
        callback_handler: None,
        hostname_map: None,
    })
    .await;

    // The outcome → BlueTaskResult conversion needs to log warn/error/info
    // for the operator-visible failure modes; the structural mapping itself
    // is pure and lives in `result_from_outcome` so each variant is covered
    // by unit tests without standing up an agent loop.
    match &outcome.reason {
        LoopEndReason::TaskComplete { .. } => info!(
            task_id = %task.task_id,
            steps = outcome.steps,
            tool_calls = outcome.tool_calls_dispatched,
            "Blue task completed"
        ),
        LoopEndReason::MaxSteps => {
            warn!(task_id = %task.task_id, steps = outcome.steps, "Blue task hit max steps");
        }
        LoopEndReason::Error(err) => {
            error!(task_id = %task.task_id, err = %err, "Blue task error");
        }
        _ => {}
    }

    result_from_outcome(task, &outcome, agent_name)
}

/// Project a finished `AgentLoopOutcome` into the `BlueTaskResult` that goes
/// back on the result queue.
///
/// Pure side-effect-free mapping. Operator-visible logging lives in the
/// caller (`execute_blue_task`) so this function stays unit-testable.
fn result_from_outcome(
    task: &BlueTaskMessage,
    outcome: &ares_llm::AgentLoopOutcome,
    agent_name: &str,
) -> BlueTaskResult {
    match &outcome.reason {
        LoopEndReason::TaskComplete { result, .. } => BlueTaskResult::success(
            &task.task_id,
            &task.investigation_id,
            serde_json::json!({
                "summary": result,
                "steps": outcome.steps,
                "tool_calls": outcome.tool_calls_dispatched,
            }),
            agent_name,
        ),
        LoopEndReason::EndTurn { content } => BlueTaskResult::success(
            &task.task_id,
            &task.investigation_id,
            serde_json::json!({
                "summary": content,
                "steps": outcome.steps,
            }),
            agent_name,
        ),
        LoopEndReason::RequestAssistance { issue, context } => BlueTaskResult::failure(
            &task.task_id,
            &task.investigation_id,
            format!("Assistance needed: {issue} (context: {context})"),
            agent_name,
        ),
        LoopEndReason::MaxSteps => BlueTaskResult::failure(
            &task.task_id,
            &task.investigation_id,
            format!("Hit max steps ({})", outcome.steps),
            agent_name,
        ),
        LoopEndReason::MaxTokens => BlueTaskResult::failure(
            &task.task_id,
            &task.investigation_id,
            "Hit max tokens".into(),
            agent_name,
        ),
        LoopEndReason::BudgetExceeded { reason } => BlueTaskResult::failure(
            &task.task_id,
            &task.investigation_id,
            format!("Budget exceeded: {reason}"),
            agent_name,
        ),
        LoopEndReason::Error(err) => BlueTaskResult::failure(
            &task.task_id,
            &task.investigation_id,
            err.clone(),
            agent_name,
        ),
    }
}

/// Parse a worker role string into a BlueAgentRole.
fn parse_blue_role(role: &str) -> BlueAgentRole {
    match role {
        "triage" => BlueAgentRole::Triage,
        "threat_hunter" => BlueAgentRole::ThreatHunter,
        "lateral_analyst" => BlueAgentRole::LateralAnalyst,
        "escalation_triage" => BlueAgentRole::EscalationTriage,
        "blue_orchestrator" => BlueAgentRole::Orchestrator,
        _ => {
            warn!(role = role, "Unknown blue team role, defaulting to Triage");
            BlueAgentRole::Triage
        }
    }
}

/// Blue team tool dispatcher that handles HTTP-based tools locally.
///
/// Blue team tools (Loki, Prometheus, detection queries) are HTTP-based
/// and don't need worker dispatch — they run in-process.
pub struct BlueLocalToolDispatcher;

impl BlueLocalToolDispatcher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for BlueLocalToolDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        call: &ares_llm::ToolCall,
    ) -> Result<ares_llm::ToolExecResult> {
        debug!(tool = %call.name, "Executing blue team tool locally");

        // Check if this is a blue team HTTP tool
        if ares_tools::blue::is_blue_tool(&call.name) {
            match ares_tools::blue::dispatch_blue(&call.name, &call.arguments).await {
                Ok(output) => {
                    let error = if output.success {
                        None
                    } else {
                        Some(output.stderr.clone())
                    };
                    Ok(ares_llm::ToolExecResult {
                        output: output.stdout,
                        error,
                        discoveries: None,
                    })
                }
                Err(e) => Ok(ares_llm::ToolExecResult {
                    output: String::new(),
                    error: Some(e.to_string()),
                    discoveries: None,
                }),
            }
        } else {
            // Unknown tool
            Ok(ares_llm::ToolExecResult {
                output: String::new(),
                error: Some(format!("Unknown blue team tool: {}", call.name)),
                discoveries: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_llm::AgentLoopOutcome;

    #[test]
    fn parses_blue_role() {
        assert_eq!(parse_blue_role("triage").as_str(), "triage");
        assert_eq!(parse_blue_role("threat_hunter").as_str(), "threat_hunter");
        assert_eq!(
            parse_blue_role("lateral_analyst").as_str(),
            "lateral_analyst"
        );
        assert_eq!(
            parse_blue_role("escalation_triage").as_str(),
            "escalation_triage"
        );
        assert_eq!(
            parse_blue_role("blue_orchestrator").as_str(),
            "blue_orchestrator"
        );
        // Unknown defaults to triage
        assert_eq!(parse_blue_role("unknown").as_str(), "triage");
    }

    fn task() -> BlueTaskMessage {
        BlueTaskMessage {
            task_id: "task-7".into(),
            investigation_id: "inv-7".into(),
            task_type: "hunt".into(),
            role: "threat_hunter".into(),
            params: serde_json::json!({}),
            created_at: "1970-01-01T00:00:00Z".into(),
        }
    }

    fn outcome(reason: LoopEndReason, steps: u32, tool_calls: u32) -> AgentLoopOutcome {
        AgentLoopOutcome {
            reason,
            total_usage: Default::default(),
            steps,
            tool_calls_dispatched: tool_calls,
            discoveries: Vec::new(),
            llm_findings: Vec::new(),
            tool_outputs: Vec::new(),
        }
    }

    #[test]
    fn task_complete_maps_to_success_with_summary_and_counters() {
        let out = outcome(
            LoopEndReason::TaskComplete {
                task_id: "task-7".into(),
                result: "Found 3 IOCs".into(),
            },
            12,
            4,
        );
        let r = result_from_outcome(&task(), &out, "agent-alpha");
        assert!(r.success);
        assert_eq!(r.task_id, "task-7");
        assert_eq!(r.investigation_id, "inv-7");
        assert_eq!(r.worker_agent.as_deref(), Some("agent-alpha"));
        let body = r.result.expect("result payload");
        assert_eq!(body["summary"], "Found 3 IOCs");
        assert_eq!(body["steps"], 12);
        assert_eq!(body["tool_calls"], 4);
    }

    #[test]
    fn end_turn_maps_to_success_with_content_and_steps_only() {
        let out = outcome(
            LoopEndReason::EndTurn {
                content: "Nothing to add.".into(),
            },
            5,
            2,
        );
        let r = result_from_outcome(&task(), &out, "agent-x");
        assert!(r.success);
        let body = r.result.expect("result payload");
        assert_eq!(body["summary"], "Nothing to add.");
        assert_eq!(body["steps"], 5);
        // EndTurn intentionally omits tool_calls to mirror the prior shape.
        assert!(body.get("tool_calls").is_none());
    }

    #[test]
    fn request_assistance_maps_to_failure_with_combined_message() {
        let out = outcome(
            LoopEndReason::RequestAssistance {
                issue: "missing creds".into(),
                context: "tried svc1, svc2".into(),
            },
            3,
            0,
        );
        let r = result_from_outcome(&task(), &out, "agent-x");
        assert!(!r.success);
        let err = r.error.expect("error");
        assert!(err.contains("missing creds"));
        assert!(err.contains("tried svc1, svc2"));
        assert!(r.result.is_none());
    }

    #[test]
    fn max_steps_maps_to_failure_with_step_count() {
        let out = outcome(LoopEndReason::MaxSteps, 50, 10);
        let r = result_from_outcome(&task(), &out, "agent-x");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("Hit max steps (50)"));
    }

    #[test]
    fn max_tokens_maps_to_failure_with_fixed_message() {
        let out = outcome(LoopEndReason::MaxTokens, 8, 1);
        let r = result_from_outcome(&task(), &out, "agent-x");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("Hit max tokens"));
    }

    #[test]
    fn budget_exceeded_maps_to_failure_with_reason_text() {
        let out = outcome(
            LoopEndReason::BudgetExceeded {
                reason: "input token budget exhausted (12000 >= 10000)".into(),
            },
            6,
            0,
        );
        let r = result_from_outcome(&task(), &out, "agent-x");
        assert!(!r.success);
        let err = r.error.expect("error");
        assert!(err.starts_with("Budget exceeded:"));
        assert!(err.contains("12000 >= 10000"));
    }

    #[test]
    fn error_variant_maps_to_failure_with_raw_message() {
        let out = outcome(LoopEndReason::Error("loki 502".into()), 0, 0);
        let r = result_from_outcome(&task(), &out, "agent-x");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("loki 502"));
    }
}
