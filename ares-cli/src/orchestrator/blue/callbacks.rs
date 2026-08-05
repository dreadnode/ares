//! Blue team callback handler for orchestrator dispatch and query tools.
//!
//! Implements `CallbackHandler` to handle:
//! - **Dispatch tools** — `dispatch_triage`, `dispatch_threat_hunt`,
//!   `dispatch_lateral_analysis` run sub-agent loops inline and return results.
//! - **Query tools** — `get_investigation_status`, `get_task_result`,
//!   `wait_for_all_tasks` read from Redis investigation state.
//! - **Completion callbacks** — `complete_investigation`, `escalate_investigation`,
//!   `triage_complete`, etc. signal investigation lifecycle transitions.

use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};

use ares_core::op_state_log::OpStateRecorder;
use ares_llm::agent_loop::CallbackResult;
use ares_llm::tool_registry::blue::{self, BlueAgentRole};
use ares_llm::{
    run_agent_loop, AgentLoopConfig, CallbackHandler, LlmProvider, RunAgentLoopParams, TokenUsage,
    ToolCall, ToolDispatcher,
};

use super::simulated_response::{self, emit_simulated_response_span};
use super::sub_agent::{BlueToolDispatcher, SubAgentCallbackHandler};

/// All tool names this handler recognizes as callbacks.
pub(super) const BLUE_HANDLED_TOOLS: &[&str] = &[
    // Dispatch tools (run sub-agent loops)
    "dispatch_triage",
    "dispatch_threat_hunt",
    "dispatch_lateral_analysis",
    // Query tools
    "get_investigation_status",
    "get_task_result",
    "wait_for_all_tasks",
    // Completion/lifecycle callbacks
    "triage_complete",
    "hunt_complete",
    "lateral_complete",
    "complete_investigation",
    "escalate_investigation",
    "confirm_escalation",
    "downgrade_escalation",
    "request_reinvestigation",
    "route_to_team",
];

/// Blue team callback handler for the orchestrator agent.
///
/// Created per-investigation, holds references needed to run sub-agent loops
/// and query investigation state.
pub struct BlueCallbackHandler {
    provider: Arc<dyn LlmProvider>,
    dispatcher: Arc<dyn ToolDispatcher>,
    model: String,
    investigation_id: String,
    alert: serde_json::Value,
    redis_url: String,
    deployment: Option<String>,
    /// Operation ID pulled from the alert labels (or empty when the alert
    /// carries no operation context). Included on every simulated-response
    /// span so the `attack-demo-live` dashboard's per-operation filter matches.
    operation_id: String,
    /// Recorder for op-state events. When active, `confirm_escalation` with a
    /// containment action publishes a matching containment event so the
    /// red-side projector observes it and the exploitation queue drops
    /// entries whose preconditions are now invalid. Defaults to
    /// [`OpStateRecorder::disabled`] when the caller does not opt in.
    op_state_recorder: OpStateRecorder,
}

impl BlueCallbackHandler {
    /// Same as [`Self::new`] but wires an op-state recorder so that simulated
    /// containment actions confirmed through `confirm_escalation` are
    /// published as red-side observations. Callers that already own a
    /// NATS-backed recorder (production) or a capturing one (tests) should
    /// use this constructor; the recorder-less `new` still works and simply
    /// omits the red-side observation half of the demo path.
    pub fn with_recorder(
        provider: Arc<dyn LlmProvider>,
        dispatcher: Arc<dyn ToolDispatcher>,
        model: String,
        investigation_id: String,
        alert: serde_json::Value,
        redis_url: String,
        op_state_recorder: OpStateRecorder,
    ) -> Self {
        // Extract deployment from alert labels or fall back to env var
        let deployment = alert
            .get("labels")
            .and_then(|l| l.get("deployment"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("ARES_DEPLOYMENT").ok());

        // Correlate blue lifecycle spans with the red operation so the demo
        // dashboard's per-op filter picks them up. Empty string when the
        // alert carries no operation context (unit tests, ad-hoc alerts).
        let operation_id = alert
            .get("labels")
            .and_then(|l| l.get("operation_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Self {
            provider,
            dispatcher,
            model,
            investigation_id,
            alert,
            redis_url,
            deployment,
            operation_id,
            op_state_recorder,
        }
    }

    /// Run a sub-agent loop for a blue team role and return the result text.
    ///
    /// `pub(crate)` so the investigation lifecycle can drive auto-chained
    /// follow-up hunts inline after the orchestrator loop finishes (there is no
    /// blue-task worker fleet to consume an enqueued chained task).
    pub(crate) async fn run_sub_agent(
        &self,
        role: BlueAgentRole,
        task_prompt: &str,
    ) -> Result<String> {
        let tools = blue::blue_tools_for_role(role);
        let capabilities: Vec<String> = tools
            .iter()
            .filter(|t| !blue::is_blue_callback_tool(&t.name))
            .map(|t| t.name.clone())
            .collect();

        let system_prompt = ares_llm::prompt::blue::build_blue_system_prompt(
            role.as_str(),
            &capabilities,
            self.deployment.as_deref(),
        )?;

        let config = AgentLoopConfig {
            model: self.model.clone(),
            max_steps: 50,
            max_tool_calls_per_name: 25,
            // Capture the blue transcript when ARES_SESSION_LOG_DIR is set;
            // `..default()` disables session logging otherwise.
            session_log: ares_llm::SessionLogConfig::from_env(),
            // Sub-agents inherit the same deterministic-sampling knobs so all
            // three layers (root investigation, sub-agent, tool loop) sample
            // identically under `benchmark run --seed/--temperature`.
            temperature: super::investigation::parse_env_temperature(),
            seed: super::investigation::parse_env_seed(),
            ..AgentLoopConfig::default()
        };

        // Wrap the dispatcher so blue tools (add_evidence, add_technique, etc.)
        // are executed locally via dispatch_blue() instead of going through
        // the red-team dispatcher which doesn't know about them.
        let blue_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(BlueToolDispatcher {
            inner: Arc::clone(&self.dispatcher),
            investigation_id: self.investigation_id.clone(),
        });

        let sub_agent_cb: Arc<dyn CallbackHandler> = Arc::new(SubAgentCallbackHandler {
            investigation_id: self.investigation_id.clone(),
            redis_url: self.redis_url.clone(),
        });

        let outcome = run_agent_loop(RunAgentLoopParams {
            provider: self.provider.as_ref(),
            dispatcher: blue_dispatcher,
            config: &config,
            system_prompt: &system_prompt,
            task_prompt,
            role: role.as_str(),
            task_id: &self.investigation_id,
            tools: &tools,
            callback_handler: Some(sub_agent_cb),
            hostname_map: None,
        })
        .await;

        // Extract result text from the outcome
        let result = match &outcome.reason {
            ares_llm::LoopEndReason::TaskComplete { result, .. } => result.clone(),
            ares_llm::LoopEndReason::EndTurn { content } => content.clone(),
            ares_llm::LoopEndReason::RequestAssistance { issue, context } => {
                format!("Sub-agent requested assistance: {issue}. Context: {context}")
            }
            ares_llm::LoopEndReason::MaxSteps => {
                format!("Sub-agent hit max steps ({} steps)", outcome.steps)
            }
            ares_llm::LoopEndReason::MaxTokens => "Sub-agent hit max tokens".to_string(),
            ares_llm::LoopEndReason::BudgetExceeded { reason } => {
                format!("Sub-agent budget exceeded: {reason}")
            }
            ares_llm::LoopEndReason::Error(e) => format!("Sub-agent error: {e}"),
        };

        Ok(result)
    }

    /// Dispatch triage sub-agent.
    async fn dispatch_triage(&self, _call: &ToolCall) -> Result<CallbackResult> {
        info!(
            investigation_id = %self.investigation_id,
            "Dispatching triage sub-agent"
        );

        let alert_summary = serde_json::to_string_pretty(&self.alert).unwrap_or_default();
        let task_prompt = format!(
            "You are triaging alert for investigation {}.\n\n\
             Alert data:\n{}\n\n\
             Analyze this alert. Determine severity, identify key indicators of compromise, \
             and recommend whether this needs deeper investigation. Use the available Loki \
             query tools to examine relevant logs around the alert timeframe.",
            self.investigation_id, alert_summary
        );

        let result = self
            .run_sub_agent(BlueAgentRole::Triage, &task_prompt)
            .await?;
        info!(
            investigation_id = %self.investigation_id,
            "Triage sub-agent completed"
        );
        Ok(CallbackResult::Continue(format!(
            "Triage result:\n{result}"
        )))
    }

    /// Dispatch threat hunt sub-agent.
    async fn dispatch_threat_hunt(&self, call: &ToolCall) -> Result<CallbackResult> {
        let technique_id = call.arguments["technique_id"].as_str().unwrap_or("unknown");
        let detection_method = call.arguments["detection_method"]
            .as_str()
            .unwrap_or("log_analysis");
        let hostname = call.arguments["hostname"].as_str().unwrap_or("");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let context = call.arguments["context"].as_str().unwrap_or("");

        info!(
            investigation_id = %self.investigation_id,
            technique_id = technique_id,
            "Dispatching threat hunt sub-agent"
        );

        let mut task_prompt = format!(
            "You are hunting for MITRE ATT&CK technique {} in investigation {}.\n\
             Detection method: {}\n",
            technique_id, self.investigation_id, detection_method
        );
        if !hostname.is_empty() {
            task_prompt.push_str(&format!("Target host: {hostname}\n"));
        }
        if !username.is_empty() {
            task_prompt.push_str(&format!("Target user: {username}\n"));
        }
        if !context.is_empty() {
            task_prompt.push_str(&format!("Context: {context}\n"));
        }
        task_prompt.push_str(
            "\nUse the available Loki query tools to search for evidence of this technique. \
             Look for relevant log patterns, authentication events, process execution, \
             and lateral movement indicators.",
        );

        let result = self
            .run_sub_agent(BlueAgentRole::ThreatHunter, &task_prompt)
            .await?;
        info!(
            investigation_id = %self.investigation_id,
            technique_id = technique_id,
            "Threat hunt sub-agent completed"
        );
        Ok(CallbackResult::Continue(format!(
            "Threat hunt result ({technique_id}):\n{result}"
        )))
    }

    /// Dispatch lateral analysis sub-agent.
    async fn dispatch_lateral_analysis(&self, call: &ToolCall) -> Result<CallbackResult> {
        let focus_host = call.arguments["focus_host"].as_str().unwrap_or("unknown");
        let focus_user = call.arguments["focus_user"].as_str().unwrap_or("");
        let context = call.arguments["context"].as_str().unwrap_or("");

        info!(
            investigation_id = %self.investigation_id,
            focus_host = focus_host,
            "Dispatching lateral analysis sub-agent"
        );

        let mut task_prompt = format!(
            "You are analyzing lateral movement patterns in investigation {}.\n\
             Primary host: {}\n",
            self.investigation_id, focus_host
        );
        if !focus_user.is_empty() {
            task_prompt.push_str(&format!("Primary user: {focus_user}\n"));
        }
        if !context.is_empty() {
            task_prompt.push_str(&format!("Context: {context}\n"));
        }
        task_prompt.push_str(
            "\nUse the available Loki query tools to trace authentication patterns, \
             SMB/WinRM/RDP connections, and credential usage across hosts. Map the \
             lateral movement path and identify compromised accounts.",
        );

        let result = self
            .run_sub_agent(BlueAgentRole::LateralAnalyst, &task_prompt)
            .await?;
        info!(
            investigation_id = %self.investigation_id,
            focus_host = focus_host,
            "Lateral analysis sub-agent completed"
        );
        Ok(CallbackResult::Continue(format!(
            "Lateral analysis result:\n{result}"
        )))
    }

    /// Dispatch escalation triage sub-agent.
    ///
    /// Instead of immediately returning `RequestAssistance`, we launch an
    /// `EscalationTriage` sub-agent that reviews the investigation context and
    /// decides whether to confirm, downgrade, reinvestigate, or route.
    async fn dispatch_escalation_triage(&self, call: &ToolCall) -> Result<CallbackResult> {
        let reason = call.arguments["reason"].as_str().unwrap_or("unknown");
        let severity = call.arguments["severity"].as_str().unwrap_or("high");

        // Emit a simulated-response span for the escalation decision itself
        // so the demo dashboard shows the moment blue kicked off triage.
        let _ = emit_simulated_response_span(
            simulated_response::ACTION_ESCALATE_TO_HUMAN,
            severity,
            &self.investigation_id,
            &self.operation_id,
            reason,
        );

        info!(
            investigation_id = %self.investigation_id,
            severity = severity,
            reason = reason,
            "Dispatching escalation triage sub-agent"
        );

        let task_prompt = format!(
            "You are performing escalation triage for investigation {}.\n\n\
             Escalation reason: {}\n\
             Severity: {}\n\n\
             Review the full investigation context using get_investigation_context. \
             Then make ONE of these decisions:\n\
             1. confirm_escalation — if the evidence warrants human review\n\
             2. downgrade_escalation — if this is a false positive or low severity\n\
             3. request_reinvestigation — if more evidence is needed before deciding\n\
             4. route_to_team — if a specialist team should handle this\n\n\
             Be decisive. Evaluate the evidence quality, technique severity, and \
             scope of compromise before making your decision.",
            self.investigation_id, reason, severity
        );

        let result = self
            .run_sub_agent(BlueAgentRole::EscalationTriage, &task_prompt)
            .await?;

        info!(
            investigation_id = %self.investigation_id,
            "Escalation triage sub-agent completed"
        );

        // If the triage confirmed escalation, propagate as RequestAssistance
        // so the orchestrator loop terminates with escalated status.
        // Otherwise return the triage decision as a Continue so the orchestrator
        // can incorporate the finding (e.g., downgrade → complete investigation).
        let lower = result.to_lowercase();
        if lower.contains("escalation confirmed") || lower.contains("confirm") {
            Ok(CallbackResult::RequestAssistance {
                issue: format!("Escalation confirmed by triage ({severity}): {reason}"),
                context: result,
            })
        } else {
            Ok(CallbackResult::Continue(format!(
                "Escalation triage result:\n{result}"
            )))
        }
    }

    /// Handle `confirm_escalation`. Always emits a simulated-response span
    /// so the demo dashboard's `Simulated Response Actions` panel picks up
    /// the decision; when a containment action is named and the recorder is
    /// active, also publishes the matching op-state event so the red
    /// projector observes it and the queue-filter drops invalidated
    /// entries. Result value is identical to the pre-existing static path so
    /// upstream state machines are unaffected.
    async fn handle_confirm_escalation(&self, call: &ToolCall) -> Result<CallbackResult> {
        let action_type = call.arguments["containment_action"]
            .as_str()
            .unwrap_or(simulated_response::ACTION_ESCALATE_TO_HUMAN);
        let target = call.arguments["target"].as_str().unwrap_or("");
        let reasoning = call.arguments["reasoning"].as_str().unwrap_or("");

        let _ = emit_simulated_response_span(
            action_type,
            target,
            &self.investigation_id,
            &self.operation_id,
            reasoning,
        );

        if let Some(payload) =
            simulated_response::payload_for_containment(action_type, target, &self.investigation_id)
        {
            let op_id = if self.operation_id.is_empty() {
                &self.investigation_id
            } else {
                &self.operation_id
            };
            simulated_response::publish_containment(&self.op_state_recorder, op_id, payload).await;
        }

        // Preserve the lifecycle-callback contract from the static path.
        let action_result = call.arguments["action"].as_str().unwrap_or(action_type);
        Ok(CallbackResult::TaskComplete {
            task_id: "escalation_triage".into(),
            result: format!("Escalation confirmed: {action_result}"),
        })
    }

    /// Handle `downgrade_escalation`. Emits a simulated-response span so the
    /// dashboard shows blue explicitly ruling out containment (false
    /// positives are still a datapoint in the demo scoreboard). No
    /// containment publish — a downgrade never invalidates red's queue.
    async fn handle_downgrade_escalation(&self, call: &ToolCall) -> Result<CallbackResult> {
        let reason = call.arguments["reason"]
            .as_str()
            .or_else(|| call.arguments["reasoning"].as_str())
            .unwrap_or("");
        let _ = emit_simulated_response_span(
            simulated_response::ACTION_DOWNGRADE_ESCALATION,
            "",
            &self.investigation_id,
            &self.operation_id,
            reason,
        );
        Ok(CallbackResult::TaskComplete {
            task_id: "escalation_triage".into(),
            result: format!("Escalation downgraded: {reason}"),
        })
    }

    /// Handle query tools that read investigation state from Redis.
    async fn handle_query_tool(&self, call: &ToolCall) -> Result<CallbackResult> {
        match call.name.as_str() {
            "get_investigation_status" => {
                let reader = ares_core::state::BlueStateReader::new(self.investigation_id.clone());
                let mut conn = redis::Client::open(self.redis_url.as_str())?
                    .get_connection_manager()
                    .await?;
                match reader.load_state(&mut conn).await? {
                    Some(state) => {
                        let mut summary = format!(
                            "Investigation: {}\nStage: {:?}\n",
                            self.investigation_id, state.stage
                        );
                        if !state.evidence.is_empty() {
                            summary
                                .push_str(&format!("Evidence items: {}\n", state.evidence.len()));
                            for (i, ev) in state.evidence.iter().enumerate().take(10) {
                                summary.push_str(&format!(
                                    "  {}. [{}] {}\n",
                                    i + 1,
                                    ev.evidence_type,
                                    ev.value
                                ));
                            }
                        }
                        if !state.timeline.is_empty() {
                            summary
                                .push_str(&format!("Timeline events: {}\n", state.timeline.len()));
                        }
                        Ok(CallbackResult::Continue(summary))
                    }
                    None => Ok(CallbackResult::Continue(
                        "Investigation state not yet initialized.".to_string(),
                    )),
                }
            }
            "get_task_result" => {
                let task_id = call.arguments["task_id"].as_str().unwrap_or("unknown");
                Ok(CallbackResult::Continue(format!(
                    "Task {task_id} result lookup not yet implemented — \
                     sub-agent results are returned inline from dispatch tools."
                )))
            }
            "wait_for_all_tasks" => {
                // In the inline dispatch model, tasks complete synchronously
                Ok(CallbackResult::Continue(
                    "All dispatched tasks have completed (inline execution).".to_string(),
                ))
            }
            _ => Ok(CallbackResult::Continue(format!(
                "Unknown query tool: {}",
                call.name
            ))),
        }
    }

    /// Handle completion/lifecycle callbacks.
    pub(super) fn handle_lifecycle_callback(call: &ToolCall) -> Option<CallbackResult> {
        match call.name.as_str() {
            "triage_complete" => {
                let severity = call.arguments["severity"].as_str().unwrap_or("unknown");
                let summary = call.arguments["summary"].as_str().unwrap_or("");
                let escalate = call.arguments["escalate"].as_bool().unwrap_or(false);
                let result =
                    format!("Triage complete: severity={severity}, escalate={escalate}. {summary}");
                Some(CallbackResult::TaskComplete {
                    task_id: "triage".into(),
                    result,
                })
            }
            "hunt_complete" => {
                let findings = call.arguments["findings"].as_str().unwrap_or("");
                let confidence = call.arguments["confidence"].as_str().unwrap_or("medium");
                let result = format!("Hunt complete (confidence: {confidence}): {findings}");
                Some(CallbackResult::TaskComplete {
                    task_id: "threat_hunt".into(),
                    result,
                })
            }
            "lateral_complete" => {
                let connections = call.arguments["connections_found"].as_u64().unwrap_or(0);
                let summary = call.arguments["summary"].as_str().unwrap_or("");
                let result =
                    format!("Lateral analysis: {connections} connections found. {summary}");
                Some(CallbackResult::TaskComplete {
                    task_id: "lateral_analysis".into(),
                    result,
                })
            }
            "complete_investigation" => {
                let summary = call.arguments["summary"].as_str().unwrap_or("");
                let result = format!("Investigation complete. {summary}");
                Some(CallbackResult::TaskComplete {
                    task_id: "investigation".into(),
                    result,
                })
            }
            // escalate_investigation is handled async in dispatch_escalation_triage
            // confirm_escalation and downgrade_escalation are also handled
            // async now — see `handle_confirm_escalation` /
            // `handle_downgrade_escalation` for span emission + optional
            // simulated-containment publish.
            "confirm_escalation" => {
                let action = call.arguments["action"].as_str().unwrap_or("escalate");
                Some(CallbackResult::TaskComplete {
                    task_id: "escalation_triage".into(),
                    result: format!("Escalation confirmed: {action}"),
                })
            }
            "downgrade_escalation" => {
                let reason = call.arguments["reason"].as_str().unwrap_or("");
                Some(CallbackResult::TaskComplete {
                    task_id: "escalation_triage".into(),
                    result: format!("Escalation downgraded: {reason}"),
                })
            }
            "request_reinvestigation" => {
                let focus = call.arguments["focus"].as_str().unwrap_or("");
                Some(CallbackResult::Continue(format!(
                    "Reinvestigation queued with focus: {focus}"
                )))
            }
            "route_to_team" => {
                let team = call.arguments["team"].as_str().unwrap_or("soc");
                let priority = call.arguments["priority"].as_str().unwrap_or("medium");
                Some(CallbackResult::TaskComplete {
                    task_id: "routing".into(),
                    result: format!("Routed to {team} team (priority: {priority})"),
                })
            }
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl CallbackHandler for BlueCallbackHandler {
    fn is_callback(&self, tool_name: &str) -> bool {
        BLUE_HANDLED_TOOLS.contains(&tool_name)
    }

    async fn handle_callback(
        &self,
        call: &ToolCall,
        _role: &str,
    ) -> Option<Result<CallbackResult>> {
        match call.name.as_str() {
            // Dispatch tools — run sub-agent loops
            "dispatch_triage" => Some(self.dispatch_triage(call).await),
            "dispatch_threat_hunt" => Some(self.dispatch_threat_hunt(call).await),
            "dispatch_lateral_analysis" => Some(self.dispatch_lateral_analysis(call).await),

            // Escalation — launches escalation triage sub-agent
            "escalate_investigation" => Some(self.dispatch_escalation_triage(call).await),

            // Confirm/downgrade need &self so they can emit spans and
            // (optionally) publish simulated-containment op-state events.
            "confirm_escalation" => Some(self.handle_confirm_escalation(call).await),
            "downgrade_escalation" => Some(self.handle_downgrade_escalation(call).await),

            // Query tools
            "get_investigation_status" | "get_task_result" | "wait_for_all_tasks" => {
                Some(self.handle_query_tool(call).await)
            }

            // Lifecycle callbacks (triage_complete, hunt_complete, etc.)
            _ => Self::handle_lifecycle_callback(call).map(Ok),
        }
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
                    usage.cache_read_input_tokens.into(),
                    usage.output_tokens.into(),
                    model,
                )
                .await
                {
                    warn!(err = %e, "Failed to record blue token usage");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checks_callback() {
        let handler = BlueCallbackHandler {
            provider: Arc::new(MockProvider),
            dispatcher: Arc::new(MockDispatcher),
            model: "test".into(),
            investigation_id: "inv-test".into(),
            alert: json!({}),
            redis_url: "redis://localhost".into(),
            deployment: None,
            operation_id: String::new(),
            op_state_recorder: OpStateRecorder::disabled(),
        };

        assert!(handler.is_callback("dispatch_triage"));
        assert!(handler.is_callback("dispatch_threat_hunt"));
        assert!(handler.is_callback("dispatch_lateral_analysis"));
        assert!(handler.is_callback("complete_investigation"));
        assert!(handler.is_callback("escalate_investigation"));
        assert!(handler.is_callback("get_investigation_status"));
        assert!(!handler.is_callback("nmap_scan"));
        assert!(!handler.is_callback("query_loki_logs"));
    }

    #[test]
    fn triage_complete_callback() {
        let call = ToolCall {
            id: "c1".into(),
            name: "triage_complete".into(),
            arguments: json!({
                "severity": "high",
                "summary": "Kerberoasting detected",
                "escalate": true,
            }),
        };
        let result = BlueCallbackHandler::handle_lifecycle_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { result, .. } => {
                assert!(result.contains("high"));
                assert!(result.contains("escalate=true"));
            }
            _ => panic!("Expected TaskComplete"),
        }
    }

    #[test]
    fn escalate_investigation_not_in_lifecycle_callbacks() {
        // escalate_investigation is now handled async via dispatch_escalation_triage,
        // not the static handle_lifecycle_callback
        let call = ToolCall {
            id: "c2".into(),
            name: "escalate_investigation".into(),
            arguments: json!({
                "reason": "Active lateral movement detected",
                "severity": "critical",
            }),
        };
        assert!(BlueCallbackHandler::handle_lifecycle_callback(&call).is_none());
    }

    #[test]
    fn complete_investigation_callback() {
        let call = ToolCall {
            id: "c3".into(),
            name: "complete_investigation".into(),
            arguments: json!({
                "summary": "True positive: credential theft confirmed",
            }),
        };
        let result = BlueCallbackHandler::handle_lifecycle_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { result, .. } => {
                assert!(result.contains("credential theft"));
            }
            _ => panic!("Expected TaskComplete"),
        }
    }

    #[test]
    fn unknown_callback() {
        let call = ToolCall {
            id: "c4".into(),
            name: "nmap_scan".into(),
            arguments: json!({}),
        };
        assert!(BlueCallbackHandler::handle_lifecycle_callback(&call).is_none());
    }

    fn test_handler_with_recorder(recorder: OpStateRecorder) -> BlueCallbackHandler {
        BlueCallbackHandler::with_recorder(
            Arc::new(MockProvider),
            Arc::new(MockDispatcher),
            "test".into(),
            "inv-42".into(),
            json!({ "labels": { "operation_id": "op-42" } }),
            "redis://localhost".into(),
            recorder,
        )
    }

    #[tokio::test]
    async fn confirm_escalation_publishes_containment_when_action_named() {
        let recorder = OpStateRecorder::capturing();
        let handler = test_handler_with_recorder(recorder.clone());
        let call = ToolCall {
            id: "c-confirm".into(),
            name: "confirm_escalation".into(),
            arguments: json!({
                "reasoning": "Confirmed kerberoast, revoking service account",
                "severity": "high",
                "confidence": 0.9,
                "containment_action": "disable_ad_account",
                "target": "svc_mssql@contoso.local",
            }),
        };
        let outcome = handler.handle_confirm_escalation(&call).await.unwrap();
        assert!(matches!(outcome, CallbackResult::TaskComplete { .. }));
        let events = recorder.captured().await;
        assert_eq!(events.len(), 1, "expected one containment event published");
        assert!(matches!(
            events[0].payload,
            ares_core::models::OpStateEventPayload::CredentialRevoked { .. }
        ));
        assert_eq!(events[0].op_id, "op-42");
    }

    #[tokio::test]
    async fn confirm_escalation_without_action_only_emits_span() {
        let recorder = OpStateRecorder::capturing();
        let handler = test_handler_with_recorder(recorder.clone());
        let call = ToolCall {
            id: "c-confirm-noop".into(),
            name: "confirm_escalation".into(),
            arguments: json!({
                "reasoning": "Real intrusion, humans should decide the response",
                "severity": "critical",
                "confidence": 0.95,
                "containment_action": "escalate_to_human",
            }),
        };
        let outcome = handler.handle_confirm_escalation(&call).await.unwrap();
        assert!(matches!(outcome, CallbackResult::TaskComplete { .. }));
        // escalate_to_human is not a containment action, so no state event.
        assert!(recorder.captured().await.is_empty());
    }

    #[tokio::test]
    async fn confirm_escalation_target_only_publishes_when_present() {
        let recorder = OpStateRecorder::capturing();
        let handler = test_handler_with_recorder(recorder.clone());
        let call = ToolCall {
            id: "c-confirm-notarget".into(),
            name: "confirm_escalation".into(),
            arguments: json!({
                "reasoning": "Would isolate but target unknown",
                "severity": "high",
                "confidence": 0.7,
                "containment_action": "isolate_host_firewall",
                // no `target` — payload_for_containment must decline
            }),
        };
        let _ = handler.handle_confirm_escalation(&call).await.unwrap();
        assert!(
            recorder.captured().await.is_empty(),
            "no target should mean no containment publish"
        );
    }

    #[tokio::test]
    async fn downgrade_escalation_never_publishes_containment() {
        let recorder = OpStateRecorder::capturing();
        let handler = test_handler_with_recorder(recorder.clone());
        let call = ToolCall {
            id: "c-down".into(),
            name: "downgrade_escalation".into(),
            arguments: json!({
                "reasoning": "Turned out to be a scheduled scan",
                "is_false_positive": true,
                "confidence": 0.95,
            }),
        };
        let outcome = handler.handle_downgrade_escalation(&call).await.unwrap();
        assert!(matches!(outcome, CallbackResult::TaskComplete { .. }));
        assert!(recorder.captured().await.is_empty());
    }

    #[test]
    fn extract_operation_id_from_alert_labels() {
        let handler = BlueCallbackHandler::with_recorder(
            Arc::new(MockProvider),
            Arc::new(MockDispatcher),
            "test".into(),
            "inv-x".into(),
            json!({ "labels": { "operation_id": "op-hero-01" } }),
            "redis://localhost".into(),
            OpStateRecorder::capturing(),
        );
        assert_eq!(handler.operation_id, "op-hero-01");
    }

    #[test]
    fn extract_operation_id_defaults_empty() {
        let handler = BlueCallbackHandler::with_recorder(
            Arc::new(MockProvider),
            Arc::new(MockDispatcher),
            "test".into(),
            "inv-x".into(),
            json!({ "labels": { "deployment": "prod" } }),
            "redis://localhost".into(),
            OpStateRecorder::capturing(),
        );
        assert!(handler.operation_id.is_empty());
    }

    // Minimal mock types for tests
    struct MockProvider;

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        async fn chat(
            &self,
            _request: &ares_llm::provider::LlmRequest,
        ) -> std::result::Result<ares_llm::provider::LlmResponse, ares_llm::provider::LlmError>
        {
            unimplemented!("Mock provider")
        }
        fn name(&self) -> &str {
            "mock"
        }
    }

    struct MockDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for MockDispatcher {
        async fn dispatch_tool(
            &self,
            _role: &str,
            _task_id: &str,
            _call: &ToolCall,
        ) -> anyhow::Result<ares_llm::ToolExecResult> {
            Ok(ares_llm::ToolExecResult {
                output: "mock result".to_string(),
                error: None,
                discoveries: None,
                failure_kind: None,
            })
        }
    }
}
