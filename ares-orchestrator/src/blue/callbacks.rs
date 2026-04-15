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

use ares_llm::agent_loop::CallbackResult;
use ares_llm::tool_registry::blue::{self, BlueAgentRole};
use ares_llm::{
    run_agent_loop, AgentLoopConfig, CallbackHandler, LlmProvider, TokenUsage, ToolCall,
    ToolDispatcher,
};

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
}

impl BlueCallbackHandler {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        dispatcher: Arc<dyn ToolDispatcher>,
        model: String,
        investigation_id: String,
        alert: serde_json::Value,
        redis_url: String,
    ) -> Self {
        Self {
            provider,
            dispatcher,
            model,
            investigation_id,
            alert,
            redis_url,
        }
    }

    /// Run a sub-agent loop for a blue team role and return the result text.
    async fn run_sub_agent(&self, role: BlueAgentRole, task_prompt: &str) -> Result<String> {
        let tools = blue::blue_tools_for_role(role);
        let capabilities: Vec<String> = tools
            .iter()
            .filter(|t| !blue::is_blue_callback_tool(&t.name))
            .map(|t| t.name.clone())
            .collect();

        let system_prompt =
            ares_llm::prompt::blue::build_blue_system_prompt(role.as_str(), &capabilities)?;

        let config = AgentLoopConfig {
            model: self.model.clone(),
            max_steps: 50,
            max_tool_calls_per_name: 25,
            ..AgentLoopConfig::default()
        };

        // Wrap the dispatcher so blue tools (add_evidence, add_technique, etc.)
        // are executed locally via dispatch_blue() instead of going through
        // the red-team dispatcher which doesn't know about them.
        let blue_dispatcher: Arc<dyn ToolDispatcher> = Arc::new(BlueToolDispatcher {
            inner: Arc::clone(&self.dispatcher),
        });

        let sub_agent_cb: Arc<dyn CallbackHandler> = Arc::new(SubAgentCallbackHandler {
            investigation_id: self.investigation_id.clone(),
            redis_url: self.redis_url.clone(),
        });

        let outcome = run_agent_loop(
            self.provider.as_ref(),
            blue_dispatcher,
            &config,
            &system_prompt,
            task_prompt,
            role.as_str(),
            &self.investigation_id,
            &tools,
            Some(sub_agent_cb),
        )
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
                    result: result.to_string(),
                })
            }
            // escalate_investigation is handled async in dispatch_escalation_triage
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

    async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>> {
        match call.name.as_str() {
            // Dispatch tools — run sub-agent loops
            "dispatch_triage" => Some(self.dispatch_triage(call).await),
            "dispatch_threat_hunt" => Some(self.dispatch_threat_hunt(call).await),
            "dispatch_lateral_analysis" => Some(self.dispatch_lateral_analysis(call).await),

            // Escalation — launches escalation triage sub-agent
            "escalate_investigation" => Some(self.dispatch_escalation_triage(call).await),

            // Query tools
            "get_investigation_status" | "get_task_result" | "wait_for_all_tasks" => {
                Some(self.handle_query_tool(call).await)
            }

            // Lifecycle callbacks
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
    fn test_is_callback() {
        let handler = BlueCallbackHandler {
            provider: Arc::new(MockProvider),
            dispatcher: Arc::new(MockDispatcher),
            model: "test".into(),
            investigation_id: "inv-test".into(),
            alert: json!({}),
            redis_url: "redis://localhost".into(),
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
    fn test_triage_complete_callback() {
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
    fn test_escalate_investigation_not_in_lifecycle_callbacks() {
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
    fn test_complete_investigation_callback() {
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
    fn test_unknown_callback() {
        let call = ToolCall {
            id: "c4".into(),
            name: "nmap_scan".into(),
            arguments: json!({}),
        };
        assert!(BlueCallbackHandler::handle_lifecycle_callback(&call).is_none());
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
            })
        }
    }
}
