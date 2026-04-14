//! Investigation lifecycle management.
//!
//! Handles creating investigations, dispatching tasks to workers,
//! processing results, and driving the investigation to completion.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use tracing::{info, warn};

use ares_core::eval::workflow::evaluate_live_investigation;
use ares_core::state::blue_task_queue::{BlueTaskMessage, BlueTaskQueue, BlueTaskResult};
use ares_core::state::{BlueStateReader, BlueStateWriter, RedisStateReader};
use ares_llm::tool_registry::blue::BlueAgentRole;
use ares_llm::{
    run_agent_loop, AgentLoopConfig, AgentLoopOutcome, LlmProvider, LoopEndReason, ToolDispatcher,
};

use super::chaining;

/// Represents a running investigation.
pub struct Investigation {
    pub investigation_id: String,
    pub alert: serde_json::Value,
    pub model: String,
    /// Red team operation ID for post-investigation scoring against ground truth.
    pub operation_id: Option<String>,
    pub state_writer: BlueStateWriter,
}

impl Investigation {
    pub fn new(
        investigation_id: String,
        alert: serde_json::Value,
        model: String,
        operation_id: Option<String>,
    ) -> Self {
        let state_writer = BlueStateWriter::new(investigation_id.clone());
        Self {
            investigation_id,
            alert,
            model,
            operation_id,
            state_writer,
        }
    }
}

/// Run a complete investigation workflow driven by the orchestrator LLM.
///
/// The orchestrator agent coordinates triage, threat hunting, and lateral
/// analysis by calling `dispatch_task` and processing results.
pub async fn run_investigation(
    investigation: &Investigation,
    provider: &dyn LlmProvider,
    dispatcher: Arc<dyn ToolDispatcher>,
    _task_queue: &mut BlueTaskQueue,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<InvestigationOutcome> {
    info!(
        investigation_id = %investigation.investigation_id,
        "Starting blue team investigation"
    );

    // Initialize investigation state in Redis
    investigation
        .state_writer
        .initialize(conn, &investigation.alert)
        .await
        .context("Failed to initialize investigation state")?;

    investigation
        .state_writer
        .set_status(conn, &serde_json::Value::String("in_progress".into()))
        .await
        .ok();

    // Build the orchestrator system prompt
    let role = BlueAgentRole::Orchestrator;
    let tools = ares_llm::tool_registry::blue::blue_tools_for_role(role);
    let capabilities: Vec<String> = tools
        .iter()
        .filter(|t| !ares_llm::tool_registry::blue::is_blue_callback_tool(&t.name))
        .map(|t| t.name.clone())
        .collect();

    let system_prompt =
        ares_llm::prompt::blue::build_blue_system_prompt(role.as_str(), &capabilities)
            .context("Failed to build blue orchestrator system prompt")?;

    // Build the task prompt with alert context
    let alert_summary = investigation
        .alert
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown alert");
    let now_str = Utc::now().to_rfc3339();
    let alert_timestamp = investigation
        .alert
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or(&now_str);

    let task_prompt = format!(
        "## New Investigation: {}\n\n\
         **Alert Summary**: {}\n\
         **Timestamp**: {}\n\
         **Investigation ID**: {}\n\n\
         Full alert data:\n```json\n{}\n```\n\n\
         Coordinate the investigation using your available tools. \
         Start with triage, then dispatch threat hunting and lateral analysis as needed.",
        investigation.investigation_id,
        alert_summary,
        alert_timestamp,
        investigation.investigation_id,
        serde_json::to_string_pretty(&investigation.alert).unwrap_or_default()
    );

    let config = AgentLoopConfig {
        model: investigation.model.clone(),
        max_steps: 50,
        ..AgentLoopConfig::default()
    };

    // Run the orchestrator agent loop
    let outcome = run_agent_loop(
        provider,
        dispatcher,
        &config,
        &system_prompt,
        &task_prompt,
        role.as_str(),
        &investigation.investigation_id,
        &tools,
        None, // Blue team doesn't need custom callbacks
    )
    .await;

    let investigation_outcome = process_outcome(&outcome, &investigation.investigation_id);

    // Auto-chain follow-up tasks based on discoveries from the agent loop.
    let mut dispatched_chains: HashSet<String> = HashSet::new();
    let mut chained_task_ids: Vec<String> = Vec::new();

    for discovery in &outcome.discoveries {
        let synthetic_result = BlueTaskResult {
            task_id: format!("discovery_{}", investigation.investigation_id),
            investigation_id: investigation.investigation_id.clone(),
            success: true,
            result: Some(discovery.clone()),
            error: None,
            completed_at: Utc::now().to_rfc3339(),
            worker_agent: Some("orchestrator".into()),
        };

        match chaining::process_task_result(
            &synthetic_result,
            _task_queue,
            &investigation.investigation_id,
            &mut dispatched_chains,
        )
        .await
        {
            Ok(new_ids) => chained_task_ids.extend(new_ids),
            Err(e) => {
                warn!(
                    investigation_id = %investigation.investigation_id,
                    error = %e,
                    "Failed to process evidence chain"
                );
            }
        }
    }

    if !chained_task_ids.is_empty() {
        info!(
            investigation_id = %investigation.investigation_id,
            count = chained_task_ids.len(),
            "Evidence auto-chaining dispatched follow-up tasks"
        );
    }

    // Score investigation against red team ground truth
    if let Some(op_id) = &investigation.operation_id {
        score_against_ground_truth(
            conn,
            &investigation.investigation_id,
            op_id,
            &investigation.model,
            &outcome,
        )
        .await;
    }

    // Update investigation status
    let final_status = match &investigation_outcome {
        InvestigationOutcome::Completed { verdict, .. } => {
            info!(
                investigation_id = %investigation.investigation_id,
                verdict = %verdict,
                steps = outcome.steps,
                "Investigation completed"
            );
            "completed"
        }
        InvestigationOutcome::Escalated { reason, .. } => {
            warn!(
                investigation_id = %investigation.investigation_id,
                reason = %reason,
                "Investigation escalated"
            );
            "escalated"
        }
        InvestigationOutcome::Failed { error } => {
            warn!(
                investigation_id = %investigation.investigation_id,
                error = %error,
                "Investigation failed"
            );
            "failed"
        }
    };

    investigation
        .state_writer
        .set_status(conn, &serde_json::Value::String(final_status.into()))
        .await
        .ok();
    investigation
        .state_writer
        .set_meta(
            conn,
            "completed_at",
            &serde_json::Value::String(Utc::now().to_rfc3339()),
        )
        .await
        .ok();

    Ok(investigation_outcome)
}

/// Outcome of a completed investigation.
#[derive(Debug)]
#[allow(dead_code)]
pub enum InvestigationOutcome {
    Completed {
        verdict: String,
        summary: String,
        steps: u32,
    },
    Escalated {
        reason: String,
        severity: String,
    },
    Failed {
        error: String,
    },
}

fn process_outcome(outcome: &AgentLoopOutcome, investigation_id: &str) -> InvestigationOutcome {
    match &outcome.reason {
        LoopEndReason::TaskComplete { result, .. } => InvestigationOutcome::Completed {
            verdict: extract_verdict(result),
            summary: result.clone(),
            steps: outcome.steps,
        },
        LoopEndReason::RequestAssistance { issue, .. } => InvestigationOutcome::Escalated {
            reason: issue.clone(),
            severity: if issue.to_lowercase().contains("critical") {
                "critical".into()
            } else {
                "high".into()
            },
        },
        LoopEndReason::EndTurn { content } => InvestigationOutcome::Completed {
            verdict: extract_verdict(content),
            summary: content.clone(),
            steps: outcome.steps,
        },
        LoopEndReason::MaxSteps => InvestigationOutcome::Failed {
            error: format!(
                "Investigation {investigation_id} hit max steps ({})",
                outcome.steps
            ),
        },
        LoopEndReason::MaxTokens => InvestigationOutcome::Failed {
            error: format!("Investigation {investigation_id} hit max tokens"),
        },
        LoopEndReason::Error(err) => InvestigationOutcome::Failed { error: err.clone() },
    }
}

/// Extract a verdict from the investigation result text.
fn extract_verdict(text: &str) -> String {
    let lower = text.to_lowercase();
    if lower.contains("true positive") {
        "true_positive".into()
    } else if lower.contains("false positive") {
        "false_positive".into()
    } else if lower.contains("benign") {
        "benign".into()
    } else if lower.contains("malicious") || lower.contains("confirmed threat") {
        "true_positive".into()
    } else {
        "inconclusive".into()
    }
}

/// Dispatch a sub-task to a blue team worker agent.
///
/// Called by the orchestrator's LLM when it uses `dispatch_task` tool.
#[allow(dead_code)]
pub async fn dispatch_subtask(
    task_queue: &mut BlueTaskQueue,
    investigation_id: &str,
    task_type: &str,
    role: BlueAgentRole,
    params: serde_json::Value,
) -> Result<String> {
    let task_id = format!(
        "{}_{}_{}",
        task_type,
        investigation_id.chars().take(8).collect::<String>(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );

    let task = BlueTaskMessage {
        task_id: task_id.clone(),
        investigation_id: investigation_id.to_string(),
        task_type: task_type.to_string(),
        role: role.as_str().to_string(),
        params,
        created_at: Utc::now().to_rfc3339(),
    };

    task_queue.submit_task(&task).await?;

    info!(
        task_id = %task_id,
        task_type = task_type,
        role = role.as_str(),
        investigation_id = investigation_id,
        "Dispatched blue team sub-task"
    );

    Ok(task_id)
}

/// Score a completed investigation against red team ground truth.
///
/// Loads the blue team investigation state and the red team operation state
/// from Redis, then runs all six scorers to produce a grade and gap analysis.
async fn score_against_ground_truth(
    conn: &mut redis::aio::ConnectionManager,
    investigation_id: &str,
    operation_id: &str,
    model: &str,
    outcome: &AgentLoopOutcome,
) {
    // Load blue team state
    let blue_reader = BlueStateReader::new(investigation_id.to_string());
    let blue_state = match blue_reader.load_state(conn).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            warn!(
                investigation_id = investigation_id,
                "Skipping evaluation: blue team state not found in Redis"
            );
            return;
        }
        Err(e) => {
            warn!(
                investigation_id = investigation_id,
                error = %e,
                "Skipping evaluation: failed to load blue team state"
            );
            return;
        }
    };

    // Load red team state
    let red_reader = RedisStateReader::new(operation_id.to_string());
    let red_state = match red_reader.load_state(conn).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            warn!(
                operation_id = operation_id,
                "Skipping evaluation: red team state not found in Redis"
            );
            return;
        }
        Err(e) => {
            warn!(
                operation_id = operation_id,
                error = %e,
                "Skipping evaluation: failed to load red team state"
            );
            return;
        }
    };

    // Estimate duration from outcome step count (rough heuristic: ~10s per step)
    let duration_seconds = outcome.steps as f64 * 10.0;

    let eval_output = evaluate_live_investigation(&blue_state, &red_state, model, duration_seconds);

    info!(
        investigation_id = investigation_id,
        operation_id = operation_id,
        grade = eval_output.result.grade(),
        overall_score = format!("{:.2}", eval_output.result.overall_score),
        ioc_detection = format!("{:.2}", eval_output.result.ioc_detection_rate),
        technique_coverage = format!("{:.2}", eval_output.result.technique_coverage),
        evidence_count = eval_output.result.evidence_count,
        "Investigation evaluation complete"
    );

    if !eval_output.gap_analysis.detection_gaps.is_empty() {
        info!(
            investigation_id = investigation_id,
            gaps = eval_output.gap_analysis.detection_gaps.len(),
            "Detection gaps identified — see gap analysis for recommendations"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_verdict() {
        assert_eq!(extract_verdict("This is a true positive"), "true_positive");
        assert_eq!(
            extract_verdict("Determined to be a false positive"),
            "false_positive"
        );
        assert_eq!(extract_verdict("Activity is benign"), "benign");
        assert_eq!(extract_verdict("Confirmed threat"), "true_positive");
        assert_eq!(extract_verdict("Needs more data"), "inconclusive");
    }

    #[test]
    fn test_process_outcome_completed() {
        let outcome = AgentLoopOutcome {
            reason: LoopEndReason::TaskComplete {
                task_id: "inv1".into(),
                result: "True positive: lateral movement confirmed".into(),
            },
            total_usage: Default::default(),
            steps: 10,
            tool_calls_dispatched: 5,
            discoveries: Vec::new(),
            tool_outputs: Vec::new(),
        };
        match process_outcome(&outcome, "inv1") {
            InvestigationOutcome::Completed { verdict, steps, .. } => {
                assert_eq!(verdict, "true_positive");
                assert_eq!(steps, 10);
            }
            other => panic!("Expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn test_process_outcome_escalated() {
        let outcome = AgentLoopOutcome {
            reason: LoopEndReason::RequestAssistance {
                issue: "Critical: active data exfiltration".into(),
                context: "".into(),
            },
            total_usage: Default::default(),
            steps: 3,
            tool_calls_dispatched: 1,
            discoveries: Vec::new(),
            tool_outputs: Vec::new(),
        };
        match process_outcome(&outcome, "inv1") {
            InvestigationOutcome::Escalated { severity, .. } => {
                assert_eq!(severity, "critical");
            }
            other => panic!("Expected Escalated, got {other:?}"),
        }
    }
}
