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
use ares_core::state::blue_task_queue::{BlueTaskQueue, BlueTaskResult};
use ares_core::state::{BlueStateReader, BlueStateWriter, RedisStateReader};
use ares_llm::tool_registry::blue::BlueAgentRole;
use ares_llm::{
    run_agent_loop, AgentLoopConfig, AgentLoopOutcome, LlmProvider, LoopEndReason,
    RunAgentLoopParams, ToolDispatcher,
};

use super::callbacks::BlueCallbackHandler;
use super::chaining;

/// Represents a running investigation.
pub struct Investigation {
    pub investigation_id: String,
    pub alert: serde_json::Value,
    pub model: String,
    /// Red team operation ID for post-investigation scoring against ground truth.
    pub operation_id: Option<String>,
    /// Custom report output directory. Falls back to `ARES_REPORT_DIR` env var,
    /// then `~/.ares/reports/`.
    pub report_dir: Option<String>,
    pub state_writer: BlueStateWriter,
}

impl Investigation {
    pub fn new(
        investigation_id: String,
        alert: serde_json::Value,
        model: String,
        operation_id: Option<String>,
        report_dir: Option<String>,
    ) -> Self {
        let state_writer = BlueStateWriter::new(investigation_id.clone());
        Self {
            investigation_id,
            alert,
            model,
            operation_id,
            report_dir,
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
    provider: Arc<dyn LlmProvider>,
    dispatcher: Arc<dyn ToolDispatcher>,
    _task_queue: &mut BlueTaskQueue,
    redis_url: &str,
    conn: &mut redis::aio::ConnectionManager,
) -> Result<InvestigationOutcome> {
    info!(
        investigation_id = %investigation.investigation_id,
        "Starting blue team investigation"
    );

    // Load investigation env vars from Redis and inject into process environment.
    // These are set by `ares blue from-operation` and include GRAFANA_URL,
    // GRAFANA_SERVICE_ACCOUNT_TOKEN, etc. needed by blue tools (e.g. Loki queries
    // routed through Grafana's datasource proxy).
    let env_key = format!("ares:blue:inv:{}:env_vars", investigation.investigation_id);
    if let Ok(env_json) = redis::AsyncCommands::get::<_, String>(conn, &env_key).await {
        if let Ok(env_map) =
            serde_json::from_str::<std::collections::HashMap<String, String>>(&env_json)
        {
            for (key, value) in &env_map {
                // Only set if not already present — don't clobber orchestrator's own env
                if std::env::var(key).is_err() {
                    std::env::set_var(key, value);
                }
            }
            info!(
                investigation_id = %investigation.investigation_id,
                count = env_map.len(),
                "Injected investigation env vars"
            );
        }
    }

    investigation
        .state_writer
        .initialize(conn, &investigation.alert)
        .await
        .context("Failed to initialize investigation state")?;

    // Acquire investigation lock (TTL 1 hour)
    if let Ok(true) = investigation.state_writer.acquire_lock(conn, 3600).await {
        info!(
            investigation_id = %investigation.investigation_id,
            "Acquired investigation lock"
        );
    }

    investigation
        .state_writer
        .set_status(conn, "in_progress", None)
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

    let deployment = investigation
        .alert
        .get("labels")
        .and_then(|l| l.get("deployment"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| std::env::var("ARES_DEPLOYMENT").ok());

    let system_prompt = ares_llm::prompt::blue::build_blue_system_prompt(
        role.as_str(),
        &capabilities,
        deployment.as_deref(),
    )
    .context("Failed to build blue orchestrator system prompt")?;

    // Build the task prompt with alert context using the initial alert prompt template
    let task_prompt = ares_llm::prompt::blue::build_initial_alert_prompt(
        &investigation.investigation_id,
        &investigation.alert,
        investigation.operation_id.as_deref(),
    )
    .context("Failed to build initial alert prompt")?;

    let config = AgentLoopConfig {
        model: investigation.model.clone(),
        max_steps: 75,
        max_tool_calls_per_name: 25,
        ..AgentLoopConfig::default()
    };

    // Wire blue callback handler for dispatch + query + lifecycle tools
    let callback_handler = Arc::new(BlueCallbackHandler::new(
        Arc::clone(&provider),
        Arc::clone(&dispatcher),
        investigation.model.clone(),
        investigation.investigation_id.clone(),
        investigation.alert.clone(),
        redis_url.to_string(),
    ));

    // Run the orchestrator agent loop
    let outcome = run_agent_loop(RunAgentLoopParams {
        provider: provider.as_ref(),
        dispatcher,
        config: &config,
        system_prompt: &system_prompt,
        task_prompt: &task_prompt,
        role: role.as_str(),
        task_id: &investigation.investigation_id,
        tools: &tools,
        callback_handler: Some(callback_handler),
        hostname_map: None,
    })
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
        InvestigationOutcome::Completed { verdict, steps } => {
            info!(
                investigation_id = %investigation.investigation_id,
                verdict = %verdict,
                steps,
                "Investigation completed"
            );
            "completed"
        }
        InvestigationOutcome::Escalated { reason, severity } => {
            warn!(
                investigation_id = %investigation.investigation_id,
                reason = %reason,
                severity = %severity,
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

    let error_msg = match &investigation_outcome {
        InvestigationOutcome::Failed { error } => Some(error.as_str()),
        _ => None,
    };
    investigation
        .state_writer
        .set_status(conn, final_status, error_msg)
        .await
        .ok();

    // Release investigation lock
    investigation.state_writer.release_lock(conn).await.ok();

    // Auto-generate investigation report
    generate_report(
        conn,
        &investigation.investigation_id,
        investigation.report_dir.as_deref(),
    )
    .await;

    Ok(investigation_outcome)
}

/// Resolve the report output directory.
///
/// Priority: explicit `report_dir` > `ARES_REPORT_DIR` env var > `~/.ares/reports/`.
fn resolve_report_dir(report_dir: Option<&str>) -> std::path::PathBuf {
    if let Some(dir) = report_dir {
        return std::path::PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("ARES_REPORT_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".ares").join("reports")
}

/// Generate a markdown investigation report and write it to disk.
///
/// Best-effort: logs warnings on failure rather than propagating errors.
pub(super) async fn generate_report(
    conn: &mut redis::aio::ConnectionManager,
    investigation_id: &str,
    report_dir: Option<&str>,
) {
    let reader = BlueStateReader::new(investigation_id.to_string());
    let state = match reader.load_state(conn).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!(
                investigation_id = investigation_id,
                "Skipping report: investigation state not found"
            );
            return;
        }
        Err(e) => {
            warn!(
                investigation_id = investigation_id,
                error = %e,
                "Skipping report: failed to load state"
            );
            return;
        }
    };

    let generator = match ares_core::reports::BlueTeamReportGenerator::new() {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "Skipping report: failed to create report generator");
            return;
        }
    };

    let report = match generator.generate_investigation(&state, &[]) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                investigation_id = investigation_id,
                error = %e,
                "Failed to generate investigation report"
            );
            return;
        }
    };

    let reports_dir = resolve_report_dir(report_dir)
        .join("blue")
        .join("investigations");

    if let Err(e) = std::fs::create_dir_all(&reports_dir) {
        warn!(
            error = %e,
            "Failed to create reports directory"
        );
        return;
    }

    let report_path = reports_dir.join(format!("{investigation_id}.md"));
    match std::fs::write(&report_path, &report) {
        Ok(()) => {
            info!(
                investigation_id = investigation_id,
                path = %report_path.display(),
                "Investigation report written"
            );
        }
        Err(e) => {
            warn!(
                investigation_id = investigation_id,
                error = %e,
                "Failed to write investigation report"
            );
        }
    }
}

/// Outcome of a completed investigation.
#[derive(Debug)]
pub enum InvestigationOutcome {
    Completed { verdict: String, steps: u32 },
    Escalated { reason: String, severity: String },
    Failed { error: String },
}

fn process_outcome(outcome: &AgentLoopOutcome, investigation_id: &str) -> InvestigationOutcome {
    match &outcome.reason {
        LoopEndReason::TaskComplete { result, .. } => InvestigationOutcome::Completed {
            verdict: extract_verdict(result),
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
        LoopEndReason::BudgetExceeded { reason } => InvestigationOutcome::Failed {
            error: format!("Investigation {investigation_id} budget exceeded: {reason}"),
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
    fn extracts_verdict() {
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
    fn process_outcome_completed() {
        let outcome = AgentLoopOutcome {
            reason: LoopEndReason::TaskComplete {
                task_id: "inv1".into(),
                result: "True positive: lateral movement confirmed".into(),
            },
            total_usage: Default::default(),
            steps: 10,
            tool_calls_dispatched: 5,
            discoveries: Vec::new(),
            llm_findings: Vec::new(),
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
    fn process_outcome_escalated() {
        let outcome = AgentLoopOutcome {
            reason: LoopEndReason::RequestAssistance {
                issue: "Critical: active data exfiltration".into(),
                context: "".into(),
            },
            total_usage: Default::default(),
            steps: 3,
            tool_calls_dispatched: 1,
            discoveries: Vec::new(),
            llm_findings: Vec::new(),
            tool_outputs: Vec::new(),
        };
        match process_outcome(&outcome, "inv1") {
            InvestigationOutcome::Escalated { severity, .. } => {
                assert_eq!(severity, "critical");
            }
            other => panic!("Expected Escalated, got {other:?}"),
        }
    }

    fn outcome_with(reason: LoopEndReason, steps: u32) -> AgentLoopOutcome {
        AgentLoopOutcome {
            reason,
            total_usage: Default::default(),
            steps,
            tool_calls_dispatched: 0,
            discoveries: Vec::new(),
            llm_findings: Vec::new(),
            tool_outputs: Vec::new(),
        }
    }

    #[test]
    fn process_outcome_escalated_non_critical_is_high() {
        let outcome = outcome_with(
            LoopEndReason::RequestAssistance {
                issue: "Suspicious 4625 cluster, need access to host logs".into(),
                context: "".into(),
            },
            4,
        );
        match process_outcome(&outcome, "inv-x") {
            InvestigationOutcome::Escalated { severity, .. } => assert_eq!(severity, "high"),
            other => panic!("expected Escalated/high, got {other:?}"),
        }
    }

    #[test]
    fn process_outcome_end_turn_uses_verdict_extraction() {
        let outcome = outcome_with(
            LoopEndReason::EndTurn {
                content: "Activity is benign — no follow-up required.".into(),
            },
            12,
        );
        match process_outcome(&outcome, "inv-x") {
            InvestigationOutcome::Completed { verdict, steps } => {
                assert_eq!(verdict, "benign");
                assert_eq!(steps, 12);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn process_outcome_max_steps_max_tokens_and_budget_are_failures() {
        let cases = [
            (LoopEndReason::MaxSteps, "hit max steps"),
            (LoopEndReason::MaxTokens, "hit max tokens"),
            (
                LoopEndReason::BudgetExceeded {
                    reason: "input token budget exhausted".into(),
                },
                "budget exceeded",
            ),
        ];
        for (reason, needle) in cases {
            let out = outcome_with(reason, 7);
            match process_outcome(&out, "inv-bx") {
                InvestigationOutcome::Failed { error } => {
                    let lower = error.to_lowercase();
                    assert!(
                        lower.contains(needle),
                        "{lower:?} did not contain {needle:?}"
                    );
                    assert!(lower.contains("inv-bx"));
                }
                other => panic!("expected Failed for {needle}, got {other:?}"),
            }
        }
    }

    #[test]
    fn process_outcome_error_carries_message_through() {
        let outcome = outcome_with(LoopEndReason::Error("redis closed".into()), 0);
        match process_outcome(&outcome, "inv-x") {
            InvestigationOutcome::Failed { error } => assert_eq!(error, "redis closed"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Bundled to serialise mutations to `ARES_REPORT_DIR`/`HOME` against
    /// the rest of the binary's tests.
    #[test]
    fn resolves_report_dir_with_priority() {
        const ENV_KEY: &str = "ARES_REPORT_DIR";
        let prev_env = std::env::var(ENV_KEY).ok();
        let prev_home = std::env::var("HOME").ok();
        std::env::remove_var(ENV_KEY);

        // Explicit wins.
        assert_eq!(
            resolve_report_dir(Some("/tmp/explicit")),
            std::path::PathBuf::from("/tmp/explicit")
        );

        // Env var beats HOME fallback.
        std::env::set_var(ENV_KEY, "/tmp/from-env");
        assert_eq!(
            resolve_report_dir(None),
            std::path::PathBuf::from("/tmp/from-env")
        );

        // HOME fallback when nothing else is set.
        std::env::remove_var(ENV_KEY);
        std::env::set_var("HOME", "/home/probe");
        assert_eq!(
            resolve_report_dir(None),
            std::path::PathBuf::from("/home/probe/.ares/reports")
        );

        // Restore.
        match prev_env {
            Some(v) => std::env::set_var(ENV_KEY, v),
            None => std::env::remove_var(ENV_KEY),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    #[test]
    fn extract_verdict_malicious_maps_to_true_positive() {
        // "malicious" is a distinct path from "true positive" / "confirmed threat"
        // in `extract_verdict`; verify it reaches the correct branch.
        assert_eq!(extract_verdict("Activity is malicious"), "true_positive");
        assert_eq!(
            extract_verdict("The host is exhibiting malicious behaviour"),
            "true_positive"
        );
    }

    #[test]
    fn extract_verdict_case_insensitive_true_positive() {
        assert_eq!(
            extract_verdict("Conclusion: TRUE POSITIVE indicator found"),
            "true_positive"
        );
    }

    #[test]
    fn extract_verdict_confirmed_threat_maps_to_true_positive() {
        // Ensure the "confirmed threat" path works independently of "malicious".
        assert_eq!(
            extract_verdict("This is a Confirmed Threat based on evidence"),
            "true_positive"
        );
    }

    #[test]
    fn extract_verdict_empty_string_is_inconclusive() {
        assert_eq!(extract_verdict(""), "inconclusive");
    }

    #[test]
    fn process_outcome_end_turn_malicious_is_true_positive() {
        let outcome = AgentLoopOutcome {
            reason: LoopEndReason::EndTurn {
                content: "The activity is malicious — host is compromised.".into(),
            },
            total_usage: Default::default(),
            steps: 8,
            tool_calls_dispatched: 3,
            discoveries: Vec::new(),
            llm_findings: Vec::new(),
            tool_outputs: Vec::new(),
        };
        match process_outcome(&outcome, "inv-m") {
            InvestigationOutcome::Completed { verdict, steps } => {
                assert_eq!(verdict, "true_positive");
                assert_eq!(steps, 8);
            }
            other => panic!("Expected Completed, got {other:?}"),
        }
    }
}
