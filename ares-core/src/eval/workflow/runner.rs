//! Evaluation runner functions for live and offline scenarios.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;

use crate::eval::gap_analysis::{analyze_detection_gaps, GapAnalysisReport};
use crate::eval::ground_truth::{create_ground_truth_from_red_state, EvaluationGroundTruth};
use crate::eval::results::{DatasetEvaluationResult, EvaluationResult};
use crate::eval::scorers::{self, InvestigationSnapshot};
use crate::models::{SharedBlueTeamState, SharedRedTeamState};

use super::dataset::{load_red_state_from_file, EvaluationDataset, EvaluationScenario};

/// Result of evaluating a single scenario offline.
#[derive(Debug)]
pub struct ScenarioEvaluationOutput {
    pub scenario_name: String,
    pub ground_truth: EvaluationGroundTruth,
    pub result: EvaluationResult,
    pub gap_analysis: GapAnalysisReport,
}

/// Output from a live post-investigation evaluation.
#[derive(Debug)]
pub struct LiveEvaluationOutput {
    pub evaluation_id: String,
    pub investigation_id: String,
    pub operation_id: String,
    pub ground_truth: EvaluationGroundTruth,
    pub result: EvaluationResult,
    pub gap_analysis: GapAnalysisReport,
}

/// Evaluate a completed live investigation against red team ground truth.
///
/// Called post-investigation with the blue team's state loaded from Redis
/// and the red team's state (also from Redis). Returns the scored result
/// and gap analysis.
pub fn evaluate_live_investigation(
    blue_state: &SharedBlueTeamState,
    red_state: &SharedRedTeamState,
    model: &str,
    duration_seconds: f64,
) -> LiveEvaluationOutput {
    let techniques: Vec<String> = red_state.all_techniques.clone();
    let ground_truth = create_ground_truth_from_red_state(red_state, &techniques);
    let snap = InvestigationSnapshot::from_blue_state(blue_state);

    let eval_id = format!(
        "live-eval-{}-{}",
        red_state.operation_id,
        blue_state
            .investigation_id
            .chars()
            .take(8)
            .collect::<String>()
    );

    let result = scorers::evaluate(
        &eval_id,
        &snap,
        &ground_truth,
        true,
        model,
        duration_seconds,
    );
    let gap_analysis = analyze_detection_gaps(&result);

    LiveEvaluationOutput {
        evaluation_id: eval_id,
        investigation_id: blue_state.investigation_id.clone(),
        operation_id: red_state.operation_id.clone(),
        ground_truth,
        result,
        gap_analysis,
    }
}

/// Evaluate a single scenario from a saved red team state file.
///
/// Generates ground truth and a baseline evaluation result (no investigation data).
/// The gap analysis shows what the blue team should have detected.
pub fn evaluate_scenario(scenario: &EvaluationScenario) -> Result<ScenarioEvaluationOutput> {
    let (state, techniques) = load_red_state_from_file(&scenario.state_file)?;

    let ground_truth = scenario
        .ground_truth
        .clone()
        .unwrap_or_else(|| create_ground_truth_from_red_state(&state, &techniques));

    // Build a minimal snapshot (no investigation data — scores reflect baseline)
    let snap = scorers::InvestigationSnapshot::default();

    let eval_id = format!("eval-{}", &state.operation_id);
    let result = scorers::evaluate(&eval_id, &snap, &ground_truth, false, "", 0.0);

    let gap_analysis = analyze_detection_gaps(&result);

    Ok(ScenarioEvaluationOutput {
        scenario_name: scenario.name.clone(),
        ground_truth,
        result,
        gap_analysis,
    })
}

/// Evaluate all scenarios in a dataset.
pub fn evaluate_dataset(dataset: &EvaluationDataset) -> Result<DatasetEvaluationResult> {
    let mut results = Vec::new();

    for scenario in &dataset.scenarios {
        match evaluate_scenario(scenario) {
            Ok(output) => results.push(output.result),
            Err(e) => {
                let result = EvaluationResult {
                    evaluation_id: format!("eval-failed-{}", scenario.name),
                    error: Some(format!("{e:#}")),
                    ..Default::default()
                };
                results.push(result);
            }
        }
    }

    Ok(DatasetEvaluationResult {
        dataset_name: dataset.name.clone(),
        evaluated_at: Utc::now(),
        results,
    })
}

/// Save an evaluation result to a JSON file.
pub fn save_evaluation_result(result: &EvaluationResult, output_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;
    let filename = format!("eval_{}_{}.json", result.evaluation_id, result.operation_id);
    let filepath = output_dir.join(filename);
    let json = serde_json::to_string_pretty(&result.to_value())?;
    fs::write(&filepath, json)?;
    Ok(filepath)
}

/// Save a gap analysis report to a markdown file.
pub fn save_gap_analysis(report: &GapAnalysisReport, output_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;
    let filename = format!(
        "gap_analysis_{}_{}.md",
        report.evaluation_id, report.operation_id
    );
    let filepath = output_dir.join(filename);
    fs::write(&filepath, report.to_markdown())?;
    Ok(filepath)
}
