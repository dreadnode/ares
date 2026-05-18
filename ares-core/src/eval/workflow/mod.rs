//! Evaluation workflow for offline blue team evaluation.
//!
//! Provides scenario/dataset loading and offline evaluation from saved
//! red team state files for non-live evaluation use cases.

mod costs;
mod dataset;
mod runner;

#[cfg(test)]
mod tests;

pub use costs::{estimate_cost, ModelCost};
pub use dataset::{load_red_state_from_file, EvaluationDataset, EvaluationScenario};
pub use runner::{
    evaluate_dataset, evaluate_live_investigation, evaluate_scenario, save_evaluation_result,
    save_gap_analysis, LiveEvaluationOutput, ScenarioEvaluationOutput,
};
