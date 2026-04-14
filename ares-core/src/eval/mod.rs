//! Evaluation framework for blue team investigation quality assessment.
//!
//! # Modules
//!
//! - [`ground_truth`] — Ground truth schema and transformation from red team state.
//! - [`results`] — Evaluation result types and aggregation.
//! - [`scorers`] — Scoring functions for investigation quality metrics.
//! - [`gap_analysis`] — Detection gap analysis and recommendations.
//! - [`workflow`] — Scenario/dataset loading and offline evaluation.

pub mod gap_analysis;
pub mod ground_truth;
pub mod results;
pub mod scorers;
pub mod workflow;
