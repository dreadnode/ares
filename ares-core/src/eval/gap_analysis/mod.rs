//! Detection gap analysis and recommendations.
//!
//! Analyzes evaluation results to identify detection gaps and provide
//! actionable recommendations for improving blue team detection capabilities.

mod analysis;
mod recommendations;
#[cfg(test)]
mod tests;
pub mod types;

pub use analysis::analyze_detection_gaps;
pub use types::{DetectionRecommendation, GapAnalysisReport};
