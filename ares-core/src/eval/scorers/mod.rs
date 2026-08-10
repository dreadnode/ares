//! Scoring functions for blue team evaluation.
//!
//! Each scorer evaluates investigation state against ground truth and returns
//! a float score between 0.0 and 1.0.

mod evaluate;
mod scoring;
#[cfg(test)]
mod tests;
pub mod types;

pub use evaluate::{
    evaluate, get_found_iocs, get_found_techniques, get_missed_iocs, get_missed_techniques,
};
pub use scoring::{
    score_evidence_quality, score_investigation_overall, score_ioc_detection, score_phase_coverage,
    score_pyramid_elevation, score_technique_coverage, score_timeline_accuracy,
};
pub use types::{EvidenceItem, InvestigationSnapshot, TimelineEvent};
