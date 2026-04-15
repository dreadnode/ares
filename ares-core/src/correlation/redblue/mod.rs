//! Red-Blue Correlation Engine.
//!
//! Correlates red team attack activities with blue team detections
//! to measure detection coverage and identify gaps.

mod engine;
mod report;
mod types;

pub use engine::RedBlueCorrelator;
pub use types::{
    BlueTeamDetection, CorrelationMatch, CorrelationReport, DetectionGap, RedTeamActivity,
    TechniqueCoverage,
};
