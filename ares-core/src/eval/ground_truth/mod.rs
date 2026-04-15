//! Ground truth schema and transformation for blue team evaluation.
//!
//! Transforms red team operation state into expected findings that the
//! blue team investigation should detect.

mod mappings;
mod schema;
mod transform;

#[cfg(test)]
mod tests;

pub use mappings::{get_techniques_for_vuln_type, is_technique_required};
pub use schema::{
    EvaluationGroundTruth, ExpectedIOC, ExpectedShare, ExpectedTechnique, ExpectedTimelineEvent,
    ExpectedVulnerability,
};
pub use transform::create_ground_truth_from_red_state;
