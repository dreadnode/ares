//! Investigation question engines: MITRENavigator and PyramidClimber.
//!
//! Generates investigative questions based on identified techniques and evidence
//! to drive investigation depth — climbing the Pyramid of Pain and following
//! MITRE ATT&CK chains.

pub mod data;
pub mod mitre;
pub mod pyramid;
pub mod tools;

// Re-export all public tool functions so callers via `engines::` still work.
pub use tools::{
    assess_pyramid_state_tool, generate_mitre_questions_tool, generate_pyramid_questions_tool,
    get_attack_chain_precursors, get_combined_questions_tool, get_detection_recipe,
    list_detection_recipes,
};
