//! MITRE ATT&CK learning tools for blue team agents.
//!
//! Provides offline lookup of MITRE ATT&CK techniques and evidence-based
//! technique suggestions without requiring external API calls.

mod history;
mod mitre_db;
mod playbook;

// Re-export all public functions so callers use `learning::foo` as before.
pub use history::{
    check_false_positive_pattern, find_similar_investigations, get_effective_queries,
    get_investigation_statistics,
};
pub use mitre_db::{lookup_technique, suggest_techniques};
pub use playbook::{get_attack_playbook, get_detection_queries_for_technique};
