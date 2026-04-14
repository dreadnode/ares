//! MITRE ATT&CK technique lookup.

use std::collections::HashMap;

use once_cell::sync::Lazy;

const MITRE_TECHNIQUES_YAML: &str = include_str!("data/mitre_techniques.yaml");

static MITRE_TECHNIQUES: Lazy<HashMap<String, String>> = Lazy::new(|| {
    serde_yaml::from_str::<HashMap<String, String>>(MITRE_TECHNIQUES_YAML).unwrap_or_default()
});

/// Get a display string for a MITRE technique ID (e.g. "T1003.006 (DCSync)").
pub fn get_technique_display(technique_id: &str) -> String {
    match MITRE_TECHNIQUES.get(technique_id) {
        Some(name) => format!("{technique_id} ({name})"),
        None => technique_id.to_string(),
    }
}
