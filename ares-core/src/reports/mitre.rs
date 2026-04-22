//! MITRE ATT&CK technique lookup.

use std::collections::HashMap;

use std::sync::LazyLock;

const MITRE_TECHNIQUES_YAML: &str = include_str!("data/mitre_techniques.yaml");

static MITRE_TECHNIQUES: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    serde_yaml::from_str::<HashMap<String, String>>(MITRE_TECHNIQUES_YAML).unwrap_or_default()
});

/// Get a display string for a MITRE technique ID (e.g. "T1003.006 (DCSync)").
pub fn get_technique_display(technique_id: &str) -> String {
    match MITRE_TECHNIQUES.get(technique_id) {
        Some(name) => format!("{technique_id} ({name})"),
        None => technique_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_display_known_id() {
        let display = get_technique_display("T1003");
        assert!(display.starts_with("T1003"));
        assert!(display.contains('('));
    }

    #[test]
    fn technique_display_unknown_id_returns_raw() {
        let display = get_technique_display("T9999.999");
        assert_eq!(display, "T9999.999");
    }

    #[test]
    fn technique_display_empty_string() {
        let display = get_technique_display("");
        assert_eq!(display, "");
    }

    #[test]
    fn mitre_techniques_map_loads() {
        let _ = MITRE_TECHNIQUES.len();
    }
}
