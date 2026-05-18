//! Shared detection configuration — YAML-driven templates, MITRE mappings,
//! and activity scopes used by both the blue tool layer (ares-tools) and the
//! correlation/lateral-movement analyzer (ares-core).
//!
//! The canonical data lives in `detections.yaml`, embedded at compile time.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

// ─── Config types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DetectionConfig {
    /// Event ID descriptions — agent context, not used by query builder.
    pub event_id_reference: BTreeMap<String, String>,
    pub activity_scopes: BTreeMap<String, Vec<String>>,
    /// Regex patterns for classifying lateral movement connection types.
    #[serde(default)]
    pub lateral_patterns: BTreeMap<String, Vec<String>>,
    pub templates: BTreeMap<String, TemplateEntry>,
}

#[derive(Debug, Deserialize)]
pub struct TemplateEntry {
    pub description: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub mitre_id: String,
    pub tactic: String,
    pub severity: String,
    #[serde(default)]
    pub red_team_tool: Option<String>,
    #[serde(default)]
    pub auto_pivot: bool,
    #[serde(default = "default_log_source")]
    pub log_source: String,
    #[serde(default)]
    pub host_as_filter: bool,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub filter_stages: Vec<Vec<String>>,
    /// Negative regex patterns — exclude lines matching any of these.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Lateral movement connection types this template is relevant to.
    ///
    /// Used by `templates_for_connection_type()`. Values come from the
    /// `lateral_patterns` keys (smb, psexec, wmi, dcom, mssql, winrm, rdp,
    /// ssh, scheduled_task, constrained_delegation, ntlm_relay).
    #[serde(default)]
    pub connection_types: Vec<String>,
}

fn default_log_source() -> String {
    "windows-security".to_string()
}

// ─── Singleton loader ──────────────────────────────────────────────────────

static CONFIG: OnceLock<DetectionConfig> = OnceLock::new();

pub fn detection_config() -> &'static DetectionConfig {
    CONFIG.get_or_init(|| {
        let yaml = include_str!("detections.yaml");
        serde_yaml::from_str(yaml).expect("detections.yaml is invalid")
    })
}

// ─── Template lookup ───────────────────────────────────────────────────────

/// Find a template by name or alias.
pub fn find_template(name: &str) -> Option<(&'static str, &'static TemplateEntry)> {
    let config = detection_config();
    // Direct match
    if let Some((key, entry)) = config.templates.get_key_value(name) {
        return Some((key.as_str(), entry));
    }
    // Alias match
    for (key, entry) in &config.templates {
        if entry.aliases.iter().any(|a| a == name) {
            return Some((key.as_str(), entry));
        }
    }
    None
}

// ─── Lateral movement helpers ──────────────────────────────────────────────

/// Mapping from connection type to MITRE technique ID.
///
/// YAML templates are authoritative: any template whose `connection_types`
/// includes a given key contributes its `mitre_id` for that key.  When
/// multiple templates cover the same connection type the first one wins
/// (BTreeMap iteration order is alphabetical, giving stable results).
///
/// Hardcoded values are inserted last with `or_insert`, acting as fallbacks
/// only for connection types that have no YAML template coverage.
pub fn mitre_for_connection_type(conn_type: &str) -> Option<&'static str> {
    static MAPPING: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    let map = MAPPING.get_or_init(|| {
        let config = detection_config();
        let mut m: BTreeMap<&'static str, &'static str> = BTreeMap::new();

        // Primary source: derive from connection_types declared in YAML templates.
        // Templates are iterated in alphabetical key order; first writer wins per
        // connection type, so the canonical template for each type takes precedence.
        for entry in config.templates.values() {
            for ct in &entry.connection_types {
                m.entry(ct.as_str()).or_insert(entry.mitre_id.as_str());
            }
        }

        // Fallbacks for connection types not yet covered by any YAML template.
        m.entry("smb").or_insert("T1021.002");
        m.entry("rdp").or_insert("T1021.001");
        m.entry("wmi").or_insert("T1047");
        m.entry("psexec").or_insert("T1569.002");
        m.entry("winrm").or_insert("T1021.006");
        m.entry("ssh").or_insert("T1021.004");
        m.entry("dcom").or_insert("T1021.003");
        m.entry("scheduled_task").or_insert("T1053.005");
        m.entry("mssql").or_insert("T1210");
        m.entry("constrained_delegation").or_insert("T1550.003");
        m.entry("ntlm_relay").or_insert("T1557");

        m
    });
    map.get(conn_type).copied()
}

/// Return template names relevant to a lateral movement connection type.
///
/// Templates declare which connection types they cover via the `connection_types`
/// field in `detections.yaml`.  This function simply filters by that field,
/// replacing the previous hardcoded match arms.
pub fn templates_for_connection_type(conn_type: &str) -> Vec<&'static str> {
    let config = detection_config();
    config
        .templates
        .iter()
        .filter(|(_, entry)| {
            entry
                .connection_types
                .iter()
                .any(|ct| ct.as_str() == conn_type)
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_config_loads_successfully() {
        let config = detection_config();
        assert!(
            !config.templates.is_empty(),
            "templates should not be empty"
        );
        assert!(
            !config.activity_scopes.is_empty(),
            "activity_scopes should not be empty"
        );
    }

    #[test]
    fn detection_config_has_event_id_reference() {
        let config = detection_config();
        assert!(
            !config.event_id_reference.is_empty(),
            "event_id_reference should not be empty"
        );
    }

    #[test]
    fn detection_config_singleton_returns_same_ref() {
        let c1 = detection_config();
        let c2 = detection_config();
        assert!(std::ptr::eq(c1, c2));
    }

    #[test]
    fn find_template_by_direct_name() {
        let config = detection_config();
        let first_name = config.templates.keys().next().unwrap();
        let (key, _) = find_template(first_name).expect("should find template by name");
        assert_eq!(key, first_name.as_str());
    }

    #[test]
    fn find_template_nonexistent_returns_none() {
        assert!(find_template("nonexistent_xyz_42").is_none());
    }

    #[test]
    fn find_template_by_alias() {
        let config = detection_config();
        for (name, entry) in &config.templates {
            if let Some(alias) = entry.aliases.first() {
                let (key, _) = find_template(alias).expect("should find template by alias");
                assert_eq!(key, name.as_str());
                return;
            }
        }
    }

    #[test]
    fn template_entries_have_required_fields() {
        let config = detection_config();
        for (name, entry) in &config.templates {
            assert!(
                !entry.description.is_empty(),
                "'{name}' missing description"
            );
            assert!(!entry.mitre_id.is_empty(), "'{name}' missing mitre_id");
            assert!(!entry.tactic.is_empty(), "'{name}' missing tactic");
            assert!(!entry.severity.is_empty(), "'{name}' missing severity");
        }
    }

    #[test]
    fn mitre_for_connection_type_known_types() {
        let known = [
            "smb",
            "rdp",
            "wmi",
            "psexec",
            "winrm",
            "ssh",
            "dcom",
            "scheduled_task",
            "mssql",
            "constrained_delegation",
            "ntlm_relay",
        ];
        for ct in &known {
            assert!(
                mitre_for_connection_type(ct).is_some(),
                "'{ct}' should have a MITRE mapping"
            );
        }
    }

    #[test]
    fn mitre_for_connection_type_unknown_returns_none() {
        assert!(mitre_for_connection_type("unknown_proto_xyz").is_none());
    }

    #[test]
    fn mitre_for_connection_type_smb_maps_to_t1021() {
        let mitre = mitre_for_connection_type("smb").unwrap();
        assert!(
            mitre.starts_with("T1021"),
            "SMB should map to T1021.x, got {mitre}"
        );
    }

    #[test]
    fn templates_for_connection_type_smb_returns_entries() {
        let t = templates_for_connection_type("smb");
        assert!(!t.is_empty(), "smb should have matching templates");
    }

    #[test]
    fn templates_for_connection_type_unknown_empty() {
        let t = templates_for_connection_type("unknown_xyz");
        assert!(t.is_empty());
    }

    #[test]
    fn default_log_source_is_windows_security() {
        assert_eq!(default_log_source(), "windows-security");
    }

    #[test]
    fn lateral_patterns_present_in_config() {
        let config = detection_config();
        // lateral_patterns may be empty but should be loadable
        // If present, keys should be connection type names
        for key in config.lateral_patterns.keys() {
            assert!(!key.is_empty(), "lateral_patterns key should not be empty");
        }
    }

    #[test]
    fn activity_scopes_values_are_non_empty() {
        let config = detection_config();
        for (scope, ids) in &config.activity_scopes {
            assert!(!ids.is_empty(), "scope '{scope}' should have event IDs");
        }
    }
}
