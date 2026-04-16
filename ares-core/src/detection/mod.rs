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
    #[allow(dead_code)]
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
