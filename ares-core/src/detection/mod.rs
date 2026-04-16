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

/// Mapping from connection type to MITRE technique ID, derived from templates.
///
/// Falls back to well-known defaults for connection types not covered by YAML.
pub fn mitre_for_connection_type(conn_type: &str) -> Option<&'static str> {
    // First check if any template's red_team_tool or tactic maps to this type
    static MAPPING: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    let map = MAPPING.get_or_init(|| {
        let mut m = BTreeMap::new();
        // Hardcoded baseline for connection types without explicit templates
        m.insert("smb", "T1021.002");
        m.insert("rdp", "T1021.001");
        m.insert("wmi", "T1047");
        m.insert("psexec", "T1569.002");
        m.insert("winrm", "T1021.006");
        m.insert("ssh", "T1021.004");
        m.insert("dcom", "T1021.003");
        m.insert("scheduled_task", "T1053.005");

        // Enrich from YAML templates
        let config = detection_config();
        for entry in config.templates.values() {
            match entry.tactic.as_str() {
                "lateral_movement" => {
                    if let Some(tool) = &entry.red_team_tool {
                        m.entry(leak_str(tool)).or_insert(leak_str(&entry.mitre_id));
                    }
                }
                _ => {
                    // Map specific tools to connection types
                    if let Some(tool) = &entry.red_team_tool {
                        match tool.as_str() {
                            "mssql_relay" => {
                                m.entry("mssql").or_insert(leak_str(&entry.mitre_id));
                            }
                            "get_st" => {
                                m.entry("constrained_delegation")
                                    .or_insert(leak_str(&entry.mitre_id));
                            }
                            "ntlmrelayx" => {
                                m.entry("ntlm_relay").or_insert(leak_str(&entry.mitre_id));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        m
    });
    map.get(conn_type).copied()
}

/// Return template names relevant to a lateral movement connection type.
pub fn templates_for_connection_type(conn_type: &str) -> Vec<&'static str> {
    let config = detection_config();
    let mut out = Vec::new();

    for (name, entry) in &config.templates {
        let dominated = match conn_type {
            "smb" => {
                entry.tactic == "lateral_movement"
                    || matches!(
                        name.as_str(),
                        "detect_share_enumeration"
                            | "detect_mass_share_enumeration"
                            | "detect_smb_signing_disabled"
                            | "detect_smb_file_access"
                    )
            }
            "psexec" => {
                matches!(
                    entry.red_team_tool.as_deref(),
                    Some("psexec") | Some("smbexec")
                ) || name == "detect_service_creation"
            }
            "wmi" => entry.red_team_tool.as_deref() == Some("wmiexec"),
            "dcom" => entry.red_team_tool.as_deref() == Some("dcomexec"),
            "mssql" => entry.red_team_tool.as_deref() == Some("mssql_relay"),
            "constrained_delegation" => {
                entry.red_team_tool.as_deref() == Some("get_st")
                    || entry.red_team_tool.as_deref() == Some("rbcd_write")
            }
            "ntlm_relay" => {
                entry.red_team_tool.as_deref() == Some("ntlmrelayx")
                    || name == "detect_smb_signing_disabled"
            }
            "scheduled_task" => entry.red_team_tool.as_deref() == Some("atexec"),
            "rdp" => entry.tactic == "lateral_movement" && name.contains("rdp"),
            "winrm" => entry.tactic == "lateral_movement" && name.contains("winrm"),
            _ => entry.tactic == "lateral_movement",
        };
        if dominated {
            out.push(name.as_str());
        }
    }
    out
}

/// Leak a string into 'static lifetime for the singleton maps.
/// Safe because these are only called once during OnceLock init.
fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}
