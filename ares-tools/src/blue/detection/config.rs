//! YAML-driven detection configuration — types, loader, and LogQL builder.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::{build_event_filter, build_pattern_filter, build_selector, WIN_SECURITY, WIN_SYSTEM};

// ─── Config types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DetectionConfig {
    /// Event ID descriptions — agent context, not used by query builder.
    #[allow(dead_code)]
    pub event_id_reference: BTreeMap<String, String>,
    pub activity_scopes: BTreeMap<String, Vec<String>>,
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

// ─── LogQL builder ─────────────────────────────────────────────────────────

/// Compose a LogQL query from a template entry and optional hostname.
pub fn build_template_logql(entry: &TemplateEntry, host: Option<&str>) -> String {
    let job = match entry.log_source.as_str() {
        "windows-system" => WIN_SYSTEM,
        _ => WIN_SECURITY,
    };
    let sel = build_selector(job, host);

    let ids: Vec<&str> = entry.event_ids.iter().map(|s| s.as_str()).collect();
    let event_filter = build_event_filter(&ids);

    let mut logql = format!("{sel}{event_filter}");

    // `patterns` = single filter stage (OR within)
    if !entry.patterns.is_empty() {
        let refs: Vec<&str> = entry.patterns.iter().map(|s| s.as_str()).collect();
        logql.push_str(&build_pattern_filter(&refs));
    }

    // `filter_stages` = multiple chained filters (AND between stages)
    for stage in &entry.filter_stages {
        let refs: Vec<&str> = stage.iter().map(|s| s.as_str()).collect();
        logql.push_str(&build_pattern_filter(&refs));
    }

    // Some templates also match host as a line filter
    if entry.host_as_filter {
        if let Some(ip) = host {
            logql.push_str(&format!(r#" |= "{ip}""#));
        }
    }

    logql
}
