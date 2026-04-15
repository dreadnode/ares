//! Embedded YAML data, shared structs, lazy-loaded caches, and pure helpers.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

use crate::ToolOutput;

// ---------------------------------------------------------------------------
// Embedded YAML data
// ---------------------------------------------------------------------------

const ATTACK_CHAINS_YAML: &str = include_str!("../data/attack_chains.yaml");
const DETECTION_RECIPES_YAML: &str = include_str!("../data/detection_recipes.yaml");
const CLIMB_STRATEGIES_YAML: &str = include_str!("../data/climb_strategies.yaml");

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AttackChainEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub precursors: Vec<ChainPrecursor>,
    #[serde(default)]
    pub follow_on: Vec<ChainPrecursor>,
    #[serde(default)]
    pub windows_events: Vec<WindowsEvent>,
    #[serde(default)]
    pub log_patterns: Vec<LogPattern>,
    #[serde(default)]
    pub investigation_questions: Vec<ChainQuestion>,
    #[serde(default)]
    pub detection_patterns: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainPrecursor {
    pub technique: String,
    pub name: String,
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub relevance: f64,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WindowsEvent {
    pub event_id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub relevance: f64,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub query_pattern: String,
    #[serde(default)]
    pub threshold: Option<String>,
    #[serde(default)]
    pub detection_logic: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogPattern {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainQuestion {
    pub question: String,
    #[serde(default)]
    pub priority: f64,
    #[serde(default)]
    pub target_technique: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClimbStrategy {
    pub template: String,
    pub target: String,
    #[serde(default)]
    pub insight: String,
    #[serde(default)]
    pub elevation: u32,
}

// ---------------------------------------------------------------------------
// Lazy-loaded data caches
// ---------------------------------------------------------------------------

pub fn attack_chains() -> &'static HashMap<String, AttackChainEntry> {
    static CACHE: OnceLock<HashMap<String, AttackChainEntry>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: HashMap<String, Value> =
            serde_yaml::from_str(ATTACK_CHAINS_YAML).unwrap_or_default();
        let mut chains = HashMap::new();
        for (key, val) in raw {
            if key.starts_with('T') {
                if let Ok(entry) = serde_json::from_value::<AttackChainEntry>(
                    serde_json::to_value(&val).unwrap_or_default(),
                ) {
                    chains.insert(key, entry);
                }
            }
        }
        chains
    })
}

pub fn detection_recipes() -> &'static HashMap<String, Value> {
    static CACHE: OnceLock<HashMap<String, Value>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: HashMap<String, Value> =
            serde_yaml::from_str(DETECTION_RECIPES_YAML).unwrap_or_default();
        raw.into_iter()
            .filter(|(k, _)| !k.starts_with("query_"))
            .collect()
    })
}

pub fn climb_strategies() -> &'static HashMap<String, Vec<ClimbStrategy>> {
    static CACHE: OnceLock<HashMap<String, Vec<ClimbStrategy>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: HashMap<String, Vec<Value>> =
            serde_yaml::from_str(CLIMB_STRATEGIES_YAML).unwrap_or_default();
        let mut strategies = HashMap::new();
        for (level, vals) in raw {
            let parsed: Vec<ClimbStrategy> = vals
                .into_iter()
                .filter_map(|v| {
                    serde_json::from_value::<ClimbStrategy>(
                        serde_json::to_value(&v).unwrap_or_default(),
                    )
                    .ok()
                })
                .collect();
            if !parsed.is_empty() {
                strategies.insert(level, parsed);
            }
        }
        strategies
    })
}

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

/// Pyramid level display name mapping.
pub fn pyramid_level_name(level: &str) -> &str {
    match level {
        "hash_values" => "Hash Values",
        "ip_addresses" => "IP Addresses",
        "domain_names" => "Domain Names",
        "network_host_artifacts" => "Network/Host Artifacts",
        "tools" => "Tools",
        "ttps" => "TTPs",
        _ => level,
    }
}

pub fn pyramid_level_value(level: &str) -> u32 {
    match level {
        "hash_values" => 1,
        "ip_addresses" => 2,
        "domain_names" => 3,
        "network_host_artifacts" => 4,
        "tools" => 5,
        "ttps" => 6,
        _ => 0,
    }
}

/// Technique-to-recipe mapping (hardcoded like Python).
pub fn technique_to_recipe() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("T1003.006", "dcsync");
        m.insert("T1110", "password_spray");
        m.insert("T1110.003", "password_spray");
        m.insert("T1110.004", "credential_stuffing");
        m.insert("T1558.003", "kerberos_attacks");
        m.insert("T1558.004", "kerberos_attacks");
        m.insert("T1558.001", "kerberos_attacks");
        m.insert("T1550.002", "pass_the_hash");
        m.insert("T1135", "share_enumeration");
        m.insert("T1087.002", "ldap_enumeration");
        m.insert("T1046", "service_enumeration");
        m
    })
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

pub fn make_output(body: &str) -> ToolOutput {
    ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}
