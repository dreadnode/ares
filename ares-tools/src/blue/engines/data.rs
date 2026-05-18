//! Embedded YAML data, shared structs, lazy-loaded caches, and pure helpers.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

use crate::ToolOutput;

const ATTACK_CHAINS_YAML: &str = include_str!("../data/attack_chains.yaml");
const DETECTION_RECIPES_YAML: &str = include_str!("../data/detection_recipes.yaml");
const CLIMB_STRATEGIES_YAML: &str = include_str!("../data/climb_strategies.yaml");

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

/// Technique-to-recipe mapping.
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

pub fn make_output(body: &str) -> ToolOutput {
    ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── pyramid_level_name ──────────────────────────────────────────

    #[test]
    fn pyramid_level_name_known_levels() {
        assert_eq!(pyramid_level_name("hash_values"), "Hash Values");
        assert_eq!(pyramid_level_name("ip_addresses"), "IP Addresses");
        assert_eq!(pyramid_level_name("domain_names"), "Domain Names");
        assert_eq!(
            pyramid_level_name("network_host_artifacts"),
            "Network/Host Artifacts"
        );
        assert_eq!(pyramid_level_name("tools"), "Tools");
        assert_eq!(pyramid_level_name("ttps"), "TTPs");
    }

    #[test]
    fn pyramid_level_name_unknown_passthrough() {
        assert_eq!(pyramid_level_name("something_else"), "something_else");
    }

    // ── pyramid_level_value ─────────────────────────────────────────

    #[test]
    fn pyramid_level_value_ordering() {
        assert_eq!(pyramid_level_value("hash_values"), 1);
        assert_eq!(pyramid_level_value("ip_addresses"), 2);
        assert_eq!(pyramid_level_value("domain_names"), 3);
        assert_eq!(pyramid_level_value("network_host_artifacts"), 4);
        assert_eq!(pyramid_level_value("tools"), 5);
        assert_eq!(pyramid_level_value("ttps"), 6);
    }

    #[test]
    fn pyramid_level_value_unknown_is_zero() {
        assert_eq!(pyramid_level_value("unknown"), 0);
    }

    // ── technique_to_recipe ─────────────────────────────────────────

    #[test]
    fn technique_to_recipe_known_mappings() {
        let map = technique_to_recipe();
        assert_eq!(map.get("T1003.006"), Some(&"dcsync"));
        assert_eq!(map.get("T1110"), Some(&"password_spray"));
        assert_eq!(map.get("T1558.003"), Some(&"kerberos_attacks"));
        assert_eq!(map.get("T1550.002"), Some(&"pass_the_hash"));
        assert_eq!(map.get("T1135"), Some(&"share_enumeration"));
        assert_eq!(map.get("T1087.002"), Some(&"ldap_enumeration"));
        assert_eq!(map.get("T1046"), Some(&"service_enumeration"));
    }

    #[test]
    fn technique_to_recipe_unknown_returns_none() {
        let map = technique_to_recipe();
        assert!(map.get("T9999").is_none());
    }

    // ── attack_chains lazy cache ────────────────────────────────────

    #[test]
    fn attack_chains_loads_and_is_nonempty() {
        let chains = attack_chains();
        assert!(!chains.is_empty(), "attack_chains YAML should parse");
    }

    #[test]
    fn attack_chains_keys_start_with_t() {
        let chains = attack_chains();
        for key in chains.keys() {
            assert!(key.starts_with('T'), "key should start with T: {key}");
        }
    }

    #[test]
    fn attack_chains_entry_has_name() {
        let chains = attack_chains();
        // Pick any entry and verify it has a name
        if let Some((_, entry)) = chains.iter().next() {
            assert!(!entry.name.is_empty());
        }
    }

    // ── detection_recipes lazy cache ────────────────────────────────

    #[test]
    fn detection_recipes_loads_and_is_nonempty() {
        let recipes = detection_recipes();
        assert!(!recipes.is_empty(), "detection_recipes YAML should parse");
    }

    #[test]
    fn detection_recipes_excludes_query_prefixed_keys() {
        let recipes = detection_recipes();
        for key in recipes.keys() {
            assert!(
                !key.starts_with("query_"),
                "query_ prefixed keys should be filtered: {key}"
            );
        }
    }

    // ── climb_strategies lazy cache ─────────────────────────────────

    #[test]
    fn climb_strategies_loads_and_is_nonempty() {
        let strategies = climb_strategies();
        assert!(!strategies.is_empty(), "climb_strategies YAML should parse");
    }

    #[test]
    fn climb_strategies_entries_have_template() {
        let strategies = climb_strategies();
        for (_, entries) in strategies.iter() {
            for entry in entries {
                assert!(!entry.template.is_empty());
                assert!(!entry.target.is_empty());
            }
        }
    }

    // ── make_output ─────────────────────────────────────────────────

    #[test]
    fn make_output_returns_success() {
        let out = make_output("test body");
        assert!(out.success);
        assert_eq!(out.stdout, "test body");
        assert!(out.stderr.is_empty());
        assert_eq!(out.exit_code, Some(0));
    }
}
