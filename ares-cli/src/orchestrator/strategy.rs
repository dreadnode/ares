//! Strategy profiles — technique weights and filtering for path diversity.
//!
//! Controls which attack techniques the operator prioritizes, allowing the same
//! codebase to run in "fast" mode (shortest path to DA) or "comprehensive" mode
//! (exploit everything discovered). Weights are generic AD technique categories,
//! not target-specific, so they scale to any environment.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tracing::info;

/// Named strategy presets. Each provides default technique weights.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyPreset {
    /// Shortest path to DA. Current default behavior.
    #[default]
    Fast,
    /// Exploit all discovered vulnerabilities. Don't stop on first DA.
    Comprehensive,
    /// Avoid noisy techniques. Prefer ADCS, delegation, ACL abuse.
    Stealth,
}

impl StrategyPreset {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "comprehensive" | "full" | "all" => Self::Comprehensive,
            "stealth" | "quiet" => Self::Stealth,
            _ => Self::Fast,
        }
    }

    /// Default technique weights for this preset.
    /// Lower number = higher priority (1 = most urgent, 10 = lowest).
    fn default_weights(&self) -> HashMap<String, i32> {
        match self {
            Self::Fast => fast_weights(),
            Self::Comprehensive => comprehensive_weights(),
            Self::Stealth => stealth_weights(),
        }
    }

    /// Whether this preset implies `continue_after_da = true`.
    pub fn implies_continue_after_da(&self) -> bool {
        matches!(self, Self::Comprehensive)
    }
}

/// Resolved strategy: preset defaults merged with user overrides.
#[derive(Debug, Clone)]
pub struct Strategy {
    pub preset: StrategyPreset,
    /// Merged technique weights (preset defaults + user overrides).
    pub weights: HashMap<String, i32>,
    /// Techniques to completely exclude (never dispatch).
    pub exclude_techniques: HashSet<String>,
    /// If non-empty, ONLY these techniques are allowed.
    pub include_techniques: HashSet<String>,
    /// Keep exploiting after DA? Overridden by YAML stop_on_domain_admin.
    pub continue_after_da: bool,
    /// LLM temperature override. None = provider default.
    pub llm_temperature: Option<f32>,
}

impl Default for Strategy {
    fn default() -> Self {
        Self::from_preset(StrategyPreset::Fast)
    }
}

impl Strategy {
    pub fn from_preset(preset: StrategyPreset) -> Self {
        Self {
            continue_after_da: preset.implies_continue_after_da(),
            weights: preset.default_weights(),
            exclude_techniques: HashSet::new(),
            include_techniques: HashSet::new(),
            llm_temperature: None,
            preset,
        }
    }

    /// Resolve the strategy from all config sources.
    ///
    /// Precedence (highest wins):
    /// 1. Environment variables (`ARES_STRATEGY`, `ARES_EXCLUDE_TECHNIQUES`, etc.)
    /// 2. JSON operation payload fields (`strategy`, `technique_weights`, etc.)
    /// 3. YAML config (`operation.strategy`, `operation.technique_weights`,
    ///    `vulnerability_priorities`)
    /// 4. Preset defaults
    pub fn resolve(
        json: Option<&serde_json::Value>,
        yaml: Option<&ares_core::config::AresConfig>,
    ) -> Self {
        // 1. Determine preset: env > json > yaml > default
        let preset_str = std::env::var("ARES_STRATEGY")
            .ok()
            .or_else(|| {
                json.and_then(|v| v.get("strategy"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                yaml.map(|c| &c.operation.strategy)
                    .filter(|s| !s.is_empty())
                    .cloned()
            })
            .unwrap_or_else(|| "fast".to_string());
        let preset = StrategyPreset::from_str_loose(&preset_str);

        let mut strategy = Self::from_preset(preset);

        // 2. Merge technique weights: yaml vulnerability_priorities first (lowest
        //    precedence), then yaml technique_weights, then json, then env.
        //    Later layers overwrite earlier ones.
        if let Some(cfg) = yaml {
            // vulnerability_priorities from YAML (existing section)
            for (k, v) in &cfg.vulnerability_priorities {
                strategy.weights.insert(k.to_lowercase(), (*v).clamp(1, 10));
            }
            // operation.technique_weights from YAML (new section, higher precedence)
            for (k, v) in &cfg.operation.technique_weights {
                strategy.weights.insert(k.to_lowercase(), (*v).clamp(1, 10));
            }
        }

        // JSON payload technique_weights (higher precedence than YAML)
        if let Some(weights) = json
            .and_then(|v| v.get("technique_weights"))
            .and_then(|v| v.as_object())
        {
            for (k, v) in weights {
                if let Some(w) = v.as_i64() {
                    strategy
                        .weights
                        .insert(k.to_lowercase(), w.clamp(1, 10) as i32);
                }
            }
        }

        // 3. Parse exclude_techniques: env > json > yaml
        let exclude = parse_technique_list(
            json.and_then(|v| v.get("exclude_techniques")),
            "ARES_EXCLUDE_TECHNIQUES",
        );
        let exclude = if exclude.is_empty() {
            yaml.map(|c| {
                c.operation
                    .exclude_techniques
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect()
            })
            .unwrap_or_default()
        } else {
            exclude
        };
        strategy.exclude_techniques = exclude;

        // 4. Parse include_techniques: env > json > yaml
        let include = parse_technique_list(
            json.and_then(|v| v.get("include_techniques")),
            "ARES_INCLUDE_TECHNIQUES",
        );
        let include = if include.is_empty() {
            yaml.map(|c| {
                c.operation
                    .include_techniques
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect()
            })
            .unwrap_or_default()
        } else {
            include
        };
        strategy.include_techniques = include;

        // 5. Parse continue_after_da: env > json > yaml > preset default
        if let Ok(v) = std::env::var("ARES_CONTINUE_AFTER_DA") {
            strategy.continue_after_da = v == "1" || v.to_lowercase() == "true";
        } else if let Some(v) = json
            .and_then(|v| v.get("continue_after_da"))
            .and_then(|v| v.as_bool())
        {
            strategy.continue_after_da = v;
        } else if let Some(cfg) = yaml {
            if cfg.operation.continue_after_da {
                strategy.continue_after_da = true;
            }
        }

        // 6. Parse llm_temperature: env > json > yaml
        strategy.llm_temperature = std::env::var("ARES_LLM_TEMPERATURE")
            .ok()
            .and_then(|v| v.parse::<f32>().ok())
            .or_else(|| {
                json.and_then(|v| v.get("llm_temperature"))
                    .and_then(|v| v.as_f64())
                    .map(|v| v as f32)
            })
            .or_else(|| yaml.and_then(|c| c.operation.llm_temperature));

        info!(
            preset = ?strategy.preset,
            continue_after_da = strategy.continue_after_da,
            llm_temperature = ?strategy.llm_temperature,
            exclude_count = strategy.exclude_techniques.len(),
            include_count = strategy.include_techniques.len(),
            weight_overrides = strategy.weights.len(),
            "Strategy resolved"
        );

        strategy
    }

    /// Check if a technique is allowed by the current strategy.
    ///
    /// A technique is blocked if:
    /// - It appears in `exclude_techniques`, OR
    /// - `include_techniques` is non-empty and the technique is NOT in it
    pub fn is_technique_allowed(&self, technique: &str) -> bool {
        let t = technique.to_lowercase();

        if self.exclude_techniques.contains(&t) {
            return false;
        }

        if !self.include_techniques.is_empty() && !self.include_techniques.contains(&t) {
            return false;
        }

        true
    }

    /// Get the effective priority for a vulnerability type.
    ///
    /// Returns the weight from the merged map, or a default of 5.
    pub fn effective_priority(&self, vuln_type: &str) -> i32 {
        let t = vuln_type.to_lowercase();
        self.weights.get(&t).copied().unwrap_or(5)
    }

    /// Whether exploitation should continue after DA is achieved.
    ///
    /// `comprehensive` preset defaults to true. Can be overridden by
    /// `continue_after_da` field or YAML `stop_on_domain_admin`.
    pub fn should_continue_after_da(&self) -> bool {
        self.continue_after_da
    }

    /// Whether the strategy allows higher dispatch throughput per cycle.
    /// Comprehensive mode lifts per-cycle `.take()` limits so all domains
    /// get work dispatched in parallel rather than being serialized.
    pub fn is_comprehensive(&self) -> bool {
        self.preset == StrategyPreset::Comprehensive
    }
}

// ---------------------------------------------------------------------------
// Preset weight maps
// ---------------------------------------------------------------------------

/// Fast: prioritize secretsdump and golden ticket. ADCS and ACL are fallbacks.
fn fast_weights() -> HashMap<String, i32> {
    [
        ("dc_secretsdump", 1),
        ("golden_ticket", 1),
        ("forest_trust_escalation", 1),
        ("child_to_parent", 1),
        ("domain_admin", 1),
        ("secretsdump", 2),
        ("credential_reuse", 3),
        ("mssql_access", 4),
        ("mssql_linked_server", 4),
        ("mssql_impersonation", 4),
        ("constrained_delegation", 5),
        ("unconstrained_delegation", 5),
        ("esc1", 5),
        ("esc4", 5),
        ("esc8", 5),
        ("rbcd", 6),
        ("acl_abuse", 6),
        ("shadow_credentials", 6),
        ("mssql_deep_exploitation", 4),
        ("kerberoast", 5),
        ("asrep_roast", 5),
        ("password_spray", 4),
        ("gmsa", 3),
        ("low_hanging_fruit", 4),
        ("smb_signing_disabled", 7),
        ("adcs_esc1", 5),
        ("adcs_esc4", 5),
        ("adcs_esc8", 5),
        ("gpo_abuse", 6),
        ("laps", 4),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// Comprehensive: flat priorities so all techniques get equal attention.
fn comprehensive_weights() -> HashMap<String, i32> {
    [
        ("dc_secretsdump", 3),
        ("golden_ticket", 3),
        ("forest_trust_escalation", 3),
        ("child_to_parent", 3),
        ("domain_admin", 3),
        ("secretsdump", 3),
        ("credential_reuse", 3),
        ("mssql_access", 3),
        ("mssql_linked_server", 3),
        ("mssql_impersonation", 3),
        ("constrained_delegation", 3),
        ("unconstrained_delegation", 3),
        ("esc1", 3),
        ("esc4", 3),
        ("esc8", 3),
        ("rbcd", 3),
        ("acl_abuse", 3),
        ("shadow_credentials", 3),
        ("mssql_deep_exploitation", 3),
        ("kerberoast", 3),
        ("asrep_roast", 3),
        ("password_spray", 3),
        ("gmsa", 3),
        ("low_hanging_fruit", 3),
        ("smb_signing_disabled", 3),
        ("adcs_esc1", 3),
        ("adcs_esc4", 3),
        ("adcs_esc8", 3),
        ("gpo_abuse", 3),
        ("laps", 3),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// Stealth: suppress noisy techniques, prefer ADCS and ACL paths.
fn stealth_weights() -> HashMap<String, i32> {
    [
        ("dc_secretsdump", 6),
        ("golden_ticket", 4),
        ("forest_trust_escalation", 4),
        ("child_to_parent", 4),
        ("domain_admin", 3),
        ("secretsdump", 7),
        ("credential_reuse", 3),
        ("mssql_access", 4),
        ("mssql_linked_server", 4),
        ("mssql_impersonation", 4),
        ("constrained_delegation", 2),
        ("unconstrained_delegation", 2),
        ("esc1", 1),
        ("esc4", 1),
        ("esc8", 2),
        ("rbcd", 3),
        ("acl_abuse", 1),
        ("shadow_credentials", 2),
        ("mssql_deep_exploitation", 4),
        ("kerberoast", 4),
        ("asrep_roast", 3),
        ("password_spray", 8),
        ("gmsa", 3),
        ("low_hanging_fruit", 4),
        ("smb_signing_disabled", 8),
        ("adcs_esc1", 1),
        ("adcs_esc4", 1),
        ("adcs_esc8", 2),
        ("gpo_abuse", 3),
        ("laps", 3),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a technique list from a JSON value (array of strings) or env var (comma-separated).
fn parse_technique_list(json_val: Option<&serde_json::Value>, env_key: &str) -> HashSet<String> {
    let mut set = HashSet::new();

    if let Some(arr) = json_val.and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                set.insert(s.to_lowercase());
            }
        }
    }

    if let Ok(env_val) = std::env::var(env_key) {
        for item in env_val.split(',') {
            let trimmed = item.trim().to_lowercase();
            if !trimmed.is_empty() {
                set.insert(trimmed);
            }
        }
    }

    set
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_strategy_is_fast() {
        let s = Strategy::default();
        assert_eq!(s.preset, StrategyPreset::Fast);
        assert!(!s.continue_after_da);
    }

    #[test]
    fn test_comprehensive_implies_continue_after_da() {
        let s = Strategy::from_preset(StrategyPreset::Comprehensive);
        assert!(s.continue_after_da);
    }

    #[test]
    fn test_technique_allowed_no_filters() {
        let s = Strategy::default();
        assert!(s.is_technique_allowed("secretsdump"));
        assert!(s.is_technique_allowed("esc1"));
    }

    #[test]
    fn test_technique_excluded() {
        let mut s = Strategy::default();
        s.exclude_techniques.insert("secretsdump".to_string());
        assert!(!s.is_technique_allowed("secretsdump"));
        assert!(!s.is_technique_allowed("Secretsdump")); // case insensitive
        assert!(s.is_technique_allowed("esc1"));
    }

    #[test]
    fn test_technique_include_allowlist() {
        let mut s = Strategy::default();
        s.include_techniques.insert("esc1".to_string());
        s.include_techniques.insert("esc4".to_string());
        assert!(s.is_technique_allowed("esc1"));
        assert!(s.is_technique_allowed("esc4"));
        assert!(!s.is_technique_allowed("secretsdump"));
    }

    #[test]
    fn test_effective_priority_from_preset() {
        let s = Strategy::from_preset(StrategyPreset::Fast);
        assert_eq!(s.effective_priority("dc_secretsdump"), 1);
        assert_eq!(s.effective_priority("esc1"), 5);
    }

    #[test]
    fn test_effective_priority_with_override() {
        let mut s = Strategy::from_preset(StrategyPreset::Fast);
        s.weights.insert("esc1".to_string(), 1);
        assert_eq!(s.effective_priority("esc1"), 1);
    }

    #[test]
    fn test_effective_priority_unknown_type() {
        let s = Strategy::default();
        assert_eq!(s.effective_priority("unknown_technique"), 5);
    }

    #[test]
    fn test_stealth_deprioritizes_noisy() {
        let s = Strategy::from_preset(StrategyPreset::Stealth);
        assert!(s.effective_priority("password_spray") > s.effective_priority("esc1"));
        assert!(s.effective_priority("secretsdump") > s.effective_priority("acl_abuse"));
    }

    #[test]
    fn test_comprehensive_flat_weights() {
        let s = Strategy::from_preset(StrategyPreset::Comprehensive);
        assert_eq!(s.effective_priority("secretsdump"), 3);
        assert_eq!(s.effective_priority("esc1"), 3);
        assert_eq!(s.effective_priority("acl_abuse"), 3);
    }

    #[test]
    fn test_preset_from_str_loose() {
        assert_eq!(StrategyPreset::from_str_loose("fast"), StrategyPreset::Fast);
        assert_eq!(
            StrategyPreset::from_str_loose("comprehensive"),
            StrategyPreset::Comprehensive
        );
        assert_eq!(
            StrategyPreset::from_str_loose("full"),
            StrategyPreset::Comprehensive
        );
        assert_eq!(
            StrategyPreset::from_str_loose("stealth"),
            StrategyPreset::Stealth
        );
        assert_eq!(
            StrategyPreset::from_str_loose("quiet"),
            StrategyPreset::Stealth
        );
        assert_eq!(
            StrategyPreset::from_str_loose("garbage"),
            StrategyPreset::Fast
        );
    }

    #[test]
    fn test_from_json_with_overrides() {
        let json = serde_json::json!({
            "strategy": "fast",
            "technique_weights": {
                "esc1": 1,
                "secretsdump": 8
            },
            "exclude_techniques": ["password_spray"],
            "continue_after_da": true
        });

        let s = Strategy::resolve(Some(&json), None);
        assert_eq!(s.preset, StrategyPreset::Fast);
        assert_eq!(s.effective_priority("esc1"), 1);
        assert_eq!(s.effective_priority("secretsdump"), 8);
        assert!(!s.is_technique_allowed("password_spray"));
        assert!(s.continue_after_da);
    }

    #[test]
    fn test_parse_technique_list_json_array() {
        let json = serde_json::json!(["secretsdump", "golden_ticket"]);
        let result = parse_technique_list(Some(&json), "NONEXISTENT_ENV_KEY_12345");
        assert!(result.contains("secretsdump"));
        assert!(result.contains("golden_ticket"));
        assert_eq!(result.len(), 2);
    }

    /// Build a minimal AresConfig for testing YAML strategy resolution.
    fn test_yaml_config(
        strategy: &str,
        continue_after_da: bool,
        exclude: Vec<&str>,
        technique_weights: Vec<(&str, i32)>,
        vuln_priorities: Vec<(&str, i32)>,
    ) -> ares_core::config::AresConfig {
        let yaml_str = serde_yaml::to_string(&serde_json::json!({
            "operation": {
                "name": "test",
                "namespace": "ns",
                "strategy": strategy,
                "continue_after_da": continue_after_da,
                "exclude_techniques": exclude,
                "technique_weights": technique_weights.into_iter()
                    .collect::<std::collections::HashMap<_, _>>(),
            },
            "agents": {},
            "timeouts": {},
            "recovery": {},
            "phase_detection": {},
            "context_management": {},
            "vulnerability_priorities": vuln_priorities.into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
            "logging": {},
            "resources": {},
            "security": {},
        }))
        .unwrap();
        serde_yaml::from_str(&yaml_str).unwrap()
    }

    #[test]
    fn test_resolve_with_yaml_config() {
        let cfg = test_yaml_config(
            "comprehensive",
            true,
            vec!["password_spray"],
            vec![("esc1", 1), ("secretsdump", 8)],
            vec![("adcs_esc1", 2), ("kerberoast", 7)],
        );

        let s = Strategy::resolve(None, Some(&cfg));
        assert_eq!(s.preset, StrategyPreset::Comprehensive);
        assert!(s.continue_after_da);
        assert!(!s.is_technique_allowed("password_spray"));
        // technique_weights override vulnerability_priorities for same key
        assert_eq!(s.effective_priority("esc1"), 1);
        // vulnerability_priorities loaded for keys not in technique_weights
        assert_eq!(s.effective_priority("kerberoast"), 7);
        // technique_weights takes precedence
        assert_eq!(s.effective_priority("secretsdump"), 8);
    }

    #[test]
    fn test_json_overrides_yaml() {
        let cfg = test_yaml_config("stealth", false, vec![], vec![("esc1", 5)], vec![]);

        // JSON payload overrides YAML
        let json = serde_json::json!({
            "strategy": "fast",
            "technique_weights": {"esc1": 2}
        });
        let s = Strategy::resolve(Some(&json), Some(&cfg));
        // JSON "fast" wins over YAML "stealth"
        assert_eq!(s.preset, StrategyPreset::Fast);
        // JSON weight wins over YAML weight
        assert_eq!(s.effective_priority("esc1"), 2);
    }

    #[test]
    fn test_is_comprehensive() {
        assert!(Strategy::from_preset(StrategyPreset::Comprehensive).is_comprehensive());
        assert!(!Strategy::from_preset(StrategyPreset::Fast).is_comprehensive());
        assert!(!Strategy::from_preset(StrategyPreset::Stealth).is_comprehensive());
    }

    #[test]
    fn test_should_continue_after_da() {
        let fast = Strategy::from_preset(StrategyPreset::Fast);
        assert!(!fast.should_continue_after_da());

        let comp = Strategy::from_preset(StrategyPreset::Comprehensive);
        assert!(comp.should_continue_after_da());

        let stealth = Strategy::from_preset(StrategyPreset::Stealth);
        assert!(!stealth.should_continue_after_da());
    }

    #[test]
    fn test_new_technique_weights_in_presets() {
        // Verify that new techniques added in this branch are in all presets
        let new_techniques = ["rbcd", "shadow_credentials", "mssql_deep_exploitation"];
        for preset in [
            StrategyPreset::Fast,
            StrategyPreset::Comprehensive,
            StrategyPreset::Stealth,
        ] {
            let s = Strategy::from_preset(preset);
            for tech in &new_techniques {
                assert!(
                    s.weights.contains_key(*tech),
                    "Preset {:?} missing weight for {tech}",
                    preset
                );
            }
        }
    }

    #[test]
    fn test_comprehensive_has_equal_weights() {
        let s = Strategy::from_preset(StrategyPreset::Comprehensive);
        // All comprehensive weights should be 3
        for (tech, weight) in &s.weights {
            assert_eq!(*weight, 3, "Technique {tech} has weight {weight} != 3");
        }
    }

    #[test]
    fn test_stealth_penalizes_noisy_techniques() {
        let s = Strategy::from_preset(StrategyPreset::Stealth);
        // Password spray and SMB signing should be most penalized (8)
        assert_eq!(s.effective_priority("password_spray"), 8);
        assert_eq!(s.effective_priority("smb_signing_disabled"), 8);
        // ADCS/ACL should be most prioritized (1)
        assert_eq!(s.effective_priority("esc1"), 1);
        assert_eq!(s.effective_priority("acl_abuse"), 1);
    }

    #[test]
    fn test_fast_prioritizes_secretsdump() {
        let s = Strategy::from_preset(StrategyPreset::Fast);
        assert_eq!(s.effective_priority("dc_secretsdump"), 1);
        assert_eq!(s.effective_priority("golden_ticket"), 1);
        assert_eq!(s.effective_priority("secretsdump"), 2);
    }

    #[test]
    fn test_preset_implies_continue_after_da() {
        assert!(StrategyPreset::Comprehensive.implies_continue_after_da());
        assert!(!StrategyPreset::Fast.implies_continue_after_da());
        assert!(!StrategyPreset::Stealth.implies_continue_after_da());
    }

    #[test]
    fn test_include_and_exclude_interact() {
        let mut s = Strategy::default();
        // Include-only list
        s.include_techniques.insert("esc1".to_string());
        // Exclude takes precedence over include
        s.exclude_techniques.insert("esc1".to_string());
        assert!(!s.is_technique_allowed("esc1"));
    }
}
