//! Configuration module — single source of truth for all Ares settings.
//!
//! The YAML config file (pointed to by `ARES_CONFIG`) is the canonical config.
//! No env-var fallback chains for individual settings. One file, one truth.

pub mod defaults;
pub mod sections;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub use sections::*;

use defaults::default_max_steps;

/// Default search paths for the config file, in priority order.
const DEFAULT_PATHS: &[&str] = &[
    "./config/ares.yaml",
    "/ares/config/ares.yaml",
    "/etc/ares/config.yaml",
];

/// Root configuration for the Ares system.
///
/// Loaded from a single YAML file. This is the single source of truth
/// for all operational parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AresConfig {
    pub operation: OperationConfig,
    pub agents: HashMap<String, AgentConfig>,
    pub timeouts: TimeoutConfig,
    pub recovery: RecoveryConfig,
    pub phase_detection: PhaseDetectionConfig,
    pub context_management: ContextManagementConfig,
    pub vulnerability_priorities: HashMap<String, i32>,
    pub logging: LoggingConfig,
    pub resources: ResourceConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub grafana: Option<GrafanaConfig>,
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,
}

impl AresConfig {
    /// Load config from a specific file path.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Self = serde_yaml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate config invariants after loading.
    fn validate(&self) -> Result<()> {
        if self.operation.stop_on_domain_admin && self.operation.stop_on_golden_ticket {
            bail!(
                "stop_on_domain_admin and stop_on_golden_ticket are mutually exclusive — \
                 enable one or the other, not both"
            );
        }
        Ok(())
    }

    /// Resolve the config file path and load it.
    ///
    /// Resolution order:
    /// 1. `ARES_CONFIG` env var
    /// 2. `./config/ares.yaml`
    /// 3. `/etc/ares/config.yaml`
    pub fn from_env() -> Result<Self> {
        let path = Self::resolve_path()?;
        Self::load(&path)
    }

    /// Resolve the config file path without loading.
    ///
    /// Same resolution order as [`from_env`].
    pub fn resolve_path() -> Result<PathBuf> {
        // 1. Explicit env var
        if let Ok(env_path) = std::env::var("ARES_CONFIG") {
            let p = PathBuf::from(&env_path);
            if p.exists() {
                return Ok(p);
            }
            bail!("ARES_CONFIG points to {env_path} but the file does not exist");
        }

        // 2. Default search paths
        for candidate in DEFAULT_PATHS {
            let p = PathBuf::from(candidate);
            if p.exists() {
                return Ok(p);
            }
        }

        bail!(
            "No config file found. Set ARES_CONFIG or place config at one of: {}",
            DEFAULT_PATHS.join(", ")
        );
    }

    /// Get the model assigned to a specific agent role.
    ///
    /// Returns `None` if the role is not defined in the config.
    pub fn model_for_role(&self, role: &str) -> Option<&str> {
        self.agents.get(role).map(|a| a.model.as_str())
    }

    /// List all agent role names defined in the config.
    pub fn agent_roles(&self) -> Vec<&str> {
        self.agents.keys().map(|k| k.as_str()).collect()
    }

    /// Get the priority value for a vulnerability type.
    ///
    /// Lower values = higher priority. Returns `i32::MAX` if the type
    /// is not in the priority map.
    pub fn vulnerability_priority(&self, vuln_type: &str) -> i32 {
        self.vulnerability_priorities
            .get(vuln_type)
            .copied()
            .unwrap_or(i32::MAX)
    }

    /// Set the model for a specific role, returning the old value.
    ///
    /// Returns `None` if the role did not exist (and creates it with defaults).
    pub fn set_model_for_role(&mut self, role: &str, model: &str) -> Option<String> {
        if let Some(agent) = self.agents.get_mut(role) {
            let old = std::mem::replace(&mut agent.model, model.to_string());
            Some(old)
        } else {
            self.agents.insert(
                role.to_string(),
                AgentConfig {
                    model: model.to_string(),
                    max_steps: default_max_steps(),
                    pod_selector: String::new(),
                    capabilities: Vec::new(),
                    tools: Vec::new(),
                },
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Minimal valid YAML for testing.
    const MINIMAL_YAML: &str = r#"
operation:
  name: "test-op"
  namespace: "test-ns"
agents:
  orchestrator:
    model: "gpt-5.2"
    max_steps: 200
  recon:
    model: "gpt-4.1"
    max_steps: 100
    capabilities:
      - nmap
      - ldapsearch
timeouts:
  agent_heartbeat: 180
  task_timeout: 300
  operation_timeout: 7200
  lateral_movement: 180
  hash_cracking: 600
  exploitation: 900
recovery:
  enabled: true
  max_retries: 3
  retry_delay: 10
phase_detection:
  lateral_movement_admin_creds: 3
  lateral_movement_owned_hosts: 5
  min_slots_per_role: 1
context_management:
  max_context_tokens: 50000
  min_messages_to_keep: 15
  max_output_chars: 3000
vulnerability_priorities:
  adcs_esc1: 1
  constrained_delegation: 4
  kerberoast: 20
  password_spray: 50
logging:
  level: "INFO"
resources:
  max_concurrent_tasks: 10
security:
  verify_ssl: true
  audit_logging: true
"#;

    fn write_temp_yaml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_load_minimal_config() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert_eq!(cfg.operation.name, "test-op");
        assert_eq!(cfg.operation.namespace, "test-ns");
        assert_eq!(cfg.agents.len(), 2);
    }

    #[test]
    fn test_model_for_role() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert_eq!(cfg.model_for_role("orchestrator"), Some("gpt-5.2"));
        assert_eq!(cfg.model_for_role("recon"), Some("gpt-4.1"));
        assert_eq!(cfg.model_for_role("nonexistent"), None);
    }

    #[test]
    fn test_agent_roles() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let cfg = AresConfig::load(f.path()).unwrap();
        let mut roles = cfg.agent_roles();
        roles.sort();
        assert_eq!(roles, vec!["orchestrator", "recon"]);
    }

    #[test]
    fn test_vulnerability_priority() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert_eq!(cfg.vulnerability_priority("adcs_esc1"), 1);
        assert_eq!(cfg.vulnerability_priority("constrained_delegation"), 4);
        assert_eq!(cfg.vulnerability_priority("kerberoast"), 20);
        assert_eq!(cfg.vulnerability_priority("password_spray"), 50);
        assert_eq!(cfg.vulnerability_priority("unknown_type"), i32::MAX);
    }

    #[test]
    fn test_set_model_for_role() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let mut cfg = AresConfig::load(f.path()).unwrap();
        let old = cfg.set_model_for_role("orchestrator", "gpt-4o");
        assert_eq!(old, Some("gpt-5.2".to_string()));
        assert_eq!(cfg.model_for_role("orchestrator"), Some("gpt-4o"));
    }

    #[test]
    fn test_set_model_for_new_role() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let mut cfg = AresConfig::load(f.path()).unwrap();
        let old = cfg.set_model_for_role("new_role", "gpt-4o-mini");
        assert!(old.is_none());
        assert_eq!(cfg.model_for_role("new_role"), Some("gpt-4o-mini"));
    }

    #[test]
    fn test_from_env_with_env_var() {
        let f = write_temp_yaml(MINIMAL_YAML);
        // Temporarily set env var
        let path_str = f.path().to_string_lossy().to_string();
        std::env::set_var("ARES_CONFIG", &path_str);
        let cfg = AresConfig::from_env().unwrap();
        assert_eq!(cfg.operation.name, "test-op");
        std::env::remove_var("ARES_CONFIG");
    }

    #[test]
    fn test_from_env_missing_file() {
        std::env::set_var("ARES_CONFIG", "/nonexistent/path/config.yaml");
        let result = AresConfig::from_env();
        assert!(result.is_err());
        std::env::remove_var("ARES_CONFIG");
    }

    #[test]
    fn test_defaults_applied() {
        let minimal = r#"
operation:
  name: "test"
  namespace: "ns"
agents: {}
timeouts: {}
recovery: {}
phase_detection: {}
context_management: {}
vulnerability_priorities: {}
logging: {}
resources: {}
security: {}
"#;
        let f = write_temp_yaml(minimal);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert_eq!(cfg.operation.checkpoint_interval, 60);
        assert_eq!(cfg.operation.max_concurrent_tasks, 8);
        assert!(cfg.recovery.enabled);
        assert_eq!(cfg.recovery.max_retries, 3);
        assert_eq!(cfg.context_management.max_context_tokens, 50000);
    }

    #[test]
    fn test_load_production_config() {
        // Test against the actual production config if it exists at the expected relative path
        let prod_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config/ares.yaml");

        if prod_path.exists() {
            let cfg = AresConfig::load(&prod_path).unwrap();
            assert_eq!(cfg.operation.name, "ares-multi-agent");
            assert_eq!(cfg.operation.namespace, "attack-simulation");
            // All 8 agent roles should be present
            assert!(cfg.agents.contains_key("orchestrator"));
            assert!(cfg.agents.contains_key("recon"));
            assert!(cfg.agents.contains_key("credential_access"));
            assert!(cfg.agents.contains_key("cracker"));
            assert!(cfg.agents.contains_key("acl"));
            assert!(cfg.agents.contains_key("privesc"));
            assert!(cfg.agents.contains_key("lateral"));
            assert!(cfg.agents.contains_key("coercion"));
            assert_eq!(cfg.agents.len(), 8);
            // Vulnerability priorities
            assert_eq!(cfg.vulnerability_priority("adcs_esc1"), 1);
            assert_eq!(cfg.vulnerability_priority("password_spray"), 50);
        }
    }

    #[test]
    fn test_stop_criteria_mutually_exclusive() {
        let yaml = MINIMAL_YAML.replace(
            "namespace: \"test-ns\"",
            "namespace: \"test-ns\"\n  stop_on_domain_admin: true\n  stop_on_golden_ticket: true",
        );
        let f = write_temp_yaml(&yaml);
        let result = AresConfig::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("mutually exclusive"),
            "Expected mutual exclusivity error, got: {err}"
        );
    }

    #[test]
    fn test_stop_on_golden_ticket_alone_valid() {
        let yaml = MINIMAL_YAML.replace(
            "namespace: \"test-ns\"",
            "namespace: \"test-ns\"\n  stop_on_golden_ticket: true",
        );
        let f = write_temp_yaml(&yaml);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert!(cfg.operation.stop_on_golden_ticket);
        assert!(!cfg.operation.stop_on_domain_admin);
    }

    #[test]
    fn test_stop_on_domain_admin_alone_valid() {
        let yaml = MINIMAL_YAML.replace(
            "namespace: \"test-ns\"",
            "namespace: \"test-ns\"\n  stop_on_domain_admin: true",
        );
        let f = write_temp_yaml(&yaml);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert!(cfg.operation.stop_on_domain_admin);
        assert!(!cfg.operation.stop_on_golden_ticket);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let cfg = AresConfig::load(f.path()).unwrap();
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let cfg2: AresConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.operation.name, cfg2.operation.name);
        assert_eq!(cfg.agents.len(), cfg2.agents.len());
    }

    #[test]
    fn test_grafana_optional() {
        let f = write_temp_yaml(MINIMAL_YAML);
        let cfg = AresConfig::load(f.path()).unwrap();
        assert!(cfg.grafana.is_none());

        let with_grafana = format!(
            "{}\ngrafana:\n  enabled: true\n  base_url: http://grafana\n",
            MINIMAL_YAML
        );
        let f2 = write_temp_yaml(&with_grafana);
        let cfg2 = AresConfig::load(f2.path()).unwrap();
        assert!(cfg2.grafana.is_some());
        assert!(cfg2.grafana.unwrap().enabled);
    }
}
