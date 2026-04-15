//! Configuration section structs for each part of the Ares config.

use serde::{Deserialize, Serialize};

use super::defaults::*;

/// Operation-level settings: name, namespace, and task dispatch behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationConfig {
    pub name: String,
    pub namespace: String,
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_tasks: u32,
    #[serde(default)]
    pub task_dispatch_delay: f64,
    #[serde(default)]
    pub rate_limit_backoff: f64,
    #[serde(default)]
    pub rate_limit_threshold: u32,
    #[serde(default)]
    pub stop_on_domain_admin: bool,
    #[serde(default)]
    pub stop_on_golden_ticket: bool,
}

/// Per-agent configuration: model selection, step limits, and tool allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub model: String,
    #[serde(default = "default_max_steps")]
    pub max_steps: u32,
    #[serde(default)]
    pub pod_selector: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

/// Timeout values (in seconds) for various operation phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default)]
    pub agent_heartbeat: u64,
    #[serde(default)]
    pub task_timeout: u64,
    #[serde(default)]
    pub operation_timeout: u64,
    #[serde(default)]
    pub lateral_movement: u64,
    #[serde(default)]
    pub hash_cracking: u64,
    #[serde(default)]
    pub exploitation: u64,
}

/// Task retry and checkpoint recovery settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_delay")]
    pub retry_delay: u64,
    #[serde(default = "default_true")]
    pub checkpoint_on_credential: bool,
    #[serde(default = "default_true")]
    pub checkpoint_on_vulnerability: bool,
}

/// Thresholds that trigger phase transitions (e.g. lateral movement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseDetectionConfig {
    #[serde(default = "default_lateral_admin_creds")]
    pub lateral_movement_admin_creds: u32,
    #[serde(default = "default_lateral_owned_hosts")]
    pub lateral_movement_owned_hosts: u32,
    #[serde(default = "default_min_slots")]
    pub min_slots_per_role: u32,
}

/// LLM context window management settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextManagementConfig {
    #[serde(default = "default_max_context_tokens")]
    pub max_context_tokens: u64,
    #[serde(default = "default_min_messages")]
    pub min_messages_to_keep: u32,
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: u32,
}

/// Structured logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_file")]
    pub file: String,
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u32,
    #[serde(default = "default_backup_count")]
    pub backup_count: u32,
}

/// Resource limits for concurrent task execution and credential caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    #[serde(default = "default_max_concurrent_resources")]
    pub max_concurrent_tasks: u32,
    #[serde(default = "default_max_creds_per_expansion")]
    pub max_credentials_per_expansion: u32,
    #[serde(default = "default_max_hosts_per_scan")]
    pub max_hosts_per_scan: u32,
    #[serde(default = "default_cred_cache_ttl")]
    pub credential_cache_ttl: u64,
}

/// Security hardening settings: TLS verification, audit logging, rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub verify_ssl: bool,
    #[serde(default)]
    pub encrypted_state: bool,
    #[serde(default = "default_true")]
    pub audit_logging: bool,
    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,
}

/// API rate-limiting settings applied to outbound LLM requests.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_rpm")]
    pub max_requests_per_minute: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_config_defaults() {
        let cfg: RecoveryConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(cfg.retry_delay, 10);
        assert!(cfg.checkpoint_on_credential);
        assert!(cfg.checkpoint_on_vulnerability);
    }

    #[test]
    fn test_recovery_config_override() {
        let cfg: RecoveryConfig =
            serde_json::from_str(r#"{"enabled": false, "max_retries": 5}"#).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_retries, 5);
    }

    #[test]
    fn test_phase_detection_config_defaults() {
        let cfg: PhaseDetectionConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.lateral_movement_admin_creds, 3);
        assert_eq!(cfg.lateral_movement_owned_hosts, 5);
        assert_eq!(cfg.min_slots_per_role, 1);
    }

    #[test]
    fn test_context_management_config_defaults() {
        let cfg: ContextManagementConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.max_context_tokens, 50000);
        assert_eq!(cfg.min_messages_to_keep, 15);
        assert_eq!(cfg.max_output_chars, 3000);
    }

    #[test]
    fn test_logging_config_defaults() {
        let cfg: LoggingConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.level, "INFO");
        assert_eq!(cfg.max_size_mb, 100);
        assert_eq!(cfg.backup_count, 5);
    }

    #[test]
    fn test_resource_config_defaults() {
        let cfg: ResourceConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.max_concurrent_tasks, 10);
        assert_eq!(cfg.max_credentials_per_expansion, 100);
        assert_eq!(cfg.max_hosts_per_scan, 50);
        assert_eq!(cfg.credential_cache_ttl, 3600);
    }

    #[test]
    fn test_security_config_defaults() {
        let cfg: SecurityConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.verify_ssl);
        assert!(!cfg.encrypted_state);
        assert!(cfg.audit_logging);
    }

    #[test]
    fn test_rate_limiting_config_defaults() {
        let cfg: RateLimitingConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_requests_per_minute, 60);
    }

    #[test]
    fn test_timeout_config_all_zero_defaults() {
        let cfg: TimeoutConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.agent_heartbeat, 0);
        assert_eq!(cfg.task_timeout, 0);
        assert_eq!(cfg.operation_timeout, 0);
    }

    #[test]
    fn test_agent_config_defaults() {
        let cfg: AgentConfig = serde_json::from_str(r#"{"model": "openai/gpt-4.1"}"#).unwrap();
        assert_eq!(cfg.model, "openai/gpt-4.1");
        assert_eq!(cfg.max_steps, 100);
        assert!(cfg.capabilities.is_empty());
        assert!(cfg.tools.is_empty());
    }
}

/// Optional Grafana dashboard integration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub dashboard_uid: String,
}

/// Observability backend URLs for blue team tools.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservabilityConfig {
    /// Direct Loki URL (e.g. `http://localhost:3100`).
    #[serde(default)]
    pub loki_url: String,
    /// Optional Bearer token for Loki auth.
    #[serde(default)]
    pub loki_auth_token: String,
    /// Direct Prometheus URL (e.g. `http://localhost:9090`).
    #[serde(default)]
    pub prometheus_url: String,
}
