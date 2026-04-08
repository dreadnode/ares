//! Configuration section structs for each part of the Ares config.

use serde::{Deserialize, Serialize};

use super::defaults::*;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseDetectionConfig {
    #[serde(default = "default_lateral_admin_creds")]
    pub lateral_movement_admin_creds: u32,
    #[serde(default = "default_lateral_owned_hosts")]
    pub lateral_movement_owned_hosts: u32,
    #[serde(default = "default_min_slots")]
    pub min_slots_per_role: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextManagementConfig {
    #[serde(default = "default_max_context_tokens")]
    pub max_context_tokens: u64,
    #[serde(default = "default_min_messages")]
    pub min_messages_to_keep: u32,
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: u32,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_rpm")]
    pub max_requests_per_minute: u32,
}

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
