//! Data models for the Ares red team orchestration system.
//!
//! These structs match the Python models exactly in field names and JSON serialization
//! format, ensuring interoperability with the existing Python orchestrator and workers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Red Team Core Models
// ============================================================================

/// Primary target information.
///
/// Matches Python: `class Target(Model)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
}

/// Discovered host information.
///
/// Matches Python: `class Host(Model)`
/// Redis serialization: `{"ip","hostname","os","roles","services","is_dc"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default)]
    pub is_dc: bool,
    #[serde(default)]
    pub owned: bool,
}

impl Host {
    /// Detect if this host is a domain controller based on services/hostname/roles.
    pub fn detect_dc(&self) -> bool {
        let hostname_lower = self.hostname.to_lowercase();
        let roles_lower = self.roles.join(" ").to_lowercase();

        if hostname_lower.contains("dc") || roles_lower.contains("domain controller") {
            return true;
        }

        let dc_port_prefixes = ["88/tcp", "389/tcp"];
        let dc_service_names = ["kerberos", "ldap"];

        for svc in &self.services {
            let svc_lower = svc.to_lowercase();
            if dc_port_prefixes.iter().any(|p| svc_lower.starts_with(p)) {
                return true;
            }
            if dc_service_names.iter().any(|name| svc_lower.contains(name)) {
                return true;
            }
        }
        false
    }
}

/// Discovered user account.
///
/// Matches Python: `class User(Model)`
/// Redis serialization: `{"username","domain","source"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

/// Discovered credential.
///
/// Matches Python: `class Credential(Model)`
/// Redis serialization: `{"id","username","password","domain","source","parent_id","attack_step"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub attack_step: i32,
}

/// Discovered password hash.
///
/// Matches Python: `class Hash(Model)`
/// Redis serialization: `{"id","username","hash_type","hash_value","domain","source","cracked_password","discovered_at","parent_id","attack_step"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hash {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub username: String,
    pub hash_value: String,
    #[serde(default = "default_hash_type")]
    pub hash_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cracked_password: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub attack_step: i32,
    /// AES256 key for Kerberos golden tickets (Windows 2016+ rejects RC4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aes_key: Option<String>,
}

fn default_hash_type() -> String {
    "NTLM".to_string()
}

/// Discovered SMB share.
///
/// Matches Python: `class Share(Model)`
/// Redis serialization: `{"host","name","permissions","comment"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Share {
    pub host: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub permissions: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

// ============================================================================
// Multi-Agent Models
// ============================================================================

/// Specialized roles for multi-agent red team operations.
///
/// Matches Python: `class AgentRole(Enum)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Orchestrator,
    Recon,
    CredentialAccess,
    Cracker,
    Acl,
    Privesc,
    Lateral,
    Coercion,
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::Orchestrator => write!(f, "orchestrator"),
            AgentRole::Recon => write!(f, "recon"),
            AgentRole::CredentialAccess => write!(f, "credential_access"),
            AgentRole::Cracker => write!(f, "cracker"),
            AgentRole::Acl => write!(f, "acl"),
            AgentRole::Privesc => write!(f, "privesc"),
            AgentRole::Lateral => write!(f, "lateral"),
            AgentRole::Coercion => write!(f, "coercion"),
        }
    }
}

/// Status of a dispatched task.
///
/// Matches Python: `class TaskStatus(Enum)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Retrying,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "pending"),
            TaskStatus::InProgress => write!(f, "in_progress"),
            TaskStatus::Completed => write!(f, "completed"),
            TaskStatus::Failed => write!(f, "failed"),
            TaskStatus::Cancelled => write!(f, "cancelled"),
            TaskStatus::Retrying => write!(f, "retrying"),
        }
    }
}

/// Information about a dispatched task.
///
/// Matches Python: `class TaskInfo` dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub task_id: String,
    pub task_type: String,
    pub assigned_agent: String,
    #[serde(default = "default_task_status")]
    pub status: TaskStatus,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default = "chrono::Utc::now")]
    pub last_activity_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub retry_count: i32,
    #[serde(default = "default_max_retries")]
    pub max_retries: i32,
}

fn default_task_status() -> TaskStatus {
    TaskStatus::Pending
}

fn default_max_retries() -> i32 {
    3
}

/// Result of a completed task.
///
/// Matches Python: `class TaskResult` dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    pub completed_at: DateTime<Utc>,
}

/// Information about a discovered vulnerability.
///
/// Matches Python: `class VulnerabilityInfo` dataclass
/// Redis serialization: `{"vuln_id","vuln_type","target","discovered_by","discovered_at","details","recommended_agent","priority"}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub vuln_id: String,
    pub vuln_type: String,
    pub target: String,
    pub discovered_by: String,
    #[serde(default = "chrono::Utc::now")]
    pub discovered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recommended_agent: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    5
}

/// Metadata about a registered agent.
///
/// Matches Python: `class AgentInfo` dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub pod_name: String,
    pub role: AgentRole,
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub capabilities: HashSet<String>,
    #[serde(default = "default_agent_status")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_task: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    pub registered_at: DateTime<Utc>,
    #[serde(default = "chrono::Utc::now")]
    pub last_heartbeat: DateTime<Utc>,
}

fn default_agent_status() -> String {
    "idle".to_string()
}

// ============================================================================
// Task Status (from Redis ares:task_status:* keys)
// ============================================================================

/// Task status record stored in Redis `ares:task_status:*` keys.
///
/// This is the JSON format used by the task queue, distinct from TaskInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatusRecord {
    pub operation_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

// ============================================================================
// Operation Metadata (from Redis ares:op:{id}:meta HASH)
// ============================================================================

/// Operation metadata stored in the `ares:op:{id}:meta` Redis HASH.
///
/// Fields are stored as individual hash fields, not a single JSON blob.
#[derive(Debug, Clone, Default)]
pub struct OperationMeta {
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub target_ip: Option<String>,
    pub target_domain: Option<String>,
    pub target_ips: Vec<String>,
}

impl OperationMeta {
    /// Parse from a Redis HGETALL result (HashMap<String, String>).
    ///
    /// Meta values are stored by Python as `json.dumps(value)`, so:
    /// - Booleans are stored as `"true"` or `"false"` (JSON-encoded)
    /// - Strings are stored as `"\"some string\""` (double-quoted JSON)
    /// - Arrays may be stored as `"[\"ip1\",\"ip2\"]"` (JSON array)
    /// - Or as plain comma-separated values (legacy format)
    pub fn from_redis_hash(data: &HashMap<String, String>) -> Self {
        let started_at = data
            .get("started_at")
            .and_then(|s| parse_meta_datetime(s))
            .map(|dt| dt.with_timezone(&Utc));

        let completed_at = data
            .get("completed_at")
            .and_then(|s| parse_meta_datetime(s))
            .map(|dt| dt.with_timezone(&Utc));

        let target_ips = data
            .get("target_ips")
            .map(|s| parse_meta_string_list(s))
            .unwrap_or_default();

        Self {
            has_domain_admin: data
                .get("has_domain_admin")
                .map(|v| parse_meta_bool(v))
                .unwrap_or(false),
            has_golden_ticket: data
                .get("has_golden_ticket")
                .map(|v| parse_meta_bool(v))
                .unwrap_or(false),
            domain_admin_path: data
                .get("domain_admin_path")
                .and_then(|s| parse_meta_string(s)),
            started_at,
            completed_at,
            target_ip: data.get("target_ip").and_then(|s| parse_meta_string(s)),
            target_domain: data.get("target_domain").and_then(|s| parse_meta_string(s)),
            target_ips,
        }
    }
}

/// Parse a meta boolean value.
///
/// Python stores booleans via `json.dumps(True)` = `"true"`, `json.dumps(False)` = `"false"`.
/// Also handles legacy `"True"`/`"False"` and `"1"`/`"0"`.
fn parse_meta_bool(raw: &str) -> bool {
    matches!(raw, "true" | "True" | "1")
}

/// Parse a meta string value.
///
/// Python stores strings via `json.dumps("value")` = `"\"value\""` (JSON-encoded string).
/// Returns `None` for empty/null values.
fn parse_meta_string(raw: &str) -> Option<String> {
    // Try JSON-decoding first (handles `"\"quoted string\""`)
    if let Ok(serde_json::Value::String(s)) = serde_json::from_str::<serde_json::Value>(raw) {
        if s.is_empty() {
            return None;
        }
        return Some(s);
    }
    // Fall back to raw value (unquoted strings from legacy or direct writes)
    if raw.is_empty() || raw == "null" {
        return None;
    }
    Some(raw.to_string())
}

/// Parse a meta datetime value.
///
/// Python stores datetimes via `json.dumps(value, default=str)`, which produces
/// either a JSON-encoded string `"\"2025-01-28T12:00:00+00:00\""` or a bare string.
fn parse_meta_datetime(raw: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    // Try JSON-decoding first to strip outer quotes
    let s = if let Ok(serde_json::Value::String(inner)) =
        serde_json::from_str::<serde_json::Value>(raw)
    {
        inner
    } else {
        raw.to_string()
    };
    if s.is_empty() || s == "null" {
        return None;
    }
    DateTime::parse_from_rfc3339(&s)
        .ok()
        .or_else(|| s.parse().ok())
}

/// Parse a meta value that should be a list of strings.
///
/// Python may store this as:
/// - A JSON array: `'["ip1","ip2"]'` (from `json.dumps(["ip1","ip2"])`)
/// - A comma-separated string: `'"ip1,ip2"'` (from `json.dumps("ip1,ip2")`)
/// - A plain comma-separated string: `"ip1,ip2"` (legacy)
fn parse_meta_string_list(raw: &str) -> Vec<String> {
    // Try parsing as JSON array first
    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(raw) {
        return arr
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect();
    }

    // Try as JSON string (unwrap quotes), then split by comma
    let s = if let Ok(serde_json::Value::String(inner)) =
        serde_json::from_str::<serde_json::Value>(raw)
    {
        inner
    } else {
        raw.to_string()
    };

    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// Shared Red Team State (read-only view for CLI)
// ============================================================================

/// Read-only view of the shared red team state, loaded from Redis.
///
/// This matches the Python `SharedRedTeamState` dataclass but only includes
/// fields needed by the CLI (loot, status, runtime, etc.).
#[derive(Debug, Clone)]
pub struct SharedRedTeamState {
    pub operation_id: String,
    pub target: Option<Target>,
    pub target_ips: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,

    // Global discoveries
    pub all_domains: Vec<String>,
    pub all_credentials: Vec<Credential>,
    pub all_hashes: Vec<Hash>,
    pub all_hosts: Vec<Host>,
    pub all_users: Vec<User>,
    pub all_shares: Vec<Share>,
    pub all_weaknesses: Vec<String>,

    // Vulnerability registry
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,

    // Success flags
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,

    // Domain controller cache
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,
}

impl SharedRedTeamState {
    /// Create a new empty state for an operation.
    pub fn new(operation_id: String) -> Self {
        Self {
            operation_id,
            target: None,
            target_ips: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            all_domains: Vec::new(),
            all_credentials: Vec::new(),
            all_hashes: Vec::new(),
            all_hosts: Vec::new(),
            all_users: Vec::new(),
            all_shares: Vec::new(),
            all_weaknesses: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
        }
    }
}

// ============================================================================
// Blue Team Enums
// ============================================================================

/// Levels of the Pyramid of Pain.
///
/// Higher levels are harder for adversaries to change.
/// Matches Python: `class PyramidLevel(IntEnum)`
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PyramidLevel {
    HashValues = 1,
    IpAddresses = 2,
    DomainNames = 3,
    NetworkHostArtifacts = 4,
    Tools = 5,
    Ttps = 6,
}

impl std::fmt::Display for PyramidLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PyramidLevel::HashValues => write!(f, "hash_values"),
            PyramidLevel::IpAddresses => write!(f, "ip_addresses"),
            PyramidLevel::DomainNames => write!(f, "domain_names"),
            PyramidLevel::NetworkHostArtifacts => write!(f, "network_host_artifacts"),
            PyramidLevel::Tools => write!(f, "tools"),
            PyramidLevel::Ttps => write!(f, "ttps"),
        }
    }
}

/// Stages of the investigation workflow.
///
/// Matches Python: `class InvestigationStage(Enum)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStage {
    Triage,
    Causation,
    Lateral,
    Synthesis,
}

impl std::fmt::Display for InvestigationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvestigationStage::Triage => write!(f, "triage"),
            InvestigationStage::Causation => write!(f, "causation"),
            InvestigationStage::Lateral => write!(f, "lateral"),
            InvestigationStage::Synthesis => write!(f, "synthesis"),
        }
    }
}

/// Triage decisions for escalated investigations.
///
/// Matches Python: `class TriageDecision(Enum)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriageDecision {
    Pending,
    Confirmed,
    Downgraded,
    Reinvestigate,
    Routed,
}

impl std::fmt::Display for TriageDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriageDecision::Pending => write!(f, "pending"),
            TriageDecision::Confirmed => write!(f, "confirmed"),
            TriageDecision::Downgraded => write!(f, "downgraded"),
            TriageDecision::Reinvestigate => write!(f, "reinvestigate"),
            TriageDecision::Routed => write!(f, "routed"),
        }
    }
}

// ============================================================================
// Blue Team Models
// ============================================================================

/// A piece of evidence discovered during investigation.
///
/// Matches Python: `class Evidence(Model)`
/// Redis serialization: stored as JSON in evidence HASH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    /// Evidence type (ip, domain, hash, process, user, file, artifact, tool, technique).
    /// Named `evidence_type` to avoid conflict with Rust reserved word `type`.
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub value: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub pyramid_level: i32,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        alias = "mitre-techniques"
    )]
    pub mitre_techniques: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_query_id: Option<String>,
    #[serde(default)]
    pub validated: bool,
}

fn default_confidence() -> f64 {
    0.5
}

/// An event in the investigation timeline.
///
/// Matches Python: `class TimelineEvent(Model)`
/// Redis serialization: stored as JSON in timeline LIST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "evidence-ids")]
    pub evidence_ids: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        alias = "mitre-techniques"
    )]
    pub mitre_techniques: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default = "default_timeline_source")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_data_json: Option<String>,
}

fn default_timeline_source() -> String {
    "investigation".to_string()
}

/// Information about a dispatched blue team task.
///
/// Matches Python: `class BlueTaskInfo` dataclass
/// Redis serialization: stored as JSON in tasks:pending / tasks:completed HASH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueTaskInfo {
    pub task_id: String,
    pub task_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default = "default_blue_task_status")]
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn default_blue_task_status() -> String {
    "pending".to_string()
}

/// Record of a triage decision for audit trail.
///
/// Matches Python: `class TriageRecord` dataclass
/// Redis serialization: stored as JSON in triage:records LIST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRecord {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub triage_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub investigation_id: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reasoning: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routed_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub focus_areas: Vec<String>,
    #[serde(default)]
    pub reinvestigation_cycle: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Read-only view of the shared blue team state, loaded from Redis.
///
/// Matches Python: `class SharedBlueTeamState` dataclass
/// This provides the CLI with investigation state for display and reporting.
#[derive(Debug, Clone)]
pub struct SharedBlueTeamState {
    pub investigation_id: String,
    pub alert: serde_json::Value,
    pub stage: String,
    pub started_at: String,
    pub evidence: Vec<Evidence>,
    pub timeline: Vec<TimelineEvent>,
    pub identified_techniques: Vec<String>,
    pub identified_tactics: Vec<String>,
    pub technique_names: HashMap<String, String>,
    pub queried_hosts: Vec<String>,
    pub queried_users: Vec<String>,
    pub executed_query_types: Vec<String>,
    pub escalated: bool,
    pub escalation_reason: Option<String>,
    pub attack_synopsis: Option<String>,
    pub recommendations: Vec<String>,
    pub triage_decision: Option<serde_json::Value>,
    pub triage_records: Vec<TriageRecord>,
    pub pending_tasks: HashMap<String, BlueTaskInfo>,
    pub completed_tasks: HashMap<String, BlueTaskInfo>,
}

impl SharedBlueTeamState {
    /// Create a new empty state for an investigation.
    pub fn new(investigation_id: String) -> Self {
        Self {
            investigation_id,
            alert: serde_json::Value::Null,
            stage: "triage".to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            evidence: Vec::new(),
            timeline: Vec::new(),
            identified_techniques: Vec::new(),
            identified_tactics: Vec::new(),
            technique_names: HashMap::new(),
            queried_hosts: Vec::new(),
            queried_users: Vec::new(),
            executed_query_types: Vec::new(),
            escalated: false,
            escalation_reason: None,
            attack_synopsis: None,
            recommendations: Vec::new(),
            triage_decision: None,
            triage_records: Vec::new(),
            pending_tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_roundtrip() {
        // Match the exact compact JSON format used by Python state_backend
        let json = r#"{"id":"abc","username":"testuser","password":"P@ssw0rd!","domain":"contoso.local","source":"manual-inject","parent_id":null,"attack_step":0}"#; // pragma: allowlist secret
        let cred: Credential = serde_json::from_str(json).unwrap();
        assert_eq!(cred.username, "testuser");
        assert_eq!(cred.domain, "contoso.local");
        assert_eq!(cred.password, "P@ssw0rd!");
        assert_eq!(cred.attack_step, 0);
        assert!(cred.parent_id.is_none());
    }

    #[test]
    fn test_hash_roundtrip() {
        let json = r#"{"id":"def","username":"krbtgt","hash_type":"NTLM","hash_value":"aad3b435b51404ee","domain":"contoso.local","source":"secretsdump","cracked_password":null,"discovered_at":"2025-01-28T12:00:00Z","parent_id":null,"attack_step":0}"#; // pragma: allowlist secret
        let h: Hash = serde_json::from_str(json).unwrap();
        assert_eq!(h.username, "krbtgt");
        assert_eq!(h.hash_type, "NTLM");
        assert_eq!(h.domain, "contoso.local");
    }

    #[test]
    fn test_host_roundtrip() {
        let json = r#"{"ip":"192.168.58.10","hostname":"dc01.contoso.local","os":"Windows Server 2019","roles":["Domain Controller"],"services":["88/tcp kerberos","389/tcp ldap"],"is_dc":true}"#;
        let host: Host = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip, "192.168.58.10");
        assert!(host.is_dc);
        assert!(host.detect_dc());
    }

    #[test]
    fn test_user_roundtrip() {
        let json = r#"{"username":"testuser","domain":"contoso.local","source":"netexec_smb"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.domain, "contoso.local");
    }

    #[test]
    fn test_share_roundtrip() {
        let json = r#"{"host":"192.168.58.10","name":"SYSVOL","permissions":"READ","comment":""}"#;
        let share: Share = serde_json::from_str(json).unwrap();
        assert_eq!(share.name, "SYSVOL");
    }

    #[test]
    fn test_vulnerability_roundtrip() {
        let json = r#"{"vuln_id":"esc1_192.168.58.10_svc","vuln_type":"ADCS_ESC1","target":"192.168.58.10","discovered_by":"recon","discovered_at":"2025-01-28T12:00:00Z","details":{"target_ip":"192.168.58.10"},"recommended_agent":"privesc","priority":1}"#;
        let vuln: VulnerabilityInfo = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.vuln_type, "ADCS_ESC1");
        assert_eq!(vuln.priority, 1);
    }

    #[test]
    fn test_operation_meta_from_hash() {
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "True".to_string());
        data.insert("has_golden_ticket".to_string(), "false".to_string());
        data.insert(
            "started_at".to_string(),
            "2025-01-28T12:00:00+00:00".to_string(),
        );
        data.insert(
            "target_ips".to_string(),
            "192.168.58.10,192.168.58.20".to_string(),
        );

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.started_at.is_some());
        assert_eq!(meta.target_ips.len(), 2);
    }

    #[test]
    fn test_operation_meta_json_encoded() {
        // Python stores meta values via json.dumps(), so booleans become "true"/"false",
        // strings become "\"value\"", and arrays become "[\"a\",\"b\"]".
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "true".to_string());
        data.insert("has_golden_ticket".to_string(), "false".to_string());
        data.insert(
            "started_at".to_string(),
            "\"2025-01-28T12:00:00+00:00\"".to_string(),
        );
        data.insert(
            "target_ips".to_string(),
            r#"["192.168.58.10","192.168.58.20"]"#.to_string(),
        );
        data.insert("target_domain".to_string(), "\"contoso.local\"".to_string());
        data.insert("target_ip".to_string(), "\"192.168.58.10\"".to_string());
        data.insert(
            "domain_admin_path".to_string(),
            "\"secretsdump -> golden ticket\"".to_string(),
        );

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.started_at.is_some());
        assert_eq!(meta.target_ips.len(), 2);
        assert_eq!(meta.target_ips[0], "192.168.58.10");
        assert_eq!(meta.target_ips[1], "192.168.58.20");
        assert_eq!(meta.target_domain.as_deref(), Some("contoso.local"));
        assert_eq!(meta.target_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(
            meta.domain_admin_path.as_deref(),
            Some("secretsdump -> golden ticket")
        );
    }

    #[test]
    fn test_meta_null_and_empty() {
        let mut data = HashMap::new();
        data.insert("target_domain".to_string(), "null".to_string());
        data.insert("target_ip".to_string(), "\"\"".to_string());
        data.insert("domain_admin_path".to_string(), "".to_string());

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.target_domain.is_none());
        assert!(meta.target_ip.is_none());
        assert!(meta.domain_admin_path.is_none());
    }

    #[test]
    fn test_task_status_display() {
        assert_eq!(TaskStatus::InProgress.to_string(), "in_progress");
        assert_eq!(TaskStatus::Pending.to_string(), "pending");
    }
}
