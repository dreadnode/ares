//! Blue team models: PyramidLevel, InvestigationStage, Evidence, etc.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::util::{default_blue_task_status, default_confidence, default_timeline_source};

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
