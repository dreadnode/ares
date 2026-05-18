//! Blue team models: PyramidLevel, InvestigationStage, Evidence, etc.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::util::{default_blue_task_status, default_confidence, default_timeline_source};

/// Levels of the Pyramid of Pain.
///
/// Higher levels are harder for adversaries to change.
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
/// Provides the CLI with investigation state for display and reporting.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─── PyramidLevel ────────────────────────────────────────────────────

    #[test]
    fn pyramid_level_display() {
        assert_eq!(PyramidLevel::HashValues.to_string(), "hash_values");
        assert_eq!(PyramidLevel::IpAddresses.to_string(), "ip_addresses");
        assert_eq!(PyramidLevel::DomainNames.to_string(), "domain_names");
        assert_eq!(
            PyramidLevel::NetworkHostArtifacts.to_string(),
            "network_host_artifacts"
        );
        assert_eq!(PyramidLevel::Tools.to_string(), "tools");
        assert_eq!(PyramidLevel::Ttps.to_string(), "ttps");
    }

    #[test]
    fn pyramid_level_values() {
        assert_eq!(PyramidLevel::HashValues as i32, 1);
        assert_eq!(PyramidLevel::Ttps as i32, 6);
    }

    // ─── InvestigationStage ──────────────────────────────────────────────

    #[test]
    fn investigation_stage_display() {
        assert_eq!(InvestigationStage::Triage.to_string(), "triage");
        assert_eq!(InvestigationStage::Causation.to_string(), "causation");
        assert_eq!(InvestigationStage::Lateral.to_string(), "lateral");
        assert_eq!(InvestigationStage::Synthesis.to_string(), "synthesis");
    }

    #[test]
    fn investigation_stage_serde() {
        let stage = InvestigationStage::Causation;
        let json_str = serde_json::to_string(&stage).unwrap();
        assert_eq!(json_str, r#""causation""#);
        let back: InvestigationStage = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back, InvestigationStage::Causation);
    }

    // ─── TriageDecision ──────────────────────────────────────────────────

    #[test]
    fn triage_decision_display() {
        assert_eq!(TriageDecision::Pending.to_string(), "pending");
        assert_eq!(TriageDecision::Confirmed.to_string(), "confirmed");
        assert_eq!(TriageDecision::Downgraded.to_string(), "downgraded");
        assert_eq!(TriageDecision::Reinvestigate.to_string(), "reinvestigate");
        assert_eq!(TriageDecision::Routed.to_string(), "routed");
    }

    #[test]
    fn triage_decision_serde() {
        let d = TriageDecision::Confirmed;
        let json_str = serde_json::to_string(&d).unwrap();
        assert_eq!(json_str, r#""confirmed""#);
        let back: TriageDecision = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back, TriageDecision::Confirmed);
    }

    // ─── Evidence serde ──────────────────────────────────────────────────

    #[test]
    fn evidence_deserialize_minimal() {
        let j = json!({
            "id": "ev-001",
            "type": "ip",
            "value": "192.168.58.10",
            "source": "nmap"
        });
        let ev: Evidence = serde_json::from_value(j).unwrap();
        assert_eq!(ev.id, "ev-001");
        assert_eq!(ev.evidence_type, "ip");
        assert_eq!(ev.value, "192.168.58.10");
        assert_eq!(ev.confidence, 0.5); // default
        assert!(!ev.validated);
        assert!(ev.mitre_techniques.is_empty());
    }

    #[test]
    fn evidence_type_rename() {
        let j = json!({
            "id": "ev-002",
            "type": "technique",
            "value": "T1046",
            "source": "detection",
            "mitre_techniques": ["T1046"],
            "confidence": 0.9,
            "validated": true
        });
        let ev: Evidence = serde_json::from_value(j).unwrap();
        assert_eq!(ev.evidence_type, "technique");
        assert_eq!(ev.confidence, 0.9);
        assert!(ev.validated);
        assert_eq!(ev.mitre_techniques, vec!["T1046"]);
    }

    // ─── BlueTaskInfo serde ──────────────────────────────────────────────

    #[test]
    fn blue_task_info_defaults() {
        let j = json!({
            "task_id": "bt-001",
            "task_type": "query_logs"
        });
        let info: BlueTaskInfo = serde_json::from_value(j).unwrap();
        assert_eq!(info.task_id, "bt-001");
        assert_eq!(info.status, "pending"); // default
        assert!(info.completed_at.is_none());
        assert!(info.result.is_none());
        assert!(info.error.is_none());
    }

    // ─── SharedBlueTeamState::new ────────────────────────────────────────

    #[test]
    fn shared_blue_team_state_new() {
        let state = SharedBlueTeamState::new("inv-001".to_string());
        assert_eq!(state.investigation_id, "inv-001");
        assert_eq!(state.stage, "triage");
        assert!(!state.escalated);
        assert!(state.evidence.is_empty());
        assert!(state.timeline.is_empty());
        assert!(state.recommendations.is_empty());
        assert!(state.attack_synopsis.is_none());
        assert!(state.triage_decision.is_none());
    }

    // ─── TriageRecord serde ──────────────────────────────────────────────

    #[test]
    fn triage_record_deserialize() {
        let j = json!({
            "decision": "confirmed",
            "reasoning": "Multiple IOCs match known attack pattern",
            "confidence": 0.95,
            "focus_areas": ["lateral_movement", "credential_access"]
        });
        let record: TriageRecord = serde_json::from_value(j).unwrap();
        assert_eq!(record.decision, "confirmed");
        assert_eq!(record.confidence, 0.95);
        assert_eq!(record.focus_areas.len(), 2);
        assert!(record.routed_to.is_none());
        assert_eq!(record.reinvestigation_cycle, 0);
    }
}
