//! Template context structs for blue team reports.

use std::collections::HashMap;

use serde::Serialize;

/// Template context structures for blue team reports.
#[derive(Serialize)]
pub struct BlueTeamAlertSummary {
    pub investigation_id_short: String,
    pub alert_name: String,
    pub severity: String,
    pub evidence_count: usize,
    pub highest_pyramid_level: i32,
    pub status_display: String,
    pub techniques: Vec<String>,
}

#[derive(Serialize)]
pub struct BlueTeamTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Serialize)]
pub struct PyramidEntry {
    pub level: i32,
    pub category: String,
    pub count: i32,
    pub pain: String,
}

#[derive(Serialize)]
pub struct BlueTeamEvidenceItem {
    pub id_short: String,
    #[serde(rename = "type")]
    pub ev_type: String,
    pub value: String,
    pub techniques_display: String,
    pub confidence_display: String,
}

#[derive(Serialize)]
pub struct BlueTeamEvidenceLevel {
    pub level: i32,
    pub name: String,
    pub evidence: Vec<BlueTeamEvidenceItem>,
}

#[derive(Serialize)]
pub struct BlueTeamInvestigationDetail {
    pub investigation_id: String,
    pub alert_name: String,
    pub severity: String,
    pub status: String,
    pub evidence_count: usize,
    pub techniques_display: String,
    pub alert_payload: String,
    pub queries: Vec<serde_json::Value>,
    pub queries_display: Vec<serde_json::Value>,
    pub extra_query_count: usize,
}

/// Input data for blue team report generation.
///
/// Since we don't have full blue team state models in Rust yet, this struct
/// provides a data-transfer object that the CLI can populate from Redis.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BlueTeamReportInput {
    pub operation_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration: String,
    pub investigation_count: usize,
    pub alert_count: usize,
    pub evidence_count: usize,
    pub technique_count: usize,
    pub tactic_count: usize,
    pub host_count: usize,
    pub user_count: usize,
    pub highest_pyramid_level: i32,
    pub ttp_count: usize,
    pub escalation_count: usize,
    pub attack_synopses: Vec<String>,
    pub alert_summaries: Vec<serde_json::Value>,
    pub evidence_by_level: HashMap<i32, Vec<serde_json::Value>>,
    pub timeline: Vec<serde_json::Value>,
    pub techniques: Vec<serde_json::Value>,
    pub tactics: Vec<String>,
    pub hosts: Vec<String>,
    pub users: Vec<String>,
    pub recommendations: Vec<String>,
    pub investigation_details: Vec<serde_json::Value>,
    pub pyramid_distribution: HashMap<i32, i32>,
}
