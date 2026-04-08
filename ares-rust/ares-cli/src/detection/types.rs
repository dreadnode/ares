use std::collections::HashMap;

#[derive(serde::Serialize)]
pub(crate) struct DetectionPlaybook {
    pub operation_id: String,
    pub generated_at: String,
    pub attack_window: AttackWindow,
    pub summary: PlaybookSummary,
    pub executive_summary: String,
    pub technique_detections: HashMap<String, TechniqueDetection>,
    pub detection_targets: Vec<DetectionTarget>,
    pub priority_queries: Vec<PlaybookQuery>,
}

#[derive(serde::Serialize)]
pub(crate) struct AttackWindow {
    pub start: String,
    pub end: String,
    pub duration_minutes: i64,
}

#[derive(serde::Serialize)]
pub(crate) struct PlaybookSummary {
    pub techniques_used: Vec<String>,
    pub technique_count: usize,
    pub total_credentials: usize,
    pub total_hosts: usize,
    pub achieved_domain_admin: bool,
    pub domain_admin_path: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct PlaybookQuery {
    pub technique_id: String,
    pub technique_name: String,
    pub description: String,
    pub logql: String,
    pub label_selector: String,
    pub expected_evidence: Vec<String>,
    pub time_window: TimeWindow,
    pub priority: String,
    pub windows_event_ids: Vec<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct TimeWindow {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct DetectionTarget {
    pub ioc_type: String,
    pub value: String,
    pub pyramid_level: u8,
    pub pyramid_level_name: String,
    pub context: String,
    pub detection_queries: Vec<String>,
    pub log_sources: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct TechniqueDetection {
    pub technique_id: String,
    pub technique_name: String,
    pub description: String,
    pub occurred_at: Vec<String>,
    pub targets: Vec<String>,
    pub credentials_used: Vec<String>,
    pub detection_queries: Vec<PlaybookQuery>,
    pub windows_event_ids: Vec<String>,
    pub log_sources: Vec<String>,
    pub detection_guidance: String,
}
