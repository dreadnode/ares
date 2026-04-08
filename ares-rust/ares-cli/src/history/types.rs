use chrono::{DateTime, Utc};

#[derive(sqlx::FromRow)]
pub(crate) struct OperationRow {
    pub operation_id: String,
    pub target_domain: Option<String>,
    pub target_ip: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub credential_count: i32,
    pub hash_count: i32,
    pub host_count: i32,
    pub vulnerability_count: i32,
}

#[derive(sqlx::FromRow)]
pub(crate) struct OperationDetailRow {
    pub operation_id: String,
    pub target_domain: Option<String>,
    pub target_ip: Option<String>,
    pub environment: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,
    pub credential_count: i32,
    pub hash_count: i32,
    pub host_count: i32,
    pub vulnerability_count: i32,
}

#[derive(sqlx::FromRow)]
pub(crate) struct CredentialSearchRow {
    pub username: String,
    pub domain: Option<String>,
    pub is_admin: bool,
    pub source: Option<String>,
    #[allow(dead_code)]
    pub attack_step: Option<i32>,
    pub operation_id: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct HashSearchRow {
    pub username: String,
    pub domain: Option<String>,
    pub hash_type: Option<String>,
    pub is_cracked: Option<bool>,
    #[allow(dead_code)]
    pub source: Option<String>,
    pub operation_id: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct CostRow {
    pub operation_id: String,
    pub target_domain: Option<String>,
    pub started_at: DateTime<Utc>,
    pub total_input_tokens: Option<i64>,
    pub total_output_tokens: Option<i64>,
    pub total_cost: Option<f64>,
    pub model_usage: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct MitreCoverageRow {
    pub mitre_techniques: Vec<String>,
    pub operation_id: String,
}
