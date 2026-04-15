//! Row types and public DTOs for historical query results.

use chrono::{DateTime, Utc};
use serde_json;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OperationRow {
    pub id: Uuid,
    pub operation_id: String,
    pub target_domain: Option<String>,
    pub target_ip: Option<String>,
    pub environment: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,
    pub credential_count: Option<i32>,
    pub hash_count: Option<i32>,
    pub host_count: Option<i32>,
    pub vulnerability_count: Option<i32>,
    pub exploited_vulnerability_count: Option<i32>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: Uuid,
    pub operation_id: String,
    pub username: String,
    pub domain: Option<String>,
    pub is_admin: bool,
    pub source: Option<String>,
    pub attack_step: i32,
    pub discovered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HashRow {
    pub id: Uuid,
    pub operation_id: String,
    pub username: String,
    pub domain: Option<String>,
    pub hash_type: Option<String>,
    pub is_cracked: Option<bool>,
    pub source: Option<String>,
    pub attack_step: i32,
    pub discovered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct MitreTechniqueRow {
    pub mitre_techniques: Option<Vec<String>>,
    pub operation_id: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CostRow {
    pub operation_id: String,
    pub target_domain: Option<String>,
    pub started_at: DateTime<Utc>,
    pub total_input_tokens: Option<i64>,
    pub total_output_tokens: Option<i64>,
    pub total_cost: Option<f64>,
    pub model_usage: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct OperationSummary {
    pub id: Uuid,
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
    pub exploited_vulnerability_count: i32,
    pub duration_seconds: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct MitreCoverage {
    pub technique_id: String,
    pub occurrence_count: usize,
    pub operations: Vec<String>,
}
