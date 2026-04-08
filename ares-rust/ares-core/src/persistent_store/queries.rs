//! Historical query service for persistent data store.
//!
//! Provides read-only query methods for analyzing historical operation data,
//! cross-operation credential/hash search, MITRE coverage analysis, and
//! retention policy enforcement.

use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

// ============================================================================
// Row types (sqlx::FromRow)
// ============================================================================

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
struct MitreTechniqueRow {
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

// ============================================================================
// Result types
// ============================================================================

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

// ============================================================================
// HistoricalQueryService
// ============================================================================

/// Service for querying historical operation data.
///
/// Provides cross-operation search, MITRE coverage analysis,
/// and retention policy enforcement.
#[derive(Clone)]
pub struct HistoricalQueryService {
    pool: PgPool,
}

impl HistoricalQueryService {
    /// Create from an existing connection pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect to PostgreSQL.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL")?;
        Ok(Self { pool })
    }

    // =========================================================================
    // Operation Queries
    // =========================================================================

    /// List operations with optional filters.
    pub async fn list_operations(
        &self,
        domain: Option<&str>,
        has_da: Option<bool>,
        since: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<OperationSummary>> {
        // Build query dynamically
        let mut sql = String::from(
            "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                    environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                    domain_admin_path,
                    COALESCE(credential_count, 0) as credential_count,
                    COALESCE(hash_count, 0) as hash_count,
                    COALESCE(host_count, 0) as host_count,
                    COALESCE(vulnerability_count, 0) as vulnerability_count,
                    COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
             FROM operations WHERE 1=1",
        );

        let mut param_idx = 1u32;
        let mut bind_domain = None;
        let mut bind_has_da = None;
        let mut bind_since = None;

        if let Some(d) = domain {
            param_idx += 1;
            sql.push_str(&format!(" AND target_domain ILIKE ${param_idx}"));
            bind_domain = Some(format!("%{d}%"));
        }

        if let Some(da) = has_da {
            param_idx += 1;
            sql.push_str(&format!(" AND has_domain_admin = ${param_idx}"));
            bind_has_da = Some(da);
        }

        if let Some(s) = since {
            param_idx += 1;
            sql.push_str(&format!(" AND started_at >= ${param_idx}"));
            bind_since = Some(s);
        }

        sql.push_str(" ORDER BY started_at DESC LIMIT $1");

        // We need to build the query with the right number of binds.
        // Using a simpler approach with conditional queries.
        let rows = match (bind_domain.as_deref(), bind_has_da, bind_since) {
            (None, None, None) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations ORDER BY started_at DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), None, None) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE target_domain ILIKE $1
                     ORDER BY started_at DESC LIMIT $2",
                )
                .bind(format!("%{d}%"))
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(da), None) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE has_domain_admin = $1
                     ORDER BY started_at DESC LIMIT $2",
                )
                .bind(da)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), Some(da), None) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE target_domain ILIKE $1 AND has_domain_admin = $2
                     ORDER BY started_at DESC LIMIT $3",
                )
                .bind(format!("%{d}%"))
                .bind(da)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, None, Some(s)) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE started_at >= $1
                     ORDER BY started_at DESC LIMIT $2",
                )
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), None, Some(s)) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE target_domain ILIKE $1 AND started_at >= $2
                     ORDER BY started_at DESC LIMIT $3",
                )
                .bind(format!("%{d}%"))
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(da), Some(s)) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE has_domain_admin = $1 AND started_at >= $2
                     ORDER BY started_at DESC LIMIT $3",
                )
                .bind(da)
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), Some(da), Some(s)) => {
                sqlx::query_as::<_, OperationRow>(
                    "SELECT id, operation_id, target_domain, target_ip::text as target_ip,
                            environment, started_at, completed_at, has_domain_admin, has_golden_ticket,
                            domain_admin_path,
                            COALESCE(credential_count, 0) as credential_count,
                            COALESCE(hash_count, 0) as hash_count,
                            COALESCE(host_count, 0) as host_count,
                            COALESCE(vulnerability_count, 0) as vulnerability_count,
                            COALESCE(exploited_vulnerability_count, 0) as exploited_vulnerability_count
                     FROM operations WHERE target_domain ILIKE $1 AND has_domain_admin = $2
                            AND started_at >= $3
                     ORDER BY started_at DESC LIMIT $4",
                )
                .bind(format!("%{d}%"))
                .bind(da)
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows
            .into_iter()
            .map(|r| {
                let duration = if let Some(completed) = r.completed_at {
                    Some((completed - r.started_at).num_seconds() as f64)
                } else {
                    Some((Utc::now() - r.started_at).num_seconds() as f64)
                };
                OperationSummary {
                    id: r.id,
                    operation_id: r.operation_id,
                    target_domain: r.target_domain,
                    target_ip: r.target_ip,
                    started_at: r.started_at,
                    completed_at: r.completed_at,
                    has_domain_admin: r.has_domain_admin,
                    has_golden_ticket: r.has_golden_ticket,
                    credential_count: r.credential_count.unwrap_or(0),
                    hash_count: r.hash_count.unwrap_or(0),
                    host_count: r.host_count.unwrap_or(0),
                    vulnerability_count: r.vulnerability_count.unwrap_or(0),
                    exploited_vulnerability_count: r.exploited_vulnerability_count.unwrap_or(0),
                    duration_seconds: duration,
                }
            })
            .collect())
    }

    /// Get a single operation's report.
    pub async fn get_operation_report(&self, operation_id: &str) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT final_report FROM operations WHERE operation_id = $1")
                .bind(operation_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.and_then(|r| r.0))
    }

    // =========================================================================
    // Credential/Hash Search
    // =========================================================================

    /// Search credentials across all operations.
    pub async fn search_credentials(
        &self,
        domain: Option<&str>,
        username: Option<&str>,
        is_admin: Option<bool>,
        limit: i64,
    ) -> Result<Vec<CredentialRow>> {
        let rows = match (domain, username, is_admin) {
            (None, None, None) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     ORDER BY c.created_at DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), None, None) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE LOWER(c.domain) = LOWER($1)
                     ORDER BY c.created_at DESC LIMIT $2",
                )
                .bind(d)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(u), None) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE c.username ILIKE $1
                     ORDER BY c.created_at DESC LIMIT $2",
                )
                .bind(format!("%{u}%"))
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), Some(u), None) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE LOWER(c.domain) = LOWER($1) AND c.username ILIKE $2
                     ORDER BY c.created_at DESC LIMIT $3",
                )
                .bind(d)
                .bind(format!("%{u}%"))
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, None, Some(admin)) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE c.is_admin = $1
                     ORDER BY c.created_at DESC LIMIT $2",
                )
                .bind(admin)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), None, Some(admin)) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE LOWER(c.domain) = LOWER($1) AND c.is_admin = $2
                     ORDER BY c.created_at DESC LIMIT $3",
                )
                .bind(d)
                .bind(admin)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(u), Some(admin)) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE c.username ILIKE $1 AND c.is_admin = $2
                     ORDER BY c.created_at DESC LIMIT $3",
                )
                .bind(format!("%{u}%"))
                .bind(admin)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), Some(u), Some(admin)) => {
                sqlx::query_as::<_, CredentialRow>(
                    "SELECT c.id, o.operation_id, c.username, c.domain, c.is_admin,
                            c.source, c.attack_step, c.discovered_at
                     FROM credentials c JOIN operations o ON c.operation_id = o.id
                     WHERE LOWER(c.domain) = LOWER($1) AND c.username ILIKE $2 AND c.is_admin = $3
                     ORDER BY c.created_at DESC LIMIT $4",
                )
                .bind(d)
                .bind(format!("%{u}%"))
                .bind(admin)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows)
    }

    /// Search hashes across all operations.
    pub async fn search_hashes(
        &self,
        domain: Option<&str>,
        username: Option<&str>,
        hash_type: Option<&str>,
        cracked_only: bool,
        limit: i64,
    ) -> Result<Vec<HashRow>> {
        // Base query with computed is_cracked
        let base = "SELECT h.id, o.operation_id, h.username, h.domain, h.hash_type,
                           (h.cracked_password_hash IS NOT NULL) as is_cracked,
                           h.source, h.attack_step, h.discovered_at
                    FROM hashes h JOIN operations o ON h.operation_id = o.id";

        let mut conditions = Vec::new();
        if domain.is_some() {
            conditions.push("LOWER(h.domain) = LOWER($1)");
        }
        if username.is_some() {
            let idx = conditions.len() + 1;
            conditions.push(if idx == 1 {
                "h.username ILIKE $1"
            } else {
                "h.username ILIKE $2"
            });
        }
        if hash_type.is_some() {
            let idx = conditions.len() + 1;
            match idx {
                1 => conditions.push("LOWER(h.hash_type) = LOWER($1)"),
                2 => conditions.push("LOWER(h.hash_type) = LOWER($2)"),
                _ => conditions.push("LOWER(h.hash_type) = LOWER($3)"),
            }
        }
        if cracked_only {
            conditions.push("h.cracked_password_hash IS NOT NULL");
        }

        // Simpler approach: just handle the common cases
        let rows = if domain.is_none() && username.is_none() && hash_type.is_none() {
            if cracked_only {
                sqlx::query_as::<_, HashRow>(
                    "SELECT h.id, o.operation_id, h.username, h.domain, h.hash_type,
                            (h.cracked_password_hash IS NOT NULL) as is_cracked,
                            h.source, h.attack_step, h.discovered_at
                     FROM hashes h JOIN operations o ON h.operation_id = o.id
                     WHERE h.cracked_password_hash IS NOT NULL
                     ORDER BY h.created_at DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            } else {
                sqlx::query_as::<_, HashRow>(
                    "SELECT h.id, o.operation_id, h.username, h.domain, h.hash_type,
                            (h.cracked_password_hash IS NOT NULL) as is_cracked,
                            h.source, h.attack_step, h.discovered_at
                     FROM hashes h JOIN operations o ON h.operation_id = o.id
                     ORDER BY h.created_at DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        } else {
            // Build WHERE clause dynamically
            let mut where_parts = Vec::new();
            let mut bind_values: Vec<String> = Vec::new();

            if let Some(d) = domain {
                bind_values.push(d.to_string());
                where_parts.push(format!("LOWER(h.domain) = LOWER(${})", bind_values.len()));
            }
            if let Some(u) = username {
                bind_values.push(format!("%{u}%"));
                where_parts.push(format!("h.username ILIKE ${}", bind_values.len()));
            }
            if let Some(ht) = hash_type {
                bind_values.push(ht.to_string());
                where_parts.push(format!(
                    "LOWER(h.hash_type) = LOWER(${})",
                    bind_values.len()
                ));
            }
            if cracked_only {
                where_parts.push("h.cracked_password_hash IS NOT NULL".to_string());
            }

            let limit_idx = bind_values.len() + 1;
            let sql = format!(
                "{base} WHERE {} ORDER BY h.created_at DESC LIMIT ${limit_idx}",
                where_parts.join(" AND ")
            );

            // Bind dynamically — sqlx doesn't support dynamic binds easily,
            // so we use query_scalar pattern with explicit bind count
            match bind_values.len() {
                1 => {
                    sqlx::query_as::<_, HashRow>(&sql)
                        .bind(&bind_values[0])
                        .bind(limit)
                        .fetch_all(&self.pool)
                        .await?
                }
                2 => {
                    sqlx::query_as::<_, HashRow>(&sql)
                        .bind(&bind_values[0])
                        .bind(&bind_values[1])
                        .bind(limit)
                        .fetch_all(&self.pool)
                        .await?
                }
                3 => {
                    sqlx::query_as::<_, HashRow>(&sql)
                        .bind(&bind_values[0])
                        .bind(&bind_values[1])
                        .bind(&bind_values[2])
                        .bind(limit)
                        .fetch_all(&self.pool)
                        .await?
                }
                _ => Vec::new(),
            }
        };

        Ok(rows)
    }

    // =========================================================================
    // MITRE Coverage Analysis
    // =========================================================================

    /// Get MITRE ATT&CK technique coverage across operations.
    pub async fn get_mitre_coverage(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<MitreCoverage>> {
        let rows = if let Some(s) = since {
            sqlx::query_as::<_, MitreTechniqueRow>(
                "SELECT te.mitre_techniques, o.operation_id
                 FROM timeline_events te JOIN operations o ON te.operation_id = o.id
                 WHERE te.mitre_techniques IS NOT NULL
                   AND array_length(te.mitre_techniques, 1) > 0
                   AND o.started_at >= $1",
            )
            .bind(s)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, MitreTechniqueRow>(
                "SELECT te.mitre_techniques, o.operation_id
                 FROM timeline_events te JOIN operations o ON te.operation_id = o.id
                 WHERE te.mitre_techniques IS NOT NULL
                   AND array_length(te.mitre_techniques, 1) > 0",
            )
            .fetch_all(&self.pool)
            .await?
        };

        // Aggregate by technique
        let mut technique_ops: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            if let Some(techniques) = row.mitre_techniques {
                for t in techniques {
                    technique_ops
                        .entry(t)
                        .or_default()
                        .push(row.operation_id.clone());
                }
            }
        }

        // Deduplicate operations per technique
        let mut result: Vec<MitreCoverage> = technique_ops
            .into_iter()
            .map(|(technique_id, mut ops)| {
                ops.sort();
                ops.dedup();
                let occurrence_count = ops.len();
                MitreCoverage {
                    technique_id,
                    occurrence_count,
                    operations: ops,
                }
            })
            .collect();

        // Sort by occurrence count descending
        result.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));

        Ok(result)
    }

    // =========================================================================
    // Cost Queries
    // =========================================================================

    /// Get cost data for operations.
    pub async fn get_costs(
        &self,
        domain: Option<&str>,
        since: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<CostRow>> {
        let rows = match (domain, since) {
            (None, None) => {
                sqlx::query_as::<_, CostRow>(
                    "SELECT operation_id, target_domain, started_at,
                            total_input_tokens, total_output_tokens, total_cost, model_usage
                     FROM operations
                     WHERE total_cost IS NOT NULL
                     ORDER BY started_at DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), None) => {
                sqlx::query_as::<_, CostRow>(
                    "SELECT operation_id, target_domain, started_at,
                            total_input_tokens, total_output_tokens, total_cost, model_usage
                     FROM operations
                     WHERE total_cost IS NOT NULL AND target_domain ILIKE $1
                     ORDER BY started_at DESC LIMIT $2",
                )
                .bind(format!("%{d}%"))
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(s)) => {
                sqlx::query_as::<_, CostRow>(
                    "SELECT operation_id, target_domain, started_at,
                            total_input_tokens, total_output_tokens, total_cost, model_usage
                     FROM operations
                     WHERE total_cost IS NOT NULL AND started_at >= $1
                     ORDER BY started_at DESC LIMIT $2",
                )
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(d), Some(s)) => {
                sqlx::query_as::<_, CostRow>(
                    "SELECT operation_id, target_domain, started_at,
                            total_input_tokens, total_output_tokens, total_cost, model_usage
                     FROM operations
                     WHERE total_cost IS NOT NULL AND target_domain ILIKE $1 AND started_at >= $2
                     ORDER BY started_at DESC LIMIT $3",
                )
                .bind(format!("%{d}%"))
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows)
    }

    // =========================================================================
    // Retention/Cleanup
    // =========================================================================

    /// Apply retention policies to delete old data.
    ///
    /// - Operations without DA: deleted after `default_days`
    /// - Operations with DA: deleted after `da_days` (longer retention)
    ///
    /// Returns count of deleted operations.
    pub async fn apply_retention_policy(&self, default_days: i64, da_days: i64) -> Result<i64> {
        let now = Utc::now();
        let mut total_deleted = 0i64;

        // Delete old operations without DA
        let cutoff = now - Duration::days(default_days);
        let result = sqlx::query(
            "DELETE FROM operations WHERE started_at < $1 AND has_domain_admin = false",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        total_deleted += result.rows_affected() as i64;

        // Delete old DA operations (longer retention)
        let da_cutoff = now - Duration::days(da_days);
        let result =
            sqlx::query("DELETE FROM operations WHERE started_at < $1 AND has_domain_admin = true")
                .bind(da_cutoff)
                .execute(&self.pool)
                .await?;
        total_deleted += result.rows_affected() as i64;

        if total_deleted > 0 {
            info!(deleted = total_deleted, "Applied retention policy");
        }

        Ok(total_deleted)
    }
}
