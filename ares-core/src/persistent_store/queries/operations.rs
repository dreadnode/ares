//! Operation-level queries: list and report retrieval.

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::rows::{OperationRow, OperationSummary};
use super::HistoricalQueryService;

impl HistoricalQueryService {
    /// List operations with optional filters.
    pub async fn list_operations(
        &self,
        domain: Option<&str>,
        has_da: Option<bool>,
        since: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<OperationSummary>> {
        let rows = match (domain, has_da, since) {
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
}
