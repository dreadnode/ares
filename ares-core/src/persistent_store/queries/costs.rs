//! Cost queries and retention policy enforcement.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use tracing::info;

use super::rows::CostRow;
use super::HistoricalQueryService;

impl HistoricalQueryService {
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
