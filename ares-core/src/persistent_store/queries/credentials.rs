//! Credential and hash search queries across all operations.

use anyhow::Result;

use super::rows::{CredentialRow, HashRow};
use super::HistoricalQueryService;

impl HistoricalQueryService {
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
}
