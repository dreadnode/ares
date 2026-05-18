//! Persistent store for offloading operation data to PostgreSQL.
//!
//! Provides the write path for persisting operation data from Redis (hot storage)
//! to PostgreSQL (long-term storage). Supports full operation offload on completion
//! and incremental sync during operation.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{Credential, Hash, Host, User, VulnerabilityInfo};

use super::config::PersistentStoreConfig;

/// Async PostgreSQL store for long-term operation data.
///
/// Uses sqlx with a connection pool. Thread-safe — cloneable and shareable.
#[derive(Clone)]
pub struct PersistentStore {
    pool: PgPool,
}

impl PersistentStore {
    /// Create a new persistent store from a connection pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect to PostgreSQL using a [`PersistentStoreConfig`].
    ///
    /// The config must have `database_url` set (i.e. `is_enabled()` must be true).
    /// Pool size and timeout are taken from the config rather than hardcoded.
    pub async fn from_config(config: &PersistentStoreConfig) -> Result<Self> {
        let database_url = config
            .database_url
            .as_deref()
            .context("database_url is required but not set")?;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .min_connections(config.pool_min_size)
            .max_connections(config.pool_max_size)
            .acquire_timeout(config.pool_timeout())
            .connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL")?;

        info!("Persistent store connected to PostgreSQL (from config)");
        Ok(Self { pool })
    }

    /// Connect to PostgreSQL and create a new persistent store.
    ///
    /// Uses hardcoded pool defaults. Prefer [`from_config`](Self::from_config)
    /// for configurable pool settings.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL")?;
        info!("Persistent store connected to PostgreSQL");
        Ok(Self { pool })
    }

    /// Run the schema migration (create tables if they don't exist).
    pub async fn migrate(&self) -> Result<()> {
        let schema = include_str!("schema.sql");
        sqlx::raw_sql(schema)
            .execute(&self.pool)
            .await
            .context("Failed to run schema migration")?;
        info!("Persistent store schema migrated");
        Ok(())
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // Full Operation Offload
    // =========================================================================

    /// Offload complete operation state to PostgreSQL.
    ///
    /// This is the main entry point for persisting an operation, typically
    /// called on operation completion. All upserts run in a single transaction.
    pub async fn offload_operation(&self, state: &OperationOffload) -> Result<bool> {
        let mut tx = self.pool.begin().await?;

        // Upsert operation record
        let op_uuid = self.upsert_operation(&mut tx, state).await?;

        // Batch upsert all collections
        self.upsert_credentials(&mut tx, op_uuid, &state.credentials)
            .await?;
        self.upsert_hashes(&mut tx, op_uuid, &state.hashes).await?;
        self.upsert_hosts(&mut tx, op_uuid, &state.hosts).await?;
        self.upsert_users(&mut tx, op_uuid, &state.users).await?;
        self.upsert_vulnerabilities(
            &mut tx,
            op_uuid,
            &state.vulnerabilities,
            &state.exploited_vulnerabilities,
        )
        .await?;

        // Update aggregated stats
        sqlx::query(
            "UPDATE operations SET
                credential_count = $2,
                hash_count = $3,
                host_count = $4,
                vulnerability_count = $5,
                exploited_vulnerability_count = $6
             WHERE id = $1",
        )
        .bind(op_uuid)
        .bind(state.credentials.len() as i32)
        .bind(state.hashes.len() as i32)
        .bind(state.hosts.len() as i32)
        .bind(state.vulnerabilities.len() as i32)
        .bind(state.exploited_vulnerabilities.len() as i32)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        info!(
            operation_id = %state.operation_id,
            creds = state.credentials.len(),
            hashes = state.hashes.len(),
            hosts = state.hosts.len(),
            "Offloaded operation to persistent store"
        );

        Ok(true)
    }

    async fn upsert_operation(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        state: &OperationOffload,
    ) -> Result<Uuid> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO operations (operation_id, target_ip, target_domain, environment,
                                     started_at, completed_at, has_domain_admin, has_golden_ticket,
                                     domain_admin_path, da_hash_id)
             VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (operation_id) DO UPDATE SET
                completed_at = EXCLUDED.completed_at,
                has_domain_admin = EXCLUDED.has_domain_admin,
                has_golden_ticket = EXCLUDED.has_golden_ticket,
                domain_admin_path = EXCLUDED.domain_admin_path,
                da_hash_id = EXCLUDED.da_hash_id
             RETURNING id",
        )
        .bind(&state.operation_id)
        .bind(&state.target_ip)
        .bind(&state.target_domain)
        .bind(&state.environment)
        .bind(state.started_at)
        .bind(state.completed_at)
        .bind(state.has_domain_admin)
        .bind(state.has_golden_ticket)
        .bind(&state.domain_admin_path)
        .bind(&state.da_hash_id)
        .fetch_one(&mut **tx)
        .await
        .context("Failed to upsert operation")?;

        Ok(row.0)
    }

    async fn upsert_credentials(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        operation_uuid: Uuid,
        credentials: &[Credential],
    ) -> Result<()> {
        for cred in credentials {
            let password_hash = if cred.password.is_empty() {
                None
            } else {
                Some(sha256_prefix(&cred.password, 16))
            };

            let domain = if cred.domain.is_empty() {
                None
            } else {
                Some(cred.domain.as_str())
            };

            let source = if cred.source.is_empty() {
                None
            } else {
                Some(cred.source.as_str())
            };

            sqlx::query(
                "INSERT INTO credentials (operation_id, credential_id, username, domain,
                                          password_hash, is_admin, source, attack_step, discovered_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT ON CONSTRAINT uq_cred DO NOTHING",
            )
            .bind(operation_uuid)
            .bind(&cred.id)
            .bind(&cred.username)
            .bind(domain)
            .bind(password_hash.as_deref())
            .bind(cred.is_admin)
            .bind(source)
            .bind(cred.attack_step)
            .bind(cred.discovered_at)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn upsert_hashes(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        operation_uuid: Uuid,
        hashes: &[Hash],
    ) -> Result<()> {
        for h in hashes {
            let hash_prefix = if h.hash_value.is_empty() {
                None
            } else {
                Some(&h.hash_value[..h.hash_value.len().min(64)])
            };

            let cracked_hash = h
                .cracked_password
                .as_deref()
                .filter(|p| !p.is_empty())
                .map(|p| sha256_prefix(p, 16));

            let domain = if h.domain.is_empty() {
                None
            } else {
                Some(h.domain.as_str())
            };

            let hash_type = if h.hash_type.is_empty() {
                None
            } else {
                Some(h.hash_type.as_str())
            };

            let source = if h.source.is_empty() {
                None
            } else {
                Some(h.source.as_str())
            };

            sqlx::query(
                "INSERT INTO hashes (operation_id, hash_id, username, domain, hash_type,
                                     hash_value_prefix, cracked_password_hash, source,
                                     attack_step, discovered_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT ON CONSTRAINT uq_hash DO NOTHING",
            )
            .bind(operation_uuid)
            .bind(&h.id)
            .bind(&h.username)
            .bind(domain)
            .bind(hash_type)
            .bind(hash_prefix)
            .bind(cracked_hash.as_deref())
            .bind(source)
            .bind(h.attack_step)
            .bind(h.discovered_at)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn upsert_hosts(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        operation_uuid: Uuid,
        hosts: &[Host],
    ) -> Result<()> {
        for host in hosts {
            if host.ip.is_empty() {
                warn!("Skipping host with empty IP");
                continue;
            }

            let hostname = if host.hostname.is_empty() {
                None
            } else {
                Some(host.hostname.as_str())
            };

            let os = if host.os.is_empty() {
                None
            } else {
                Some(host.os.as_str())
            };

            let roles: Option<&[String]> = if host.roles.is_empty() {
                None
            } else {
                Some(&host.roles)
            };

            let services: Option<&[String]> = if host.services.is_empty() {
                None
            } else {
                Some(&host.services)
            };

            sqlx::query(
                "INSERT INTO hosts (operation_id, ip, hostname, os, is_dc, is_owned, roles, services)
                 VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT ON CONSTRAINT uq_host DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    os = EXCLUDED.os,
                    is_dc = EXCLUDED.is_dc,
                    is_owned = EXCLUDED.is_owned,
                    roles = EXCLUDED.roles,
                    services = EXCLUDED.services",
            )
            .bind(operation_uuid)
            .bind(&host.ip)
            .bind(hostname)
            .bind(os)
            .bind(host.is_dc)
            .bind(host.owned)
            .bind(roles)
            .bind(services)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn upsert_users(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        operation_uuid: Uuid,
        users: &[User],
    ) -> Result<()> {
        for user in users {
            let domain = if user.domain.is_empty() {
                None
            } else {
                Some(user.domain.as_str())
            };

            let description = if user.description.is_empty() {
                None
            } else {
                Some(user.description.as_str())
            };

            let source = if user.source.is_empty() {
                None
            } else {
                Some(user.source.as_str())
            };

            sqlx::query(
                "INSERT INTO users (operation_id, username, domain, description, is_admin, source)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT ON CONSTRAINT uq_user DO NOTHING",
            )
            .bind(operation_uuid)
            .bind(&user.username)
            .bind(domain)
            .bind(description)
            .bind(user.is_admin)
            .bind(source)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn upsert_vulnerabilities(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        operation_uuid: Uuid,
        vulnerabilities: &HashMap<String, VulnerabilityInfo>,
        exploited: &HashSet<String>,
    ) -> Result<()> {
        for (vuln_id, vuln) in vulnerabilities {
            let exploited_at: Option<DateTime<Utc>> = if exploited.contains(vuln_id) {
                Some(Utc::now())
            } else {
                None
            };

            let (target_ip, target_hostname) = if is_ip(&vuln.target) {
                (Some(vuln.target.as_str()), None)
            } else {
                (None, Some(vuln.target.as_str()))
            };

            let details = if vuln.details.is_empty() {
                None
            } else {
                Some(serde_json::to_value(&vuln.details)?)
            };

            sqlx::query(
                "INSERT INTO vulnerabilities (operation_id, vuln_id, vuln_type, target_ip,
                                              target_hostname, priority, discovered_by,
                                              discovered_at, exploited_at, details)
                 VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT ON CONSTRAINT uq_vuln DO UPDATE SET
                    exploited_at = EXCLUDED.exploited_at,
                    details = EXCLUDED.details",
            )
            .bind(operation_uuid)
            .bind(&vuln.vuln_id)
            .bind(&vuln.vuln_type)
            .bind(target_ip)
            .bind(target_hostname)
            .bind(vuln.priority)
            .bind(&vuln.discovered_by)
            .bind(vuln.discovered_at)
            .bind(exploited_at)
            .bind(details)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    // =========================================================================
    // Incremental Offload (sync during operation)
    // =========================================================================

    /// Incrementally offload credentials during an operation.
    pub async fn offload_credentials(
        &self,
        operation_id: &str,
        credentials: &[Credential],
    ) -> Result<bool> {
        if credentials.is_empty() {
            return Ok(true);
        }

        let Some(op_uuid) = self.get_operation_uuid(operation_id).await? else {
            debug!(operation_id, "Operation not found in persistent store");
            return Ok(false);
        };

        let mut tx = self.pool.begin().await?;
        self.upsert_credentials(&mut tx, op_uuid, credentials)
            .await?;
        tx.commit().await?;

        Ok(true)
    }

    /// Incrementally offload hashes during an operation.
    pub async fn offload_hashes(&self, operation_id: &str, hashes: &[Hash]) -> Result<bool> {
        if hashes.is_empty() {
            return Ok(true);
        }

        let Some(op_uuid) = self.get_operation_uuid(operation_id).await? else {
            debug!(operation_id, "Operation not found in persistent store");
            return Ok(false);
        };

        let mut tx = self.pool.begin().await?;
        self.upsert_hashes(&mut tx, op_uuid, hashes).await?;
        tx.commit().await?;

        Ok(true)
    }

    // =========================================================================
    // Store Report
    // =========================================================================

    /// Store the final operation report.
    pub async fn store_report(&self, operation_id: &str, report_markdown: &str) -> Result<bool> {
        let result = sqlx::query("UPDATE operations SET final_report = $2 WHERE operation_id = $1")
            .bind(operation_id)
            .bind(report_markdown)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            debug!(operation_id, "Operation not found for report storage");
            return Ok(false);
        }

        debug!(operation_id, "Stored operation report");
        Ok(true)
    }

    // =========================================================================
    // Cost Tracking
    // =========================================================================

    /// Update cost tracking for an operation.
    pub async fn update_cost(
        &self,
        operation_id: &str,
        total_input_tokens: i64,
        total_output_tokens: i64,
        total_cost: f64,
        model_usage: &serde_json::Value,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE operations SET
                total_input_tokens = $2,
                total_output_tokens = $3,
                total_cost = $4,
                model_usage = $5
             WHERE operation_id = $1",
        )
        .bind(operation_id)
        .bind(total_input_tokens)
        .bind(total_output_tokens)
        .bind(total_cost)
        .bind(model_usage)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    async fn get_operation_uuid(&self, operation_id: &str) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM operations WHERE operation_id = $1")
                .bind(operation_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|r| r.0))
    }
}

/// Data needed to offload a complete operation.
///
/// Built from `SharedRedTeamState` or equivalent in-memory state.
pub struct OperationOffload {
    pub operation_id: String,
    pub target_ip: Option<String>,
    pub target_domain: Option<String>,
    pub environment: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,
    pub da_hash_id: Option<String>,
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,
}

/// SHA-256 hash of a string, truncated to `len` hex chars.
fn sha256_prefix(input: &str, len: usize) -> String {
    let hash = Sha256::digest(input.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    hex[..hex.len().min(len)].to_string()
}

/// Check if a string looks like an IP address.
fn is_ip(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_prefix_returns_correct_length() {
        let result = sha256_prefix("P@ssw0rd!", 16); // pragma: allowlist secret
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn sha256_prefix_deterministic() {
        let a = sha256_prefix("test_password", 16); // pragma: allowlist secret
        let b = sha256_prefix("test_password", 16); // pragma: allowlist secret
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_prefix_different_inputs_differ() {
        let a = sha256_prefix("password1", 16); // pragma: allowlist secret
        let b = sha256_prefix("password2", 16); // pragma: allowlist secret
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_prefix_all_hex_chars() {
        let result = sha256_prefix("contoso.local\\admin", 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_prefix_len_zero() {
        let result = sha256_prefix("anything", 0);
        assert!(result.is_empty());
    }

    #[test]
    fn sha256_prefix_len_exceeds_hash() {
        // SHA-256 produces 64 hex chars; requesting more should clamp
        let result = sha256_prefix("test", 128);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn sha256_prefix_empty_input() {
        let result = sha256_prefix("", 16);
        assert_eq!(result.len(), 16);
        // SHA-256 of empty string is well-known
        assert!(result.starts_with("e3b0c44298fc1c14"));
    }

    #[test]
    fn sha256_prefix_various_lengths() {
        for len in [1, 4, 8, 16, 32, 64] {
            let result = sha256_prefix("contoso.local", len);
            assert_eq!(result.len(), len, "Expected length {len}");
        }
    }

    #[test]
    fn is_ip_valid_ipv4() {
        assert!(is_ip("192.168.58.10"));
        assert!(is_ip("192.168.58.240"));
        assert!(is_ip("192.168.58.1"));
        assert!(is_ip("0.0.0.0"));
        assert!(is_ip("255.255.255.255"));
    }

    #[test]
    fn is_ip_empty_string() {
        assert!(!is_ip(""));
    }

    #[test]
    fn is_ip_hostname() {
        assert!(!is_ip("dc01.contoso.local"));
        assert!(!is_ip("contoso.local"));
        assert!(!is_ip("sql01.fabrikam.local"));
    }

    #[test]
    fn is_ip_too_few_octets() {
        assert!(!is_ip("192.168.58"));
        assert!(!is_ip("192.168"));
        assert!(!is_ip("192"));
    }

    #[test]
    fn is_ip_too_many_octets() {
        assert!(!is_ip("192.168.58.10.1"));
    }

    #[test]
    fn is_ip_octet_out_of_range() {
        assert!(!is_ip("256.168.58.10"));
        assert!(!is_ip("192.168.58.999"));
        assert!(!is_ip("192.168.300.10"));
    }

    #[test]
    fn is_ip_non_numeric_octets() {
        assert!(!is_ip("abc.def.ghi.jkl"));
        assert!(!is_ip("192.168.58.abc"));
    }

    #[test]
    fn is_ip_negative_octets() {
        assert!(!is_ip("-1.168.58.10"));
        assert!(!is_ip("192.168.58.-10"));
    }

    #[test]
    fn is_ip_with_spaces() {
        assert!(!is_ip(" 192.168.58.10"));
        assert!(!is_ip("192.168.58.10 "));
        assert!(!is_ip("192. 168.58.10"));
    }

    #[test]
    fn is_ip_ipv6_rejected() {
        assert!(!is_ip("::1"));
        assert!(!is_ip("fe80::1"));
        assert!(!is_ip("2001:db8::1"));
    }

    #[test]
    fn is_ip_cidr_rejected() {
        assert!(!is_ip("192.168.58.0/24"));
    }
}
