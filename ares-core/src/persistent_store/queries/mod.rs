//! Historical query service for persistent data store.
//!
//! Provides read-only query methods for analyzing historical operation data,
//! cross-operation credential/hash search, MITRE coverage analysis, and
//! retention policy enforcement.

mod costs;
mod coverage;
mod credentials;
mod operations;
pub mod rows;

pub use rows::{CostRow, CredentialRow, HashRow, MitreCoverage, OperationRow, OperationSummary};

use anyhow::{Context, Result};
use sqlx::PgPool;

use super::config::PersistentStoreConfig;

/// Service for querying historical operation data.
///
/// Provides cross-operation search, MITRE coverage analysis,
/// and retention policy enforcement.
#[derive(Clone)]
pub struct HistoricalQueryService {
    pub(super) pool: PgPool,
}

impl HistoricalQueryService {
    /// Create from an existing connection pool.
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

        Ok(Self { pool })
    }

    /// Connect to PostgreSQL.
    ///
    /// Uses hardcoded pool defaults. Prefer [`from_config`](Self::from_config)
    /// for configurable pool settings.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL")?;
        Ok(Self { pool })
    }
}
