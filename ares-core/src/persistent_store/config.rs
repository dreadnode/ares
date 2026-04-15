//! Configuration for persistent data store.
//!
//! Supports configuration via environment variables with sensible defaults.

use std::env;
use std::time::Duration;

use tracing::debug;

/// Retention policy configuration for different data types.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Days to keep operation metadata (default: 90).
    pub operations_default_days: i64,
    /// Days to keep operations that achieved domain admin (default: 365).
    pub operations_with_da_days: i64,
    /// Max artifact size to persist in bytes (default: 10 MB).
    pub artifacts_max_size_bytes: usize,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            operations_default_days: 90,
            operations_with_da_days: 365,
            artifacts_max_size_bytes: 10_485_760, // 10 MB
        }
    }
}

/// Configuration for PostgreSQL persistent store.
#[derive(Debug, Clone)]
pub struct PersistentStoreConfig {
    /// PostgreSQL connection URL (from `ARES_DATABASE_URL`).
    pub database_url: Option<String>,
    /// Minimum connection pool size (default: 2).
    pub pool_min_size: u32,
    /// Maximum connection pool size (default: 5).
    pub pool_max_size: u32,
    /// Connection pool timeout in seconds (default: 30).
    pub pool_timeout_secs: u64,
    /// Retention policies.
    pub retention: RetentionConfig,
}

impl Default for PersistentStoreConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            pool_min_size: 2,
            pool_max_size: 5,
            pool_timeout_secs: 30,
            retention: RetentionConfig::default(),
        }
    }
}

impl PersistentStoreConfig {
    /// Load configuration from environment variables with defaults.
    ///
    /// # Environment Variables
    ///
    /// - `ARES_DATABASE_URL` — PostgreSQL connection URL
    /// - `ARES_PG_POOL_MIN` — Minimum pool size (default: 2)
    /// - `ARES_PG_POOL_MAX` — Maximum pool size (default: 5)
    /// - `ARES_PG_POOL_TIMEOUT` — Pool acquire timeout in seconds (default: 30)
    /// - `ARES_RETENTION_DEFAULT_DAYS` — Operation retention days (default: 90)
    /// - `ARES_RETENTION_DA_DAYS` — DA operation retention days (default: 365)
    /// - `ARES_RETENTION_ARTIFACT_MAX_BYTES` — Max artifact size in bytes (default: 10485760)
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = env::var("ARES_DATABASE_URL") {
            if !url.is_empty() {
                debug!("Persistent store enabled with database URL");
                config.database_url = Some(url);
            }
        }

        if let Ok(val) = env::var("ARES_PG_POOL_MIN") {
            if let Ok(n) = val.parse::<u32>() {
                config.pool_min_size = n;
            }
        }

        if let Ok(val) = env::var("ARES_PG_POOL_MAX") {
            if let Ok(n) = val.parse::<u32>() {
                config.pool_max_size = n;
            }
        }

        if let Ok(val) = env::var("ARES_PG_POOL_TIMEOUT") {
            if let Ok(n) = val.parse::<u64>() {
                config.pool_timeout_secs = n;
            }
        }

        if let Ok(val) = env::var("ARES_RETENTION_DEFAULT_DAYS") {
            if let Ok(n) = val.parse::<i64>() {
                config.retention.operations_default_days = n;
            }
        }

        if let Ok(val) = env::var("ARES_RETENTION_DA_DAYS") {
            if let Ok(n) = val.parse::<i64>() {
                config.retention.operations_with_da_days = n;
            }
        }

        if let Ok(val) = env::var("ARES_RETENTION_ARTIFACT_MAX_BYTES") {
            if let Ok(n) = val.parse::<usize>() {
                config.retention.artifacts_max_size_bytes = n;
            }
        }

        config
    }

    /// Returns `true` if the persistent store is enabled (has a database URL).
    pub fn is_enabled(&self) -> bool {
        self.database_url.is_some()
    }

    /// Pool acquire timeout as a `Duration`.
    pub fn pool_timeout(&self) -> Duration {
        Duration::from_secs(self.pool_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PersistentStoreConfig::default();
        assert!(config.database_url.is_none());
        assert!(!config.is_enabled());
        assert_eq!(config.pool_min_size, 2);
        assert_eq!(config.pool_max_size, 5);
        assert_eq!(config.pool_timeout_secs, 30);
    }

    #[test]
    fn test_default_retention() {
        let retention = RetentionConfig::default();
        assert_eq!(retention.operations_default_days, 90);
        assert_eq!(retention.operations_with_da_days, 365);
        assert_eq!(retention.artifacts_max_size_bytes, 10_485_760);
    }

    #[test]
    fn test_is_enabled() {
        let mut config = PersistentStoreConfig::default();
        assert!(!config.is_enabled());

        config.database_url = Some("postgres://localhost/ares".to_string());
        assert!(config.is_enabled());
    }

    #[test]
    fn test_pool_timeout_duration() {
        let config = PersistentStoreConfig::default();
        assert_eq!(config.pool_timeout(), Duration::from_secs(30));
    }
}
