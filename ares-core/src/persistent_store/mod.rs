//! Persistent store for long-term operation data in PostgreSQL.
//!
//! This module provides the write path (`PersistentStore`) for offloading
//! operation data from Redis to PostgreSQL, and the read path
//! (`HistoricalQueryService`) for querying historical data.
//!
//! # Architecture
//!
//! Redis is the hot storage layer with 24h TTL. PostgreSQL is the durable
//! store for cross-operation analysis and historical queries.
//!
//! The persistent store supports:
//! - Full operation offload on completion
//! - Incremental credential/hash sync during operation
//! - Report storage
//! - Cost tracking
//! - MITRE ATT&CK coverage analysis
//! - Retention policy enforcement

mod config;
mod queries;
mod store;

pub use config::{PersistentStoreConfig, RetentionConfig};
pub use queries::{
    CostRow, CredentialRow, HashRow, HistoricalQueryService, MitreCoverage, OperationRow,
    OperationSummary,
};
pub use store::{OperationOffload, PersistentStore};
