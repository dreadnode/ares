//! Background automation tasks.
//!
//! Each `auto_*` function is a long-running tokio task that periodically checks
//! the shared state and dispatches new tasks when conditions are met. All follow
//! the same pattern:
//!
//!   1. Sleep for an interval (configurable)
//!   2. Take a read lock, collect new work items
//!   3. Release lock, submit tasks via the dispatcher
//!   4. Mark items as processed (write lock + Redis persist)
//!
//! This mirrors the Python `_orchestrator.py` background tasks but eliminates
//! all threading hacks since tokio tasks are truly concurrent.

mod acl;
mod adcs;
mod bloodhound;
mod coercion;
mod crack;
mod credential_access;
mod credential_expansion;
mod delegation;
mod golden_ticket;
mod mssql;
mod refresh;
mod secretsdump;
mod shares;

// Re-export all public task functions at the same paths they had before the split.
pub use acl::auto_acl_chain_follow;
pub use adcs::auto_adcs_enumeration;
pub use bloodhound::auto_bloodhound;
pub use coercion::auto_coercion;
pub use crack::auto_crack_dispatch;
pub use credential_access::auto_credential_access;
pub use credential_expansion::auto_credential_expansion;
pub use delegation::auto_delegation_enumeration;
pub use golden_ticket::auto_golden_ticket;
pub use mssql::auto_mssql_detection;
pub use refresh::state_refresh;
pub use secretsdump::auto_local_admin_secretsdump;
pub use shares::auto_share_spider;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a deduplication key for crack requests.
pub(crate) fn crack_dedup_key(hash: &ares_core::models::Hash) -> String {
    let prefix = &hash.hash_value[..32.min(hash.hash_value.len())];
    format!(
        "{}:{}:{}",
        hash.domain.to_lowercase(),
        hash.username.to_lowercase(),
        prefix
    )
}
