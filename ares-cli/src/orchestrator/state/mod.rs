//! In-memory shared state synced with Redis.
//!
//! `SharedState` wraps the operation state in `Arc<RwLock<...>>` so that all
//! background automation tasks can read state concurrently, and writes
//! (credential publishing, result processing) are serialized.
//!
//! State is loaded from Redis at startup and updated incrementally as results
//! arrive. Dedup sets are persisted to Redis so they survive orchestrator restarts.

mod dedup;
mod inner;
mod persistence;
mod publishing;
mod shared;

// Re-export everything that was publicly visible from the old single file.
pub use shared::SharedState;

// ---------------------------------------------------------------------------
// Dedup set names (match Python `ares:op:{op_id}:dedup:{name}`)
// ---------------------------------------------------------------------------

pub const DEDUP_CRACK_REQUESTS: &str = "crack_requests";
pub const DEDUP_SECRETSDUMP: &str = "secretsdump";
pub const DEDUP_DELEGATION_CREDS: &str = "delegation_creds";
pub const DEDUP_ADCS_SERVERS: &str = "adcs_servers";
pub const DEDUP_BLOODHOUND_DOMAINS: &str = "bloodhound_domains";
pub const DEDUP_SPIDERED_SHARES: &str = "spidered_shares";
pub const DEDUP_EXPANSION_CREDS: &str = "expansion_creds";
pub const DEDUP_ASREP_DOMAINS: &str = "asrep_domains";
pub const DEDUP_USERNAME_SPRAY: &str = "username_spray";
pub const DEDUP_PASSWORD_SPRAY: &str = "password_spray";
pub const DEDUP_ESC8_SERVERS: &str = "esc8_servers";
pub const DEDUP_COERCED_DCS: &str = "coerced_dcs";
pub const DEDUP_WRITABLE_SHARES: &str = "writable_shares";
pub const DEDUP_HASH_LATERAL: &str = "hash_lateral";
pub const DEDUP_SCANNED_TARGETS: &str = "scanned_targets";
pub const DEDUP_ACL_STEPS: &str = "acl_steps";
pub const DEDUP_TRUST_FOLLOW: &str = "trust_follow";
pub const DEDUP_S4U_EXPLOITS: &str = "s4u_exploits";
pub const DEDUP_GMSA_ACCOUNTS: &str = "gmsa_accounts";
pub const DEDUP_LOW_HANGING: &str = "low_hanging";
pub const DEDUP_CRED_SECRETSDUMP: &str = "cred_secretsdump";
pub const DEDUP_SHARE_ENUM: &str = "share_enum";

/// Vuln queue ZSET key suffix.
pub const KEY_VULN_QUEUE: &str = "vuln_queue";

/// Discovery list key prefix (NOT under ares:op:).
pub const DISCOVERY_KEY_PREFIX: &str = "ares:discoveries";

const ALL_DEDUP_SETS: &[&str] = &[
    DEDUP_CRACK_REQUESTS,
    DEDUP_SECRETSDUMP,
    DEDUP_DELEGATION_CREDS,
    DEDUP_ADCS_SERVERS,
    DEDUP_BLOODHOUND_DOMAINS,
    DEDUP_SPIDERED_SHARES,
    DEDUP_EXPANSION_CREDS,
    DEDUP_ASREP_DOMAINS,
    DEDUP_USERNAME_SPRAY,
    DEDUP_PASSWORD_SPRAY,
    DEDUP_ESC8_SERVERS,
    DEDUP_COERCED_DCS,
    DEDUP_WRITABLE_SHARES,
    DEDUP_HASH_LATERAL,
    DEDUP_SCANNED_TARGETS,
    DEDUP_ACL_STEPS,
    DEDUP_TRUST_FOLLOW,
    DEDUP_S4U_EXPLOITS,
    DEDUP_SHARE_ENUM,
    DEDUP_GMSA_ACCOUNTS,
    DEDUP_LOW_HANGING,
    DEDUP_CRED_SECRETSDUMP,
];
