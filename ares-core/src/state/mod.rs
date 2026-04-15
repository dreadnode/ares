//! Redis-native state backend for reading SharedRedTeamState.
//!
//! This module provides Redis-native storage access for SharedRedTeamState collections,
//! matching the Python `RedisStateBackend` key patterns exactly.
//!
//! Redis key structure:
//!     ares:op:{op_id}:credentials       HASH (dedup_key -> JSON)
//!     ares:op:{op_id}:hashes            HASH (dedup_key -> JSON)
//!     ares:op:{op_id}:hosts             LIST (JSON per entry)
//!     ares:op:{op_id}:users             LIST (JSON per entry)
//!     ares:op:{op_id}:shares            HASH (dedup_key -> JSON)
//!     ares:op:{op_id}:domains           SET
//!     ares:op:{op_id}:vulns             HASH (vuln_id -> JSON)
//!     ares:op:{op_id}:exploited         SET
//!     ares:op:{op_id}:meta              HASH
//!     ares:op:{op_id}:dc_map            HASH
//!     ares:op:{op_id}:netbios_map       HASH
//!     ares:op:{op_id}:artifacts         HASH
//!     ares:op:{op_id}:timeline          LIST (JSON per entry)
//!     ares:op:{op_id}:dedup:{set_name}  SET
//!     ares:op:{op_id}:techniques        SET
//!     ares:op:{op_id}:golden_tickets    LIST
//!     ares:op:{op_id}:adminsd_backdoors LIST
//!     ares:op:{op_id}:acl_chains        LIST
//!     ares:op:{op_id}:gmsa_accounts     LIST
//!
//! Lock keys:
//!     ares:lock:{op_id}                 STRING (operation lock)
//!
//! Task status keys:
//!     ares:task_status:{task_id}         STRING (JSON TaskStatusRecord)

#[cfg(feature = "blue")]
mod blue_operations;
#[cfg(feature = "blue")]
mod blue_reader;
#[cfg(feature = "blue")]
pub mod blue_task_queue;
#[cfg(feature = "blue")]
mod blue_writer;
pub mod circuit_breaker;
mod dedup_keys;
mod keys;
mod operations;
mod reader;

#[cfg(feature = "blue")]
pub use blue_operations::*;
#[cfg(feature = "blue")]
pub use blue_reader::*;
#[cfg(feature = "blue")]
pub use blue_task_queue::BlueTaskQueue;
#[cfg(feature = "blue")]
pub use blue_writer::*;
pub use circuit_breaker::CircuitBreaker;
pub use dedup_keys::*;
pub use keys::*;
pub use operations::*;
pub use reader::*;

use serde::de::DeserializeOwned;
use tracing::warn;

/// Attempt to deserialize a JSON string, logging a warning on failure.
///
/// This replaces the repetitive `match serde_json::from_str { Ok => push, Err => warn }` pattern
/// used throughout the state readers.
pub(crate) fn try_deserialize<T: DeserializeOwned>(json: &str, label: &str) -> Option<T> {
    match serde_json::from_str(json) {
        Ok(item) => Some(item),
        Err(e) => {
            warn!("Failed to deserialize {label}: {e}");
            None
        }
    }
}

/// Build a Redis key for an operation's collection.
///
/// # Examples
/// ```
/// use ares_core::state::build_key;
/// assert_eq!(build_key("op-123", "meta"), "ares:op:op-123:meta");
/// ```
pub fn build_key(operation_id: &str, suffix: &str) -> String {
    format!("{KEY_PREFIX}:{operation_id}:{suffix}")
}

/// Build a Redis lock key for an operation.
pub fn build_lock_key(operation_id: &str) -> String {
    format!("{LOCK_PREFIX}:{operation_id}")
}

/// Build a Redis key for a blue team investigation's collection.
///
/// # Examples
/// ```
/// use ares_core::state::build_blue_key;
/// assert_eq!(build_blue_key("inv-123", "meta"), "ares:blue:inv:inv-123:meta");
/// ```
#[cfg(feature = "blue")]
pub fn build_blue_key(investigation_id: &str, suffix: &str) -> String {
    format!("{BLUE_KEY_PREFIX}:{investigation_id}:{suffix}")
}

/// Build a Redis lock key for a blue team investigation.
#[cfg(feature = "blue")]
pub fn build_blue_lock_key(investigation_id: &str) -> String {
    format!("{BLUE_LOCK_PREFIX}:{investigation_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Credential;

    #[test]
    fn test_build_key() {
        assert_eq!(build_key("op-123", "meta"), "ares:op:op-123:meta");
        assert_eq!(
            build_key("op-123", "credentials"),
            "ares:op:op-123:credentials"
        );
    }

    #[test]
    fn test_build_lock_key() {
        assert_eq!(build_lock_key("op-123"), "ares:lock:op-123");
    }

    #[test]
    fn test_credential_dedup_key() {
        let cred = Credential {
            id: "test".to_string(),
            username: "TestUser".to_string(),
            password: "Password123".to_string(), // pragma: allowlist secret
            domain: "CONTOSO.LOCAL".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        let key = build_credential_dedup_key(&cred);
        // Should be lowercase and use md5 of password
        assert!(key.starts_with("cred:contoso.local:testuser:"));
        assert_eq!(key.len(), "cred:contoso.local:testuser:".len() + 16);
    }
}
