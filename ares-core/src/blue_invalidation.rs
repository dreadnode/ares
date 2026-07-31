//! Per-operation counters for red work discarded because of blue containment.
//!
//! When blue revokes a credential, isolates a host or rotates `krbtgt`, the
//! deferred-task processor drops every queued task bound to that principal,
//! host or realm. The drop is logged and then forgotten, so a red verification
//! run whose subject was deleted mid-flight is indistinguishable from a driver
//! that never built the work at all.
//!
//! These counters make that difference readable from `ares ops runtime`.
//!
//! ## Redis key format
//!
//! All counters live in a single HASH at `ares:op:{op_id}:blue_invalidated`:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `total` | Every deferred task dropped by containment |
//! | `role:{target_role}` | Tasks dropped, per agent role |
//! | `type:{task_type}` | Tasks dropped, per task type |
//! | `reason:{kind}` | Tasks dropped, per containment kind |
//!
//! Role, task-type and reason names are bounded, operator-authored identifiers,
//! so they are stored verbatim rather than encoded. The revoked principal
//! itself is deliberately *not* a field: it is loot, its cardinality is
//! unbounded, and it already appears in the drop log line.

use std::collections::BTreeMap;

use redis::AsyncCommands;

/// HASH field holding the operation-wide total.
const FIELD_TOTAL: &str = "total";
/// HASH field prefix for per-role counters.
const ROLE_PREFIX: &str = "role";
/// HASH field prefix for per-task-type counters.
const TYPE_PREFIX: &str = "type";
/// HASH field prefix for per-containment-kind counters.
const REASON_PREFIX: &str = "reason";

/// Why a queued task stopped being viable.
///
/// A closed set, unlike the human-readable reason string that accompanies it
/// in the log line — that string names the revoked principal or the isolated
/// host and is therefore unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ContainmentKind {
    /// Blue isolated the host the task targets.
    HostIsolated,
    /// Blue revoked the credential the task authenticates with.
    CredentialRevoked,
    /// Blue rotated `krbtgt` in the realm the task operates against.
    KrbtgtRotated,
}

impl ContainmentKind {
    /// Stable identifier used as the Redis HASH field suffix and in output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostIsolated => "host_isolated",
            Self::CredentialRevoked => "credential_revoked",
            Self::KrbtgtRotated => "krbtgt_rotated",
        }
    }
}

/// Build the Redis key for an operation's blue-invalidation HASH.
pub fn blue_invalidated_key(operation_id: &str) -> String {
    format!("ares:op:{operation_id}:blue_invalidated")
}

/// Counts of deferred tasks that blue containment removed from the queue.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BlueInvalidatedTasks {
    /// Every dropped task, regardless of role.
    pub total: u64,
    /// Dropped tasks per agent role, e.g. `acl` → 2.
    pub by_role: BTreeMap<String, u64>,
    /// Dropped tasks per task type, e.g. `acl_chain_step` → 2.
    pub by_task_type: BTreeMap<String, u64>,
    /// Dropped tasks per containment kind.
    pub by_reason: BTreeMap<String, u64>,
}

impl BlueInvalidatedTasks {
    /// True when nothing was ever dropped, so callers can stay silent.
    pub fn is_empty(&self) -> bool {
        self.total == 0
            && self.by_role.is_empty()
            && self.by_task_type.is_empty()
            && self.by_reason.is_empty()
    }

    /// Roles ordered by dropped-task count, highest first, ties broken by name.
    pub fn roles_by_count(&self) -> Vec<(&str, u64)> {
        let mut rows: Vec<(&str, u64)> = self
            .by_role
            .iter()
            .map(|(role, count)| (role.as_str(), *count))
            .collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        rows
    }

    /// Task types ordered by dropped-task count, highest first.
    pub fn task_types_by_count(&self) -> Vec<(&str, u64)> {
        let mut rows: Vec<(&str, u64)> = self
            .by_task_type
            .iter()
            .map(|(task_type, count)| (task_type.as_str(), *count))
            .collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        rows
    }
}

/// Record one deferred task dropped by blue containment.
///
/// Every field is an HINCRBY, so concurrent orchestrator loops accumulate
/// without a lock and a crash mid-operation loses nothing already counted.
/// Empty `task_type` / `target_role` still bump `total`, so the headline can
/// never undercount a drop whose payload was missing a field.
pub async fn record_blue_invalidated_task(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    task_type: &str,
    target_role: &str,
    kind: ContainmentKind,
) -> Result<(), redis::RedisError> {
    let key = blue_invalidated_key(operation_id);

    let mut pipe = redis::pipe();
    pipe.cmd("HINCRBY").arg(&key).arg(FIELD_TOTAL).arg(1);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg(format!("{REASON_PREFIX}:{}", kind.as_str()))
        .arg(1);
    if !target_role.is_empty() {
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(format!("{ROLE_PREFIX}:{target_role}"))
            .arg(1);
    }
    if !task_type.is_empty() {
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(format!("{TYPE_PREFIX}:{task_type}"))
            .arg(1);
    }

    pipe.query_async::<()>(conn).await?;
    Ok(())
}

/// Read the blue-invalidation counters for an operation.
///
/// Returns an all-zero record when the key is absent, so a caller can render
/// unconditionally without distinguishing "no drops" from "no key".
pub async fn get_blue_invalidated_tasks(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<BlueInvalidatedTasks, redis::RedisError> {
    let key = blue_invalidated_key(operation_id);
    let data: std::collections::HashMap<String, String> = conn.hgetall(&key).await?;

    let mut counts = BlueInvalidatedTasks::default();
    for (field, value) in &data {
        let Ok(count) = value.parse::<u64>() else {
            continue;
        };
        if field == FIELD_TOTAL {
            counts.total = count;
        } else if let Some(role) = field.strip_prefix(&format!("{ROLE_PREFIX}:")) {
            counts.by_role.insert(role.to_string(), count);
        } else if let Some(task_type) = field.strip_prefix(&format!("{TYPE_PREFIX}:")) {
            counts.by_task_type.insert(task_type.to_string(), count);
        } else if let Some(reason) = field.strip_prefix(&format!("{REASON_PREFIX}:")) {
            counts.by_reason.insert(reason.to_string(), count);
        }
    }

    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::mock_redis::MockRedisConnection;

    #[test]
    fn key_is_namespaced_under_the_operation() {
        assert_eq!(
            blue_invalidated_key("op-20260731-053105"),
            "ares:op:op-20260731-053105:blue_invalidated"
        );
    }

    #[test]
    fn containment_kinds_have_distinct_stable_names() {
        assert_eq!(ContainmentKind::HostIsolated.as_str(), "host_isolated");
        assert_eq!(
            ContainmentKind::CredentialRevoked.as_str(),
            "credential_revoked"
        );
        assert_eq!(ContainmentKind::KrbtgtRotated.as_str(), "krbtgt_rotated");
    }

    #[tokio::test]
    async fn absent_key_reads_as_empty_rather_than_erroring() {
        let mut conn = MockRedisConnection::new();
        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");
        assert!(counts.is_empty());
        assert_eq!(counts.total, 0);
    }

    #[tokio::test]
    async fn records_split_by_role_task_type_and_reason() {
        let mut conn = MockRedisConnection::new();
        for _ in 0..2 {
            record_blue_invalidated_task(
                &mut conn,
                "op-test-001",
                "acl_chain_step",
                "acl",
                ContainmentKind::CredentialRevoked,
            )
            .await
            .expect("record should succeed");
        }
        record_blue_invalidated_task(
            &mut conn,
            "op-test-001",
            "recon",
            "recon",
            ContainmentKind::HostIsolated,
        )
        .await
        .expect("record should succeed");

        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");

        assert_eq!(counts.total, 3);
        assert_eq!(counts.by_role.get("acl"), Some(&2));
        assert_eq!(counts.by_role.get("recon"), Some(&1));
        assert_eq!(counts.by_task_type.get("acl_chain_step"), Some(&2));
        assert_eq!(counts.by_reason.get("credential_revoked"), Some(&2));
        assert_eq!(counts.by_reason.get("host_isolated"), Some(&1));
    }

    #[tokio::test]
    async fn total_still_counts_a_drop_with_no_role_or_task_type() {
        let mut conn = MockRedisConnection::new();
        record_blue_invalidated_task(
            &mut conn,
            "op-test-001",
            "",
            "",
            ContainmentKind::KrbtgtRotated,
        )
        .await
        .expect("record should succeed");

        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");

        assert_eq!(counts.total, 1);
        assert!(counts.by_role.is_empty());
        assert!(counts.by_task_type.is_empty());
        assert_eq!(counts.by_reason.get("krbtgt_rotated"), Some(&1));
        assert!(!counts.is_empty());
    }

    #[tokio::test]
    async fn counters_are_scoped_per_operation() {
        let mut conn = MockRedisConnection::new();
        record_blue_invalidated_task(
            &mut conn,
            "op-test-001",
            "lateral",
            "lateral",
            ContainmentKind::CredentialRevoked,
        )
        .await
        .expect("record should succeed");

        let other = get_blue_invalidated_tasks(&mut conn, "op-test-002")
            .await
            .expect("read should succeed");
        assert!(other.is_empty());
    }

    #[test]
    fn roles_rank_by_count_then_name() {
        let counts = BlueInvalidatedTasks {
            total: 47,
            by_role: BTreeMap::from([
                ("recon".to_string(), 24),
                ("acl".to_string(), 2),
                ("lateral".to_string(), 12),
                ("coercion".to_string(), 2),
            ]),
            by_task_type: BTreeMap::new(),
            by_reason: BTreeMap::new(),
        };

        assert_eq!(
            counts.roles_by_count(),
            vec![("recon", 24), ("lateral", 12), ("acl", 2), ("coercion", 2)]
        );
    }

    #[test]
    fn task_types_rank_by_count() {
        let counts = BlueInvalidatedTasks {
            total: 5,
            by_role: BTreeMap::new(),
            by_task_type: BTreeMap::from([
                ("acl_chain_step".to_string(), 2),
                ("exploit".to_string(), 3),
            ]),
            by_reason: BTreeMap::new(),
        };

        assert_eq!(
            counts.task_types_by_count(),
            vec![("exploit", 3), ("acl_chain_step", 2)]
        );
    }
}
