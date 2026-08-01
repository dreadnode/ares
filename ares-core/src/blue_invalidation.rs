//! Per-operation counters for red work discarded by a containment observation.
//!
//! Once a credential stops authenticating, a host stops answering or a realm's
//! tickets stop decrypting, the deferred-task processor drops every queued task
//! bound to that principal, host or realm. The drop is logged and then
//! forgotten, so a red verification run whose subject was deleted mid-flight is
//! indistinguishable from a driver that never built the work at all.
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
//! | `attribution:{attribution}` | Tasks dropped, split by who the drop can honestly be blamed on |
//! | `retained_total` | Tasks *kept* despite a containment observation too weak to delete them |
//! | `retained_role:{target_role}` | Retained tasks, per agent role |
//!
//! Role, task-type and reason names are bounded, operator-authored identifiers,
//! so they are stored verbatim rather than encoded. The revoked principal
//! itself is deliberately *not* a field: it is loot, its cardinality is
//! unbounded, and it already appears in the drop log line.
//!
//! ## Attribution
//!
//! Red never sees a blue containment action. It sees a tool failing with a
//! string such as `STATUS_LOGON_FAILURE` and infers one. That inference is
//! only admissible when blue was actually running, so every drop carries a
//! [`ContainmentAttribution`] and the `reason:` field is named after what the
//! evidence supports: `credential_revoked` when blue was live,
//! `credential_rejected_inferred` when it was not.

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
/// HASH field prefix for per-attribution counters.
const ATTRIBUTION_PREFIX: &str = "attribution";
/// HASH field holding the operation-wide retained total.
const FIELD_RETAINED_TOTAL: &str = "retained_total";
/// HASH field prefix for per-role retained counters.
const RETAINED_ROLE_PREFIX: &str = "retained_role";

/// Who a dropped task can honestly be blamed on.
///
/// The classifier that produces containment observations reads red's own tool
/// output; it has no channel to blue. The one fact the orchestrator does hold
/// is whether blue was enabled for the operation, which is what separates
/// these two variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ContainmentAttribution {
    /// Blue was running for this operation, so a containment action is a live
    /// explanation for the failure red observed.
    BlueActive,
    /// Blue was not running. The drop rests entirely on red's own failing
    /// tool output — a stale hash, a lockout, an expired ticket or a wrong
    /// password guess — and is not evidence of any blue action.
    RedInferred,
}

impl ContainmentAttribution {
    /// Stable identifier used as the Redis HASH field suffix and in output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlueActive => "blue_active",
            Self::RedInferred => "red_inferred",
        }
    }

    /// Resolve from the operation's blue-team enablement.
    pub fn from_blue_enabled(blue_enabled: bool) -> Self {
        if blue_enabled {
            Self::BlueActive
        } else {
            Self::RedInferred
        }
    }
}

/// Why a queued task stopped being viable.
///
/// A closed set, unlike the human-readable reason string that accompanies it
/// in the log line — that string names the revoked principal or the isolated
/// host and is therefore unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ContainmentKind {
    /// The host the task targets stopped answering.
    HostIsolated,
    /// The credential the task authenticates with stopped being accepted.
    CredentialRevoked,
    /// Tickets in the realm the task operates against stopped decrypting.
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

    /// Stable identifier naming what the evidence actually establishes.
    ///
    /// With blue running, the containment reading stands. With blue off, the
    /// same tool output only proves that an authentication was refused, a host
    /// was unreachable, or a ticket failed to decrypt, so the name says that
    /// instead of asserting a revocation nobody performed.
    pub fn reason_field(self, attribution: ContainmentAttribution) -> &'static str {
        match attribution {
            ContainmentAttribution::BlueActive => self.as_str(),
            ContainmentAttribution::RedInferred => match self {
                Self::HostIsolated => "host_unreachable_inferred",
                Self::CredentialRevoked => "credential_rejected_inferred",
                Self::KrbtgtRotated => "kerberos_key_mismatch_inferred",
            },
        }
    }

    /// Human-readable cause for the drop log line, phrased for `attribution`.
    pub fn detail_label(self, attribution: ContainmentAttribution) -> &'static str {
        match attribution {
            ContainmentAttribution::BlueActive => match self {
                Self::HostIsolated => "host isolated",
                Self::CredentialRevoked => "credential revoked",
                Self::KrbtgtRotated => "krbtgt rotated",
            },
            ContainmentAttribution::RedInferred => match self {
                Self::HostIsolated => "host unreachable",
                Self::CredentialRevoked => "credential rejected",
                Self::KrbtgtRotated => "kerberos key mismatch",
            },
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
    /// Dropped tasks per attribution. Empty for operations recorded before
    /// attribution existed, which callers must render as the legacy case
    /// rather than as "nothing attributed".
    pub by_attribution: BTreeMap<String, u64>,
    /// Tasks kept in the queue despite a containment observation whose
    /// evidence was too weak to justify deleting them.
    pub retained_total: u64,
    /// Retained tasks per agent role.
    pub retained_by_role: BTreeMap<String, u64>,
}

impl BlueInvalidatedTasks {
    /// True when nothing was ever dropped, so callers can stay silent.
    pub fn is_empty(&self) -> bool {
        self.total == 0
            && self.by_role.is_empty()
            && self.by_task_type.is_empty()
            && self.by_reason.is_empty()
            && self.by_attribution.is_empty()
            && self.retained_total == 0
            && self.retained_by_role.is_empty()
    }

    /// Drops recorded while blue was running for the operation.
    pub fn blue_active_total(&self) -> u64 {
        self.by_attribution
            .get(ContainmentAttribution::BlueActive.as_str())
            .copied()
            .unwrap_or(0)
    }

    /// Drops recorded with blue off, which cannot be blue's doing.
    pub fn red_inferred_total(&self) -> u64 {
        self.by_attribution
            .get(ContainmentAttribution::RedInferred.as_str())
            .copied()
            .unwrap_or(0)
    }

    /// Roles ordered by dropped-task count, highest first, ties broken by name.
    pub fn roles_by_count(&self) -> Vec<(&str, u64)> {
        rank_by_count(&self.by_role)
    }

    /// Task types ordered by dropped-task count, highest first.
    pub fn task_types_by_count(&self) -> Vec<(&str, u64)> {
        rank_by_count(&self.by_task_type)
    }

    /// Containment kinds ordered by dropped-task count, highest first.
    pub fn reasons_by_count(&self) -> Vec<(&str, u64)> {
        rank_by_count(&self.by_reason)
    }

    /// Roles ordered by retained-task count, highest first.
    pub fn retained_roles_by_count(&self) -> Vec<(&str, u64)> {
        rank_by_count(&self.retained_by_role)
    }
}

fn rank_by_count(counts: &BTreeMap<String, u64>) -> Vec<(&str, u64)> {
    let mut rows: Vec<(&str, u64)> = counts
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows
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
    attribution: ContainmentAttribution,
) -> Result<(), redis::RedisError> {
    let key = blue_invalidated_key(operation_id);

    let mut pipe = redis::pipe();
    pipe.cmd("HINCRBY").arg(&key).arg(FIELD_TOTAL).arg(1);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg(format!(
            "{REASON_PREFIX}:{}",
            kind.reason_field(attribution)
        ))
        .arg(1);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg(format!("{ATTRIBUTION_PREFIX}:{}", attribution.as_str()))
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

/// Record one deferred task that a containment observation did *not* delete.
///
/// The counterpart to [`record_blue_invalidated_task`]: an inferred credential
/// rejection with blue off hides the credential from the LLM but leaves queued
/// work alone, and that decision has to stay visible. Without this an operator
/// who fixes the false attribution just sees the drop count fall to zero and
/// concludes the signal was thrown away.
pub async fn record_retained_task(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    target_role: &str,
) -> Result<(), redis::RedisError> {
    let key = blue_invalidated_key(operation_id);

    let mut pipe = redis::pipe();
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg(FIELD_RETAINED_TOTAL)
        .arg(1);
    if !target_role.is_empty() {
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(format!("{RETAINED_ROLE_PREFIX}:{target_role}"))
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
        } else if field == FIELD_RETAINED_TOTAL {
            counts.retained_total = count;
        } else if let Some(role) = field.strip_prefix(&format!("{RETAINED_ROLE_PREFIX}:")) {
            counts.retained_by_role.insert(role.to_string(), count);
        } else if let Some(role) = field.strip_prefix(&format!("{ROLE_PREFIX}:")) {
            counts.by_role.insert(role.to_string(), count);
        } else if let Some(task_type) = field.strip_prefix(&format!("{TYPE_PREFIX}:")) {
            counts.by_task_type.insert(task_type.to_string(), count);
        } else if let Some(reason) = field.strip_prefix(&format!("{REASON_PREFIX}:")) {
            counts.by_reason.insert(reason.to_string(), count);
        } else if let Some(attribution) = field.strip_prefix(&format!("{ATTRIBUTION_PREFIX}:")) {
            counts.by_attribution.insert(attribution.to_string(), count);
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

    #[test]
    fn attribution_follows_blue_enablement() {
        assert_eq!(
            ContainmentAttribution::from_blue_enabled(true),
            ContainmentAttribution::BlueActive
        );
        assert_eq!(
            ContainmentAttribution::from_blue_enabled(false),
            ContainmentAttribution::RedInferred
        );
    }

    #[test]
    fn reason_field_never_claims_revocation_with_blue_off() {
        for kind in [
            ContainmentKind::HostIsolated,
            ContainmentKind::CredentialRevoked,
            ContainmentKind::KrbtgtRotated,
        ] {
            let blue = kind.reason_field(ContainmentAttribution::BlueActive);
            let inferred = kind.reason_field(ContainmentAttribution::RedInferred);
            assert_eq!(blue, kind.as_str());
            assert_ne!(blue, inferred);
            assert!(inferred.ends_with("_inferred"), "{inferred}");
        }
        assert_eq!(
            ContainmentKind::CredentialRevoked.reason_field(ContainmentAttribution::RedInferred),
            "credential_rejected_inferred"
        );
    }

    #[test]
    fn detail_label_drops_the_blue_verb_when_blue_is_off() {
        assert_eq!(
            ContainmentKind::CredentialRevoked.detail_label(ContainmentAttribution::BlueActive),
            "credential revoked"
        );
        assert_eq!(
            ContainmentKind::CredentialRevoked.detail_label(ContainmentAttribution::RedInferred),
            "credential rejected"
        );
        assert_eq!(
            ContainmentKind::KrbtgtRotated.detail_label(ContainmentAttribution::RedInferred),
            "kerberos key mismatch"
        );
    }

    #[tokio::test]
    async fn blue_off_drops_are_counted_under_their_own_reason_and_attribution() {
        let mut conn = MockRedisConnection::new();
        record_blue_invalidated_task(
            &mut conn,
            "op-test-001",
            "recon",
            "recon",
            ContainmentKind::CredentialRevoked,
            ContainmentAttribution::RedInferred,
        )
        .await
        .expect("record should succeed");

        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");

        assert_eq!(counts.total, 1);
        assert_eq!(
            counts.by_reason.get("credential_rejected_inferred"),
            Some(&1)
        );
        assert_eq!(counts.by_reason.get("credential_revoked"), None);
        assert_eq!(counts.red_inferred_total(), 1);
        assert_eq!(counts.blue_active_total(), 0);
    }

    #[tokio::test]
    async fn retained_tasks_are_counted_separately_from_drops() {
        let mut conn = MockRedisConnection::new();
        record_blue_invalidated_task(
            &mut conn,
            "op-test-001",
            "lateral",
            "lateral",
            ContainmentKind::CredentialRevoked,
            ContainmentAttribution::RedInferred,
        )
        .await
        .expect("record should succeed");
        for _ in 0..40 {
            record_retained_task(&mut conn, "op-test-001", "recon")
                .await
                .expect("record should succeed");
        }

        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");

        assert_eq!(counts.total, 1);
        assert_eq!(counts.retained_total, 40);
        assert_eq!(counts.retained_by_role.get("recon"), Some(&40));
        assert_eq!(counts.by_role.get("recon"), None);
        assert_eq!(counts.retained_roles_by_count(), vec![("recon", 40)]);
    }

    #[tokio::test]
    async fn retention_alone_is_not_an_empty_record() {
        let mut conn = MockRedisConnection::new();
        record_retained_task(&mut conn, "op-test-001", "recon")
            .await
            .expect("record should succeed");

        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");

        assert!(!counts.is_empty());
        assert_eq!(counts.total, 0);
        assert_eq!(counts.retained_total, 1);
    }

    #[tokio::test]
    async fn mixed_attribution_totals_split_without_overlap() {
        let mut conn = MockRedisConnection::new();
        record_blue_invalidated_task(
            &mut conn,
            "op-test-001",
            "lateral",
            "lateral",
            ContainmentKind::CredentialRevoked,
            ContainmentAttribution::BlueActive,
        )
        .await
        .expect("record should succeed");
        for _ in 0..3 {
            record_blue_invalidated_task(
                &mut conn,
                "op-test-001",
                "recon",
                "recon",
                ContainmentKind::HostIsolated,
                ContainmentAttribution::RedInferred,
            )
            .await
            .expect("record should succeed");
        }

        let counts = get_blue_invalidated_tasks(&mut conn, "op-test-001")
            .await
            .expect("read should succeed");

        assert_eq!(counts.total, 4);
        assert_eq!(counts.blue_active_total(), 1);
        assert_eq!(counts.red_inferred_total(), 3);
        assert_eq!(
            counts.blue_active_total() + counts.red_inferred_total(),
            counts.total
        );
        assert_eq!(counts.by_reason.get("credential_revoked"), Some(&1));
        assert_eq!(counts.by_reason.get("host_unreachable_inferred"), Some(&3));
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
                ContainmentAttribution::BlueActive,
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
            ContainmentAttribution::BlueActive,
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
            ContainmentAttribution::BlueActive,
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
            ContainmentAttribution::BlueActive,
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
            by_attribution: BTreeMap::new(),
            retained_total: 0,
            retained_by_role: BTreeMap::new(),
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
            by_attribution: BTreeMap::new(),
            retained_total: 0,
            retained_by_role: BTreeMap::new(),
        };

        assert_eq!(
            counts.task_types_by_count(),
            vec![("exploit", 3), ("acl_chain_step", 2)]
        );
    }

    #[test]
    fn reasons_rank_by_count_then_name() {
        let counts = BlueInvalidatedTasks {
            total: 75,
            by_role: BTreeMap::new(),
            by_task_type: BTreeMap::new(),
            by_reason: BTreeMap::from([
                ("host_isolated".to_string(), 16),
                ("credential_revoked".to_string(), 59),
            ]),
            by_attribution: BTreeMap::new(),
            retained_total: 0,
            retained_by_role: BTreeMap::new(),
        };

        assert_eq!(
            counts.reasons_by_count(),
            vec![("credential_revoked", 59), ("host_isolated", 16)]
        );
    }
}
