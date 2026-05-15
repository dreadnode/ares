//! Red team operation listing, resolution, and deletion.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use super::keys::*;
use super::{build_key, build_lock_key};

/// Publish a state update notification via NATS.
///
/// Subject: `ares.state.updates.{operation_id}` (core publish, fire-and-forget).
/// Message: `{"type":"state_update","operation_id":"...","ts":"..."}`
///
/// Returns 0 on success (no per-subscriber count; NATS core publish is async).
/// Connects to NATS using `ARES_NATS_URL` / `NATS_URL` if `nats` is None.
pub async fn publish_state_update(
    _conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<i64, redis::RedisError> {
    use bytes::Bytes;
    let message = serde_json::json!({
        "type": "state_update",
        "operation_id": operation_id,
        "ts": chrono::Utc::now().to_rfc3339(),
    });
    let msg_bytes = Bytes::from(serde_json::to_vec(&message).unwrap_or_default());
    let subject = format!(
        "{}.{operation_id}",
        crate::nats::STATE_UPDATE_SUBJECT_PREFIX
    );

    // Best-effort one-shot publish. Errors here are not fatal — state writes
    // already succeeded and the subscriber-count signal isn't load-bearing.
    match crate::nats::NatsBroker::connect_from_env().await {
        Ok(broker) => {
            if let Err(e) = broker.client().publish(subject, msg_bytes).await {
                tracing::debug!(operation_id, "NATS publish_state_update failed: {e}");
            }
        }
        Err(e) => {
            tracing::debug!(operation_id, "NATS unavailable for state update: {e}");
        }
    }
    Ok(0)
}

/// Set the operation status JSON string.
///
/// Key: `ares:op:{id}:status` — matches Python's operation status tracking.
pub async fn set_operation_status(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    status: &str,
) -> Result<(), redis::RedisError> {
    let key = build_key(operation_id, KEY_STATUS);
    let payload = serde_json::json!({
        "status": status,
        "operation_id": operation_id,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    let json = serde_json::to_string(&payload).unwrap_or_default();
    conn.set_ex::<_, _, ()>(&key, &json, 86400).await?;
    Ok(())
}

/// Finalize an operation in Redis — write completion metadata, clean up pointers.
///
/// Matches Python's operation completion sequence:
/// 1. Set `completed=true` and `completed_at` in meta HASH
/// 2. Write status key
/// 3. Delete operation lock
/// 4. Delete `ares:op:active` if it points to this operation
pub async fn finalize_operation(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    status: &str,
) -> Result<(), redis::RedisError> {
    let meta_key = build_key(operation_id, KEY_META);
    let now = Utc::now().to_rfc3339();

    // 1. Mark completed in meta HASH
    let completed_json = serde_json::to_string(&true).unwrap_or_default();
    let completed_at_json = serde_json::to_string(&now).unwrap_or_default();
    conn.hset::<_, _, _, ()>(&meta_key, "completed", &completed_json)
        .await?;
    conn.hset::<_, _, _, ()>(&meta_key, "completed_at", &completed_at_json)
        .await?;
    conn.hset::<_, _, _, ()>(
        &meta_key,
        "red_blocked_on_blue",
        serde_json::to_string(&false).unwrap_or_default(),
    )
    .await?;
    conn.expire::<_, ()>(&meta_key, 86400).await?;

    // 2. Write status key
    set_operation_status(conn, operation_id, status).await?;

    // 3. Delete the operation lock
    let lock_key = build_lock_key(operation_id);
    conn.del::<_, ()>(&lock_key).await?;

    // 4. Clear ares:op:active if it points to this operation
    let active: Option<String> = conn.get("ares:op:active").await?;
    if active.as_deref() == Some(operation_id) {
        conn.del::<_, ()>("ares:op:active").await?;
    }

    Ok(())
}

/// List all operation IDs by scanning `ares:op:*:meta` keys.
///
/// Uses SCAN with cursor iteration to avoid blocking Redis (unlike KEYS).
pub async fn list_operation_ids(
    conn: &mut impl AsyncCommands,
) -> Result<Vec<String>, redis::RedisError> {
    let mut op_ids = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("ares:op:*:meta")
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await?;

        for key in keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() >= 3 {
                op_ids.push(parts[2].to_string());
            }
        }

        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    op_ids.sort();
    Ok(op_ids)
}

/// List all running operation IDs by scanning lock keys.
///
/// Uses SCAN with cursor iteration to avoid blocking Redis.
pub async fn list_running_operations(
    conn: &mut impl AsyncCommands,
) -> Result<HashSet<String>, redis::RedisError> {
    let mut running = HashSet::new();
    let mut cursor: u64 = 0;
    let pattern = format!("{LOCK_PREFIX}:*");
    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await?;

        for key in keys {
            let parts: Vec<&str> = key.splitn(3, ':').collect();
            if parts.len() >= 3 {
                running.insert(parts[2].to_string());
            }
        }

        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(running)
}

/// Resolve the latest operation ID, preferring running operations.
///
/// Matches the Python `_resolve_latest_operation()` logic.
pub async fn resolve_latest_operation(
    conn: &mut impl AsyncCommands,
) -> Result<Option<String>, redis::RedisError> {
    let running_ops = list_running_operations(conn).await?;
    let all_op_ids = list_operation_ids(conn).await?;

    if all_op_ids.is_empty() {
        return Ok(None);
    }

    // Collect (started_at, op_id, is_running) tuples
    let mut ops: Vec<(Option<DateTime<Utc>>, String, bool)> = Vec::new();

    for op_id in &all_op_ids {
        let meta_key = build_key(op_id, KEY_META);
        let data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
        let started_at = data
            .get("started_at")
            .and_then(|s| {
                // Try JSON-decoding first (Python/Rust stores as json.dumps(value))
                if let Ok(serde_json::Value::String(inner)) =
                    serde_json::from_str::<serde_json::Value>(s)
                {
                    DateTime::parse_from_rfc3339(&inner)
                        .ok()
                        .or_else(|| inner.parse().ok())
                } else {
                    // Fall back to raw string
                    DateTime::parse_from_rfc3339(s)
                        .ok()
                        .or_else(|| s.parse().ok())
                }
            })
            .map(|dt| dt.with_timezone(&Utc));
        let is_running = running_ops.contains(op_id);
        ops.push((started_at, op_id.clone(), is_running));
    }

    // Prefer running operations
    let running: Vec<_> = ops
        .iter()
        .filter(|(_, _, is_running)| *is_running)
        .collect();
    if !running.is_empty() {
        return Ok(Some(pick_latest(&running)));
    }

    // Fall back to latest by started_at
    let all: Vec<_> = ops.iter().collect();
    Ok(Some(pick_latest(&all)))
}

pub(crate) fn pick_latest(items: &[&(Option<DateTime<Utc>>, String, bool)]) -> String {
    // Prefer items with a timestamp, sort descending
    let mut with_time: Vec<_> = items.iter().filter(|(t, _, _)| t.is_some()).collect();
    if !with_time.is_empty() {
        with_time.sort_by_key(|x| std::cmp::Reverse(x.0));
        return with_time[0].1.clone();
    }
    // Fallback: sort by op_id descending
    let mut by_id: Vec<_> = items.to_vec();
    by_id.sort_by(|a, b| b.1.cmp(&a.1));
    by_id[0].1.clone()
}

/// Delete an operation and all its associated Redis keys.
///
/// Uses SCAN with cursor iteration to avoid blocking Redis.
pub async fn delete_operation(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<usize, redis::RedisError> {
    // Find all keys for this operation via SCAN
    let pattern = format!("{KEY_PREFIX}:{operation_id}:*");
    let mut keys = scan_keys(conn, &pattern).await?;

    // Also delete the lock key
    keys.push(build_lock_key(operation_id));

    // Delete task status keys for this operation via SCAN
    let task_pattern = format!("{TASK_STATUS_PREFIX}:*");
    let task_keys = scan_keys(conn, &task_pattern).await?;

    for task_key in task_keys {
        let raw: Option<String> = conn.get(&task_key).await?;
        if let Some(json_str) = raw {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                if data.get("operation_id").and_then(|v| v.as_str()) == Some(operation_id) {
                    keys.push(task_key);
                }
            }
        }
    }

    let mut deleted = 0usize;
    for key in &keys {
        let count: usize = conn.del(key).await?;
        deleted += count;
    }

    Ok(deleted)
}

/// Request an operation to stop by setting a short-lived signal key.
///
/// Key: `ares:op:{id}:stop_requested` with a 120s TTL.
/// The orchestrator polls this key and initiates graceful shutdown when found.
pub async fn request_stop_operation(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<(), redis::RedisError> {
    let key = build_key(operation_id, KEY_STOP_REQUESTED);
    conn.set_ex::<_, _, ()>(&key, "1", 120).await?;
    Ok(())
}

/// Check whether a stop has been requested for this operation.
pub async fn is_stop_requested(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<bool, redis::RedisError> {
    let key = build_key(operation_id, KEY_STOP_REQUESTED);
    let exists: bool = conn.exists(&key).await?;
    Ok(exists)
}

/// Scan Redis keys matching a pattern using cursor iteration.
///
/// This is a non-blocking alternative to KEYS that won't stall Redis.
async fn scan_keys(
    conn: &mut impl AsyncCommands,
    pattern: &str,
) -> Result<Vec<String>, redis::RedisError> {
    let mut all_keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await?;

        all_keys.extend(keys);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(all_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(year: i32, month: u32, day: u32) -> Option<DateTime<Utc>> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single()
    }

    #[test]
    fn pick_latest_returns_most_recent_timestamp() {
        let older = (ts(2024, 1, 1), "op-older".to_string(), false);
        let newer = (ts(2024, 6, 1), "op-newer".to_string(), false);
        let oldest = (ts(2023, 3, 15), "op-oldest".to_string(), false);
        let items = [&older, &newer, &oldest];
        assert_eq!(pick_latest(&items), "op-newer");
    }

    #[test]
    fn pick_latest_no_timestamps_uses_lexicographic_descending() {
        let a = (None, "op-alpha".to_string(), false);
        let b = (None, "op-zeta".to_string(), false);
        let c = (None, "op-beta".to_string(), false);
        let items = [&a, &b, &c];
        // "op-zeta" sorts last lexicographically in descending order → picked
        assert_eq!(pick_latest(&items), "op-zeta");
    }

    #[test]
    fn pick_latest_mixed_prefers_timestamped() {
        let no_ts = (None, "op-zzz".to_string(), false);
        let with_ts = (ts(2024, 1, 1), "op-aaa".to_string(), false);
        let items = [&no_ts, &with_ts];
        // Even though "op-zzz" sorts higher lexicographically, the timestamped
        // entry wins because items with a timestamp are always preferred.
        assert_eq!(pick_latest(&items), "op-aaa");
    }

    #[test]
    fn pick_latest_single_item_with_timestamp() {
        let only = (ts(2024, 3, 10), "op-solo".to_string(), true);
        let items = [&only];
        assert_eq!(pick_latest(&items), "op-solo");
    }

    #[test]
    fn pick_latest_single_item_without_timestamp() {
        let only = (None, "op-solo".to_string(), false);
        let items = [&only];
        assert_eq!(pick_latest(&items), "op-solo");
    }

    // -- async tests using MockRedisConnection --------------------------------

    use crate::state::mock_redis::MockRedisConnection;
    use redis::AsyncCommands;

    #[tokio::test]
    async fn publish_state_update_returns_zero_without_subscribers() {
        let mut conn = MockRedisConnection::new();
        let count = publish_state_update(&mut conn, "op-1").await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn set_operation_status_stores_json_with_status_field() {
        let mut conn = MockRedisConnection::new();
        set_operation_status(&mut conn, "op-1", "running")
            .await
            .unwrap();

        let key = build_key("op-1", KEY_STATUS);
        let raw: String = conn.get(&key).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["status"], "running");
        assert_eq!(parsed["operation_id"], "op-1");
        assert!(parsed["updated_at"].is_string());
    }

    #[tokio::test]
    async fn set_operation_status_overwrites_previous() {
        let mut conn = MockRedisConnection::new();
        set_operation_status(&mut conn, "op-1", "running")
            .await
            .unwrap();
        set_operation_status(&mut conn, "op-1", "completed")
            .await
            .unwrap();

        let key = build_key("op-1", KEY_STATUS);
        let raw: String = conn.get(&key).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["status"], "completed");
    }

    #[tokio::test]
    async fn finalize_operation_sets_completed_metadata() {
        let mut conn = MockRedisConnection::new();
        let meta_key = build_key("op-1", KEY_META);

        // Set up initial meta hash
        let _: () = conn
            .hset(&meta_key, "started_at", "\"2024-06-01T00:00:00Z\"")
            .await
            .unwrap();

        // Set up lock key and active pointer
        let lock_key = build_lock_key("op-1");
        let _: () = conn.set(&lock_key, "1").await.unwrap();
        let _: () = conn.set("ares:op:active", "op-1").await.unwrap();

        finalize_operation(&mut conn, "op-1", "completed")
            .await
            .unwrap();

        // Verify completed fields in meta hash
        let completed: String = conn.hget(&meta_key, "completed").await.unwrap();
        assert_eq!(completed, "true");

        let completed_at: String = conn.hget(&meta_key, "completed_at").await.unwrap();
        assert!(!completed_at.is_empty());
    }

    #[tokio::test]
    async fn finalize_operation_deletes_lock_key() {
        let mut conn = MockRedisConnection::new();
        let meta_key = build_key("op-1", KEY_META);
        let _: () = conn
            .hset(&meta_key, "started_at", "\"2024-06-01T00:00:00Z\"")
            .await
            .unwrap();
        let lock_key = build_lock_key("op-1");
        let _: () = conn.set(&lock_key, "1").await.unwrap();

        finalize_operation(&mut conn, "op-1", "completed")
            .await
            .unwrap();

        let exists: bool = conn.exists(&lock_key).await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn finalize_operation_clears_active_when_matching() {
        let mut conn = MockRedisConnection::new();
        let meta_key = build_key("op-1", KEY_META);
        let _: () = conn
            .hset(&meta_key, "started_at", "\"2024-06-01T00:00:00Z\"")
            .await
            .unwrap();
        let _: () = conn.set("ares:op:active", "op-1").await.unwrap();

        finalize_operation(&mut conn, "op-1", "completed")
            .await
            .unwrap();

        let active: Option<String> = conn.get("ares:op:active").await.unwrap();
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn finalize_operation_preserves_active_when_different() {
        let mut conn = MockRedisConnection::new();
        let meta_key = build_key("op-1", KEY_META);
        let _: () = conn
            .hset(&meta_key, "started_at", "\"2024-06-01T00:00:00Z\"")
            .await
            .unwrap();
        let _: () = conn.set("ares:op:active", "op-other").await.unwrap();

        finalize_operation(&mut conn, "op-1", "completed")
            .await
            .unwrap();

        let active: Option<String> = conn.get("ares:op:active").await.unwrap();
        assert_eq!(active.as_deref(), Some("op-other"));
    }

    #[tokio::test]
    async fn list_operation_ids_returns_sorted_ids() {
        let mut conn = MockRedisConnection::new();

        // Insert meta hashes for three operations
        let _: () = conn
            .hset(
                "ares:op:op-c:meta",
                "started_at",
                "\"2024-01-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn
            .hset(
                "ares:op:op-a:meta",
                "started_at",
                "\"2024-03-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn
            .hset(
                "ares:op:op-b:meta",
                "started_at",
                "\"2024-02-01T00:00:00Z\"",
            )
            .await
            .unwrap();

        let ids = list_operation_ids(&mut conn).await.unwrap();
        assert_eq!(ids, vec!["op-a", "op-b", "op-c"]);
    }

    #[tokio::test]
    async fn list_operation_ids_empty_when_no_ops() {
        let mut conn = MockRedisConnection::new();
        let ids = list_operation_ids(&mut conn).await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_running_operations_returns_locked_ids() {
        let mut conn = MockRedisConnection::new();
        let _: () = conn.set("ares:lock:op-1", "1").await.unwrap();
        let _: () = conn.set("ares:lock:op-2", "1").await.unwrap();

        let running = list_running_operations(&mut conn).await.unwrap();
        assert_eq!(running.len(), 2);
        assert!(running.contains("op-1"));
        assert!(running.contains("op-2"));
    }

    #[tokio::test]
    async fn list_running_operations_empty_when_no_locks() {
        let mut conn = MockRedisConnection::new();
        let running = list_running_operations(&mut conn).await.unwrap();
        assert!(running.is_empty());
    }

    #[tokio::test]
    async fn resolve_latest_operation_returns_none_when_empty() {
        let mut conn = MockRedisConnection::new();
        let result = resolve_latest_operation(&mut conn).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_latest_operation_picks_most_recent() {
        let mut conn = MockRedisConnection::new();

        let _: () = conn
            .hset(
                "ares:op:op-old:meta",
                "started_at",
                "\"2024-01-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn
            .hset(
                "ares:op:op-new:meta",
                "started_at",
                "\"2024-06-15T00:00:00Z\"",
            )
            .await
            .unwrap();

        let result = resolve_latest_operation(&mut conn).await.unwrap();
        assert_eq!(result.as_deref(), Some("op-new"));
    }

    #[tokio::test]
    async fn resolve_latest_operation_prefers_running() {
        let mut conn = MockRedisConnection::new();

        // op-new is newer but not running
        let _: () = conn
            .hset(
                "ares:op:op-new:meta",
                "started_at",
                "\"2024-06-15T00:00:00Z\"",
            )
            .await
            .unwrap();
        // op-old is older but running (has a lock key)
        let _: () = conn
            .hset(
                "ares:op:op-old:meta",
                "started_at",
                "\"2024-01-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn.set("ares:lock:op-old", "1").await.unwrap();

        let result = resolve_latest_operation(&mut conn).await.unwrap();
        assert_eq!(result.as_deref(), Some("op-old"));
    }

    #[tokio::test]
    async fn delete_operation_removes_all_related_keys() {
        let mut conn = MockRedisConnection::new();

        // Set up operation keys
        let _: () = conn
            .hset(
                "ares:op:op-1:meta",
                "started_at",
                "\"2024-06-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn.set("ares:op:op-1:status", "running").await.unwrap();
        let _: () = conn.set("ares:lock:op-1", "1").await.unwrap();

        let deleted = delete_operation(&mut conn, "op-1").await.unwrap();
        assert!(deleted >= 2); // at least meta + lock

        // Verify keys are gone
        let exists_meta: bool = conn.exists("ares:op:op-1:meta").await.unwrap();
        let exists_lock: bool = conn.exists("ares:lock:op-1").await.unwrap();
        let exists_status: bool = conn.exists("ares:op:op-1:status").await.unwrap();
        assert!(!exists_meta);
        assert!(!exists_lock);
        assert!(!exists_status);
    }

    #[tokio::test]
    async fn delete_operation_removes_matching_task_status_keys() {
        let mut conn = MockRedisConnection::new();

        // Set up a task status key that references op-1
        let task_json = serde_json::json!({
            "operation_id": "op-1",
            "task": "nmap_scan",
            "status": "done"
        });
        let _: () = conn
            .set(
                "ares:task_status:task-abc",
                serde_json::to_string(&task_json).unwrap(),
            )
            .await
            .unwrap();

        // Set up a task status key for a different operation (should not be deleted)
        let other_json = serde_json::json!({
            "operation_id": "op-2",
            "task": "smb_enum",
            "status": "done"
        });
        let _: () = conn
            .set(
                "ares:task_status:task-xyz",
                serde_json::to_string(&other_json).unwrap(),
            )
            .await
            .unwrap();

        delete_operation(&mut conn, "op-1").await.unwrap();

        let exists_op1: bool = conn.exists("ares:task_status:task-abc").await.unwrap();
        let exists_op2: bool = conn.exists("ares:task_status:task-xyz").await.unwrap();
        assert!(!exists_op1);
        assert!(exists_op2);
    }

    #[tokio::test]
    async fn request_stop_then_is_stop_requested_returns_true() {
        let mut conn = MockRedisConnection::new();

        request_stop_operation(&mut conn, "op-1").await.unwrap();

        let stopped = is_stop_requested(&mut conn, "op-1").await.unwrap();
        assert!(stopped);
    }

    #[tokio::test]
    async fn is_stop_requested_returns_false_when_not_set() {
        let mut conn = MockRedisConnection::new();

        let stopped = is_stop_requested(&mut conn, "op-1").await.unwrap();
        assert!(!stopped);
    }

    #[tokio::test]
    async fn stop_request_is_per_operation() {
        let mut conn = MockRedisConnection::new();

        request_stop_operation(&mut conn, "op-1").await.unwrap();

        let stopped_op1 = is_stop_requested(&mut conn, "op-1").await.unwrap();
        let stopped_op2 = is_stop_requested(&mut conn, "op-2").await.unwrap();
        assert!(stopped_op1);
        assert!(!stopped_op2);
    }
}
