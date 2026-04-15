//! Red team operation listing, resolution, and deletion.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use super::keys::*;
use super::{build_key, build_lock_key};

/// Publish a state update notification via Redis PUBLISH.
///
/// Channel: `ares:state:updates:{operation_id}`
/// Message: `{"type":"state_update","operation_id":"...","ts":"..."}`
///
/// Returns the number of subscribers that received the message.
pub async fn publish_state_update(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<i64, redis::RedisError> {
    let channel = format!("{STATE_UPDATE_CHANNEL_PREFIX}:{operation_id}");
    let message = serde_json::json!({
        "type": "state_update",
        "operation_id": operation_id,
        "ts": chrono::Utc::now().to_rfc3339(),
    });
    let msg_str = serde_json::to_string(&message).unwrap_or_default();
    let count: i64 = conn.publish(&channel, &msg_str).await?;
    Ok(count)
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
        with_time.sort_by(|a, b| b.0.cmp(&a.0));
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
