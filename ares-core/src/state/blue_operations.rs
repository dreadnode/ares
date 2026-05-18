//! Blue team investigation listing, resolution, and deletion.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use super::keys::*;
use super::{build_blue_key, build_blue_lock_key};

/// Scan Redis keys matching a pattern using cursor iteration (avoids KEYS).
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

/// List all blue team investigation IDs by scanning `ares:blue:inv:*:meta` keys.
///
/// Uses SCAN with cursor iteration to avoid blocking Redis.
pub async fn list_investigation_ids(
    conn: &mut impl AsyncCommands,
) -> Result<Vec<String>, redis::RedisError> {
    let keys = scan_keys(conn, "ares:blue:inv:*:meta").await?;

    let mut inv_ids = Vec::new();
    for key in keys {
        // Key format: ares:blue:inv:{id}:meta
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() >= 4 {
            inv_ids.push(parts[3].to_string());
        }
    }
    inv_ids.sort();
    Ok(inv_ids)
}

/// List all running blue team investigation IDs by scanning lock keys.
///
/// Uses SCAN with cursor iteration to avoid blocking Redis.
pub async fn list_running_investigations(
    conn: &mut impl AsyncCommands,
) -> Result<HashSet<String>, redis::RedisError> {
    let pattern = format!("{BLUE_LOCK_PREFIX}:*");
    let keys = scan_keys(conn, &pattern).await?;

    let mut running = HashSet::new();
    for key in keys {
        // Key format: ares:blue:lock:{id}
        let parts: Vec<&str> = key.splitn(4, ':').collect();
        if parts.len() >= 4 {
            running.insert(parts[3].to_string());
        }
    }
    Ok(running)
}

/// Resolve the latest blue team investigation ID, preferring running investigations.
pub async fn resolve_latest_investigation(
    conn: &mut impl AsyncCommands,
) -> Result<Option<String>, redis::RedisError> {
    let running_invs = list_running_investigations(conn).await?;
    let all_inv_ids = list_investigation_ids(conn).await?;

    if all_inv_ids.is_empty() {
        return Ok(None);
    }

    // Collect (started_at, inv_id, is_running) tuples
    let mut invs: Vec<(Option<DateTime<Utc>>, String, bool)> = Vec::new();

    for inv_id in &all_inv_ids {
        let meta_key = build_blue_key(inv_id, BLUE_KEY_META);
        let data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
        let started_at = data
            .get("started_at")
            .and_then(|s| {
                // Try JSON-decoding first — meta values are stored as json.dumps(value).
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
        let is_running = running_invs.contains(inv_id);
        invs.push((started_at, inv_id.clone(), is_running));
    }

    // Prefer running investigations
    let mut running: Vec<_> = invs
        .iter()
        .filter(|(_, _, is_running)| *is_running)
        .cloned()
        .collect();
    if !running.is_empty() {
        running.sort_by_key(|x| std::cmp::Reverse(x.0));
        return Ok(Some(running[0].1.clone()));
    }

    // Fall back to latest by started_at
    let mut all: Vec<_> = invs;
    all.sort_by_key(|x| std::cmp::Reverse(x.0));
    Ok(Some(all[0].1.clone()))
}

/// List investigation IDs belonging to a specific operation.
///
/// Reads the Redis SET `ares:blue:op:{operation_id}:investigations` and returns a sorted vector
/// of investigation IDs.
pub async fn list_investigations_for_operation(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<Vec<String>, redis::RedisError> {
    let key = format!("ares:blue:op:{operation_id}:investigations");
    let members: std::collections::HashSet<String> = conn.smembers(&key).await?;
    let mut ids: Vec<String> = members.into_iter().collect();
    ids.sort();
    Ok(ids)
}

/// Delete an investigation and all its associated Redis keys.
///
/// Uses SCAN with cursor iteration to avoid blocking Redis.
pub async fn delete_investigation(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
) -> Result<usize, redis::RedisError> {
    let pattern = format!("{BLUE_KEY_PREFIX}:{investigation_id}:*");
    let mut keys = scan_keys(conn, &pattern).await?;

    // Also delete the lock key
    keys.push(build_blue_lock_key(investigation_id));

    let mut deleted = 0usize;
    for key in &keys {
        let count: usize = conn.del(key).await?;
        deleted += count;
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::mock_redis::MockRedisConnection;
    use redis::AsyncCommands;

    #[tokio::test]
    async fn list_investigation_ids_empty() {
        let mut conn = MockRedisConnection::new();
        let ids = list_investigation_ids(&mut conn).await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_investigation_ids_returns_sorted() {
        let mut conn = MockRedisConnection::new();
        let _: () = conn
            .hset("ares:blue:inv:inv-b:meta", "stage", "triage")
            .await
            .unwrap();
        let _: () = conn
            .hset("ares:blue:inv:inv-a:meta", "stage", "triage")
            .await
            .unwrap();
        let _: () = conn
            .hset("ares:blue:inv:inv-c:meta", "stage", "triage")
            .await
            .unwrap();
        let ids = list_investigation_ids(&mut conn).await.unwrap();
        assert_eq!(ids, vec!["inv-a", "inv-b", "inv-c"]);
    }

    #[tokio::test]
    async fn list_running_investigations_empty() {
        let mut conn = MockRedisConnection::new();
        let running = list_running_investigations(&mut conn).await.unwrap();
        assert!(running.is_empty());
    }

    #[tokio::test]
    async fn list_running_investigations_finds_locks() {
        let mut conn = MockRedisConnection::new();
        let _: () = conn
            .set("ares:blue:lock:inv-1", "2024-01-01T00:00:00Z")
            .await
            .unwrap();
        let _: () = conn
            .set("ares:blue:lock:inv-2", "2024-01-01T00:00:00Z")
            .await
            .unwrap();
        let running = list_running_investigations(&mut conn).await.unwrap();
        assert_eq!(running.len(), 2);
        assert!(running.contains("inv-1"));
        assert!(running.contains("inv-2"));
    }

    #[tokio::test]
    async fn resolve_latest_investigation_empty() {
        let mut conn = MockRedisConnection::new();
        let latest = resolve_latest_investigation(&mut conn).await.unwrap();
        assert!(latest.is_none());
    }

    #[tokio::test]
    async fn resolve_latest_investigation_by_started_at() {
        let mut conn = MockRedisConnection::new();
        let _: () = conn
            .hset(
                "ares:blue:inv:inv-old:meta",
                "started_at",
                "\"2024-01-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn
            .hset(
                "ares:blue:inv:inv-new:meta",
                "started_at",
                "\"2024-06-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let latest = resolve_latest_investigation(&mut conn).await.unwrap();
        assert_eq!(latest, Some("inv-new".to_string()));
    }

    #[tokio::test]
    async fn resolve_latest_investigation_prefers_running() {
        let mut conn = MockRedisConnection::new();
        // inv-old is newer by timestamp but not running
        let _: () = conn
            .hset(
                "ares:blue:inv:inv-old:meta",
                "started_at",
                "\"2024-06-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        // inv-running is older but has a lock
        let _: () = conn
            .hset(
                "ares:blue:inv:inv-running:meta",
                "started_at",
                "\"2024-01-01T00:00:00Z\"",
            )
            .await
            .unwrap();
        let _: () = conn
            .set("ares:blue:lock:inv-running", "2024-01-01T00:00:00Z")
            .await
            .unwrap();
        let latest = resolve_latest_investigation(&mut conn).await.unwrap();
        assert_eq!(latest, Some("inv-running".to_string()));
    }

    #[tokio::test]
    async fn list_investigations_for_operation_empty() {
        let mut conn = MockRedisConnection::new();
        let ids = list_investigations_for_operation(&mut conn, "op-1")
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_investigations_for_operation_returns_sorted() {
        let mut conn = MockRedisConnection::new();
        let key = "ares:blue:op:op-1:investigations";
        let _: () = conn.sadd(key, "inv-b").await.unwrap();
        let _: () = conn.sadd(key, "inv-a").await.unwrap();
        let ids = list_investigations_for_operation(&mut conn, "op-1")
            .await
            .unwrap();
        assert_eq!(ids, vec!["inv-a", "inv-b"]);
    }

    #[tokio::test]
    async fn delete_investigation_removes_keys() {
        let mut conn = MockRedisConnection::new();
        let _: () = conn
            .hset("ares:blue:inv:inv-1:meta", "stage", "triage")
            .await
            .unwrap();
        let _: () = conn
            .hset("ares:blue:inv:inv-1:evidence", "e1", "{}")
            .await
            .unwrap();
        let _: () = conn
            .set("ares:blue:lock:inv-1", "2024-01-01T00:00:00Z")
            .await
            .unwrap();

        let deleted = delete_investigation(&mut conn, "inv-1").await.unwrap();
        assert!(deleted >= 2); // at least meta + lock

        // Verify keys are gone
        let exists: bool = conn.exists("ares:blue:inv:inv-1:meta").await.unwrap();
        assert!(!exists);
        let exists: bool = conn.exists("ares:blue:lock:inv-1").await.unwrap();
        assert!(!exists);
    }
}
