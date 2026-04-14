//! Blue team investigation listing, resolution, and deletion.

use std::collections::{HashMap, HashSet};

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
    let mut invs: Vec<(Option<String>, String, bool)> = Vec::new();

    for inv_id in &all_inv_ids {
        let meta_key = build_blue_key(inv_id, BLUE_KEY_META);
        let data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
        let started_at = data.get("started_at").and_then(|s| {
            // Try JSON-decoding first (Python stores as json.dumps(value))
            if let Ok(serde_json::Value::String(inner)) =
                serde_json::from_str::<serde_json::Value>(s)
            {
                Some(inner)
            } else if !s.is_empty() && s != "null" {
                Some(s.clone())
            } else {
                None
            }
        });
        let is_running = running_invs.contains(inv_id);
        invs.push((started_at, inv_id.clone(), is_running));
    }

    // Prefer running investigations
    let running: Vec<_> = invs
        .iter()
        .filter(|(_, _, is_running)| *is_running)
        .collect();
    if !running.is_empty() {
        return Ok(Some(pick_latest_blue(&running)));
    }

    // Fall back to latest by started_at
    let all: Vec<_> = invs.iter().collect();
    Ok(Some(pick_latest_blue(&all)))
}

pub(crate) fn pick_latest_blue(items: &[&(Option<String>, String, bool)]) -> String {
    // Prefer items with a timestamp, sort descending
    let mut with_time: Vec<_> = items.iter().filter(|(t, _, _)| t.is_some()).collect();
    if !with_time.is_empty() {
        with_time.sort_by(|a, b| b.0.cmp(&a.0));
        return with_time[0].1.clone();
    }
    // Fallback: sort by inv_id descending
    let mut by_id: Vec<_> = items.to_vec();
    by_id.sort_by(|a, b| b.1.cmp(&a.1));
    by_id[0].1.clone()
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
