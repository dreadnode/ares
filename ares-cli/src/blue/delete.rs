use std::collections::HashSet;

use anyhow::Result;
use chrono::Utc;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;
use crate::util::{parse_datetime, scan_redis_keys};

pub(crate) async fn blue_delete(
    redis_url: Option<String>,
    investigation_id: String,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if !force {
        eprint!("Delete investigation {investigation_id} and all data? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Aborted");
            return Ok(());
        }
    }

    let pattern = format!("ares:blue:inv:{investigation_id}:*");
    let keys = scan_redis_keys(&mut conn, &pattern).await?;

    let mut deleted = 0usize;
    for key in &keys {
        let count: usize = conn.del(key).await?;
        deleted += count;
    }

    let removed: i64 = conn
        .srem("ares:blue:active_investigations", &investigation_id)
        .await?;
    deleted += removed as usize;

    if deleted == 0 {
        println!("No data found for investigation: {investigation_id}");
    } else {
        println!("Deleted {deleted} keys for investigation: {investigation_id}");
    }

    Ok(())
}

pub(crate) async fn blue_delete_operation(
    redis_url: Option<String>,
    operation_id: String,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let op_inv_key = format!("ares:blue:op:{operation_id}:investigations");
    let inv_ids_vec =
        ares_core::state::list_investigations_for_operation(&mut conn, &operation_id).await?;
    let inv_ids: HashSet<String> = inv_ids_vec.into_iter().collect();

    if inv_ids.is_empty() {
        println!("No investigations found for operation: {operation_id}");
        return Ok(());
    }

    println!("Operation: {operation_id}");
    println!("Investigations to delete: {}", inv_ids.len());
    for inv_id in &inv_ids {
        println!("  - {inv_id}");
    }

    if !force {
        eprint!(
            "\nDelete operation {operation_id} and {} investigation(s)? [y/N] ",
            inv_ids.len()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Aborted");
            return Ok(());
        }
    }

    let mut total_deleted = 0usize;
    for inv_id in &inv_ids {
        let pattern = format!("ares:blue:inv:{inv_id}:*");
        let keys = scan_redis_keys(&mut conn, &pattern).await?;
        for key in &keys {
            let count: usize = conn.del(key).await?;
            total_deleted += count;
        }
    }

    if !inv_ids.is_empty() {
        let inv_list: Vec<&String> = inv_ids.iter().collect();
        let removed: i64 = conn
            .srem("ares:blue:active_investigations", inv_list.as_slice())
            .await?;
        total_deleted += removed as usize;
    }

    let _: usize = conn.del(&op_inv_key).await?;
    total_deleted += 1;

    println!("\nDeleted {total_deleted} keys");
    println!(
        "Operation {operation_id} and {} investigation(s) deleted",
        inv_ids.len()
    );

    Ok(())
}

pub(crate) async fn blue_cleanup(
    redis_url: Option<String>,
    max_age_hours: u64,
    all: bool,
    dry_run: bool,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if all {
        let inv_keys = scan_redis_keys(&mut conn, "ares:blue:inv:*").await?;
        let op_keys = scan_redis_keys(&mut conn, "ares:blue:op:*").await?;
        let active_exists: bool = conn.exists("ares:blue:active_investigations").await?;
        let queue_len: i64 = conn.llen("ares:blue:investigations").await?;

        println!("Found {} investigation keys", inv_keys.len());
        println!("Found {} operation tracking keys", op_keys.len());
        println!("Queue length: {queue_len}");

        if dry_run {
            println!("(dry run - no changes made)");
            return Ok(());
        }

        if !force {
            eprint!("Delete ALL blue team investigations? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                println!("Aborted");
                return Ok(());
            }
        }

        let mut deleted = 0usize;
        for key in &inv_keys {
            let count: usize = conn.del(key).await?;
            deleted += count;
        }
        for key in &op_keys {
            let count: usize = conn.del(key).await?;
            deleted += count;
        }
        if active_exists {
            let count: usize = conn.del("ares:blue:active_investigations").await?;
            deleted += count;
        }
        if queue_len > 0 {
            let _: usize = conn.del("ares:blue:investigations").await?;
            deleted += 1;
        }

        println!("Deleted {deleted} keys");
        println!("All blue team investigations cleared");
        return Ok(());
    }

    // Selective cleanup: only completed/failed older than max_age_hours
    let cutoff = Utc::now().timestamp() - (max_age_hours as i64 * 3600);

    let status_keys = scan_redis_keys(&mut conn, "ares:blue:inv:*:status").await?;

    let mut to_delete: Vec<String> = Vec::new();

    for key in &status_keys {
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let inv_id = parts[3].to_string();

        let raw: Option<String> = conn.get(key).await?;
        let Some(json_str) = raw else { continue };

        let data: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("");

        if status != "completed" && status != "failed" {
            continue;
        }

        let completed_str = data
            .get("completed_at")
            .and_then(|v| v.as_str())
            .or_else(|| data.get("failed_at").and_then(|v| v.as_str()));

        if let Some(ts_str) = completed_str {
            if let Ok(dt) = parse_datetime(ts_str) {
                if dt.timestamp() < cutoff {
                    to_delete.push(inv_id);
                }
            }
        }
    }

    if to_delete.is_empty() {
        println!("No investigations older than {max_age_hours} hours to clean up");
        return Ok(());
    }

    println!("Found {} investigation(s) to clean up:", to_delete.len());
    for inv_id in &to_delete {
        println!("  - {inv_id}");
    }

    if dry_run {
        println!("(dry run - no changes made)");
        return Ok(());
    }

    let mut total_deleted = 0usize;
    for inv_id in &to_delete {
        let pattern = format!("ares:blue:inv:{inv_id}:*");
        let keys = scan_redis_keys(&mut conn, &pattern).await?;
        for key in &keys {
            let count: usize = conn.del(key).await?;
            total_deleted += count;
        }
    }

    if !to_delete.is_empty() {
        let inv_refs: Vec<&str> = to_delete.iter().map(|s| s.as_str()).collect();
        let removed: i64 = conn
            .srem("ares:blue:active_investigations", inv_refs.as_slice())
            .await?;
        total_deleted += removed as usize;
    }

    println!(
        "Deleted {total_deleted} keys from {} investigation(s)",
        to_delete.len()
    );

    Ok(())
}
