use anyhow::Result;
use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use tracing::{info, warn};

use ares_core::state;

use crate::redis_conn::connect_redis;

pub(crate) async fn ops_delete(
    redis_url: Option<String>,
    operation_id: String,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let meta_key = state::build_key(&operation_id, state::KEY_META);
    let exists: bool = conn.exists(&meta_key).await?;

    if !exists {
        warn!("Operation {operation_id} not found");
        return Ok(());
    }

    if !force {
        eprint!("Delete operation {operation_id}? [y/N]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Cancelled");
            return Ok(());
        }
    }

    let deleted = state::delete_operation(&mut conn, &operation_id).await?;
    info!("Deleted operation {operation_id} ({deleted} keys removed)");

    Ok(())
}

pub(crate) async fn ops_cleanup(redis_url: Option<String>, max_age_hours: u64) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours as i64);

    let all_op_ids = state::list_operation_ids(&mut conn).await?;
    let running_ops = state::list_running_operations(&mut conn).await?;

    let mut cleaned = 0u32;
    for op_id in &all_op_ids {
        // Never clean up running operations
        if running_ops.contains(op_id) {
            continue;
        }

        // Parse timestamp from operation ID format: op-YYYYMMDD-HHMMSS
        let op_time = parse_operation_timestamp(op_id);
        match op_time {
            Some(ts) if ts < cutoff => {
                let deleted = state::delete_operation(&mut conn, op_id).await?;
                info!("Cleaned up {op_id} ({deleted} keys)");
                cleaned += 1;
            }
            Some(_) => {} // Not old enough
            None => {
                warn!("Could not parse timestamp from operation ID: {op_id}, skipping");
            }
        }
    }

    if cleaned == 0 {
        println!("No operations older than {max_age_hours}h to clean up");
    } else {
        println!("Cleaned up {cleaned} operation(s)");
    }

    Ok(())
}

/// Parse a UTC timestamp from an operation ID with format `op-YYYYMMDD-HHMMSS`.
pub(crate) fn parse_operation_timestamp(op_id: &str) -> Option<DateTime<Utc>> {
    // Expected format: op-YYYYMMDD-HHMMSS (e.g., op-20250128-123456)
    if !op_id.starts_with("op-") || op_id.len() < 18 {
        return None;
    }
    let date_part = &op_id[3..11]; // YYYYMMDD
    let time_part = &op_id[12..18]; // HHMMSS
    let datetime_str = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &date_part[..4],
        &date_part[4..6],
        &date_part[6..8],
        &time_part[..2],
        &time_part[2..4],
        &time_part[4..6],
    );
    datetime_str.parse::<DateTime<Utc>>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_operation_timestamp_valid() {
        let ts = parse_operation_timestamp("op-20250128-123456").unwrap();
        assert_eq!(
            ts.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2025-01-28 12:34:56"
        );
    }

    #[test]
    fn test_parse_operation_timestamp_invalid() {
        assert!(parse_operation_timestamp("not-an-op-id").is_none());
        assert!(parse_operation_timestamp("op-bad").is_none());
        assert!(parse_operation_timestamp("").is_none());
    }

    #[test]
    fn test_parse_operation_timestamp_with_suffix() {
        // Some IDs may have extra suffix after the timestamp
        let ts = parse_operation_timestamp("op-20260407-091000-abc123").unwrap();
        assert_eq!(
            ts.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-04-07 09:10:00"
        );
    }
}
