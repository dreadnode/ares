use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use ares_core::state::{self, RedisStateReader};

use crate::redis_conn::connect_redis;
use crate::util::format_duration;

/// Metadata for displaying an operation in the list.
struct OperationListEntry {
    checkpoint_time: Option<DateTime<Utc>>,
    operation_id: String,
    is_running: bool,
    started_at: Option<DateTime<Utc>>,
}

pub(crate) async fn ops_list(redis_url: Option<String>, latest: bool) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if latest {
        let op_id = state::resolve_latest_operation(&mut conn)
            .await?
            .context("No operations found")?;
        println!("{op_id}");
        return Ok(());
    }

    let running_ops = state::list_running_operations(&mut conn).await?;
    let op_ids = state::list_operation_ids(&mut conn).await?;

    if op_ids.is_empty() {
        println!("No operations found");
        return Ok(());
    }

    // Collect metadata for each operation
    let mut ops: Vec<OperationListEntry> = Vec::new();
    for op_id in &op_ids {
        let reader = RedisStateReader::new(op_id.clone());
        let meta = reader.get_meta(&mut conn).await?;
        let is_running = running_ops.contains(op_id);
        ops.push(OperationListEntry {
            checkpoint_time: meta.started_at,
            operation_id: op_id.clone(),
            is_running,
            started_at: meta.started_at,
        });
    }

    // Sort by started_at descending
    ops.sort_by(|a, b| b.checkpoint_time.cmp(&a.checkpoint_time));

    println!("Multi-Agent Operations:");
    println!("{}", "=".repeat(70));

    let now = Utc::now();
    for entry in &ops {
        let status = if entry.is_running { " [running]" } else { "" };
        let mut runtime_str = String::new();
        if let Some(started) = entry.started_at {
            let end_time = if entry.is_running {
                now
            } else {
                entry.checkpoint_time.unwrap_or(now)
            };
            let runtime_seconds = (end_time - started).num_seconds().max(0) as u64;
            runtime_str = format!(" runtime: {}", format_duration(runtime_seconds));
        }
        let time_str = entry
            .checkpoint_time
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {}: checkpoint at {time_str}{status}{runtime_str}",
            entry.operation_id
        );
    }

    Ok(())
}
