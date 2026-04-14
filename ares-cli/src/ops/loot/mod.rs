mod format;
mod snapshot;

use anyhow::{Context, Result};
use chrono::Utc;
use tracing::warn;

use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) use self::format::print_loot;
pub(crate) use self::snapshot::{loot_snapshot, print_diff, LootSnapshot};

pub(crate) async fn ops_loot(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    json_output: bool,
    watch: u64,
    diff: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let watch_interval = if diff && watch == 0 { 10 } else { watch };

    if watch_interval > 0 {
        loot_watch(&mut conn, &op_id, watch_interval, diff, json_output).await
    } else {
        loot_once(&mut conn, &op_id, json_output).await
    }
}

async fn loot_once(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    json_output: bool,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let state = reader
        .load_state(conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    print_loot(&state, json_output);
    Ok(())
}

async fn loot_watch(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    interval: u64,
    diff_mode: bool,
    json_output: bool,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let mut prev_snapshot: Option<LootSnapshot> = None;

    loop {
        match reader.load_state(conn).await {
            Ok(Some(state)) => {
                let curr = loot_snapshot(&state);

                if diff_mode {
                    if prev_snapshot.is_none() {
                        print_loot(&state, json_output);
                    } else if let Some(prev) = &prev_snapshot {
                        print_diff(prev, &curr);
                    }
                } else {
                    let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
                    if prev_snapshot.is_some() {
                        println!("\n{}", "=".repeat(60));
                    }
                    println!("[watch] Refreshing every {interval}s  |  {ts}");
                    println!("{}", "=".repeat(60));
                    print_loot(&state, json_output);
                }

                prev_snapshot = Some(curr);
            }
            Ok(None) => {
                warn!("No state found for {op_id}, retrying in {interval}s...");
            }
            Err(e) => {
                warn!("Redis fetch failed: {e}");
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}
