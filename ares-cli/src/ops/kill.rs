use anyhow::Result;
use tracing::info;

use ares_core::state;

use crate::redis_conn::connect_redis;

/// Kill (stop + delete) running operations.
///
/// Default behaviour: kill all running operations **except** the most recent.
/// `--all`: kill every running operation.
/// With an explicit `operation_id`: kill only that one.
pub(crate) async fn ops_kill(
    redis_url: Option<String>,
    operation_id: Option<String>,
    all: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    // Single-operation kill
    if let Some(ref id) = operation_id {
        kill_one(&mut conn, id).await?;
        return Ok(());
    }

    let running_set = state::list_running_operations(&mut conn).await?;
    if running_set.is_empty() {
        println!("No running operations found");
        return Ok(());
    }

    let mut running: Vec<String> = running_set.into_iter().collect();
    running.sort();

    println!("Found {} running operation(s)", running.len());

    // Determine which operations to kill
    let to_kill: Vec<&String> = if all {
        running.iter().collect()
    } else {
        // Keep the latest (last in the sorted list)
        if running.len() <= 1 {
            println!(
                "Only 1 running operation ({}) — use --all to kill it",
                running[0]
            );
            return Ok(());
        }
        let latest = running.last().unwrap();
        println!("Keeping latest: {latest}");
        running.iter().filter(|id| *id != latest).collect()
    };

    for id in &to_kill {
        kill_one(&mut conn, id).await?;
    }

    println!("Killed {} operation(s)", to_kill.len());
    Ok(())
}

async fn kill_one(conn: &mut redis::aio::MultiplexedConnection, op_id: &str) -> Result<()> {
    // Stop first (if running), then delete
    let running = state::list_running_operations(conn).await?;
    if running.contains(op_id) {
        state::request_stop_operation(conn, op_id).await?;
        info!("Stopped {op_id}");
    }
    let deleted = state::delete_operation(conn, op_id).await?;
    info!("Deleted {op_id} ({deleted} keys)");
    println!("  killed: {op_id}");
    Ok(())
}
