use anyhow::Result;

use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) async fn ops_status(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());
    if !reader.exists(&mut conn).await? {
        println!("Operation {op_id} not found");
        return Ok(());
    }

    let meta = reader.get_meta(&mut conn).await?;
    let is_running = reader.is_running(&mut conn).await?;

    // `red_completed_at` is set the instant the red side finishes, before the
    // orchestrator's blue-drain wait (up to 45m). Treat that as completed so the
    // Taskfile watch loop auto-fetches the red report as soon as red is done,
    // rather than blocking on blue.
    let status = if meta.completed_at.is_some() || meta.red_completed_at.is_some() {
        "completed"
    } else if is_running {
        "running"
    } else {
        "stopped"
    };

    println!("Operation: {op_id}");
    println!("Status: {status}");
    if let Some(started) = meta.started_at {
        println!("Started: {}", started.to_rfc3339());
    }
    print_liveness(&mut conn, &op_id, status).await?;
    if meta.has_domain_admin {
        println!("*** DOMAIN ADMIN ACHIEVED ***");
    }
    if meta.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }

    Ok(())
}

/// Report the orchestrator's last heartbeat so `Status: running` can be told
/// apart from `Status: running, but nothing has ticked in 40 minutes`.
async fn print_liveness(
    conn: &mut impl redis::AsyncCommands,
    op_id: &str,
    derived_status: &str,
) -> Result<()> {
    let Some(record) = ares_core::state::read_operation_status(conn, op_id).await? else {
        return Ok(());
    };

    if let Some(changed) = record.status_changed_at {
        println!("Status set: {}", changed.to_rfc3339());
    }

    if derived_status != "running" || !record.is_running() {
        return Ok(());
    }

    match record.heartbeat_age_secs(chrono::Utc::now()) {
        Some(age) => {
            let stale = if record.is_stale(chrono::Utc::now()) {
                "  *** STALE — orchestrator may be wedged ***"
            } else {
                ""
            };
            println!("Last heartbeat: {age}s ago{stale}");
        }
        None => println!("Last heartbeat: unknown (no timestamp on status record)"),
    }

    Ok(())
}
