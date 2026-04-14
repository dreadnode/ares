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

    let status = if meta.completed_at.is_some() {
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
    if meta.has_domain_admin {
        println!("*** DOMAIN ADMIN ACHIEVED ***");
    }
    if meta.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }

    Ok(())
}
