use anyhow::{bail, Result};
use tracing::info;

use ares_core::state;

use crate::redis_conn::connect_redis;

pub(crate) async fn ops_stop(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    // Resolve which operation to stop
    let op_id = if let Some(id) = operation_id {
        id
    } else if latest {
        match state::resolve_latest_operation(&mut conn).await? {
            Some(id) => id,
            None => bail!("No operations found"),
        }
    } else {
        bail!("Provide an operation ID or use --latest");
    };

    // Verify it's actually running
    let running = state::list_running_operations(&mut conn).await?;
    if !running.contains(&op_id) {
        println!("Operation {op_id} is not running");
        return Ok(());
    }

    // Send the stop signal
    state::request_stop_operation(&mut conn, &op_id).await?;
    info!("Stop requested for operation {op_id}");
    println!("Stop signal sent to {op_id} — orchestrator will shut down within ~5s");

    Ok(())
}
