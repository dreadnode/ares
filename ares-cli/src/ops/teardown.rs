//! `ares ops teardown` — reverse the persistent mutations an operation made
//! against its targets, using the operation's mutation journal.
//!
//! Distinct from `ops cleanup`, which is Redis-key retention GC. This command
//! touches the target range; `--dry-run` prints the plan without changing
//! anything.

use anyhow::{bail, Result};

use ares_core::state;

use crate::orchestrator::cleanup::{run_teardown, TeardownOptions};
use crate::redis_conn::connect_redis;

pub(crate) async fn ops_teardown(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    dry_run: bool,
    only: Option<String>,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

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

    let report = run_teardown(&mut conn, &op_id, &TeardownOptions { dry_run, only }).await?;

    // Non-zero exit when a revert we attempted failed, so `task ec2:teardown`
    // and CI can gate on it.
    if !dry_run && !report.is_clean() {
        bail!(
            "teardown left {} un-reverted mutation(s) for {op_id} — see FAIL entries above",
            report.failed
        );
    }
    Ok(())
}
