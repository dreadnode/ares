use anyhow::Result;

use ares_core::state::{self, RedisStateReader};

use crate::redis_conn::connect_redis;

pub(crate) async fn ops_queue(redis_url: Option<String>) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let running_ops = state::list_running_operations(&mut conn).await?;
    let op_ids = state::list_operation_ids(&mut conn).await?;

    if op_ids.is_empty() {
        println!("No operations found");
        return Ok(());
    }

    println!("Multi-Agent Operations (Redis)");
    println!("{}", "=".repeat(70));

    for op_id in &op_ids {
        let reader = RedisStateReader::new(op_id.clone());
        let meta = reader.get_meta(&mut conn).await?;
        let is_running = running_ops.contains(op_id);
        let vulns = reader.get_vulnerabilities(&mut conn).await?;
        let exploited = reader.get_exploited_vulnerabilities(&mut conn).await?;

        let status = if is_running { "running" } else { "idle" };
        let checkpoint = meta
            .started_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string());

        let da = if meta.has_domain_admin { "yes" } else { "no" };
        let gt = if meta.has_golden_ticket { "yes" } else { "no" };

        println!("  {op_id} [{status}] checkpoint: {checkpoint}");
        println!(
            "    domain_admin: {da}  golden_ticket: {gt}  vulns: {}  exploited: {}",
            vulns.len(),
            exploited.len()
        );
    }

    Ok(())
}

pub(crate) async fn ops_claim_next(redis_url: Option<String>, timeout: u64) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let result: Option<(String, String)> = redis::cmd("BRPOP")
        .arg("ares:operations")
        .arg(timeout as i64)
        .query_async(&mut conn)
        .await?;

    if let Some((_queue, payload)) = result {
        println!("{payload}");
    }

    Ok(())
}
