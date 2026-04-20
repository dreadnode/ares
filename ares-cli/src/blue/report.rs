use std::collections::HashMap;

use anyhow::{Context, Result};

use ares_core::reports::BlueTeamReportGenerator;
use ares_core::state::BlueStateReader;

use crate::redis_conn::connect_redis;

pub(crate) async fn blue_report(
    redis_url: Option<String>,
    operation_id: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
    _regenerate: bool,
    output_dir: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let generator = BlueTeamReportGenerator::new()
        .context("Failed to initialize blue team report template engine")?;

    // Determine what to generate: operation report or single investigation report
    if let Some(ref inv_id) = investigation_id {
        // Single investigation report (no operation context)
        let report = generate_investigation_report(&mut conn, &generator, inv_id).await?;
        let path = save_investigation_report(&output_dir, None, inv_id, &report)?;
        println!("Investigation report saved to {path}");
    } else if let Some(ref op_id) = operation_id {
        // Operation report (multi-investigation)
        let report = generate_operation_report(&mut conn, &generator, op_id).await?;
        let path = save_operation_report(&output_dir, op_id, &report)?;
        println!("Operation report saved to {path}");
    } else if latest {
        // Try operation first, fall back to investigation
        let op_id = ares_core::state::resolve_latest_operation(&mut conn).await?;
        if let Some(ref op_id) = op_id {
            // Check if there are blue team investigations for this operation
            let inv_ids =
                ares_core::state::list_investigations_for_operation(&mut conn, op_id).await?;
            if !inv_ids.is_empty() {
                let report = generate_operation_report(&mut conn, &generator, op_id).await?;
                let path = save_operation_report(&output_dir, op_id, &report)?;
                println!("Operation report saved to {path}");
                return Ok(());
            }
        }
        // Fall back to latest investigation
        let inv_id = super::resolve_latest_investigation(&mut conn)
            .await?
            .context("No investigations or operations found")?;
        let report = generate_investigation_report(&mut conn, &generator, &inv_id).await?;
        let path = save_investigation_report(&output_dir, None, &inv_id, &report)?;
        println!("Investigation report saved to {path}");
    } else {
        anyhow::bail!("Either --operation-id, --investigation-id, or --latest is required");
    }

    Ok(())
}

async fn generate_investigation_report(
    conn: &mut redis::aio::MultiplexedConnection,
    generator: &BlueTeamReportGenerator,
    investigation_id: &str,
) -> Result<String> {
    let reader = BlueStateReader::new(investigation_id.to_string());
    let state = reader
        .load_state(conn)
        .await?
        .with_context(|| format!("No state found for investigation: {investigation_id}"))?;
    let queries = reader.get_queries(conn).await.unwrap_or_default();

    generator
        .generate_investigation(&state, &queries)
        .context("Failed to render investigation report")
}

async fn generate_operation_report(
    conn: &mut redis::aio::MultiplexedConnection,
    generator: &BlueTeamReportGenerator,
    operation_id: &str,
) -> Result<String> {
    let inv_ids = ares_core::state::list_investigations_for_operation(conn, operation_id).await?;

    if inv_ids.is_empty() {
        anyhow::bail!("No investigations found for operation: {operation_id}");
    }

    let mut states = Vec::new();
    let mut queries_by_inv = HashMap::new();

    for inv_id in &inv_ids {
        let reader = BlueStateReader::new(inv_id.clone());
        if let Ok(Some(state)) = reader.load_state(conn).await {
            let queries = reader.get_queries(conn).await.unwrap_or_default();
            queries_by_inv.insert(inv_id.clone(), queries);
            states.push(state);
        }
    }

    generator
        .generate_from_states(operation_id, &states, &queries_by_inv)
        .context("Failed to render operation report")
}

/// Save a blue team operation report under `{output_dir}/blue/`.
fn save_operation_report(output_dir: &str, op_id: &str, report: &str) -> Result<String> {
    let dir = format!("{output_dir}/blue");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create report directory: {dir}"))?;
    let path = format!("{dir}/{op_id}.md");
    std::fs::write(&path, report).with_context(|| format!("Failed to write report to {path}"))?;
    Ok(path)
}

/// Save a blue team investigation report.
///
/// When `op_id` is provided, saves under `{output_dir}/blue/{op_id}/`.
/// Otherwise saves under `{output_dir}/blue/investigations/`.
fn save_investigation_report(
    output_dir: &str,
    op_id: Option<&str>,
    inv_id: &str,
    report: &str,
) -> Result<String> {
    let dir = match op_id {
        Some(op) => format!("{output_dir}/blue/{op}"),
        None => format!("{output_dir}/blue/investigations"),
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create report directory: {dir}"))?;
    let path = format!("{dir}/{inv_id}.md");
    std::fs::write(&path, report).with_context(|| format!("Failed to write report to {path}"))?;
    Ok(path)
}
