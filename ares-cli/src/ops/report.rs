use anyhow::{Context, Result};

use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) async fn ops_report(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    regenerate: bool,
    output_dir: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());

    // Check for cached report first (unless regenerating)
    if !regenerate {
        if let Ok(Some(cached)) = reader.get_report(&mut conn).await {
            let report_path = save_report(&output_dir, &op_id, &cached)?;
            println!("Report saved to {report_path} (cached)");
            return Ok(());
        }
    }

    // Generate report from state using tera templates
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let timeline = reader.get_timeline(&mut conn).await.unwrap_or_default();
    let techniques = reader.get_techniques(&mut conn).await.unwrap_or_default();
    let is_running = reader.is_running(&mut conn).await.unwrap_or(false);

    let generator = ares_core::reports::RedTeamReportGenerator::new()
        .context("Failed to initialize report template engine")?;
    let report = generator
        .generate_comprehensive(&state, &timeline, &techniques)
        .or_else(|_| generator.generate_summary(&state, &timeline, &techniques, is_running))
        .context("Failed to render report template")?;
    let report_path = save_report(&output_dir, &op_id, &report)?;
    println!("Report saved to {report_path}");

    Ok(())
}

fn save_report(output_dir: &str, op_id: &str, report: &str) -> Result<String> {
    let dir = format!("{output_dir}/red");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create report directory: {dir}"))?;
    let path = format!("{dir}/{op_id}.md");
    std::fs::write(&path, report).with_context(|| format!("Failed to write report to {path}"))?;
    Ok(path)
}
