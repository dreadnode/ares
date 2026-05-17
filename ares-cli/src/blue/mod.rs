mod delete;
mod evidence;
mod list;
mod operation;
mod report;
mod runtime;
mod status;
pub(super) mod submit;
mod techniques;
mod triage;
mod watch;

use anyhow::{Context, Result};
use tracing::info;

use crate::cli::BlueCommands;

pub(crate) async fn run_blue(cmd: BlueCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        BlueCommands::List {
            latest,
            operation_id,
            json,
        } => list::blue_list(redis_url, latest, operation_id, json).await,
        BlueCommands::Status {
            investigation_id,
            latest,
        } => status::blue_status(redis_url, investigation_id, latest).await,
        BlueCommands::Evidence {
            investigation_id,
            latest,
            json,
        } => evidence::blue_evidence(redis_url, investigation_id, latest, json).await,
        BlueCommands::Techniques {
            investigation_id,
            latest,
        } => techniques::blue_techniques(redis_url, investigation_id, latest).await,
        BlueCommands::Runtime {
            investigation_id,
            latest,
        } => runtime::blue_runtime(redis_url, investigation_id, latest).await,
        BlueCommands::TriageStatus {
            investigation_id,
            latest,
            json,
        } => triage::blue_triage_status(redis_url, investigation_id, latest, json).await,
        BlueCommands::OperationStatus {
            operation_id,
            latest,
            watch,
            json,
        } => operation::blue_operation_status(redis_url, operation_id, latest, watch, json).await,
        BlueCommands::Report {
            operation_id,
            investigation_id,
            latest,
            regenerate,
            output_dir,
        } => {
            report::blue_report(
                redis_url,
                operation_id,
                investigation_id,
                latest,
                regenerate,
                output_dir,
            )
            .await
        }
        BlueCommands::Delete {
            investigation_id,
            force,
        } => delete::blue_delete(redis_url, investigation_id, force).await,
        BlueCommands::DeleteOperation {
            operation_id,
            force,
        } => delete::blue_delete_operation(redis_url, operation_id, force).await,
        BlueCommands::Cleanup {
            max_age_hours,
            all,
            dry_run,
            force,
        } => delete::blue_cleanup(redis_url, max_age_hours, all, dry_run, force).await,
        BlueCommands::Submit {
            alert_json,
            investigation_id,
            model,
            max_steps,
            multi_agent,
            no_auto_route,
            grafana_url,
            grafana_api_key,
        } => {
            submit::blue_submit(submit::BlueSubmitParams {
                redis_url,
                alert_json,
                investigation_id,
                model,
                max_steps,
                multi_agent,
                auto_route: !no_auto_route,
                grafana_url,
                grafana_api_key,
            })
            .await
        }
        BlueCommands::Watch {
            poll_interval,
            model,
            max_steps,
            grafana_url,
            grafana_api_key,
        } => {
            watch::blue_watch(
                redis_url,
                poll_interval,
                model,
                max_steps,
                grafana_url,
                grafana_api_key,
            )
            .await
        }
        BlueCommands::FromOperation {
            operation_id,
            latest,
            model,
            max_steps,
            grafana_url,
            grafana_api_key,
        } => {
            submit::blue_from_operation(submit::BlueFromOperationParams {
                redis_url,
                operation_id,
                latest,
                model,
                max_steps,
                grafana_url,
                grafana_api_key,
            })
            .await
        }
    }
}

pub(super) async fn resolve_latest_investigation(
    conn: &mut redis::aio::MultiplexedConnection,
) -> Result<Option<String>> {
    let id = ares_core::state::resolve_latest_investigation(conn)
        .await
        .context("Failed to resolve latest investigation from Redis")?;
    Ok(id)
}

pub(super) async fn resolve_investigation_id(
    conn: &mut redis::aio::MultiplexedConnection,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<String> {
    if let Some(id) = investigation_id {
        return Ok(id);
    }
    if latest {
        let id = resolve_latest_investigation(conn)
            .await?
            .context("No investigations found")?;
        info!("Using latest investigation: {id}");
        return Ok(id);
    }
    anyhow::bail!("Either investigation_id or --latest is required")
}
