mod delete;
mod evidence;
mod list;
mod operation;
mod report;
mod runtime;
mod status;
mod submit;
mod techniques;
mod triage;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::info;

use crate::cli::BlueCommands;

/// Metadata for an investigation candidate when resolving the latest.
struct InvestigationCandidate {
    id: String,
    status: String,
    started_at: String,
}

pub(crate) async fn run_blue(cmd: BlueCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        BlueCommands::List { latest } => list::blue_list(redis_url, latest).await,
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
        } => operation::blue_operation_status(redis_url, operation_id, latest, watch).await,
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
            submit::blue_submit(
                redis_url,
                alert_json,
                investigation_id,
                model,
                max_steps,
                multi_agent,
                !no_auto_route,
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
            submit::blue_from_operation(
                redis_url,
                operation_id,
                latest,
                model,
                max_steps,
                grafana_url,
                grafana_api_key,
            )
            .await
        }
    }
}

pub(super) async fn resolve_latest_investigation(
    conn: &mut redis::aio::MultiplexedConnection,
) -> Result<Option<String>> {
    let status_keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:blue:inv:*:status")
        .query_async(conn)
        .await?;

    let mut candidates: Vec<InvestigationCandidate> = Vec::new();

    for key in &status_keys {
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let inv_id = parts[3].to_string();

        let raw: Option<String> = conn.get(key).await?;
        if let Some(json_str) = raw {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                let status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let started = data
                    .get("started_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                candidates.push(InvestigationCandidate {
                    id: inv_id,
                    status,
                    started_at: started,
                });
            }
        }
    }

    if candidates.is_empty() {
        return Ok(None);
    }

    // Sort by started_at descending
    candidates.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    // Prefer running investigations
    if let Some(running) = candidates.iter().find(|c| c.status == "running") {
        return Ok(Some(running.id.clone()));
    }

    Ok(candidates.first().map(|c| c.id.clone()))
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
