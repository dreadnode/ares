use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::Serialize;

use crate::redis_conn::connect_redis;

/// Summary of an investigation for display in the list view.
#[derive(Serialize)]
struct InvestigationSummary {
    id: String,
    status: String,
    started_at: String,
}

pub(crate) async fn blue_list(
    redis_url: Option<String>,
    latest: bool,
    operation_id: Option<String>,
    json: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if latest {
        let id = ares_core::state::resolve_latest_investigation(&mut conn)
            .await?
            .context("No investigations found")?;
        println!("{id}");
        return Ok(());
    }

    let inv_ids = if let Some(ref op_id) = operation_id {
        let ids = ares_core::state::list_investigations_for_operation(&mut conn, op_id).await?;
        if ids.is_empty() {
            if json {
                println!("[]");
            } else {
                println!("No investigations found for operation: {op_id}");
            }
            return Ok(());
        }
        ids
    } else {
        ares_core::state::list_investigation_ids(&mut conn).await?
    };

    let mut investigations: Vec<InvestigationSummary> = Vec::new();

    for inv_id in inv_ids {
        let status_key = format!("ares:blue:inv:{inv_id}:status");
        let raw: Option<String> = conn.get(status_key).await?;
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
                investigations.push(InvestigationSummary {
                    id: inv_id,
                    status,
                    started_at: started,
                });
            }
        }
    }

    investigations.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    if investigations.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("No investigations found");
        }
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&investigations)?);
        return Ok(());
    }

    if let Some(ref op_id) = operation_id {
        println!("Investigations for operation: {op_id}");
        println!();
    }

    println!(
        "{:<25} {:<12} {:<25}",
        "Investigation ID", "Status", "Started"
    );
    println!("{}", "-".repeat(65));
    for inv in &investigations {
        let started_display = if inv.started_at.len() > 25 {
            &inv.started_at[..25]
        } else {
            &inv.started_at
        };
        println!("{:<25} {:<12} {started_display:<25}", inv.id, inv.status);
    }

    Ok(())
}
