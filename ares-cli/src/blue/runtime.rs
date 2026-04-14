use anyhow::Result;
use chrono::Utc;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;
use crate::util::{format_duration, parse_datetime};

use super::resolve_investigation_id;

pub(crate) async fn blue_runtime(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    let status_key = format!("ares:blue:inv:{inv_id}:status");
    let raw: Option<String> = conn.get(&status_key).await?;

    match raw {
        Some(json_str) => {
            let data: serde_json::Value = serde_json::from_str(&json_str)?;
            let status = data
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            println!("Investigation: {inv_id}");
            println!("Status: {status}");

            let started_at = data.get("started_at").and_then(|v| v.as_str());
            let completed_at = data
                .get("completed_at")
                .and_then(|v| v.as_str())
                .or_else(|| data.get("failed_at").and_then(|v| v.as_str()));

            if let Some(started_str) = started_at {
                if let Ok(start_dt) = parse_datetime(started_str) {
                    println!("Started: {}", start_dt.to_rfc3339());

                    let elapsed = if let Some(end_str) = completed_at {
                        parse_datetime(end_str)
                            .ok()
                            .map(|end_dt| (end_dt - start_dt).num_seconds().max(0) as u64)
                    } else if status == "running" {
                        Some((Utc::now() - start_dt).num_seconds().max(0) as u64)
                    } else {
                        None
                    };

                    if let Some(secs) = elapsed {
                        if secs > 0 {
                            println!("Duration: {}", format_duration(secs));
                        }
                    }
                }
            }

            if let Some(completed) = completed_at {
                println!("Completed: {completed}");
            }
        }
        None => {
            println!("Investigation not found: {inv_id}");
        }
    }

    Ok(())
}
