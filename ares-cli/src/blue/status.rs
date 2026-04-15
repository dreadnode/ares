use anyhow::Result;
use redis::AsyncCommands;

use super::resolve_investigation_id;
use crate::redis_conn::connect_redis;

pub(crate) async fn blue_status(
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
            println!("Investigation: {inv_id}");
            println!(
                "Status: {}",
                data.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            );
            if let Some(started) = data.get("started_at").and_then(|v| v.as_str()) {
                println!("Started: {started}");
            }
            if let Some(completed) = data.get("completed_at").and_then(|v| v.as_str()) {
                println!("Completed: {completed}");
            }
            if let Some(error) = data.get("error").and_then(|v| v.as_str()) {
                println!("Error: {error}");
            }
        }
        None => println!("Investigation not found: {inv_id}"),
    }

    Ok(())
}
