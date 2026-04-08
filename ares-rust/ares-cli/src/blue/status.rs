use anyhow::{Context, Result};
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;

pub(crate) async fn blue_status(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let inv_id = if latest {
        let status_keys: Vec<String> = redis::cmd("KEYS")
            .arg("ares:blue:inv:*:status")
            .query_async(&mut conn)
            .await?;

        let mut candidates: Vec<(String, String)> = Vec::new();
        for key in &status_keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() < 4 {
                continue;
            }
            let id = parts[3].to_string();
            let raw: Option<String> = conn.get(key).await?;
            let started = raw
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| {
                    v.get("started_at")
                        .and_then(|s| s.as_str().map(String::from))
                })
                .unwrap_or_default();
            candidates.push((id, started));
        }
        candidates.sort_by(|a, b| b.1.cmp(&a.1));
        candidates
            .first()
            .map(|(id, _)| id.clone())
            .context("No investigations found")?
    } else {
        investigation_id.context("Either investigation_id or --latest is required")?
    };

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
