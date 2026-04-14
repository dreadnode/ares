use anyhow::Result;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;

/// Summary of an investigation for display in the list view.
struct InvestigationSummary {
    id: String,
    status: String,
    started_at: String,
}

pub(crate) async fn blue_list(redis_url: Option<String>, latest: bool) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let status_keys = crate::util::scan_redis_keys(&mut conn, "ares:blue:inv:*:status").await?;

    let mut investigations: Vec<InvestigationSummary> = Vec::new();

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
                investigations.push(InvestigationSummary {
                    id: inv_id,
                    status,
                    started_at: started,
                });
            }
        }
    }

    investigations.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    if latest {
        // Prefer running
        if let Some(running) = investigations.iter().find(|inv| inv.status == "running") {
            println!("{}", running.id);
        } else if let Some(first) = investigations.first() {
            println!("{}", first.id);
        }
        return Ok(());
    }

    if investigations.is_empty() {
        println!("No investigations found");
        return Ok(());
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
