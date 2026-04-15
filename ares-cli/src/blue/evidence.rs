use std::collections::HashMap;

use anyhow::Result;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;

use super::resolve_investigation_id;

pub(crate) async fn blue_evidence(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
    json_output: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    let evidence_key = format!("ares:blue:inv:{inv_id}:evidence");
    let evidence_data: HashMap<String, String> = conn.hgetall(&evidence_key).await?;

    if evidence_data.is_empty() {
        println!("No evidence found for investigation: {inv_id}");
        return Ok(());
    }

    let mut evidence_items: Vec<serde_json::Value> = Vec::new();
    for value in evidence_data.values() {
        if let Ok(item) = serde_json::from_str::<serde_json::Value>(value) {
            evidence_items.push(item);
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&evidence_items).unwrap_or_default()
        );
        return Ok(());
    }

    println!("Evidence for investigation: {inv_id}");
    println!("Total items: {}", evidence_items.len());
    println!("{}", "-".repeat(60));

    // Group by type
    let mut by_type: HashMap<String, Vec<&serde_json::Value>> = HashMap::new();
    for item in &evidence_items {
        let ev_type = item
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        by_type.entry(ev_type).or_default().push(item);
    }

    let mut types: Vec<String> = by_type.keys().cloned().collect();
    types.sort();

    for ev_type in &types {
        let items = &by_type[ev_type];
        println!("\n{} ({} items):", ev_type.to_uppercase(), items.len());
        for item in items.iter().take(10) {
            let value = item
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let display = if value.is_object() || value.is_array() {
                serde_json::to_string(&value).unwrap_or_default()
            } else {
                value
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| value.to_string())
            };
            if display.len() > 80 {
                let mut end = 80;
                while !display.is_char_boundary(end) {
                    end -= 1;
                }
                println!("  - {}...", &display[..end]);
            } else {
                println!("  - {display}");
            }
        }
        if items.len() > 10 {
            println!("  ... and {} more", items.len() - 10);
        }
    }

    Ok(())
}
