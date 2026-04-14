use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use ares_core::state;

use crate::redis_conn::connect_redis;
use crate::util::{format_duration, parse_datetime};

pub(crate) async fn blue_operation_status(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    watch: u64,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let op_id = if latest {
        state::resolve_latest_operation(&mut conn)
            .await?
            .context("No red team operations found")?
    } else {
        operation_id.context("Either operation_id or --latest is required")?
    };

    if watch > 0 {
        loop {
            // Clear screen
            print!("\x1B[2J\x1B[H");
            let all_done = blue_operation_status_once(&mut conn, &op_id).await?;
            if all_done {
                println!("\nAll investigations complete.");
                break;
            }
            println!("\nRefreshing in {watch}s... (Ctrl+C to stop)");
            tokio::time::sleep(tokio::time::Duration::from_secs(watch)).await;
        }
    } else {
        blue_operation_status_once(&mut conn, &op_id).await?;
    }

    Ok(())
}

/// Show status for all investigations in an operation. Returns true if all done.
async fn blue_operation_status_once(
    conn: &mut redis::aio::MultiplexedConnection,
    operation_id: &str,
) -> Result<bool> {
    let op_inv_key = format!("ares:blue:op:{operation_id}:investigations");
    let inv_ids: HashSet<String> = conn.smembers(&op_inv_key).await?;

    if inv_ids.is_empty() {
        println!("No investigations found for operation: {operation_id}");
        return Ok(true);
    }

    let mut status_counts: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut triage_counts: HashMap<String, i64> = HashMap::new();
    let mut earliest_start: Option<DateTime<Utc>> = None;
    let mut latest_end: Option<DateTime<Utc>> = None;

    let mut sorted_ids: Vec<String> = inv_ids.iter().cloned().collect();
    sorted_ids.sort();

    for inv_id in &sorted_ids {
        let status_key = format!("ares:blue:inv:{inv_id}:status");
        let status_json: Option<String> = conn.get(&status_key).await?;

        if let Some(json_str) = status_json {
            if let Ok(mut data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                data.as_object_mut().map(|obj| {
                    obj.insert(
                        "investigation_id".to_string(),
                        serde_json::Value::String(inv_id.clone()),
                    )
                });

                let inv_status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Track timestamps
                if let Some(started) = data.get("started_at").and_then(|v| v.as_str()) {
                    if let Ok(dt) = parse_datetime(started) {
                        if earliest_start.is_none_or(|prev| dt < prev) {
                            earliest_start = Some(dt);
                        }
                    }
                }

                let completed_at = data
                    .get("completed_at")
                    .and_then(|v| v.as_str())
                    .or_else(|| data.get("failed_at").and_then(|v| v.as_str()));
                if let Some(end_str) = completed_at {
                    if let Ok(dt) = parse_datetime(end_str) {
                        if latest_end.is_none_or(|prev| dt > prev) {
                            latest_end = Some(dt);
                        }
                    }
                }

                // Check triage for escalated/routed/completed
                if matches!(inv_status.as_str(), "escalated" | "routed" | "completed") {
                    let triage_key = format!("ares:blue:inv:{inv_id}:triage:decision");
                    let triage_data: Option<String> = conn.get(&triage_key).await?;
                    if let Some(triage_str) = triage_data {
                        if let Ok(triage) = serde_json::from_str::<serde_json::Value>(&triage_str) {
                            let decision = triage
                                .get("decision")
                                .and_then(|v| v.as_str())
                                .unwrap_or("pending")
                                .to_string();
                            *triage_counts.entry(decision).or_insert(0) += 1;
                        }
                    }
                }

                status_counts.entry(inv_status).or_default().push(data);
            }
        } else {
            status_counts
                .entry("submitted".to_string())
                .or_default()
                .push(serde_json::json!({"investigation_id": inv_id}));
        }
    }

    // Calculate duration
    let now = Utc::now();
    let elapsed = if let Some(start) = earliest_start {
        let has_running =
            status_counts.contains_key("running") || status_counts.contains_key("submitted");
        if has_running {
            (now - start).num_seconds().max(0) as u64
        } else if let Some(end) = latest_end {
            (end - start).num_seconds().max(0) as u64
        } else {
            0
        }
    } else {
        0
    };

    let total = sorted_ids.len();
    let running = status_counts.get("running").map_or(0, |v| v.len());
    let completed = status_counts.get("completed").map_or(0, |v| v.len());
    let escalated = status_counts.get("escalated").map_or(0, |v| v.len());
    let routed = status_counts.get("routed").map_or(0, |v| v.len());
    let failed = status_counts.get("failed").map_or(0, |v| v.len());
    let submitted = status_counts.get("submitted").map_or(0, |v| v.len());

    println!("Operation: {operation_id}");
    println!("Total investigations: {total}");
    println!("  Running:   {running}");
    println!("  Completed: {completed}");
    println!("  Escalated: {escalated}");
    println!("  Routed:    {routed}");
    println!("  Failed:    {failed}");
    println!("  Submitted: {submitted}");
    println!("Duration: {}", format_duration(elapsed));

    let total_triaged: i64 = triage_counts.values().sum();
    if total_triaged > 0 {
        println!("\nTriage breakdown:");
        println!(
            "  Confirmed:     {}",
            triage_counts.get("confirmed").unwrap_or(&0)
        );
        println!(
            "  Downgraded:    {}",
            triage_counts.get("downgraded").unwrap_or(&0)
        );
        println!(
            "  Routed:        {}",
            triage_counts.get("routed").unwrap_or(&0)
        );
        println!(
            "  Reinvestigate: {}",
            triage_counts.get("reinvestigate").unwrap_or(&0)
        );
        println!(
            "  Pending:       {}",
            triage_counts.get("pending").unwrap_or(&0)
        );
    }

    if let Some(start) = earliest_start {
        println!("\nStarted: {}", start.to_rfc3339());
    }
    let has_active = running > 0 || submitted > 0;
    if let Some(end) = latest_end {
        if !has_active {
            println!("Completed: {}", end.to_rfc3339());
        }
    }

    if let Some(running_invs) = status_counts.get("running") {
        println!("\nRunning investigations:");
        for inv in running_invs {
            let inv_id = inv
                .get("investigation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let started = inv.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
            let started_display = if started.len() > 19 {
                &started[..19]
            } else {
                started
            };
            println!("  {inv_id} (started: {started_display})");
        }
    }

    if let Some(failed_invs) = status_counts.get("failed") {
        println!("\nFailed investigations:");
        for inv in failed_invs {
            let inv_id = inv
                .get("investigation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let error = inv.get("error").and_then(|v| v.as_str()).unwrap_or("");
            let error_display = if error.len() > 60 {
                let mut end = 60;
                while !error.is_char_boundary(end) {
                    end -= 1;
                }
                &error[..end]
            } else {
                error
            };
            println!("  {inv_id}: {error_display}");
        }
    }

    Ok(!has_active)
}
