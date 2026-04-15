use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::Serialize;

use ares_core::state;

use crate::redis_conn::connect_redis;
use crate::util::{format_duration, parse_datetime};

pub(crate) async fn blue_operation_status(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    watch: u64,
    json: bool,
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
            let all_done = blue_operation_status_once(&mut conn, &op_id, json).await?;
            if all_done {
                if !json {
                    println!("\nAll investigations complete.");
                }
                break;
            }
            if !json {
                println!("\nRefreshing in {watch}s... (Ctrl+C to stop)");
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(watch)).await;
        }
    } else {
        blue_operation_status_once(&mut conn, &op_id, json).await?;
    }

    Ok(())
}

#[derive(Serialize)]
struct OperationStatusJson {
    operation_id: String,
    total: usize,
    running: usize,
    completed: usize,
    escalated: usize,
    routed: usize,
    failed: usize,
    submitted: usize,
    duration_seconds: u64,
    started_at: Option<String>,
    completed_at: Option<String>,
    triage: HashMap<String, i64>,
    investigations: Vec<InvestigationStatusJson>,
}

#[derive(Serialize)]
struct InvestigationStatusJson {
    id: String,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    error: Option<String>,
    triage_decision: Option<String>,
}

/// Show status for all investigations in an operation. Returns true if all done.
async fn blue_operation_status_once(
    conn: &mut redis::aio::MultiplexedConnection,
    operation_id: &str,
    json: bool,
) -> Result<bool> {
    let inv_ids = state::list_investigations_for_operation(conn, operation_id).await?;

    if inv_ids.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&OperationStatusJson {
                    operation_id: operation_id.to_string(),
                    total: 0,
                    running: 0,
                    completed: 0,
                    escalated: 0,
                    routed: 0,
                    failed: 0,
                    submitted: 0,
                    duration_seconds: 0,
                    started_at: None,
                    completed_at: None,
                    triage: HashMap::new(),
                    investigations: Vec::new(),
                })?
            );
        } else {
            println!("No investigations found for operation: {operation_id}");
        }
        return Ok(true);
    }

    let mut status_counts: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut triage_counts: HashMap<String, i64> = HashMap::new();
    let mut earliest_start: Option<DateTime<Utc>> = None;
    let mut latest_end: Option<DateTime<Utc>> = None;
    let mut inv_details: Vec<InvestigationStatusJson> = Vec::new();

    for inv_id in &inv_ids {
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

                let started_at_str = data
                    .get("started_at")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Track timestamps
                if let Some(ref started) = started_at_str {
                    if let Ok(dt) = parse_datetime(started) {
                        if earliest_start.is_none_or(|prev| dt < prev) {
                            earliest_start = Some(dt);
                        }
                    }
                }

                let completed_at_str = data
                    .get("completed_at")
                    .and_then(|v| v.as_str())
                    .or_else(|| data.get("failed_at").and_then(|v| v.as_str()))
                    .map(|s| s.to_string());

                if let Some(ref end_str) = completed_at_str {
                    if let Ok(dt) = parse_datetime(end_str) {
                        if latest_end.is_none_or(|prev| dt > prev) {
                            latest_end = Some(dt);
                        }
                    }
                }

                let error_str = data
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Check triage for escalated/routed/completed
                let mut triage_decision = None;
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
                            *triage_counts.entry(decision.clone()).or_insert(0) += 1;
                            triage_decision = Some(decision);
                        }
                    }
                }

                inv_details.push(InvestigationStatusJson {
                    id: inv_id.clone(),
                    status: inv_status.clone(),
                    started_at: started_at_str,
                    completed_at: completed_at_str,
                    error: error_str,
                    triage_decision,
                });

                status_counts.entry(inv_status).or_default().push(data);
            }
        } else {
            inv_details.push(InvestigationStatusJson {
                id: inv_id.clone(),
                status: "submitted".to_string(),
                started_at: None,
                completed_at: None,
                error: None,
                triage_decision: None,
            });
            status_counts
                .entry("submitted".to_string())
                .or_default()
                .push(serde_json::json!({"investigation_id": inv_id}));
        }
    }

    // Calculate duration
    let now = Utc::now();
    let has_active_running = status_counts.contains_key("running")
        || status_counts.contains_key("in_progress")
        || status_counts.contains_key("submitted");
    let elapsed = if let Some(start) = earliest_start {
        if has_active_running {
            (now - start).num_seconds().max(0) as u64
        } else if let Some(end) = latest_end {
            (end - start).num_seconds().max(0) as u64
        } else {
            0
        }
    } else {
        0
    };

    let total = inv_ids.len();
    let running = status_counts.get("running").map_or(0, |v| v.len())
        + status_counts.get("in_progress").map_or(0, |v| v.len());
    let completed = status_counts.get("completed").map_or(0, |v| v.len());
    let escalated = status_counts.get("escalated").map_or(0, |v| v.len());
    let routed = status_counts.get("routed").map_or(0, |v| v.len());
    let failed = status_counts.get("failed").map_or(0, |v| v.len());
    let submitted = status_counts.get("submitted").map_or(0, |v| v.len());

    let has_active = running > 0 || submitted > 0;

    if json {
        let output = OperationStatusJson {
            operation_id: operation_id.to_string(),
            total,
            running,
            completed,
            escalated,
            routed,
            failed,
            submitted,
            duration_seconds: elapsed,
            started_at: earliest_start.map(|dt| dt.to_rfc3339()),
            completed_at: if !has_active {
                latest_end.map(|dt| dt.to_rfc3339())
            } else {
                None
            },
            triage: triage_counts,
            investigations: inv_details,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(!has_active);
    }

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
    if let Some(end) = latest_end {
        if !has_active {
            println!("Completed: {}", end.to_rfc3339());
        }
    }

    let running_invs: Vec<_> = status_counts
        .get("running")
        .into_iter()
        .chain(status_counts.get("in_progress"))
        .flat_map(|v| v.iter())
        .collect();
    if !running_invs.is_empty() {
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
