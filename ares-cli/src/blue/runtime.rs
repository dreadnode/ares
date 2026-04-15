use anyhow::Result;
use chrono::Utc;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;
use crate::util::{format_duration, format_number, parse_datetime};

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

            // Token usage & estimated cost
            match ares_core::token_usage::get_blue_token_usage(&mut conn, &inv_id).await {
                Ok(Some(usage)) if usage.input_tokens > 0 || usage.output_tokens > 0 => {
                    let in_tok = usage.input_tokens;
                    let out_tok = usage.output_tokens;
                    let total_tok = in_tok + out_tok;

                    println!(
                        "\nTokens: {} (in: {}  out: {})",
                        format_number(total_tok),
                        format_number(in_tok),
                        format_number(out_tok)
                    );

                    if !usage.models.is_empty() {
                        let mut model_names: Vec<_> = usage.models.keys().collect();
                        model_names.sort();
                        let label = if model_names.len() > 1 {
                            "Models"
                        } else {
                            "Model"
                        };
                        println!(
                            "{label}:  {}",
                            model_names
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );

                        let (total_cost, breakdown, unpriced) =
                            ares_core::token_usage::estimate_usage_cost(&usage);

                        if let Some(cost) = total_cost {
                            let suffix = if breakdown.len() > 1 {
                                " (blended)"
                            } else {
                                ""
                            };
                            println!("Cost:   ${cost:.4}{suffix}");
                        } else if !usage.model.is_empty() {
                            println!("Cost:   unavailable");
                        }

                        if breakdown.len() > 1 {
                            for item in &breakdown {
                                println!(
                                    "  - {}: {} tokens (${:.4})",
                                    item.model, item.total_tokens, item.cost
                                );
                            }
                        }

                        if !unpriced.is_empty() {
                            println!("Unpriced models: {}", unpriced.join(", "));
                        }
                    }
                }
                _ => {}
            }
        }
        None => {
            println!("Investigation not found: {inv_id}");
        }
    }

    Ok(())
}
