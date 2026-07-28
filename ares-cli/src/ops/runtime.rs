use anyhow::{Context, Result};
use chrono::Utc;

use ares_core::models::SharedRedTeamState;
use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};
use crate::util::{format_duration, format_number};

fn finalizing_note(state: &SharedRedTeamState) -> Option<String> {
    if state.completed_at.is_some() || state.red_completed_at.is_none() {
        return None;
    }
    if state.red_blocked_on_blue {
        return Some("waiting on blue investigations".to_string());
    }
    state.red_completion_reason.clone()
}

pub(crate) async fn ops_runtime(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let is_running = reader.is_running(&mut conn).await?;
    let now = Utc::now();

    let (runtime_seconds, status) = if let Some(completed) = state.completed_at {
        (
            (completed - state.started_at).num_seconds().max(0) as u64,
            "completed",
        )
    } else if let Some(red_completed) = state.red_completed_at {
        (
            (red_completed - state.started_at).num_seconds().max(0) as u64,
            "completed",
        )
    } else if is_running {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "running",
        )
    } else {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "stopped",
        )
    };

    println!("Operation: {op_id}");
    println!("Status:    {status}");
    println!("Started:   {}", state.started_at.to_rfc3339());
    println!("Runtime:   {}", format_duration(runtime_seconds));
    if let Some(note) = finalizing_note(&state) {
        println!("Finalizing: {note}");
    }
    println!();

    let (creds, hashes) = super::loot::reportable_counts(&state);
    let vulns = state.discovered_vulnerabilities.len();
    let exploited = state.exploited_vulnerabilities.len();

    println!("Credentials: {creds}  Hashes: {hashes}");
    println!("Vulns: {vulns} discovered, {exploited} exploited");
    println!();

    super::loot::print_runtime_summary(&state);

    // Token usage & estimated cost (from Redis counters set by workers)
    match ares_core::token_usage::get_token_usage(&mut conn, &op_id).await {
        Ok(Some(usage)) if usage.input_tokens > 0 || usage.output_tokens > 0 => {
            let in_tok = usage.input_tokens;
            let cached_tok = usage.cache_read_input_tokens;
            let out_tok = usage.output_tokens;
            let total_tok = in_tok + cached_tok + out_tok;
            let total_input = in_tok + cached_tok;

            println!(
                "\nTokens: {} (in: {}  out: {})",
                format_number(total_tok),
                format_number(total_input),
                format_number(out_tok)
            );
            if total_input > 0 {
                let pct = (cached_tok as f64 / total_input as f64) * 100.0;
                println!(
                    "Cache:  hit {} / {} tokens ({:.1}%)",
                    format_number(cached_tok),
                    format_number(total_input),
                    pct
                );
            }

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

                // Per-model breakdown for multi-model operations
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32, min: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, hour, min, 0).unwrap()
    }

    fn running_state() -> SharedRedTeamState {
        let mut state = SharedRedTeamState::new("op-test-001".to_string());
        state.started_at = at(3, 46);
        state
    }

    fn red_done_state() -> SharedRedTeamState {
        let mut state = running_state();
        state.red_completed_at = Some(at(4, 10));
        state.red_completion_reason = Some("all forests dominated".to_string());
        state.red_blocked_on_blue = true;
        state
    }

    #[test]
    fn running_op_has_no_finalizing_note() {
        assert_eq!(finalizing_note(&running_state()), None);
    }

    #[test]
    fn red_done_blocked_on_blue_reports_blue_wait() {
        assert_eq!(
            finalizing_note(&red_done_state()),
            Some("waiting on blue investigations".to_string())
        );
    }

    #[test]
    fn red_done_without_blue_reports_completion_reason() {
        let mut state = red_done_state();
        state.red_blocked_on_blue = false;
        assert_eq!(
            finalizing_note(&state),
            Some("all forests dominated".to_string())
        );
    }

    #[test]
    fn fully_completed_op_has_no_finalizing_note() {
        let mut state = red_done_state();
        state.completed_at = Some(at(4, 30));
        assert_eq!(finalizing_note(&state), None);
    }
}
