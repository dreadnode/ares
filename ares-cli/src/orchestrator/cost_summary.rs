//! Periodic token usage and cost summary.
//!
//! Spawns a background task that logs aggregate token usage and estimated cost
//! every 120 seconds.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use ares_core::token_usage::{estimate_usage_cost, get_token_usage};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::task_queue::TaskQueue;
use crate::util::{format_model_cost_line, format_number};

/// How often to log the cost summary.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(120);

/// Spawn the periodic cost summary background task.
pub fn spawn_cost_summary(
    queue: TaskQueue,
    config: Arc<OrchestratorConfig>,
    shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(cost_summary_loop(queue, config, shutdown_rx))
}

async fn cost_summary_loop(
    queue: TaskQueue,
    config: Arc<OrchestratorConfig>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(SUMMARY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Skip the first immediate tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown_rx.changed() => {
                debug!("Cost summary: shutdown");
                return;
            }
        }

        if *shutdown_rx.borrow() {
            return;
        }

        let mut conn = queue.connection();
        match get_token_usage(&mut conn, &config.operation_id).await {
            Ok(Some(usage)) => {
                let in_tok = usage.input_tokens;
                let cached_tok = usage.cache_read_input_tokens;
                let out_tok = usage.output_tokens;
                if in_tok == 0 && cached_tok == 0 && out_tok == 0 {
                    continue;
                }
                let total = in_tok + cached_tok + out_tok;

                let (total_cost, breakdown, _unpriced) = estimate_usage_cost(&usage);

                let cost_str = match total_cost {
                    Some(cost) => {
                        let suffix = if breakdown.len() > 1 { " blended" } else { "" };
                        format!(" | ${cost:.4}{suffix}")
                    }
                    None if !usage.models.is_empty() => {
                        let n = usage.models.len();
                        let label = if n > 1 { "models" } else { "model" };
                        format!(" | cost unavailable for {n} {label}")
                    }
                    _ => String::new(),
                };

                info!(
                    "💰 [token-usage] {} tokens (in: {}  cached: {}  out: {}){cost_str}",
                    format_number(total),
                    format_number(in_tok),
                    format_number(cached_tok),
                    format_number(out_tok)
                );
                if breakdown.len() > 1 {
                    for item in &breakdown {
                        info!("💰 [token-usage] {}", format_model_cost_line(item));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                debug!("Token usage summary failed: {e}");
            }
        }
    }
}
