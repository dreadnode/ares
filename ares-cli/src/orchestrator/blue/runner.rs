//! Blue team orchestrator service loop.
//!
//! Polls `ares:blue:investigations` for new investigation requests and
//! drives each through the investigation workflow using the LLM agent loop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tokio::sync::watch;
use tracing::{error, info, warn};

use ares_core::nats::NatsBroker;
use ares_core::op_state_log::OpStateRecorder;
use ares_core::state::blue_task_queue::BlueTaskQueue;
use ares_llm::{LlmProvider, ToolDispatcher};

use super::investigation::{self, Investigation};

/// Timeout for a single investigation run (45 minutes).
/// Loki queries via the Grafana proxy take 30-40s each from EC2,
/// so the agent needs more headroom to complete triage + hunting.
pub(crate) const INVESTIGATION_TIMEOUT_SECS: u64 = 2700;

/// How often a running investigation checks for a supersede request.
const SUPERSEDE_POLL_SECS: u64 = 10;

/// Threshold for considering a running investigation as stale (50 minutes).
const STALE_INVESTIGATION_THRESHOLD_SECS: i64 = 3000;

/// Interval between periodic stale investigation checks (5 minutes).
const STALE_CHECK_INTERVAL_SECS: u64 = 300;

/// Blue team investigation orchestrator.
///
/// Owns the LLM provider and tool dispatcher, and drives investigations
/// from alert to completion.
pub struct BlueOrchestrator {
    provider: Arc<dyn LlmProvider>,
    model_name: String,
    dispatcher: Arc<dyn ToolDispatcher>,
    redis_url: String,
    nats_url: String,
}

impl BlueOrchestrator {
    pub fn new(
        provider: Box<dyn LlmProvider>,
        model_name: String,
        dispatcher: Arc<dyn ToolDispatcher>,
        redis_url: String,
        nats_url: String,
    ) -> Self {
        Self {
            provider: Arc::from(provider),
            model_name,
            dispatcher,
            redis_url,
            nats_url,
        }
    }

    /// Clean up stale investigations left in "running" status.
    ///
    /// Scans `ares:blue:active_investigations` for investigation IDs whose
    /// status has been `in_progress` for longer than the threshold. Marks
    /// them as `failed` with an orphaned message and removes from the active set.
    async fn cleanup_stale_investigations(&self) {
        let cm_config = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(Some(std::time::Duration::from_secs(30)));
        let conn = match redis::Client::open(self.redis_url.as_str()) {
            Ok(client) => match client.get_connection_manager_with_config(cm_config).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Stale cleanup: failed to connect to Redis: {e}");
                    return;
                }
            },
            Err(e) => {
                warn!("Stale cleanup: failed to open Redis client: {e}");
                return;
            }
        };
        let mut conn = conn;

        let active_ids: Vec<String> = match conn
            .smembers::<_, Vec<String>>(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS)
            .await
        {
            Ok(ids) => ids,
            Err(e) => {
                warn!("Stale cleanup: failed to read active investigations: {e}");
                return;
            }
        };

        if active_ids.is_empty() {
            return;
        }

        let now = chrono::Utc::now();
        let mut cleaned = 0u32;

        for inv_id in &active_ids {
            let status_key = format!("ares:blue:inv:{inv_id}:status");
            let status_json: Option<String> = conn.get(&status_key).await.unwrap_or(None);

            let Some(status_obj) = status_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            else {
                continue;
            };

            let status = status_obj
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if status != "in_progress" {
                continue;
            }

            let started_at = status_obj
                .get("started_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            let elapsed_secs = match started_at {
                Some(dt) => (now - dt).num_seconds(),
                None => STALE_INVESTIGATION_THRESHOLD_SECS + 1, // no timestamp = assume stale
            };

            if elapsed_secs > STALE_INVESTIGATION_THRESHOLD_SECS {
                let hours = elapsed_secs as f64 / 3600.0;
                let error_msg = format!(
                    "Investigation orphaned after orchestrator restart (was running {hours:.1}h)"
                );

                let updated = serde_json::json!({
                    "status": "failed",
                    "started_at": status_obj.get("started_at").unwrap_or(&serde_json::Value::Null),
                    "failed_at": now.to_rfc3339(),
                    "error": error_msg,
                });
                let data = serde_json::to_string(&updated).unwrap_or_default();
                let _: Result<(), _> = conn.set_ex::<_, _, ()>(&status_key, &data, 86400).await;

                let _: Result<(), _> = conn
                    .srem::<_, _, ()>(ares_core::state::BLUE_ACTIVE_INVESTIGATIONS, inv_id)
                    .await;

                warn!(
                    investigation_id = %inv_id,
                    elapsed_hours = format!("{hours:.1}"),
                    "Marked stale investigation as failed"
                );
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            info!(count = cleaned, "Stale investigation cleanup complete");
        }
    }

    /// Run the blue team orchestration loop until shutdown.
    ///
    /// Polls `ares:blue:investigations` for new investigation requests.
    /// Each request contains an alert payload and LLM model to use.
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        info!("Blue team orchestrator starting");

        self.cleanup_stale_investigations().await;

        let mut task_queue = BlueTaskQueue::connect_with_nats(&self.redis_url, &self.nats_url)
            .await
            .context("Failed to connect blue task queue (Redis + NATS)")?;

        // Blue is DETECT-ONLY by default: it investigates and identifies red's
        // activity but publishes no containment, so red runs its full attack
        // while blue tracks it. Opt in to the red-facing containment loop
        // (`confirm_escalation` with a containment action → ARES_OPSTATE event →
        // red-side projector drops invalidated tasks) with
        // ARES_BLUE_SIMULATED_CONTAINMENT=1. When off, a disabled recorder makes
        // `publish_containment` a no-op; blue's investigation/detection output is
        // unaffected either way.
        let containment_enabled =
            std::env::var("ARES_BLUE_SIMULATED_CONTAINMENT").as_deref() == Ok("1");
        let op_state_recorder = if !containment_enabled {
            info!(
                "Blue orchestrator: detect-only (simulated containment OFF); set \
                 ARES_BLUE_SIMULATED_CONTAINMENT=1 to feed containment observations to red"
            );
            OpStateRecorder::disabled()
        } else {
            match NatsBroker::connect(&self.nats_url).await {
                Ok(broker) => {
                    info!("Blue orchestrator: simulated containment ON — op-state recorder wired to NATS");
                    OpStateRecorder::nats(Arc::new(broker))
                }
                Err(e) => {
                    warn!(
                        err = %e,
                        "Blue orchestrator: could not connect NATS broker for op-state recorder — simulated-containment publish disabled"
                    );
                    OpStateRecorder::disabled()
                }
            }
        };

        let mut retry_delay = Duration::from_secs(1);
        let max_retry_delay = Duration::from_secs(30);
        let mut last_stale_check = std::time::Instant::now();

        loop {
            if *shutdown_rx.borrow() {
                info!("Blue orchestrator: shutdown signalled");
                break;
            }

            let poll_result = tokio::select! {
                result = task_queue.pop_investigation_request(5.0) => result,
                _ = shutdown_rx.changed() => {
                    info!("Blue orchestrator: shutdown during poll");
                    break;
                }
            };

            match poll_result {
                Ok(Some(request)) => {
                    retry_delay = Duration::from_secs(1);

                    let investigation_id = request
                        .get("investigation_id")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                    let alert = request
                        .get("alert")
                        .cloned()
                        .unwrap_or(serde_json::json!({}));

                    let raw_model = request
                        .get("model")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .unwrap_or(&self.model_name);
                    // Strip provider prefix (e.g. "openai/gpt-5.2" → "gpt-5.2")
                    let model = raw_model
                        .split_once('/')
                        .map(|(_, name)| name)
                        .unwrap_or(raw_model)
                        .to_string();

                    let operation_id = request
                        .get("operation_id")
                        .and_then(|v| v.as_str())
                        .map(String::from);

                    // Report directory: request > ARES_REPORT_DIR env > ~/.ares/reports/
                    let report_dir = request
                        .get("report_dir")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| std::env::var("ARES_REPORT_DIR").ok());

                    info!(
                        investigation_id = %investigation_id,
                        model = %model,
                        operation_id = ?operation_id,
                        "Received investigation request"
                    );

                    if let Err(e) = task_queue
                        .register_investigation(&investigation_id, &alert, &model)
                        .await
                    {
                        warn!(err = %e, "Failed to register investigation");
                    }

                    let investigation = Investigation::new(
                        investigation_id.clone(),
                        alert,
                        model,
                        operation_id,
                        report_dir,
                    );

                    let mut conn = redis::Client::open(self.redis_url.as_str())?
                        .get_connection_manager()
                        .await?;

                    let mut supersede_conn = conn.clone();
                    let watched_id = investigation_id.clone();
                    let run_result = tokio::select! {
                        result = tokio::time::timeout(
                            Duration::from_secs(INVESTIGATION_TIMEOUT_SECS),
                            investigation::run_investigation(
                                &investigation,
                                Arc::clone(&self.provider),
                                Arc::clone(&self.dispatcher),
                                &mut task_queue,
                                &self.redis_url,
                                &mut conn,
                                op_state_recorder.clone(),
                            ),
                        ) => Some(result),
                        () = await_supersede(&mut supersede_conn, &watched_id) => None,
                    };

                    match run_result {
                        Some(Ok(Ok(outcome))) => {
                            info!(
                                investigation_id = %investigation_id,
                                outcome = ?outcome,
                                "Investigation finished"
                            );
                        }
                        Some(Ok(Err(e))) => {
                            error!(
                                investigation_id = %investigation_id,
                                err = %e,
                                "Investigation failed with error"
                            );
                        }
                        None => {
                            warn!(
                                investigation_id = %investigation_id,
                                "Investigation superseded — yielding the runner slot"
                            );

                            investigation
                                .state_writer
                                .set_status(
                                    &mut conn,
                                    "superseded",
                                    Some("Superseded by a newer investigation"),
                                )
                                .await
                                .ok();

                            investigation
                                .state_writer
                                .release_lock(&mut conn)
                                .await
                                .ok();

                            ares_core::state::clear_blue_supersede(&mut conn, &investigation_id)
                                .await
                                .ok();

                            investigation::generate_report(
                                &mut conn,
                                &investigation.investigation_id,
                                investigation.report_dir.as_deref(),
                            )
                            .await;
                        }
                        Some(Err(_elapsed)) => {
                            error!(
                                investigation_id = %investigation_id,
                                timeout_secs = INVESTIGATION_TIMEOUT_SECS,
                                "Investigation timed out — cancelling"
                            );

                            // Write timed_out status so downstream consumers know
                            // what happened (the future was dropped before it could
                            // write its own final status).
                            investigation
                                .state_writer
                                .set_status(
                                    &mut conn,
                                    "timed_out",
                                    Some("Investigation exceeded timeout"),
                                )
                                .await
                                .ok();

                            // Release the lock that was acquired inside the
                            // now-cancelled future.
                            investigation
                                .state_writer
                                .release_lock(&mut conn)
                                .await
                                .ok();

                            // Generate a partial report from whatever evidence was
                            // collected before the timeout.
                            investigation::generate_report(
                                &mut conn,
                                &investigation.investigation_id,
                                investigation.report_dir.as_deref(),
                            )
                            .await;
                        }
                    }

                    let _: Result<(), _> = conn
                        .srem::<_, _, ()>(
                            ares_core::state::BLUE_ACTIVE_INVESTIGATIONS,
                            &investigation_id,
                        )
                        .await;
                }
                Ok(None) => {
                    retry_delay = Duration::from_secs(1);
                    if last_stale_check.elapsed() >= Duration::from_secs(STALE_CHECK_INTERVAL_SECS)
                    {
                        self.cleanup_stale_investigations().await;
                        last_stale_check = std::time::Instant::now();
                    }
                }
                Err(e) => {
                    let error_str = e.to_string().to_lowercase();
                    let is_conn_error = ["connection", "closed", "timeout", "broken", "reset"]
                        .iter()
                        .any(|kw| error_str.contains(kw));

                    if is_conn_error {
                        warn!(
                            delay_secs = retry_delay.as_secs(),
                            "Blue orchestrator: connection error, will reconnect: {e}"
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(retry_delay) => {}
                            _ = shutdown_rx.changed() => break,
                        }
                        retry_delay = (retry_delay * 2).min(max_retry_delay);

                        // Reconnect the task queue — the previous ConnectionManager
                        // can be stuck after Redis restarts or prolonged outages.
                        match BlueTaskQueue::connect_with_nats(&self.redis_url, &self.nats_url)
                            .await
                        {
                            Ok(new_queue) => {
                                task_queue = new_queue;
                                info!("Blue orchestrator: reconnected to Redis + NATS");
                            }
                            Err(reconnect_err) => {
                                warn!("Blue orchestrator: reconnect failed: {reconnect_err}");
                            }
                        }
                    } else {
                        error!("Blue orchestrator: non-connection error: {e}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }

        info!("Blue team orchestrator stopped");
        Ok(())
    }
}

/// Resolve once a supersede request lands for `investigation_id`.
///
/// Never resolves otherwise, so it can sit in a `select!` against the
/// investigation future without ever winning on its own. Redis errors are
/// treated as "no request pending" — a transient read failure must not abandon
/// a healthy investigation.
async fn await_supersede(conn: &mut redis::aio::ConnectionManager, investigation_id: &str) {
    loop {
        match ares_core::state::is_blue_supersede_requested(conn, investigation_id).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => {
                warn!(
                    investigation_id = %investigation_id,
                    err = %e,
                    "Failed to read supersede flag"
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(SUPERSEDE_POLL_SECS)).await;
    }
}

/// Spawn the blue team orchestrator as a background tokio task.
///
/// Returns a `JoinHandle` that resolves when the orchestrator stops.
pub fn spawn_blue_orchestrator(
    provider: Box<dyn LlmProvider>,
    model_name: String,
    dispatcher: Arc<dyn ToolDispatcher>,
    redis_url: String,
    nats_url: String,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let orchestrator =
            BlueOrchestrator::new(provider, model_name, dispatcher, redis_url, nats_url);
        if let Err(e) = orchestrator.run(shutdown_rx).await {
            error!("Blue orchestrator exited with error: {e}");
        }
    })
}
