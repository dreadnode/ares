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

use ares_core::state::blue_task_queue::BlueTaskQueue;
use ares_llm::{LlmProvider, ToolDispatcher};

use super::investigation::{self, Investigation};

/// Blue team investigation orchestrator.
///
/// Owns the LLM provider and tool dispatcher, and drives investigations
/// from alert to completion.
pub struct BlueOrchestrator {
    provider: Arc<dyn LlmProvider>,
    model_name: String,
    dispatcher: Arc<dyn ToolDispatcher>,
    redis_url: String,
}

impl BlueOrchestrator {
    pub fn new(
        provider: Box<dyn LlmProvider>,
        model_name: String,
        dispatcher: Arc<dyn ToolDispatcher>,
        redis_url: String,
    ) -> Self {
        Self {
            provider: Arc::from(provider),
            model_name,
            dispatcher,
            redis_url,
        }
    }

    /// Run the blue team orchestration loop until shutdown.
    ///
    /// Polls `ares:blue:investigations` for new investigation requests.
    /// Each request contains an alert payload and LLM model to use.
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        info!("Blue team orchestrator starting");

        let mut task_queue = BlueTaskQueue::connect(&self.redis_url)
            .await
            .context("Failed to connect blue task queue to Redis")?;

        let mut retry_delay = Duration::from_secs(1);
        let max_retry_delay = Duration::from_secs(30);

        loop {
            // Check shutdown
            if *shutdown_rx.borrow() {
                info!("Blue orchestrator: shutdown signalled");
                break;
            }

            // Poll for investigation requests
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

                    info!(
                        investigation_id = %investigation_id,
                        model = %model,
                        operation_id = ?operation_id,
                        "Received investigation request"
                    );

                    // Register the investigation
                    if let Err(e) = task_queue
                        .register_investigation(&investigation_id, &alert, &model)
                        .await
                    {
                        warn!(err = %e, "Failed to register investigation");
                    }

                    // Run the investigation
                    let investigation =
                        Investigation::new(investigation_id.clone(), alert, model, operation_id);

                    let mut conn = redis::Client::open(self.redis_url.as_str())?
                        .get_connection_manager()
                        .await?;

                    match investigation::run_investigation(
                        &investigation,
                        Arc::clone(&self.provider),
                        Arc::clone(&self.dispatcher),
                        &mut task_queue,
                        &self.redis_url,
                        &mut conn,
                    )
                    .await
                    {
                        Ok(outcome) => {
                            info!(
                                investigation_id = %investigation_id,
                                outcome = ?outcome,
                                "Investigation finished"
                            );
                        }
                        Err(e) => {
                            error!(
                                investigation_id = %investigation_id,
                                err = %e,
                                "Investigation failed with error"
                            );
                        }
                    }

                    // Clean up active investigation registration
                    let _: Result<(), _> = conn
                        .srem::<_, _, ()>(
                            ares_core::state::BLUE_ACTIVE_INVESTIGATIONS,
                            &investigation_id,
                        )
                        .await;
                }
                Ok(None) => {
                    // No request, just loop
                    retry_delay = Duration::from_secs(1);
                }
                Err(e) => {
                    let error_str = e.to_string().to_lowercase();
                    let is_conn_error = ["connection", "closed", "timeout", "broken", "reset"]
                        .iter()
                        .any(|kw| error_str.contains(kw));

                    if is_conn_error {
                        warn!(
                            delay_secs = retry_delay.as_secs(),
                            "Blue orchestrator: connection error, retrying: {e}"
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(retry_delay) => {}
                            _ = shutdown_rx.changed() => break,
                        }
                        retry_delay = (retry_delay * 2).min(max_retry_delay);
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

/// Spawn the blue team orchestrator as a background tokio task.
///
/// Returns a `JoinHandle` that resolves when the orchestrator stops.
pub fn spawn_blue_orchestrator(
    provider: Box<dyn LlmProvider>,
    model_name: String,
    dispatcher: Arc<dyn ToolDispatcher>,
    redis_url: String,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let orchestrator = BlueOrchestrator::new(provider, model_name, dispatcher, redis_url);
        if let Err(e) = orchestrator.run(shutdown_rx).await {
            error!("Blue orchestrator exited with error: {e}");
        }
    })
}
