//! Task submission — throttled_submit and do_submit.

use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::deferred::DeferredTask;
use crate::llm_runner::LlmTaskRunner;
use crate::routing::ActiveTask;
use crate::task_queue::TaskResult;
use crate::throttling::ThrottleDecision;

use ares_llm::LoopEndReason;

use super::Dispatcher;

impl Dispatcher {
    /// Submit a task with throttle checking. Returns the task_id if submitted,
    /// None if deferred or rejected.
    pub async fn throttled_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<Option<String>> {
        let decision = self
            .throttler
            .check(task_type, target_role, Some(&payload))
            .await;

        match decision {
            ThrottleDecision::Allow => {
                self.do_submit(task_type, target_role, payload, priority)
                    .await
            }
            ThrottleDecision::Defer => {
                let task = DeferredTask {
                    priority,
                    enqueue_time: Utc::now().timestamp() as f64,
                    task_type: task_type.to_string(),
                    target_role: target_role.to_string(),
                    payload,
                    source_agent: "orchestrator".to_string(),
                };
                match self.deferred.enqueue(&task).await {
                    Ok(true) => {
                        debug!(task_type, target_role, "Task deferred");
                        Ok(None)
                    }
                    Ok(false) => {
                        debug!(task_type, target_role, "Deferred queue full, task dropped");
                        Ok(None)
                    }
                    Err(e) => {
                        warn!(err = %e, "Failed to defer task, attempting direct submit");
                        self.do_submit(task_type, target_role, task.payload, priority)
                            .await
                    }
                }
            }
            ThrottleDecision::Wait(dur) => {
                // Sleep and retry once
                tokio::time::sleep(dur).await;
                let retry_decision = self
                    .throttler
                    .check(task_type, target_role, Some(&payload))
                    .await;
                match retry_decision {
                    ThrottleDecision::Allow => {
                        self.do_submit(task_type, target_role, payload, priority)
                            .await
                    }
                    _ => {
                        let task = DeferredTask {
                            priority,
                            enqueue_time: Utc::now().timestamp() as f64,
                            task_type: task_type.to_string(),
                            target_role: target_role.to_string(),
                            payload,
                            source_agent: "orchestrator".to_string(),
                        };
                        let _ = self.deferred.enqueue(&task).await;
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Direct submit (bypasses throttle). Returns task_id.
    ///
    /// Routes the task to the Rust LLM agent loop. If the task type
    /// has no mapped role, logs a warning and drops the task.
    pub(super) async fn do_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        _priority: i32,
    ) -> Result<Option<String>> {
        let role = match crate::llm_runner::role_for_task_type(task_type) {
            Some(r) => r,
            None => {
                warn!(
                    task_type = task_type,
                    "No LLM role mapping for task type, dropping"
                );
                return Ok(None);
            }
        };

        self.submit_to_llm(
            self.llm_runner.clone(),
            task_type,
            target_role,
            role,
            payload,
        )
        .await
    }

    /// Submit a task to the Rust LLM agent loop. Spawns a background tokio
    /// task and pushes the result back through the normal result queue so it
    /// flows through `process_completed_task()`.
    async fn submit_to_llm(
        &self,
        runner: Arc<LlmTaskRunner>,
        task_type: &str,
        target_role: &str,
        role: ares_llm::tool_registry::AgentRole,
        payload: serde_json::Value,
    ) -> Result<Option<String>> {
        let task_id = format!(
            "{}_{}",
            task_type,
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );

        info!(
            task_id = %task_id,
            task_type = task_type,
            role = target_role,
            "Routing task to LLM runner (Rust agent loop)"
        );

        self.tracker
            .add(ActiveTask {
                task_id: task_id.clone(),
                task_type: task_type.to_string(),
                role: target_role.to_string(),
                submitted_at: std::time::Instant::now(),
            })
            .await;

        self.throttler.record_dispatch().await;

        // Set initial task status
        let _ = self.queue.set_task_status(&task_id, "in_progress").await;

        // Spawn the LLM agent loop as a background task
        let queue = self.queue.clone();
        let tid = task_id.clone();
        let tt = task_type.to_string();
        tokio::spawn(async move {
            let outcome = runner.execute_task(&tt, &tid, role, &payload).await;

            // Convert outcome to TaskResult and push to result queue
            let result = match outcome {
                Ok(outcome) => {
                    // Merge all structured discoveries from tool results
                    let merged_discoveries = if outcome.discoveries.is_empty() {
                        None
                    } else {
                        Some(ares_tools::parsers::merge_discoveries(&outcome.discoveries))
                    };

                    match &outcome.reason {
                        LoopEndReason::TaskComplete { result, .. } => {
                            let mut result_json = json!({
                                "summary": result,
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            TaskResult {
                                task_id: tid.clone(),
                                success: true,
                                result: Some(result_json),
                                error: None,
                                completed_at: Some(Utc::now()),
                                worker_pod: Some("rust-llm-runner".into()),
                                agent_name: Some(tt.clone()),
                            }
                        }
                        LoopEndReason::RequestAssistance { issue, context } => TaskResult {
                            task_id: tid.clone(),
                            success: false,
                            result: None,
                            error: Some(format!("Assistance needed: {issue} (context: {context})")),
                            completed_at: Some(Utc::now()),
                            worker_pod: Some("rust-llm-runner".into()),
                            agent_name: Some(tt.clone()),
                        },
                        LoopEndReason::MaxSteps => {
                            let mut result_json = json!({
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            TaskResult {
                                task_id: tid.clone(),
                                success: false,
                                result: Some(result_json),
                                error: Some("Agent hit max steps limit".into()),
                                completed_at: Some(Utc::now()),
                                worker_pod: Some("rust-llm-runner".into()),
                                agent_name: Some(tt.clone()),
                            }
                        }
                        LoopEndReason::EndTurn { content } => {
                            let mut result_json = json!({"summary": content});
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            TaskResult {
                                task_id: tid.clone(),
                                success: true,
                                result: Some(result_json),
                                error: None,
                                completed_at: Some(Utc::now()),
                                worker_pod: Some("rust-llm-runner".into()),
                                agent_name: Some(tt.clone()),
                            }
                        }
                        LoopEndReason::MaxTokens => TaskResult {
                            task_id: tid.clone(),
                            success: false,
                            result: None,
                            error: Some("Agent hit max tokens".into()),
                            completed_at: Some(Utc::now()),
                            worker_pod: Some("rust-llm-runner".into()),
                            agent_name: Some(tt.clone()),
                        },
                        LoopEndReason::Error(err) => TaskResult {
                            task_id: tid.clone(),
                            success: false,
                            result: None,
                            error: Some(err.clone()),
                            completed_at: Some(Utc::now()),
                            worker_pod: Some("rust-llm-runner".into()),
                            agent_name: Some(tt.clone()),
                        },
                    }
                }
                Err(e) => TaskResult {
                    task_id: tid.clone(),
                    success: false,
                    result: None,
                    error: Some(format!("LLM runner error: {e}")),
                    completed_at: Some(Utc::now()),
                    worker_pod: Some("rust-llm-runner".into()),
                    agent_name: Some(tt.clone()),
                },
            };

            // Push result to the normal result queue so the result consumer picks it up
            if let Err(e) = queue.send_result(&tid, &result).await {
                warn!(
                    task_id = %tid,
                    err = %e,
                    "Failed to push LLM task result to Redis"
                );
            }
        });

        Ok(Some(task_id))
    }
}
