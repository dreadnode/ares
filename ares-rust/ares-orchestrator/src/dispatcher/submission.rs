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
    /// If the LLM runner is available and the task type is supported,
    /// spawns a tokio task that drives the LLM agent loop. Otherwise,
    /// pushes to the Redis queue for Python workers.
    pub(super) async fn do_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<Option<String>> {
        // Check if the LLM runner can handle this task
        let llm_role = self
            .llm_runner
            .as_ref()
            .and_then(|_| crate::llm_runner::role_for_task_type(task_type));

        if let (Some(runner), Some(role)) = (&self.llm_runner, llm_role) {
            return self
                .submit_to_llm(runner.clone(), task_type, target_role, role, payload)
                .await;
        }

        // Fallback: push to Redis for Python workers
        self.submit_to_queue(task_type, target_role, payload, priority)
            .await
    }

    /// Submit a task to the Redis queue for Python workers.
    async fn submit_to_queue(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<Option<String>> {
        let task_id = self
            .queue
            .submit_task(task_type, target_role, payload, "orchestrator", priority)
            .await?;

        self.tracker
            .add(ActiveTask {
                task_id: task_id.clone(),
                task_type: task_type.to_string(),
                role: target_role.to_string(),
                submitted_at: std::time::Instant::now(),
            })
            .await;

        self.throttler.record_dispatch().await;
        Ok(Some(task_id))
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
                Ok(outcome) => match &outcome.reason {
                    LoopEndReason::TaskComplete { result, .. } => TaskResult {
                        task_id: tid.clone(),
                        success: true,
                        result: Some(json!({
                            "summary": result,
                            "steps": outcome.steps,
                            "tool_calls": outcome.tool_calls_dispatched,
                        })),
                        error: None,
                        completed_at: Some(Utc::now()),
                        worker_pod: Some("rust-llm-runner".into()),
                        agent_name: Some(tt.clone()),
                    },
                    LoopEndReason::RequestAssistance { issue, context } => TaskResult {
                        task_id: tid.clone(),
                        success: false,
                        result: None,
                        error: Some(format!("Assistance needed: {issue} (context: {context})")),
                        completed_at: Some(Utc::now()),
                        worker_pod: Some("rust-llm-runner".into()),
                        agent_name: Some(tt.clone()),
                    },
                    LoopEndReason::MaxSteps => TaskResult {
                        task_id: tid.clone(),
                        success: false,
                        result: Some(json!({
                            "steps": outcome.steps,
                            "tool_calls": outcome.tool_calls_dispatched,
                        })),
                        error: Some("Agent hit max steps limit".into()),
                        completed_at: Some(Utc::now()),
                        worker_pod: Some("rust-llm-runner".into()),
                        agent_name: Some(tt.clone()),
                    },
                    LoopEndReason::EndTurn { content } => TaskResult {
                        task_id: tid.clone(),
                        success: true,
                        result: Some(json!({"summary": content})),
                        error: None,
                        completed_at: Some(Utc::now()),
                        worker_pod: Some("rust-llm-runner".into()),
                        agent_name: Some(tt.clone()),
                    },
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
                },
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
