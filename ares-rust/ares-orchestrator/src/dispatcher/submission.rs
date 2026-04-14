//! Task submission — throttled_submit and do_submit.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use serde_json::{json, Value};
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
    /// Routes the task to the Rust LLM agent loop. Prefers `target_role`
    /// when it maps to a valid AgentRole (e.g. MSSQL exploit → lateral),
    /// falling back to `role_for_task_type` for the default mapping.
    pub async fn do_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        _priority: i32,
    ) -> Result<Option<String>> {
        // Prefer the caller-specified target_role (from recommended_agent)
        // over the static task_type → role mapping. This lets automation
        // modules like MSSQL route exploits to lateral instead of privesc.
        let role = ares_llm::tool_registry::AgentRole::parse(target_role)
            .or_else(|| crate::llm_runner::role_for_task_type(task_type));

        let role = match role {
            Some(r) => r,
            None => {
                warn!(
                    task_type = task_type,
                    target_role = target_role,
                    "No LLM role mapping for task type or target role, dropping"
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
        // Per-credential concurrency gate: if too many tasks are already
        // in-flight for this credential, defer instead of spawning another.
        let cred_key = super::credential_key_from_payload(&payload);
        if let Some(ref key) = cred_key {
            if !self.credential_inflight.try_acquire(key).await {
                info!(
                    credential = key.as_str(),
                    task_type, "Credential concurrency limit reached, deferring task"
                );
                let task = DeferredTask {
                    priority: 3,
                    enqueue_time: Utc::now().timestamp() as f64,
                    task_type: task_type.to_string(),
                    target_role: target_role.to_string(),
                    payload,
                    source_agent: "orchestrator".to_string(),
                };
                let _ = self.deferred.enqueue(&task).await;
                return Ok(None);
            }
        }

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

        // Set initial task status with full metadata
        let _ = self
            .queue
            .set_task_status_full(
                &task_id,
                "in_progress",
                &self.config.operation_id,
                target_role,
                task_type,
                Some(&payload),
            )
            .await;

        // Persist pending task to Redis HASH for recovery
        let now = Utc::now();
        let mut task_params: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(ref key) = cred_key {
            task_params.insert("credential_key".to_string(), serde_json::json!(key));
        }
        let task_info = ares_core::models::TaskInfo {
            task_id: task_id.clone(),
            task_type: task_type.to_string(),
            assigned_agent: target_role.to_string(),
            status: ares_core::models::TaskStatus::InProgress,
            created_at: now,
            started_at: Some(now),
            completed_at: None,
            last_activity_at: now,
            params: task_params,
            result: None,
            error: None,
            retry_count: 0,
            max_retries: 3,
        };
        let _ = self.state.track_pending_task(&self.queue, task_info).await;

        // Capture vuln_id from exploit payloads so it survives into the result.
        let vuln_id_for_result = payload
            .get("vuln_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Spawn the LLM agent loop as a background task
        let queue = self.queue.clone();
        let tid = task_id.clone();
        let tt = task_type.to_string();
        let cred_inflight = self.credential_inflight.clone();
        let cred_key_owned = cred_key.clone();
        tokio::spawn(async move {
            let outcome = runner.execute_task(&tt, &tid, role, &payload).await;

            // Token usage is now recorded incrementally per-LLM-call via
            // CallbackHandler::on_token_usage — no batch recording needed here.

            // Convert outcome to TaskResult and push to result queue
            let mut result = match outcome {
                Ok(outcome) => {
                    // Merge all structured discoveries from tool results
                    let merged_discoveries = if outcome.discoveries.is_empty() {
                        None
                    } else {
                        Some(ares_tools::parsers::merge_discoveries(&outcome.discoveries))
                    };

                    // Collect raw tool outputs for secondary regex extraction
                    let tool_outputs_json: Vec<Value> = outcome
                        .tool_outputs
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect();

                    match &outcome.reason {
                        LoopEndReason::TaskComplete { result, .. } => {
                            // The result may be a JSON string (serialized object from
                            // the LLM) or plain text. If it parses as JSON, merge its
                            // fields into the result payload so extract_discoveries()
                            // can find any LLM-reported hosts/credentials.
                            let mut result_json =
                                if let Ok(parsed) = serde_json::from_str::<Value>(result) {
                                    if parsed.is_object() {
                                        let mut obj = parsed;
                                        obj["steps"] = json!(outcome.steps);
                                        obj["tool_calls"] = json!(outcome.tool_calls_dispatched);
                                        obj
                                    } else {
                                        json!({
                                            "summary": result,
                                            "steps": outcome.steps,
                                            "tool_calls": outcome.tool_calls_dispatched,
                                        })
                                    }
                                } else {
                                    json!({
                                        "summary": result,
                                        "steps": outcome.steps,
                                        "tool_calls": outcome.tool_calls_dispatched,
                                    })
                                };
                            // Overwrite "discoveries" with parser-extracted data only.
                            // The LLM's task_complete result is untrusted prose —
                            // any discovery-like keys it contains are ignored.
                            // Only ares-tools parsers (run on real tool stdout)
                            // produce authoritative discoveries.
                            if let Some(obj) = result_json.as_object_mut() {
                                obj.remove("discoveries");
                            }
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
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
                        LoopEndReason::RequestAssistance { issue, context } => {
                            let mut result_json = json!({
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
                            }
                            TaskResult {
                                task_id: tid.clone(),
                                success: false,
                                result: Some(result_json),
                                error: Some(format!(
                                    "Assistance needed: {issue} (context: {context})"
                                )),
                                completed_at: Some(Utc::now()),
                                worker_pod: Some("rust-llm-runner".into()),
                                agent_name: Some(tt.clone()),
                            }
                        }
                        LoopEndReason::MaxSteps => {
                            let mut result_json = json!({
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
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
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
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
                        LoopEndReason::MaxTokens => {
                            let mut result_json = json!({
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
                            }
                            TaskResult {
                                task_id: tid.clone(),
                                success: false,
                                result: Some(result_json),
                                error: Some("Agent hit max tokens".into()),
                                completed_at: Some(Utc::now()),
                                worker_pod: Some("rust-llm-runner".into()),
                                agent_name: Some(tt.clone()),
                            }
                        }
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

            // Inject vuln_id into result so process_completed_task can mark_exploited.
            if let Some(ref vid) = vuln_id_for_result {
                if let Some(ref mut res) = result.result {
                    if let Some(obj) = res.as_object_mut() {
                        obj.insert("vuln_id".to_string(), json!(vid));
                    }
                }
            }

            // Release per-credential concurrency slot
            if let Some(ref key) = cred_key_owned {
                cred_inflight.release(key).await;
            }

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
