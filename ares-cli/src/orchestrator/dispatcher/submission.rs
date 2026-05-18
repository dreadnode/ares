//! Task submission — throttled_submit and do_submit.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use serde_json::{json, Value};
use tracing::{debug, field::Empty, info, info_span, warn, Instrument};

use crate::orchestrator::deferred::DeferredTask;
use crate::orchestrator::llm_runner::LlmTaskRunner;
use crate::orchestrator::routing::ActiveTask;
use crate::orchestrator::task_queue::TaskResult;
use crate::orchestrator::throttling::ThrottleDecision;

use ares_llm::LoopEndReason;

use super::{Dispatcher, SubmissionOutcome};

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
        match self
            .throttled_submit_outcome(task_type, target_role, payload, priority)
            .await?
        {
            SubmissionOutcome::Submitted(id) => Ok(Some(id)),
            SubmissionOutcome::Deferred | SubmissionOutcome::Dropped => Ok(None),
        }
    }

    /// Like `throttled_submit` but returns a `SubmissionOutcome` distinguishing
    /// "deferred and safely enqueued" from "dropped due to overflow". Use this
    /// when the caller needs to dedup deferred work without losing tasks that
    /// got silently dropped on queue overflow.
    pub async fn throttled_submit_outcome(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<SubmissionOutcome> {
        let span = info_span!(
            "automation.dispatch",
            task_type = task_type,
            target_role = target_role,
            priority = priority,
            "task.id" = Empty,
            "automation.decision" = Empty,
        );
        self.throttled_submit_outcome_inner(task_type, target_role, payload, priority, span.clone())
            .instrument(span)
            .await
    }

    async fn throttled_submit_outcome_inner(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
        span: tracing::Span,
    ) -> Result<SubmissionOutcome> {
        // Rate cap: if this (task_type, target, principal) pattern ended
        // with `RequestAssistance` inside the assist-abandoned TTL, refuse
        // to redispatch. The pattern is usually doomed — missing tool
        // primitive, wrong-realm cred pairing, stale automation entry —
        // and each re-attempt burns ~30k input tokens loading the LLM
        // context only for the agent to bail with the same complaint.
        //
        // After `ASSIST_ABANDONED_TTL_SECS` (10 min by default) elapses,
        // one re-dispatch is allowed: parallel cred-harvest may have
        // landed the missing material since the abandonment, and the
        // earlier no-TTL behavior locked out patterns that became viable.
        // If the re-dispatch hits the same failure, the new
        // `mark_assist_abandoned` extends the window.
        let assist_key = assist_pattern_key(task_type, &payload);
        if let Some(ref key) = assist_key {
            let state = self.state.read().await;
            if state.is_assist_abandoned(key) {
                drop(state);
                span.record("automation.decision", "drop_assist_abandoned");
                debug!(
                    task_type,
                    target_role,
                    pattern = %key,
                    "Refusing dispatch — task pattern within assist-abandoned TTL",
                );
                return Ok(SubmissionOutcome::Dropped);
            }
        }

        let decision = self
            .throttler
            .check(task_type, target_role, Some(&payload))
            .await;

        match decision {
            ThrottleDecision::Allow => {
                span.record("automation.decision", "allow");
                let outcome = self
                    .do_submit_outcome(task_type, target_role, payload, priority)
                    .await?;
                if let SubmissionOutcome::Submitted(ref tid) = outcome {
                    span.record("task.id", tid.as_str());
                }
                Ok(outcome)
            }
            ThrottleDecision::Defer => {
                span.record("automation.decision", "defer");
                self.enqueue_deferred(task_type, target_role, payload, priority)
                    .await
            }
            ThrottleDecision::Wait(dur) => {
                span.record("automation.decision", "wait");
                tokio::time::sleep(dur).await;
                let retry_decision = self
                    .throttler
                    .check(task_type, target_role, Some(&payload))
                    .await;
                match retry_decision {
                    ThrottleDecision::Allow => {
                        span.record("automation.decision", "wait_allow");
                        let outcome = self
                            .do_submit_outcome(task_type, target_role, payload, priority)
                            .await?;
                        if let SubmissionOutcome::Submitted(ref tid) = outcome {
                            span.record("task.id", tid.as_str());
                        }
                        Ok(outcome)
                    }
                    _ => {
                        span.record("automation.decision", "wait_defer");
                        self.enqueue_deferred(task_type, target_role, payload, priority)
                            .await
                    }
                }
            }
        }
    }

    async fn enqueue_deferred(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<SubmissionOutcome> {
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
                Ok(SubmissionOutcome::Deferred)
            }
            Ok(false) => {
                warn!(
                    task_type,
                    target_role, "Deferred queue full, task dropped (will retry next tick)"
                );
                Ok(SubmissionOutcome::Dropped)
            }
            Err(e) => {
                warn!(err = %e, "Failed to defer task, attempting direct submit");
                self.do_submit_outcome(task_type, target_role, task.payload, priority)
                    .await
            }
        }
    }

    /// Submit bypassing the throttle soft/hard cap.  Used by automations
    /// whose tasks are small (single LDAP query) and must not be blocked by
    /// long-running initial recon.  Still routes through `do_submit` which
    /// respects the per-role semaphore.
    pub async fn force_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<Option<String>> {
        self.do_submit(task_type, target_role, payload, priority)
            .await
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
        priority: i32,
    ) -> Result<Option<String>> {
        match self
            .do_submit_outcome(task_type, target_role, payload, priority)
            .await?
        {
            SubmissionOutcome::Submitted(id) => Ok(Some(id)),
            SubmissionOutcome::Deferred | SubmissionOutcome::Dropped => Ok(None),
        }
    }

    /// Like `do_submit` but returns a `SubmissionOutcome`.
    pub async fn do_submit_outcome(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<SubmissionOutcome> {
        let role = ares_llm::tool_registry::AgentRole::parse(target_role)
            .or_else(|| crate::orchestrator::llm_runner::role_for_task_type(task_type));

        let Some(role) = role else {
            warn!(
                task_type = task_type,
                target_role = target_role,
                "No LLM role mapping for task type or target role, dropping"
            );
            return Ok(SubmissionOutcome::Dropped);
        };

        self.submit_to_llm(
            self.llm_runner.clone(),
            task_type,
            target_role,
            role,
            payload,
            priority,
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
        priority: i32,
    ) -> Result<SubmissionOutcome> {
        // Per-credential concurrency gate: if too many tasks are already
        // in-flight for this credential, defer instead of spawning another.
        let cred_key = super::credential_key_from_payload(&payload);
        if let Some(ref key) = cred_key {
            if !self.credential_inflight.try_acquire(key).await {
                debug!(
                    credential = key.as_str(),
                    task_type, "Credential concurrency limit reached, deferring task"
                );
                let task = DeferredTask {
                    priority,
                    enqueue_time: Utc::now().timestamp() as f64,
                    task_type: task_type.to_string(),
                    target_role: target_role.to_string(),
                    payload,
                    source_agent: "orchestrator".to_string(),
                };
                return match self.deferred.enqueue(&task).await {
                    Ok(true) => Ok(SubmissionOutcome::Deferred),
                    Ok(false) => {
                        warn!(
                            credential = key.as_str(),
                            task_type, "Deferred queue full while gating on cred — task dropped"
                        );
                        Ok(SubmissionOutcome::Dropped)
                    }
                    Err(e) => {
                        warn!(err = %e, "Failed to defer cred-gated task");
                        Ok(SubmissionOutcome::Dropped)
                    }
                };
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
                credential_key: cred_key.clone(),
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
        let task_params = task_params_from_payload(&payload, cred_key.as_deref());
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
        // Capture the assist-abandon pattern key + state handle so the
        // spawn can record on RequestAssistance without re-resolving them.
        let state_for_assist = self.state.clone();
        let assist_key_for_spawn = assist_pattern_key(&tt, &payload);
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

                    // LLM-fabricated findings (`report_finding`,
                    // `report_lateral_success`) are kept on a SEPARATE field so
                    // `extract_discoveries` (which only reads "discoveries")
                    // never feeds them into `publish_*` state writes. Reports
                    // surface them under `llm_findings` for context only.
                    let llm_findings_json: Option<Value> = if outcome.llm_findings.is_empty() {
                        None
                    } else {
                        Some(Value::Array(outcome.llm_findings.clone()))
                    };

                    // Collect raw tool outputs for secondary regex extraction.
                    // Serialize as objects {name, arguments, output} so consumers
                    // can be tool-aware (skip credential regex for hash-auth invocations).
                    let tool_outputs_json: Vec<Value> = outcome
                        .tool_outputs
                        .iter()
                        .map(|to| {
                            serde_json::json!({
                                "name": to.name,
                                "arguments": to.arguments,
                                "output": to.output,
                            })
                        })
                        .collect();

                    match &outcome.reason {
                        LoopEndReason::TaskComplete { result, .. } => {
                            let parsed = parse_task_complete_result(
                                result,
                                outcome.steps,
                                outcome.tool_calls_dispatched,
                            );
                            let result_json = merge_result_extras(
                                parsed,
                                merged_discoveries,
                                llm_findings_json.clone(),
                                tool_outputs_json.clone(),
                            );
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
                            let result_json = merge_result_extras(
                                json!({
                                    "steps": outcome.steps,
                                    "tool_calls": outcome.tool_calls_dispatched,
                                }),
                                merged_discoveries,
                                llm_findings_json.clone(),
                                tool_outputs_json.clone(),
                            );
                            // Record this pattern as abandoned so future
                            // dispatches of (task_type, target, user,
                            // domain) get refused at throttled_submit
                            // for the next ASSIST_ABANDONED_TTL_SECS. One
                            // failure is enough — re-running an LLM round
                            // on a doomed task costs ~30k input tokens for
                            // a guaranteed repeat of the same complaint.
                            // The TTL gives the pattern one re-look later
                            // in case state has shifted (cred materialized,
                            // vuln became reachable).
                            if let Some(ref key) = assist_key_for_spawn {
                                state_for_assist
                                    .write()
                                    .await
                                    .mark_assist_abandoned(key.clone());
                                warn!(
                                    task_id = %tid,
                                    pattern = %key,
                                    "Marked task pattern as assist-abandoned — future dispatches dropped until TTL expires",
                                );
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
                            let result_json = merge_result_extras(
                                json!({
                                    "steps": outcome.steps,
                                    "tool_calls": outcome.tool_calls_dispatched,
                                }),
                                merged_discoveries,
                                llm_findings_json.clone(),
                                tool_outputs_json.clone(),
                            );
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
                            let result_json = merge_result_extras(
                                json!({"summary": content}),
                                merged_discoveries,
                                llm_findings_json.clone(),
                                tool_outputs_json.clone(),
                            );
                            // Bare end-of-turn means the LLM stopped without
                            // calling task_complete or request_assistance — it
                            // is a stall, not a success. Treating it as success
                            // lets capability-gap exits masquerade as
                            // accomplished objectives in run accounting.
                            TaskResult {
                                task_id: tid.clone(),
                                success: false,
                                result: Some(result_json),
                                error: Some(
                                    "Agent ended turn without task_complete or \
                                     request_assistance"
                                        .into(),
                                ),
                                completed_at: Some(Utc::now()),
                                worker_pod: Some("rust-llm-runner".into()),
                                agent_name: Some(tt.clone()),
                            }
                        }
                        LoopEndReason::MaxTokens => {
                            let result_json = merge_result_extras(
                                json!({
                                    "steps": outcome.steps,
                                    "tool_calls": outcome.tool_calls_dispatched,
                                }),
                                merged_discoveries,
                                llm_findings_json.clone(),
                                tool_outputs_json.clone(),
                            );
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
                        LoopEndReason::BudgetExceeded { reason } => {
                            let result_json = merge_result_extras(
                                json!({
                                    "steps": outcome.steps,
                                    "tool_calls": outcome.tool_calls_dispatched,
                                }),
                                merged_discoveries,
                                None,
                                tool_outputs_json.clone(),
                            );
                            TaskResult {
                                task_id: tid.clone(),
                                success: false,
                                result: Some(result_json),
                                error: Some(format!("Budget exceeded: {reason}")),
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
                inject_vuln_id_into_result(&mut result, vid);
            }

            // The CredentialInflight slot is released by whichever caller
            // evicts this task from `ActiveTaskTracker` — either the result
            // consumer when it picks up the result, or the stale-task
            // cleanup when this future has hung past the timeout. That
            // mirrors the slot to the tracker entry's lifetime, so a hung
            // future doesn't pin the slot indefinitely.

            // Push result to the normal result queue so the result consumer picks it up
            if let Err(e) = queue.send_result(&tid, &result).await {
                warn!(
                    task_id = %tid,
                    err = %e,
                    "Failed to push LLM task result to Redis"
                );
            }
        });

        Ok(SubmissionOutcome::Submitted(task_id))
    }
}

/// Extract the subset of payload fields we want to thread into the pending-task
/// record so result processing has the metadata it needs without re-reading
/// the original payload.
///
/// Used by `submit_to_llm` when persisting the `TaskInfo` to Redis.
pub(crate) fn task_params_from_payload(
    payload: &Value,
    cred_key: Option<&str>,
) -> HashMap<String, Value> {
    let mut task_params: HashMap<String, Value> = HashMap::new();
    if let Some(key) = cred_key {
        task_params.insert("credential_key".to_string(), json!(key));
    }
    for key in &[
        "target_ip",
        "domain",
        "technique",
        "hash_value",
        "just_dc_user",
        "credential",
    ] {
        if let Some(val) = payload.get(*key) {
            task_params.insert(key.to_string(), val.clone());
        }
    }
    task_params
}

/// Inject a `vuln_id` field into a `TaskResult`'s `result` payload so
/// `process_completed_task` can mark the parent vuln exploited on success.
///
/// No-op when `result.result` is `None` or the inner value isn't an object.
pub(crate) fn inject_vuln_id_into_result(result: &mut TaskResult, vuln_id: &str) {
    if let Some(ref mut res) = result.result {
        if let Some(obj) = res.as_object_mut() {
            obj.insert("vuln_id".to_string(), json!(vuln_id));
        }
    }
}

/// Parse the `task_complete` `result` string into a JSON object. If the string
/// is JSON-decodable AND parses to an object, that object is returned; the
/// `steps` and `tool_calls` fields are then injected. Otherwise the string
/// becomes the `summary` field of a fresh object alongside the same
/// `steps`/`tool_calls` numbers.
///
/// Extracted from the inline match-arm so the fallback path (LLM returned
/// raw text) and the structured path (LLM returned a JSON object) can both
/// be tested without spinning up an agent loop.
pub(crate) fn parse_task_complete_result(result: &str, steps: u32, tool_calls: u32) -> Value {
    if let Ok(parsed) = serde_json::from_str::<Value>(result) {
        if parsed.is_object() {
            let mut obj = parsed;
            obj["steps"] = json!(steps);
            obj["tool_calls"] = json!(tool_calls);
            return obj;
        }
    }
    json!({
        "summary": result,
        "steps": steps,
        "tool_calls": tool_calls,
    })
}

/// Merge discoveries, LLM-fabricated findings, and raw tool outputs into a
/// result-payload object. Pure JSON manipulation — drops any caller-supplied
/// evidence keys first (LLM-controlled prose must never shadow parser/tool
/// output) and only emits each section when non-empty.
pub(crate) fn merge_result_extras(
    mut result_json: Value,
    merged_discoveries: Option<Value>,
    llm_findings: Option<Value>,
    tool_outputs: Vec<Value>,
) -> Value {
    if let Some(obj) = result_json.as_object_mut() {
        for key in [
            "discoveries",
            "llm_findings",
            "tool_outputs",
            "tool_output",
            "output",
            "has_domain_admin",
            "domain_admin_path",
            "has_golden_ticket",
            "vuln_id",
            "domain",
            "target",
            "target_ip",
            "target_spn",
        ] {
            obj.remove(key);
        }
    }
    if let Some(disc) = merged_discoveries {
        result_json["discoveries"] = disc;
    }
    if let Some(findings) = llm_findings {
        result_json["llm_findings"] = findings;
    }
    if !tool_outputs.is_empty() {
        result_json["tool_outputs"] = Value::Array(tool_outputs);
    }
    result_json
}

/// Canonical key identifying a task pattern for the assist-abandon dedup
/// set. Keys off (task_type, target_ip-or-dc_ip, username, domain).
///
/// Only returns a key when the payload identifies a SPECIFIC principal
/// (non-empty `username`). Generic enum tasks dispatched without a
/// username — anonymous recon, low-hanging-fruit probes, automation
/// tasks targeting a host without binding a user — MUST NOT be
/// abandoned, because (a) they routinely fire many times against the
/// same target as state accumulates and (b) one transient failure of
/// an empty-user enum task against a DC would otherwise blacklist all
/// further enumeration of that host. The previous version of this
/// function returned a key with empty username embedded
/// (`task_type|target||domain`); a single assistance failure on a
/// generic recon task permanently blocked all further enum dispatches
/// against that target — choking the orchestrator after ~6 such
/// failures across the 3 DCs in a typical multi-forest run.
///
/// With a non-empty username, one failure of (task_type, target, user,
/// domain) is enough to suppress retries: the same principal failing
/// the same task against the same target is the "wrong realm cred",
/// "missing tool primitive", or "no auth resolvable" signature we want
/// to stop burning tokens on.
pub(crate) fn assist_pattern_key(task_type: &str, payload: &serde_json::Value) -> Option<String> {
    let obj = payload.as_object()?;
    let pick = |k: &str| -> &str { obj.get(k).and_then(|v| v.as_str()).unwrap_or("") };

    // Username lookup priority:
    //   1. Top-level `username` — set by enum/recon/spray tasks dispatched
    //      via the various recon/exploit submit helpers.
    //   2. `credential.username` — exploit payloads built by
    //      `request_exploit` (task_builders.rs ~line 578) nest the auth
    //      identity under `credential` instead of promoting it. Without
    //      this fallback the assist-abandoned dedup silently bypassed every
    //      LLM-routed exploit dispatch — observed in a live op as a
    //      delegation exploit retried 6× in 26 minutes after attempt 1
    //      ended with RequestAssistance, burning ~30k input tokens per
    //      retry on a guaranteed-repeat doomed task.
    //   3. `hash_username` — pass-the-hash exploit payloads carry the
    //      principal here when no plaintext credential is in state.
    let credential_username = obj
        .get("credential")
        .and_then(|v| v.as_object())
        .and_then(|c| c.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let username = if !pick("username").is_empty() {
        pick("username")
    } else if !credential_username.is_empty() {
        credential_username
    } else {
        pick("hash_username")
    };

    if username.is_empty() {
        return None;
    }
    let target = {
        let t = pick("target_ip");
        if !t.is_empty() {
            t.to_string()
        } else {
            pick("dc_ip").to_string()
        }
    };
    // Domain lookup mirrors username: fall back to the credential's domain
    // when the top-level `domain` is absent. Without this, two exploits
    // against the same target with creds from different forests would
    // collide into the same pattern key.
    let credential_domain = obj
        .get("credential")
        .and_then(|v| v.as_object())
        .and_then(|c| c.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let domain = if !pick("domain").is_empty() {
        pick("domain")
    } else {
        credential_domain
    };
    Some(format!(
        "{task_type}|{target}|{u}|{d}",
        u = username.to_lowercase(),
        d = domain.to_lowercase(),
    ))
}

#[cfg(test)]
mod assist_key_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pattern_key_includes_target_user_domain() {
        let p =
            json!({"target_ip": "192.168.58.10", "username": "Alice", "domain": "Contoso.LOCAL"});
        let k = assist_pattern_key("smb_login_check", &p).unwrap();
        assert_eq!(k, "smb_login_check|192.168.58.10|alice|contoso.local");
    }

    #[test]
    fn pattern_key_falls_back_to_dc_ip() {
        let p = json!({"dc_ip": "192.168.58.10", "username": "alice", "domain": "contoso.local"});
        let k = assist_pattern_key("certipy_find", &p).unwrap();
        assert!(k.starts_with("certipy_find|192.168.58.10|"));
    }

    #[test]
    fn pattern_key_none_when_no_identifying_fields() {
        let p = json!({"technique": "recon"});
        assert!(assist_pattern_key("recon", &p).is_none());
    }

    #[test]
    fn pattern_key_none_for_empty_username_generic_enum() {
        // The dispatcher fires generic enum tasks against a target with
        // no `username` field; one transient assistance failure must NOT
        // permanently blacklist all future enumeration of that target.
        // Regression for: empty-user keys (`recon|target||domain`) earlier
        // choked the orchestrator after ~6 failures across 3 DCs.
        let p = json!({"target_ip": "192.168.58.10", "domain": "contoso.local"});
        assert!(
            assist_pattern_key("recon", &p).is_none(),
            "generic-enum task (no username) must never be abandoned"
        );
        let p = json!({"dc_ip": "192.168.58.10", "domain": "contoso.local", "username": ""});
        assert!(
            assist_pattern_key("credential_access", &p).is_none(),
            "explicit empty username must never be abandoned"
        );
    }

    #[test]
    fn pattern_key_reads_username_from_nested_credential_for_exploits() {
        // Exploit payloads built by `request_exploit` nest the auth
        // identity under `credential` instead of top-level. Without this
        // fallback, the assist-abandoned dedup silently bypasses every
        // exploit dispatch and a RequestAssistance failure ends up
        // re-running ~5× through MAX_EXPLOIT_FAILURES.
        let p = json!({
            "vuln_id": "constrained_delegation_alice",
            "vuln_type": "constrained_delegation",
            "target_ip": "192.168.58.10",
            "credential": {
                "username": "alice",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            }
        });
        let k = assist_pattern_key("exploit", &p).expect("exploit payload should yield a key");
        assert_eq!(k, "exploit|192.168.58.10|alice|contoso.local");
    }

    #[test]
    fn pattern_key_prefers_top_level_username_over_credential() {
        // If both are set (defense-in-depth), top-level wins so existing
        // call sites that explicitly promoted username keep their
        // pre-existing pattern keys intact.
        let p = json!({
            "username": "outer",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {"username": "inner", "domain": "other.local"}
        });
        let k = assist_pattern_key("exploit", &p).unwrap();
        assert!(k.contains("|outer|"), "got {k}");
        // domain also prefers top-level when present.
        assert!(k.ends_with("|contoso.local"), "got {k}");
    }

    #[test]
    fn pattern_key_uses_hash_username_when_no_credential() {
        // Pass-the-hash payloads from request_exploit may carry only
        // `hash_username` when no plaintext cred exists in state.
        let p = json!({
            "vuln_id": "constrained_delegation_bob",
            "hash_username": "bob",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        });
        let k = assist_pattern_key("exploit", &p).expect("hash payload should yield a key");
        assert_eq!(k, "exploit|192.168.58.10|bob|contoso.local");
    }

    #[test]
    fn pattern_key_falls_back_to_credential_domain() {
        // Cross-forest exploits omit top-level `domain` but the credential
        // carries the auth realm; the key must include it so two different
        // forests aren't collapsed into the same pattern.
        let p = json!({
            "vuln_id": "rbcd_alice",
            "target_ip": "192.168.58.20",
            "credential": {"username": "alice", "domain": "fabrikam.local"}
        });
        let k = assist_pattern_key("exploit", &p).unwrap();
        assert_eq!(k, "exploit|192.168.58.20|alice|fabrikam.local");
    }

    #[test]
    fn pattern_key_credential_lowercased_consistently() {
        // Credential-sourced username/domain must hit the same lowercase
        // treatment as top-level so the same logical identity hashes to
        // the same key regardless of payload shape.
        let p_top = json!({
            "username": "Alice",
            "domain": "Contoso.LOCAL",
            "target_ip": "192.168.58.10",
        });
        let p_nested = json!({
            "target_ip": "192.168.58.10",
            "credential": {"username": "Alice", "domain": "Contoso.LOCAL"}
        });
        assert_eq!(
            assist_pattern_key("exploit", &p_top),
            assist_pattern_key("exploit", &p_nested),
            "top-level and nested forms of the same identity must share a key"
        );
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use serde_json::json;

    // --- task_params_from_payload ---------------------------------------

    #[test]
    fn task_params_includes_credential_key_when_provided() {
        let payload = json!({"target_ip": "192.168.58.10"});
        let p = task_params_from_payload(&payload, Some("cred:alice@contoso.local"));
        assert_eq!(p["credential_key"], "cred:alice@contoso.local");
    }

    #[test]
    fn task_params_omits_credential_key_when_none() {
        let payload = json!({"target_ip": "192.168.58.10"});
        let p = task_params_from_payload(&payload, None);
        assert!(!p.contains_key("credential_key"));
    }

    #[test]
    fn task_params_threads_recognised_metadata_keys() {
        let payload = json!({
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "technique": "asrep_roast",
            "hash_value": "deadbeef",
            "just_dc_user": "alice",
            "credential": {"username": "alice", "password": "P@ss"},
            "extra_field": "ignored",
        });
        let p = task_params_from_payload(&payload, None);
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["technique"], "asrep_roast");
        assert_eq!(p["hash_value"], "deadbeef");
        assert_eq!(p["just_dc_user"], "alice");
        assert_eq!(p["credential"]["username"], "alice");
        assert!(!p.contains_key("extra_field"));
    }

    #[test]
    fn task_params_missing_fields_omitted() {
        let payload = json!({});
        let p = task_params_from_payload(&payload, None);
        assert!(p.is_empty());
    }

    // --- inject_vuln_id_into_result --------------------------------------

    fn make_result(result: Option<serde_json::Value>) -> TaskResult {
        TaskResult {
            task_id: "t-test".into(),
            success: true,
            result,
            error: None,
            completed_at: Some(chrono::Utc::now()),
            worker_pod: Some("test".into()),
            agent_name: Some("test".into()),
        }
    }

    #[test]
    fn inject_vuln_id_adds_field_to_existing_object() {
        let mut tr = make_result(Some(json!({"summary": "ok"})));
        inject_vuln_id_into_result(&mut tr, "vuln-1");
        assert_eq!(tr.result.unwrap()["vuln_id"], "vuln-1");
    }

    #[test]
    fn inject_vuln_id_no_op_when_result_none() {
        let mut tr = make_result(None);
        inject_vuln_id_into_result(&mut tr, "vuln-1");
        assert!(tr.result.is_none());
    }

    #[test]
    fn inject_vuln_id_no_op_when_result_not_object() {
        let mut tr = make_result(Some(json!("just a string")));
        inject_vuln_id_into_result(&mut tr, "vuln-1");
        // Stayed a string; injection silently no-ops.
        assert_eq!(tr.result.unwrap(), json!("just a string"));
    }

    // --- parse_task_complete_result --------------------------------------

    #[test]
    fn parse_complete_result_uses_object_form_when_json() {
        let r =
            parse_task_complete_result(r#"{"summary":"ok","credentials":[{"u":"alice"}]}"#, 5, 10);
        assert_eq!(r["summary"], "ok");
        assert_eq!(r["credentials"][0]["u"], "alice");
        assert_eq!(r["steps"], 5);
        assert_eq!(r["tool_calls"], 10);
    }

    #[test]
    fn parse_complete_result_falls_back_for_plain_text() {
        let r = parse_task_complete_result("just a string", 3, 1);
        assert_eq!(r["summary"], "just a string");
        assert_eq!(r["steps"], 3);
        assert_eq!(r["tool_calls"], 1);
    }

    #[test]
    fn parse_complete_result_falls_back_for_json_non_object() {
        // JSON array → falls back to summary path (not an object).
        let r = parse_task_complete_result("[1,2,3]", 2, 2);
        assert_eq!(r["summary"], "[1,2,3]");
        assert_eq!(r["steps"], 2);
    }

    #[test]
    fn parse_complete_result_object_overwrites_steps_and_tool_calls() {
        // LLM-supplied steps/tool_calls fields get overwritten by the
        // dispatcher-tracked counts.
        let r =
            parse_task_complete_result(r#"{"summary":"ok","steps":999,"tool_calls":999}"#, 5, 10);
        assert_eq!(r["steps"], 5);
        assert_eq!(r["tool_calls"], 10);
    }

    // --- merge_result_extras ---------------------------------------------

    #[test]
    fn merge_extras_strips_llm_supplied_keys_first() {
        let base = json!({
            "summary": "ok",
            "discoveries": {"credentials": [{"forged_by_llm": "true"}]},
            "llm_findings": [{"forged_by_llm": "true"}],
            "tool_outputs": [{"output": "Saving ticket in fake.ccache"}],
            "tool_output": "Domain Sid: S-1-5-21-1-2-3",
            "output": "SeImpersonatePrivilege Enabled",
            "has_domain_admin": true,
            "domain_admin_path": "agent-made path",
            "has_golden_ticket": true,
            "vuln_id": "agent_supplied_vuln",
            "domain": "agent.local",
            "target_ip": "192.0.2.10",
        });
        let m = merge_result_extras(
            base,
            Some(json!({"credentials": [{"username": "alice"}]})),
            None,
            Vec::new(),
        );
        // LLM-supplied `discoveries` overwritten by the parser-derived value.
        assert_eq!(m["discoveries"]["credentials"][0]["username"], "alice");
        assert_eq!(
            m["discoveries"]["credentials"][0].get("forged_by_llm"),
            None
        );
        // LLM-supplied `llm_findings` stripped entirely (caller passed None).
        assert!(m.get("llm_findings").is_none());
        for key in [
            "tool_outputs",
            "tool_output",
            "output",
            "has_domain_admin",
            "domain_admin_path",
            "has_golden_ticket",
            "vuln_id",
            "domain",
            "target_ip",
        ] {
            assert!(m.get(key).is_none(), "{key} should be stripped");
        }
    }

    #[test]
    fn merge_extras_keeps_caller_supplied_findings() {
        let base = json!({"summary": "ok"});
        let m = merge_result_extras(base, None, Some(json!([{"finding": "x"}])), Vec::new());
        assert_eq!(m["llm_findings"][0]["finding"], "x");
    }

    #[test]
    fn merge_extras_emits_tool_outputs_only_when_present() {
        let base = json!({"summary": "ok"});
        let m = merge_result_extras(base.clone(), None, None, Vec::new());
        assert!(m.get("tool_outputs").is_none());

        let m = merge_result_extras(
            base,
            None,
            None,
            vec![json!({"name": "tool", "output": "x"})],
        );
        assert!(m["tool_outputs"].is_array());
        assert_eq!(m["tool_outputs"][0]["output"], "x");
    }

    #[test]
    fn merge_extras_omits_discoveries_when_none() {
        let base = json!({"summary": "ok"});
        let m = merge_result_extras(base, None, None, Vec::new());
        assert!(m.get("discoveries").is_none());
    }

    #[test]
    fn merge_extras_preserves_other_existing_fields() {
        let base = json!({"summary": "ok", "steps": 5, "tool_calls": 12});
        let m = merge_result_extras(base, None, None, Vec::new());
        assert_eq!(m["summary"], "ok");
        assert_eq!(m["steps"], 5);
        assert_eq!(m["tool_calls"], 12);
    }
}
