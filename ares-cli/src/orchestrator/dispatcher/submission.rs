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
        // Hard rate cap: if this (task_type, target, principal) pattern
        // already ended with `RequestAssistance` once this op, refuse to
        // redispatch. The pattern is doomed — usually a missing tool
        // primitive, a wrong-realm cred pairing, or a stale automation
        // entry — and each re-attempt burns ~30k input tokens loading the
        // LLM context only for the agent to bail with the same complaint.
        // Re-enabling requires the operator to manually clear the dedup
        // (or starts a new op with a wiped Redis).
        let assist_key = assist_pattern_key(task_type, &payload);
        if let Some(ref key) = assist_key {
            let state = self.state.read().await;
            if state.is_processed(crate::orchestrator::state::DEDUP_ASSIST_ABANDONED, key) {
                drop(state);
                span.record("automation.decision", "drop_assist_abandoned");
                debug!(
                    task_type,
                    target_role,
                    pattern = %key,
                    "Refusing dispatch — task pattern previously ended with RequestAssistance",
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

        let role = match role {
            Some(r) => r,
            None => {
                warn!(
                    task_type = task_type,
                    target_role = target_role,
                    "No LLM role mapping for task type or target role, dropping"
                );
                return Ok(SubmissionOutcome::Dropped);
            }
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
        let mut task_params: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(ref key) = cred_key {
            task_params.insert("credential_key".to_string(), serde_json::json!(key));
        }
        // Propagate task metadata so process_completed_task can access them
        // (mark_host_owned needs target_ip, domain attribution needs domain,
        // the Impacket failure classifier needs technique/hash_value/
        // just_dc_user/credential to rebuild a corrected re-dispatch).
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
                            // produce authoritative discoveries. LLM-fabricated
                            // findings live on a separate `llm_findings` field.
                            if let Some(obj) = result_json.as_object_mut() {
                                obj.remove("discoveries");
                                obj.remove("llm_findings");
                            }
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if let Some(findings) = llm_findings_json.clone() {
                                result_json["llm_findings"] = findings;
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
                            if let Some(findings) = llm_findings_json.clone() {
                                result_json["llm_findings"] = findings;
                            }
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
                            }
                            // Record this pattern as abandoned so future
                            // dispatches of (task_type, target, user, domain)
                            // get refused at throttled_submit. One failure is
                            // enough — re-running an LLM round on a doomed
                            // task costs ~30k input tokens for a guaranteed
                            // repeat of the same "Assistance requested".
                            if let Some(ref key) = assist_key_for_spawn {
                                state_for_assist.write().await.mark_processed(
                                    crate::orchestrator::state::DEDUP_ASSIST_ABANDONED,
                                    key.clone(),
                                );
                                let _ = state_for_assist
                                    .persist_dedup(
                                        &queue,
                                        crate::orchestrator::state::DEDUP_ASSIST_ABANDONED,
                                        key,
                                    )
                                    .await;
                                warn!(
                                    task_id = %tid,
                                    pattern = %key,
                                    "Marked task pattern as assist-abandoned — future dispatches will be dropped",
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
                            let mut result_json = json!({
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if let Some(findings) = llm_findings_json.clone() {
                                result_json["llm_findings"] = findings;
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
                            if let Some(findings) = llm_findings_json.clone() {
                                result_json["llm_findings"] = findings;
                            }
                            if !tool_outputs_json.is_empty() {
                                result_json["tool_outputs"] =
                                    Value::Array(tool_outputs_json.clone());
                            }
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
                            let mut result_json = json!({
                                "steps": outcome.steps,
                                "tool_calls": outcome.tool_calls_dispatched,
                            });
                            if let Some(disc) = merged_discoveries {
                                result_json["discoveries"] = disc;
                            }
                            if let Some(findings) = llm_findings_json.clone() {
                                result_json["llm_findings"] = findings;
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
                        LoopEndReason::BudgetExceeded { reason } => {
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
                if let Some(ref mut res) = result.result {
                    if let Some(obj) = res.as_object_mut() {
                        obj.insert("vuln_id".to_string(), json!(vid));
                    }
                }
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
    let username = pick("username");
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
    let domain = pick("domain");
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
}
