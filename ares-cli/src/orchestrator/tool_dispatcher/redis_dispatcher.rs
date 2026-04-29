//! NATS-backed tool dispatcher.
//!
//! Each tool call becomes a NATS request to `ares.tools.exec.{role}` with
//! an auto-generated reply inbox; the worker subscribes to that subject as
//! a queue group and replies on the inbox. This replaces the old Redis
//! BRPOP pattern, eliminating the dedicated-connection-per-waiter
//! requirement (a single multiplexed NATS connection handles arbitrary
//! concurrent request/reply pairs).

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::{debug, warn, Instrument};

use ares_core::nats;
use ares_core::telemetry::propagation::inject_traceparent;
use ares_core::telemetry::spans::{producer_span, Team};
use ares_llm::{ToolCall, ToolExecResult};

use crate::orchestrator::task_queue::TaskQueue;

use super::{
    extract_credential_key, push_realtime_discoveries, AuthThrottle, ToolExecRequest,
    ToolExecResponse,
};

/// Dispatches tool calls to workers via NATS request/reply.
///
/// When tool results contain structured discoveries (hosts, credentials, etc.),
/// they are pushed to the `ares:discoveries:{op_id}` list for real-time
/// processing by the discovery poller — ensuring discoveries reach state
/// immediately rather than waiting for the task result consumer.
pub struct RedisToolDispatcher {
    pub(super) queue: TaskQueue,
    pub(super) tool_timeout: Duration,
    pub(super) operation_id: String,
    pub(super) auth_throttle: AuthThrottle,
}

impl RedisToolDispatcher {
    pub fn new(queue: TaskQueue, operation_id: String, auth_throttle: AuthThrottle) -> Self {
        Self {
            queue,
            tool_timeout: Duration::from_secs(super::DEFAULT_TOOL_TIMEOUT_SECS),
            operation_id,
            auth_throttle,
        }
    }
}

/// Synthetic ToolExecResult returned when the NATS request itself fails
/// (broker disconnect, no responders, etc.). Free function so the wording
/// is testable and stays in lock-step with the agent-facing error message.
pub(super) fn dispatch_error_result(
    tool_name: &str,
    err: impl std::fmt::Display,
) -> ToolExecResult {
    ToolExecResult {
        output: String::new(),
        error: Some(format!("Tool '{tool_name}' dispatch error: {err}")),
        discoveries: None,
    }
}

/// Synthetic ToolExecResult returned when the request times out waiting for
/// a worker to reply.
pub(super) fn dispatch_timeout_result(tool_name: &str, timeout: Duration) -> ToolExecResult {
    ToolExecResult {
        output: String::new(),
        error: Some(format!(
            "Tool '{tool_name}' timed out after {}s",
            timeout.as_secs()
        )),
        discoveries: None,
    }
}

/// Per-call request id for correlating worker replies with outstanding calls.
pub(super) fn build_call_id(tool_name: &str) -> String {
    format!("{tool_name}_{}", uuid::Uuid::new_v4().simple())
}

/// Build the wire request that `dispatch_tool` sends to the worker. Pulled
/// out so the request shape can be unit-tested without a NATS broker.
pub(super) fn build_tool_exec_request(
    call_id: String,
    task_id: &str,
    tool_name: &str,
    arguments: serde_json::Value,
    traceparent: Option<String>,
    operation_id: Option<String>,
) -> ToolExecRequest {
    ToolExecRequest {
        call_id,
        task_id: task_id.to_string(),
        tool_name: tool_name.to_string(),
        arguments,
        traceparent,
        operation_id,
    }
}

/// Convert a deserialized worker reply into the [`ToolExecResult`] returned
/// to the LLM agent loop.
pub(super) fn tool_exec_result_from_response(response: ToolExecResponse) -> ToolExecResult {
    ToolExecResult {
        output: response.output,
        error: response.error,
        discoveries: response.discoveries,
    }
}

#[async_trait::async_trait]
impl ares_llm::ToolDispatcher for RedisToolDispatcher {
    async fn dispatch_tool(
        &self,
        role: &str,
        task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        let effective_role = super::resolve_queue_role(role, &call.name);
        let span = producer_span(
            &format!("dispatch.{}", call.name),
            role,
            Team::Red,
            &format!("ares-worker-{effective_role}"),
        );

        async {
            // Rate-limit auth-bearing tools to prevent AD account lockout
            if let Some(cred_key) = extract_credential_key(call) {
                self.auth_throttle.acquire(&cred_key).await;
            }

            let call_id = build_call_id(&call.name);

            // Inject trace context for cross-service span linking
            let traceparent = inject_traceparent(&tracing::Span::current());

            let request = build_tool_exec_request(
                call_id.clone(),
                task_id,
                &call.name,
                call.arguments.clone(),
                traceparent,
                Some(self.operation_id.clone()),
            );

            let subject = nats::tool_exec_subject(effective_role);
            let payload =
                serde_json::to_vec(&request).context("Failed to serialize tool exec request")?;

            debug!(
                tool = %call.name,
                call_id = %call_id,
                subject = %subject,
                effective_role = %effective_role,
                "Dispatching tool call to worker"
            );

            let nats = self
                .queue
                .nats_broker()
                .context("ToolDispatcher requires NATS broker")?;
            let client = nats.client().clone();

            let timeout = self.tool_timeout;
            let response_msg = match tokio::time::timeout(
                timeout,
                client.request(subject.clone(), Bytes::from(payload)),
            )
            .await
            {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => {
                    warn!(
                        tool = %call.name,
                        call_id = %call_id,
                        err = %e,
                        "NATS request failed"
                    );
                    return Ok(dispatch_error_result(&call.name, e));
                }
                Err(_) => {
                    warn!(
                        tool = %call.name,
                        call_id = %call_id,
                        timeout_secs = timeout.as_secs(),
                        "Tool execution timed out"
                    );
                    return Ok(dispatch_timeout_result(&call.name, timeout));
                }
            };

            let response: ToolExecResponse = serde_json::from_slice(&response_msg.payload)
                .context("Failed to deserialize tool exec response")?;

            debug!(
                tool = %call.name,
                call_id = %call_id,
                has_error = response.error.is_some(),
                "Tool result received"
            );

            // Push discoveries to the real-time discovery list so the
            // discovery poller publishes them to state immediately,
            // independent of the task result consumer.
            if let Some(ref disc) = response.discoveries {
                push_realtime_discoveries(
                    &self.queue,
                    &self.operation_id,
                    disc,
                    &call.name,
                    &call.arguments,
                )
                .await;
            }

            Ok(tool_exec_result_from_response(response))
        }
        .instrument(span)
        .await
    }
}
