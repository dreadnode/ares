//! Redis-backed tool dispatcher.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{debug, warn, Instrument};

use ares_core::telemetry::propagation::inject_traceparent;
use ares_core::telemetry::spans::{producer_span, Team};
use ares_llm::{ToolCall, ToolExecResult};

use crate::task_queue::TaskQueue;

use super::{
    extract_credential_key, push_realtime_discoveries, AuthThrottle, ToolExecRequest,
    ToolExecResponse, RESULT_TTL_SECS, TOOL_EXEC_PREFIX, TOOL_RESULT_PREFIX,
};

/// Dispatches tool calls to workers via Redis queues.
///
/// When tool results contain structured discoveries (hosts, credentials, etc.),
/// they are pushed to the `ares:discoveries:{op_id}` list for real-time
/// processing by the discovery poller — ensuring discoveries reach state
/// immediately rather than waiting for the task result consumer.
pub struct RedisToolDispatcher {
    pub(super) queue: TaskQueue,
    pub(super) tool_timeout: std::time::Duration,
    pub(super) operation_id: String,
    pub(super) auth_throttle: AuthThrottle,
}

impl RedisToolDispatcher {
    pub fn new(queue: TaskQueue, operation_id: String, auth_throttle: AuthThrottle) -> Self {
        Self {
            queue,
            tool_timeout: std::time::Duration::from_secs(super::DEFAULT_TOOL_TIMEOUT_SECS),
            operation_id,
            auth_throttle,
        }
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

            let call_id = format!("{}_{}", call.name, uuid::Uuid::new_v4().simple());

            // Inject trace context for cross-service span linking
            let traceparent = inject_traceparent(&tracing::Span::current());

            let request = ToolExecRequest {
                call_id: call_id.clone(),
                task_id: task_id.to_string(),
                tool_name: call.name.clone(),
                arguments: call.arguments.clone(),
                traceparent,
                operation_id: Some(self.operation_id.clone()),
            };

            let queue_key = format!("{TOOL_EXEC_PREFIX}:{effective_role}");
            let result_key = format!("{TOOL_RESULT_PREFIX}:{call_id}");
            let payload =
                serde_json::to_string(&request).context("Failed to serialize tool exec request")?;

            debug!(
                tool = %call.name,
                call_id = %call_id,
                queue = %queue_key,
                effective_role = %effective_role,
                "Dispatching tool call to worker"
            );

            // Push request to worker queue
            let mut conn = self.queue.connection();
            conn.lpush::<_, _, ()>(&queue_key, &payload)
                .await
                .context("Failed to push tool exec request to Redis")?;

            // Wait for result with timeout
            let timeout_secs = self.tool_timeout.as_secs().max(1) as f64;
            let brpop_result: Option<(String, String)> = redis::cmd("BRPOP")
                .arg(&result_key)
                .arg(timeout_secs)
                .query_async(&mut conn)
                .await
                .context("BRPOP failed for tool result")?;

            match brpop_result {
                Some((_key, value)) => {
                    let response: ToolExecResponse = serde_json::from_str(&value)
                        .context("Failed to deserialize tool exec response")?;

                    debug!(
                        tool = %call.name,
                        call_id = %call_id,
                        has_error = response.error.is_some(),
                        "Tool result received"
                    );

                    // Push discoveries to the real-time discovery list so
                    // the discovery poller publishes them to state immediately,
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

                    Ok(ToolExecResult {
                        output: response.output,
                        error: response.error,
                        discoveries: response.discoveries,
                    })
                }
                None => {
                    warn!(
                        tool = %call.name,
                        call_id = %call_id,
                        timeout_secs = timeout_secs,
                        "Tool execution timed out"
                    );

                    // Clean up any late result
                    let _: Result<(), _> = conn
                        .expire::<_, ()>(&result_key, RESULT_TTL_SECS as i64)
                        .await;

                    Ok(ToolExecResult {
                        output: String::new(),
                        error: Some(format!(
                            "Tool '{}' timed out after {timeout_secs}s",
                            call.name
                        )),
                        discoveries: None,
                    })
                }
            }
        }
        .instrument(span)
        .await
    }
}
