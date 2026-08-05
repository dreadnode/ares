//! Orchestrator-side callback handler for tools that need in-memory state access.
//!
//! Handles the reporting tools every agent role is offered (`list_credentials`,
//! `get_operation_summary`) plus disabled-tool safety nets, all without going
//! through Redis tool queues.

mod dispatch;
mod query;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Result;
use tracing::warn;

use ares_llm::provider::ToolCall;
use ares_llm::{CallbackHandler, CallbackResult};

use crate::orchestrator::dispatcher::submission::as_orchestrator_directed;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueue;

/// Callback handler for orchestrator LLM agent tools.
///
/// Provides direct access to shared state (for query tools) and the dispatcher
/// (for sub-task submission) without going through Redis tool queues.
pub struct OrchestratorCallbackHandler {
    pub(super) state: SharedState,
    pub(super) dispatcher: Option<Arc<Dispatcher>>,
    pub(super) task_queue: Option<TaskQueue>,
}

impl OrchestratorCallbackHandler {
    pub fn new(state: SharedState, task_queue: TaskQueue) -> Self {
        Self {
            state,
            dispatcher: None,
            task_queue: Some(task_queue),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(state: SharedState) -> Self {
        Self {
            state,
            dispatcher: None,
            task_queue: None,
        }
    }

    pub fn with_dispatcher(mut self, dispatcher: Arc<Dispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }
}

impl OrchestratorCallbackHandler {
    /// Disabled — credentials are parsed out of tool output instead. Answered
    /// in-process so a hallucinated call gets guidance rather than an error.
    async fn record_credential(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_credential called but disabled — credentials are auto-extracted from tool output");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Credentials are automatically extracted from tool output. \
             Focus on running tools that produce credential data (secretsdump, lsassy, netexec, etc.) \
             and the system will parse and store credentials automatically."
                .to_string(),
        ))
    }

    /// Disabled — timeline events are generated from discoveries in
    /// `result_processing`. Same safety-net rationale as `record_credential`.
    async fn record_timeline_event(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_timeline_event called but disabled — timeline events are auto-generated from discoveries");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Timeline events are automatically generated when \
             credentials, hashes, and hosts are discovered from tool output. Focus on \
             running attack tools and the system will build the timeline automatically."
                .to_string(),
        ))
    }
}

const ORCHESTRATOR_ONLY_TOOLS: &[&str] = &[
    "dispatch_recon",
    "dispatch_credential_access",
    "dispatch_lateral_movement",
    "dispatch_privesc_exploit",
    "dispatch_coercion",
    "dispatch_crack",
    "get_proposed_work",
    "approve_work",
    "reject_work",
    "complete_operation",
];

#[async_trait::async_trait]
impl CallbackHandler for OrchestratorCallbackHandler {
    async fn handle_callback(&self, call: &ToolCall, role: &str) -> Option<Result<CallbackResult>> {
        if ORCHESTRATOR_ONLY_TOOLS.contains(&call.name.as_str()) && role != "orchestrator" {
            warn!(
                role = role,
                tool = %call.name,
                "Refusing orchestrator-only tool called by a worker role"
            );
            return Some(Ok(CallbackResult::Continue(format!(
                "You are not the orchestrator and cannot call {}. Only the orchestrator \
                 submits work or ends the operation. Finish your own task and report what \
                 you found with task_complete.",
                call.name
            ))));
        }

        match call.name.as_str() {
            // Query tools
            "get_operation_summary" => Some(self.get_operation_summary().await),
            "get_credential_summary" => Some(self.get_credential_summary().await),
            "get_hash_summary" => Some(self.get_hash_summary().await),
            "get_all_credentials" => Some(self.get_all_credentials(call).await),
            "get_all_hashes" => Some(self.get_all_hashes(call).await),
            "get_pending_tasks" => Some(self.get_pending_tasks().await),
            "get_agent_status" => Some(self.get_agent_status().await),
            // list_credentials delegates to get_all_credentials so non-orchestrator
            // agents (lateral, exploit) get real credential data instead of a stub.
            "list_credentials" => Some(self.get_all_credentials(call).await),
            "dispatch_recon" => Some(as_orchestrator_directed(self.dispatch_recon(call)).await),
            "dispatch_credential_access" => {
                Some(as_orchestrator_directed(self.dispatch_credential_access(call)).await)
            }
            "dispatch_lateral_movement" => {
                Some(as_orchestrator_directed(self.dispatch_lateral(call)).await)
            }
            "dispatch_privesc_exploit" => {
                Some(as_orchestrator_directed(self.dispatch_exploit(call)).await)
            }
            "dispatch_coercion" => {
                Some(as_orchestrator_directed(self.dispatch_coercion(call)).await)
            }
            "dispatch_crack" => Some(as_orchestrator_directed(self.dispatch_crack(call)).await),
            "get_proposed_work" => Some(self.get_proposed_work(call).await),
            "approve_work" => Some(as_orchestrator_directed(self.approve_work(call)).await),
            "reject_work" => Some(self.reject_work(call).await),
            "complete_operation" => Some(self.complete_operation(call).await),
            // Recording tools — persist to state and Redis
            "record_credential" => Some(self.record_credential(call).await),
            "record_timeline_event" => Some(self.record_timeline_event(call).await),
            // Not ours — let built-in handler take over
            _ => None,
        }
    }

    async fn on_token_usage(&self, usage: &ares_llm::TokenUsage, model: &str, role: &str) {
        if usage.input_tokens == 0 && usage.output_tokens == 0 {
            return;
        }
        if let Some(ref queue) = self.task_queue {
            let op_id = self.state.read().await.operation_id.clone();
            let mut conn = queue.connection();
            if let Err(e) = ares_core::token_usage::increment_token_usage(
                &mut conn,
                &op_id,
                usage.input_tokens.into(),
                usage.cache_read_input_tokens.into(),
                usage.output_tokens.into(),
                model,
                role,
            )
            .await
            {
                warn!(err = %e, "Failed to record incremental token usage");
            }
        }
    }
}
