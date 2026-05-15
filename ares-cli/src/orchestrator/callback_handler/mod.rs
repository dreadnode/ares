//! Orchestrator-specific callback handler for state query and dispatch tools.
//!
//! Implements `CallbackHandler` to handle tools that need in-memory state access:
//!
//! **Query tools** — read from SharedState (credentials, hashes, tasks, agent status)
//! **Dispatch tools** — submit sub-tasks via the Dispatcher (recon, credential_access, etc.)
//!
//! These tools are available only to the orchestrator agent role.

mod dispatch;
mod query;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Result;
use tracing::warn;

use ares_llm::provider::ToolCall;
use ares_llm::{CallbackHandler, CallbackResult};

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

#[async_trait::async_trait]
impl CallbackHandler for OrchestratorCallbackHandler {
    async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>> {
        match call.name.as_str() {
            // Query tools
            "get_credential_summary" => Some(self.get_credential_summary().await),
            "get_hash_summary" => Some(self.get_hash_summary().await),
            "get_all_credentials" => Some(self.get_all_credentials(call).await),
            "get_all_hashes" => Some(self.get_all_hashes(call).await),
            "get_hash_value" => Some(self.get_hash_value(call).await),
            "get_pending_tasks" => Some(self.get_pending_tasks().await),
            "get_agent_status" => Some(self.get_agent_status().await),
            "get_operation_summary" => Some(self.get_operation_summary().await),
            // list_credentials delegates to get_all_credentials so non-orchestrator
            // agents (lateral, exploit) get real credential data instead of a stub.
            "list_credentials" => Some(self.get_all_credentials(call).await),
            // Recording tools — persist to state and Redis
            "record_credential" => Some(self.record_credential(call).await),
            "record_timeline_event" => Some(self.record_timeline_event(call).await),
            // Dispatch tools
            "dispatch_recon" => Some(self.dispatch_recon(call).await),
            "dispatch_credential_access" => Some(self.dispatch_credential_access(call).await),
            "dispatch_lateral_movement" => Some(self.dispatch_lateral(call).await),
            "dispatch_privesc_exploit" => Some(self.dispatch_exploit(call).await),
            "dispatch_coercion" => Some(self.dispatch_coercion(call).await),
            "dispatch_crack" => Some(self.dispatch_crack(call).await),
            // Not ours — let built-in handler take over
            _ => None,
        }
    }

    async fn on_token_usage(&self, usage: &ares_llm::TokenUsage, model: &str) {
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
                usage.output_tokens.into(),
                model,
            )
            .await
            {
                warn!(err = %e, "Failed to record incremental token usage");
            }
        }
    }
}
