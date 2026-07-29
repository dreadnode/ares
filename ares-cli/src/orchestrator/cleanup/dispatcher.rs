//! `JournalingToolDispatcher` — a transparent decorator around the operation's
//! `ToolDispatcher`. It forwards every call to the inner dispatcher and, on
//! success, records mutating calls to the operation's mutation journal.
//!
//! Wrapping the single `Arc<dyn ToolDispatcher>` that the red LLM runner shares
//! with every deterministic automation (via `LlmTaskRunner::tool_dispatcher()`)
//! captures BOTH the LLM-driven path and the ~15 deterministic dispatch sites
//! at one point, with zero edits to the automation modules.

use std::sync::Arc;

use anyhow::Result;
use ares_llm::{ToolCall, ToolDispatcher, ToolExecResult};
use tracing::debug;

use super::journal::{self, MutationRecord};

/// Decorator that journals successful mutating tool calls.
pub struct JournalingToolDispatcher {
    inner: Arc<dyn ToolDispatcher>,
    operation_id: String,
    conn: redis::aio::ConnectionManager,
}

impl JournalingToolDispatcher {
    /// Wrap `inner`, returning it as a `ToolDispatcher` trait object ready to
    /// hand to `LlmTaskRunner::new`.
    pub fn wrap(
        inner: Arc<dyn ToolDispatcher>,
        operation_id: String,
        conn: redis::aio::ConnectionManager,
    ) -> Arc<dyn ToolDispatcher> {
        Arc::new(Self {
            inner,
            operation_id,
            conn,
        })
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for JournalingToolDispatcher {
    async fn dispatch_tool(
        &self,
        role: &str,
        task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        let result = self.inner.dispatch_tool(role, task_id, call).await;

        // Journal only successful mutations. A dispatch error (Err) or a tool
        // that ran but reported failure (`error.is_some()`) left no persistent
        // state to reverse.
        if let Ok(ref exec) = result {
            if exec.error.is_none() && journal::is_mutating(&call.name) {
                // A zero exit is not proof of a mutation: "make it so" tools
                // report success when the state was already set. Journaling a
                // call that changed nothing hands teardown an inverse for
                // state it did not create.
                if super::capture::mutation_took_effect(&call.name, &call.arguments, &exec.output) {
                    let mut record =
                        MutationRecord::from_call(role, task_id, &call.name, &call.arguments);
                    record.hint =
                        super::capture::hint_for(&call.name, &call.arguments, &exec.output);
                    journal::append(&self.conn, &self.operation_id, &record).await;
                } else {
                    debug!(
                        tool = %call.name,
                        "mutating tool reported success but changed nothing — not journaled"
                    );
                }
            }
        }

        result
    }
}
