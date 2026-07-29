//! `JournalingToolDispatcher` — a transparent decorator around the operation's
//! `ToolDispatcher`. It forwards every call to the inner dispatcher and records
//! mutating calls to the operation's mutation journal — an intent written
//! before the call, resolved by an outcome written after it.
//!
//! Wrapping the single `Arc<dyn ToolDispatcher>` that the red LLM runner shares
//! with every deterministic automation (via `LlmTaskRunner::tool_dispatcher()`)
//! captures BOTH the LLM-driven path and the ~15 deterministic dispatch sites
//! at one point, with zero edits to the automation modules.

use std::sync::Arc;

use anyhow::Result;
use ares_llm::{ToolCall, ToolDispatcher, ToolExecResult};
use tracing::{debug, warn};

use super::journal::{self, MutationRecord, MutationStatus};

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
        // Write-ahead: record the intent BEFORE the target is touched. A
        // post-hoc journal loses every mutation the process does not outlive,
        // and the worker-path timeout below is guaranteed to lose one.
        let intent = if journal::is_mutating(&call.name) {
            let record = MutationRecord::intent(role, task_id, &call.name, &call.arguments);
            journal::append(&self.conn, &self.operation_id, &record).await;
            Some(record)
        } else {
            None
        };

        let result = self.inner.dispatch_tool(role, task_id, call).await;

        if let Some(intent) = intent {
            let (status, hint) = match &result {
                // The tool ran and reported success. A zero exit is not proof
                // of a mutation: "make it so" tools report success when the
                // state was already set, and reverting one of those deletes
                // state this operation did not create.
                Ok(exec) if exec.error.is_none() => {
                    if super::capture::mutation_took_effect(
                        &call.name,
                        &call.arguments,
                        &exec.output,
                    ) {
                        (
                            MutationStatus::Confirmed,
                            super::capture::hint_for(&call.name, &call.arguments, &exec.output),
                        )
                    } else {
                        debug!(
                            tool = %call.name,
                            "mutating tool reported success but changed nothing — marking aborted"
                        );
                        (MutationStatus::Aborted, None)
                    }
                }
                // The orchestrator gave up waiting; the worker holds no
                // cancellation token and runs the tool to completion, so the
                // target may well have been changed. Leaving the intent
                // unresolved is the honest record — this is the shape that
                // previously guaranteed a successful mutation went unjournalled.
                Ok(exec) if dispatch_timed_out(exec.error.as_deref()) => {
                    warn!(
                        tool = %call.name,
                        "mutating tool timed out at the orchestrator while the worker kept running — journal entry left unresolved"
                    );
                    (MutationStatus::Intent, None)
                }
                // Ran and reported failure, or never started.
                _ => (MutationStatus::Aborted, None),
            };

            if status != MutationStatus::Intent {
                journal::append(
                    &self.conn,
                    &self.operation_id,
                    &intent.resolution(status, hint),
                )
                .await;
            }
        }

        result
    }
}

/// Whether a tool result carries the orchestrator's own dispatch deadline
/// rather than a failure the tool reported.
fn dispatch_timed_out(error: Option<&str>) -> bool {
    error.is_some_and(|e| e.to_lowercase().contains("timed out"))
}

#[cfg(test)]
mod tests {
    use super::dispatch_timed_out;

    /// The orchestrator's deadline is not the tool's verdict: the worker holds
    /// no cancellation token and runs to completion, so a mutation may well
    /// have landed. Classifying this as "nothing happened" is what guaranteed a
    /// successful mutation went unjournalled.
    #[test]
    fn a_dispatch_timeout_is_distinguished_from_a_tool_failure() {
        assert!(dispatch_timed_out(Some(
            "worker dispatch timed out after 95m (the tool may have been running fine)"
        )));
        assert!(dispatch_timed_out(Some("Timed Out")));

        assert!(!dispatch_timed_out(None));
        assert!(!dispatch_timed_out(Some(
            "[-] rpc_s_access_denied while writing the delegation attribute"
        )));
        assert!(!dispatch_timed_out(Some("tool binary not found")));
    }
}
