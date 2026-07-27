//! In-process tool dispatcher (no Redis).

use std::borrow::Cow;

use anyhow::Result;
use tracing::{debug, info, warn};

use ares_llm::{ToolCall, ToolExecResult};

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueue;
use crate::worker::credential_resolver::resolve_credentials;

use super::domain_validator::{check_cross_realm_auth, check_domain_arg};
use super::{
    extract_credential_key, inject_excluded_users, inject_spray_attempts,
    push_realtime_discoveries, AuthThrottle,
};

/// Dispatches tool calls directly via `ares_tools::dispatch` without Redis.
///
/// Useful for testing, single-binary deployments, or when workers are
/// colocated in the same process as the orchestrator.
pub struct LocalToolDispatcher {
    pub(super) queue: TaskQueue,
    pub(super) operation_id: String,
    pub(super) auth_throttle: AuthThrottle,
    pub(super) state: Option<SharedState>,
}

impl LocalToolDispatcher {
    pub fn new(queue: TaskQueue, operation_id: String, auth_throttle: AuthThrottle) -> Self {
        Self {
            queue,
            operation_id,
            auth_throttle,
            state: None,
        }
    }

    /// Attach orchestrator state so spray-style tool calls can be augmented
    /// with the current quarantine list before dispatch.
    pub fn with_state(mut self, state: SharedState) -> Self {
        self.state = Some(state);
        self
    }
}

#[async_trait::async_trait]
impl ares_llm::ToolDispatcher for LocalToolDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        // Reject calls whose `domain` argument doesn't match a known domain.
        if let Some(rejection) = check_domain_arg(&self.queue, &self.operation_id, call).await {
            return Ok(rejection);
        }

        // Reject native-credential auth aimed across a forest boundary with no
        // forged inter-realm ticket — the doomed KDC_ERR_WRONG_REALM mechanic.
        if let Some(rejection) = check_cross_realm_auth(&self.queue, &self.operation_id, call).await
        {
            return Ok(rejection);
        }

        // Rate-limit auth-bearing tools to prevent AD account lockout
        if let Some(cred_key) = extract_credential_key(call) {
            self.auth_throttle.acquire(&cred_key).await;
        }

        debug!(tool = %call.name, "Executing tool locally");

        // Resolve credentials from operation state. The LLM never passes
        // secret material — usernames + domains only. Mirrors the worker
        // tool_executor path so local (in-process) dispatch gets the same
        // injection.
        let mut resolved_arguments = call.arguments.clone();
        // Spray hygiene: augment excluded_users from the current quarantine
        // list before dispatch. Done before credential resolution so the
        // domain arg (used for the lookup) is the LLM-supplied target.
        inject_excluded_users(&self.state, &call.name, &mut resolved_arguments).await;
        let mut conn = self.queue.connection();
        // A cross-forest Kerberos coercion may redirect to a `*_kerberos`
        // variant (e.g. psexec → psexec_kerberos). Track the effective tool
        // name so the dispatch call below picks up the rename — without this
        // the rename in `resolve_credentials` would silently no-op.
        let mut effective_tool_name: Cow<'_, str> = Cow::Borrowed(call.name.as_str());
        match resolve_credentials(
            &mut conn,
            Some(self.operation_id.as_str()),
            &call.name,
            &mut resolved_arguments,
        )
        .await
        {
            Ok(Some(renamed)) => {
                info!(
                    from = %call.name,
                    to = %renamed,
                    "tool_dispatcher: applying Kerberos variant redirect from credential_resolver"
                );
                effective_tool_name = Cow::Owned(renamed);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    tool = %call.name,
                    err = %e,
                    "credential_resolver failed; continuing with original arguments"
                );
                resolved_arguments = call.arguments.clone();
                inject_excluded_users(&self.state, &call.name, &mut resolved_arguments).await;
            }
        }

        // Spray lockout budget. Deliberately after the credential-resolution
        // match rather than beside `inject_excluded_users`: the error arm
        // rebuilds `resolved_arguments` from scratch, so injecting earlier
        // would either be discarded or debit the tally twice. Here it runs
        // exactly once, against the arguments actually dispatched.
        inject_spray_attempts(&self.state, &call.name, &mut resolved_arguments).await;

        match ares_tools::dispatch(&effective_tool_name, &resolved_arguments).await {
            Ok(output) => {
                let raw = output.combined_raw();
                let mut combined = output.combined();
                let error = if output.success {
                    None
                } else {
                    Some(format!("tool exited with code {:?}", output.exit_code))
                };

                // Parse structured discoveries from raw (unfiltered) output.
                // Use the effective (post-redirect) tool name so the parser
                // matches the actual binary that ran — secretsdump and
                // secretsdump_kerberos emit slightly different output shapes.
                let discoveries = ares_tools::parsers::parse_tool_output(
                    &effective_tool_name,
                    &raw,
                    &resolved_arguments,
                );
                let discoveries = if discoveries.as_object().is_none_or(|o| o.is_empty()) {
                    None
                } else {
                    Some(discoveries)
                };

                // Push discoveries to real-time list immediately (like RedisToolDispatcher)
                if let Some(ref disc) = discoveries {
                    push_realtime_discoveries(
                        &self.queue,
                        &self.operation_id,
                        disc,
                        &effective_tool_name,
                        &resolved_arguments,
                    )
                    .await;
                }

                // Mirror the worker path: flag a zero-yield unauthenticated
                // harvest so the LLM changes strategy instead of re-spraying.
                if output.success {
                    if let Some(note) = ares_tools::parsers::empty_harvest_advisory(
                        &effective_tool_name,
                        discoveries.as_ref(),
                    ) {
                        combined.push_str(&note);
                    }
                }

                Ok(ToolExecResult {
                    output: combined,
                    error,
                    discoveries,
                    failure_kind: if output.success {
                        None
                    } else {
                        Some(ares_llm::ToolFailureKind::ToolError)
                    },
                })
            }
            Err(e) => {
                // Classify the spawn error via the typed marker so the
                // in-process LocalToolDispatcher matches the NATS path's
                // pruning behavior exactly (BinaryNotFound → prune,
                // TransientSpawn → do not prune).
                let failure_kind = ares_tools::spawn_error_kind(&e).map(|kind| {
                    if kind.is_not_found() {
                        ares_llm::ToolFailureKind::BinaryNotFound
                    } else {
                        ares_llm::ToolFailureKind::TransientSpawn
                    }
                });
                Ok(ToolExecResult {
                    output: String::new(),
                    error: Some(e.to_string()),
                    discoveries: None,
                    failure_kind,
                })
            }
        }
    }
}
