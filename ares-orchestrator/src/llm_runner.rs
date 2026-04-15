//! LLM task runner — drives tasks through the Rust agent loop.
//!
//! Replaces the Python dreadnode Agent for LLM-driven tasks.
//! The runner builds prompts, calls the LLM, dispatches tool calls to
//! Python workers via Redis, and handles callbacks in Rust.

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use tracing::{debug, info, warn};

use ares_llm::prompt::templates;
use ares_llm::prompt::StateSnapshot;
use ares_llm::tool_registry::{self, AgentRole};
use ares_llm::{
    run_agent_loop, AgentLoopConfig, AgentLoopOutcome, CallbackHandler, LlmProvider, LoopEndReason,
    ToolDispatcher,
};

use crate::state::SharedState;

// ---------------------------------------------------------------------------
// LLM task runner
// ---------------------------------------------------------------------------

/// Drives LLM-powered tasks through the Rust agent loop.
///
/// Owns an LLM provider and tool dispatcher, and builds prompts from
/// the current operation state.
#[allow(dead_code)]
pub struct LlmTaskRunner {
    provider: Box<dyn LlmProvider>,
    model_name: String,
    dispatcher: Arc<dyn ToolDispatcher>,
    state: SharedState,
    config: AgentLoopConfig,
    /// Deferred callback handler — set after construction to break the
    /// `LlmTaskRunner → Dispatcher → LlmTaskRunner` circular dependency.
    callback_handler: OnceLock<Arc<dyn CallbackHandler>>,
}

impl LlmTaskRunner {
    pub fn new(
        provider: Box<dyn LlmProvider>,
        model_name: String,
        dispatcher: Arc<dyn ToolDispatcher>,
        state: SharedState,
    ) -> Self {
        let config = AgentLoopConfig {
            model: model_name.clone(),
            ..AgentLoopConfig::default()
        };
        Self {
            provider,
            model_name,
            dispatcher,
            state,
            config,
            callback_handler: OnceLock::new(),
        }
    }

    /// Set the callback handler after construction.
    ///
    /// This is safe to call from `&self` (interior mutability via `OnceLock`),
    /// which lets us break the circular dependency: the handler needs the
    /// `Dispatcher`, which itself holds an `Arc<LlmTaskRunner>`.
    pub fn set_callback_handler(&self, handler: Arc<dyn CallbackHandler>) {
        let _ = self.callback_handler.set(handler);
    }

    /// Execute a task through the LLM agent loop.
    ///
    /// This is the main entry point called by the orchestrator when
    /// a task should be driven by the LLM rather than pushed to a
    /// Python worker's full agent loop.
    pub async fn execute_task(
        &self,
        task_type: &str,
        task_id: &str,
        role: AgentRole,
        payload: &serde_json::Value,
    ) -> Result<AgentLoopOutcome> {
        let role_str = role.as_str();

        // 1. Snapshot state (releases RwLock before LLM calls)
        let snapshot = self.state.snapshot().await;

        // 2. Build system prompt from agent template
        let system_prompt = build_system_prompt(role, &snapshot)?;

        // 3. Build task prompt from Tera template + payload
        let task_prompt = build_task_prompt(task_type, task_id, payload, &snapshot)?;

        // 4. Get tool schemas for this role
        let tools = tool_registry::tools_for_role(role);

        info!(
            task_id = task_id,
            task_type = task_type,
            role = role_str,
            tools = tools.len(),
            "Starting LLM agent loop"
        );

        // 5. Run the agent loop
        let outcome = run_agent_loop(
            self.provider.as_ref(),
            Arc::clone(&self.dispatcher),
            &self.config,
            &system_prompt,
            &task_prompt,
            role_str,
            task_id,
            &tools,
            self.callback_handler.get().cloned(),
        )
        .await;

        log_outcome(task_id, &outcome);

        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------
// Prompt building helpers
// ---------------------------------------------------------------------------

/// Build the system prompt for a given agent role.
fn build_system_prompt(role: AgentRole, snapshot: &StateSnapshot) -> Result<String> {
    // Get capabilities from the tool definitions for this role
    let tools = tool_registry::tools_for_role(role);
    let capabilities: Vec<String> = tools
        .iter()
        .filter(|t| !tool_registry::is_callback_tool(&t.name))
        .map(|t| t.name.clone())
        .collect();

    let template_name = match role {
        AgentRole::Recon => templates::TEMPLATE_RECON,
        AgentRole::CredentialAccess => templates::TEMPLATE_CREDENTIAL_ACCESS,
        AgentRole::Cracker => templates::TEMPLATE_CRACKER,
        AgentRole::Acl => templates::TEMPLATE_ACL,
        AgentRole::Privesc => templates::TEMPLATE_PRIVESC,
        AgentRole::Lateral => templates::TEMPLATE_LATERAL,
        AgentRole::Coercion => templates::TEMPLATE_COERCION,
        AgentRole::Orchestrator => templates::TEMPLATE_ORCHESTRATOR,
    };

    // Render system instructions (no per-role capability map for now)
    let system_instructions = templates::render_system_instructions(None)?;

    // Render agent-specific instructions
    let agent_instructions = templates::render_agent_instructions(
        template_name,
        &capabilities,
        false,
        &snapshot.undominated_forests,
    )?;

    Ok(format!("{system_instructions}\n\n{agent_instructions}"))
}

/// Build the task-specific prompt from payload and state.
fn build_task_prompt(
    task_type: &str,
    task_id: &str,
    payload: &serde_json::Value,
    snapshot: &StateSnapshot,
) -> Result<String> {
    // Use the PromptBuilder from ares-llm
    let prompt =
        ares_llm::prompt::generate_task_prompt(task_type, task_id, payload, Some(snapshot));

    match prompt {
        Some(p) => Ok(p),
        None => {
            warn!(
                task_type = task_type,
                task_id = task_id,
                "No prompt template for task type, using raw payload"
            );
            Ok(format!(
                "## Task: {task_id}\n\nType: {task_type}\n\nPayload:\n```json\n{}\n```\n\nComplete this task and call `task_complete` with results.",
                serde_json::to_string_pretty(payload).unwrap_or_default()
            ))
        }
    }
}

/// Map task type string to AgentRole.
pub fn role_for_task_type(task_type: &str) -> Option<AgentRole> {
    match task_type {
        "recon" | "nmap" | "bloodhound" | "delegation_enum" | "certipy_find" => {
            Some(AgentRole::Recon)
        }
        "credential_access" | "secretsdump" | "share_spider" | "kerberoast" | "asrep_roast"
        | "password_spray" => Some(AgentRole::CredentialAccess),
        "crack" => Some(AgentRole::Cracker),
        "lateral" | "lateral_movement" => Some(AgentRole::Lateral),
        "exploit" | "privesc_enumeration" => Some(AgentRole::Privesc),
        "coercion" => Some(AgentRole::Coercion),
        "acl_analysis" => Some(AgentRole::Acl),
        "command" => None, // Command tasks go to whatever role is specified
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

fn log_outcome(task_id: &str, outcome: &AgentLoopOutcome) {
    match &outcome.reason {
        LoopEndReason::TaskComplete { result, .. } => {
            info!(
                task_id = task_id,
                steps = outcome.steps,
                tool_calls = outcome.tool_calls_dispatched,
                input_tokens = outcome.total_usage.input_tokens,
                output_tokens = outcome.total_usage.output_tokens,
                "Task completed via LLM: {result}"
            );
        }
        LoopEndReason::RequestAssistance { issue, .. } => {
            warn!(
                task_id = task_id,
                steps = outcome.steps,
                "LLM agent requested assistance: {issue}"
            );
        }
        LoopEndReason::MaxSteps => {
            warn!(
                task_id = task_id,
                steps = outcome.steps,
                "LLM agent hit max steps limit"
            );
        }
        LoopEndReason::EndTurn { content } => {
            debug!(
                task_id = task_id,
                steps = outcome.steps,
                "LLM agent ended turn: {content}"
            );
        }
        LoopEndReason::MaxTokens => {
            warn!(
                task_id = task_id,
                steps = outcome.steps,
                "LLM agent hit max tokens"
            );
        }
        LoopEndReason::Error(err) => {
            warn!(
                task_id = task_id,
                steps = outcome.steps,
                "LLM agent loop error: {err}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_for_task_type_recon_variants() {
        for tt in &[
            "recon",
            "nmap",
            "bloodhound",
            "delegation_enum",
            "certipy_find",
        ] {
            assert_eq!(
                role_for_task_type(tt),
                Some(AgentRole::Recon),
                "Failed for: {tt}"
            );
        }
    }

    #[test]
    fn test_role_for_task_type_credential_access_variants() {
        for tt in &[
            "credential_access",
            "secretsdump",
            "share_spider",
            "kerberoast",
            "asrep_roast",
            "password_spray",
        ] {
            assert_eq!(
                role_for_task_type(tt),
                Some(AgentRole::CredentialAccess),
                "Failed for: {tt}"
            );
        }
    }

    #[test]
    fn test_role_for_task_type_other_roles() {
        assert_eq!(role_for_task_type("crack"), Some(AgentRole::Cracker));
        assert_eq!(role_for_task_type("lateral"), Some(AgentRole::Lateral));
        assert_eq!(
            role_for_task_type("lateral_movement"),
            Some(AgentRole::Lateral)
        );
        assert_eq!(role_for_task_type("exploit"), Some(AgentRole::Privesc));
        assert_eq!(
            role_for_task_type("privesc_enumeration"),
            Some(AgentRole::Privesc)
        );
        assert_eq!(role_for_task_type("coercion"), Some(AgentRole::Coercion));
        assert_eq!(role_for_task_type("acl_analysis"), Some(AgentRole::Acl));
    }

    #[test]
    fn test_role_for_task_type_unmapped() {
        assert_eq!(role_for_task_type("command"), None);
        assert_eq!(role_for_task_type("unknown"), None);
        assert_eq!(role_for_task_type(""), None);
    }

    #[test]
    fn test_build_system_prompt_all_roles() {
        let snapshot = StateSnapshot::default();
        for role in &[
            AgentRole::Recon,
            AgentRole::CredentialAccess,
            AgentRole::Cracker,
            AgentRole::Acl,
            AgentRole::Privesc,
            AgentRole::Lateral,
            AgentRole::Coercion,
            AgentRole::Orchestrator,
        ] {
            let result = build_system_prompt(*role, &snapshot);
            assert!(result.is_ok(), "Failed for role: {:?}", role);
            let prompt = result.unwrap();
            assert!(!prompt.is_empty(), "Empty prompt for role: {:?}", role);
        }
    }

    #[test]
    fn test_build_task_prompt_known_types() {
        let snapshot = StateSnapshot::default();
        let payload = serde_json::json!({
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "techniques": ["nmap"]
        });

        let result = build_task_prompt("recon", "t-1", &payload, &snapshot);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_build_task_prompt_unknown_type_falls_back() {
        let snapshot = StateSnapshot::default();
        let payload = serde_json::json!({"foo": "bar"});

        let result = build_task_prompt("unknown_type", "t-1", &payload, &snapshot);
        assert!(result.is_ok());
        let prompt = result.unwrap();
        assert!(prompt.contains("unknown_type"));
        assert!(prompt.contains("task_complete"));
    }
}
