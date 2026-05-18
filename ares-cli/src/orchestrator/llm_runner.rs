//! LLM task runner — drives tasks through the Rust agent loop.
//!
//! Builds prompts, calls the LLM, dispatches tool calls to workers via Redis,
//! and handles callbacks in Rust.

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use tracing::{debug, info, warn};

use ares_llm::prompt::templates;
use ares_llm::prompt::StateSnapshot;
use ares_llm::tool_registry::{self, AgentRole};
use ares_llm::{
    run_agent_loop, AgentLoopConfig, AgentLoopOutcome, CallbackHandler, HostnameMap, LlmProvider,
    LoopEndReason, RunAgentLoopParams, ToolDispatcher,
};

use crate::orchestrator::state::SharedState;

/// Drives LLM-powered tasks through the Rust agent loop.
///
/// Owns an LLM provider and tool dispatcher, and builds prompts from
/// the current operation state.
pub struct LlmTaskRunner {
    provider: Box<dyn LlmProvider>,
    dispatcher: Arc<dyn ToolDispatcher>,
    state: SharedState,
    config: AgentLoopConfig,
    /// Sorted technique priorities from strategy (technique, weight).
    /// Passed to the system prompt template to render a dynamic priority table.
    technique_priorities: Vec<(String, i32)>,
    /// Orchestrator listener IP — injected into agent prompt templates so
    /// example tool calls (e.g. coercion `listener=...`) show the real IP
    /// instead of a literal that the LLM may copy verbatim.
    listener_ip: String,
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
        temperature: Option<f32>,
        technique_priorities: Vec<(String, i32)>,
        listener_ip: String,
    ) -> Self {
        // Layer env-var overrides (ARES_AGENT_*, ARES_CONTEXT_*, ARES_BUDGET_*,
        // ARES_SESSION_LOG_*) on top of compiled defaults so operators can
        // tune the loop without a code change.
        let config = AgentLoopConfig::from_env(model_name, temperature);
        Self {
            provider,
            dispatcher,
            state,
            config,
            technique_priorities,
            listener_ip,
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

    /// Get a reference to the tool dispatcher for direct tool calls.
    pub fn tool_dispatcher(&self) -> &Arc<dyn ToolDispatcher> {
        &self.dispatcher
    }

    /// Execute a task through the LLM agent loop.
    ///
    /// Main entry point when a task should be driven by the LLM directly
    /// rather than pushed through a worker's full agent loop.
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
        let system_prompt = build_system_prompt(
            role,
            &snapshot,
            &self.technique_priorities,
            &self.listener_ip,
        )?;

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

        // 5. Build IP→FQDN map from discovered hosts so spans show hostnames
        //    instead of bare IPs in destination.address.
        let hostname_map: Option<HostnameMap> = {
            let hosts = &snapshot.hosts;
            if hosts.is_empty() {
                None
            } else {
                let map: std::collections::HashMap<String, String> = hosts
                    .iter()
                    .filter(|h| !h.hostname.is_empty())
                    .map(|h| {
                        let fqdn = if h.hostname.contains('.') {
                            h.hostname.to_lowercase()
                        } else if let Some(domain) = snapshot.domains.first() {
                            format!("{}.{}", h.hostname.to_lowercase(), domain)
                        } else {
                            h.hostname.to_lowercase()
                        };
                        (h.ip.clone(), fqdn)
                    })
                    .collect();
                if map.is_empty() {
                    None
                } else {
                    Some(Arc::new(map))
                }
            }
        };

        // 6. Run the agent loop
        let outcome = run_agent_loop(RunAgentLoopParams {
            provider: self.provider.as_ref(),
            dispatcher: Arc::clone(&self.dispatcher),
            config: &self.config,
            system_prompt: &system_prompt,
            task_prompt: &task_prompt,
            role: role_str,
            task_id,
            tools: &tools,
            callback_handler: self.callback_handler.get().cloned(),
            hostname_map,
        })
        .await;

        log_outcome(task_id, &outcome);

        Ok(outcome)
    }
}

/// Build the system prompt for a given agent role.
fn build_system_prompt(
    role: AgentRole,
    snapshot: &StateSnapshot,
    technique_priorities: &[(String, i32)],
    listener_ip: &str,
) -> Result<String> {
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

    // Render system instructions with strategy-driven priority table
    let priorities = if technique_priorities.is_empty() {
        None
    } else {
        Some(technique_priorities)
    };
    let op = templates::OperationContext {
        target_domain: &snapshot.target_domain,
        target_dc_ip: &snapshot.target_dc_ip,
        target_dc_fqdn: &snapshot.target_dc_fqdn,
        listener_ip,
    };
    let system_instructions = templates::render_system_instructions(None, priorities, op)?;

    // Render agent-specific instructions
    let agent_instructions = templates::render_agent_instructions(
        template_name,
        &capabilities,
        !snapshot.undominated_forests.is_empty(),
        &snapshot.undominated_forests,
        op,
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
        LoopEndReason::BudgetExceeded { reason } => {
            warn!(
                task_id = task_id,
                steps = outcome.steps,
                "LLM agent budget circuit breaker tripped: {reason}"
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
    fn role_for_task_type_recon_variants() {
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
    fn role_for_task_type_credential_access_variants() {
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
    fn role_for_task_type_other_roles() {
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
    fn role_for_task_type_unmapped() {
        assert_eq!(role_for_task_type("command"), None);
        assert_eq!(role_for_task_type("unknown"), None);
        assert_eq!(role_for_task_type(""), None);
    }

    #[test]
    fn build_system_prompt_all_roles() {
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
            let result = build_system_prompt(*role, &snapshot, &[], "192.168.58.50");
            assert!(result.is_ok(), "Failed for role: {:?}", role);
            let prompt = result.unwrap();
            assert!(!prompt.is_empty(), "Empty prompt for role: {:?}", role);
        }
    }

    #[test]
    fn build_task_prompt_known_types() {
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
    fn build_task_prompt_unknown_type_falls_back() {
        let snapshot = StateSnapshot::default();
        let payload = serde_json::json!({"foo": "bar"});

        let result = build_task_prompt("unknown_type", "t-1", &payload, &snapshot);
        assert!(result.is_ok());
        let prompt = result.unwrap();
        assert!(prompt.contains("unknown_type"));
        assert!(prompt.contains("task_complete"));
    }
}
