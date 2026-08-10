//! LLM task runner — drives tasks through the Rust agent loop.
//!
//! Builds prompts, calls the LLM, dispatches tool calls to workers via Redis,
//! and handles callbacks in Rust.

use std::collections::HashMap;
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

/// Per-role LLM provider plus its agent-loop configuration. Different roles
/// can ship different models (e.g. a cheap mini model for mechanical recon vs
/// a reasoning model for the orchestrator) so we keep one entry per role.
pub struct RoleProvider {
    pub provider: Arc<dyn LlmProvider>,
    pub config: AgentLoopConfig,
}

/// Drives LLM-powered tasks through the Rust agent loop.
///
/// Owns a per-role map of LLM providers and a tool dispatcher, and builds
/// prompts from the current operation state.
pub struct LlmTaskRunner {
    /// Per-role LLM provider + agent-loop config. Lookup fails over to
    /// `fallback_provider` for any role not in the map.
    providers: HashMap<AgentRole, RoleProvider>,
    /// Used when `providers` has no entry for the requested role.
    fallback_provider: RoleProvider,
    dispatcher: Arc<dyn ToolDispatcher>,
    state: SharedState,
    /// Sorted technique priorities from strategy (technique, weight).
    /// Passed to the system prompt template to render a dynamic priority table.
    technique_priorities: Vec<(String, i32)>,
    /// Operation-scoped context frozen at runner creation. Inserted into the
    /// system prompt with stable values so OpenAI's prefix auto-caching can
    /// hit across every step of every task. Current values (which may shift
    /// as recon discovers new infrastructure) flow through the task prompt
    /// instead — see `dynamic_context_block`.
    frozen_op_context: FrozenOpContext,
    /// Deferred callback handler — set after construction to break the
    /// `LlmTaskRunner → Dispatcher → LlmTaskRunner` circular dependency.
    callback_handler: OnceLock<Arc<dyn CallbackHandler>>,
}

/// Operation context frozen at runner creation so the system prompt stays
/// byte-stable for prefix caching. Use [`FrozenOpContext::from_parts`] to
/// build one from the orchestrator's initial snapshot + config.
#[derive(Debug, Clone, Default)]
pub struct FrozenOpContext {
    pub target_domain: String,
    pub target_dc_ip: String,
    pub target_dc_fqdn: String,
    pub listener_ip: String,
}

impl FrozenOpContext {
    fn as_template(&self) -> templates::OperationContext<'_> {
        templates::OperationContext {
            target_domain: &self.target_domain,
            target_dc_ip: &self.target_dc_ip,
            target_dc_fqdn: &self.target_dc_fqdn,
            listener_ip: &self.listener_ip,
        }
    }
}

impl LlmTaskRunner {
    pub fn new(
        providers: HashMap<AgentRole, RoleProvider>,
        fallback_provider: RoleProvider,
        dispatcher: Arc<dyn ToolDispatcher>,
        state: SharedState,
        technique_priorities: Vec<(String, i32)>,
        frozen_op_context: FrozenOpContext,
    ) -> Self {
        Self {
            providers,
            fallback_provider,
            dispatcher,
            state,
            technique_priorities,
            frozen_op_context,
            callback_handler: OnceLock::new(),
        }
    }

    fn provider_for(&self, role: AgentRole) -> &RoleProvider {
        self.providers.get(&role).unwrap_or(&self.fallback_provider)
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

        // 2. Build system prompt from agent template using FROZEN context so
        //    OpenAI's prefix auto-caching can hit across every step. The
        //    snapshot's current target_dc_ip / undominated_forests flow
        //    through the task prompt instead — see step 3.
        let system_prompt = build_system_prompt(
            role,
            &self.technique_priorities,
            self.frozen_op_context.as_template(),
        )?;

        // 3. Build task prompt from Tera template + payload, then prepend a
        //    dynamic Operation Context block so the LLM sees current
        //    discoveries without invalidating the system-prompt cache.
        let task_prompt_body = build_task_prompt(task_type, task_id, payload, &snapshot)?;
        let task_prompt = dynamic_context_block(role, &snapshot) + &task_prompt_body;

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

        // 6. Run the agent loop with this role's provider+config.
        let rp = self.provider_for(role);
        let outcome = run_agent_loop(RunAgentLoopParams {
            provider: rp.provider.as_ref(),
            dispatcher: Arc::clone(&self.dispatcher),
            config: &rp.config,
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
///
/// The system prompt is intentionally byte-stable across every step of every
/// task: it depends only on the role, the frozen operation context (set at
/// runner creation), and strategy weights — all of which are immutable for
/// the lifetime of the runner. This is what lets OpenAI's prefix auto-cache
/// fire across the agent loop. Anything that mutates per step (snapshot
/// state, undominated forests, multi-forest flag) lives in the task prompt.
fn build_system_prompt(
    role: AgentRole,
    technique_priorities: &[(String, i32)],
    op: templates::OperationContext<'_>,
) -> Result<String> {
    let tools = tool_registry::tools_for_role(role);
    let capabilities: Vec<String> = tools
        .iter()
        .filter(|t| role == AgentRole::Orchestrator || !tool_registry::is_callback_tool(&t.name))
        .map(|t| t.name.clone())
        .collect();

    let template_name = match role {
        AgentRole::Orchestrator => templates::TEMPLATE_ORCHESTRATOR,
        AgentRole::Recon => templates::TEMPLATE_RECON,
        AgentRole::CredentialAccess => templates::TEMPLATE_CREDENTIAL_ACCESS,
        AgentRole::Cracker => templates::TEMPLATE_CRACKER,
        AgentRole::Acl => templates::TEMPLATE_ACL,
        AgentRole::Privesc => templates::TEMPLATE_PRIVESC,
        AgentRole::Lateral => templates::TEMPLATE_LATERAL,
        AgentRole::Coercion => templates::TEMPLATE_COERCION,
    };

    // Render system instructions with strategy-driven priority table
    let priorities = if technique_priorities.is_empty() {
        None
    } else {
        Some(technique_priorities)
    };
    let system_instructions = templates::render_system_instructions(None, priorities, op)?;

    // Render agent-specific instructions. Always pass `multi_forest_mode=false`
    // and an empty forest list — the orchestrator's dynamic Multi-Forest Status
    // is injected into the task prompt via `dynamic_context_block` so the
    // system prompt stays byte-stable for prefix caching.
    let agent_instructions =
        templates::render_agent_instructions(template_name, &capabilities, false, &[], op)?;

    Ok(format!("{system_instructions}\n\n{agent_instructions}"))
}

/// Build the dynamic operation context block that prepends to every task
/// prompt. This carries the snapshot state that previously lived in the
/// system prompt (current discoveries, undominated forests) so the system
/// prompt itself stays byte-stable for prefix-cache hits.
fn dynamic_context_block(role: AgentRole, snapshot: &StateSnapshot) -> String {
    let mut out = String::from("## Current Operation Context\n\n");
    if !snapshot.target_domain.is_empty() {
        out.push_str(&format!("- Target Domain: {}\n", snapshot.target_domain));
    }
    if !snapshot.target_dc_ip.is_empty() {
        out.push_str(&format!("- Target DC IP: {}\n", snapshot.target_dc_ip));
    }
    if !snapshot.target_dc_fqdn.is_empty() {
        out.push_str(&format!("- Target DC FQDN: {}\n", snapshot.target_dc_fqdn));
    }
    if role == AgentRole::Orchestrator && !snapshot.undominated_forests.is_empty() {
        out.push_str("\n### Multi-Forest Status\n\n**The following forest roots have NOT been dominated (no krbtgt hash obtained):**\n\n");
        for forest in &snapshot.undominated_forests {
            out.push_str(&format!("- **{forest}** — needs krbtgt extraction\n"));
        }
        out.push_str(
            "\nYou MUST NOT call `complete_operation()` until ALL forests are dominated or all attack paths are exhausted.\n",
        );
    }
    out.push('\n');
    out
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
        "orchestrator_plan" => Some(AgentRole::Orchestrator),
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
    fn orchestrator_plan_task_resolves_to_a_runnable_orchestrator_turn() {
        assert_eq!(
            role_for_task_type("orchestrator_plan"),
            Some(AgentRole::Orchestrator)
        );

        assert_eq!(
            AgentRole::parse("orchestrator"),
            Some(AgentRole::Orchestrator)
        );

        let system = build_system_prompt(AgentRole::Orchestrator, &[], test_op()).unwrap();
        assert!(system.contains("Red Team Orchestrator"));

        assert!(
            system.contains("dispatch_recon"),
            "orchestrator capabilities must survive the callback filter"
        );

        let payload = serde_json::json!({
            "domains": ["contoso.local"],
            "credentials": 2,
            "uncracked_hashes": 1,
            "unexploited_vulnerability_ids": ["esc1_ca01"],
        });
        let prompt = build_task_prompt(
            "orchestrator_plan",
            "plan-1",
            &payload,
            &StateSnapshot::default(),
        )
        .unwrap();
        assert!(prompt.contains("esc1_ca01"));
        assert!(
            !prompt.contains("Payload:"),
            "orchestrator_plan must render its template, not the raw-payload fallback"
        );
    }

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

    fn test_op() -> templates::OperationContext<'static> {
        templates::OperationContext {
            target_domain: "contoso.local",
            target_dc_ip: "192.168.58.10",
            target_dc_fqdn: "dc01.contoso.local",
            listener_ip: "192.168.58.50",
        }
    }

    #[test]
    fn build_system_prompt_all_roles() {
        for role in &[
            AgentRole::Recon,
            AgentRole::CredentialAccess,
            AgentRole::Cracker,
            AgentRole::Acl,
            AgentRole::Privesc,
            AgentRole::Lateral,
            AgentRole::Coercion,
        ] {
            let result = build_system_prompt(*role, &[], test_op());
            assert!(result.is_ok(), "Failed for role: {:?}", role);
            let prompt = result.unwrap();
            assert!(!prompt.is_empty(), "Empty prompt for role: {:?}", role);
        }
    }

    #[test]
    fn build_system_prompt_byte_stable_across_calls() {
        let a = build_system_prompt(AgentRole::Recon, &[], test_op()).unwrap();
        let b = build_system_prompt(AgentRole::Recon, &[], test_op()).unwrap();
        assert_eq!(a, b, "system prompt must be byte-stable for prefix caching");
    }

    #[test]
    fn build_system_prompt_independent_of_snapshot_state() {
        // Same frozen op context + same role → same bytes, regardless of
        // what discoveries the orchestrator has made. This is the cache
        // contract: snapshot mutations land in the user message, not here.
        let prompt_with_data = build_system_prompt(AgentRole::Privesc, &[], test_op()).unwrap();
        let prompt_again = build_system_prompt(AgentRole::Privesc, &[], test_op()).unwrap();
        assert_eq!(prompt_with_data, prompt_again);
        assert!(!prompt_with_data.contains("Multi-Forest Status"));
    }

    #[test]
    fn dynamic_context_block_carries_target_not_forests_for_workers() {
        let snap = StateSnapshot {
            target_dc_ip: "192.168.58.10".into(),
            undominated_forests: vec!["fabrikam.local".into()],
            ..Default::default()
        };
        let block = dynamic_context_block(AgentRole::Privesc, &snap);
        assert!(block.contains("Target DC IP: 192.168.58.10"));
        assert!(!block.contains("Multi-Forest Status"));
        assert!(!block.contains("fabrikam.local"));
    }

    #[test]
    fn dynamic_context_block_carries_forests_for_orchestrator() {
        let snap = StateSnapshot {
            target_dc_ip: "192.168.58.10".into(),
            undominated_forests: vec!["fabrikam.local".into()],
            ..Default::default()
        };
        let block = dynamic_context_block(AgentRole::Orchestrator, &snap);
        assert!(block.contains("Multi-Forest Status"));
        assert!(block.contains("fabrikam.local"));
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
