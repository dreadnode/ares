//! Tera template embedding and rendering for agent instructions.
//!
//! Templates are embedded at compile time via `include_str!` and rendered
//! with a `tera::Context` containing role-specific variables like capabilities
//! and multi-forest mode flags.

use anyhow::{Context as _, Result};
use std::collections::HashMap;
use std::sync::LazyLock;
use tera::{Context, Tera};

const RECON_TEMPLATE: &str = include_str!("../../templates/redteam/agents/recon.md.tera");
const CREDENTIAL_ACCESS_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/credential_access.md.tera");
const CRACKER_TEMPLATE: &str = include_str!("../../templates/redteam/agents/cracker.md.tera");
const ACL_TEMPLATE: &str = include_str!("../../templates/redteam/agents/acl.md.tera");
const PRIVESC_TEMPLATE: &str = include_str!("../../templates/redteam/agents/privesc.md.tera");
const LATERAL_TEMPLATE: &str = include_str!("../../templates/redteam/agents/lateral.md.tera");
const COERCION_TEMPLATE: &str = include_str!("../../templates/redteam/agents/coercion.md.tera");
const ORCHESTRATOR_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/orchestrator.md.tera");
const SYSTEM_INSTRUCTIONS_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/system_instructions.md.tera");

const INITIAL_TASK_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/initial_task.md.tera");
const CRACKER_INSTRUCTIONS_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/cracker_instructions.md.tera");
const CRACKER_TASK_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/cracker_task.md.tera");
const GOLDEN_TICKET_INSTRUCTIONS_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/golden_ticket_instructions.md.tera");
const GOLDEN_TICKET_TASK_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/golden_ticket_task.md.tera");
const SHARE_PILFER_INSTRUCTIONS_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/share_pilfer_instructions.md.tera");
const SHARE_PILFER_TASK_TEMPLATE: &str =
    include_str!("../../templates/redteam/agents/share_pilfer_task.md.tera");

const TASK_RECON_TEMPLATE: &str = include_str!("../../templates/redteam/tasks/recon.md.tera");
const TASK_CRACK_TEMPLATE: &str = include_str!("../../templates/redteam/tasks/crack.md.tera");
const TASK_LATERAL_TEMPLATE: &str = include_str!("../../templates/redteam/tasks/lateral.md.tera");
const TASK_COERCION_TEMPLATE: &str = include_str!("../../templates/redteam/tasks/coercion.md.tera");
const TASK_PRIVESC_ENUMERATION_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/privesc_enumeration.md.tera");
const TASK_ACL_ANALYSIS_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/acl_analysis.md.tera");
const TASK_ACL_CHAIN_STEP_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/acl_chain_step.md.tera");
const TASK_COMMAND_TEMPLATE: &str = include_str!("../../templates/redteam/tasks/command.md.tera");

const TASK_EXPLOIT_ADCS_ENUMERATE_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_adcs_enumerate.md.tera");
const TASK_EXPLOIT_ADCS_ESC_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_adcs_esc.md.tera");
const TASK_EXPLOIT_DELEGATION_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_delegation.md.tera");
const TASK_EXPLOIT_GENERIC_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_generic.md.tera");
const TASK_EXPLOIT_MSSQL_LATERAL_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_mssql_lateral.md.tera");
const TASK_EXPLOIT_MSSQL_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_mssql.md.tera");
const TASK_EXPLOIT_TRUST_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_trust.md.tera");
const TASK_EXPLOIT_UNCONSTRAINED_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_unconstrained.md.tera");
const TASK_EXPLOIT_GOLDEN_TICKET_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/exploit_golden_ticket.md.tera");

const TASK_CREDACCESS_KERBEROS_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_kerberos.md.tera");
const TASK_CREDACCESS_LOW_HANGING_WITH_CREDS_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_low_hanging_with_creds.md.tera");
const TASK_CREDACCESS_LOW_HANGING_NO_CREDS_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_low_hanging_no_creds.md.tera");
const TASK_CREDACCESS_SHARE_SPIDER_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_share_spider.md.tera");
const TASK_CREDACCESS_NO_CRED_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_no_cred.md.tera");
const TASK_CREDACCESS_SPRAY_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_spray.md.tera");
const TASK_CREDACCESS_WITH_CREDS_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_with_creds.md.tera");
const TASK_CREDACCESS_FALLBACK_TEMPLATE: &str =
    include_str!("../../templates/redteam/tasks/credaccess_fallback.md.tera");

#[cfg(feature = "blue")]
const BLUE_TRIAGE_TEMPLATE: &str = include_str!("../../templates/blueteam/agents/triage.md.tera");
#[cfg(feature = "blue")]
const BLUE_THREAT_HUNTER_TEMPLATE: &str =
    include_str!("../../templates/blueteam/agents/threat_hunter.md.tera");
#[cfg(feature = "blue")]
const BLUE_LATERAL_ANALYST_TEMPLATE: &str =
    include_str!("../../templates/blueteam/agents/lateral_analyst.md.tera");
#[cfg(feature = "blue")]
const BLUE_ORCHESTRATOR_TEMPLATE: &str =
    include_str!("../../templates/blueteam/agents/orchestrator.md.tera");
#[cfg(feature = "blue")]
const BLUE_ESCALATION_TRIAGE_TEMPLATE: &str =
    include_str!("../../templates/blueteam/agents/escalation_triage.md.tera");
#[cfg(feature = "blue")]
const BLUE_INITIAL_ALERT_PROMPT_TEMPLATE: &str =
    include_str!("../../templates/blueteam/agents/initial_alert_prompt.md.tera");

#[cfg(feature = "blue")]
const BLUE_TASK_TRIAGE_TEMPLATE: &str =
    include_str!("../../templates/blueteam/tasks/triage_task.md.tera");
#[cfg(feature = "blue")]
const BLUE_TASK_THREAT_HUNT_TEMPLATE: &str =
    include_str!("../../templates/blueteam/tasks/threat_hunt_task.md.tera");
#[cfg(feature = "blue")]
const BLUE_TASK_LATERAL_TEMPLATE: &str =
    include_str!("../../templates/blueteam/tasks/lateral_task.md.tera");
#[cfg(feature = "blue")]
const BLUE_TASK_USER_INVESTIGATION_TEMPLATE: &str =
    include_str!("../../templates/blueteam/tasks/user_investigation_task.md.tera");
#[cfg(feature = "blue")]
const BLUE_TASK_HOST_INVESTIGATION_TEMPLATE: &str =
    include_str!("../../templates/blueteam/tasks/host_investigation_task.md.tera");

// Agent instruction templates (used as system prompts)
pub const TEMPLATE_RECON: &str = "redteam/agents/recon";
pub const TEMPLATE_CREDENTIAL_ACCESS: &str = "redteam/agents/credential_access";
pub const TEMPLATE_CRACKER: &str = "redteam/agents/cracker";
pub const TEMPLATE_ACL: &str = "redteam/agents/acl";
pub const TEMPLATE_PRIVESC: &str = "redteam/agents/privesc";
pub const TEMPLATE_LATERAL: &str = "redteam/agents/lateral";
pub const TEMPLATE_COERCION: &str = "redteam/agents/coercion";
pub const TEMPLATE_ORCHESTRATOR: &str = "redteam/agents/orchestrator";
pub const TEMPLATE_SYSTEM_INSTRUCTIONS: &str = "redteam/agents/system_instructions";

// Special-purpose templates (from Jinja2 ports)
pub const TEMPLATE_INITIAL_TASK: &str = "redteam/agents/initial_task";
pub const TEMPLATE_CRACKER_INSTRUCTIONS: &str = "redteam/agents/cracker_instructions";
pub const TEMPLATE_CRACKER_TASK: &str = "redteam/agents/cracker_task";
pub const TEMPLATE_GOLDEN_TICKET_INSTRUCTIONS: &str = "redteam/agents/golden_ticket_instructions";
pub const TEMPLATE_GOLDEN_TICKET_TASK: &str = "redteam/agents/golden_ticket_task";
pub const TEMPLATE_SHARE_PILFER_INSTRUCTIONS: &str = "redteam/agents/share_pilfer_instructions";
pub const TEMPLATE_SHARE_PILFER_TASK: &str = "redteam/agents/share_pilfer_task";

// Per-task-type prompt templates
pub const TASK_RECON: &str = "redteam/tasks/recon";
pub const TASK_CRACK: &str = "redteam/tasks/crack";
pub const TASK_LATERAL: &str = "redteam/tasks/lateral";
pub const TASK_COERCION: &str = "redteam/tasks/coercion";
pub const TASK_PRIVESC_ENUMERATION: &str = "redteam/tasks/privesc_enumeration";
pub const TASK_ACL_ANALYSIS: &str = "redteam/tasks/acl_analysis";
pub const TASK_ACL_CHAIN_STEP: &str = "redteam/tasks/acl_chain_step";
pub const TASK_COMMAND: &str = "redteam/tasks/command";

// Exploit task templates
pub const TASK_EXPLOIT_ADCS_ENUMERATE: &str = "redteam/tasks/exploit_adcs_enumerate";
pub const TASK_EXPLOIT_ADCS_ESC: &str = "redteam/tasks/exploit_adcs_esc";
pub const TASK_EXPLOIT_DELEGATION: &str = "redteam/tasks/exploit_delegation";
pub const TASK_EXPLOIT_GENERIC: &str = "redteam/tasks/exploit_generic";
pub const TASK_EXPLOIT_MSSQL_LATERAL: &str = "redteam/tasks/exploit_mssql_lateral";
pub const TASK_EXPLOIT_MSSQL: &str = "redteam/tasks/exploit_mssql";
pub const TASK_EXPLOIT_TRUST: &str = "redteam/tasks/exploit_trust";
pub const TASK_EXPLOIT_UNCONSTRAINED: &str = "redteam/tasks/exploit_unconstrained";
pub const TASK_EXPLOIT_GOLDEN_TICKET: &str = "redteam/tasks/exploit_golden_ticket";

// Credential access task templates
pub const TASK_CREDACCESS_KERBEROS: &str = "redteam/tasks/credaccess_kerberos";
pub const TASK_CREDACCESS_LOW_HANGING_WITH_CREDS: &str =
    "redteam/tasks/credaccess_low_hanging_with_creds";
pub const TASK_CREDACCESS_LOW_HANGING_NO_CREDS: &str =
    "redteam/tasks/credaccess_low_hanging_no_creds";
pub const TASK_CREDACCESS_SHARE_SPIDER: &str = "redteam/tasks/credaccess_share_spider";
pub const TASK_CREDACCESS_NO_CRED: &str = "redteam/tasks/credaccess_no_cred";
pub const TASK_CREDACCESS_SPRAY: &str = "redteam/tasks/credaccess_spray";
pub const TASK_CREDACCESS_WITH_CREDS: &str = "redteam/tasks/credaccess_with_creds";
pub const TASK_CREDACCESS_FALLBACK: &str = "redteam/tasks/credaccess_fallback";

// Blue team agent instruction templates
#[cfg(feature = "blue")]
pub const TEMPLATE_BLUE_TRIAGE: &str = "blueteam/agents/triage";
#[cfg(feature = "blue")]
pub const TEMPLATE_BLUE_THREAT_HUNTER: &str = "blueteam/agents/threat_hunter";
#[cfg(feature = "blue")]
pub const TEMPLATE_BLUE_LATERAL_ANALYST: &str = "blueteam/agents/lateral_analyst";
#[cfg(feature = "blue")]
pub const TEMPLATE_BLUE_ORCHESTRATOR: &str = "blueteam/agents/orchestrator";
#[cfg(feature = "blue")]
pub const TEMPLATE_BLUE_ESCALATION_TRIAGE: &str = "blueteam/agents/escalation_triage";
#[cfg(feature = "blue")]
pub const TEMPLATE_BLUE_INITIAL_ALERT_PROMPT: &str = "blueteam/agents/initial_alert_prompt";

// Blue team task templates
#[cfg(feature = "blue")]
pub const BLUE_TASK_TRIAGE: &str = "blueteam/tasks/triage_task";
#[cfg(feature = "blue")]
pub const BLUE_TASK_THREAT_HUNT: &str = "blueteam/tasks/threat_hunt_task";
#[cfg(feature = "blue")]
pub const BLUE_TASK_LATERAL: &str = "blueteam/tasks/lateral_task";
#[cfg(feature = "blue")]
pub const BLUE_TASK_USER_INVESTIGATION: &str = "blueteam/tasks/user_investigation_task";
#[cfg(feature = "blue")]
pub const BLUE_TASK_HOST_INVESTIGATION: &str = "blueteam/tasks/host_investigation_task";

/// Global Tera instance with all agent templates registered.
static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| {
    let mut tera = Tera::default();

    // Agent instruction templates
    let templates: &[(&str, &str)] = &[
        (TEMPLATE_RECON, RECON_TEMPLATE),
        (TEMPLATE_CREDENTIAL_ACCESS, CREDENTIAL_ACCESS_TEMPLATE),
        (TEMPLATE_CRACKER, CRACKER_TEMPLATE),
        (TEMPLATE_ACL, ACL_TEMPLATE),
        (TEMPLATE_PRIVESC, PRIVESC_TEMPLATE),
        (TEMPLATE_LATERAL, LATERAL_TEMPLATE),
        (TEMPLATE_COERCION, COERCION_TEMPLATE),
        (TEMPLATE_ORCHESTRATOR, ORCHESTRATOR_TEMPLATE),
        (TEMPLATE_SYSTEM_INSTRUCTIONS, SYSTEM_INSTRUCTIONS_TEMPLATE),
        // Task templates
        (TEMPLATE_INITIAL_TASK, INITIAL_TASK_TEMPLATE),
        (TEMPLATE_CRACKER_INSTRUCTIONS, CRACKER_INSTRUCTIONS_TEMPLATE),
        (TEMPLATE_CRACKER_TASK, CRACKER_TASK_TEMPLATE),
        (
            TEMPLATE_GOLDEN_TICKET_INSTRUCTIONS,
            GOLDEN_TICKET_INSTRUCTIONS_TEMPLATE,
        ),
        (TEMPLATE_GOLDEN_TICKET_TASK, GOLDEN_TICKET_TASK_TEMPLATE),
        (
            TEMPLATE_SHARE_PILFER_INSTRUCTIONS,
            SHARE_PILFER_INSTRUCTIONS_TEMPLATE,
        ),
        (TEMPLATE_SHARE_PILFER_TASK, SHARE_PILFER_TASK_TEMPLATE),
        // Per-task-type prompt templates
        (TASK_RECON, TASK_RECON_TEMPLATE),
        (TASK_CRACK, TASK_CRACK_TEMPLATE),
        (TASK_LATERAL, TASK_LATERAL_TEMPLATE),
        (TASK_COERCION, TASK_COERCION_TEMPLATE),
        (TASK_PRIVESC_ENUMERATION, TASK_PRIVESC_ENUMERATION_TEMPLATE),
        (TASK_ACL_ANALYSIS, TASK_ACL_ANALYSIS_TEMPLATE),
        (TASK_ACL_CHAIN_STEP, TASK_ACL_CHAIN_STEP_TEMPLATE),
        (TASK_COMMAND, TASK_COMMAND_TEMPLATE),
        // Exploit task templates
        (
            TASK_EXPLOIT_ADCS_ENUMERATE,
            TASK_EXPLOIT_ADCS_ENUMERATE_TEMPLATE,
        ),
        (TASK_EXPLOIT_ADCS_ESC, TASK_EXPLOIT_ADCS_ESC_TEMPLATE),
        (TASK_EXPLOIT_DELEGATION, TASK_EXPLOIT_DELEGATION_TEMPLATE),
        (TASK_EXPLOIT_GENERIC, TASK_EXPLOIT_GENERIC_TEMPLATE),
        (
            TASK_EXPLOIT_MSSQL_LATERAL,
            TASK_EXPLOIT_MSSQL_LATERAL_TEMPLATE,
        ),
        (TASK_EXPLOIT_MSSQL, TASK_EXPLOIT_MSSQL_TEMPLATE),
        (TASK_EXPLOIT_TRUST, TASK_EXPLOIT_TRUST_TEMPLATE),
        (
            TASK_EXPLOIT_UNCONSTRAINED,
            TASK_EXPLOIT_UNCONSTRAINED_TEMPLATE,
        ),
        (
            TASK_EXPLOIT_GOLDEN_TICKET,
            TASK_EXPLOIT_GOLDEN_TICKET_TEMPLATE,
        ),
        // Credential access task templates
        (TASK_CREDACCESS_KERBEROS, TASK_CREDACCESS_KERBEROS_TEMPLATE),
        (
            TASK_CREDACCESS_LOW_HANGING_WITH_CREDS,
            TASK_CREDACCESS_LOW_HANGING_WITH_CREDS_TEMPLATE,
        ),
        (
            TASK_CREDACCESS_LOW_HANGING_NO_CREDS,
            TASK_CREDACCESS_LOW_HANGING_NO_CREDS_TEMPLATE,
        ),
        (
            TASK_CREDACCESS_SHARE_SPIDER,
            TASK_CREDACCESS_SHARE_SPIDER_TEMPLATE,
        ),
        (TASK_CREDACCESS_NO_CRED, TASK_CREDACCESS_NO_CRED_TEMPLATE),
        (TASK_CREDACCESS_SPRAY, TASK_CREDACCESS_SPRAY_TEMPLATE),
        (
            TASK_CREDACCESS_WITH_CREDS,
            TASK_CREDACCESS_WITH_CREDS_TEMPLATE,
        ),
        (TASK_CREDACCESS_FALLBACK, TASK_CREDACCESS_FALLBACK_TEMPLATE),
    ];

    for (name, content) in templates {
        tera.add_raw_template(name, content)
            .unwrap_or_else(|e| panic!("Failed to register template '{name}': {e}"));
    }

    // Blue team templates (behind "blue" feature)
    #[cfg(feature = "blue")]
    {
        let blue_templates: &[(&str, &str)] = &[
            (TEMPLATE_BLUE_TRIAGE, BLUE_TRIAGE_TEMPLATE),
            (TEMPLATE_BLUE_THREAT_HUNTER, BLUE_THREAT_HUNTER_TEMPLATE),
            (TEMPLATE_BLUE_LATERAL_ANALYST, BLUE_LATERAL_ANALYST_TEMPLATE),
            (TEMPLATE_BLUE_ORCHESTRATOR, BLUE_ORCHESTRATOR_TEMPLATE),
            (
                TEMPLATE_BLUE_ESCALATION_TRIAGE,
                BLUE_ESCALATION_TRIAGE_TEMPLATE,
            ),
            (
                TEMPLATE_BLUE_INITIAL_ALERT_PROMPT,
                BLUE_INITIAL_ALERT_PROMPT_TEMPLATE,
            ),
            (BLUE_TASK_TRIAGE, BLUE_TASK_TRIAGE_TEMPLATE),
            (BLUE_TASK_THREAT_HUNT, BLUE_TASK_THREAT_HUNT_TEMPLATE),
            (BLUE_TASK_LATERAL, BLUE_TASK_LATERAL_TEMPLATE),
            (
                BLUE_TASK_USER_INVESTIGATION,
                BLUE_TASK_USER_INVESTIGATION_TEMPLATE,
            ),
            (
                BLUE_TASK_HOST_INVESTIGATION,
                BLUE_TASK_HOST_INVESTIGATION_TEMPLATE,
            ),
        ];
        for (name, content) in blue_templates {
            tera.add_raw_template(name, content)
                .unwrap_or_else(|e| panic!("Failed to register template '{name}': {e}"));
        }
    }

    tera
});

/// Operation context fields injected into agent and system prompt templates so
/// example tool calls show real operation values instead of generic literals
/// the LLM might copy verbatim.
#[derive(Debug, Clone, Copy)]
pub struct OperationContext<'a> {
    /// Primary target FQDN (e.g. `contoso.local`)
    pub target_domain: &'a str,
    /// Primary target DC IP
    pub target_dc_ip: &'a str,
    /// Primary target DC FQDN
    pub target_dc_fqdn: &'a str,
    /// Listener IP for callback-style tools
    pub listener_ip: &'a str,
}

impl OperationContext<'_> {
    /// All-empty context, for templates that don't reference operation values.
    pub const EMPTY: Self = Self {
        target_domain: "",
        target_dc_ip: "",
        target_dc_fqdn: "",
        listener_ip: "",
    };

    fn insert_into(&self, ctx: &mut Context) {
        ctx.insert("target_domain", self.target_domain);
        ctx.insert("target_dc_ip", self.target_dc_ip);
        ctx.insert("target_dc_fqdn", self.target_dc_fqdn);
        ctx.insert("listener_ip", self.listener_ip);
    }
}

/// Render an agent instruction template with the given context variables.
///
/// Used for role-based system prompts (recon, credential_access, cracker, etc.)
/// that have a `{% for tool in capabilities %}` loop.
///
/// # Arguments
/// * `template_name` - Template identifier (e.g. `TEMPLATE_RECON`)
/// * `capabilities` - List of tool names available to this agent role
/// * `multi_forest_mode` - Whether multi-forest operation is active
/// * `undominated_forests` - Forest names not yet dominated (for orchestrator)
/// * `op` - Operation context injected into example tool calls
pub fn render_agent_instructions(
    template_name: &str,
    capabilities: &[String],
    multi_forest_mode: bool,
    undominated_forests: &[String],
    op: OperationContext<'_>,
) -> Result<String> {
    render_agent_instructions_with_extras(
        template_name,
        capabilities,
        multi_forest_mode,
        undominated_forests,
        op,
        &[],
    )
}

/// Like `render_agent_instructions` but accepts additional (key, value) pairs
/// to insert into the Tera context (e.g. `deployment` for blue team templates).
pub fn render_agent_instructions_with_extras(
    template_name: &str,
    capabilities: &[String],
    multi_forest_mode: bool,
    undominated_forests: &[String],
    op: OperationContext<'_>,
    extras: &[(&str, &str)],
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("capabilities", capabilities);
    ctx.insert("multi_forest_mode", &multi_forest_mode);
    ctx.insert("undominated_forests", undominated_forests);
    op.insert_into(&mut ctx);
    for (k, v) in extras {
        ctx.insert(k.to_string(), v);
    }

    TEMPLATES
        .render(template_name, &ctx)
        .with_context(|| format!("Failed to render template '{template_name}'"))
}

/// Render the system_instructions template.
///
/// - `all_capabilities`: map of role → tool list. Falls back to hardcoded defaults if None.
/// - `technique_priorities`: sorted list of (technique, weight) pairs for the priority table.
///   If provided, renders a dynamic "ATTACK FALLBACK CHAINS" section.
/// - `op`: operation context injected into example tool calls.
pub fn render_system_instructions(
    all_capabilities: Option<&HashMap<String, Vec<String>>>,
    technique_priorities: Option<&[(String, i32)]>,
    op: OperationContext<'_>,
) -> Result<String> {
    let mut ctx = Context::new();
    if let Some(caps) = all_capabilities {
        ctx.insert("all_capabilities", caps);
    }
    if let Some(priorities) = technique_priorities {
        ctx.insert("technique_priorities", priorities);
    }
    op.insert_into(&mut ctx);

    TEMPLATES
        .render(TEMPLATE_SYSTEM_INSTRUCTIONS, &ctx)
        .with_context(|| "Failed to render system_instructions template".to_string())
}

/// Render a task template with a pre-built Tera context.
///
/// This is the primary render function for task prompts generated by
/// `generate_task_prompt()`. The caller builds a typed `tera::Context`
/// with the right variable types (strings, arrays, booleans).
pub fn render_template_with_context(template_name: &str, ctx: &Context) -> Result<String> {
    TEMPLATES
        .render(template_name, ctx)
        .with_context(|| format!("Failed to render template '{template_name}'"))
}

/// Render a task-specific template with string key-value context.
///
/// Convenience wrapper for templates that only need simple string variables
/// (e.g. initial_task, cracker_task, golden_ticket_task, share_pilfer_task).
pub fn render_task_template(
    template_name: &str,
    variables: &HashMap<String, String>,
) -> Result<String> {
    let mut ctx = Context::new();
    for (key, value) in variables {
        ctx.insert(key.clone(), value);
    }
    render_template_with_context(template_name, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_OP: OperationContext<'static> = OperationContext {
        target_domain: "contoso.local",
        target_dc_ip: "192.168.58.10",
        target_dc_fqdn: "dc01.contoso.local",
        listener_ip: "192.168.58.50",
    };

    #[test]
    fn render_recon_template() {
        let capabilities = vec![
            "nmap_scan".to_string(),
            "enumerate_users".to_string(),
            "run_bloodhound".to_string(),
        ];
        let result =
            render_agent_instructions(TEMPLATE_RECON, &capabilities, false, &[], TEST_OP).unwrap();

        assert!(result.contains("RECON Worker Agent"));
        assert!(result.contains("- nmap_scan"));
        assert!(result.contains("- enumerate_users"));
        assert!(result.contains("- run_bloodhound"));
    }

    #[test]
    fn render_recon_empty_capabilities() {
        let result = render_agent_instructions(TEMPLATE_RECON, &[], false, &[], TEST_OP).unwrap();
        assert!(result.contains("RECON Worker Agent"));
        assert!(result.contains("## Available Tools"));
    }

    #[test]
    fn render_credential_access_template() {
        let capabilities = vec!["secretsdump".to_string(), "kerberoast".to_string()];
        let result = render_agent_instructions(
            TEMPLATE_CREDENTIAL_ACCESS,
            &capabilities,
            false,
            &[],
            TEST_OP,
        )
        .unwrap();
        assert!(result.contains("Credential Access Agent"));
        assert!(result.contains("- secretsdump"));
        assert!(result.contains("- kerberoast"));
    }

    #[test]
    fn render_cracker_template() {
        let capabilities = vec!["crack_with_hashcat".to_string()];
        let result =
            render_agent_instructions(TEMPLATE_CRACKER, &capabilities, false, &[], TEST_OP)
                .unwrap();
        assert!(result.contains("Hash Cracker Agent"));
        assert!(result.contains("- crack_with_hashcat"));
    }

    #[test]
    fn render_acl_template() {
        let capabilities = vec!["pywhisker".to_string(), "dacl_edit".to_string()];
        let result =
            render_agent_instructions(TEMPLATE_ACL, &capabilities, false, &[], TEST_OP).unwrap();
        assert!(result.contains("ACL Exploitation Agent"));
        assert!(result.contains("- pywhisker"));
    }

    #[test]
    fn render_privesc_template() {
        let capabilities = vec!["certipy_find".to_string(), "s4u_attack".to_string()];
        let result =
            render_agent_instructions(TEMPLATE_PRIVESC, &capabilities, false, &[], TEST_OP)
                .unwrap();
        assert!(result.contains("Privilege Escalation Agent"));
        assert!(result.contains("- certipy_find"));
    }

    #[test]
    fn render_lateral_template() {
        let capabilities = vec!["psexec".to_string(), "evil_winrm".to_string()];
        let result =
            render_agent_instructions(TEMPLATE_LATERAL, &capabilities, false, &[], TEST_OP)
                .unwrap();
        assert!(result.contains("Lateral Movement Agent"));
        assert!(result.contains("- psexec"));
    }

    #[test]
    fn render_coercion_template() {
        let capabilities = vec!["petitpotam".to_string(), "start_responder".to_string()];
        let result =
            render_agent_instructions(TEMPLATE_COERCION, &capabilities, false, &[], TEST_OP)
                .unwrap();
        assert!(result.contains("Coercion Agent"));
        assert!(result.contains("- petitpotam"));
    }

    #[test]
    fn render_orchestrator_template() {
        let capabilities = vec!["dispatch_recon".to_string()];
        let result =
            render_agent_instructions(TEMPLATE_ORCHESTRATOR, &capabilities, false, &[], TEST_OP)
                .unwrap();
        assert!(result.contains("Red Team Orchestrator"));
    }

    #[test]
    fn render_system_instructions_with_capabilities() {
        let mut caps: HashMap<String, Vec<String>> = HashMap::new();
        caps.insert("recon".to_string(), vec!["nmap_scan".to_string()]);
        caps.insert(
            "credential_access".to_string(),
            vec!["secretsdump".to_string()],
        );
        caps.insert("cracker".to_string(), vec!["hashcat".to_string()]);
        caps.insert("coercion".to_string(), vec!["responder".to_string()]);
        caps.insert("acl".to_string(), vec!["pywhisker".to_string()]);
        caps.insert("privesc".to_string(), vec!["certipy".to_string()]);
        caps.insert("lateral".to_string(), vec!["psexec".to_string()]);

        let result = render_system_instructions(Some(&caps), None, TEST_OP).unwrap();
        assert!(result.contains("RECON"));
        assert!(result.contains("nmap_scan"));
    }

    #[test]
    fn render_system_instructions_without_capabilities() {
        let result = render_system_instructions(None, None, TEST_OP).unwrap();
        // Falls back to hardcoded defaults
        assert!(result.contains("nmap, netexec, rpcclient"));
        // Hardcoded fallback table
        assert!(result.contains("ADCS ESC1"));
        assert!(result.contains("certipy_request"));
    }

    #[test]
    fn render_system_instructions_with_priorities() {
        let priorities = vec![
            ("dc_secretsdump".to_string(), 1),
            ("golden_ticket".to_string(), 1),
            ("secretsdump".to_string(), 2),
            ("esc1".to_string(), 5),
            ("acl_abuse".to_string(), 6),
        ];
        let result = render_system_instructions(None, Some(&priorities), TEST_OP).unwrap();
        // Dynamic table rendered
        assert!(
            result.contains("operator strategy"),
            "Should mention strategy: {result}"
        );
        assert!(result.contains("dc_secretsdump"));
        assert!(result.contains("esc1"));
        assert!(result.contains("acl_abuse"));
        // Hardcoded table should NOT appear
        assert!(
            !result.contains("certipy_request → certipy_auth → secretsdump"),
            "Hardcoded table should not appear when priorities are provided"
        );
    }

    #[test]
    fn render_initial_task() {
        let mut vars = HashMap::new();
        vars.insert(
            "target_ip".to_string(),
            "192.168.58.10 192.168.58.20".to_string(),
        );
        let result = render_task_template(TEMPLATE_INITIAL_TASK, &vars).unwrap();
        assert!(result.contains("192.168.58.10 192.168.58.20"));
        assert!(result.contains("nmap scan"));
    }

    #[test]
    fn render_cracker_task() {
        let mut vars = HashMap::new();
        vars.insert(
            "hash_value".to_string(),
            "$krb5tgs$23$*svc_sql$".to_string(),
        );
        vars.insert("hash_type".to_string(), "Kerberos TGS".to_string());
        let result = render_task_template(TEMPLATE_CRACKER_TASK, &vars).unwrap();
        assert!(result.contains("$krb5tgs$23$*svc_sql$"));
        assert!(result.contains("Kerberos TGS"));
    }

    #[test]
    fn render_golden_ticket_task() {
        let mut vars = HashMap::new();
        vars.insert("krbtgt_hash".to_string(), "aad3b435:5703ad15".to_string());
        vars.insert("user_name".to_string(), "admin".to_string());
        vars.insert("password".to_string(), "P@ss".to_string());
        vars.insert(
            "compromised_domain".to_string(),
            "child.contoso.local".to_string(),
        );
        vars.insert("target_domain".to_string(), "contoso.local".to_string());
        vars.insert("compromised_dc_ip".to_string(), "192.168.58.10".to_string());
        vars.insert("target_dc_ip".to_string(), "192.168.58.20".to_string());
        let result = render_task_template(TEMPLATE_GOLDEN_TICKET_TASK, &vars).unwrap();
        assert!(result.contains("aad3b435:5703ad15"));
        assert!(result.contains("child.contoso.local"));
        assert!(result.contains("192.168.58.10"));
        assert!(result.contains("192.168.58.20"));
    }

    #[test]
    fn render_share_pilfer_task() {
        let mut vars = HashMap::new();
        vars.insert("target".to_string(), "192.168.58.10".to_string());
        vars.insert("share_name".to_string(), "SYSVOL".to_string());
        vars.insert("username".to_string(), "admin".to_string());
        vars.insert("password".to_string(), "P@ss".to_string());
        let result = render_task_template(TEMPLATE_SHARE_PILFER_TASK, &vars).unwrap();
        assert!(result.contains("SYSVOL"));
        assert!(result.contains("192.168.58.10"));
    }

    #[test]
    fn render_static_templates() {
        // Templates with no variables should render cleanly
        let empty: HashMap<String, String> = HashMap::new();
        let result = render_task_template(TEMPLATE_CRACKER_INSTRUCTIONS, &empty).unwrap();
        assert!(result.contains("Password Cracking Agent"));

        let result = render_task_template(TEMPLATE_GOLDEN_TICKET_INSTRUCTIONS, &empty).unwrap();
        assert!(result.contains("Golden Ticket Agent"));

        let result = render_task_template(TEMPLATE_SHARE_PILFER_INSTRUCTIONS, &empty).unwrap();
        assert!(result.contains("Share Pilfering Agent"));
    }

    #[test]
    fn invalid_template_name() {
        let result = render_agent_instructions("nonexistent", &[], false, &[], TEST_OP);
        assert!(result.is_err());
    }
}
