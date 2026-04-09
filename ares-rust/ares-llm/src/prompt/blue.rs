//! Blue team task prompt generation.
//!
//! Generates prompts for blue team investigation tasks (triage, threat hunt,
//! lateral analysis) from Tera templates and investigation state.

use anyhow::Result;
use tera::Context;

use super::templates;

/// Generate a blue team task prompt from task type and parameters.
pub fn generate_blue_task_prompt(
    task_type: &str,
    task_id: &str,
    params: &serde_json::Value,
    state_summary: &str,
) -> Option<String> {
    let result = match task_type {
        "triage_alert" | "triage" => generate_triage_prompt(task_id, params, state_summary),
        "threat_hunt" => generate_threat_hunt_prompt(task_id, params, state_summary),
        "lateral_analysis" | "lateral" => generate_lateral_prompt(task_id, params, state_summary),
        "user_investigation" => generate_user_investigation_prompt(task_id, params, state_summary),
        "host_investigation" => generate_host_investigation_prompt(task_id, params, state_summary),
        _ => return None,
    };
    Some(result.unwrap_or_else(|e| format!("Error generating blue team prompt: {e}")))
}

fn generate_triage_prompt(
    task_id: &str,
    params: &serde_json::Value,
    state_summary: &str,
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("state_summary", state_summary);

    let alert_summary = params
        .get("alert_summary")
        .and_then(|v| v.as_str())
        .unwrap_or("No alert summary available");
    ctx.insert("alert_summary", alert_summary);

    let alert_timestamp = params
        .get("alert_timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    ctx.insert("alert_timestamp", alert_timestamp);

    templates::render_template_with_context(templates::BLUE_TASK_TRIAGE, &ctx)
}

fn generate_threat_hunt_prompt(
    task_id: &str,
    params: &serde_json::Value,
    state_summary: &str,
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("state_summary", state_summary);

    let technique_id = params
        .get("technique_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    ctx.insert("technique_id", technique_id);

    let detection_method = params
        .get("detection_method")
        .and_then(|v| v.as_str())
        .unwrap_or("general");
    ctx.insert("detection_method", detection_method);

    let hostname = params.get("hostname").and_then(|v| v.as_str());
    ctx.insert("hostname", &hostname);

    let username = params.get("username").and_then(|v| v.as_str());
    ctx.insert("username", &username);

    let context = params.get("context").and_then(|v| v.as_str());
    ctx.insert("context", &context);

    templates::render_template_with_context(templates::BLUE_TASK_THREAT_HUNT, &ctx)
}

fn generate_lateral_prompt(
    task_id: &str,
    params: &serde_json::Value,
    state_summary: &str,
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("state_summary", state_summary);

    let focus_host = params.get("focus_host").and_then(|v| v.as_str());
    ctx.insert("focus_host", &focus_host);

    let focus_user = params.get("focus_user").and_then(|v| v.as_str());
    ctx.insert("focus_user", &focus_user);

    let context = params.get("context").and_then(|v| v.as_str());
    ctx.insert("context", &context);

    templates::render_template_with_context(templates::BLUE_TASK_LATERAL, &ctx)
}

fn generate_user_investigation_prompt(
    task_id: &str,
    params: &serde_json::Value,
    state_summary: &str,
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("state_summary", state_summary);

    let username = params
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    ctx.insert("username", username);

    let domain = params.get("domain").and_then(|v| v.as_str());
    ctx.insert("domain", &domain);

    let context = params.get("context").and_then(|v| v.as_str());
    ctx.insert("context", &context);

    templates::render_template_with_context(templates::BLUE_TASK_USER_INVESTIGATION, &ctx)
}

fn generate_host_investigation_prompt(
    task_id: &str,
    params: &serde_json::Value,
    state_summary: &str,
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("state_summary", state_summary);

    let hostname = params
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    ctx.insert("hostname", hostname);

    let context = params.get("context").and_then(|v| v.as_str());
    ctx.insert("context", &context);

    templates::render_template_with_context(templates::BLUE_TASK_HOST_INVESTIGATION, &ctx)
}

/// Get the template name for a blue team agent role's system prompt.
pub fn blue_role_template(role: &str) -> &'static str {
    match role {
        "triage" => templates::TEMPLATE_BLUE_TRIAGE,
        "threat_hunter" => templates::TEMPLATE_BLUE_THREAT_HUNTER,
        "lateral_analyst" => templates::TEMPLATE_BLUE_LATERAL_ANALYST,
        "blue_orchestrator" => templates::TEMPLATE_BLUE_ORCHESTRATOR,
        "escalation_triage" => templates::TEMPLATE_BLUE_ESCALATION_TRIAGE,
        _ => templates::TEMPLATE_BLUE_TRIAGE,
    }
}

/// Build a system prompt for a blue team agent role.
pub fn build_blue_system_prompt(role: &str, capabilities: &[String]) -> Result<String> {
    let template_name = blue_role_template(role);
    templates::render_agent_instructions(template_name, capabilities, false, &[])
}
