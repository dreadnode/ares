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

/// Build the initial alert prompt for a blue team investigation.
///
/// Extracts alert metadata, red team operation context, and time window
/// information to produce a context-rich initial prompt for the orchestrator.
pub fn build_initial_alert_prompt(
    investigation_id: &str,
    alert: &serde_json::Value,
    operation_id: Option<&str>,
) -> Result<String> {
    use tera::Context;

    let mut ctx = Context::new();
    ctx.insert("investigation_id", investigation_id);

    // Extract alert labels
    let labels = alert
        .get("labels")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let annotations = alert
        .get("annotations")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let alert_name = labels
        .get("alertname")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    ctx.insert("alert_name", alert_name);

    let severity = labels
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    ctx.insert("severity", severity);

    let deployment = labels.get("deployment").and_then(|v| v.as_str());
    ctx.insert("deployment", &deployment);

    let instance = labels.get("instance").and_then(|v| v.as_str());
    ctx.insert("instance", &instance);

    let job = labels.get("job").and_then(|v| v.as_str());
    ctx.insert("job", &job);

    let rulename = labels.get("rulename").and_then(|v| v.as_str());
    ctx.insert("rulename", &rulename);

    let starts_at = alert
        .get("startsAt")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    ctx.insert("starts_at", starts_at);

    let summary = annotations
        .get("summary")
        .and_then(|v| v.as_str())
        .or_else(|| alert.get("summary").and_then(|v| v.as_str()))
        .unwrap_or("No summary available");
    ctx.insert("summary", summary);

    let description = annotations
        .get("description")
        .and_then(|v| v.as_str())
        .or_else(|| alert.get("description").and_then(|v| v.as_str()));
    ctx.insert("description", &description);

    // Extract MITRE technique from labels or annotations
    let mitre_technique = ["mitre_technique", "mitre", "technique_id", "technique"]
        .iter()
        .find_map(|key| {
            labels
                .get(*key)
                .and_then(|v| v.as_str())
                .or_else(|| annotations.get(*key).and_then(|v| v.as_str()))
        });
    ctx.insert("mitre_technique", &mitre_technique);

    // Extract operation context (from `blue from-operation` submissions)
    let op_ctx = alert.get("operation_context");
    let op_id = operation_id.or_else(|| {
        op_ctx
            .and_then(|c| c.get("operation_id"))
            .and_then(|v| v.as_str())
    });
    ctx.insert("operation_id", &op_id);

    let attack_window_start = op_ctx
        .and_then(|c| c.get("attack_window_start"))
        .and_then(|v| v.as_str());
    ctx.insert("attack_window_start", &attack_window_start);

    let attack_window_end = op_ctx
        .and_then(|c| c.get("attack_window_end"))
        .and_then(|v| v.as_str());
    ctx.insert("attack_window_end", &attack_window_end);

    // Techniques used (array of strings)
    let techniques_used: Vec<String> = op_ctx
        .and_then(|c| c.get("techniques_used"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    ctx.insert("techniques_used", &techniques_used);

    // Target IPs and users (from `blue from-operation`)
    let target_ips: Vec<String> = alert
        .get("target_ips")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .take(20)
                .collect()
        })
        .unwrap_or_default();
    if !target_ips.is_empty() {
        ctx.insert("target_ips", &target_ips.join(", "));
    } else {
        ctx.insert("target_ips", &None::<String>);
    }

    let target_users: Vec<String> = alert
        .get("target_users")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .take(20)
                .collect()
        })
        .unwrap_or_default();
    if !target_users.is_empty() {
        ctx.insert("target_users", &target_users.join(", "));
    } else {
        ctx.insert("target_users", &None::<String>);
    }

    // Current time values for queries
    let now = chrono::Utc::now();
    ctx.insert("current_time", &now.to_rfc3339());
    ctx.insert(
        "current_time_minus_1h",
        &(now - chrono::Duration::hours(1)).to_rfc3339(),
    );
    ctx.insert(
        "current_time_minus_2h",
        &(now - chrono::Duration::hours(2)).to_rfc3339(),
    );

    // Full alert JSON for reference
    let alert_json = serde_json::to_string_pretty(alert).unwrap_or_else(|_| "{}".to_string());
    ctx.insert("alert_json", &alert_json);

    templates::render_template_with_context(templates::TEMPLATE_BLUE_INITIAL_ALERT_PROMPT, &ctx)
}
