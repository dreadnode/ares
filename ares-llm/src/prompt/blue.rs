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
///
/// If `deployment` is provided, it is injected into the template context so
/// sub-agent prompts use the correct deployment label for Loki queries instead
/// of a hardcoded value.
pub fn build_blue_system_prompt(
    role: &str,
    capabilities: &[String],
    deployment: Option<&str>,
) -> Result<String> {
    let template_name = blue_role_template(role);
    let extras: Vec<(&str, &str)> = deployment
        .map(|d| vec![("deployment", d)])
        .unwrap_or_default();
    templates::render_agent_instructions_with_extras(
        template_name,
        capabilities,
        false,
        &[],
        templates::OperationContext::EMPTY,
        &extras,
    )
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

    // Current time values for queries. During a benchmark replay, anchor "now"
    // to the shared replay clock (ARES_REPLAY_CLOCK_START = first fired alert) so
    // the template's "query from now-2h to now" window lands on the captured
    // attack instead of wall-clock now.
    let now = ares_core::replay_clock::replay_now();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generate_blue_task_prompt_returns_none_for_unknown_type() {
        let params = json!({});
        assert!(generate_blue_task_prompt("nonexistent", "t-1", &params, "").is_none());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_triage_alert() {
        let params = json!({"alert_summary": "suspicious login"});
        assert!(generate_blue_task_prompt("triage_alert", "t-1", &params, "state").is_some());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_triage() {
        let params = json!({"alert_summary": "suspicious login"});
        assert!(generate_blue_task_prompt("triage", "t-2", &params, "state").is_some());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_threat_hunt() {
        let params = json!({"technique_id": "T1003"});
        assert!(generate_blue_task_prompt("threat_hunt", "t-3", &params, "state").is_some());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_lateral_analysis() {
        let params = json!({"focus_host": "dc01"});
        assert!(generate_blue_task_prompt("lateral_analysis", "t-4", &params, "state").is_some());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_lateral() {
        let params = json!({"focus_host": "dc01"});
        assert!(generate_blue_task_prompt("lateral", "t-5", &params, "state").is_some());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_user_investigation() {
        let params = json!({"username": "admin"});
        assert!(generate_blue_task_prompt("user_investigation", "t-6", &params, "state").is_some());
    }

    #[test]
    fn generate_blue_task_prompt_returns_some_for_host_investigation() {
        let params = json!({"hostname": "dc01"});
        assert!(generate_blue_task_prompt("host_investigation", "t-7", &params, "state").is_some());
    }

    #[test]
    fn role_template_triage() {
        assert_eq!(
            blue_role_template("triage"),
            templates::TEMPLATE_BLUE_TRIAGE
        );
    }

    #[test]
    fn role_template_threat_hunter() {
        assert_eq!(
            blue_role_template("threat_hunter"),
            templates::TEMPLATE_BLUE_THREAT_HUNTER
        );
    }

    #[test]
    fn role_template_lateral_analyst() {
        assert_eq!(
            blue_role_template("lateral_analyst"),
            templates::TEMPLATE_BLUE_LATERAL_ANALYST
        );
    }

    #[test]
    fn role_template_blue_orchestrator() {
        assert_eq!(
            blue_role_template("blue_orchestrator"),
            templates::TEMPLATE_BLUE_ORCHESTRATOR
        );
    }

    #[test]
    fn role_template_escalation_triage() {
        assert_eq!(
            blue_role_template("escalation_triage"),
            templates::TEMPLATE_BLUE_ESCALATION_TRIAGE
        );
    }

    #[test]
    fn role_template_defaults_to_triage_for_unknown() {
        assert_eq!(
            blue_role_template("nonexistent_role"),
            templates::TEMPLATE_BLUE_TRIAGE
        );
    }

    #[test]
    fn system_prompt_succeeds_for_triage() {
        let caps = vec!["query_loki".to_string(), "record_evidence".to_string()];
        let result = build_blue_system_prompt("triage", &caps, None);
        assert!(result.is_ok());
    }

    #[test]
    fn system_prompt_succeeds_for_threat_hunter() {
        let caps = vec!["query_loki".to_string()];
        let result = build_blue_system_prompt("threat_hunter", &caps, None);
        assert!(result.is_ok());
    }

    #[test]
    fn system_prompt_succeeds_for_lateral_analyst() {
        let caps = vec!["query_loki".to_string()];
        let result = build_blue_system_prompt("lateral_analyst", &caps, None);
        assert!(result.is_ok());
    }

    #[test]
    fn system_prompt_succeeds_for_blue_orchestrator() {
        let caps = vec!["dispatch_triage".to_string()];
        let result = build_blue_system_prompt("blue_orchestrator", &caps, None);
        assert!(result.is_ok());
    }

    #[test]
    fn system_prompt_escalation_triage_fails_without_investigation_context() {
        // The escalation_triage template requires {{ investigation_context }}
        // which build_blue_system_prompt does not supply. The actual caller
        // provides it separately, so rendering via this helper is expected to fail.
        let caps = vec!["query_loki".to_string()];
        let result = build_blue_system_prompt("escalation_triage", &caps, None);
        assert!(result.is_err());
    }

    #[test]
    fn system_prompt_includes_capabilities() {
        let caps = vec![
            "query_loki".to_string(),
            "record_evidence".to_string(),
            "track_host".to_string(),
        ];
        let result = build_blue_system_prompt("triage", &caps, None).unwrap();
        assert!(result.contains("query_loki"));
        assert!(result.contains("record_evidence"));
        assert!(result.contains("track_host"));
    }

    #[test]
    fn system_prompt_with_deployment() {
        let caps = vec!["query_loki".to_string()];
        let result = build_blue_system_prompt("triage", &caps, Some("prod-cluster")).unwrap();
        // The deployment value should be accessible in the template context,
        // even if the triage template doesn't explicitly render it.
        assert!(!result.is_empty());
    }

    #[test]
    fn initial_alert_prompt_extracts_alert_name_from_labels() {
        let alert = json!({
            "labels": {
                "alertname": "CredentialDumping",
                "severity": "critical"
            },
            "annotations": {
                "summary": "Credential dumping detected"
            },
            "startsAt": "2026-04-08T12:00:00Z"
        });
        let result = build_initial_alert_prompt("inv-001", &alert, None).unwrap();
        assert!(result.contains("CredentialDumping"));
        assert!(result.contains("critical"));
    }

    #[test]
    fn initial_alert_prompt_handles_missing_labels() {
        let alert = json!({
            "startsAt": "2026-04-08T12:00:00Z"
        });
        let result = build_initial_alert_prompt("inv-002", &alert, None).unwrap();
        // Should fall back to defaults
        assert!(result.contains("Unknown")); // default alert_name
        assert!(result.contains("inv-002"));
    }

    #[test]
    fn initial_alert_prompt_handles_missing_annotations() {
        let alert = json!({
            "labels": {
                "alertname": "TestAlert"
            }
        });
        let result = build_initial_alert_prompt("inv-003", &alert, None).unwrap();
        assert!(result.contains("TestAlert"));
        assert!(result.contains("No summary available")); // default summary
    }

    #[test]
    fn initial_alert_prompt_includes_operation_id_when_provided() {
        // operation_id is only rendered when attack_window_start/end are present,
        // so we need operation_context with those fields.
        let alert = json!({
            "labels": {
                "alertname": "ScanDetected",
                "severity": "high"
            },
            "annotations": {
                "summary": "Network scan detected"
            },
            "startsAt": "2026-04-08T12:00:00Z",
            "operation_context": {
                "attack_window_start": "2026-04-08T11:00:00Z",
                "attack_window_end": "2026-04-08T13:00:00Z"
            }
        });
        let result = build_initial_alert_prompt("inv-004", &alert, Some("op-red-42")).unwrap();
        assert!(result.contains("op-red-42"));
    }

    #[test]
    fn initial_alert_prompt_extracts_operation_id_from_operation_context() {
        let alert = json!({
            "labels": {
                "alertname": "TestAlert",
                "severity": "medium"
            },
            "annotations": {},
            "startsAt": "2026-04-08T12:00:00Z",
            "operation_context": {
                "operation_id": "op-from-context",
                "attack_window_start": "2026-04-08T11:00:00Z",
                "attack_window_end": "2026-04-08T13:00:00Z",
                "techniques_used": ["T1003", "T1046"]
            }
        });
        let result = build_initial_alert_prompt("inv-005", &alert, None).unwrap();
        assert!(result.contains("op-from-context"));
        assert!(result.contains("T1003"));
        assert!(result.contains("T1046"));
    }

    #[test]
    fn initial_alert_prompt_includes_deployment_label() {
        let alert = json!({
            "labels": {
                "alertname": "TestAlert",
                "severity": "low",
                "deployment": "staging-env"
            },
            "annotations": {},
            "startsAt": "2026-04-08T12:00:00Z"
        });
        let result = build_initial_alert_prompt("inv-006", &alert, None).unwrap();
        assert!(result.contains("staging-env"));
    }

    #[test]
    fn initial_alert_prompt_includes_mitre_technique() {
        let alert = json!({
            "labels": {
                "alertname": "DCSync",
                "severity": "critical",
                "mitre_technique": "T1003.006"
            },
            "annotations": {
                "summary": "DCSync attack detected"
            },
            "startsAt": "2026-04-08T12:00:00Z"
        });
        let result = build_initial_alert_prompt("inv-007", &alert, None).unwrap();
        assert!(result.contains("T1003.006"));
    }

    #[test]
    fn initial_alert_prompt_includes_target_ips_and_users() {
        let alert = json!({
            "labels": {
                "alertname": "TestAlert",
                "severity": "high"
            },
            "annotations": {},
            "startsAt": "2026-04-08T12:00:00Z",
            "target_ips": ["192.168.58.10", "192.168.58.20"],
            "target_users": ["admin", "svc_sql"]
        });
        let result = build_initial_alert_prompt("inv-008", &alert, None).unwrap();
        assert!(result.contains("192.168.58.10"));
        assert!(result.contains("192.168.58.20"));
        assert!(result.contains("admin"));
        assert!(result.contains("svc_sql"));
    }

    #[test]
    fn initial_alert_prompt_contains_alert_json() {
        let alert = json!({
            "labels": {
                "alertname": "TestAlert",
                "severity": "low"
            },
            "startsAt": "2026-04-08T12:00:00Z"
        });
        let result = build_initial_alert_prompt("inv-009", &alert, None).unwrap();
        // The full alert JSON should be embedded
        assert!(result.contains("\"alertname\": \"TestAlert\""));
    }

    #[test]
    fn initial_alert_prompt_explicit_operation_id_overrides_context() {
        let alert = json!({
            "labels": {
                "alertname": "TestAlert",
                "severity": "medium"
            },
            "annotations": {},
            "startsAt": "2026-04-08T12:00:00Z",
            "operation_context": {
                "operation_id": "op-context-id",
                "attack_window_start": "2026-04-08T11:00:00Z",
                "attack_window_end": "2026-04-08T13:00:00Z"
            }
        });
        // Explicit operation_id should take precedence over context
        let result = build_initial_alert_prompt("inv-010", &alert, Some("op-explicit")).unwrap();
        assert!(result.contains("op-explicit"));
    }
}
