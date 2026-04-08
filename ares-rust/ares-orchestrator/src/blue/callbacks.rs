//! Blue team callback tool handlers.
//!
//! These are processed in-process (not dispatched to workers) when the
//! LLM agent loop encounters a blue team callback tool.

use ares_llm::agent_loop::CallbackResult;
use ares_llm::ToolCall;

/// Handle a blue team callback tool call.
///
/// Returns `None` if the tool is not a blue team callback.
pub fn handle_blue_callback(call: &ToolCall) -> Option<CallbackResult> {
    match call.name.as_str() {
        // ── Worker completion callbacks ──────────────────────────────
        "triage_complete" => {
            let severity = call.arguments["severity"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let summary = call.arguments["summary"].as_str().unwrap_or("").to_string();
            let escalate = call.arguments["escalate"].as_bool().unwrap_or(false);
            let result =
                format!("Triage complete: severity={severity}, escalate={escalate}. {summary}");
            Some(CallbackResult::TaskComplete {
                task_id: "triage".into(),
                result,
            })
        }

        "hunt_complete" => {
            let findings = call.arguments["findings"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let confidence = call.arguments["confidence"].as_str().unwrap_or("medium");
            let result = format!("Hunt complete (confidence: {confidence}): {findings}");
            Some(CallbackResult::TaskComplete {
                task_id: "threat_hunt".into(),
                result,
            })
        }

        "lateral_complete" => {
            let connections = call.arguments["connections_found"].as_u64().unwrap_or(0);
            let summary = call.arguments["summary"].as_str().unwrap_or("").to_string();
            let result = format!("Lateral analysis: {connections} connections found. {summary}");
            Some(CallbackResult::TaskComplete {
                task_id: "lateral_analysis".into(),
                result,
            })
        }

        // ── Orchestrator-level callbacks ─────────────────────────────
        "complete_investigation" => {
            let verdict = call.arguments["verdict"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let summary = call.arguments["summary"].as_str().unwrap_or("").to_string();
            let result = format!("Investigation complete: {verdict}. {summary}");
            Some(CallbackResult::TaskComplete {
                task_id: "investigation".into(),
                result,
            })
        }

        "escalate_investigation" => {
            let reason = call.arguments["reason"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let severity = call.arguments["severity"]
                .as_str()
                .unwrap_or("high")
                .to_string();
            Some(CallbackResult::RequestAssistance {
                issue: format!("Escalation ({severity}): {reason}"),
                context: call
                    .arguments
                    .get("context")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        }

        // ── Escalation triage callbacks ──────────────────────────────
        "confirm_escalation" => {
            let action = call.arguments["action"]
                .as_str()
                .unwrap_or("escalate")
                .to_string();
            let result = format!("Escalation confirmed: {action}");
            Some(CallbackResult::TaskComplete {
                task_id: "escalation_triage".into(),
                result,
            })
        }

        "downgrade_escalation" => {
            let reason = call.arguments["reason"].as_str().unwrap_or("").to_string();
            let result = format!("Escalation downgraded: {reason}");
            Some(CallbackResult::TaskComplete {
                task_id: "escalation_triage".into(),
                result,
            })
        }

        "request_reinvestigation" => {
            let focus = call.arguments["focus"].as_str().unwrap_or("").to_string();
            Some(CallbackResult::Continue(format!(
                "Reinvestigation queued with focus: {focus}"
            )))
        }

        "route_to_team" => {
            let team = call.arguments["team"].as_str().unwrap_or("soc").to_string();
            let priority = call.arguments["priority"]
                .as_str()
                .unwrap_or("medium")
                .to_string();
            let result = format!("Routed to {team} team (priority: {priority})");
            Some(CallbackResult::TaskComplete {
                task_id: "routing".into(),
                result,
            })
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_triage_complete() {
        let call = ToolCall {
            id: "c1".into(),
            name: "triage_complete".into(),
            arguments: json!({
                "severity": "high",
                "summary": "Kerberoasting detected",
                "escalate": true,
            }),
        };
        let result = handle_blue_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { result, .. } => {
                assert!(result.contains("high"));
                assert!(result.contains("escalate=true"));
            }
            _ => panic!("Expected TaskComplete"),
        }
    }

    #[test]
    fn test_escalate_investigation() {
        let call = ToolCall {
            id: "c2".into(),
            name: "escalate_investigation".into(),
            arguments: json!({
                "reason": "Active lateral movement detected",
                "severity": "critical",
            }),
        };
        let result = handle_blue_callback(&call).unwrap();
        match result {
            CallbackResult::RequestAssistance { issue, .. } => {
                assert!(issue.contains("critical"));
                assert!(issue.contains("lateral movement"));
            }
            _ => panic!("Expected RequestAssistance"),
        }
    }

    #[test]
    fn test_unknown_callback() {
        let call = ToolCall {
            id: "c3".into(),
            name: "nmap_scan".into(),
            arguments: json!({}),
        };
        assert!(handle_blue_callback(&call).is_none());
    }
}
