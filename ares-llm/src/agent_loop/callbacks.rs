use anyhow::Result;
use tracing::{info, warn};

use crate::provider::ToolCall;

use super::types::{CallbackHandler, CallbackResult};

pub(super) fn handle_builtin_callback(call: &ToolCall) -> Result<CallbackResult> {
    match call.name.as_str() {
        "task_complete" => {
            let task_id = call.arguments["task_id"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            // The LLM may pass result as a string or a JSON object — handle both.
            let result = match &call.arguments["result"] {
                serde_json::Value::String(s) => s.clone(),
                other if !other.is_null() => serde_json::to_string(other).unwrap_or_default(),
                _ => String::new(),
            };
            Ok(CallbackResult::TaskComplete { task_id, result })
        }
        "request_assistance" => {
            let issue = call.arguments["issue"]
                .as_str()
                .unwrap_or("unknown issue")
                .to_string();
            let context = call.arguments["context"].as_str().unwrap_or("").to_string();
            Ok(CallbackResult::RequestAssistance { issue, context })
        }
        "report_cracked_credential" => {
            warn!("report_cracked_credential called but removed — passwords are auto-extracted from tool output");
            Ok(CallbackResult::Continue(
                "This tool no longer exists. Cracked passwords are automatically extracted from \
                 hashcat/john stdout. Just call task_complete with a summary."
                    .to_string(),
            ))
        }
        "report_crack_failed" => {
            let hash_type = call.arguments["hash_type"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let username = call.arguments["username"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(username = %username, hash_type = %hash_type, "Crack failed reported");
            Ok(CallbackResult::Continue(format!(
                "Crack failure recorded for {username} ({hash_type})"
            )))
        }
        "report_finding" => {
            let finding_type = call.arguments["finding_type"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let description = call.arguments["description"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let target = call.arguments["target"].as_str().unwrap_or("").to_string();
            let severity = call.arguments["severity"]
                .as_str()
                .unwrap_or("info")
                .to_string();
            info!(finding_type = %finding_type, target = %target, severity = %severity, "Finding reported: {description}");

            // Route into `llm_findings` (NOT `discoveries`). The LLM-asserted
            // payload reaches reports for context but MUST NOT feed
            // `publish_vulnerability` — only parser-produced discoveries do.
            let vuln_id = if target.is_empty() {
                format!("finding_{finding_type}")
            } else {
                format!("finding_{}_{}", finding_type, target.replace('.', "_"))
            };
            let finding = serde_json::json!({
                "vulnerabilities": [{
                    "vuln_id": vuln_id,
                    "vuln_type": finding_type,
                    "target": target,
                    "details": {
                        "description": description,
                        "severity": severity,
                        "discovered_by": "agent_report_finding",
                    },
                }]
            });
            Ok(CallbackResult::LlmFinding {
                response: format!("Finding recorded: {finding_type}"),
                finding,
            })
        }
        "report_lateral_success" => {
            let target = call.arguments["target_ip"]
                .as_str()
                .or_else(|| call.arguments["target"].as_str())
                .unwrap_or("")
                .to_string();
            let technique = call.arguments["technique"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(target = %target, technique = %technique, "Lateral movement succeeded");

            // Surface as an LLM finding only — does NOT feed `publish_vulnerability`.
            let vuln_id = format!("lateral_success_{}_{}", technique, target.replace('.', "_"));
            let finding = serde_json::json!({
                "vulnerabilities": [{
                    "vuln_id": vuln_id,
                    "vuln_type": format!("lateral_{technique}"),
                    "target": target,
                    "details": {
                        "description": format!("Successful lateral movement via {technique}"),
                        "severity": "high",
                        "discovered_by": "agent_lateral_movement",
                    },
                }]
            });
            Ok(CallbackResult::LlmFinding {
                response: format!("Lateral movement recorded: {technique} → {target}"),
                finding,
            })
        }
        "report_lateral_failed" => {
            let target = call.arguments["target_ip"]
                .as_str()
                .or_else(|| call.arguments["target"].as_str())
                .unwrap_or("")
                .to_string();
            let technique = call.arguments["technique"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let reason = call.arguments["reason"].as_str().unwrap_or("").to_string();
            info!(target = %target, technique = %technique, "Lateral movement failed: {reason}");
            Ok(CallbackResult::Continue(format!(
                "Lateral failure recorded: {technique} → {target}: {reason}"
            )))
        }
        "complete_operation" => {
            let summary = call.arguments["summary"]
                .as_str()
                .unwrap_or("Operation completed")
                .to_string();
            info!("Operation marked complete: {summary}");
            Ok(CallbackResult::TaskComplete {
                task_id: "operation".to_string(),
                result: summary,
            })
        }
        // record_credential is deprecated — credentials are extracted automatically
        // from tool output via regex parsing. This handler exists only as a safety net.
        "record_credential" => {
            warn!("record_credential called but tool is disabled — credentials are auto-extracted from tool output");
            Ok(CallbackResult::Continue(
                "This tool is disabled. Credentials are automatically extracted from tool output. \
                 Focus on running tools that produce credential data (secretsdump, lsassy, netexec, etc.) \
                 and the system will parse and store credentials automatically.".to_string()
            ))
        }
        "record_compromised_host" => {
            let ip = call.arguments["ip"].as_str().unwrap_or("").to_string();
            let hostname = call.arguments["hostname"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let access = call.arguments["access_level"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!(ip = %ip, hostname = %hostname, access = %access, "Compromised host recorded");
            Ok(CallbackResult::Continue(format!(
                "Compromised host recorded: {ip} ({hostname}) — {access}"
            )))
        }
        "record_timeline_event" => {
            let desc = call.arguments["description"]
                .as_str()
                .unwrap_or("")
                .to_string();
            info!("Timeline event recorded: {desc}");
            Ok(CallbackResult::Continue(format!(
                "Timeline event recorded: {desc}"
            )))
        }
        "list_credentials" => {
            // Fallback when no OrchestratorCallbackHandler is wired (e.g. standalone worker).
            // When the orchestrator handler IS present, it intercepts this before we get here.
            Ok(CallbackResult::Continue(
                "No credentials available in this context. Credentials are injected \
                 into your task payload at dispatch time — check the task description."
                    .to_string(),
            ))
        }
        // Orchestrator-only tools — these require a custom CallbackHandler
        // (OrchestratorCallbackHandler) to provide meaningful state. When called
        // without one (e.g., by a worker), return a generic message.
        "get_credential_summary"
        | "get_hash_summary"
        | "get_all_credentials"
        | "get_all_hashes"
        | "get_hash_value"
        | "get_pending_tasks"
        | "get_agent_status"
        | "get_operation_summary"
        | "dispatch_recon"
        | "dispatch_credential_access"
        | "dispatch_lateral_movement"
        | "dispatch_privesc_exploit"
        | "dispatch_coercion"
        | "dispatch_crack" => Ok(CallbackResult::Continue(
            "This tool requires the orchestrator callback handler.".to_string(),
        )),
        _ => anyhow::bail!("Unknown callback tool: {}", call.name),
    }
}

/// Handle a callback tool, trying the custom handler first then built-in.
pub(super) async fn handle_callback(
    call: &ToolCall,
    custom: Option<&dyn CallbackHandler>,
) -> Result<CallbackResult> {
    // Try custom handler first (orchestrator state queries, dispatch tools)
    if let Some(handler) = custom {
        if let Some(result) = handler.handle_callback(call).await {
            return result;
        }
    }
    // Fall back to built-in handlers
    handle_builtin_callback(call)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(name: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "test-id".to_string(),
            name: name.to_string(),
            arguments: args,
        }
    }

    #[test]
    fn list_credentials_fallback() {
        let call = make_call("list_credentials", serde_json::json!({}));
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("No credentials available"));
                assert!(msg.contains("task payload"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn task_complete_string_result() {
        let call = make_call(
            "task_complete",
            serde_json::json!({"task_id": "t-123", "result": "done"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { task_id, result } => {
                assert_eq!(task_id, "t-123");
                assert_eq!(result, "done");
            }
            other => panic!("Expected TaskComplete, got {other:?}"),
        }
    }

    #[test]
    fn task_complete_json_result() {
        let call = make_call(
            "task_complete",
            serde_json::json!({"task_id": "t-456", "result": {"status": "success"}}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { task_id, result } => {
                assert_eq!(task_id, "t-456");
                assert!(result.contains("success"));
            }
            other => panic!("Expected TaskComplete, got {other:?}"),
        }
    }

    #[test]
    fn request_assistance() {
        let call = make_call(
            "request_assistance",
            serde_json::json!({"issue": "stuck", "context": "ldap failed"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::RequestAssistance { issue, context } => {
                assert_eq!(issue, "stuck");
                assert_eq!(context, "ldap failed");
            }
            other => panic!("Expected RequestAssistance, got {other:?}"),
        }
    }

    #[test]
    fn record_credential_disabled() {
        let call = make_call(
            "record_credential",
            serde_json::json!({
                "username": "admin",
                "password": "P@ssw0rd",
                "domain": "contoso.local"
            }),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("disabled"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn orchestrator_only_tools() {
        for tool_name in [
            "get_credential_summary",
            "get_hash_summary",
            "get_all_credentials",
            "dispatch_recon",
        ] {
            let call = make_call(tool_name, serde_json::json!({}));
            let result = handle_builtin_callback(&call).unwrap();
            match result {
                CallbackResult::Continue(msg) => {
                    assert!(msg.contains("orchestrator callback handler"));
                }
                other => panic!("Expected Continue for {tool_name}, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_callback() {
        let call = make_call("nonexistent_tool", serde_json::json!({}));
        let result = handle_builtin_callback(&call);
        assert!(result.is_err());
    }

    #[test]
    fn report_cracked_credential_removed() {
        let call = make_call(
            "report_cracked_credential",
            serde_json::json!({"username": "administrator", "password": "Welcome1"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("no longer exists"));
                assert!(msg.contains("task_complete"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn report_crack_failed() {
        let call = make_call(
            "report_crack_failed",
            serde_json::json!({"username": "jdoe", "hash_type": "ntlm"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("jdoe"));
                assert!(msg.contains("ntlm"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn report_finding() {
        let call = make_call(
            "report_finding",
            serde_json::json!({"finding_type": "kerberoastable_account", "description": "Found SPN", "target": "192.168.58.10"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::LlmFinding { response, finding } => {
                assert!(response.contains("kerberoastable_account"));
                let vulns = finding["vulnerabilities"].as_array().unwrap();
                assert_eq!(vulns.len(), 1);
                assert_eq!(vulns[0]["vuln_type"], "kerberoastable_account");
                assert_eq!(vulns[0]["target"], "192.168.58.10");
            }
            other => panic!("Expected LlmFinding, got {other:?}"),
        }
    }

    #[test]
    fn report_lateral_success_with_target_ip() {
        let call = make_call(
            "report_lateral_success",
            serde_json::json!({"target_ip": "192.168.58.10", "technique": "psexec"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::LlmFinding { response, finding } => {
                assert!(response.contains("psexec"));
                assert!(response.contains("192.168.58.10"));
                let vulns = finding["vulnerabilities"].as_array().unwrap();
                assert_eq!(vulns.len(), 1);
                assert_eq!(vulns[0]["vuln_type"], "lateral_psexec");
            }
            other => panic!("Expected LlmFinding, got {other:?}"),
        }
    }

    #[test]
    fn report_lateral_success_with_target_fallback() {
        // When target_ip is absent the handler falls back to the "target" key.
        let call = make_call(
            "report_lateral_success",
            serde_json::json!({"target": "srv01.contoso.local", "technique": "wmiexec"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::LlmFinding { response, finding } => {
                assert!(response.contains("wmiexec"));
                assert!(response.contains("srv01.contoso.local"));
                let vulns = finding["vulnerabilities"].as_array().unwrap();
                assert_eq!(vulns[0]["vuln_type"], "lateral_wmiexec");
            }
            other => panic!("Expected LlmFinding, got {other:?}"),
        }
    }

    #[test]
    fn report_lateral_failed() {
        let call = make_call(
            "report_lateral_failed",
            serde_json::json!({
                "target_ip": "192.168.58.20",
                "technique": "smbexec",
                "reason": "access denied"
            }),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("smbexec"));
                assert!(msg.contains("192.168.58.20"));
                assert!(msg.contains("access denied"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn record_compromised_host() {
        let call = make_call(
            "record_compromised_host",
            serde_json::json!({
                "ip": "192.168.58.10",
                "hostname": "dc01.contoso.local",
                "access_level": "SYSTEM"
            }),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("192.168.58.10"));
                assert!(msg.contains("dc01.contoso.local"));
                assert!(msg.contains("SYSTEM"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn record_timeline_event() {
        let call = make_call(
            "record_timeline_event",
            serde_json::json!({"description": "Obtained DA via AS-REP roasting"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("Obtained DA via AS-REP roasting"));
            }
            other => panic!("Expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn complete_operation() {
        let call = make_call(
            "complete_operation",
            serde_json::json!({"summary": "Achieved domain admin across all forests"}),
        );
        let result = handle_builtin_callback(&call).unwrap();
        match result {
            CallbackResult::TaskComplete { task_id, result } => {
                assert_eq!(task_id, "operation");
                assert!(result.contains("domain admin"));
            }
            other => panic!("Expected TaskComplete, got {other:?}"),
        }
    }
}
