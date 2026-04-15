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
            // This tool was removed. Cracked passwords are auto-extracted from
            // hashcat/john stdout. Tell the LLM to just call task_complete.
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
            info!(finding_type = %finding_type, "Finding reported: {description}");
            Ok(CallbackResult::Continue(format!(
                "Finding recorded: {finding_type}"
            )))
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
            Ok(CallbackResult::Continue(format!(
                "Lateral movement recorded: {technique} → {target}"
            )))
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
            // Minimal response — real data comes from OrchestratorCallbackHandler
            Ok(CallbackResult::Continue(
                "Use get_all_credentials for full credential listing.".to_string(),
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
