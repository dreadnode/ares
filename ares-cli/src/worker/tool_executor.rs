//! Thin tool executor loop for LLM-driven orchestration.
//!
//! When the Rust orchestrator drives agent loops via `ARES_LLM_MODEL`, it
//! issues a NATS request to `ares.tools.exec.{role}`. Workers subscribe as
//! a queue group so each request goes to exactly one worker, and reply on
//! the auto-generated reply inbox.
//!
//! ```text
//! loop {
//!     1. Receive NATS request on ares.tools.exec.{role} (queue group)
//!     2. Deserialize ToolExecRequest
//!     3. Execute tool via ares_tools::dispatch()
//!     4. Serialize ToolExecResponse
//!     5. Reply on msg.reply inbox
//! }
//! ```
//!

use std::sync::Arc;

use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn, Instrument};

use ares_core::nats::{self, NatsBroker};
use ares_core::telemetry::propagation::set_span_parent;
use ares_core::telemetry::spans::{trace_discovery, AgentSpanBuilder, SpanKind, Team};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

use crate::worker::config::WorkerConfig;
use crate::worker::heartbeat::WorkerStatus;

// ─── Wire types (match orchestrator's tool_dispatcher.rs exactly) ────────────

/// Request from the orchestrator's RedisToolDispatcher.
#[derive(Debug, Deserialize)]
struct ToolExecRequest {
    call_id: String,
    task_id: String,
    tool_name: String,
    arguments: serde_json::Value,
    /// W3C traceparent header for cross-service span linking.
    #[serde(default)]
    traceparent: Option<String>,
    /// Operation ID for span correlation with dashboards.
    #[serde(default)]
    operation_id: Option<String>,
}

/// Response pushed back to the orchestrator.
#[derive(Debug, Serialize)]
struct ToolExecResponse {
    call_id: String,
    output: String,
    error: Option<String>,
    /// Structured discoveries parsed from the tool output.
    #[serde(skip_serializing_if = "Option::is_none")]
    discoveries: Option<serde_json::Value>,
}

// ─── Tool executor loop ─────────────────────────────────────────────────────

/// Run the tool execution loop until shutdown is signalled.
///
/// Subscribes to `ares.tools.exec.{role}` as a queue group so each request
/// goes to exactly one worker. Replies on the request's reply inbox.
pub async fn run_tool_exec_loop(
    config: &WorkerConfig,
    _conn: redis::aio::ConnectionManager,
    nats: NatsBroker,
    status_tx: tokio::sync::watch::Sender<WorkerStatus>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let subject = nats::tool_exec_subject(&config.worker_role);
    let queue_group = format!("ares-tools-{}", config.worker_role);

    let client = nats.client().clone();
    let mut sub = client
        .queue_subscribe(subject.clone(), queue_group.clone())
        .await?;
    info!(
        subject = %subject,
        queue_group = %queue_group,
        agent = %config.agent_name,
        "Starting tool executor loop (NATS queue subscribe)"
    );

    let mut unavailable_tools: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        let next = tokio::select! {
            m = sub.next() => m,
            _ = shutdown.notified() => {
                info!("Tool executor: shutdown signalled, finishing");
                return Ok(());
            }
        };

        let msg = match next {
            Some(m) => m,
            None => {
                warn!("Tool executor: subscription closed, exiting");
                return Ok(());
            }
        };

        let request: ToolExecRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!(err = %e, "Bad ToolExecRequest payload, skipping");
                continue;
            }
        };

        let _ = status_tx.send(WorkerStatus {
            status: "busy".to_string(),
            current_task: Some(format!("{}:{}", request.tool_name, request.call_id)),
        });

        let ti = extract_target_info(&request.arguments);
        let tt = infer_target_type_from_info(&ti);
        let mut span_builder = AgentSpanBuilder::new("tool_exec", &config.worker_role, Team::Red)
            .tool(&request.tool_name)
            .kind(SpanKind::Consumer);
        if let Some(ref ip) = ti.target_ip {
            span_builder = span_builder.target_ip(ip);
        }
        if let Some(ref fqdn) = ti.target_fqdn {
            span_builder = span_builder.target_fqdn(fqdn);
        }
        if let Some(ref user) = ti.target_user {
            span_builder = span_builder.target_user(user);
        }
        if let Some(target_type) = tt {
            span_builder = span_builder.target_type(target_type);
        }
        if let Some(ref op) = request.operation_id {
            span_builder = span_builder.operation_id(op);
        }
        let exec_span = span_builder.build();
        if let Some(ref tp) = request.traceparent {
            set_span_parent(&exec_span, tp);
        }

        let reply_to = msg.reply.clone();
        let client_for_reply = client.clone();

        execute_and_respond(client_for_reply, reply_to, &request, &mut unavailable_tools)
            .instrument(exec_span)
            .await;

        let _ = status_tx.send(WorkerStatus {
            status: "idle".to_string(),
            current_task: None,
        });
    }
}

/// Execute a tool call and reply on the NATS inbox.
async fn execute_and_respond(
    client: async_nats::Client,
    reply_to: Option<async_nats::Subject>,
    request: &ToolExecRequest,
    unavailable_tools: &mut std::collections::HashSet<String>,
) {
    if unavailable_tools.contains(&request.tool_name) {
        debug!(
            tool = %request.tool_name,
            call_id = %request.call_id,
            "Skipping unavailable tool (previously failed to spawn)"
        );
        let response = ToolExecResponse {
            call_id: request.call_id.clone(),
            output: String::new(),
            error: Some(format!(
                "Tool '{}' is not installed on this worker. \
                 Do not call this tool again — it failed to spawn previously.",
                request.tool_name
            )),
            discoveries: None,
        };
        send_reply(&client, reply_to.as_ref(), &response).await;
        return;
    }

    info!(
        tool = %request.tool_name,
        call_id = %request.call_id,
        task_id = %request.task_id,
        "Executing tool"
    );

    let di = extract_target_info(&request.arguments);
    let dt = infer_target_type_from_info(&di);

    let response = match ares_tools::dispatch(&request.tool_name, &request.arguments).await {
        Ok(output) => {
            let raw = output.combined_raw();
            let combined = output.combined();
            let error = if output.success {
                None
            } else {
                Some(format!("tool exited with code {:?}", output.exit_code))
            };

            let discoveries = ares_tools::parsers::parse_tool_output(
                &request.tool_name,
                &raw,
                &request.arguments,
            );
            let discoveries = if discoveries.as_object().is_none_or(|o| o.is_empty()) {
                None
            } else {
                Some(discoveries)
            };

            if let Some(ref disc) = discoveries {
                if let Some(obj) = disc.as_object() {
                    for (disc_type, items) in obj {
                        let count = items.as_array().map(|a| a.len()).unwrap_or(0);
                        if count > 0 {
                            let span = trace_discovery(
                                disc_type,
                                &request.tool_name,
                                di.target_user.as_deref(),
                                None,
                                di.target_ip.as_deref(),
                                di.target_fqdn.as_deref(),
                                dt,
                                request.operation_id.as_deref(),
                            );
                            let _guard = span.enter();
                        }
                    }
                }
            }

            ToolExecResponse {
                call_id: request.call_id.clone(),
                output: combined,
                error,
                discoveries,
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("failed to spawn") || err_str.contains("not installed") {
                warn!(
                    tool = %request.tool_name,
                    "Tool binary not found — marking as unavailable for this session"
                );
                unavailable_tools.insert(request.tool_name.clone());
            }
            warn!(
                tool = %request.tool_name,
                call_id = %request.call_id,
                err = %e,
                "Tool execution failed"
            );
            ToolExecResponse {
                call_id: request.call_id.clone(),
                output: String::new(),
                error: Some(err_str),
                discoveries: None,
            }
        }
    };

    debug!(
        tool = %request.tool_name,
        call_id = %request.call_id,
        has_error = response.error.is_some(),
        "Tool result ready"
    );
    send_reply(&client, reply_to.as_ref(), &response).await;
}

async fn send_reply(
    client: &async_nats::Client,
    reply_to: Option<&async_nats::Subject>,
    response: &ToolExecResponse,
) {
    let Some(reply) = reply_to else {
        warn!(call_id = %response.call_id, "No reply subject — orchestrator will time out");
        return;
    };
    match serde_json::to_vec(response) {
        Ok(bytes) => {
            if let Err(e) = client.publish(reply.clone(), Bytes::from(bytes)).await {
                error!(call_id = %response.call_id, "Failed to publish reply: {e}");
            }
        }
        Err(e) => {
            error!(call_id = %response.call_id, "Failed to serialize reply: {e}");
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_exec_request_deserialize() {
        let json = r#"{
            "call_id": "nmap_scan_abc123",
            "task_id": "recon_def456",
            "tool_name": "nmap_scan",
            "arguments": {"target": "192.168.58.0/24"}
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.call_id, "nmap_scan_abc123");
        assert_eq!(req.tool_name, "nmap_scan");
        assert_eq!(req.task_id, "recon_def456");
    }

    #[test]
    fn tool_exec_response_serialize() {
        let resp = ToolExecResponse {
            call_id: "nmap_scan_abc123".into(),
            output: "Found 5 hosts".into(),
            error: None,
            discoveries: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("nmap_scan_abc123"));
        assert!(json.contains("Found 5 hosts"));
        // discoveries omitted when None
        assert!(!json.contains("discoveries"));
    }

    #[test]
    fn tool_exec_response_with_error() {
        let resp = ToolExecResponse {
            call_id: "x".into(),
            output: String::new(),
            error: Some("Connection refused".into()),
            discoveries: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"], "Connection refused");
    }

    #[test]
    fn tool_exec_response_with_discoveries() {
        let resp = ToolExecResponse {
            call_id: "nmap_abc".into(),
            output: "scan output".into(),
            error: None,
            discoveries: Some(serde_json::json!({
                "hosts": [{"ip": "192.168.58.10", "services": ["445/tcp"]}]
            })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("discoveries"));
        assert!(json.contains("192.168.58.10"));
    }

    #[test]
    fn tool_exec_request_deserialize_with_traceparent() {
        let json = r#"{
            "call_id": "secretsdump_001",
            "task_id": "task_abc",
            "tool_name": "secretsdump",
            "arguments": {"target": "192.168.58.10", "domain": "contoso.local"},
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.call_id, "secretsdump_001");
        assert_eq!(req.tool_name, "secretsdump");
        assert_eq!(
            req.traceparent.as_deref(),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn tool_exec_request_deserialize_with_operation_id() {
        let json = r#"{
            "call_id": "nmap_002",
            "task_id": "recon_task",
            "tool_name": "nmap_scan",
            "arguments": {"target": "192.168.58.0/24"},
            "operation_id": "op-20260422-abc123"
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operation_id.as_deref(), Some("op-20260422-abc123"));
    }

    #[test]
    fn tool_exec_request_defaults_for_optional_fields() {
        let json = r#"{
            "call_id": "basic_001",
            "task_id": "task_001",
            "tool_name": "whoami",
            "arguments": {}
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert!(req.traceparent.is_none());
        assert!(req.operation_id.is_none());
    }

    #[test]
    fn tool_exec_request_complex_arguments() {
        let json = r#"{
            "call_id": "netexec_003",
            "task_id": "lateral_task",
            "tool_name": "netexec_smb",
            "arguments": {
                "target": "192.168.58.10",
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
                "shares": true,
                "port": 445
            }
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tool_name, "netexec_smb");
        assert_eq!(req.arguments["target"], "192.168.58.10");
        assert_eq!(req.arguments["domain"], "contoso.local");
        assert_eq!(req.arguments["shares"], true);
        assert_eq!(req.arguments["port"], 445);
    }

    #[test]
    fn tool_exec_response_empty_discoveries_omitted() {
        let resp = ToolExecResponse {
            call_id: "test_001".into(),
            output: "some output".into(),
            error: None,
            discoveries: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("discoveries"));
    }

    #[test]
    fn tool_exec_response_with_multiple_discovery_types() {
        let resp = ToolExecResponse {
            call_id: "nmap_004".into(),
            output: "scan output".into(),
            error: None,
            discoveries: Some(serde_json::json!({
                "hosts": [
                    {"ip": "192.168.58.10", "hostname": "dc01.contoso.local", "services": ["445/tcp", "88/tcp"]},
                    {"ip": "192.168.58.11", "hostname": "sql01.contoso.local", "services": ["1433/tcp"]}
                ],
                "services": [
                    {"port": 445, "protocol": "tcp", "service": "microsoft-ds"}
                ]
            })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let hosts = parsed["discoveries"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[1]["hostname"], "sql01.contoso.local");
    }

    #[test]
    fn tool_exec_response_serialization_roundtrip() {
        let resp = ToolExecResponse {
            call_id: "roundtrip_test".into(),
            output: "output with special chars: <>&\"'".into(),
            error: Some("exit code 1".into()),
            discoveries: Some(serde_json::json!({"credentials": []})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["call_id"], "roundtrip_test");
        assert_eq!(parsed["error"], "exit code 1");
        assert!(parsed["discoveries"]["credentials"].is_array());
    }

    #[test]
    fn tool_exec_response_error_message_format() {
        // Verify the format used in execute_and_respond for unavailable tools
        let tool_name = "nonexistent_tool";
        let error_msg = format!(
            "Tool '{}' is not installed on this worker. \
             Do not call this tool again — it failed to spawn previously.",
            tool_name
        );
        assert!(error_msg.contains("nonexistent_tool"));
        assert!(error_msg.contains("not installed"));
    }

    #[test]
    fn nats_subject_format() {
        let role = "recon";
        let subj = nats::tool_exec_subject(role);
        assert_eq!(subj, "ares.tools.exec.recon");
    }

    #[test]
    fn unavailable_tool_detection_keywords() {
        // Verify the keywords used to detect unavailable tools
        let test_errors = [
            ("failed to spawn 'nmap' — is it installed?", true),
            ("tool not installed: certipy", true),
            ("command not found", false),
            ("permission denied", false),
        ];

        for (err_str, expected_unavailable) in test_errors {
            let is_unavailable =
                err_str.contains("failed to spawn") || err_str.contains("not installed");
            assert_eq!(
                is_unavailable,
                expected_unavailable,
                "Error '{}' should {}mark tool as unavailable",
                err_str,
                if expected_unavailable { "" } else { "NOT " }
            );
        }
    }

    #[test]
    fn tool_exec_request_deserialize_rejects_missing_required() {
        // Missing call_id should fail
        let json = r#"{
            "task_id": "task_001",
            "tool_name": "nmap",
            "arguments": {}
        }"#;
        let result: Result<ToolExecRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn tool_exec_request_deserialize_rejects_missing_tool_name() {
        let json = r#"{
            "call_id": "call_001",
            "task_id": "task_001",
            "arguments": {}
        }"#;
        let result: Result<ToolExecRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
