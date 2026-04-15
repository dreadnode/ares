//! Universal reporting tool definitions.
//!
//! These tools are available to ALL agent roles, providing a shared interface
//! for recording credentials, vulnerabilities, compromised hosts, and timeline
//! events during an operation.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // NOTE: record_credential removed — credentials come only from tool output parsing.
        // NOTE: record_timeline_event removed — timeline events are auto-generated from
        //       state changes in result_processing.rs (credential/hash/host discoveries).
        // NOTE: record_compromised_host is log-only (no state write), kept as a signal.
        ToolDefinition {
            name: "record_compromised_host".into(),
            description:
                "Record a host that has been compromised or accessed during the operation. \
                Tracks the scope of compromise and available pivot points for lateral movement."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address of the compromised host"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Hostname or FQDN of the compromised host (e.g. 'dc01.contoso.local')"
                    },
                    "os": {
                        "type": "string",
                        "description": "Operating system of the host (e.g. 'Windows Server 2019', 'Windows 10 Enterprise')"
                    },
                    "access_level": {
                        "type": "string",
                        "description": "Level of access obtained (e.g. 'SYSTEM', 'local admin', 'domain user', 'service account')"
                    },
                    "notes": {
                        "type": "string",
                        "description": "Additional notes about the compromise (e.g. method used, services running, useful files found)"
                    }
                },
                "required": ["ip"]
            }),
        },
        ToolDefinition {
            name: "list_credentials".into(),
            description: "List all credentials that have been recorded during the operation. \
                Returns usernames, domains, credential types, admin status, and sources \
                for every collected credential."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_operation_summary".into(),
            description: "Get a high-level summary of the current operation status. \
                Includes counts of compromised hosts, collected credentials, discovered \
                vulnerabilities, active agents, and pending tasks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
    ]
}
