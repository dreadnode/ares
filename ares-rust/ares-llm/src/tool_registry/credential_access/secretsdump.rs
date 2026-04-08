//! Secretsdump tool definition.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![ToolDefinition {
        name: "secretsdump".into(),
        description: "Dump secrets from a target machine including SAM hashes, NTDS.dit credentials, LSA secrets, and cached domain credentials via DRSUAPI or registry extraction.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname"
                },
                "username": {
                    "type": "string",
                    "description": "Username for authentication"
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication"
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash authentication (LM:NT format)"
                },
                "domain": {
                    "type": "string",
                    "description": "Domain name for authentication"
                },
                "dc_ip": {
                    "type": "string",
                    "description": "Domain controller IP (used for DRSUAPI replication)"
                },
                "no_pass": {
                    "type": "boolean",
                    "description": "Attempt authentication with no password"
                },
                "ticket_path": {
                    "type": "string",
                    "description": "Path to Kerberos ccache ticket file for authentication"
                },
                "timeout_minutes": {
                    "type": "integer",
                    "description": "Overall operation timeout in minutes (default: 3)",
                    "default": 3
                },
                "connection_timeout": {
                    "type": "integer",
                    "description": "Connection timeout in seconds (default: 30)",
                    "default": 30
                },
                "skip_connectivity_check": {
                    "type": "boolean",
                    "description": "Skip the initial connectivity check before dumping"
                }
            },
            "required": ["target", "username"]
        }),
    }]
}
