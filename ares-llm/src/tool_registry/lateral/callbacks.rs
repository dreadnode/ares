//! Lateral movement result reporting tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "report_lateral_success".into(),
            description: "Report successful lateral movement to a new host. Records the \
                method used and any new credentials or hashes obtained during the move."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this lateral movement attempt"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "The host that was successfully accessed (IP or hostname)"
                    },
                    "method": {
                        "type": "string",
                        "description": "The lateral movement method used (e.g. psexec, wmiexec, evil_winrm)"
                    },
                    "new_credentials": {
                        "type": "string",
                        "description": "JSON array of new credentials discovered (e.g. [{\"username\": \"admin\", \"password\": \"pass\", \"domain\": \"contoso.local\"}])"
                    },
                    "new_hashes": {
                        "type": "string",
                        "description": "JSON array of new NTLM hashes discovered (e.g. [{\"username\": \"admin\", \"hash\": \"aad3b435...:31d6cfe0...\", \"domain\": \"contoso.local\"}])"
                    }
                },
                "required": ["task_id", "target_host", "method"]
            }),
        },
        ToolDefinition {
            name: "report_lateral_failed".into(),
            description: "Report a failed lateral movement attempt. Records the target, \
                reason for failure, and allows the orchestrator to retry with different \
                methods or credentials."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this lateral movement attempt"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "The host that could not be accessed (IP or hostname)"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason the lateral movement failed (e.g. access denied, port closed, authentication error)"
                    }
                },
                "required": ["task_id", "target_host", "reason"]
            }),
        },
    ]
}
