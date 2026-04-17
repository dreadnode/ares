//! Detection query tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn detection_query_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "run_detection_query".into(),
            description:
                "Run a pre-built detection query template for a specific attack technique.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query_name": {
                        "type": "string",
                        "description": "Detection template name (e.g., 'detect_kerberoasting', 'detect_secretsdump', 'detect_lateral_movement')"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Target hostname to focus the query on"
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours back to search (default: 1, max recommended: 1). Values >1 will likely timeout through the Grafana proxy. Use 1 unless you have a specific reason."
                    }
                },
                "required": ["query_name"]
            }),
        },
        ToolDefinition {
            name: "run_parallel_detections".into(),
            description: "Run multiple detection queries in parallel for faster investigation. Executes up to max_concurrent queries concurrently.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query_names": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of detection template names to run (e.g., ['detect_dcsync', 'detect_kerberoasting', 'detect_pass_the_hash'])"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Target hostname to focus all detections on"
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Hours back to search (default: 1, max recommended: 1). Values >1 will likely timeout."
                    },
                    "max_concurrent": {
                        "type": "integer",
                        "description": "Maximum concurrent queries (default: 5). Higher values are faster but may stress Loki."
                    }
                },
                "required": ["query_names"]
            }),
        },
        ToolDefinition {
            name: "list_detection_templates".into(),
            description: "List all available detection query templates with MITRE ATT&CK mappings, severity, tactic, and red team tool correlation.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "get_host_activity".into(),
            description: "Get all log activity for a specific host. Can optionally filter to only show attack-related patterns (security events).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Hostname to investigate"
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Hours of logs to search (default: 1)"
                    },
                    "attack_patterns_only": {
                        "type": "boolean",
                        "description": "If true, filter for attack-related events only (4624, 4625, 4662, 4769, etc.)"
                    }
                },
                "required": ["hostname"]
            }),
        },
        ToolDefinition {
            name: "get_user_activity".into(),
            description: "Get all log activity mentioning a specific user account. Useful for investigating compromised accounts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to investigate"
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Hours of logs to search (default: 1)"
                    }
                },
                "required": ["username"]
            }),
        },
    ]
}
