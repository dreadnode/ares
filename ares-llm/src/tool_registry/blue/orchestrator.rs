//! Orchestrator tool definitions for the blue team orchestrator role.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn orchestrator_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "dispatch_triage".into(),
            description: "Dispatch a triage task to assess the alert.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "wait_for_result": {
                        "type": "boolean",
                        "description": "Whether to wait for the result (default: false)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "dispatch_threat_hunt".into(),
            description: "Dispatch a threat hunting task for a specific technique.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID to hunt for"
                    },
                    "detection_method": {
                        "type": "string",
                        "description": "Detection method to use"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Target hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Target username"
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context"
                    },
                    "wait_for_result": {
                        "type": "boolean",
                        "description": "Whether to wait for the result"
                    }
                },
                "required": ["technique_id", "detection_method"]
            }),
        },
        ToolDefinition {
            name: "dispatch_lateral_analysis".into(),
            description: "Dispatch a lateral movement analysis task.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "focus_host": {
                        "type": "string",
                        "description": "Primary host to analyze"
                    },
                    "focus_user": {
                        "type": "string",
                        "description": "Primary user to analyze"
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context"
                    },
                    "wait_for_result": {
                        "type": "boolean",
                        "description": "Whether to wait for the result"
                    }
                },
                "required": ["focus_host"]
            }),
        },
        ToolDefinition {
            name: "get_investigation_status".into(),
            description:
                "Get the current investigation summary including evidence and task status.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "get_task_result".into(),
            description: "Get the result of a previously dispatched task.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "Task ID to get results for"
                    }
                },
                "required": ["task_id"]
            }),
        },
        ToolDefinition {
            name: "wait_for_all_tasks".into(),
            description: "Wait for all pending tasks to complete.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "complete_investigation".into(),
            description: "Complete the investigation with a summary and recommendations.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Investigation summary"
                    },
                    "attack_synopsis": {
                        "type": "string",
                        "description": "Synopsis of the attack if confirmed"
                    },
                    "recommendations": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Remediation and detection recommendations"
                    }
                },
                "required": ["summary"]
            }),
        },
        ToolDefinition {
            name: "escalate_investigation".into(),
            description: "Escalate the investigation for immediate human intervention.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Reason for escalation"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium"],
                        "description": "Escalation severity"
                    },
                    "attack_synopsis": {
                        "type": "string",
                        "description": "Synopsis of confirmed attack activity"
                    },
                    "recommendations": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Immediate action recommendations"
                    }
                },
                "required": ["reason", "severity"]
            }),
        },
    ]
}
