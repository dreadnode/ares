//! Callback tool definitions for worker completion signaling and escalation triage.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn worker_callback_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "triage_complete".into(),
            description: "Signal that triage is complete with assessment results.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Triage summary"
                    },
                    "severity_assessment": {
                        "type": "string",
                        "description": "Severity assessment (critical, high, medium, low)"
                    },
                    "initial_techniques": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "MITRE technique IDs identified"
                    },
                    "recommended_next_steps": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Recommended follow-up actions"
                    },
                    "needs_deep_investigation": {
                        "type": "boolean",
                        "description": "Whether deep investigation is recommended"
                    }
                },
                "required": ["summary", "severity_assessment"]
            }),
        },
        ToolDefinition {
            name: "hunt_complete".into(),
            description: "Signal that threat hunting is complete with findings.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "findings_summary": {
                        "type": "string",
                        "description": "Summary of threat hunting findings"
                    },
                    "techniques_found": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "MITRE techniques confirmed"
                    },
                    "evidence_highlights": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Key evidence found"
                    },
                    "detection_gaps": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Detection gaps identified"
                    },
                    "recommended_pivots": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Recommended investigation pivots"
                    }
                },
                "required": ["findings_summary"]
            }),
        },
        ToolDefinition {
            name: "lateral_complete".into(),
            description: "Signal that lateral movement analysis is complete.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope_summary": {
                        "type": "string",
                        "description": "Summary of lateral movement scope"
                    },
                    "hosts_investigated": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Hosts that were investigated"
                    },
                    "users_investigated": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Users that were investigated"
                    },
                    "lateral_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Identified lateral movement paths"
                    },
                    "containment_recommendations": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Containment recommendations"
                    }
                },
                "required": ["scope_summary"]
            }),
        },
    ]
}

pub(super) fn escalation_triage_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "get_investigation_context".into(),
            description: "Get the full investigation context for triage evaluation.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    }
                },
                "required": ["investigation_id"]
            }),
        },
        ToolDefinition {
            name: "confirm_escalation".into(),
            description: "Confirm the escalation — keep it for human review.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "Why escalation is confirmed"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium"],
                        "description": "Confirmed severity"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence in this decision (0.0-1.0)"
                    }
                },
                "required": ["reasoning", "severity", "confidence"]
            }),
        },
        ToolDefinition {
            name: "downgrade_escalation".into(),
            description: "Downgrade the escalation — mark as false positive or low severity."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "Why the escalation is being downgraded"
                    },
                    "is_false_positive": {
                        "type": "boolean",
                        "description": "Whether this is a false positive"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence in this decision (0.0-1.0)"
                    }
                },
                "required": ["reasoning", "confidence"]
            }),
        },
        ToolDefinition {
            name: "request_reinvestigation".into(),
            description: "Request additional investigation before making a triage decision.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "Why more investigation is needed"
                    },
                    "focus_areas": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Areas to focus reinvestigation on"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence that reinvestigation will be productive (0.0-1.0)"
                    }
                },
                "required": ["reasoning", "focus_areas", "confidence"]
            }),
        },
        ToolDefinition {
            name: "route_to_team".into(),
            description: "Route the investigation to a specialist team.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "Why routing is needed"
                    },
                    "team": {
                        "type": "string",
                        "enum": ["incident_response", "threat_intel", "forensics", "legal", "infrastructure"],
                        "description": "Target team"
                    },
                    "action": {
                        "type": "string",
                        "description": "Recommended action for the team"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence in routing decision (0.0-1.0)"
                    }
                },
                "required": ["reasoning", "team", "confidence"]
            }),
        },
    ]
}
