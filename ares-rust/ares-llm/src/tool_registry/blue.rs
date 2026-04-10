//! Blue team tool definitions for investigation agents.
//!
//! Provides tool schemas for Loki log queries, evidence recording,
//! investigation state management, and agent callbacks.

use serde_json::json;

use crate::ToolDefinition;

/// Blue team agent roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlueAgentRole {
    /// Orchestrator coordinating multi-agent investigation
    Orchestrator,
    /// Initial alert triage
    Triage,
    /// Deep investigation using log analysis
    ThreatHunter,
    /// Lateral movement analysis
    LateralAnalyst,
    /// Escalation triage evaluation
    EscalationTriage,
}

impl BlueAgentRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Orchestrator => "blue_orchestrator",
            Self::Triage => "triage",
            Self::ThreatHunter => "threat_hunter",
            Self::LateralAnalyst => "lateral_analyst",
            Self::EscalationTriage => "escalation_triage",
        }
    }
}

/// Names of blue team callback tools handled in Rust (not dispatched to workers).
pub const BLUE_CALLBACK_TOOLS: &[&str] = &[
    "triage_complete",
    "hunt_complete",
    "lateral_complete",
    "complete_investigation",
    "escalate_investigation",
    "confirm_escalation",
    "downgrade_escalation",
    "request_reinvestigation",
    "route_to_team",
];

/// Check if a tool name is a blue team callback.
pub fn is_blue_callback_tool(name: &str) -> bool {
    BLUE_CALLBACK_TOOLS.contains(&name)
}

/// Get tool definitions for a blue team agent role.
pub fn blue_tools_for_role(role: BlueAgentRole) -> Vec<ToolDefinition> {
    let mut tools = match role {
        BlueAgentRole::Orchestrator => orchestrator_tool_definitions(),
        BlueAgentRole::Triage => triage_tool_definitions(),
        BlueAgentRole::ThreatHunter => threat_hunter_tool_definitions(),
        BlueAgentRole::LateralAnalyst => lateral_analyst_tool_definitions(),
        BlueAgentRole::EscalationTriage => escalation_triage_tool_definitions(),
    };

    // Investigation state tools for all worker roles
    match role {
        BlueAgentRole::Triage | BlueAgentRole::ThreatHunter | BlueAgentRole::LateralAnalyst => {
            tools.extend(investigation_tool_definitions());
        }
        _ => {}
    }

    // Redis-backed investigation state mutation tools
    match role {
        BlueAgentRole::Triage
        | BlueAgentRole::ThreatHunter
        | BlueAgentRole::LateralAnalyst
        | BlueAgentRole::Orchestrator
        | BlueAgentRole::EscalationTriage => {
            tools.extend(investigation_state_tool_definitions());
        }
    }

    // Lateral connection tool only for lateral_analyst
    if role == BlueAgentRole::LateralAnalyst {
        tools.push(lateral_connection_tool_definition());
    }

    tools
}

// ---------------------------------------------------------------------------
// Loki / observability tools (shared across worker roles)
// ---------------------------------------------------------------------------

fn loki_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "query_loki_logs".into(),
            description: "Query logs from Loki using LogQL. Returns matching log entries within the specified time range.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "logql": {
                        "type": "string",
                        "description": "LogQL query string (e.g., '{job=\"windows\"} |= \"4624\"')"
                    },
                    "start_time": {
                        "type": "string",
                        "description": "Start time in ISO8601 format"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "End time in ISO8601 format"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of log entries to return (default: 100)"
                    }
                },
                "required": ["logql", "start_time", "end_time"]
            }),
        },
        ToolDefinition {
            name: "query_logs_around_timestamp".into(),
            description: "Query logs in a window around a specific timestamp. Useful for investigating events near an alert.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "logql": {
                        "type": "string",
                        "description": "LogQL query string"
                    },
                    "timestamp": {
                        "type": "string",
                        "description": "Center timestamp in ISO8601 format"
                    },
                    "window_minutes": {
                        "type": "integer",
                        "description": "Window size in minutes (default: 30)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum log entries (default: 100)"
                    }
                },
                "required": ["logql", "timestamp"]
            }),
        },
        ToolDefinition {
            name: "query_logs_progressive".into(),
            description: "Query logs with progressive time window expansion (30min -> 1h -> 6h -> 24h) until results are found.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "logql": {
                        "type": "string",
                        "description": "LogQL query string"
                    },
                    "reference_timestamp": {
                        "type": "string",
                        "description": "Reference timestamp in ISO8601 format"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum log entries (default: 100)"
                    }
                },
                "required": ["logql", "reference_timestamp"]
            }),
        },
        ToolDefinition {
            name: "get_loki_label_values".into(),
            description: "Get available values for a Loki label. Useful for discovering hosts, jobs, and other selectors.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "Label name (e.g., 'hostname', 'job', 'source')"
                    }
                },
                "required": ["label"]
            }),
        },
        ToolDefinition {
            name: "execute_parallel_queries".into(),
            description: "Execute multiple LogQL queries in parallel and return combined results. Max 10 queries.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "queries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "logql": { "type": "string" },
                                "description": { "type": "string" }
                            },
                            "required": ["logql"]
                        },
                        "description": "Array of queries to execute"
                    },
                    "start_time": {
                        "type": "string",
                        "description": "Start time in ISO8601 format"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "End time in ISO8601 format"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum entries per query (default: 50)"
                    }
                },
                "required": ["queries", "start_time", "end_time"]
            }),
        },
    ]
}

fn prometheus_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "query_prometheus".into(),
            description: "Execute a PromQL instant query against Prometheus.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "promql": {
                        "type": "string",
                        "description": "PromQL query expression"
                    },
                    "time": {
                        "type": "string",
                        "description": "Evaluation timestamp in ISO8601 format (default: now)"
                    }
                },
                "required": ["promql"]
            }),
        },
        ToolDefinition {
            name: "query_prometheus_range".into(),
            description: "Execute a PromQL range query against Prometheus.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "promql": {
                        "type": "string",
                        "description": "PromQL query expression"
                    },
                    "start_time": {
                        "type": "string",
                        "description": "Range start in ISO8601 format"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "Range end in ISO8601 format"
                    },
                    "step": {
                        "type": "string",
                        "description": "Step interval (e.g., '15s', '1m', '5m')"
                    }
                },
                "required": ["promql", "start_time", "end_time"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Detection query tools
// ---------------------------------------------------------------------------

fn detection_query_tool_definitions() -> Vec<ToolDefinition> {
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
                        "description": "How many hours back to search (default: 1). Shorter ranges are faster."
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
                        "description": "Hours back to search (default: 1)"
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

// ---------------------------------------------------------------------------
// Investigation state tools (used by worker agents)
// ---------------------------------------------------------------------------

fn investigation_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "record_evidence".into(),
            description: "Record a piece of evidence discovered during investigation.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "evidence_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash", "process", "user", "file", "artifact", "tool", "technique"],
                        "description": "Type of evidence"
                    },
                    "value": {
                        "type": "string",
                        "description": "The evidence value (IP address, hash, username, etc.)"
                    },
                    "source": {
                        "type": "string",
                        "description": "Where this evidence was found"
                    },
                    "pyramid_level": {
                        "type": "integer",
                        "description": "Pyramid of Pain level (1=hashes, 2=IPs, 3=domains, 4=artifacts, 5=tools, 6=TTPs)"
                    },
                    "mitre_techniques": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Associated MITRE ATT&CK technique IDs"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence level (0.0-1.0)"
                    }
                },
                "required": ["evidence_type", "value", "source", "pyramid_level"]
            }),
        },
        ToolDefinition {
            name: "add_timeline_event".into(),
            description: "Add an event to the investigation timeline.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "timestamp": {
                        "type": "string",
                        "description": "Event timestamp in ISO8601 format"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the event"
                    },
                    "evidence_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "IDs of related evidence items"
                    },
                    "mitre_techniques": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "MITRE ATT&CK technique IDs"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence level (0.0-1.0)"
                    }
                },
                "required": ["timestamp", "description"]
            }),
        },
        ToolDefinition {
            name: "record_lateral_connection".into(),
            description: "Record a lateral movement connection between two hosts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source_host": {
                        "type": "string",
                        "description": "Source hostname or IP"
                    },
                    "destination_host": {
                        "type": "string",
                        "description": "Destination hostname or IP"
                    },
                    "connection_type": {
                        "type": "string",
                        "description": "Type of connection (e.g., 'smb', 'wmi', 'rdp', 'winrm', 'psexec')"
                    },
                    "user": {
                        "type": "string",
                        "description": "User account used for the connection"
                    },
                    "mitre_technique": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID"
                    }
                },
                "required": ["source_host", "destination_host", "connection_type"]
            }),
        },
        ToolDefinition {
            name: "track_host_investigation".into(),
            description: "Mark a host as investigated and get suggested queries for it.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Hostname or IP to track"
                    }
                },
                "required": ["hostname"]
            }),
        },
        ToolDefinition {
            name: "track_user_investigation".into(),
            description: "Mark a user as investigated and get suggested queries for them.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to track"
                    }
                },
                "required": ["username"]
            }),
        },
        ToolDefinition {
            name: "get_investigation_summary".into(),
            description: "Get a summary of the current investigation state including evidence, techniques, and progress.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "transition_stage".into(),
            description: "Transition the investigation to a new stage (triage -> causation -> lateral -> synthesis).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "new_stage": {
                        "type": "string",
                        "enum": ["triage", "causation", "lateral", "synthesis"],
                        "description": "Target investigation stage"
                    }
                },
                "required": ["new_stage"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Callback tools for worker completion signaling
// ---------------------------------------------------------------------------

fn worker_callback_definitions() -> Vec<ToolDefinition> {
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

// ---------------------------------------------------------------------------
// Orchestrator tools
// ---------------------------------------------------------------------------

fn orchestrator_tool_definitions() -> Vec<ToolDefinition> {
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

// ---------------------------------------------------------------------------
// Escalation triage tools
// ---------------------------------------------------------------------------

fn escalation_triage_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "get_investigation_context".into(),
            description: "Get the full investigation context for triage evaluation.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
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

// ---------------------------------------------------------------------------
// Grafana tools (alerts, annotations, dashboards)
// ---------------------------------------------------------------------------

fn grafana_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "get_grafana_alerts".into(),
            description: "Get alerts from Grafana. Tries multiple API endpoints for compatibility across Grafana versions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "state": {
                        "type": "string",
                        "description": "Filter by alert state (e.g., 'firing', 'pending', 'inactive')"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "get_grafana_annotations".into(),
            description: "Get annotations from Grafana with optional time range and tag filters. Useful for reviewing alert history and investigation markers.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "from": {
                        "type": "string",
                        "description": "Start time as epoch milliseconds or ISO8601 string"
                    },
                    "to": {
                        "type": "string",
                        "description": "End time as epoch milliseconds or ISO8601 string"
                    },
                    "tags": {
                        "type": "string",
                        "description": "Comma-separated tag filter (e.g., 'ares,investigation')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum annotations to return (default: 100)"
                    },
                    "type": {
                        "type": "string",
                        "description": "Annotation type filter (e.g., 'alert')"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "search_grafana_dashboards".into(),
            description: "Search for dashboards in Grafana by query string or tag.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query string"
                    },
                    "tag": {
                        "type": "string",
                        "description": "Filter dashboards by tag"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 50)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "get_grafana_dashboard".into(),
            description: "Get a specific Grafana dashboard by its UID, including panel details and metadata.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {
                        "type": "string",
                        "description": "Dashboard UID"
                    }
                },
                "required": ["uid"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Investigation state mutation tools (Redis-backed, require investigation_id)
// ---------------------------------------------------------------------------

/// Core investigation state tools available to all worker roles.
fn investigation_state_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "add_evidence".into(),
            description: "Add evidence to the investigation state. Uses Redis HSETNX for deduplication.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "evidence_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash", "process", "user", "file", "artifact", "tool", "technique"],
                        "description": "Type of evidence"
                    },
                    "value": {
                        "type": "string",
                        "description": "The evidence value (IP address, hash, username, etc.)"
                    },
                    "source": {
                        "type": "string",
                        "description": "Where this evidence was found"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence level (0.0-1.0, default: 0.5)"
                    },
                    "pyramid_level": {
                        "type": "string",
                        "enum": ["hash_values", "ip_addresses", "domain_names", "network_host_artifacts", "tools", "ttps"],
                        "description": "Pyramid of Pain level (default: ip_addresses)"
                    },
                    "timestamp": {
                        "type": "string",
                        "description": "Evidence timestamp in ISO8601 format (default: now)"
                    }
                },
                "required": ["investigation_id", "evidence_type", "value", "source"]
            }),
        },
        ToolDefinition {
            name: "record_timeline_event".into(),
            description: "Add a timeline event to the investigation. Events are appended to a Redis LIST.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the event"
                    },
                    "timestamp": {
                        "type": "string",
                        "description": "Event timestamp in ISO8601 format"
                    },
                    "mitre_techniques": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "MITRE ATT&CK technique IDs associated with this event"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence level (0.0-1.0, default: 0.5)"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source of this event (default: agent)"
                    },
                    "evidence_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "IDs of related evidence items"
                    }
                },
                "required": ["investigation_id", "description", "timestamp"]
            }),
        },
        ToolDefinition {
            name: "add_technique".into(),
            description: "Record a MITRE ATT&CK technique observed during investigation. Stored in a Redis SET for deduplication.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID (e.g., T1003.001)"
                    },
                    "technique_name": {
                        "type": "string",
                        "description": "Human-readable technique name"
                    }
                },
                "required": ["investigation_id", "technique_id"]
            }),
        },
        ToolDefinition {
            name: "get_investigation_summary".into(),
            description: "Read the current investigation state from Redis and return a formatted summary including evidence count, timeline, techniques, hosts, and users.".into(),
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
    ]
}

/// Lateral movement connection tool (only for lateral_analyst role).
fn lateral_connection_tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "add_lateral_connection".into(),
        description: "Record a lateral movement connection between two hosts. Automatically tracks both hosts and the user.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "investigation_id": {
                    "type": "string",
                    "description": "Investigation ID"
                },
                "source_host": {
                    "type": "string",
                    "description": "Source hostname or IP"
                },
                "destination_host": {
                    "type": "string",
                    "description": "Destination hostname or IP"
                },
                "method": {
                    "type": "string",
                    "description": "Lateral movement method (e.g., 'smb', 'wmi', 'rdp', 'winrm', 'psexec')"
                },
                "timestamp": {
                    "type": "string",
                    "description": "Connection timestamp in ISO8601 format (default: now)"
                },
                "user": {
                    "type": "string",
                    "description": "User account used for the connection"
                }
            },
            "required": ["investigation_id", "source_host", "destination_host"]
        }),
    }
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK learning tools (available to all roles)
// ---------------------------------------------------------------------------

fn learning_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "lookup_technique".into(),
            description: "Look up a MITRE ATT&CK technique by ID. Returns the technique name, description, associated tactics, and detection recommendations.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID (e.g., 'T1003', 'T1059.001', 'T1558.003')"
                    }
                },
                "required": ["technique_id"]
            }),
        },
        ToolDefinition {
            name: "suggest_techniques".into(),
            description: "Suggest relevant MITRE ATT&CK techniques based on an evidence type or attack category. Returns technique IDs with descriptions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "evidence_type": {
                        "type": "string",
                        "description": "Evidence category (e.g., 'credential_access', 'lateral_movement', 'persistence', 'discovery', 'execution', 'privilege_escalation', 'defense_evasion', 'kerberos', 'brute_force', 'pass_the_hash', 'dcsync', 'golden_ticket')"
                    }
                },
                "required": ["evidence_type"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Role-specific tool sets
// ---------------------------------------------------------------------------

fn triage_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki_tool_definitions();
    tools.extend(grafana_tool_definitions());
    tools.extend(learning_tool_definitions());
    tools.extend(worker_callback_definitions());
    tools
}

fn threat_hunter_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki_tool_definitions();
    tools.extend(prometheus_tool_definitions());
    tools.extend(grafana_tool_definitions());
    tools.extend(detection_query_tool_definitions());
    tools.extend(learning_tool_definitions());
    tools.extend(worker_callback_definitions());
    tools
}

fn lateral_analyst_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki_tool_definitions();
    tools.extend(grafana_tool_definitions());
    tools.extend(detection_query_tool_definitions());
    tools.extend(learning_tool_definitions());
    tools.extend(worker_callback_definitions());
    tools
}
