//! Grafana tool definitions (alerts, annotations, dashboards).

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn grafana_tool_definitions() -> Vec<ToolDefinition> {
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
        ToolDefinition {
            name: "get_alert_history".into(),
            description: "Get alert rule definitions from Grafana's provisioning API. Returns all configured alert rules with their UIDs, folders, and evaluation intervals.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hours_back": {
                        "type": "integer",
                        "description": "Reserved for future use"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "get_alerts_in_time_range".into(),
            description: "Get alerts that fired within a specific time range. Queries Grafana annotations API and transforms results into normalized alert format with deduplication.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "from_time": {
                        "type": "string",
                        "description": "Start time in ISO8601 format"
                    },
                    "to_time": {
                        "type": "string",
                        "description": "End time in ISO8601 format"
                    },
                    "buffer_minutes": {
                        "type": "integer",
                        "description": "Minutes to expand the time window on each side (default: 30)"
                    }
                },
                "required": ["from_time", "to_time"]
            }),
        },
        ToolDefinition {
            name: "create_annotation".into(),
            description: "Create an annotation in Grafana to mark investigation events or findings.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Annotation text (supports markdown)"
                    },
                    "tags": {
                        "type": "string",
                        "description": "Comma-separated tags (default: 'ares,investigation')"
                    },
                    "dashboard_uid": {
                        "type": "string",
                        "description": "Scope to a specific dashboard"
                    },
                    "time_start": {
                        "type": "integer",
                        "description": "Start time as epoch milliseconds (default: now)"
                    },
                    "time_end": {
                        "type": "integer",
                        "description": "End time as epoch milliseconds"
                    }
                },
                "required": ["text"]
            }),
        },
        ToolDefinition {
            name: "create_detection_rule".into(),
            description: "Create a Grafana alert rule for automated detection. Wraps a LogQL query as a count_over_time threshold.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Alert rule name"
                    },
                    "logql_query": {
                        "type": "string",
                        "description": "LogQL query for detection (e.g., '{job=\"windows\"} |= \"4662\"')"
                    },
                    "description": {
                        "type": "string",
                        "description": "Rule description"
                    },
                    "mitre_technique": {
                        "type": "string",
                        "description": "Associated MITRE ATT&CK technique ID"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Alert severity (default: medium)"
                    },
                    "evaluation_interval": {
                        "type": "string",
                        "description": "Evaluation interval (default: '5m')"
                    },
                    "pending_period": {
                        "type": "string",
                        "description": "Pending period before firing (default: '0s')"
                    }
                },
                "required": ["title", "logql_query"]
            }),
        },
        ToolDefinition {
            name: "post_investigation_started".into(),
            description: "Post an annotation marking that an ARES investigation has started.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "alert_name": {
                        "type": "string",
                        "description": "Name of the alert being investigated"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Alert severity"
                    }
                },
                "required": ["investigation_id", "alert_name", "severity"]
            }),
        },
        ToolDefinition {
            name: "post_investigation_completed".into(),
            description: "Post an annotation marking that an ARES investigation has completed with results summary.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "alert_name": {
                        "type": "string",
                        "description": "Alert name"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["completed", "escalated", "failed"],
                        "description": "Investigation outcome"
                    },
                    "evidence_count": {
                        "type": "integer",
                        "description": "Number of evidence items found"
                    },
                    "techniques": {
                        "type": "string",
                        "description": "Comma-separated MITRE technique IDs"
                    },
                    "pyramid_level": {
                        "type": "integer",
                        "description": "Highest Pyramid of Pain level reached"
                    },
                    "summary": {
                        "type": "string",
                        "description": "Investigation summary (max 500 chars)"
                    }
                },
                "required": ["investigation_id", "alert_name", "status"]
            }),
        },
    ]
}
