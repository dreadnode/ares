//! Investigation state mutation tool definitions (Redis-backed).

use serde_json::json;

use crate::ToolDefinition;

/// Core investigation state tools available to all worker roles.
pub(super) fn investigation_state_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "add_evidence".into(),
            description: "Add a single evidence item to the investigation. For multiple items, prefer add_evidence_batch to record them all in one call.".into(),
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
            name: "add_evidence_batch".into(),
            description: "Add multiple evidence items in a single call. Use this instead of calling add_evidence repeatedly — it records all items in one Redis pipeline round-trip and has its own separate call budget.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "items": {
                        "type": "array",
                        "description": "Array of evidence items to add (max 50 per call)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "evidence_type": {
                                    "type": "string",
                                    "enum": ["ip", "domain", "hash", "process", "user", "file", "artifact", "tool", "technique"],
                                    "description": "Type of evidence"
                                },
                                "value": {
                                    "type": "string",
                                    "description": "The evidence value"
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
                                    "description": "Pyramid of Pain level (auto-assigned if omitted)"
                                },
                                "timestamp": {
                                    "type": "string",
                                    "description": "ISO8601 timestamp (default: now)"
                                }
                            },
                            "required": ["evidence_type", "value", "source"]
                        }
                    }
                },
                "required": ["investigation_id", "items"]
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
        ToolDefinition {
            name: "transition_stage".into(),
            description: "Transition the investigation to a new stage (triage -> causation -> lateral -> synthesis).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "new_stage": {
                        "type": "string",
                        "enum": ["triage", "causation", "lateral", "synthesis"],
                        "description": "Target investigation stage"
                    }
                },
                "required": ["investigation_id", "new_stage"]
            }),
        },
        ToolDefinition {
            name: "track_host_investigation".into(),
            description: "Mark a host as investigated and track it in the investigation state.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Hostname or IP to track"
                    }
                },
                "required": ["investigation_id", "hostname"]
            }),
        },
        ToolDefinition {
            name: "track_user_investigation".into(),
            description: "Mark a user as investigated and track them in the investigation state.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to track"
                    }
                },
                "required": ["investigation_id", "username"]
            }),
        },
        ToolDefinition {
            name: "list_evidence".into(),
            description: "List all evidence items grouped by Pyramid of Pain level. Optionally filter to a specific level.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "pyramid_level": {
                        "type": "integer",
                        "description": "Filter to specific pyramid level (1=hashes, 2=IPs, 3=domains, 4=artifacts, 5=tools, 6=TTPs)"
                    }
                },
                "required": ["investigation_id"]
            }),
        },
        ToolDefinition {
            name: "get_investigation_context".into(),
            description: "Get full investigation context for escalation triage. Returns evidence, timeline, techniques with implied capabilities, hosts, users, and lateral connections.".into(),
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
            name: "pop_all_queued".into(),
            description: "Pop all queued pivot and chain queries, deduplicated and ready for execution. Drains both queues atomically.".into(),
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
            name: "get_suggested_evidence".into(),
            description: "Get auto-extracted IOCs (IPs, hostnames, users, hashes) from recent query results. No parameters required — reads from the in-memory query result store.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "analyze_lateral_movement".into(),
            description: "Analyze lateral movement connections for an investigation. Builds a connection graph, computes attack paths via DFS from entry points, and suggests pivots for uninvestigated hosts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "focus_host": {
                        "type": "string",
                        "description": "Optional host to focus analysis on"
                    }
                },
                "required": ["investigation_id"]
            }),
        },
        ToolDefinition {
            name: "get_correlated_alerts".into(),
            description: "Get correlated alerts for an investigation. Returns related alerts, common hosts/users, and shared MITRE techniques from the investigation's correlation context.".into(),
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
            name: "get_queued_queries".into(),
            description: "Get queued investigation queries (pivot and chaining queues). Shows pending and executed queries to avoid duplicate work.".into(),
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
            name: "get_formatted_summary".into(),
            description: "Get a rate-limited formatted investigation summary with Pyramid of Pain progress, milestone checklist, and key metrics. Rate-limited to once per 30 seconds.".into(),
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
pub(super) fn lateral_connection_tool_definition() -> ToolDefinition {
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
