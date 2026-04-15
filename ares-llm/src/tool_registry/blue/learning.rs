//! MITRE ATT&CK learning and detection recipe tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn learning_tool_definitions() -> Vec<ToolDefinition> {
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
        ToolDefinition {
            name: "find_similar_investigations".into(),
            description: "Find similar past investigations to learn from. Returns historical investigation outcomes, effective queries, and guidance.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "alert_name": {
                        "type": "string",
                        "description": "Alert name to search for"
                    },
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE technique ID to match"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity level to match"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 5)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "get_effective_queries".into(),
            description: "Get historically effective detection queries ranked by evidence production rate.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "alert_name": {
                        "type": "string",
                        "description": "Filter by alert type"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 10)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "check_false_positive_pattern".into(),
            description: "Check if an alert matches known false positive patterns from historical investigations.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "alert_name": {
                        "type": "string",
                        "description": "Alert name to check"
                    },
                    "alert_fingerprint": {
                        "type": "string",
                        "description": "Alert fingerprint for precise matching"
                    }
                },
                "required": ["alert_name"]
            }),
        },
        ToolDefinition {
            name: "get_investigation_statistics".into(),
            description: "Get aggregate statistics across all past investigations including completion rates, TP/FP rates, and averages.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "generate_mitre_questions".into(),
            description: "Generate MITRE ATT&CK-based investigative questions from identified techniques. Uses attack chain precursors, detection recipes, and follow-on technique analysis.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID to load techniques from"
                    },
                    "max_questions": {
                        "type": "integer",
                        "description": "Maximum questions to return (default: 10)"
                    }
                },
                "required": ["investigation_id"]
            }),
        },
        ToolDefinition {
            name: "generate_pyramid_questions".into(),
            description: "Generate Pyramid of Pain climbing questions from current evidence. Suggests how to elevate lower-level indicators (hashes, IPs) to higher-level insights (tools, TTPs).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID to load evidence from"
                    },
                    "max_questions": {
                        "type": "integer",
                        "description": "Maximum questions to return (default: 10)"
                    }
                },
                "required": ["investigation_id"]
            }),
        },
        ToolDefinition {
            name: "assess_pyramid_state".into(),
            description: "Assess current Pyramid of Pain state for an investigation. Returns evidence distribution, elevation score (0-1), and recommendations.".into(),
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
            name: "get_combined_questions".into(),
            description: "Get combined questions from both MITRE and Pyramid engines, sorted by priority score. Most effective way to get next investigation steps.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "Investigation ID"
                    },
                    "max_questions": {
                        "type": "integer",
                        "description": "Maximum questions to return (default: 10)"
                    }
                },
                "required": ["investigation_id"]
            }),
        },
        ToolDefinition {
            name: "get_attack_chain_precursors".into(),
            description: "Get attack chain data for a MITRE technique including precursors, Windows events, log patterns, and investigation questions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID (e.g., 'T1003.006')"
                    }
                },
                "required": ["technique_id"]
            }),
        },
        ToolDefinition {
            name: "get_detection_recipe".into(),
            description: "Get a detection recipe by name with indicators, Windows events, LogQL queries, and investigation steps.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "recipe_name": {
                        "type": "string",
                        "description": "Recipe name (e.g., 'dcsync', 'password_spray', 'kerberos_attacks')"
                    }
                },
                "required": ["recipe_name"]
            }),
        },
        ToolDefinition {
            name: "list_detection_recipes".into(),
            description: "List all available detection recipes with their names, MITRE mappings, and descriptions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "get_attack_playbook".into(),
            description: "Get detection playbook based on active red team operations. Reads real-time red team state from Redis to generate prioritized detection queries.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string",
                        "description": "Red team operation ID. If omitted, finds the latest running operation."
                    }
                }
            }),
        },
        ToolDefinition {
            name: "get_detection_queries_for_technique".into(),
            description: "Get specific detection queries for a MITRE ATT&CK technique, enriched with context from active red team operations.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID (e.g., 'T1003.006', 'T1558.003')"
                    },
                    "operation_id": {
                        "type": "string",
                        "description": "Red team operation ID for context enrichment"
                    }
                },
                "required": ["technique_id"]
            }),
        },
    ]
}
