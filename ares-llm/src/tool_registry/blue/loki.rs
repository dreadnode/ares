//! Loki / observability tool definitions (shared across worker roles).

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn loki_tool_definitions() -> Vec<ToolDefinition> {
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
            description: "Query logs in a window around a single timestamp. For multiple queries at once, use execute_parallel_queries instead — it runs up to 10 queries concurrently in one call.".into(),
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
            description: "Execute up to 10 LogQL queries in parallel and return combined results. PREFERRED over calling query_loki_logs or query_logs_around_timestamp multiple times — batch your queries here to get all results in one call.".into(),
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
        ToolDefinition {
            name: "query_logs_recent".into(),
            description: "Query logs relative to NOW. Convenience wrapper for investigating stale or ongoing alerts without computing time ranges.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "logql": {
                        "type": "string",
                        "description": "LogQL query string"
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours back from now to search (default: 1)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum log entries (default: 100)"
                    }
                },
                "required": ["logql"]
            }),
        },
        ToolDefinition {
            name: "combine_query_patterns".into(),
            description: "Combine multiple regex patterns into a single LogQL filter using regex alternation. Returns a combined query ready for execution.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "base_selector": {
                        "type": "string",
                        "description": "Base LogQL log selector (e.g., '{job=\"windows\"}')"
                    },
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of patterns to combine with regex OR"
                    }
                },
                "required": ["base_selector", "patterns"]
            }),
        },
    ]
}
