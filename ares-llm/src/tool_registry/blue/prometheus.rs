//! Prometheus tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn prometheus_tool_definitions() -> Vec<ToolDefinition> {
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
        ToolDefinition {
            name: "get_metric_names".into(),
            description: "Get available Prometheus metric names with optional search filter."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Optional case-insensitive search filter for metric names"
                    }
                }
            }),
        },
    ]
}
