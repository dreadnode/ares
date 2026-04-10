//! Blue team HTTP-based tools for log analysis and observability.
//!
//! Unlike red team tools which wrap CLI commands, blue team tools make
//! HTTP requests to Loki, Prometheus, and Grafana APIs.

pub mod detection;
pub mod grafana;
pub mod investigation;
pub mod learning;
pub mod loki;
pub mod prometheus;
pub mod validation;

use anyhow::Result;
use serde_json::Value;

use crate::ToolOutput;

/// Dispatch a blue team tool call by name.
///
/// Blue team tools use HTTP APIs (Loki, Prometheus, Grafana) rather than
/// CLI subprocesses. They require `LOKI_URL`, `PROMETHEUS_URL`, and/or
/// `GRAFANA_URL` environment variables.
pub async fn dispatch_blue(tool_name: &str, arguments: &Value) -> Result<ToolOutput> {
    match tool_name {
        // ── Loki log queries ──────────────────────────────────────
        "query_loki_logs" => loki::query_logs(arguments).await,
        "query_logs_around_timestamp" => loki::query_logs_around_timestamp(arguments).await,
        "query_logs_progressive" => loki::query_logs_progressive(arguments).await,
        "get_loki_label_values" => loki::get_label_values(arguments).await,
        "execute_parallel_queries" => loki::execute_parallel_queries(arguments).await,

        // ── Prometheus metrics ────────────────────────────────────
        "query_prometheus" => prometheus::query_instant(arguments).await,
        "query_prometheus_range" => prometheus::query_range(arguments).await,

        // ── Detection templates ───────────────────────────────────
        "run_detection_query" => detection::run_detection_query(arguments).await,
        "run_parallel_detections" => detection::run_parallel_detections(arguments).await,
        "list_detection_templates" => detection::list_detection_templates(arguments).await,

        // ── Investigation helpers ────────────────────────────────
        "get_host_activity" => detection::get_host_activity(arguments).await,
        "get_user_activity" => detection::get_user_activity(arguments).await,

        // ── Grafana ─────────────────────────────────────────────
        "get_grafana_alerts" => grafana::get_alerts(arguments).await,
        "get_grafana_annotations" => grafana::get_annotations(arguments).await,
        "search_grafana_dashboards" => grafana::search_dashboards(arguments).await,
        "get_grafana_dashboard" => grafana::get_dashboard(arguments).await,

        // ── MITRE ATT&CK learning ─────────────────────────────────
        "lookup_technique" => Ok(learning::lookup_technique(arguments)?),
        "suggest_techniques" => Ok(learning::suggest_techniques(arguments)?),

        // ── Investigation state mutation ─────────────────────────
        "add_evidence" => investigation::add_evidence(arguments).await,
        "record_timeline_event" => investigation::record_timeline_event(arguments).await,
        "add_technique" => investigation::add_technique(arguments).await,
        "add_lateral_connection" => investigation::add_lateral_connection(arguments).await,
        "get_investigation_summary" => investigation::get_investigation_summary(arguments).await,

        _ => Err(anyhow::anyhow!("unknown blue team tool: {tool_name}")),
    }
}

/// Check if a tool name is a blue team tool.
pub fn is_blue_tool(name: &str) -> bool {
    matches!(
        name,
        "query_loki_logs"
            | "query_logs_around_timestamp"
            | "query_logs_progressive"
            | "get_loki_label_values"
            | "execute_parallel_queries"
            | "query_prometheus"
            | "query_prometheus_range"
            | "run_detection_query"
            | "run_parallel_detections"
            | "list_detection_templates"
            | "get_host_activity"
            | "get_user_activity"
            | "get_grafana_alerts"
            | "get_grafana_annotations"
            | "search_grafana_dashboards"
            | "get_grafana_dashboard"
            | "lookup_technique"
            | "suggest_techniques"
            | "add_evidence"
            | "record_timeline_event"
            | "add_technique"
            | "add_lateral_connection"
            | "get_investigation_summary"
    )
}
