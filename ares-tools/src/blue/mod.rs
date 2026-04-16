//! Blue team HTTP-based tools for log analysis and observability.
//!
//! Unlike red team tools which wrap CLI commands, blue team tools make
//! HTTP requests to Loki, Prometheus, and Grafana APIs.

pub mod detection;
pub mod engines;
pub mod evidence_validator;
pub mod grafana;
pub mod investigation;
pub mod learning;
pub mod loki;
pub mod persistence;
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

        // ── Grafana alert history ───────────────────────────────
        "get_alert_history" => grafana::get_alert_history(arguments).await,
        "get_alerts_in_time_range" => grafana::get_alerts_in_time_range(arguments).await,

        // ── Grafana write-back ──────────────────────────────────
        "create_annotation" => grafana::create_annotation(arguments).await,
        "create_detection_rule" => grafana::create_detection_rule(arguments).await,
        "post_investigation_started" => grafana::post_investigation_started(arguments).await,
        "post_investigation_completed" => grafana::post_investigation_completed(arguments).await,

        // ── Question engines (MITRE Navigator + Pyramid Climber) ──
        "generate_mitre_questions" => engines::generate_mitre_questions_tool(arguments).await,
        "generate_pyramid_questions" => engines::generate_pyramid_questions_tool(arguments).await,
        "assess_pyramid_state" => engines::assess_pyramid_state_tool(arguments).await,
        "get_combined_questions" => engines::get_combined_questions_tool(arguments).await,
        "get_attack_chain_precursors" => Ok(engines::get_attack_chain_precursors(arguments)?),
        "get_detection_recipe" => Ok(engines::get_detection_recipe(arguments)?),
        "list_detection_recipes" => Ok(engines::list_detection_recipes(arguments)?),

        // ── MITRE ATT&CK learning ─────────────────────────────────
        "lookup_technique" => Ok(learning::lookup_technique(arguments)?),
        "suggest_techniques" => Ok(learning::suggest_techniques(arguments)?),

        // ── Investigation learning ──────────────────────────────
        "find_similar_investigations" => Ok(learning::find_similar_investigations(arguments)?),
        "get_effective_queries" => Ok(learning::get_effective_queries(arguments)?),
        "check_false_positive_pattern" => Ok(learning::check_false_positive_pattern(arguments)?),
        "get_investigation_statistics" => Ok(learning::get_investigation_statistics(arguments)?),

        // ── Loki convenience ────────────────────────────────────
        "query_logs_recent" => loki::query_logs_recent(arguments).await,
        "combine_query_patterns" => Ok(loki::combine_query_patterns(arguments)?),

        // ── Prometheus convenience ──────────────────────────────
        "get_metric_names" => prometheus::get_metric_names(arguments).await,

        // ── Investigation state mutation ─────────────────────────
        "add_evidence" => investigation::add_evidence(arguments).await,
        "add_evidence_batch" => investigation::add_evidence_batch(arguments).await,
        "record_timeline_event" => investigation::record_timeline_event(arguments).await,
        "add_technique" => investigation::add_technique(arguments).await,
        "add_lateral_connection" => investigation::add_lateral_connection(arguments).await,
        "transition_stage" => investigation::transition_stage(arguments).await,
        "track_host_investigation" => investigation::track_host_investigation(arguments).await,
        "track_user_investigation" => investigation::track_user_investigation(arguments).await,
        "list_evidence" => investigation::list_evidence(arguments).await,
        "get_investigation_context" => investigation::get_investigation_context(arguments).await,
        "get_investigation_summary" => investigation::get_investigation_summary(arguments).await,

        // ── Evidence validation & analysis ──────────────────────
        "get_suggested_evidence" => Ok(investigation::get_suggested_evidence(arguments)?),
        "analyze_lateral_movement" => investigation::analyze_lateral_movement(arguments).await,
        "get_correlated_alerts" => investigation::get_correlated_alerts(arguments).await,
        "get_queued_queries" => investigation::get_queued_queries(arguments).await,
        "get_formatted_summary" => investigation::get_formatted_summary(arguments).await,
        "pop_all_queued" => investigation::pop_all_queued(arguments).await,

        // ── Red team playbook integration ───────────────────────
        "get_attack_playbook" => learning::get_attack_playbook(arguments).await,
        "get_detection_queries_for_technique" => {
            learning::get_detection_queries_for_technique(arguments).await
        }

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
            | "create_annotation"
            | "create_detection_rule"
            | "post_investigation_started"
            | "post_investigation_completed"
            | "lookup_technique"
            | "suggest_techniques"
            | "find_similar_investigations"
            | "get_effective_queries"
            | "check_false_positive_pattern"
            | "get_investigation_statistics"
            | "query_logs_recent"
            | "combine_query_patterns"
            | "get_metric_names"
            | "add_evidence"
            | "add_evidence_batch"
            | "record_timeline_event"
            | "add_technique"
            | "add_lateral_connection"
            | "transition_stage"
            | "track_host_investigation"
            | "track_user_investigation"
            | "list_evidence"
            | "get_investigation_context"
            | "get_investigation_summary"
            | "get_attack_playbook"
            | "get_detection_queries_for_technique"
            | "get_suggested_evidence"
            | "analyze_lateral_movement"
            | "get_correlated_alerts"
            | "get_queued_queries"
            | "get_formatted_summary"
            | "pop_all_queued"
            | "get_alert_history"
            | "get_alerts_in_time_range"
            | "generate_mitre_questions"
            | "generate_pyramid_questions"
            | "assess_pyramid_state"
            | "get_combined_questions"
            | "get_attack_chain_precursors"
            | "get_detection_recipe"
            | "list_detection_recipes"
    )
}
