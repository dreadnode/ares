//! Read-only Grafana API calls: alerts, annotations, and dashboards.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::{build_client, grafana_url, make_error, make_output};

/// Get alerts from Grafana.
///
/// Tries multiple API endpoints for compatibility across Grafana versions.
/// Accepts an optional `state` filter (e.g. "firing", "pending").
pub async fn get_alerts(args: &Value) -> Result<ToolOutput> {
    let state = optional_str(args, "state");
    let client = build_client()?;

    // Try multiple Grafana alert endpoints (depends on Grafana version)
    let endpoints = [
        "/api/alertmanager/grafana/api/v2/alerts",
        "/api/v1/provisioning/alert-rules",
        "/api/prometheus/grafana/api/v1/alerts",
    ];

    for endpoint in &endpoints {
        let url = format!("{}{}", grafana_url(), endpoint);
        let mut req = client.get(&url);

        if let Some(s) = state {
            req = req.query(&[("active", s)]);
        }

        let Ok(resp) = req.send().await else {
            continue;
        };

        let status = resp.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            continue;
        }

        let body = resp
            .text()
            .await
            .context("Failed to read Grafana response")?;

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Ok(make_error(&format!(
                "Grafana authentication failed ({status}): {body}"
            )));
        }

        if !status.is_success() {
            return Ok(make_error(&format!("Grafana returned {status}: {body}")));
        }

        return Ok(make_output(&format_alerts_response(&body)));
    }

    Ok(make_error(
        "Could not find a working Grafana alerts endpoint. \
         Tried alertmanager, provisioning, and prometheus APIs.",
    ))
}

/// Get annotations from Grafana with optional time range and tag filters.
///
/// Parameters:
/// - `from` (optional): Start time as epoch milliseconds or ISO8601 string
/// - `to` (optional): End time as epoch milliseconds or ISO8601 string
/// - `tags` (optional): Comma-separated tag filter
/// - `limit` (optional): Maximum annotations to return (default: 100)
/// - `type` (optional): Annotation type filter (e.g. "alert")
pub async fn get_annotations(args: &Value) -> Result<ToolOutput> {
    let limit = optional_i64(args, "limit").unwrap_or(100);
    let tags = optional_str(args, "tags");
    let ann_type = optional_str(args, "type");
    let from = optional_str(args, "from");
    let to = optional_str(args, "to");

    let client = build_client()?;
    let url = format!("{}/api/annotations", grafana_url());

    let mut params: Vec<(&str, String)> = vec![("limit", limit.to_string())];

    if let Some(f) = from {
        params.push(("from", f.to_string()));
    }
    if let Some(t) = to {
        params.push(("to", t.to_string()));
    }
    if let Some(t) = tags {
        // Grafana annotations API accepts multiple `tags` params;
        // split on comma for convenience.
        for tag in t.split(',') {
            let tag = tag.trim();
            if !tag.is_empty() {
                params.push(("tags", tag.to_string()));
            }
        }
    }
    if let Some(at) = ann_type {
        params.push(("type", at.to_string()));
    }

    let resp = client
        .get(&url)
        .query(&params)
        .send()
        .await
        .context("Failed to query Grafana annotations")?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .context("Failed to read Grafana response")?;

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    Ok(make_output(&format_annotations_response(&body)))
}

/// Search dashboards in Grafana.
///
/// Parameters:
/// - `query` (optional): Search query string
/// - `tag` (optional): Filter by tag
/// - `limit` (optional): Maximum results (default: 50)
pub async fn search_dashboards(args: &Value) -> Result<ToolOutput> {
    let query = optional_str(args, "query");
    let tag = optional_str(args, "tag");
    let limit = optional_i64(args, "limit").unwrap_or(50);

    let client = build_client()?;
    let url = format!("{}/api/search", grafana_url());

    let mut params: Vec<(&str, String)> = vec![
        ("type", "dash-db".to_string()),
        ("limit", limit.to_string()),
    ];

    if let Some(q) = query {
        params.push(("query", q.to_string()));
    }
    if let Some(t) = tag {
        params.push(("tag", t.to_string()));
    }

    let resp = client
        .get(&url)
        .query(&params)
        .send()
        .await
        .context("Failed to search Grafana dashboards")?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .context("Failed to read Grafana response")?;

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    Ok(make_output(&format_dashboard_search_response(&body)))
}

/// Get a dashboard by its UID.
///
/// Parameters:
/// - `uid` (required): Dashboard UID
pub async fn get_dashboard(args: &Value) -> Result<ToolOutput> {
    let uid = required_str(args, "uid")?;

    let client = build_client()?;
    let url = format!("{}/api/dashboards/uid/{}", grafana_url(), uid);

    let resp = client
        .get(&url)
        .send()
        .await
        .context("Failed to get Grafana dashboard")?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .context("Failed to read Grafana response")?;

    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(make_error(&format!("Dashboard with UID '{uid}' not found")));
    }

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    Ok(make_output(&format_dashboard_response(&body)))
}

/// Format a Grafana alerts JSON response into readable text.
fn format_alerts_response(body: &str) -> String {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };

    let alerts = match json.as_array() {
        Some(a) => a,
        None => {
            // Some endpoints wrap alerts in a data field
            match json
                .get("data")
                .and_then(|d| d.get("alerts"))
                .and_then(|a| a.as_array())
            {
                Some(a) => a,
                None => return format_json_pretty(&json),
            }
        }
    };

    if alerts.is_empty() {
        return "No alerts found.".to_string();
    }

    let mut lines = vec![format!("Found {} alert(s):", alerts.len())];

    for alert in alerts {
        let name = alert
            .get("labels")
            .and_then(|l| l.get("alertname"))
            .and_then(|n| n.as_str())
            .or_else(|| alert.get("title").and_then(|t| t.as_str()))
            .unwrap_or("unnamed");

        let state = alert
            .get("status")
            .and_then(|s| s.get("state"))
            .and_then(|s| s.as_str())
            .or_else(|| alert.get("state").and_then(|s| s.as_str()))
            .unwrap_or("unknown");

        let severity = alert
            .get("labels")
            .and_then(|l| l.get("severity"))
            .and_then(|s| s.as_str())
            .unwrap_or("-");

        let summary = alert
            .get("annotations")
            .and_then(|a| a.get("summary"))
            .and_then(|s| s.as_str())
            .unwrap_or("");

        lines.push(format!("\n  Alert: {name}"));
        lines.push(format!("  State: {state}"));
        lines.push(format!("  Severity: {severity}"));
        if !summary.is_empty() {
            lines.push(format!("  Summary: {summary}"));
        }

        // Show starts/ends if present
        if let Some(starts) = alert.get("startsAt").and_then(|s| s.as_str()) {
            lines.push(format!("  Started: {starts}"));
        }
        if let Some(ends) = alert.get("endsAt").and_then(|s| s.as_str()) {
            if !ends.starts_with("0001") {
                lines.push(format!("  Ended: {ends}"));
            }
        }
    }

    lines.join("\n")
}

/// Format a Grafana annotations JSON response into readable text.
fn format_annotations_response(body: &str) -> String {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };

    let Some(annotations) = json.as_array() else {
        return format_json_pretty(&json);
    };

    if annotations.is_empty() {
        return "No annotations found.".to_string();
    }

    let mut lines = vec![format!("Found {} annotation(s):", annotations.len())];

    for ann in annotations {
        let text = ann.get("text").and_then(|t| t.as_str()).unwrap_or("");
        let alert_name = ann.get("alertName").and_then(|n| n.as_str()).unwrap_or("");
        let id = ann.get("id").and_then(|i| i.as_i64()).unwrap_or(0);

        let tags = ann
            .get("tags")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        lines.push(format!("\n  ID: {id}"));
        if !alert_name.is_empty() {
            lines.push(format!("  Alert: {alert_name}"));
        }
        if !text.is_empty() {
            // Truncate long annotation text
            let display = if text.len() > 200 {
                let mut end = 200;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &text[..end])
            } else {
                text.to_string()
            };
            lines.push(format!("  Text: {display}"));
        }
        if !tags.is_empty() {
            lines.push(format!("  Tags: {tags}"));
        }

        // Show time range
        if let Some(time) = ann.get("time").and_then(|t| t.as_i64()) {
            lines.push(format!("  Time: {time}"));
        }
    }

    lines.join("\n")
}

/// Format a dashboard search JSON response into readable text.
fn format_dashboard_search_response(body: &str) -> String {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };

    let Some(dashboards) = json.as_array() else {
        return format_json_pretty(&json);
    };

    if dashboards.is_empty() {
        return "No dashboards found.".to_string();
    }

    let mut lines = vec![format!("Found {} dashboard(s):", dashboards.len())];

    for db in dashboards {
        let title = db
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("untitled");
        let uid = db.get("uid").and_then(|u| u.as_str()).unwrap_or("-");
        let uri = db.get("uri").and_then(|u| u.as_str()).unwrap_or("");
        let folder = db.get("folderTitle").and_then(|f| f.as_str()).unwrap_or("");

        let tags = db
            .get("tags")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        lines.push(format!("\n  Title: {title}"));
        lines.push(format!("  UID: {uid}"));
        if !uri.is_empty() {
            lines.push(format!("  URI: {uri}"));
        }
        if !folder.is_empty() {
            lines.push(format!("  Folder: {folder}"));
        }
        if !tags.is_empty() {
            lines.push(format!("  Tags: {tags}"));
        }
    }

    lines.join("\n")
}

/// Format a single dashboard JSON response into readable text.
fn format_dashboard_response(body: &str) -> String {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };

    let meta = json.get("meta");
    let dashboard = json.get("dashboard");

    let mut lines = Vec::new();

    if let Some(db) = dashboard {
        let title = db
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("untitled");
        let uid = db.get("uid").and_then(|u| u.as_str()).unwrap_or("-");
        let description = db.get("description").and_then(|d| d.as_str()).unwrap_or("");

        lines.push(format!("Dashboard: {title}"));
        lines.push(format!("UID: {uid}"));

        if !description.is_empty() {
            lines.push(format!("Description: {description}"));
        }

        // Show panel summary
        if let Some(panels) = db.get("panels").and_then(|p| p.as_array()) {
            lines.push(format!("\nPanels ({}):", panels.len()));
            for panel in panels {
                let panel_title = panel
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("untitled");
                let panel_type = panel
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");
                let panel_id = panel.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
                lines.push(format!("  [{panel_id}] {panel_title} ({panel_type})"));
            }
        }
    }

    if let Some(m) = meta {
        let folder = m.get("folderTitle").and_then(|f| f.as_str()).unwrap_or("");
        let updated = m.get("updated").and_then(|u| u.as_str()).unwrap_or("");
        let created_by = m.get("createdBy").and_then(|c| c.as_str()).unwrap_or("");

        if !folder.is_empty() {
            lines.push(format!("Folder: {folder}"));
        }
        if !updated.is_empty() {
            lines.push(format!("Last updated: {updated}"));
        }
        if !created_by.is_empty() {
            lines.push(format!("Created by: {created_by}"));
        }
    }

    if lines.is_empty() {
        format_json_pretty(&json)
    } else {
        lines.join("\n")
    }
}

/// Pretty-print JSON as a fallback when structured formatting isn't possible.
fn format_json_pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── format_alerts_response ────────────────────────────────────

    #[test]
    fn alerts_empty_array() {
        assert_eq!(format_alerts_response("[]"), "No alerts found.");
    }

    #[test]
    fn alerts_invalid_json_returns_raw() {
        assert_eq!(format_alerts_response("not json"), "not json");
    }

    #[test]
    fn alerts_single_with_labels() {
        let body = serde_json::to_string(&json!([{
            "labels": {"alertname": "HighCPU", "severity": "critical"},
            "status": {"state": "firing"},
            "annotations": {"summary": "CPU over 90%"},
            "startsAt": "2024-01-15T10:00:00Z"
        }]))
        .unwrap();
        let out = format_alerts_response(&body);
        assert!(out.contains("Found 1 alert(s):"));
        assert!(out.contains("Alert: HighCPU"));
        assert!(out.contains("State: firing"));
        assert!(out.contains("Severity: critical"));
        assert!(out.contains("Summary: CPU over 90%"));
        assert!(out.contains("Started: 2024-01-15T10:00:00Z"));
    }

    #[test]
    fn alerts_title_fallback() {
        let body =
            serde_json::to_string(&json!([{"title": "DiskFull", "state": "pending"}])).unwrap();
        let out = format_alerts_response(&body);
        assert!(out.contains("Alert: DiskFull"));
        assert!(out.contains("State: pending"));
    }

    #[test]
    fn alerts_ends_at_zero_year_hidden() {
        let body = serde_json::to_string(&json!([{
            "labels": {"alertname": "Test"},
            "endsAt": "0001-01-01T00:00:00Z"
        }]))
        .unwrap();
        let out = format_alerts_response(&body);
        assert!(!out.contains("Ended:"));
    }

    #[test]
    fn alerts_ends_at_real_shown() {
        let body = serde_json::to_string(&json!([{
            "labels": {"alertname": "Test"},
            "endsAt": "2024-01-15T12:00:00Z"
        }]))
        .unwrap();
        let out = format_alerts_response(&body);
        assert!(out.contains("Ended: 2024-01-15T12:00:00Z"));
    }

    #[test]
    fn alerts_data_wrapper() {
        let body = serde_json::to_string(&json!({
            "data": {"alerts": [{"labels": {"alertname": "Wrapped"}}]}
        }))
        .unwrap();
        let out = format_alerts_response(&body);
        assert!(out.contains("Alert: Wrapped"));
    }

    #[test]
    fn alerts_non_array_fallback() {
        let body = serde_json::to_string(&json!({"status": "ok"})).unwrap();
        let out = format_alerts_response(&body);
        assert!(out.contains("status"));
    }

    #[test]
    fn alerts_multiple() {
        let body = serde_json::to_string(&json!([
            {"labels": {"alertname": "A"}},
            {"labels": {"alertname": "B"}}
        ]))
        .unwrap();
        let out = format_alerts_response(&body);
        assert!(out.contains("Found 2 alert(s):"));
        assert!(out.contains("Alert: A"));
        assert!(out.contains("Alert: B"));
    }

    // ── format_annotations_response ───────────────────────────────

    #[test]
    fn annotations_empty_array() {
        assert_eq!(format_annotations_response("[]"), "No annotations found.");
    }

    #[test]
    fn annotations_invalid_json() {
        assert_eq!(format_annotations_response("bad"), "bad");
    }

    #[test]
    fn annotations_single() {
        let body = serde_json::to_string(&json!([{
            "id": 42,
            "text": "Deployment v1.2",
            "alertName": "Deploy",
            "tags": ["prod", "release"],
            "time": 1705312800000i64
        }]))
        .unwrap();
        let out = format_annotations_response(&body);
        assert!(out.contains("Found 1 annotation(s):"));
        assert!(out.contains("ID: 42"));
        assert!(out.contains("Alert: Deploy"));
        assert!(out.contains("Text: Deployment v1.2"));
        assert!(out.contains("Tags: prod, release"));
        assert!(out.contains("Time: 1705312800000"));
    }

    #[test]
    fn annotations_long_text_truncated() {
        let long_text = "x".repeat(300);
        let body = serde_json::to_string(&json!([{"id": 1, "text": long_text}])).unwrap();
        let out = format_annotations_response(&body);
        assert!(out.contains("..."));
        assert!(!out.contains(&"x".repeat(300)));
    }

    #[test]
    fn annotations_non_array_fallback() {
        let body = serde_json::to_string(&json!({"total": 0})).unwrap();
        let out = format_annotations_response(&body);
        assert!(out.contains("total"));
    }

    // ── format_dashboard_search_response ──────────────────────────

    #[test]
    fn dashboard_search_empty() {
        assert_eq!(
            format_dashboard_search_response("[]"),
            "No dashboards found."
        );
    }

    #[test]
    fn dashboard_search_invalid_json() {
        assert_eq!(format_dashboard_search_response("nope"), "nope");
    }

    #[test]
    fn dashboard_search_single() {
        let body = serde_json::to_string(&json!([{
            "title": "API Latency",
            "uid": "abc123",
            "uri": "db/api-latency",
            "folderTitle": "Production",
            "tags": ["api", "latency"]
        }]))
        .unwrap();
        let out = format_dashboard_search_response(&body);
        assert!(out.contains("Found 1 dashboard(s):"));
        assert!(out.contains("Title: API Latency"));
        assert!(out.contains("UID: abc123"));
        assert!(out.contains("URI: db/api-latency"));
        assert!(out.contains("Folder: Production"));
        assert!(out.contains("Tags: api, latency"));
    }

    #[test]
    fn dashboard_search_minimal() {
        let body = serde_json::to_string(&json!([{"title": "Simple"}])).unwrap();
        let out = format_dashboard_search_response(&body);
        assert!(out.contains("Title: Simple"));
        assert!(out.contains("UID: -"));
        assert!(!out.contains("URI:"));
        assert!(!out.contains("Folder:"));
    }

    #[test]
    fn dashboard_search_non_array_fallback() {
        let body = serde_json::to_string(&json!({"count": 5})).unwrap();
        let out = format_dashboard_search_response(&body);
        assert!(out.contains("count"));
    }

    // ── format_dashboard_response ─────────────────────────────────

    #[test]
    fn dashboard_full() {
        let body = serde_json::to_string(&json!({
            "dashboard": {
                "title": "System Overview",
                "uid": "sys-1",
                "description": "Main system dashboard",
                "panels": [
                    {"id": 1, "title": "CPU", "type": "graph"},
                    {"id": 2, "title": "Memory", "type": "stat"}
                ]
            },
            "meta": {
                "folderTitle": "Infra",
                "updated": "2024-01-15T10:00:00Z",
                "createdBy": "admin"
            }
        }))
        .unwrap();
        let out = format_dashboard_response(&body);
        assert!(out.contains("Dashboard: System Overview"));
        assert!(out.contains("UID: sys-1"));
        assert!(out.contains("Description: Main system dashboard"));
        assert!(out.contains("Panels (2):"));
        assert!(out.contains("[1] CPU (graph)"));
        assert!(out.contains("[2] Memory (stat)"));
        assert!(out.contains("Folder: Infra"));
        assert!(out.contains("Last updated: 2024-01-15T10:00:00Z"));
        assert!(out.contains("Created by: admin"));
    }

    #[test]
    fn dashboard_no_panels() {
        let body = serde_json::to_string(&json!({
            "dashboard": {"title": "Empty", "uid": "e1"}
        }))
        .unwrap();
        let out = format_dashboard_response(&body);
        assert!(out.contains("Dashboard: Empty"));
        assert!(!out.contains("Panels"));
    }

    #[test]
    fn dashboard_empty_json_fallback() {
        let body = serde_json::to_string(&json!({})).unwrap();
        let out = format_dashboard_response(&body);
        // No dashboard or meta keys → falls back to pretty JSON
        assert!(out.contains("{}") || out.contains("{\n}"));
    }

    #[test]
    fn dashboard_invalid_json() {
        assert_eq!(format_dashboard_response("broken"), "broken");
    }

    // ── format_json_pretty ────────────────────────────────────────

    #[test]
    fn json_pretty_object() {
        let val = json!({"key": "value"});
        let out = format_json_pretty(&val);
        assert!(out.contains("\"key\""));
        assert!(out.contains("\"value\""));
    }

    #[test]
    fn json_pretty_null() {
        assert_eq!(format_json_pretty(&json!(null)), "null");
    }
}
