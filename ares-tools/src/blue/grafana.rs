//! Grafana alerting and dashboard query tools.
//!
//! HTTP-based queries against Grafana's REST API for alerts, annotations,
//! and dashboard data.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

fn grafana_url() -> String {
    std::env::var("GRAFANA_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

fn grafana_api_key() -> Option<String> {
    std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok()
}

fn make_output(body: &str) -> ToolOutput {
    ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

fn make_error(msg: &str) -> ToolOutput {
    ToolOutput {
        stdout: String::new(),
        stderr: msg.to_string(),
        exit_code: Some(1),
        success: false,
    }
}

/// Build a reqwest client with optional Bearer token authentication.
fn build_client() -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(key) = grafana_api_key() {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
                .context("invalid API key characters")?,
        );
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("Failed to build HTTP client")
}

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

        let resp = match req.send().await {
            Ok(r) => r,
            Err(_) => continue,
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

// ---------------------------------------------------------------------------
// Response formatters
// ---------------------------------------------------------------------------

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

    let annotations = match json.as_array() {
        Some(a) => a,
        None => return format_json_pretty(&json),
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

    let dashboards = match json.as_array() {
        Some(a) => a,
        None => return format_json_pretty(&json),
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

// ---------------------------------------------------------------------------
// Write-back tools
// ---------------------------------------------------------------------------

/// Create an annotation in Grafana.
///
/// Parameters:
/// - `text` (required): Annotation text
/// - `tags` (optional): Comma-separated tags (default: "ares,investigation")
/// - `dashboard_uid` (optional): Scope to a specific dashboard
/// - `time_start` (optional): Start time as epoch ms (default: now)
/// - `time_end` (optional): End time as epoch ms
pub async fn create_annotation(args: &Value) -> Result<ToolOutput> {
    let text = required_str(args, "text")?;
    let tags_str = optional_str(args, "tags").unwrap_or("ares,investigation");
    let dashboard_uid = optional_str(args, "dashboard_uid");
    let time_start = optional_i64(args, "time_start");
    let time_end = optional_i64(args, "time_end");

    let tags: Vec<String> = tags_str
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let now_ms = chrono::Utc::now().timestamp_millis();

    let mut body = serde_json::json!({
        "text": text,
        "tags": tags,
        "time": time_start.unwrap_or(now_ms),
    });

    if let Some(end) = time_end {
        body["timeEnd"] = serde_json::json!(end);
    }
    if let Some(uid) = dashboard_uid {
        body["dashboardUID"] = serde_json::json!(uid);
    }

    let client = build_client()?;
    let url = format!("{}/api/annotations", grafana_url());

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Failed to create Grafana annotation")?;

    let status = resp.status();
    let resp_body = resp
        .text()
        .await
        .context("Failed to read Grafana response")?;

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {resp_body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!(
            "Grafana returned {status}: {resp_body}"
        )));
    }

    Ok(make_output(&format!(
        "[+] Annotation created: {text} [tags: {}]",
        tags.join(", ")
    )))
}

/// Post an investigation-started annotation to Grafana.
///
/// Parameters:
/// - `investigation_id` (required)
/// - `alert_name` (required)
/// - `severity` (required)
pub async fn post_investigation_started(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let alert_name = required_str(args, "alert_name")?;
    let severity = required_str(args, "severity")?;

    let text = format!(
        "**ARES Investigation Started**\n\n\
         - **ID**: {investigation_id}\n\
         - **Alert**: {alert_name}\n\
         - **Severity**: {severity}"
    );

    let tags = vec![
        "ares".to_string(),
        "investigation".to_string(),
        "started".to_string(),
        alert_name.to_string(),
        severity.to_string(),
    ];

    let now_ms = chrono::Utc::now().timestamp_millis();
    let body = serde_json::json!({
        "text": text,
        "tags": tags,
        "time": now_ms,
    });

    let client = build_client()?;
    let url = format!("{}/api/annotations", grafana_url());

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Failed to post investigation started annotation")?;

    let status = resp.status();
    let resp_body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Ok(make_error(&format!(
            "Failed to post annotation ({status}): {resp_body}"
        )));
    }

    Ok(make_output(&format!(
        "[+] Investigation started annotation posted for {alert_name}"
    )))
}

/// Post an investigation-completed annotation to Grafana.
///
/// Parameters:
/// - `investigation_id` (required)
/// - `alert_name` (required)
/// - `status` (required): "completed", "escalated", or "failed"
/// - `evidence_count` (optional)
/// - `techniques` (optional): Comma-separated technique IDs
/// - `pyramid_level` (optional)
/// - `summary` (optional)
pub async fn post_investigation_completed(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let alert_name = required_str(args, "alert_name")?;
    let inv_status = required_str(args, "status")?;
    let evidence_count = optional_i64(args, "evidence_count").unwrap_or(0);
    let techniques = optional_str(args, "techniques").unwrap_or("");
    let pyramid_level = optional_i64(args, "pyramid_level").unwrap_or(0);
    let summary = optional_str(args, "summary").unwrap_or("");

    let status_icon = match inv_status {
        "escalated" => "!",
        "failed" => "x",
        _ => "+",
    };

    let summary_truncated = if summary.len() > 500 {
        let mut end = 500;
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &summary[..end])
    } else {
        summary.to_string()
    };

    let text = format!(
        "**ARES Investigation Completed** [{status_icon}]\n\n\
         - **ID**: {investigation_id}\n\
         - **Alert**: {alert_name}\n\
         - **Status**: {inv_status}\n\
         - **Evidence**: {evidence_count} items\n\
         - **Techniques**: {techniques}\n\
         - **Pyramid Level**: {pyramid_level}\n\
         - **Summary**: {summary_truncated}"
    );

    let tags = vec![
        "ares".to_string(),
        "investigation".to_string(),
        inv_status.to_string(),
        alert_name.to_string(),
    ];

    let now_ms = chrono::Utc::now().timestamp_millis();
    let body = serde_json::json!({
        "text": text,
        "tags": tags,
        "time": now_ms,
    });

    let client = build_client()?;
    let url = format!("{}/api/annotations", grafana_url());

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Failed to post investigation completed annotation")?;

    let status = resp.status();
    let resp_body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Ok(make_error(&format!(
            "Failed to post annotation ({status}): {resp_body}"
        )));
    }

    Ok(make_output(&format!(
        "[+] Investigation completed annotation posted for {alert_name} ({inv_status})"
    )))
}

/// Create a detection alert rule in Grafana.
///
/// Parameters:
/// - `title` (required): Rule name
/// - `logql_query` (required): LogQL query for detection
/// - `description` (optional)
/// - `mitre_technique` (optional): Associated MITRE technique
/// - `severity` (optional): "critical", "high", "medium", "low" (default: "medium")
/// - `evaluation_interval` (optional): e.g. "5m" (default: "5m")
/// - `pending_period` (optional): e.g. "0s" (default: "0s")
pub async fn create_detection_rule(args: &Value) -> Result<ToolOutput> {
    let title = required_str(args, "title")?;
    let logql_query = required_str(args, "logql_query")?;
    let description = optional_str(args, "description").unwrap_or("");
    let mitre_technique = optional_str(args, "mitre_technique").unwrap_or("");
    let severity = optional_str(args, "severity").unwrap_or("medium");
    let eval_interval = optional_str(args, "evaluation_interval").unwrap_or("5m");
    let pending_period = optional_str(args, "pending_period").unwrap_or("0s");

    // Validate: reject overly broad selectors
    let broad_selectors = [
        r#"{job=~".+"}"#,
        r#"{job!=""}"#,
        r#"{__name__=~".+"}"#,
        r#"{job=~".*"}"#,
    ];
    for broad in &broad_selectors {
        if logql_query.contains(broad) {
            return Ok(make_error(&format!(
                "Query too broad — contains '{broad}'. Use a specific log selector."
            )));
        }
    }

    let client = build_client()?;

    // Ensure the ares-security folder exists
    let folder_url = format!("{}/api/folders/ares-security", grafana_url());
    let folder_resp = client.get(&folder_url).send().await;
    if let Ok(resp) = folder_resp {
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let create_body = serde_json::json!({
                "uid": "ares-security",
                "title": "ARES Security Detections"
            });
            let _ = client
                .post(format!("{}/api/folders", grafana_url()))
                .json(&create_body)
                .send()
                .await;
        }
    }

    // Build the alert rule
    let wrapped_query = format!("count_over_time({logql_query} [5m]) > 0");
    let mut labels = serde_json::json!({
        "severity": severity,
        "source": "ares",
    });
    if !mitre_technique.is_empty() {
        labels["mitre_technique"] = serde_json::json!(mitre_technique);
    }

    let rule_body = serde_json::json!({
        "folderUID": "ares-security",
        "ruleGroup": "ares-detections",
        "title": title,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "OK",
        "for": pending_period,
        "annotations": {
            "summary": description,
            "description": format!("Auto-created by ARES. LogQL: {logql_query}"),
        },
        "labels": labels,
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": { "from": 300, "to": 0 },
                "datasourceUid": "loki",
                "model": {
                    "expr": wrapped_query,
                    "refId": "A",
                },
            },
            {
                "refId": "C",
                "relativeTimeRange": { "from": 0, "to": 0 },
                "datasourceUid": "__expr__",
                "model": {
                    "type": "threshold",
                    "refId": "C",
                    "expression": "A",
                    "conditions": [{
                        "evaluator": { "type": "gt", "params": [0.0] },
                    }],
                },
            },
        ],
        "intervalSeconds": match eval_interval {
            "1m" => 60,
            "5m" => 300,
            "10m" => 600,
            "15m" => 900,
            _ => 300,
        },
    });

    let url = format!("{}/api/v1/provisioning/alert-rules", grafana_url());
    let resp = client
        .post(&url)
        .json(&rule_body)
        .send()
        .await
        .context("Failed to create Grafana alert rule")?;

    let status = resp.status();
    let resp_body = resp.text().await.unwrap_or_default();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {resp_body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!(
            "Failed to create detection rule ({status}): {resp_body}"
        )));
    }

    Ok(make_output(&format!(
        "[+] Detection rule created: {title} (severity={severity}, folder=ares-security, interval={eval_interval})"
    )))
}

/// Get alert rule definitions from Grafana's provisioning API.
pub async fn get_alert_history(args: &Value) -> Result<ToolOutput> {
    let _hours = optional_i64(args, "hours_back"); // reserved for future use
    let client = build_client()?;

    let url = format!("{}/api/v1/provisioning/alert-rules", grafana_url());
    let resp = client.get(&url).send().await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => return Ok(make_error(&format!("Failed to query Grafana: {e}"))),
    };

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    // Format the rules list
    if let Ok(rules) = serde_json::from_str::<Vec<Value>>(&body) {
        let mut parts = Vec::new();
        parts.push(format!("Alert rules ({} total):\n", rules.len()));
        for rule in &rules {
            let title = rule
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed");
            let uid = rule.get("uid").and_then(|v| v.as_str()).unwrap_or("-");
            let folder = rule
                .get("folderUID")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let interval = rule
                .get("intervalSeconds")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            parts.push(format!(
                "  - {title} (uid={uid}, folder={folder}, interval={interval}s)"
            ));
        }
        Ok(make_output(&parts.join("\n")))
    } else {
        Ok(make_output(&body))
    }
}

/// Get alerts that fired within a specific time range.
///
/// Queries Grafana's annotations API for alert annotations within the given
/// time window (with configurable buffer), then transforms annotations into
/// a normalized alert format.
pub async fn get_alerts_in_time_range(args: &Value) -> Result<ToolOutput> {
    let from_time = required_str(args, "from_time")?;
    let to_time = required_str(args, "to_time")?;
    let buffer_minutes = optional_i64(args, "buffer_minutes").unwrap_or(30);

    // Parse timestamps
    let from_dt = chrono::DateTime::parse_from_rfc3339(from_time)
        .or_else(|_| chrono::DateTime::parse_from_str(from_time, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .unwrap_or_else(|_| chrono::Utc::now().into());
    let to_dt = chrono::DateTime::parse_from_rfc3339(to_time)
        .or_else(|_| chrono::DateTime::parse_from_str(to_time, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .unwrap_or_else(|_| chrono::Utc::now().into());

    // Apply buffer
    let from_buffered = from_dt - chrono::Duration::minutes(buffer_minutes);
    let to_buffered = to_dt + chrono::Duration::minutes(buffer_minutes);

    let from_ms = from_buffered.timestamp_millis();
    let to_ms = to_buffered.timestamp_millis();

    let client = build_client()?;
    let url = format!("{}/api/annotations", grafana_url());

    let resp = client
        .get(&url)
        .query(&[
            ("from", from_ms.to_string()),
            ("to", to_ms.to_string()),
            ("type", "alert".to_string()),
        ])
        .send()
        .await
        .context("Failed to query Grafana annotations")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    let annotations: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();

    // Transform annotations to alert format with dedup
    let mut seen_fingerprints = std::collections::HashSet::new();
    let mut alerts = Vec::new();

    for ann in &annotations {
        let alert_id = ann.get("alertId").and_then(|v| v.as_i64()).unwrap_or(0);
        if alert_id == 0 {
            continue; // skip non-alert annotations
        }
        let panel_id = ann.get("panelId").and_then(|v| v.as_i64()).unwrap_or(0);
        let fingerprint = format!("ann-{alert_id}-{panel_id}");

        if !seen_fingerprints.insert(fingerprint.clone()) {
            continue; // deduplicate
        }

        // Extract labels from tags
        let mut labels = serde_json::Map::new();
        if let Some(tags) = ann.get("tags").and_then(|v| v.as_array()) {
            for tag in tags {
                if let Some(s) = tag.as_str() {
                    if let Some((k, v)) = s.split_once(':').or_else(|| s.split_once('=')) {
                        labels.insert(k.to_string(), Value::String(v.to_string()));
                    } else {
                        labels.insert("alertname".to_string(), Value::String(s.to_string()));
                    }
                }
            }
        }
        if !labels.contains_key("alertname") {
            if let Some(name) = ann.get("alertName").and_then(|v| v.as_str()) {
                labels.insert("alertname".to_string(), Value::String(name.to_string()));
            }
        }

        let text = ann
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let time_ms = ann.get("time").and_then(|v| v.as_i64()).unwrap_or(0);
        let time_end_ms = ann.get("timeEnd").and_then(|v| v.as_i64());

        let starts_at = chrono::DateTime::from_timestamp_millis(time_ms)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let ends_at = time_end_ms
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let state = if time_end_ms.is_some() {
            "resolved"
        } else {
            "firing"
        };

        alerts.push(serde_json::json!({
            "fingerprint": fingerprint,
            "labels": labels,
            "annotations": { "summary": text, "description": text },
            "startsAt": starts_at,
            "endsAt": ends_at,
            "status": { "state": state },
        }));
    }

    if alerts.is_empty() {
        return Ok(make_output("No alerts found in the specified time range."));
    }

    let output = serde_json::to_string_pretty(&alerts).unwrap_or_default();
    Ok(make_output(&format!(
        "Found {} alerts in time range:\n\n{}",
        alerts.len(),
        output
    )))
}

/// Pretty-print JSON as a fallback when structured formatting isn't possible.
fn format_json_pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}
