//! Write operations: create annotations and post investigation lifecycle events.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::{build_client, grafana_url, make_error, make_output};

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

    let now_ms = crate::blue::replay_clock::replay_now().timestamp_millis();

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

    let now_ms = crate::blue::replay_clock::replay_now().timestamp_millis();
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

    let now_ms = crate::blue::replay_clock::replay_now().timestamp_millis();
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
