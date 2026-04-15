//! Alert rule management: create detection rules and query alert history.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::{build_client, grafana_url, make_error, make_output};

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
