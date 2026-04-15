//! Prometheus metric query tools.
//!
//! HTTP-based queries against Prometheus's REST API.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::ToolOutput;

fn prometheus_url() -> String {
    std::env::var("PROMETHEUS_URL").unwrap_or_else(|_| "http://localhost:9090".to_string())
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default()
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

/// Execute a PromQL instant query.
pub async fn query_instant(args: &Value) -> Result<ToolOutput> {
    let promql = required_str(args, "promql")?;
    let time = optional_str(args, "time");

    let client = http_client();
    let mut params = vec![("query", promql.to_string())];
    if let Some(t) = time {
        params.push(("time", t.to_string()));
    }

    let resp = client
        .get(format!("{}/api/v1/query", prometheus_url()))
        .query(&params)
        .send()
        .await
        .context("Failed to query Prometheus")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        return Ok(make_error(&format!("Prometheus returned {status}: {body}")));
    }

    Ok(make_output(&format_prometheus_response(&body)))
}

/// Execute a PromQL range query.
pub async fn query_range(args: &Value) -> Result<ToolOutput> {
    let promql = required_str(args, "promql")?;
    let start_time = required_str(args, "start_time")?;
    let end_time = required_str(args, "end_time")?;
    let step = optional_str(args, "step").unwrap_or("60s");

    let client = http_client();
    let resp = client
        .get(format!("{}/api/v1/query_range", prometheus_url()))
        .query(&[
            ("query", promql),
            ("start", start_time),
            ("end", end_time),
            ("step", step),
        ])
        .send()
        .await
        .context("Failed to query Prometheus range")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        return Ok(make_error(&format!("Prometheus returned {status}: {body}")));
    }

    Ok(make_output(&format_prometheus_response(&body)))
}

/// Get available Prometheus metric names with optional search filter.
pub async fn get_metric_names(args: &Value) -> Result<ToolOutput> {
    let search = optional_str(args, "search");

    let client = http_client();
    let resp = client
        .get(format!("{}/api/v1/label/__name__/values", prometheus_url()))
        .send()
        .await
        .context("Failed to query Prometheus metric names")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        return Ok(make_error(&format!("Prometheus returned {status}: {body}")));
    }

    let json: Value = serde_json::from_str(&body).unwrap_or_default();
    let names = json
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|name| {
                    search
                        .map(|s| name.to_lowercase().contains(&s.to_lowercase()))
                        .unwrap_or(true)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if names.is_empty() {
        let msg = match search {
            Some(s) => format!("No metric names matching '{s}'."),
            None => "No metric names found.".to_string(),
        };
        return Ok(make_output(&msg));
    }

    Ok(make_output(&format!(
        "Metric names ({} total):\n{}",
        names.len(),
        names.join("\n")
    )))
}

fn format_prometheus_response(body: &str) -> String {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };

    let result_type = json
        .get("data")
        .and_then(|d| d.get("resultType"))
        .and_then(|r| r.as_str())
        .unwrap_or("unknown");

    let results = json
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array());

    match results {
        Some(results) if !results.is_empty() => {
            let mut lines = vec![format!(
                "Result type: {result_type}, {} series:",
                results.len()
            )];

            for result in results {
                let metric = result
                    .get("metric")
                    .and_then(|m| m.as_object())
                    .map(|obj| {
                        obj.iter()
                            .map(|(k, v)| format!("{k}=\"{}\"", v.as_str().unwrap_or("")))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_else(|| "{}".to_string());

                // Instant query: "value" is [timestamp, value]
                if let Some(value) = result.get("value").and_then(|v| v.as_array()) {
                    if value.len() >= 2 {
                        let val = value[1].as_str().unwrap_or("?");
                        lines.push(format!("  {{{metric}}} => {val}"));
                    }
                }
                // Range query: "values" is [[ts, val], ...]
                else if let Some(values) = result.get("values").and_then(|v| v.as_array()) {
                    lines.push(format!("  {{{metric}}} ({} samples)", values.len()));
                    for point in values.iter().take(5) {
                        if let Some(arr) = point.as_array() {
                            if arr.len() >= 2 {
                                let val = arr[1].as_str().unwrap_or("?");
                                lines.push(format!("    {val}"));
                            }
                        }
                    }
                    if values.len() > 5 {
                        lines.push(format!("    ... and {} more", values.len() - 5));
                    }
                }
            }

            lines.join("\n")
        }
        _ => "No results.".to_string(),
    }
}
