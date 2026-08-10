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
    match time {
        // Cap a caller-supplied instant at the replay clock (unfolding modes) so
        // the agent can't sample metrics from its own future; no-op passthrough
        // in static/frozen replay and live.
        Some(t) => params.push(("time", super::loki::clamp_end_to_replay(t))),
        // During replay, pin an omitted `time` to the replay clock so "now"
        // resolves to attack-time instead of the Prometheus server's wall clock.
        None => {
            if super::replay_clock::is_replay() {
                params.push(("time", super::replay_clock::replay_now().to_rfc3339()));
            }
        }
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
    let end_time_owned = super::loki::clamp_end_to_replay(required_str(args, "end_time")?);
    let end_time = end_time_owned.as_str();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn format_no_results() {
        let body = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        assert_eq!(format_prometheus_response(body), "No results.");
    }

    #[test]
    fn format_invalid_json() {
        assert_eq!(format_prometheus_response("not json"), "not json");
    }

    #[test]
    fn format_missing_data() {
        let body = r#"{"status":"success"}"#;
        assert_eq!(format_prometheus_response(body), "No results.");
    }

    #[test]
    fn format_instant_query_result() {
        let body = serde_json::to_string(&json!({
            "data": {
                "resultType": "vector",
                "result": [{
                    "metric": {"__name__": "up", "instance": "localhost:9090"},
                    "value": [1234567890, "1"]
                }]
            }
        }))
        .unwrap();
        let result = format_prometheus_response(&body);
        assert!(result.contains("vector"));
        assert!(result.contains("1 series"));
        assert!(result.contains("__name__=\"up\""));
        assert!(result.contains("=> 1"));
    }

    #[test]
    fn format_range_query_result() {
        let body = serde_json::to_string(&json!({
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {"job": "node"},
                    "values": [
                        [1000, "0.5"],
                        [1060, "0.6"],
                        [1120, "0.7"]
                    ]
                }]
            }
        }))
        .unwrap();
        let result = format_prometheus_response(&body);
        assert!(result.contains("matrix"));
        assert!(result.contains("3 samples"));
        assert!(result.contains("0.5"));
    }

    #[test]
    fn format_range_query_truncates_after_five() {
        let values: Vec<_> = (0..8)
            .map(|i| json!([1000 + i * 60, format!("{}", i)]))
            .collect();
        let body = serde_json::to_string(&json!({
            "data": {
                "resultType": "matrix",
                "result": [{"metric": {"job": "test"}, "values": values}]
            }
        }))
        .unwrap();
        let result = format_prometheus_response(&body);
        assert!(result.contains("8 samples"));
        assert!(result.contains("... and 3 more"));
    }

    #[test]
    fn format_multiple_series() {
        let body = serde_json::to_string(&json!({
            "data": {
                "resultType": "vector",
                "result": [
                    {"metric": {"instance": "a"}, "value": [1, "10"]},
                    {"metric": {"instance": "b"}, "value": [1, "20"]}
                ]
            }
        }))
        .unwrap();
        let result = format_prometheus_response(&body);
        assert!(result.contains("2 series"));
        assert!(result.contains("instance=\"a\""));
        assert!(result.contains("instance=\"b\""));
    }

    #[test]
    fn make_output_success() {
        let out = make_output("test");
        assert!(out.success);
        assert_eq!(out.stdout, "test");
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn make_error_failure() {
        let out = make_error("fail");
        assert!(!out.success);
        assert_eq!(out.stderr, "fail");
        assert_eq!(out.exit_code, Some(1));
    }
}
