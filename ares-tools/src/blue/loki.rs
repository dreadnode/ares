//! Loki log query tools.
//!
//! HTTP-based queries against Loki's REST API for LogQL log retrieval.
//!
//! Configuration priority:
//! 1. `LOKI_URL` + `LOKI_AUTH_TOKEN` — direct Loki endpoint
//! 2. `GRAFANA_URL` + `GRAFANA_SERVICE_ACCOUNT_TOKEN` — Grafana datasource proxy
//!    (auto-resolves Loki datasource ID, matching the Python approach)
//! 3. `http://localhost:3100` fallback

use anyhow::{Context, Result};
use serde_json::Value;
use std::sync::OnceLock;
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::args::{optional_i64, required_str};
use crate::ToolOutput;

/// Loki connection configuration.
#[derive(Clone)]
struct LokiConfig {
    base_url: String,
    auth_token: Option<String>,
}

/// Cached Grafana-resolved Loki proxy config.
static GRAFANA_LOKI_PROXY: OnceCell<Option<LokiConfig>> = OnceCell::const_new();

/// Resolve Loki config with Grafana datasource proxy preferred.
///
/// Priority: Grafana proxy → LOKI_URL env var → localhost:3100.
///
/// The Grafana datasource proxy is preferred because it goes through
/// Grafana's authenticated, health-checked connection to Loki, which
/// is more reliable than direct Loki API access (especially cross-region).
async fn loki_config() -> LokiConfig {
    // Preferred: Grafana datasource proxy (resolved once, cached)
    let grafana_config = GRAFANA_LOKI_PROXY
        .get_or_init(|| async { resolve_grafana_proxy().await })
        .await;

    if let Some(config) = grafana_config {
        return config.clone();
    }

    // Fallback: explicit LOKI_URL
    if let Ok(url) = std::env::var("LOKI_URL") {
        let token = std::env::var("LOKI_AUTH_TOKEN").ok();
        return LokiConfig {
            base_url: url.trim_end_matches('/').to_string(),
            auth_token: token,
        };
    }

    // Default: local Loki
    LokiConfig {
        base_url: "http://localhost:3100".to_string(),
        auth_token: None,
    }
}

/// Resolve Loki datasource proxy URL from Grafana API.
///
/// Queries `GET /api/datasources/uid/loki` to get the numeric datasource ID,
/// then constructs the proxy base URL as `{GRAFANA_URL}/api/datasources/proxy/{id}`.
async fn resolve_grafana_proxy() -> Option<LokiConfig> {
    let grafana_url = std::env::var("GRAFANA_URL").ok()?;
    let token = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN")
        .or_else(|_| std::env::var("GRAFANA_API_KEY"))
        .ok()?;

    let grafana_url = grafana_url.trim_end_matches('/');
    let client = http_client();
    let ds_url = format!("{grafana_url}/api/datasources/uid/loki");

    let resp = client.get(&ds_url).bearer_auth(&token).send().await.ok()?;

    if !resp.status().is_success() {
        warn!(
            status = %resp.status(),
            "Failed to resolve Loki datasource from Grafana"
        );
        return None;
    }

    let body: Value = resp.json().await.ok()?;
    let ds_id = body.get("id")?.as_u64()?;

    let proxy_url = format!("{grafana_url}/api/datasources/proxy/{ds_id}");
    info!(proxy_url, "Resolved Loki via Grafana datasource proxy");

    Some(LokiConfig {
        base_url: proxy_url,
        auth_token: Some(token),
    })
}

/// Shared HTTP client — reuses connection pool across all Loki calls.
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        let timeout_secs = std::env::var("LOKI_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(90);
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_default()
    })
}

/// Build a GET request with optional auth header.
fn build_get(client: &reqwest::Client, url: &str, config: &LokiConfig) -> reqwest::RequestBuilder {
    let mut req = client.get(url);
    if let Some(token) = &config.auth_token {
        req = req.bearer_auth(token);
    }
    req
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

/// Max retry attempts for transient Loki failures.
/// Loki queries through the Grafana proxy take 20-50s from EC2,
/// so we allow 3 attempts to ride through transient proxy hiccups.
const MAX_RETRIES: u32 = 3;

/// Base backoff delay between retries.
const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Check whether an HTTP status code is transient and worth retrying.
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
}

/// Query logs from Loki using LogQL.
///
/// Retries up to 2 times on transient failures (timeouts, 429/502/503/504)
/// with exponential backoff (1s, 2s). Respects `Retry-After` header on 429s.
pub async fn query_logs(args: &Value) -> Result<ToolOutput> {
    let logql = required_str(args, "logql")?;
    let start_time = required_str(args, "start_time")?;
    let end_time = required_str(args, "end_time")?;
    let limit = optional_i64(args, "limit").unwrap_or(50).min(100);

    // Reject bare label selectors with no line filter — these scan too much data
    // and cause Loki timeouts on high-volume streams like windows-security.
    let has_line_filter = logql.contains("|=")
        || logql.contains("|~")
        || logql.contains("| json")
        || logql.contains("| logfmt");
    if !has_line_filter {
        return Ok(make_output(
            "Query rejected: bare label selector with no line filter (|= or |~) would scan \
             too much data and timeout. Add a filter like |= \"4769\" or |~ \"event_id\" \
             to narrow the results.",
        ));
    }

    let config = loki_config().await;
    let client = http_client();
    let url = format!("{}/loki/api/v1/query_range", config.base_url);

    let mut last_err: Option<String> = None;
    let mut retry_after: Option<std::time::Duration> = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = retry_after
                .take()
                .unwrap_or(RETRY_BASE_DELAY * 2u32.pow(attempt - 1));
            warn!(
                attempt,
                delay_ms = delay.as_millis() as u64,
                "Retrying Loki query after transient failure"
            );
            tokio::time::sleep(delay).await;
        }

        let resp = match build_get(client, &url, &config)
            .query(&[
                ("query", logql),
                ("start", start_time),
                ("end", end_time),
                ("limit", &limit.to_string()),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Connection or timeout error — retryable
                let msg = format!("Loki request failed: {e}");
                warn!(attempt, error = %e, "Loki request error (retryable)");
                last_err = Some(msg);
                continue;
            }
        };

        // Extract Retry-After before consuming the response body.
        let status = resp.status();
        retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(std::time::Duration::from_secs);

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("Loki response body read failed: {e}");
                warn!(attempt, error = %e, "Loki body read error (retryable)");
                last_err = Some(msg);
                continue;
            }
        };

        if status.is_success() {
            let formatted = format_loki_response(&body);
            if formatted != "No results found." {
                super::evidence_validator::store_query_result(&formatted);
            }
            return Ok(make_output(&formatted));
        }

        if is_retryable_status(status) {
            let msg = format!("Loki returned {status}: {body}");
            warn!(attempt, %status, "Loki transient error (retryable)");
            last_err = Some(msg);
            continue;
        }

        // Non-retryable error (400 bad query, 401 auth, etc.)
        return Ok(make_error(&format!("Loki returned {status}: {body}")));
    }

    // All retries exhausted
    let err_msg = last_err.unwrap_or_else(|| "Unknown error".to_string());
    Ok(make_error(&format!(
        "Loki query failed after {MAX_RETRIES} attempts: {err_msg}"
    )))
}

/// Query logs around a specific timestamp.
pub async fn query_logs_around_timestamp(args: &Value) -> Result<ToolOutput> {
    let logql = required_str(args, "logql")?;
    let timestamp = required_str(args, "timestamp")?;
    let window_minutes = optional_i64(args, "window_minutes").unwrap_or(15);
    let limit = optional_i64(args, "limit").unwrap_or(50);

    // Parse timestamp and compute window
    let ts = chrono::DateTime::parse_from_rfc3339(timestamp)
        .or_else(|_| chrono::DateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .unwrap_or_else(|_| chrono::Utc::now().into());

    let start = ts - chrono::Duration::minutes(window_minutes);
    let end = ts + chrono::Duration::minutes(window_minutes);

    let modified_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": end.to_rfc3339(),
        "limit": limit,
    });

    query_logs(&modified_args).await
}

/// Query logs with progressive time window expansion.
pub async fn query_logs_progressive(args: &Value) -> Result<ToolOutput> {
    let logql = required_str(args, "logql")?;
    let reference_timestamp = required_str(args, "reference_timestamp")?;
    let limit = optional_i64(args, "limit").unwrap_or(100);

    let ts = chrono::DateTime::parse_from_rfc3339(reference_timestamp)
        .unwrap_or_else(|_| chrono::Utc::now().into());

    // Progressive windows: 30min, 1h, 6h (24h removed — causes Loki timeouts)
    for window_minutes in [30, 60, 360] {
        let start = ts - chrono::Duration::minutes(window_minutes);
        let end = ts + chrono::Duration::minutes(window_minutes);

        let modified_args = serde_json::json!({
            "logql": logql,
            "start_time": start.to_rfc3339(),
            "end_time": end.to_rfc3339(),
            "limit": limit,
        });

        let result = query_logs(&modified_args).await?;
        if result.success && !result.stdout.is_empty() && result.stdout != "No results found." {
            return Ok(ToolOutput {
                stdout: format!(
                    "[Window: ±{}min from {}]\n{}",
                    window_minutes, reference_timestamp, result.stdout
                ),
                ..result
            });
        }
    }

    Ok(make_output(
        "No results found across all time windows (30min to 24h).",
    ))
}

/// Get label values from Loki.
pub async fn get_label_values(args: &Value) -> Result<ToolOutput> {
    let label = required_str(args, "label")?;

    let config = loki_config().await;
    let client = http_client();
    let resp = build_get(
        client,
        &format!("{}/loki/api/v1/label/{}/values", config.base_url, label),
        &config,
    )
    .send()
    .await
    .context("Failed to query Loki label values")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        return Ok(make_error(&format!("Loki returned {status}: {body}")));
    }

    // Parse and format values
    if let Ok(json) = serde_json::from_str::<Value>(&body) {
        if let Some(values) = json.get("data").and_then(|d| d.as_array()) {
            let formatted: Vec<&str> = values.iter().filter_map(|v| v.as_str()).collect();
            return Ok(make_output(&format!(
                "Label '{}' values ({} total):\n{}",
                label,
                formatted.len(),
                formatted.join("\n")
            )));
        }
    }

    Ok(make_output(&body))
}

/// Execute multiple LogQL queries in parallel.
pub async fn execute_parallel_queries(args: &Value) -> Result<ToolOutput> {
    let queries = args
        .get("queries")
        .and_then(|v| v.as_array())
        .context("queries must be an array")?;
    let start_time = required_str(args, "start_time")?;
    let end_time = required_str(args, "end_time")?;
    let limit = optional_i64(args, "limit").unwrap_or(50);

    // Cap at 5 queries, max 2 concurrent — Grafana proxy + Loki is slow (~25s/query)
    let queries: Vec<&Value> = queries.iter().take(5).collect();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    let mut handles = Vec::with_capacity(queries.len());

    for q in &queries {
        let logql = q
            .get("logql")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let desc = q
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed query")
            .to_string();
        let st = start_time.to_string();
        let et = end_time.to_string();
        let sem = semaphore.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let query_args = serde_json::json!({
                "logql": logql,
                "start_time": st,
                "end_time": et,
                "limit": limit,
            });
            let result = query_logs(&query_args).await;
            (desc, logql, result)
        }));
    }

    let mut output_parts = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((desc, logql, result)) => {
                let result_text = match result {
                    Ok(out) => {
                        if out.success {
                            out.stdout
                        } else {
                            format!("Error: {}", out.stderr)
                        }
                    }
                    Err(e) => format!("Error: {e}"),
                };
                output_parts.push(format!("### {desc}\nQuery: `{logql}`\n{result_text}\n",));
            }
            Err(e) => {
                output_parts.push(format!("### Query failed\nError: {e}\n"));
            }
        }
    }

    Ok(make_output(&output_parts.join("\n---\n\n")))
}

/// Query logs relative to NOW (not alert timestamp).
///
/// Convenience wrapper for investigating stale or ongoing alerts.
pub async fn query_logs_recent(args: &Value) -> Result<ToolOutput> {
    let logql = required_str(args, "logql")?;
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1);
    let limit = optional_i64(args, "limit").unwrap_or(100);

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let modified_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": limit,
    });

    query_logs(&modified_args).await
}

/// Combine multiple regex patterns into a single LogQL filter.
///
/// Takes a base log selector and list of patterns, returns a combined
/// LogQL query using `|~` regex alternation.
pub fn combine_query_patterns(args: &Value) -> Result<ToolOutput> {
    let base_selector = required_str(args, "base_selector")?;
    let patterns = args
        .get("patterns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing required argument: patterns"))?;

    if patterns.is_empty() {
        return Ok(make_error("patterns array must not be empty"));
    }

    let pattern_strs: Vec<&str> = patterns.iter().filter_map(|v| v.as_str()).collect();

    if pattern_strs.is_empty() {
        return Ok(make_error("patterns array must contain strings"));
    }

    // Escape special regex chars in patterns and join with |
    let combined = pattern_strs
        .iter()
        .map(|p| regex::escape(p))
        .collect::<Vec<_>>()
        .join("|");

    let query = format!("{base_selector} |~ \"(?i)({combined})\"");

    Ok(make_output(&format!(
        "Combined query ({} patterns):\n{query}",
        pattern_strs.len()
    )))
}

/// Format a Loki JSON response into readable text.
fn format_loki_response(body: &str) -> String {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };

    let result = json.get("data").and_then(|d| d.get("result"));
    let streams = match result.and_then(|r| r.as_array()) {
        Some(s) if !s.is_empty() => s,
        _ => return "No results found.".to_string(),
    };

    let mut lines = Vec::new();
    let mut total_entries = 0;

    for stream in streams {
        let labels = stream
            .get("stream")
            .and_then(|s| s.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        if let Some(values) = stream.get("values").and_then(|v| v.as_array()) {
            for entry in values {
                if let Some(arr) = entry.as_array() {
                    if arr.len() >= 2 {
                        let log_line = arr[1].as_str().unwrap_or("");
                        lines.push(format!("[{labels}] {log_line}"));
                        total_entries += 1;
                    }
                }
            }
        }
    }

    if lines.is_empty() {
        "No results found.".to_string()
    } else {
        format!(
            "Found {} log entries:\n\n{}",
            total_entries,
            lines.join("\n")
        )
    }
}
