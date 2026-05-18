//! Loki log query tools.
//!
//! HTTP-based queries against Loki's REST API for LogQL log retrieval.
//!
//! Configuration priority:
//! 1. `LOKI_URL` + `LOKI_AUTH_TOKEN` — direct Loki endpoint
//! 2. `GRAFANA_URL` + `GRAFANA_SERVICE_ACCOUNT_TOKEN` — Grafana datasource proxy
//!    (auto-resolves Loki datasource ID)
//! 3. `http://localhost:3100` fallback

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
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

/// TTL for cached query results (5 minutes). Historical log data is immutable,
/// so a short TTL is safe and eliminates duplicate queries within a single
/// investigation that re-query the same time range / event IDs.
const QUERY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Maximum cached entries.
const QUERY_CACHE_MAX: usize = 100;

struct CachedResult {
    output: ToolOutput,
    expires_at: std::time::Instant,
}

fn query_cache() -> &'static tokio::sync::Mutex<HashMap<u64, CachedResult>> {
    static CACHE: OnceLock<tokio::sync::Mutex<HashMap<u64, CachedResult>>> = OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::with_capacity(QUERY_CACHE_MAX)))
}

fn cache_key(logql: &str, start: &str, end: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    logql.hash(&mut hasher);
    start.hash(&mut hasher);
    end.hash(&mut hasher);
    hasher.finish()
}

/// Query logs from Loki using LogQL.
///
/// Results are cached for 5 minutes keyed on (logql, start_time, end_time) to
/// eliminate duplicate queries within a single investigation.
///
/// Retries up to 3 times on transient failures (timeouts, 429/502/503/504)
/// with exponential backoff (1s, 2s, 4s). Respects `Retry-After` header on 429s.
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

    // Check cache for identical query
    let key = cache_key(logql, start_time, end_time);
    {
        let cache = query_cache().lock().await;
        if let Some(cached) = cache.get(&key) {
            if cached.expires_at > std::time::Instant::now() {
                info!("Loki query cache hit");
                return Ok(cached.output.clone());
            }
        }
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
            let output = make_output(&formatted);

            // Cache the result
            let mut cache = query_cache().lock().await;
            if cache.len() >= QUERY_CACHE_MAX {
                let now = std::time::Instant::now();
                cache.retain(|_, v| v.expires_at > now);
            }
            cache.insert(
                key,
                CachedResult {
                    output: output.clone(),
                    expires_at: std::time::Instant::now() + QUERY_CACHE_TTL,
                },
            );

            return Ok(output);
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
/// Compute `(start, end)` for a fixed-width window centred on `timestamp`.
///
/// `timestamp` is parsed as RFC 3339 first, then the looser
/// `%Y-%m-%dT%H:%M:%S%.fZ` form. On parse failure the centre falls back to
/// "now" so the caller still gets a sensible window. Pure — no IO, no
/// dispatcher.
pub(crate) fn time_window_around(
    timestamp: &str,
    window_minutes: i64,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let ts: chrono::DateTime<chrono::Utc> = chrono::DateTime::parse_from_rfc3339(timestamp)
        .or_else(|_| chrono::DateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let start = ts - chrono::Duration::minutes(window_minutes);
    let end = ts + chrono::Duration::minutes(window_minutes);
    (start, end)
}

/// Compute a sliding `(start, end)` for "last `hours_back` hours from now".
pub(crate) fn time_window_recent(
    hours_back: i64,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);
    (start, now)
}

/// Combine N regex patterns into a single LogQL `|~ "(?i)(p1|p2|...)"` filter
/// glued onto `base_selector`. Each pattern is escaped before joining so
/// pattern-internal `|`/`(`/`.` characters can't break out of the alternation.
///
/// Returns `Err(msg)` when `patterns` is empty (caller surfaces as a tool
/// error). Pure — used by `combine_query_patterns`.
pub(crate) fn build_combined_logql_query(
    base_selector: &str,
    patterns: &[&str],
) -> std::result::Result<String, &'static str> {
    if patterns.is_empty() {
        return Err("patterns array must not be empty");
    }
    let combined = patterns
        .iter()
        .map(|p| regex::escape(p))
        .collect::<Vec<_>>()
        .join("|");
    Ok(format!("{base_selector} |~ \"(?i)({combined})\""))
}

pub async fn query_logs_around_timestamp(args: &Value) -> Result<ToolOutput> {
    let logql = required_str(args, "logql")?;
    let timestamp = required_str(args, "timestamp")?;
    let window_minutes = optional_i64(args, "window_minutes").unwrap_or(15);
    let limit = optional_i64(args, "limit").unwrap_or(50);

    let (start, end) = time_window_around(timestamp, window_minutes);

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
        "No results found across all time windows (30min to 6h).",
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

    let (start, end) = time_window_recent(hours_back);

    let modified_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": end.to_rfc3339(),
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

    let pattern_strs: Vec<&str> = patterns.iter().filter_map(|v| v.as_str()).collect();
    if pattern_strs.is_empty() {
        return Ok(make_error(if patterns.is_empty() {
            "patterns array must not be empty"
        } else {
            "patterns array must contain strings"
        }));
    }

    let query = match build_combined_logql_query(base_selector, &pattern_strs) {
        Ok(q) => q,
        Err(msg) => return Ok(make_error(msg)),
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── format_loki_response ────────────────────────────────────────

    #[test]
    fn format_loki_response_no_results() {
        let body = r#"{"status":"success","data":{"resultType":"streams","result":[]}}"#;
        assert_eq!(format_loki_response(body), "No results found.");
    }

    #[test]
    fn format_loki_response_invalid_json() {
        let body = "not json";
        assert_eq!(format_loki_response(body), "not json");
    }

    #[test]
    fn format_loki_response_missing_data() {
        let body = r#"{"status":"success"}"#;
        assert_eq!(format_loki_response(body), "No results found.");
    }

    #[test]
    fn format_loki_response_with_entries() {
        let body = serde_json::to_string(&json!({
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [{
                    "stream": {"job": "windows", "host": "dc01"},
                    "values": [
                        ["1234567890000000000", "Event 4769: Kerberos service ticket requested"],
                        ["1234567890000000001", "Event 4624: Logon success"]
                    ]
                }]
            }
        }))
        .unwrap();
        let result = format_loki_response(&body);
        assert!(result.starts_with("Found 2 log entries:"));
        assert!(result.contains("Event 4769"));
        assert!(result.contains("Event 4624"));
        assert!(result.contains("job=windows"));
    }

    #[test]
    fn format_loki_response_multiple_streams() {
        let body = serde_json::to_string(&json!({
            "data": {
                "result": [
                    {"stream": {"host": "dc01"}, "values": [["1", "line1"]]},
                    {"stream": {"host": "web01"}, "values": [["2", "line2"]]}
                ]
            }
        }))
        .unwrap();
        let result = format_loki_response(&body);
        assert!(result.starts_with("Found 2 log entries:"));
        assert!(result.contains("host=dc01"));
        assert!(result.contains("host=web01"));
    }

    #[test]
    fn format_loki_response_empty_values() {
        let body = serde_json::to_string(&json!({
            "data": {
                "result": [{"stream": {"job": "test"}, "values": []}]
            }
        }))
        .unwrap();
        assert_eq!(format_loki_response(&body), "No results found.");
    }

    // ── is_retryable_status ─────────────────────────────────────────

    #[test]
    fn retryable_statuses() {
        use reqwest::StatusCode;
        assert!(is_retryable_status(StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn non_retryable_statuses() {
        use reqwest::StatusCode;
        assert!(!is_retryable_status(StatusCode::OK));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    // ── cache_key ───────────────────────────────────────────────────

    #[test]
    fn cache_key_deterministic() {
        let k1 = cache_key(
            "{job=\"test\"}",
            "2024-01-01T00:00:00Z",
            "2024-01-02T00:00:00Z",
        );
        let k2 = cache_key(
            "{job=\"test\"}",
            "2024-01-01T00:00:00Z",
            "2024-01-02T00:00:00Z",
        );
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_varies_by_query() {
        let k1 = cache_key("{job=\"a\"}", "start", "end");
        let k2 = cache_key("{job=\"b\"}", "start", "end");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_varies_by_time() {
        let k1 = cache_key("query", "start1", "end");
        let k2 = cache_key("query", "start2", "end");
        assert_ne!(k1, k2);
    }

    // ── make_output / make_error ────────────────────────────────────

    #[test]
    fn make_output_success() {
        let out = make_output("hello");
        assert!(out.success);
        assert_eq!(out.stdout, "hello");
        assert!(out.stderr.is_empty());
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn make_error_failure() {
        let out = make_error("boom");
        assert!(!out.success);
        assert!(out.stdout.is_empty());
        assert_eq!(out.stderr, "boom");
        assert_eq!(out.exit_code, Some(1));
    }

    // ── combine_query_patterns ──────────────────────────────────────

    #[test]
    fn combine_query_patterns_single_pattern() {
        let args = json!({
            "base_selector": "{job=\"windows\"}",
            "patterns": ["4769"]
        });
        let result = combine_query_patterns(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("1 patterns"));
        assert!(result.stdout.contains("{job=\"windows\"}"));
        assert!(result.stdout.contains("4769"));
    }

    #[test]
    fn combine_query_patterns_multiple() {
        let args = json!({
            "base_selector": "{job=\"windows\"}",
            "patterns": ["4769", "4624", "4625"]
        });
        let result = combine_query_patterns(&args).unwrap();
        assert!(result.stdout.contains("3 patterns"));
    }

    #[test]
    fn combine_query_patterns_empty_array() {
        let args = json!({
            "base_selector": "{job=\"windows\"}",
            "patterns": []
        });
        let result = combine_query_patterns(&args).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn combine_query_patterns_missing_patterns() {
        let args = json!({"base_selector": "{job=\"windows\"}"});
        assert!(combine_query_patterns(&args).is_err());
    }

    #[test]
    fn combine_query_patterns_escapes_regex() {
        let args = json!({
            "base_selector": "{job=\"test\"}",
            "patterns": ["foo.bar", "baz(qux)"]
        });
        let result = combine_query_patterns(&args).unwrap();
        // Dots and parens should be escaped
        assert!(result.stdout.contains("foo\\.bar"));
        assert!(result.stdout.contains("baz\\(qux\\)"));
    }

    // ── tests for new pure helpers ────────────────────────────────────

    #[test]
    fn time_window_around_rfc3339_centred_window() {
        let (s, e) = time_window_around("2026-01-15T12:00:00Z", 15);
        // 15 minutes either side → s = 11:45, e = 12:15.
        assert_eq!(s.to_rfc3339(), "2026-01-15T11:45:00+00:00");
        assert_eq!(e.to_rfc3339(), "2026-01-15T12:15:00+00:00");
    }

    #[test]
    fn time_window_around_zero_window_collapses_to_point() {
        let (s, e) = time_window_around("2026-01-15T12:00:00Z", 0);
        assert_eq!(s, e);
    }

    #[test]
    fn time_window_around_accepts_fractional_seconds_form() {
        // Secondary parse format: %Y-%m-%dT%H:%M:%S%.fZ
        let (s, e) = time_window_around("2026-01-15T12:00:00.123Z", 30);
        // Both timestamps must be in the same minute-30 spread around 12:00:00.123.
        let span = e - s;
        assert_eq!(span, chrono::Duration::minutes(60));
    }

    #[test]
    fn time_window_around_garbage_falls_back_to_now() {
        // Unparsable input falls back to "now" — we just check the window
        // has the requested width.
        let (s, e) = time_window_around("not a timestamp", 5);
        let span = e - s;
        assert_eq!(span, chrono::Duration::minutes(10));
    }

    #[test]
    fn time_window_recent_returns_now_plus_back() {
        let (s, e) = time_window_recent(2);
        let span = e - s;
        assert_eq!(span, chrono::Duration::hours(2));
    }

    #[test]
    fn build_combined_logql_query_basic() {
        let q = build_combined_logql_query("{job=\"app\"}", &["alpha", "beta"]).unwrap();
        assert_eq!(q, r#"{job="app"} |~ "(?i)(alpha|beta)""#);
    }

    #[test]
    fn build_combined_logql_query_escapes_regex_metachars() {
        let q = build_combined_logql_query("{}", &["foo.bar", "(x|y)"]).unwrap();
        assert!(q.contains("foo\\.bar"));
        assert!(q.contains("\\(x\\|y\\)"));
    }

    #[test]
    fn build_combined_logql_query_empty_patterns_returns_err() {
        let err = build_combined_logql_query("{}", &[]).unwrap_err();
        assert!(err.contains("not be empty"));
    }

    #[test]
    fn build_combined_logql_query_preserves_alternation_grouping() {
        // Each pattern goes in its own alternation slot; verify the
        // outermost `(?i)(...)` wrapper.
        let q = build_combined_logql_query("{j=\"\"}", &["one", "two", "three"]).unwrap();
        assert!(q.ends_with(r#"(?i)(one|two|three)""#));
    }
}
