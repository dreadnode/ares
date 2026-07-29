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

use crate::args::{optional_i64, optional_str, required_str};
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

/// Per-attempt request timeout, from `LOKI_TIMEOUT_SECS`.
pub(crate) fn request_timeout_secs() -> u64 {
    std::env::var("LOKI_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(90)
}

pub(crate) fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(request_timeout_secs()))
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
pub(crate) const MAX_RETRIES: u32 = 3;

/// Base backoff delay between retries.
pub(crate) const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Total wall-clock a single Loki query may consume across all of its attempts,
/// from `LOKI_QUERY_BUDGET_SECS` (defaults to one attempt's timeout).
///
/// `MAX_RETRIES` alone bounds the attempt *count*, not the time. A query that
/// exhausts the full request timeout on every attempt therefore occupied
/// `MAX_RETRIES * LOKI_TIMEOUT_SECS` — 270s at the defaults. The detection
/// sweep runs the catalog with a fixed concurrency under an overall cap, so
/// three such queries wedged half its slots for 75% of the budget and starved
/// the rest of the catalog, which then reported as `not_run`.
///
/// Retrying a request that already burned a full timeout is also the least
/// likely retry to succeed, so the default budget deliberately equals one
/// attempt: fast failures (connect refused, 503) still get their retries,
/// a hung query does not get two more.
pub(crate) fn query_budget() -> std::time::Duration {
    let secs = std::env::var("LOKI_QUERY_BUDGET_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or_else(request_timeout_secs);
    std::time::Duration::from_secs(secs)
}

/// Wall-clock guard shared by the query retry loops.
pub(crate) struct RetryBudget {
    deadline: tokio::time::Instant,
}

impl RetryBudget {
    pub(crate) fn new() -> Self {
        Self::with_budget(query_budget())
    }

    fn with_budget(budget: std::time::Duration) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + budget,
        }
    }

    fn remaining(&self) -> Option<std::time::Duration> {
        let now = tokio::time::Instant::now();
        (now < self.deadline).then(|| self.deadline - now)
    }

    /// Wait out this attempt's backoff, then hand back the time it may use.
    ///
    /// The result is clamped to the per-attempt request timeout so raising
    /// `LOKI_QUERY_BUDGET_SECS` buys more retries rather than one longer hang.
    ///
    /// `delay_override` carries a server-supplied `Retry-After`. `None` means
    /// the budget is spent and the caller must stop retrying — either because
    /// it is already gone or because the backoff alone would outlast it.
    pub(crate) async fn begin_attempt(
        &self,
        attempt: u32,
        delay_override: Option<std::time::Duration>,
    ) -> Option<std::time::Duration> {
        if attempt > 0 {
            let backoff = delay_override.unwrap_or(RETRY_BASE_DELAY * 2u32.pow(attempt - 1));
            let remaining = self.remaining()?;
            if backoff >= remaining {
                return None;
            }
            warn!(
                attempt,
                delay_ms = backoff.as_millis() as u64,
                "Retrying Loki query after transient failure"
            );
            tokio::time::sleep(backoff).await;
        }
        self.remaining()
            .map(|r| r.min(std::time::Duration::from_secs(request_timeout_secs())))
    }
}

/// Error text for a query that ran out of wall-clock rather than attempts.
pub(crate) fn budget_exhausted_err(last_err: Option<String>) -> String {
    match last_err {
        Some(e) => format!(
            "exceeded the {}s query budget: {e}",
            query_budget().as_secs()
        ),
        None => format!("exceeded the {}s query budget", query_budget().as_secs()),
    }
}

/// Check whether an HTTP status code is transient and worth retrying.
pub(crate) fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
}

/// Format an error with its full source chain.
/// reqwest's Display for send errors only prints "error sending request for
/// url (…)" and drops the actual cause (DNS/TLS/timeout). Walking `.source()`
/// surfaces the underlying reason so the operator can tell "DNS failed" from
/// "cert expired" from "connection refused".
fn err_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(src) = cur {
        out.push_str(": ");
        out.push_str(&src.to_string());
        cur = src.source();
    }
    out
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
/// In the unfolding replay modes, cap a query's `end_time` at the replay clock so
/// the blue agent can never retrieve events from its own future. Returns the
/// input unchanged when not clamping (live, `static`, or legacy-frozen replay) or
/// when the timestamp can't be parsed.
pub(crate) fn clamp_end_to_replay(end: &str) -> String {
    let Some(ceiling) = super::replay_clock::replay_clamp_end() else {
        return end.to_string();
    };
    match chrono::DateTime::parse_from_rfc3339(end.trim()) {
        Ok(dt) if dt.with_timezone(&chrono::Utc) > ceiling => ceiling.to_rfc3339(),
        _ => end.to_string(),
    }
}

/// True when the (clamped) query window lies entirely at/after the replay clock —
/// the attack hasn't reached it yet, so there's nothing to return.
pub(crate) fn replay_window_is_future(start: &str, clamped_end: &str) -> bool {
    if super::replay_clock::replay_clamp_end().is_none() {
        return false;
    }
    match (
        chrono::DateTime::parse_from_rfc3339(start.trim()),
        chrono::DateTime::parse_from_rfc3339(clamped_end.trim()),
    ) {
        (Ok(s), Ok(e)) => s >= e,
        _ => false,
    }
}

pub async fn query_logs(args: &Value) -> Result<ToolOutput> {
    let logql = required_str(args, "logql")?;
    let start_time = required_str(args, "start_time")?;
    let end_time_arg = required_str(args, "end_time")?;
    // Replay: cap the end at the replay clock so the agent can't see its future.
    let end_time_clamped = clamp_end_to_replay(end_time_arg);
    if replay_window_is_future(start_time, &end_time_clamped) {
        return Ok(make_output(
            "No results — that window is at or after the current replay time; \
             the attack hasn't reached that point yet.",
        ));
    }
    let end_time = end_time_clamped.as_str();
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
    let mut attempts_made = 0u32;
    let budget = RetryBudget::new();

    for attempt in 0..MAX_RETRIES {
        let Some(remaining) = budget.begin_attempt(attempt, retry_after.take()).await else {
            last_err = Some(budget_exhausted_err(last_err));
            break;
        };
        attempts_made = attempt + 1;

        let resp = match build_get(client, &url, &config)
            .timeout(remaining)
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
                // A builder error means the request could not even be
                // constructed — a malformed base URL or an invalid header
                // value (e.g. a GRAFANA_URL / auth token with a stray newline).
                // It is deterministic, so retrying re-fails identically; fail
                // fast and point the operator at the config instead of burning
                // MAX_RETRIES rounds of backoff.
                if e.is_builder() {
                    warn!(
                        error = err_chain(&e),
                        "Loki request construction failed (non-retryable)"
                    );
                    return Ok(make_error(&format!(
                        "Loki request could not be constructed \
                         (check GRAFANA_URL / LOKI_URL and auth token for invalid \
                         characters such as a trailing newline): {e}"
                    )));
                }
                // Only genuine transport failures are worth retrying.
                if e.is_connect() || e.is_timeout() {
                    let chain = err_chain(&e);
                    warn!(attempt, error = %chain, "Loki request error (retryable)");
                    last_err = Some(format!("Loki request failed: {chain}"));
                    continue;
                }
                // Anything else (redirect loops, decode, etc.) is not
                // transient — surface it without wasting retry attempts.
                let chain = err_chain(&e);
                warn!(error = %chain, "Loki request error (non-retryable)");
                return Ok(make_error(&format!("Loki request failed: {chain}")));
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
                let chain = err_chain(&e);
                warn!(attempt, error = %chain, "Loki body read error (retryable)");
                last_err = Some(format!("Loki response body read failed: {chain}"));
                continue;
            }
        };

        if status.is_success() {
            let formatted = format_loki_response(&body);
            if formatted != "No results found." {
                // `evidence_source` is set by internal callers that know how the
                // query was produced; it is not in the published tool schema, so
                // a free-form analyst query falls through to the analyst label.
                super::evidence_validator::store_query_result_from(
                    &formatted,
                    optional_str(args, "evidence_source")
                        .unwrap_or(super::evidence_validator::ANALYST_QUERY_SOURCE),
                );
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
        "Loki query failed after {attempts_made} attempt(s): {err_msg}"
    )))
}

/// A single series from a metric query: its grouping labels and its sample.
pub type MetricSeries = (std::collections::BTreeMap<String, String>, u64);

/// Run a LogQL **metric** query as an instant query, returning every series'
/// label set paired with its sample.
///
/// [`query_logs`] cannot answer this shape of question: `format_loki_response`
/// renders `streams` results and drops the `metric` label set, so an
/// aggregation like `sum by (user) (count_over_time(…))` comes back as bare
/// numbers with the grouping key — the thing being asked for — discarded.
///
/// An instant query also sidesteps the line `limit`: it yields one sample per
/// series however many events back it, so a whole-window account set costs a
/// few dozen rows instead of thousands of multi-KB log lines that would
/// truncate at 100 and silently under-report.
///
/// The whole label set is returned rather than one chosen key because
/// correlating Windows events usually needs a compound identity — an account
/// name alone is ambiguous across domains in a multi-domain forest.
///
/// Transport and HTTP failures return `Err` rather than an empty vector, so
/// callers can tell "the query broke" from "there genuinely are no series".
/// That distinction matters wherever an empty result would otherwise read as a
/// finding.
pub async fn query_metric_series(logql: &str, at: Option<&str>) -> Result<Vec<MetricSeries>> {
    let config = loki_config().await;
    let client = http_client();
    let url = format!("{}/loki/api/v1/query", config.base_url);

    let mut params = vec![("query", logql.to_string())];
    match at {
        // Cap a caller-supplied instant at the replay clock so the agent can't
        // sample its own future; a no-op outside the unfolding replay modes.
        Some(t) => params.push(("time", clamp_end_to_replay(t))),
        // Pin an omitted instant to the replay clock so "now" resolves to
        // attack-time rather than the server's wall clock.
        None => {
            if super::replay_clock::is_replay() {
                params.push(("time", super::replay_clock::replay_now().to_rfc3339()));
            }
        }
    }

    let mut last_err: Option<String> = None;
    let mut attempts_made = 0u32;
    let budget = RetryBudget::new();
    for attempt in 0..MAX_RETRIES {
        let Some(remaining) = budget.begin_attempt(attempt, None).await else {
            last_err = Some(budget_exhausted_err(last_err));
            break;
        };
        attempts_made = attempt + 1;

        let resp = match build_get(client, &url, &config)
            .timeout(remaining)
            .query(&params)
            .send()
            .await
        {
            Ok(r) => r,
            // Only genuine transport failures are worth retrying; a builder or
            // decode error re-fails identically.
            Err(e) if e.is_connect() || e.is_timeout() => {
                let chain = err_chain(&e);
                warn!(attempt, error = %chain, "Loki metric request error (retryable)");
                last_err = Some(format!("Loki request failed: {chain}"));
                continue;
            }
            Err(e) => anyhow::bail!("Loki request failed: {}", err_chain(&e)),
        };

        let status = resp.status();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                let chain = err_chain(&e);
                last_err = Some(format!("Loki response body read failed: {chain}"));
                continue;
            }
        };

        if status.is_success() {
            return parse_metric_series(&body);
        }
        if is_retryable_status(status) {
            warn!(attempt, %status, "Loki metric transient error (retryable)");
            last_err = Some(format!("Loki returned {status}: {body}"));
            continue;
        }
        anyhow::bail!("Loki returned {status}: {body}");
    }

    Err(anyhow::anyhow!(
        "Loki metric query failed after {attempts_made} attempt(s): {}",
        last_err.unwrap_or_else(|| "unknown error".to_string())
    ))
}

/// Pull `(labels, sample)` pairs out of a Loki instant-query body.
///
/// A body that parses but carries no `data.result` array is an empty result,
/// not an error — Loki answers that way for a query that matched nothing.
/// Series with no labels at all are dropped: they carry no identity, so
/// nothing can be concluded from them.
fn parse_metric_series(body: &str) -> Result<Vec<MetricSeries>> {
    let json: Value = serde_json::from_str(body).context("Loki returned a non-JSON body")?;
    let Some(results) = json
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
    else {
        return Ok(Vec::new());
    };

    Ok(results
        .iter()
        .filter_map(|series| {
            let labels: std::collections::BTreeMap<String, String> = series
                .get("metric")?
                .as_object()?
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect();
            if labels.is_empty() {
                return None;
            }
            // Instant-query samples are `[timestamp, "value"]`, value stringified.
            let sample = series
                .get("value")
                .and_then(|v| v.as_array())
                .and_then(|pair| pair.get(1))
                .and_then(|v| v.as_str())
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0);
            Some((labels, sample.max(0.0) as u64))
        })
        .collect())
}

/// A matched log line: when the event actually happened, its stream labels,
/// and the raw line.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub labels: std::collections::BTreeMap<String, String>,
    pub line: String,
}

/// Run a LogQL **log** query, returning entries with their event timestamps.
///
/// [`query_logs`] renders a human-readable blob and drops `values[i][0]` — the
/// nanosecond event timestamp — along with the per-stream labels. A caller that
/// needs to know *when* the matched activity happened cannot recover it from
/// that text.
///
/// Detection correlation needs exactly that. A detection stamped at query time
/// says nothing about whether it followed the attacker action it is credited
/// to, and a whole sweep's worth of hits collapses onto a single instant, which
/// makes time-to-detect meaningless.
///
/// Transport and HTTP failures return `Err` rather than an empty vector, so a
/// broken query stays distinguishable from a genuine no-match.
pub async fn query_log_entries(
    logql: &str,
    start_time: &str,
    end_time: &str,
    limit: i64,
) -> Result<Vec<LogEntry>> {
    let config = loki_config().await;
    let client = http_client();
    let url = format!("{}/loki/api/v1/query_range", config.base_url);
    let end_clamped = clamp_end_to_replay(end_time);

    let params = [
        ("query", logql.to_string()),
        ("start", start_time.to_string()),
        ("end", end_clamped),
        ("limit", limit.to_string()),
    ];

    let mut last_err: Option<String> = None;
    let mut attempts_made = 0u32;
    let budget = RetryBudget::new();
    for attempt in 0..MAX_RETRIES {
        let Some(remaining) = budget.begin_attempt(attempt, None).await else {
            last_err = Some(budget_exhausted_err(last_err));
            break;
        };
        attempts_made = attempt + 1;

        let resp = match build_get(client, &url, &config)
            .timeout(remaining)
            .query(&params)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if e.is_connect() || e.is_timeout() => {
                let chain = err_chain(&e);
                warn!(attempt, error = %chain, "Loki entry request error (retryable)");
                last_err = Some(format!("Loki request failed: {chain}"));
                continue;
            }
            Err(e) => anyhow::bail!("Loki request failed: {}", err_chain(&e)),
        };

        let status = resp.status();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                let chain = err_chain(&e);
                last_err = Some(format!("Loki response body read failed: {chain}"));
                continue;
            }
        };

        if status.is_success() {
            return parse_log_entries(&body);
        }
        if is_retryable_status(status) {
            warn!(attempt, %status, "Loki entry transient error (retryable)");
            last_err = Some(format!("Loki returned {status}: {body}"));
            continue;
        }
        anyhow::bail!("Loki returned {status}: {body}");
    }

    Err(anyhow::anyhow!(
        "Loki log-entry query failed after {attempts_made} attempt(s): {}",
        last_err.unwrap_or_else(|| "unknown error".to_string())
    ))
}

/// Pull `(timestamp, labels, line)` triples out of a Loki `streams` body.
///
/// A body that parses but carries no `data.result` array is an empty result,
/// not an error. Entries whose timestamp is absent or unparsable are dropped
/// rather than defaulted to "now": a fabricated timestamp would silently
/// corrupt the ordering checks this function exists to enable.
fn parse_log_entries(body: &str) -> Result<Vec<LogEntry>> {
    let json: Value = serde_json::from_str(body).context("Loki returned a non-JSON body")?;
    let Some(results) = json
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
    else {
        return Ok(Vec::new());
    };

    let mut entries = Vec::new();
    for stream in results {
        let labels: std::collections::BTreeMap<String, String> = stream
            .get("stream")
            .and_then(|s| s.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let Some(values) = stream.get("values").and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in values {
            let Some(arr) = entry.as_array() else {
                continue;
            };
            let (Some(ts_raw), Some(line)) = (
                arr.first().and_then(|v| v.as_str()),
                arr.get(1).and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let Some(timestamp) = parse_epoch_nanos(ts_raw) else {
                continue;
            };
            entries.push(LogEntry {
                timestamp,
                labels: labels.clone(),
                line: line.to_string(),
            });
        }
    }
    entries.sort_by_key(|e| e.timestamp);
    Ok(entries)
}

/// Convert Loki's stringified nanosecond epoch into a UTC datetime.
fn parse_epoch_nanos(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let ns: i64 = raw.trim().parse().ok()?;
    chrono::DateTime::from_timestamp(
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000) as u32,
    )
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
        .unwrap_or_else(|_| super::replay_clock::replay_now());
    let start = ts - chrono::Duration::minutes(window_minutes);
    let end = ts + chrono::Duration::minutes(window_minutes);
    (start, end)
}

/// Compute a sliding `(start, end)` for "last `hours_back` hours from now".
///
/// "Now" is the replay clock ([`super::replay_clock::replay_now`]): wall-clock
/// during a live investigation, or the attack-time anchor during a replay so
/// stale-alert / "recent" queries land on the captured window.
pub(crate) fn time_window_recent(
    hours_back: i64,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let now = super::replay_clock::replay_now();
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
        .unwrap_or_else(|_| super::replay_clock::replay_now().into());

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
    use std::time::Duration;

    #[tokio::test]
    async fn first_attempt_gets_the_whole_budget() {
        let budget = RetryBudget::with_budget(Duration::from_secs(60));
        let remaining = budget
            .begin_attempt(0, None)
            .await
            .expect("budget available");
        assert!(remaining <= Duration::from_secs(60));
        assert!(remaining > Duration::from_secs(55));
    }

    #[tokio::test]
    async fn spent_budget_refuses_the_first_attempt() {
        let budget = RetryBudget::with_budget(Duration::ZERO);
        assert_eq!(budget.begin_attempt(0, None).await, None);
    }

    #[tokio::test]
    async fn backoff_longer_than_remaining_stops_retrying() {
        // The regression: a query that burned its whole timeout must not sleep
        // out a backoff and then start another full-length attempt.
        let budget = RetryBudget::with_budget(Duration::from_millis(200));
        let started = std::time::Instant::now();
        assert_eq!(budget.begin_attempt(1, None).await, None);
        assert!(
            started.elapsed() < RETRY_BASE_DELAY,
            "must refuse without sleeping the backoff"
        );
    }

    #[tokio::test]
    async fn retry_after_override_is_honoured_when_it_fits() {
        let budget = RetryBudget::with_budget(Duration::from_secs(30));
        let started = std::time::Instant::now();
        let remaining = budget
            .begin_attempt(1, Some(Duration::from_millis(40)))
            .await
            .expect("budget available");
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(remaining < Duration::from_secs(30));
    }

    #[tokio::test]
    async fn retry_after_longer_than_budget_stops_retrying() {
        let budget = RetryBudget::with_budget(Duration::from_millis(50));
        assert_eq!(
            budget
                .begin_attempt(1, Some(Duration::from_secs(120)))
                .await,
            None
        );
    }

    #[tokio::test]
    async fn attempt_never_outlasts_the_per_attempt_timeout() {
        // A generous budget must buy more retries, not one longer hang.
        let budget = RetryBudget::with_budget(Duration::from_secs(3600));
        let remaining = budget
            .begin_attempt(0, None)
            .await
            .expect("budget available");
        assert!(remaining <= Duration::from_secs(request_timeout_secs()));
    }

    #[test]
    fn budget_exhausted_err_keeps_the_underlying_cause() {
        let msg = budget_exhausted_err(Some("operation timed out".to_string()));
        assert!(msg.contains("operation timed out"), "{msg}");
        assert!(msg.contains("query budget"), "{msg}");
    }

    #[test]
    fn budget_exhausted_err_without_cause_still_names_the_budget() {
        assert!(budget_exhausted_err(None).contains("query budget"));
    }

    fn vector_body(series: Value) -> String {
        serde_json::to_string(&json!({
            "status": "success",
            "data": {"resultType": "vector", "result": series}
        }))
        .unwrap()
    }

    fn labels_of(s: &MetricSeries) -> Vec<(&str, &str)> {
        s.0.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn parse_metric_series_keeps_every_grouping_label() {
        // The compound key matters: an account name alone is ambiguous across
        // domains, so all grouping labels must survive parsing.
        let body = vector_body(json!([
            {"metric": {"account": "alice", "domain": "north"}, "value": [1234567890, "7"]},
        ]));
        let parsed = parse_metric_series(&body).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            labels_of(&parsed[0]),
            vec![("account", "alice"), ("domain", "north")]
        );
        assert_eq!(parsed[0].1, 7);
    }

    #[test]
    fn parse_metric_series_drops_unlabelled_series() {
        // Lines the LogQL parser didn't match aggregate into a series with no
        // labels; they carry no identity, so nothing can be concluded.
        let body = vector_body(json!([
            {"metric": {}, "value": [1234567890, "9"]},
            {"metric": {"account": "carol"}, "value": [1234567890, "1"]},
        ]));
        let parsed = parse_metric_series(&body).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(labels_of(&parsed[0]), vec![("account", "carol")]);
    }

    #[test]
    fn parse_metric_series_empty_result_is_not_an_error() {
        assert!(parse_metric_series(&vector_body(json!([])))
            .unwrap()
            .is_empty());
        assert!(parse_metric_series(r#"{"status":"success"}"#)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn parse_metric_series_rejects_non_json() {
        // Must be an error, not an empty set: a proxy error page read as "no
        // series" would let a caller draw a conclusion from a broken query.
        assert!(parse_metric_series("<html>502 Bad Gateway</html>").is_err());
    }

    #[test]
    fn parse_metric_series_tolerates_missing_sample() {
        let body = vector_body(json!([{"metric": {"account": "dave"}}]));
        assert_eq!(parse_metric_series(&body).unwrap()[0].1, 0);
    }

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

    fn streams_body(values: serde_json::Value) -> String {
        serde_json::to_string(&json!({
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [{
                    "stream": {"job": "windows-security", "hostname": "dc01.contoso.local"},
                    "values": values
                }]
            }
        }))
        .unwrap()
    }

    #[test]
    fn parse_log_entries_keeps_event_time_and_labels() {
        let body = streams_body(json!([["1700000000000000000", "Event 4662: DCSync"]]));
        let entries = parse_log_entries(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].timestamp.timestamp(), 1_700_000_000);
        assert_eq!(entries[0].line, "Event 4662: DCSync");
        assert_eq!(
            entries[0].labels.get("hostname").map(String::as_str),
            Some("dc01.contoso.local")
        );
    }

    #[test]
    fn parse_log_entries_sorts_chronologically() {
        let body = streams_body(json!([
            ["1700000600000000000", "later"],
            ["1700000000000000000", "earlier"],
        ]));
        let entries = parse_log_entries(&body).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.line.as_str()).collect::<Vec<_>>(),
            vec!["earlier", "later"]
        );
    }

    #[test]
    fn parse_log_entries_drops_unparsable_timestamps() {
        let body = streams_body(json!([
            ["not-a-number", "dropped"],
            ["1700000000000000000", "kept"],
        ]));
        let entries = parse_log_entries(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line, "kept");
    }

    #[test]
    fn parse_log_entries_empty_without_result() {
        let body = serde_json::to_string(&json!({"status": "success", "data": {}})).unwrap();
        assert!(parse_log_entries(&body).unwrap().is_empty());
    }

    #[test]
    fn parse_log_entries_errors_on_non_json() {
        assert!(parse_log_entries("<html>502</html>").is_err());
    }

    #[test]
    fn parse_epoch_nanos_handles_sub_second() {
        let ts = parse_epoch_nanos("1700000000123456789").unwrap();
        assert_eq!(ts.timestamp(), 1_700_000_000);
        assert_eq!(ts.timestamp_subsec_nanos(), 123_456_789);
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
