//! Bulk Loki export/import for benchmark snapshots.
//!
//! Unlike the query functions in [`super::loki`] (which are agent tool calls
//! with 100-entry caps, bare-selector rejection, and caching), these functions
//! are library functions for complete stream extraction and replay injection.
//!
//! # Export format
//!
//! Each JSONL line is a Loki push-format object:
//! ```json
//! {"stream":{"job":"windows-security","host":"DC01"},"values":[["1719403200000000000","<Event ...>"]]}
//! ```
//!
//! This format is directly accepted by [`import_stream`] and Loki's
//! `POST /loki/api/v1/push` endpoint — no transformation needed.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::loki::{http_client, is_retryable_status, MAX_RETRIES, RETRY_BASE_DELAY};

/// Configuration for bulk Loki operations.
///
/// Separate from the private `LokiConfig` in `loki.rs` because callers
/// (the CLI benchmark module) need to construct this directly.
#[derive(Clone, Debug)]
pub struct BulkLokiConfig {
    pub base_url: String,
    pub auth_token: Option<String>,
}

impl BulkLokiConfig {
    /// Build from environment variables, matching `loki.rs` priority:
    /// 1. `LOKI_URL` + `LOKI_AUTH_TOKEN`
    /// 2. `http://localhost:3100` fallback
    ///
    /// Does NOT resolve the Grafana proxy — bulk operations should target
    /// Loki directly to avoid proxy timeouts on large exports.
    pub fn from_env() -> Self {
        let base_url =
            std::env::var("LOKI_URL").unwrap_or_else(|_| "http://localhost:3100".to_string());
        let auth_token = std::env::var("LOKI_AUTH_TOKEN").ok();
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token,
        }
    }

    fn build_request(&self, client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
        let mut req = client.get(url);
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        req
    }

    fn build_post(&self, client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
        let mut req = client.post(url);
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        req
    }
}

/// A single push-format entry: one stream with its values.
#[derive(Serialize, Deserialize, Debug)]
struct PushEntry {
    stream: serde_json::Map<String, serde_json::Value>,
    values: Vec<Vec<String>>,
}

/// Maximum entries per query_range page during export.
const EXPORT_PAGE_LIMIT: u64 = 5000;

/// Default batch size for import (entries per push request).
const DEFAULT_IMPORT_BATCH: usize = 2000;

/// Paginated forward-scan through `query_range`, writing push-format JSONL.
///
/// Returns the total number of log entries exported. Each output line is a
/// JSON object with `{"stream":{...},"values":[["ns_timestamp","log_line"]]}`
/// — directly compatible with [`import_stream`].
///
/// Pagination advances `start` to `last_timestamp_nanos + 1` after each page.
/// Stops when a page returns zero entries or `start >= end`.
pub async fn export_stream(
    config: &BulkLokiConfig,
    logql: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    writer: &mut (impl Write + Send),
) -> Result<u64> {
    let client = http_client();
    let url = format!("{}/loki/api/v1/query_range", config.base_url);
    let end_nanos = format!("{}", end.timestamp_nanos_opt().unwrap_or(0));

    let mut current_start_nanos = start.timestamp_nanos_opt().unwrap_or(0);
    let mut total_entries: u64 = 0;
    let mut page: u32 = 0;

    loop {
        let start_str = format!("{current_start_nanos}");
        if current_start_nanos >= end.timestamp_nanos_opt().unwrap_or(0) {
            break;
        }

        let page_entries =
            export_page(client, config, &url, logql, &start_str, &end_nanos, writer).await?;

        if page_entries.count == 0 {
            break;
        }

        total_entries += page_entries.count;
        current_start_nanos = page_entries.last_timestamp_nanos + 1;
        page += 1;

        if page.is_multiple_of(10) {
            info!("export progress: {total_entries} entries across {page} pages for {logql}");
        }
    }

    writer.flush().context("flush export writer")?;
    debug!("export complete: {total_entries} entries in {page} pages for {logql}");
    Ok(total_entries)
}

struct PageResult {
    count: u64,
    last_timestamp_nanos: i64,
}

/// Fetch a single page from query_range with retry.
async fn export_page(
    client: &reqwest::Client,
    config: &BulkLokiConfig,
    url: &str,
    logql: &str,
    start_nanos: &str,
    end_nanos: &str,
    writer: &mut impl Write,
) -> Result<PageResult> {
    let limit_str = EXPORT_PAGE_LIMIT.to_string();
    let mut last_ts: i64 = 0;
    let mut count: u64 = 0;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
            tokio::time::sleep(delay).await;
        }

        let resp = config
            .build_request(client, url)
            .query(&[
                ("query", logql),
                ("start", start_nanos),
                ("end", end_nanos),
                ("limit", &limit_str),
                ("direction", "forward"),
            ])
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) if attempt + 1 < MAX_RETRIES => {
                warn!("export page attempt {}: connection error: {e}", attempt + 1);
                continue;
            }
            Err(e) => bail!("export page failed after {MAX_RETRIES} attempts: {e}"),
        };

        let status = resp.status();
        if status.is_success() {
            let body: serde_json::Value = resp
                .json()
                .await
                .context("parse query_range response JSON")?;

            let result = body
                .get("data")
                .and_then(|d| d.get("result"))
                .and_then(|r| r.as_array());

            let streams = match result {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return Ok(PageResult {
                        count: 0,
                        last_timestamp_nanos: 0,
                    })
                }
            };

            for stream_obj in streams {
                let stream_labels = match stream_obj.get("stream") {
                    Some(s) => s.as_object().cloned().unwrap_or_default(),
                    None => continue,
                };

                let Some(values) = stream_obj.get("values").and_then(|v| v.as_array()) else {
                    continue;
                };

                for entry in values {
                    let arr = match entry.as_array() {
                        Some(a) if a.len() >= 2 => a,
                        _ => continue,
                    };

                    let ts_str = arr[0].as_str().unwrap_or("0");
                    let line = arr[1].as_str().unwrap_or("");

                    // Track last timestamp for pagination
                    if let Ok(ts) = ts_str.parse::<i64>() {
                        if ts > last_ts {
                            last_ts = ts;
                        }
                    }

                    // Write push-format JSONL: one entry per line
                    let entry = PushEntry {
                        stream: stream_labels.clone(),
                        values: vec![vec![ts_str.to_string(), line.to_string()]],
                    };
                    serde_json::to_writer(&mut *writer, &entry).context("write JSONL entry")?;
                    writer.write_all(b"\n").context("write newline")?;
                    count += 1;
                }
            }

            return Ok(PageResult {
                count,
                last_timestamp_nanos: last_ts,
            });
        }

        if is_retryable_status(status) && attempt + 1 < MAX_RETRIES {
            warn!(
                "export page attempt {}: retryable status {status}",
                attempt + 1
            );
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        bail!("export page failed: HTTP {status}: {body}");
    }

    bail!("export page failed after {MAX_RETRIES} attempts")
}

/// Read push-format JSONL and POST to `/loki/api/v1/push` in batches.
///
/// Returns the total number of entries imported. Entries with identical
/// stream labels within a batch are aggregated into a single stream object
/// for optimal Loki ingestion.
///
/// The target Loki instance must be configured with
/// `reject_old_samples: false` to accept historical timestamps.
pub async fn import_stream(
    config: &BulkLokiConfig,
    reader: impl BufRead,
    batch_size: usize,
) -> Result<u64> {
    let client = http_client();
    let url = format!("{}/loki/api/v1/push", config.base_url);
    let batch_size = if batch_size == 0 {
        DEFAULT_IMPORT_BATCH
    } else {
        batch_size
    };

    let mut total_entries: u64 = 0;
    let mut batch_entries: Vec<PushEntry> = Vec::with_capacity(batch_size);
    let mut batch_count: u64 = 0;
    let mut line_num: u64 = 0;

    for line in reader.lines() {
        line_num += 1;
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(e) => {
                warn!("skip line {line_num}: read error: {e}");
                continue;
            }
        };

        let entry: PushEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                warn!("skip line {line_num}: parse error: {e}");
                continue;
            }
        };

        batch_entries.push(entry);

        if batch_entries.len() >= batch_size {
            let pushed = push_batch(client, config, &url, &mut batch_entries).await?;
            total_entries += pushed;
            batch_count += 1;

            if batch_count.is_multiple_of(10) {
                info!("import progress: {total_entries} entries in {batch_count} batches");
            }
        }
    }

    if !batch_entries.is_empty() {
        let pushed = push_batch(client, config, &url, &mut batch_entries).await?;
        total_entries += pushed;
        batch_count += 1;
    }

    info!("import complete: {total_entries} entries in {batch_count} batches");
    Ok(total_entries)
}

/// Aggregate entries by stream labels and POST as a single push payload.
async fn push_batch(
    client: &reqwest::Client,
    config: &BulkLokiConfig,
    url: &str,
    entries: &mut Vec<PushEntry>,
) -> Result<u64> {
    if entries.is_empty() {
        return Ok(0);
    }

    // Aggregate: group values by identical stream label sets.
    // Key: sorted JSON string of labels (deterministic).
    let mut aggregated: HashMap<String, AggregatedStream> = HashMap::new();
    let mut total_values: u64 = 0;

    for entry in entries.drain(..) {
        let key = serde_json::to_string(&entry.stream).unwrap_or_default();
        let agg = aggregated.entry(key).or_insert_with(|| AggregatedStream {
            stream: entry.stream.clone(),
            values: Vec::new(),
        });
        total_values += entry.values.len() as u64;
        agg.values.extend(entry.values);
    }

    let streams: Vec<serde_json::Value> = aggregated
        .into_values()
        .map(|agg| {
            serde_json::json!({
                "stream": agg.stream,
                "values": agg.values,
            })
        })
        .collect();

    let payload = serde_json::json!({ "streams": streams });

    let json_bytes = serde_json::to_vec(&payload).context("serialize push payload")?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder
        .write_all(&json_bytes)
        .context("gzip compress push payload")?;
    let compressed = encoder.finish().context("finalize gzip compression")?;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
            tokio::time::sleep(delay).await;
        }

        let resp = config
            .build_post(client, url)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .body(compressed.clone())
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) if attempt + 1 < MAX_RETRIES => {
                warn!("push batch attempt {}: connection error: {e}", attempt + 1);
                continue;
            }
            Err(e) => bail!("push batch failed after {MAX_RETRIES} attempts: {e}"),
        };

        let status = resp.status();
        if status.is_success() {
            return Ok(total_values);
        }

        if status.as_u16() == 429 {
            // Respect Retry-After header
            let delay = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(RETRY_BASE_DELAY * 2u32.pow(attempt));
            warn!("push batch: rate limited, retrying after {delay:?}");
            tokio::time::sleep(delay).await;
            continue;
        }

        if is_retryable_status(status) && attempt + 1 < MAX_RETRIES {
            warn!(
                "push batch attempt {}: retryable status {status}",
                attempt + 1
            );
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        bail!("push batch failed: HTTP {status}: {body}");
    }

    bail!("push batch failed after {MAX_RETRIES} attempts")
}

struct AggregatedStream {
    stream: serde_json::Map<String, serde_json::Value>,
    values: Vec<Vec<String>>,
}

/// Fetch all values for a Loki label within a time range.
///
/// Used to discover which log streams exist (e.g., all `job` values)
/// so the capture can export every stream without a hardcoded list.
pub async fn export_label_values(
    config: &BulkLokiConfig,
    label: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<String>> {
    let client = http_client();
    let url = format!("{}/loki/api/v1/label/{label}/values", config.base_url);
    let start_str = format!("{}", start.timestamp_nanos_opt().unwrap_or(0));
    let end_str = format!("{}", end.timestamp_nanos_opt().unwrap_or(0));

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
            tokio::time::sleep(delay).await;
        }

        let resp = config
            .build_request(client, &url)
            .query(&[("start", &start_str), ("end", &end_str)])
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) if attempt + 1 < MAX_RETRIES => {
                warn!("label values attempt {}: {e}", attempt + 1);
                continue;
            }
            Err(e) => bail!("label values failed after {MAX_RETRIES} attempts: {e}"),
        };

        let status = resp.status();
        if status.is_success() {
            let body: serde_json::Value = resp.json().await.context("parse label values")?;
            let values = body
                .get("data")
                .and_then(|d| d.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            return Ok(values);
        }

        if is_retryable_status(status) && attempt + 1 < MAX_RETRIES {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        bail!("label values failed: HTTP {status}: {body}");
    }

    bail!("label values failed after {MAX_RETRIES} attempts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_entry_roundtrip() {
        let entry = PushEntry {
            stream: {
                let mut m = serde_json::Map::new();
                m.insert("job".into(), "windows-security".into());
                m.insert("host".into(), "DC01".into());
                m
            },
            values: vec![vec![
                "1719403200000000000".to_string(),
                "Event 4769: Kerberos service ticket requested".to_string(),
            ]],
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: PushEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.stream.get("job").unwrap(), "windows-security");
        assert_eq!(parsed.values.len(), 1);
        assert_eq!(parsed.values[0][0], "1719403200000000000");
    }

    #[test]
    fn bulk_config_from_env_defaults() {
        // Clear env to test defaults
        std::env::remove_var("LOKI_URL");
        std::env::remove_var("LOKI_AUTH_TOKEN");
        let config = BulkLokiConfig::from_env();
        assert_eq!(config.base_url, "http://localhost:3100");
        assert!(config.auth_token.is_none());
    }
}
