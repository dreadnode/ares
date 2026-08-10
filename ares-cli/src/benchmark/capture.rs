//! Snapshot capture pipeline.
//!
//! Connects to Redis, loads the completed red team state, syncs Loki chunks
//! from S3 for the capture window, exports fired Grafana alerts, generates
//! ground truth, and writes everything into a self-contained snapshot directory.
//! Automatically uploads the snapshot to the benchmark S3 bucket.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use futures::stream::{self, StreamExt};
use tracing::info;

use ares_core::eval::ground_truth::{
    create_ground_truth_from_red_state, ExpectedIOC, ExpectedTimelineEvent,
};
use ares_core::models::PyramidLevel;
use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

use super::manifest::{FiredAlert, SnapshotManifest, MANIFEST_VERSION};
use super::snapshot_s3::{benchmark_section, require, resolve};

/// Where the source Loki actually stores its chunks — from `LOKI_S3_*` in the
/// environment or `.env`, falling back to an optional `benchmark:` section.
struct LokiS3 {
    bucket: String,
    region: String,
    profile: String,
}

impl LokiS3 {
    fn from_env() -> Result<Self> {
        let cfg = benchmark_section();
        Ok(Self {
            bucket: require(
                "LOKI_S3_BUCKET",
                "benchmark.loki_s3_bucket",
                &cfg.loki_s3_bucket,
            )?,
            region: require(
                "LOKI_S3_REGION",
                "benchmark.loki_s3_region",
                &cfg.loki_s3_region,
            )?,
            profile: resolve("LOKI_S3_PROFILE", &cfg.loki_s3_profile),
        })
    }
}

/// Shared HTTP client — reqwest holds a connection pool per-instance, so
/// building one per call kills keep-alive across the Grafana surface.
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Run the `benchmark capture` command.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_capture(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    output_dir: &str,
    pre_window_hours: u32,
    post_window_minutes: u32,
    no_upload: bool,
    attacker_ips: Vec<String>,
    wait_for_flush: bool,
    flush_timeout_mins: u32,
) -> Result<()> {
    eprint!("[1/5] Loading operation state from Redis...");
    let _ = std::io::stderr().flush();
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    info!("capturing snapshot for operation {op_id}");

    let reader = RedisStateReader::new(op_id.clone());
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("no state found for operation: {op_id}"))?;

    if state.completed_at.is_none() {
        bail!("operation {op_id} has not completed — cannot capture snapshot");
    }
    let completed_at = state.completed_at.unwrap();
    eprintln!(" done ({op_id})");

    let export_start = state.started_at - Duration::hours(pre_window_hours as i64);
    let export_end = completed_at + Duration::minutes(post_window_minutes as i64);

    info!(
        "capture window: {} to {} (pre={}h, post={}m)",
        export_start.to_rfc3339(),
        export_end.to_rfc3339(),
        pre_window_hours,
        post_window_minutes,
    );

    // Loki's ingester flushes chunks to S3 with ~30-60 min latency, so a capture
    // run right after an op silently misses the attack-window logs. When asked,
    // block until those chunks have actually landed in S3.
    if wait_for_flush {
        eprintln!("[flush] waiting for Loki to flush the attack window to S3 (timeout {flush_timeout_mins}m)...");
        wait_for_attack_flush(state.started_at, completed_at, flush_timeout_mins).await?;
        eprintln!("[flush] attack window is in S3 — proceeding with capture");
    }

    let snapshot_dir = Path::new(output_dir).join(&op_id);
    let loki_dir = snapshot_dir.join("loki");
    fs::create_dir_all(&loki_dir)
        .with_context(|| format!("create snapshot directory: {}", loki_dir.display()))?;
    // Prometheus metrics + Grafana dashboards/annotations live in their own
    // subdirs; create_dir_all on grafana/dashboards also creates grafana/.
    let prometheus_dir = snapshot_dir.join("prometheus");
    fs::create_dir_all(&prometheus_dir)
        .with_context(|| format!("create prometheus directory: {}", prometheus_dir.display()))?;
    let dashboards_dir = snapshot_dir.join("grafana").join("dashboards");
    fs::create_dir_all(&dashboards_dir)
        .with_context(|| format!("create dashboards directory: {}", dashboards_dir.display()))?;

    let red_state_json = serialize_red_state(&state);
    let red_state_path = snapshot_dir.join("red-state.json");
    fs::write(
        &red_state_path,
        serde_json::to_string_pretty(&red_state_json)?,
    )
    .context("write red-state.json")?;
    info!("wrote {}", red_state_path.display());

    let techniques: Vec<String> = state.all_techniques.clone();
    let mut ground_truth = create_ground_truth_from_red_state(&state, &techniques);
    // Populate the expected attack timeline from the op's recorded event log
    // (ares:op:{id}:timeline) so the blue investigation is scored on
    // reconstructing the real sequence of attack events — otherwise the scorer
    // sees an empty timeline and returns a vacuous perfect 1.0.
    ground_truth.expected_timeline = fetch_expected_timeline(&mut conn, &op_id).await;
    info!(
        "captured {} expected timeline events",
        ground_truth.expected_timeline.len()
    );
    // Operator-supplied attacker/source IPs: the attack's most blue-observable
    // IOC, absent from the target-centric red state. Scored as required.
    for ip in &attacker_ips {
        ground_truth.expected_iocs.push(ExpectedIOC {
            ioc_type: "ip".to_string(),
            value: ip.clone(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: Vec::new(),
            required: true,
            source: "attacker_infrastructure".to_string(),
        });
    }
    if !attacker_ips.is_empty() {
        info!("added {} attacker-source IOC(s)", attacker_ips.len());
    }
    let gt_path = snapshot_dir.join("ground-truth.json");
    fs::write(&gt_path, serde_json::to_string_pretty(&ground_truth)?)
        .context("write ground-truth.json")?;
    info!("wrote {}", gt_path.display());

    eprint!("[2/5] Syncing Loki chunks from S3...");
    let _ = std::io::stderr().flush();
    let (chunk_count, index_count) = sync_loki_s3(&loki_dir, export_start, export_end).await?;
    eprintln!(" done ({chunk_count} chunks, {index_count} index files)");

    info!("synced {chunk_count} chunks + {index_count} index files from S3");

    // Metrics only over a bounded window around the attack (the agent's
    // clock-anchored Prometheus queries land here) — the full padded log
    // window × every metric series would be gigabytes.
    let metrics_start = state.started_at - Duration::minutes(30);
    let metrics_end = completed_at + Duration::minutes(30);

    eprint!(
        "[3/5] Exporting Grafana surface (alerts, metrics, dashboards, annotations, traces) in parallel..."
    );
    let _ = std::io::stderr().flush();
    // All five exports hit independent Grafana endpoints — run them concurrently
    // instead of the sequential [3/8]..[6/8] the old code did.
    let (
        alerts_res,
        metrics_series,
        dashboards_captured,
        annotations_captured,
        tempo_traces_captured,
    ) = tokio::join!(
        export_grafana_alerts(export_start, export_end),
        export_prometheus_metrics(&snapshot_dir, metrics_start, metrics_end),
        export_dashboards(&snapshot_dir),
        export_all_annotations(&snapshot_dir, export_start, export_end),
        export_tempo_traces(&snapshot_dir, &op_id, metrics_start, metrics_end),
    );
    let fired_alerts = alerts_res?;
    eprintln!(
        " done ({} alerts, {metrics_series} series, {dashboards_captured} dashboards, {annotations_captured} annotations, {tempo_traces_captured} traces)",
        fired_alerts.len()
    );
    let alerts_path = snapshot_dir.join("fired-alerts.json");
    fs::write(&alerts_path, serde_json::to_string_pretty(&fired_alerts)?)
        .context("write fired-alerts.json")?;
    info!(
        "captured {} fired alerts, {metrics_series} metric series, {dashboards_captured} dashboards, {annotations_captured} annotations",
        fired_alerts.len()
    );

    if metrics_series > 0 {
        eprint!("      Pre-building Prometheus TSDB blocks (capture-time)...");
        let _ = std::io::stderr().flush();
        match build_prometheus_tsdb_blocks(&snapshot_dir) {
            Ok(true) => eprintln!(" done"),
            Ok(false) => eprintln!(" skipped (docker/python3 unavailable — replay backfills)"),
            Err(e) => {
                eprintln!(" failed — replay backfills from metrics.json");
                info!("prometheus tsdb pre-build failed: {e}");
            }
        }
    }

    eprint!("[4/5] Writing manifest and ground truth...");
    let _ = std::io::stderr().flush();
    let target_domain = state
        .target
        .as_ref()
        .map(|t| t.domain.clone())
        .unwrap_or_default();
    let target_ip = state
        .target
        .as_ref()
        .map(|t| t.ip.clone())
        .unwrap_or_default();

    let manifest = SnapshotManifest {
        version: MANIFEST_VERSION,
        operation_id: op_id.clone(),
        target_domain,
        target_ip,
        started_at: state.started_at,
        completed_at,
        capture_window_start: export_start,
        capture_window_end: export_end,
        loki_source: "s3-chunks".to_string(),
        loki_chunks: chunk_count,
        loki_index_files: index_count,
        alerts_captured: fired_alerts.len(),
        metrics_series,
        dashboards_captured,
        annotations_captured,
        tempo_traces_captured,
        techniques: state.all_techniques.clone(),
        has_domain_admin: state.has_domain_admin,
        credential_count: state.all_credentials.len(),
        host_count: state.all_hosts.len(),
        captured_at: Utc::now(),
    };

    let manifest_path = snapshot_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .context("write manifest.json")?;
    info!("wrote {}", manifest_path.display());
    eprintln!(" done");

    if !no_upload {
        let cfg = benchmark_section();
        let bucket = require("BENCHMARK_S3_BUCKET", "benchmark.s3_bucket", &cfg.s3_bucket)?;
        let profile = resolve("BENCHMARK_AWS_PROFILE", &cfg.aws_profile);
        let region = require(
            "BENCHMARK_AWS_REGION",
            "benchmark.aws_region",
            &cfg.aws_region,
        )?;

        let s3_dest = format!("s3://{bucket}/snapshots/{op_id}/");
        eprint!("[5/5] Uploading snapshot to {s3_dest}...");
        let _ = std::io::stderr().flush();
        info!("uploading snapshot to {s3_dest}");

        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "sync",
                snapshot_dir.to_str().unwrap_or("."),
                &s3_dest,
                "--profile",
                &profile,
                "--region",
                &region,
                "--quiet",
            ])
            .status()
            .context("aws s3 sync to benchmark bucket")?;

        if !status.success() {
            bail!("aws s3 sync to {s3_dest} failed with exit code {status}");
        }
        eprintln!(" done");
        info!("S3 upload complete: {s3_dest}");
    } else {
        eprintln!("[5/5] Skipping S3 upload (--no-upload)");
    }

    println!("Snapshot captured: {}", snapshot_dir.display());
    println!("  Operation:    {op_id}");
    println!("  Loki chunks:  {chunk_count}");
    println!("  Index files:  {index_count}");
    println!("  Alerts:       {}", manifest.alerts_captured);
    println!("  Metrics:      {}", manifest.metrics_series);
    println!("  Dashboards:   {}", manifest.dashboards_captured);
    println!("  Annotations:  {}", manifest.annotations_captured);
    println!("  Tempo traces: {}", manifest.tempo_traces_captured);
    println!("  Techniques:   {}", manifest.techniques.len());
    println!("  Domain admin: {}", manifest.has_domain_admin);
    println!("  Credentials:  {}", manifest.credential_count);
    println!("  Hosts:        {}", manifest.host_count);
    if !no_upload {
        let cfg = benchmark_section();
        let bucket = require("BENCHMARK_S3_BUCKET", "benchmark.s3_bucket", &cfg.s3_bucket)?;
        println!("  S3:           s3://{bucket}/snapshots/{op_id}/");
    }

    Ok(())
}

/// A single event from the op's recorded attack timeline
/// (`ares:op:{id}:timeline`). Only the fields the scorer needs are decoded;
/// serde ignores the rest of the stored `TimelineEvent` payload.
#[derive(serde::Deserialize)]
struct RedTimelineEvent {
    description: String,
    #[serde(default)]
    mitre_techniques: Vec<String>,
    #[serde(default)]
    timestamp: String,
}

/// Fetch the operation's recorded attack timeline and map it to the ground
/// truth `ExpectedTimelineEvent` shape the blue-team scorer compares against.
///
/// Returns an empty vec if the op recorded no timeline (older ops) — the
/// scorer then drops the timeline dimension rather than scoring it vacuously.
async fn fetch_expected_timeline(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
) -> Vec<ExpectedTimelineEvent> {
    use redis::AsyncCommands;
    let key = format!("ares:op:{op_id}:timeline");
    let raw: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap_or_default();
    raw.iter()
        .filter_map(|s| serde_json::from_str::<RedTimelineEvent>(s).ok())
        // Keep only blue-observable events: drop red-internal notes such as
        // failed exploit attempts and per-hash discovery — the hash values never
        // reach defender telemetry (the dumping act is scored as a technique).
        .filter(|e| {
            let d = e.description.to_lowercase();
            !d.starts_with("exploit attempted but failed") && !d.starts_with("hash discovered")
        })
        .map(|e| ExpectedTimelineEvent {
            description_pattern: e.description,
            mitre_techniques: e.mitre_techniques,
            timestamp_range: chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                .ok()
                .map(|t| {
                    let u = t.with_timezone(&chrono::Utc);
                    (u, u)
                }),
            required: true,
        })
        .collect()
}

/// Poll the source Loki S3 until the ingester has flushed chunks covering the
/// attack window's end. Loki flushes with ~30-60 min latency, so a capture run
/// right after an op silently misses the attack-window logs; this blocks until
/// they've landed, or errors at the timeout rather than producing a
/// silently-incomplete snapshot.
async fn wait_for_attack_flush(
    attack_start: chrono::DateTime<chrono::Utc>,
    attack_end: chrono::DateTime<chrono::Utc>,
    timeout_mins: u32,
) -> Result<()> {
    let end_ms = attack_end.timestamp_millis();
    const POLL_SECS: u64 = 30;
    let max_polls = (timeout_mins as u64 * 60) / POLL_SECS;
    for poll in 0..=max_polls {
        match latest_flushed_chunk_end(attack_start, attack_end)? {
            Some(chunk_end) if chunk_end >= end_ms => {
                info!("Loki flush complete: S3 chunks cover the attack window end");
                return Ok(());
            }
            Some(chunk_end) => {
                let behind_min = (end_ms - chunk_end).max(0) / 60_000;
                eprintln!("  [flush] S3 covers up to ~{behind_min}m before attack end — waiting ({poll}/{max_polls})...");
            }
            None => {
                eprintln!(
                    "  [flush] no attack-window chunks in S3 yet — waiting ({poll}/{max_polls})..."
                );
            }
        }
        if poll < max_polls {
            tokio::time::sleep(std::time::Duration::from_secs(POLL_SECS)).await;
        }
    }
    // Some streams didn't reach the attack end within the window. This can mean the
    // ingester is still buffering (thin snapshot) OR a low-volume stream simply has
    // no data near the attack end (nothing left to flush). We can't tell which from
    // S3 alone, so warn loudly and proceed rather than fail the whole capture.
    eprintln!(
        "  [flush] WARNING: not all Loki streams reached the attack end within {timeout_mins}m — \
         proceeding with current S3 chunks. If the snapshot looks thin, re-run with a larger \
         --flush-timeout-mins."
    );
    Ok(())
}

/// Max end-time (ms) among flushed S3 chunks whose content overlaps
/// `[start, end]`, or `None` if none are present yet. Mirrors the chunk-key
/// parsing in [`sync_loki_s3`].
fn latest_flushed_chunk_end(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> Result<Option<i64>> {
    let start_ms = start.timestamp_millis();
    let end_ms = end.timestamp_millis();
    let list_start = start.format("%Y-%m-%d").to_string();
    let list_end = (end + Duration::days(1)).format("%Y-%m-%d").to_string();
    let loki = LokiS3::from_env()?;

    let output = std::process::Command::new("aws")
        .args([
            "s3api",
            "list-objects-v2",
            "--bucket",
            &loki.bucket,
            "--prefix",
            "fake/",
            "--profile",
            &loki.profile,
            "--region",
            &loki.region,
            "--query",
            &format!("Contents[?LastModified>='{list_start}' && LastModified<'{list_end}'].Key"),
            "--output",
            "json",
        ])
        .output()
        .context("aws s3api list-objects-v2 (flush check)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("s3api list-objects-v2 failed (flush check): {stderr}");
    }
    let keys: Vec<String> = serde_json::from_slice(&output.stdout).context("parse s3api output")?;

    // Each Loki stream (fingerprint = the `fake/<fp>/...` path segment) flushes
    // independently, so completion must be gated on the SLOWEST stream reaching the
    // attack end. Taking the max across all streams let one high-volume stream
    // catching up mask a low-volume stream (e.g. windows-directory-service, carrying
    // late DCSync/LDAP evidence) still buffered in the ingester — silently dropping
    // the attack tail. Track each stream's newest flushed chunk_end covering the
    // window and return the minimum across streams.
    let mut per_stream: std::collections::HashMap<&str, i64> = std::collections::HashMap::new();
    for key in &keys {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() < 3 {
            continue;
        }
        let stream_fp = parts[1];
        let ts_parts: Vec<&str> = parts[2].split(':').collect();
        if ts_parts.len() < 2 {
            continue;
        }
        let (Ok(chunk_start), Ok(chunk_end)) = (
            i64::from_str_radix(ts_parts[0], 16),
            i64::from_str_radix(ts_parts[1], 16),
        ) else {
            continue;
        };
        if chunk_end >= start_ms && chunk_start <= end_ms {
            per_stream
                .entry(stream_fp)
                .and_modify(|m| *m = (*m).max(chunk_end))
                .or_insert(chunk_end);
        }
    }
    Ok(per_stream.values().copied().min())
}

/// Sync Loki S3 chunks and index files for the given time window.
///
/// 1. Lists all chunk objects modified in the date range.
/// 2. Filters chunks whose hex-encoded start/end timestamps overlap the window.
/// 3. Downloads matching chunks and relevant index files in parallel via `aws s3 cp`.
///
/// Returns `(chunk_count, index_count)`.
async fn sync_loki_s3(
    loki_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> Result<(u64, u64)> {
    let loki = LokiS3::from_env()?;
    let chunks_dir = loki_dir.join("fake");
    let index_dir = loki_dir.join("index");
    fs::create_dir_all(&chunks_dir).context("create chunks dir")?;
    fs::create_dir_all(&index_dir).context("create index dir")?;

    let start_ms = start.timestamp_millis();
    let end_ms = end.timestamp_millis();

    // Index tables are 24h periods keyed by days since epoch.
    let start_table = start
        .date_naive()
        .signed_duration_since(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
        .num_days();
    let end_table = end
        .date_naive()
        .signed_duration_since(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
        .num_days();

    let mut index_count: u64 = 0;
    for table in start_table..=end_table {
        let prefix = format!("index/loki_index_{table}/");
        let local_index = index_dir.join(format!("loki_index_{table}"));
        fs::create_dir_all(&local_index)?;

        info!(
            "syncing index table {table} from s3://{}/{prefix}",
            loki.bucket
        );
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "sync",
                &format!("s3://{}/{prefix}", loki.bucket),
                local_index.to_str().unwrap(),
                "--profile",
                &loki.profile,
                "--region",
                &loki.region,
                "--quiet",
            ])
            .status()
            .context("aws s3 sync index")?;
        if !status.success() {
            bail!("failed to sync index table {table}");
        }
        index_count += count_files_recursive(&local_index);
    }

    // Use aws s3api list-objects-v2 with JSON output, filter by
    // LastModified falling in our date range.
    let list_start = start.format("%Y-%m-%d").to_string();
    // End date + 1 day to capture objects modified on the end date
    let list_end = (end + Duration::days(1)).format("%Y-%m-%d").to_string();

    info!("listing chunks modified between {list_start} and {list_end}");

    let output = std::process::Command::new("aws")
        .args([
            "s3api",
            "list-objects-v2",
            "--bucket",
            &loki.bucket,
            "--prefix",
            "fake/",
            "--profile",
            &loki.profile,
            "--region",
            &loki.region,
            "--query",
            &format!("Contents[?LastModified>='{list_start}' && LastModified<'{list_end}'].Key"),
            "--output",
            "json",
        ])
        .output()
        .context("aws s3api list-objects-v2")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("s3api list-objects-v2 failed: {stderr}");
    }

    let keys: Vec<String> = serde_json::from_slice(&output.stdout).context("parse s3api output")?;

    info!("found {} chunk objects in date range", keys.len());

    let matching_keys: Vec<String> = keys
        .iter()
        .filter(|key| {
            let parts: Vec<&str> = key.split('/').collect();
            let Some(chunk_name) = parts.get(2) else {
                return false;
            };
            let ts_parts: Vec<&str> = chunk_name.split(':').collect();
            if ts_parts.len() < 2 {
                return false;
            }
            let (Ok(chunk_start), Ok(chunk_end)) = (
                i64::from_str_radix(ts_parts[0], 16),
                i64::from_str_radix(ts_parts[1], 16),
            ) else {
                return false;
            };
            chunk_end >= start_ms && chunk_start <= end_ms
        })
        .cloned()
        .collect();

    info!(
        "{} chunks overlap the capture window ({} filtered out)",
        matching_keys.len(),
        keys.len() - matching_keys.len()
    );
    info!(
        "downloading {} chunks (20 parallel)...",
        matching_keys.len()
    );

    // 20-way concurrent download via async streams — one `aws s3 cp` per chunk.
    // Replaces the prior bash heredoc, which had no path escaping and no
    // error propagation from individual failures.
    let results: Vec<Result<()>> = stream::iter(matching_keys.iter().cloned())
        .map(|key| {
            let bucket = loki.bucket.clone();
            let profile = loki.profile.clone();
            let region = loki.region.clone();
            let loki_dir = loki_dir.to_path_buf();
            async move {
                let local = loki_dir.join(&key);
                if let Some(parent) = local.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("create parent dir for {key}"))?;
                }
                let src = format!("s3://{bucket}/{key}");
                let status = tokio::process::Command::new("aws")
                    .args([
                        "s3",
                        "cp",
                        &src,
                        local.to_str().unwrap(),
                        "--profile",
                        &profile,
                        "--region",
                        &region,
                        "--quiet",
                    ])
                    .status()
                    .await
                    .with_context(|| format!("spawn aws s3 cp for {key}"))?;
                if !status.success() {
                    bail!("aws s3 cp {src} failed");
                }
                Ok(())
            }
        })
        .buffer_unordered(20)
        .collect()
        .await;

    let failed = results.iter().filter(|r| r.is_err()).count();
    if failed > 0 {
        let first = results.into_iter().find_map(|r| r.err()).unwrap();
        bail!(
            "{failed}/{} chunk downloads failed (first error: {first:#})",
            matching_keys.len()
        );
    }

    let chunk_count = matching_keys.len() as u64;
    Ok((chunk_count, index_count))
}

/// Count files recursively under a directory. Used for post-sync index counting.
fn count_files_recursive(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_file() {
                1
            } else if path.is_dir() {
                count_files_recursive(&path)
            } else {
                0
            }
        })
        .sum()
}

/// Build a SavedRedState-compatible JSON value from SharedRedTeamState.
///
/// Since SharedRedTeamState doesn't derive Serialize, we manually construct
/// the JSON using the individual Serialize-derived model types.
fn serialize_red_state(state: &ares_core::models::SharedRedTeamState) -> serde_json::Value {
    serde_json::json!({
        "operation_id": state.operation_id,
        "target": state.target.as_ref().map(|t| serde_json::json!({
            "ip": t.ip,
            "hostname": t.hostname,
            "domain": t.domain,
        })),
        "all_hosts": state.all_hosts.iter().map(|h| serde_json::json!({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "roles": h.roles,
            "services": h.services,
            "is_dc": h.is_dc,
            "owned": h.owned,
        })).collect::<Vec<_>>(),
        "all_users": state.all_users.iter().map(|u| serde_json::json!({
            "username": u.username,
            "domain": u.domain,
            "is_admin": u.is_admin,
            "source": u.source,
        })).collect::<Vec<_>>(),
        "all_credentials": state.all_credentials.iter().map(|c| serde_json::json!({
            "username": c.username,
            "domain": c.domain,
            "source": c.source,
            "is_admin": c.is_admin,
        })).collect::<Vec<_>>(),
        "all_hashes": state.all_hashes.iter().map(|h| serde_json::json!({
            "username": h.username,
            "hash_value": h.hash_value,
            "hash_type": h.hash_type,
            "domain": h.domain,
            "source": h.source,
        })).collect::<Vec<_>>(),
        "all_shares": state.all_shares.iter().map(|s| serde_json::json!({
            "host": s.host,
            "name": s.name,
            "permissions": s.permissions,
        })).collect::<Vec<_>>(),
        "all_domains": state.all_domains,
        "has_domain_admin": state.has_domain_admin,
        "has_golden_ticket": state.has_golden_ticket,
        "domain_admin_path": state.domain_admin_path,
        "identified_techniques": state.all_techniques,
        // Extra fields for replay
        "started_at": state.started_at.to_rfc3339(),
        "completed_at": state.completed_at.map(|t| t.to_rfc3339()),
        "target_ips": state.target_ips,
    })
}

/// Export fired Grafana alerts in the capture window via the annotations API.
///
/// Falls back gracefully if Grafana is not configured.
async fn export_grafana_alerts(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<FiredAlert>> {
    let Ok(grafana_url) = std::env::var("GRAFANA_URL") else {
        info!("GRAFANA_URL not set — skipping alert export");
        return Ok(Vec::new());
    };
    let api_key = std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok();

    let from_ms = start.timestamp_millis();
    let to_ms = end.timestamp_millis();

    let url =
        format!("{grafana_url}/api/annotations?from={from_ms}&to={to_ms}&type=alert&limit=5000");

    let client = http();
    let mut req = client.get(&url);
    if let Some(key) = &api_key {
        req = req.bearer_auth(key);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without alerts");
            return Ok(Vec::new());
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        info!("Grafana annotations API returned {status}: {body}");
        return Ok(Vec::new());
    }

    let annotations: Vec<serde_json::Value> = resp.json().await.context("parse annotations")?;
    let mut alerts = Vec::new();

    for ann in &annotations {
        let alert_name = ann
            .get("alertName")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let time_ms = ann.get("time").and_then(|v| v.as_i64()).unwrap_or(0);
        let fired_at =
            chrono::DateTime::from_timestamp_millis(time_ms).unwrap_or_else(chrono::Utc::now);

        // Extract labels from tags array (format: "key:value" or "key=value")
        let mut labels = serde_json::Map::new();
        if let Some(tags) = ann.get("tags").and_then(|t| t.as_array()) {
            for tag in tags {
                if let Some(tag_str) = tag.as_str() {
                    if let Some((k, v)) =
                        tag_str.split_once(':').or_else(|| tag_str.split_once('='))
                    {
                        labels.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                    }
                }
            }
        }
        labels.insert(
            "alertname".to_string(),
            serde_json::Value::String(alert_name.clone()),
        );

        let mut annotations_map = serde_json::Map::new();
        if let Some(text) = ann.get("text").and_then(|v| v.as_str()) {
            annotations_map.insert(
                "summary".to_string(),
                serde_json::Value::String(text.to_string()),
            );
        }

        alerts.push(FiredAlert {
            alert_name,
            fired_at,
            labels: serde_json::Value::Object(labels),
            annotations: serde_json::Value::Object(annotations_map),
        });
    }

    alerts.sort_by_key(|a| a.fired_at);

    Ok(alerts)
}

/// Resolve the Grafana base URL + optional bearer token from the environment,
/// logging and returning `None` when `GRAFANA_URL` is unset so the caller can
/// skip the export cleanly.
fn grafana_env(purpose: &str) -> Option<(String, Option<String>)> {
    match std::env::var("GRAFANA_URL") {
        Ok(url) => Some((url, std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok())),
        Err(_) => {
            info!("GRAFANA_URL not set — skipping {purpose}");
            None
        }
    }
}

/// Attach the Grafana service-account bearer token to a request when present.
fn with_grafana_auth(
    req: reqwest::RequestBuilder,
    api_key: &Option<String>,
) -> reqwest::RequestBuilder {
    match api_key {
        Some(key) => req.bearer_auth(key),
        None => req,
    }
}

/// The OpenMetrics converter, embedded so capture needs no repo checkout.
const PROM_BACKFILL_PY: &str = include_str!("../../../benchmarks/replay-stack/prom_backfill.py");

/// Whether `<cmd> --version` succeeds — used to detect docker/python3 at capture.
fn tool_available(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Pre-build the Prometheus TSDB blocks at capture time so replay just copies
/// them instead of running the multi-minute OpenMetrics→promtool conversion on
/// every run. Writes `<snapshot>/prometheus/tsdb/` (metrics.json stays as a
/// fallback — full parity either way). Returns `Ok(false)` when docker/python3
/// aren't available (replay then backfills). promtool comes from the pinned
/// Prometheus image via docker, matching the replay Prometheus version.
fn build_prometheus_tsdb_blocks(snapshot_dir: &Path) -> Result<bool> {
    let prometheus_dir = snapshot_dir.join("prometheus");
    let metrics_json = prometheus_dir.join("metrics.json");
    if !metrics_json.exists() {
        return Ok(false);
    }
    if !tool_available("docker") || !tool_available("python3") {
        return Ok(false);
    }

    let script = prometheus_dir.join(".prom_backfill.py");
    let om_path = prometheus_dir.join(".metrics.om");
    let tsdb_dir = prometheus_dir.join("tsdb");
    let _ = fs::remove_file(&om_path);
    let _ = fs::remove_dir_all(&tsdb_dir);
    fs::write(&script, PROM_BACKFILL_PY).context("stage prom_backfill.py")?;

    // 1) Emit OpenMetrics text (pure python3 — portable, no promtool needed).
    let emit = std::process::Command::new("python3")
        .arg(&script)
        .arg("--emit-openmetrics")
        .arg(&metrics_json)
        .arg(&om_path)
        .output()
        .context("run prom_backfill.py --emit-openmetrics")?;
    let _ = fs::remove_file(&script);
    if !emit.status.success() {
        let _ = fs::remove_file(&om_path);
        bail!(
            "openmetrics emit failed: {}",
            String::from_utf8_lossy(&emit.stderr).trim()
        );
    }
    if !om_path.exists() {
        return Ok(false); // no series emitted
    }

    // 2) Build TSDB blocks with the pinned promtool via docker (into ./tsdb).
    fs::create_dir_all(&tsdb_dir).context("create tsdb dir")?;
    let prom_abs = prometheus_dir
        .canonicalize()
        .context("canonicalize prometheus dir")?;
    let promtool = std::process::Command::new("docker")
        .args(["run", "--rm", "--entrypoint", "promtool"])
        .arg("-v")
        .arg(format!("{}:/data", prom_abs.display()))
        .arg(super::versions::PROMETHEUS_IMAGE)
        .args([
            "tsdb",
            "create-blocks-from",
            "openmetrics",
            "/data/.metrics.om",
            "/data/tsdb",
        ])
        .output()
        .context("run promtool via docker")?;
    let _ = fs::remove_file(&om_path);
    if !promtool.status.success() {
        let _ = fs::remove_dir_all(&tsdb_dir);
        bail!(
            "promtool create-blocks failed: {}",
            String::from_utf8_lossy(&promtool.stderr).trim()
        );
    }
    Ok(true)
}

/// Export Prometheus metrics over the capture window via the Grafana
/// datasource proxy.
///
/// In-cluster Prometheus is not directly reachable, so we resolve the
/// datasource with `type=="prometheus"` AND `name=="Prometheus"` (not
/// "Mimir"), then range-query all series through
/// `/api/datasources/proxy/uid/{uid}/api/v1/query_range`.
///
/// Writes the raw response body to `{snapshot_dir}/prometheus/metrics.json`
/// and returns the number of series (`.data.result` length), or 0 on any
/// failure. Failures are logged and swallowed (metrics are best-effort), so
/// this never aborts the surrounding capture.
async fn export_prometheus_metrics(
    snapshot_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("Prometheus metrics export") else {
        return 0;
    };

    let client = http();

    let ds_url = format!("{grafana_url}/api/datasources");
    let ds_resp = match with_grafana_auth(client.get(&ds_url), &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana datasources request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without metrics");
            return 0;
        }
    };
    if !ds_resp.status().is_success() {
        let status = ds_resp.status();
        let body = ds_resp.text().await.unwrap_or_default();
        info!("Grafana datasources API returned {status}: {body}");
        return 0;
    }
    let datasources: Vec<serde_json::Value> = match ds_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            info!("failed to parse Grafana datasources: {e}");
            return 0;
        }
    };
    let uid = datasources.iter().find_map(|ds| {
        let is_prom = ds.get("type").and_then(|v| v.as_str()) == Some("prometheus");
        let is_named = ds.get("name").and_then(|v| v.as_str()) == Some("Prometheus");
        if is_prom && is_named {
            ds.get("uid").and_then(|v| v.as_str()).map(str::to_string)
        } else {
            None
        }
    });
    let Some(uid) = uid else {
        info!("no Prometheus datasource (type=prometheus, name=Prometheus) found — skipping metrics export");
        return 0;
    };

    let names_url =
        format!("{grafana_url}/api/datasources/proxy/uid/{uid}/api/v1/label/__name__/values");
    let names: Vec<String> = match with_grafana_auth(client.get(&names_url), &api_key)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| {
                v.get("data").and_then(|d| d.as_array()).map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default(),
        Ok(r) => {
            info!("metric-names query returned {}", r.status());
            return 0;
        }
        Err(e) => {
            info!("metric-names query failed: {e}");
            return 0;
        }
    };
    if names.is_empty() {
        info!("no Prometheus metric names returned — skipping metrics export");
        return 0;
    }

    // A single all-series query ({__name__=~".+"}) over the window times out;
    // ~80 names per batch is sub-second. Merge the matrices into one result.
    let query_url = format!("{grafana_url}/api/datasources/proxy/uid/{uid}/api/v1/query_range");
    let start_str = start.to_rfc3339();
    let end_str = end.to_rfc3339();
    const BATCH: usize = 80;
    let total_batches = names.len().div_ceil(BATCH);
    let mut all_series: Vec<serde_json::Value> = Vec::new();
    let mut failed_batches: usize = 0;
    for (i, chunk) in names.chunks(BATCH).enumerate() {
        let selector = format!(r#"{{__name__=~"{}"}}"#, chunk.join("|"));
        let params: [(&str, &str); 4] = [
            ("query", selector.as_str()),
            ("start", start_str.as_str()),
            ("end", end_str.as_str()),
            // Coarse step: all-series over the window at fine resolution is
            // hundreds of MB of mostly-irrelevant k8s cardinality.
            ("step", "300s"),
        ];
        match with_grafana_auth(client.get(&query_url).query(&params), &api_key)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    if let Some(res) = v
                        .get("data")
                        .and_then(|d| d.get("result"))
                        .and_then(|r| r.as_array())
                    {
                        all_series.extend(res.iter().cloned());
                    }
                }
            }
            Ok(r) => {
                failed_batches += 1;
                info!(
                    "metrics batch {}/{total_batches} returned {}",
                    i + 1,
                    r.status()
                );
            }
            Err(e) => {
                failed_batches += 1;
                info!("metrics batch {}/{total_batches} failed: {e}", i + 1);
            }
        }
    }
    if failed_batches > 0 {
        // Surface partial failure to the operator — an all-info log message
        // gets lost in a busy capture.
        eprintln!(
            "  warning: {failed_batches}/{total_batches} Prometheus batches failed — metrics.json is incomplete"
        );
    }

    let merged = serde_json::json!({
        "status": "success",
        "data": { "resultType": "matrix", "result": all_series },
    });
    let serialized = match serde_json::to_string(&merged) {
        Ok(s) => s,
        Err(e) => {
            info!("failed to serialize merged metrics: {e}");
            return 0;
        }
    };
    let metrics_path = snapshot_dir.join("prometheus").join("metrics.json");
    if let Err(e) = fs::write(&metrics_path, serialized) {
        info!("failed to write {}: {e}", metrics_path.display());
        return 0;
    }
    let series = all_series.len();
    info!(
        "wrote {} ({series} series across {total_batches} batches)",
        metrics_path.display()
    );
    series
}

/// Export all Grafana dashboards (`type=dash-db`).
///
/// Lists dashboards via `/api/search`, then fetches each by UID and writes the
/// raw body to `{snapshot_dir}/grafana/dashboards/{uid}.json`. Returns the
/// number of dashboards captured, or 0 on any failure.
async fn export_dashboards(snapshot_dir: &Path) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("dashboard export") else {
        return 0;
    };

    let client = http();

    let search_url = format!("{grafana_url}/api/search?type=dash-db&limit=500");
    let search_resp = match with_grafana_auth(client.get(&search_url), &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana search request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without dashboards");
            return 0;
        }
    };
    if !search_resp.status().is_success() {
        let status = search_resp.status();
        let body = search_resp.text().await.unwrap_or_default();
        info!("Grafana search API returned {status}: {body}");
        return 0;
    }
    let items: Vec<serde_json::Value> = match search_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            info!("failed to parse Grafana search response: {e}");
            return 0;
        }
    };

    let dashboards_dir = snapshot_dir.join("grafana").join("dashboards");
    let mut count: usize = 0;
    for item in &items {
        let Some(uid) = item.get("uid").and_then(|v| v.as_str()) else {
            continue;
        };
        let dash_url = format!("{grafana_url}/api/dashboards/uid/{uid}");
        let dash_resp = match with_grafana_auth(client.get(&dash_url), &api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                info!("dashboard {uid} request failed: {e}");
                continue;
            }
        };
        if !dash_resp.status().is_success() {
            info!("dashboard {uid} returned {}", dash_resp.status());
            continue;
        }
        let body = match dash_resp.text().await {
            Ok(b) => b,
            Err(e) => {
                info!("failed to read dashboard {uid} body: {e}");
                continue;
            }
        };
        let path = dashboards_dir.join(format!("{uid}.json"));
        if let Err(e) = fs::write(&path, &body) {
            info!("failed to write {}: {e}", path.display());
            continue;
        }
        count += 1;
    }
    info!("captured {count} dashboards");
    count
}

/// Export all Grafana annotations over the capture window (no type filter).
///
/// Writes the raw response body to `{snapshot_dir}/grafana/annotations.json`
/// and returns the annotation count, or 0 on any failure. This complements the
/// alert-only `fired-alerts.json` export, which is preserved as-is.
async fn export_all_annotations(
    snapshot_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("annotation export") else {
        return 0;
    };

    let from_ms = start.timestamp_millis();
    let to_ms = end.timestamp_millis();
    let url = format!("{grafana_url}/api/annotations?from={from_ms}&to={to_ms}&limit=5000");

    let client = http();
    let resp = match with_grafana_auth(client.get(&url), &api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana annotations request failed (connection error): {e}");
            eprintln!("  warning: Grafana unreachable, continuing without annotations");
            return 0;
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        info!("Grafana annotations API returned {status}: {body}");
        return 0;
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            info!("failed to read annotations response body: {e}");
            return 0;
        }
    };

    let path = snapshot_dir.join("grafana").join("annotations.json");
    if let Err(e) = fs::write(&path, &body) {
        info!("failed to write {}: {e}", path.display());
        return 0;
    }
    info!("wrote {}", path.display());

    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

/// Export the operation's Tempo traces via the Grafana datasource proxy.
///
/// Mirrors [`export_prometheus_metrics`] — in-cluster Tempo is not directly
/// reachable, so we resolve the datasource with `type=="tempo"` and go through
/// `/api/datasources/proxy/uid/{uid}/api/search` + `/api/traces/{id}`. Traces
/// are written to `{snapshot_dir}/tempo/traces.jsonl.gz` — one full OTLP-JSON
/// trace per gzipped line — so the visual-replay path
/// (`benchmarks/replay-stack` → `ares benchmark replay`) can push them back
/// into an ephemeral Tempo without a live agent stack.
///
/// Best-effort: any failure logs, returns 0, and never aborts the surrounding
/// capture. The manifest field `tempo_traces_captured` records the count so
/// downstream consumers can tell "no Tempo data" from "no traces existed".
async fn export_tempo_traces(
    snapshot_dir: &Path,
    operation_id: &str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some((grafana_url, api_key)) = grafana_env("Tempo trace export") else {
        return 0;
    };

    let client = http();

    let Some(uid) = resolve_tempo_datasource_uid(client, &grafana_url, &api_key).await else {
        return 0;
    };

    let trace_ids = match search_tempo_trace_ids(
        client,
        &grafana_url,
        &api_key,
        &uid,
        operation_id,
        start,
        end,
    )
    .await
    {
        Ok(ids) if ids.is_empty() => {
            info!(op_id = %operation_id, "Tempo returned zero traces for attack_operation_id — skipping trace export");
            return 0;
        }
        Ok(ids) => ids,
        Err(e) => {
            info!(op_id = %operation_id, err = %e, "Tempo search failed — skipping trace export");
            return 0;
        }
    };

    let tempo_dir = snapshot_dir.join("tempo");
    if let Err(e) = fs::create_dir_all(&tempo_dir) {
        info!("failed to create {}: {e}", tempo_dir.display());
        return 0;
    }
    let out_path = tempo_dir.join("traces.jsonl.gz");
    let file = match fs::File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            info!("failed to open {} for write: {e}", out_path.display());
            return 0;
        }
    };
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());

    let mut written = 0usize;
    let mut fetch_failures = 0usize;
    for trace_id in &trace_ids {
        let trace_json =
            match fetch_tempo_trace(client, &grafana_url, &api_key, &uid, trace_id).await {
                Ok(body) => body,
                Err(e) => {
                    fetch_failures += 1;
                    info!(trace_id = %trace_id, err = %e, "Tempo trace fetch failed");
                    continue;
                }
            };
        // Store a single-line JSON blob per trace so the replay side can read
        // the file line by line and re-post each trace independently.
        let compacted = match serde_json::from_str::<serde_json::Value>(&trace_json)
            .and_then(|v| serde_json::to_string(&v))
        {
            Ok(s) => s,
            Err(_) => trace_json.replace('\n', " "),
        };
        if let Err(e) = encoder
            .write_all(compacted.as_bytes())
            .and_then(|_| encoder.write_all(b"\n"))
        {
            info!("write to {} failed: {e}", out_path.display());
            return written;
        }
        written += 1;
    }
    if let Err(e) = encoder.finish() {
        info!("gzip finish on {} failed: {e}", out_path.display());
        return written;
    }

    if fetch_failures > 0 {
        eprintln!(
            "  warning: {fetch_failures}/{} Tempo trace fetches failed — traces.jsonl.gz is incomplete",
            trace_ids.len()
        );
    }
    info!(
        traces = written,
        path = %out_path.display(),
        "captured Tempo traces"
    );
    written
}

/// Find the UID of the first Grafana datasource with `type == "tempo"`.
/// Unlike Prometheus, we do not pin by name — Tempo deployments commonly use
/// the single default "Tempo" datasource, and pinning by name would silently
/// drop traces when someone renames the datasource in Grafana.
async fn resolve_tempo_datasource_uid(
    client: &reqwest::Client,
    grafana_url: &str,
    api_key: &Option<String>,
) -> Option<String> {
    let ds_url = format!("{grafana_url}/api/datasources");
    let resp = match with_grafana_auth(client.get(&ds_url), api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            info!("Grafana datasources request failed (Tempo lookup): {e}");
            return None;
        }
    };
    if !resp.status().is_success() {
        info!(
            "Grafana datasources API returned {} on Tempo lookup",
            resp.status()
        );
        return None;
    }
    let datasources: Vec<serde_json::Value> = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            info!("failed to parse Grafana datasources on Tempo lookup: {e}");
            return None;
        }
    };
    datasources.iter().find_map(|ds| {
        if ds.get("type").and_then(|v| v.as_str()) == Some("tempo") {
            ds.get("uid").and_then(|v| v.as_str()).map(str::to_string)
        } else {
            None
        }
    })
}

/// Run a TraceQL search filtered by `attack_operation_id` over the capture
/// window and return the list of matching trace IDs.
async fn search_tempo_trace_ids(
    client: &reqwest::Client,
    grafana_url: &str,
    api_key: &Option<String>,
    uid: &str,
    operation_id: &str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>> {
    let search_url = format!("{grafana_url}/api/datasources/proxy/uid/{uid}/api/search");
    // Tempo's TraceQL search expects Unix-second `start` / `end`, `q` for the
    // TraceQL query, and `limit` to cap results. attack_operation_id is the
    // load-bearing span attribute here — every ares worker span carries it.
    let q = format!(r#"{{ .attack_operation_id = "{operation_id}" }}"#);
    let start_str = start.timestamp().to_string();
    let end_str = end.timestamp().to_string();
    let params = [
        ("q", q.as_str()),
        ("start", start_str.as_str()),
        ("end", end_str.as_str()),
        ("limit", "1000"),
    ];
    let resp = with_grafana_auth(client.get(&search_url).query(&params), api_key)
        .send()
        .await
        .context("tempo search request")?;
    if !resp.status().is_success() {
        bail!("tempo search returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await.context("parse tempo search response")?;
    Ok(body
        .get("traces")
        .and_then(|t| t.as_array())
        .map(|traces| {
            traces
                .iter()
                .filter_map(|t| {
                    t.get("traceID")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default())
}

/// Fetch a single trace by ID as OTLP-derived JSON. Tempo's
/// `/api/traces/{id}` returns a `{"batches":[...]}` object mirroring the OTLP
/// resource-spans structure — the replay side re-POSTs it to `/v1/traces`.
async fn fetch_tempo_trace(
    client: &reqwest::Client,
    grafana_url: &str,
    api_key: &Option<String>,
    uid: &str,
    trace_id: &str,
) -> Result<String> {
    let trace_url = format!("{grafana_url}/api/datasources/proxy/uid/{uid}/api/traces/{trace_id}");
    let resp = with_grafana_auth(client.get(&trace_url), api_key)
        .send()
        .await
        .context("tempo trace request")?;
    if !resp.status().is_success() {
        bail!("tempo trace {trace_id} returned {}", resp.status());
    }
    resp.text().await.context("read tempo trace body")
}
