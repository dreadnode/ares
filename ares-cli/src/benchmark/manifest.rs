//! Snapshot manifest and benchmark result schemas.
//!
//! A snapshot is a self-contained directory with everything needed to replay
//! a blue team investigation without the original infrastructure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;

/// Manifest for a benchmark snapshot directory.
///
/// Written as `manifest.json` at the root of the snapshot directory.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SnapshotManifest {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Ares operation ID.
    pub operation_id: String,

    /// Target AD domain.
    pub target_domain: String,

    /// Primary target IP.
    pub target_ip: String,

    /// When the red team operation started.
    pub started_at: DateTime<Utc>,

    /// When the red team operation completed.
    pub completed_at: DateTime<Utc>,

    /// Start of the Loki export window (includes pre-attack buffer).
    pub capture_window_start: DateTime<Utc>,

    /// End of the Loki export window (includes post-attack buffer).
    pub capture_window_end: DateTime<Utc>,

    /// How Loki data was captured ("s3-chunks" or "api-export").
    pub loki_source: String,

    /// Number of Loki chunks synced from S3.
    pub loki_chunks: u64,

    /// Number of Loki index files synced from S3.
    pub loki_index_files: u64,

    /// Number of Grafana alert annotations captured.
    pub alerts_captured: usize,

    /// Number of Prometheus series captured over the window (via Grafana proxy).
    #[serde(default)]
    pub metrics_series: usize,

    /// Number of Grafana dashboards captured.
    #[serde(default)]
    pub dashboards_captured: usize,

    /// Number of Grafana annotations captured (all types, unfiltered).
    #[serde(default)]
    pub annotations_captured: usize,

    /// Number of full Tempo traces captured for this operation (see
    /// `tempo/traces.jsonl.gz`). Populated when the capture pipeline was able
    /// to query Tempo via the Grafana datasource proxy; zero on older
    /// snapshots or when the proxy was unavailable at capture time.
    #[serde(default)]
    pub tempo_traces_captured: usize,

    /// MITRE ATT&CK technique IDs used in this operation.
    pub techniques: Vec<String>,

    /// Whether domain admin was achieved.
    pub has_domain_admin: bool,

    /// Number of credentials harvested.
    pub credential_count: usize,

    /// Number of hosts discovered.
    pub host_count: usize,

    /// When this snapshot was captured.
    pub captured_at: DateTime<Utc>,
}

/// A Grafana alert that fired during the operation window.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FiredAlert {
    /// Alert rule name.
    pub alert_name: String,

    /// When the alert fired.
    pub fired_at: DateTime<Utc>,

    /// Alert labels (severity, technique, etc.).
    pub labels: serde_json::Value,

    /// Alert annotations (summary, description, etc.).
    pub annotations: serde_json::Value,
}

/// Result of a single benchmark replay run.
///
/// Written to `{output_dir}/{run_id}.json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct BenchmarkResult {
    /// Snapshot operation ID.
    pub snapshot_id: String,

    /// Ares operation ID.
    pub operation_id: String,

    /// Investigation ID for this replay run.
    pub run_id: String,

    /// Replay mode: "static" or "timeline".
    pub replay_mode: String,

    /// How the blue team was triggered ("alert-replay" or "operation").
    pub trigger_mode: String,

    /// Name of the alert that triggered the investigation (if alert-replay).
    pub trigger_alert: Option<String>,

    /// How Loki was provisioned ("ephemeral" or "external").
    pub loki_mode: String,

    /// LLM model used for the blue team.
    pub model: String,

    /// When the benchmark run started.
    pub started_at: DateTime<Utc>,

    /// When the benchmark run completed.
    pub completed_at: DateTime<Utc>,

    /// Seconds of quiet period before first alert (timeline mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_period_secs: Option<f64>,

    /// Time compression factor (timeline mode). 1.0 = real-time, 10.0 = 10x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_compression: Option<f64>,

    /// Seconds the blue team investigation took.
    pub investigation_duration_secs: f64,

    /// Full evaluation result (from EvaluationResult.to_value()).
    pub evaluation: serde_json::Value,

    /// Gap analysis report in markdown format.
    pub gap_analysis: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tempo_traces_captured_defaults_when_absent_on_older_manifests() {
        // A snapshot captured before the Tempo capture path landed will
        // have no `tempo_traces_captured` key at all. That must not break
        // `load_manifest` — the visual-replay path is additive on top of
        // the existing blue-eval replay stack.
        let json = serde_json::json!({
            "version": 1,
            "operation_id": "op-20260705-101128",
            "target_domain": "contoso.local",
            "target_ip": "192.168.58.10",
            "started_at": "2026-07-05T10:11:28Z",
            "completed_at": "2026-07-05T10:18:08Z",
            "capture_window_start": "2026-07-05T09:11:28Z",
            "capture_window_end": "2026-07-05T10:48:08Z",
            "loki_source": "s3-chunks",
            "loki_chunks": 42u64,
            "loki_index_files": 3u64,
            "alerts_captured": 9usize,
            "techniques": ["T1078.002", "T1558.001"],
            "has_domain_admin": true,
            "credential_count": 4usize,
            "host_count": 6usize,
            "captured_at": "2026-07-05T10:48:12Z",
        });
        let m: SnapshotManifest = serde_json::from_value(json).unwrap();
        assert_eq!(m.tempo_traces_captured, 0);
    }

    #[test]
    fn tempo_traces_captured_survives_roundtrip() {
        let m = SnapshotManifest {
            version: MANIFEST_VERSION,
            operation_id: "op-1".into(),
            target_domain: "contoso.local".into(),
            target_ip: "192.168.58.10".into(),
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            capture_window_start: chrono::Utc::now(),
            capture_window_end: chrono::Utc::now(),
            loki_source: "s3-chunks".into(),
            loki_chunks: 0,
            loki_index_files: 0,
            alerts_captured: 0,
            metrics_series: 0,
            dashboards_captured: 0,
            annotations_captured: 0,
            tempo_traces_captured: 123,
            techniques: vec![],
            has_domain_admin: false,
            credential_count: 0,
            host_count: 0,
            captured_at: chrono::Utc::now(),
        };
        let j = serde_json::to_string(&m).unwrap();
        let back: SnapshotManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.tempo_traces_captured, 123);
    }
}
