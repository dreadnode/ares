//! Pinned image versions used by capture-time tooling.
//!
//! The Prometheus TSDB pre-build in `capture.rs` runs promtool from a pinned
//! Docker image — that version MUST match the Prometheus in the replay stack,
//! else the blocks won't load. The compose file at
//! `benchmarks/replay-stack/docker-compose.yml` is the source of truth.

/// Prometheus image whose `promtool` pre-builds the TSDB blocks at capture time.
/// MUST match the `prometheus.image` field in
/// `benchmarks/replay-stack/docker-compose.yml`.
pub(crate) const PROMETHEUS_IMAGE: &str = "prom/prometheus:v3.11.3";
