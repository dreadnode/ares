//! OpenTelemetry instrumentation for Ares services.
//!
//! This module provides:
//! - [`init_telemetry`] / [`shutdown_telemetry`] — OTLP pipeline setup (app crates only)
//! - [`mitre`] — MITRE ATT&CK mappings for span attributes
//! - [`spans`] — Typed span attribute builders and span creation helpers
//!
//! # Architecture
//!
//! Library crates (`ares-llm`, etc.) use `tracing` directly via `#[instrument]` and
//! `info_span!`. Only application binaries call [`init_telemetry`] to wire the
//! `tracing-opentelemetry` layer and OTLP exporter.

mod init;
pub mod mitre;
pub mod propagation;
pub mod spans;
pub mod target;

pub use init::{init_telemetry, shutdown_telemetry, TelemetryConfig, TelemetryGuard};
