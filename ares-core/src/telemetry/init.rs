//! Telemetry pipeline initialization and shutdown.
//!
//! Call [`init_telemetry`] once at application startup. It returns a
//! [`TelemetryGuard`] whose [`shutdown`](TelemetryGuard::shutdown) method
//! flushes remaining spans on graceful exit.

use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Configuration for telemetry initialization.
pub struct TelemetryConfig {
    /// Service name reported in OTel resource attributes.
    pub service_name: String,
    /// Default log filter when `RUST_LOG` is not set.
    pub default_filter: String,
    /// Show the `target` column in console output.
    pub show_target: bool,
}

impl TelemetryConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            default_filter: "info".to_string(),
            show_target: false,
        }
    }

    pub fn with_default_filter(mut self, filter: impl Into<String>) -> Self {
        self.default_filter = filter.into();
        self
    }

    pub fn with_show_target(mut self, show: bool) -> Self {
        self.show_target = show;
        self
    }
}

/// Handle returned by [`init_telemetry`]. Call [`shutdown`](Self::shutdown) on
/// graceful exit to flush pending spans.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    /// Flush and shut down the tracer provider. Safe to call multiple times.
    pub fn shutdown(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("telemetry shutdown error: {e}");
            }
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Initialize the telemetry pipeline.
///
/// When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT`
/// is set, spans are exported via OTLP/gRPC. Otherwise only console logging is
/// active (no-op for traces).
///
/// Returns a [`TelemetryGuard`] that must be kept alive for the duration of the
/// program. Dropping it flushes remaining spans.
pub fn init_telemetry(config: TelemetryConfig) -> TelemetryGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.default_filter));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(config.show_target)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    // Try to set up OTLP exporter if endpoint is configured.
    let otel = try_init_otel_provider(&config.service_name);

    match otel {
        Some(provider) => {
            let tracer = provider.tracer(config.service_name.clone());
            let otel_layer = OpenTelemetryLayer::new(tracer);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();

            tracing::info!(
                service = %config.service_name,
                "telemetry initialized with OTLP exporter"
            );

            TelemetryGuard {
                provider: Some(provider),
            }
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();

            TelemetryGuard { provider: None }
        }
    }
}

/// Convenience wrapper: call `guard.shutdown()`.
pub fn shutdown_telemetry(guard: &mut TelemetryGuard) {
    guard.shutdown();
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/// Attempt to build an OTLP span exporter + tracer provider. Returns `None` if
/// no OTLP endpoint is configured (neither `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
/// nor `OTEL_EXPORTER_OTLP_ENDPOINT`).
fn try_init_otel_provider(service_name: &str) -> Option<SdkTracerProvider> {
    // The OTel SDK reads OTEL_EXPORTER_OTLP_* env vars automatically.
    // We check presence so we can skip provider creation entirely when no
    // collector is reachable — avoids noisy connection-refused errors.
    let has_endpoint = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_ok()
        || std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();

    if !has_endpoint {
        return None;
    }

    // W3C TraceContext propagator for cross-service context propagation.
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = match SpanExporter::builder().with_tonic().build() {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!("failed to create OTLP span exporter: {e}");
            return None;
        }
    };

    // Build resource with service name, namespace, and optional OTEL_RESOURCE_ATTRIBUTES.
    let mut resource_attrs = vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.namespace", "attack-simulation"),
    ];

    // Parse OTEL_RESOURCE_ATTRIBUTES (comma-separated key=value pairs).
    if let Ok(extra) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
        for pair in extra.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                resource_attrs.push(KeyValue::new(k.trim().to_string(), v.trim().to_string()));
            }
        }
    }

    let resource = Resource::builder().with_attributes(resource_attrs).build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());

    Some(provider)
}
