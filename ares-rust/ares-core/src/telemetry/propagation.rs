//! W3C TraceContext propagation for cross-service span linking via Redis.
//!
//! When the orchestrator dispatches a tool call to a worker through Redis,
//! the trace context (traceparent header) is serialized into the message.
//! The worker extracts it and links its consumer span to the orchestrator's
//! producer span, creating a single distributed trace across the queue.

use std::collections::HashMap;

use opentelemetry::global;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Extract the current tracing span's W3C traceparent header.
///
/// Returns `None` if no OTel propagator is configured or the span has no
/// valid trace context (e.g., running without an OTLP exporter).
pub fn inject_traceparent(span: &tracing::Span) -> Option<String> {
    let context = span.context();
    let mut carrier = HashMap::new();
    global::get_text_map_propagator(|prop| {
        prop.inject_context(&context, &mut carrier);
    });
    carrier.remove("traceparent")
}

/// Set a remote parent on a span from a W3C traceparent header.
///
/// Links a worker-side span to its orchestrator-side parent, creating a
/// continuous trace across the Redis queue boundary.
pub fn set_span_parent(span: &tracing::Span, traceparent: &str) {
    let mut carrier = HashMap::new();
    carrier.insert("traceparent".to_string(), traceparent.to_string());
    let context = global::get_text_map_propagator(|prop| prop.extract(&carrier));
    let _ = span.set_parent(context);
}
