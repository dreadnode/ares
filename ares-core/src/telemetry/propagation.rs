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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_traceparent_returns_none_without_propagator() {
        // No OTel provider is configured in unit tests. The global propagator
        // is the no-op default which injects nothing into the carrier, so
        // `inject_traceparent` must return None rather than panic.
        let span = tracing::Span::none();
        let result = inject_traceparent(&span);
        assert!(result.is_none());
    }

    #[test]
    fn set_span_parent_does_not_panic_with_no_provider() {
        // Calling set_span_parent with a well-formed traceparent value when no
        // OTel provider is configured should be a no-op — not a panic.
        let span = tracing::Span::none();
        // Valid W3C traceparent format: version-trace_id-parent_id-flags
        set_span_parent(
            &span,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        );
    }

    #[test]
    fn set_span_parent_does_not_panic_with_malformed_header() {
        // A malformed traceparent should be silently ignored, not panic.
        let span = tracing::Span::none();
        set_span_parent(&span, "not-a-valid-traceparent");
    }
}
