//! Span attribute builders for Ares agent telemetry.
//!
//! These helpers produce `tracing::Span` instances with structured attributes
//! that emit the canonical span schema to Tempo/Grafana.
//!
//! # Usage
//!
//! Library code should use `#[tracing::instrument]` directly. These helpers are
//! for application-level orchestration and worker code that needs domain-aware
//! span attributes (MITRE mappings, target metadata, etc.).

mod builder;
mod helpers;

pub use builder::{record_span_status, AgentSpanBuilder};
pub use helpers::{
    client_span, consumer_span, extract_target_from_args, producer_span, server_span,
    trace_decision, trace_discovery, trace_domain_admin, trace_tool_call, ServiceSpanParams,
    TraceDecisionParams, TraceDiscoveryParams, TraceToolCallParams,
};

/// Team affiliation for span attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Team {
    Red,
    Blue,
}

impl Team {
    pub fn as_str(&self) -> &'static str {
        match self {
            Team::Red => "red",
            Team::Blue => "blue",
        }
    }
}

impl std::fmt::Display for Team {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OTel span kind hint (recorded as the `otel.kind` tracing field).
#[derive(Debug, Clone, Copy)]
pub enum SpanKind {
    Internal,
    Client,
    Server,
    Producer,
    Consumer,
}

impl SpanKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpanKind::Internal => "internal",
            SpanKind::Client => "client",
            SpanKind::Server => "server",
            SpanKind::Producer => "producer",
            SpanKind::Consumer => "consumer",
        }
    }
}

/// Target information for span attributes.
#[derive(Debug, Default, Clone)]
pub struct Target {
    pub ip: Option<String>,
    pub fqdn: Option<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub environment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// Install a minimal subscriber for tests so spans are not disabled.
    fn init_test_subscriber() {
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_test_writer())
            .try_init();
    }

    #[test]
    fn agent_span_builder_basic() {
        init_test_subscriber();
        let span = AgentSpanBuilder::new("test_op", "recon", Team::Red)
            .tool("nmap_scan")
            .target_ip("192.168.58.10")
            .target_fqdn("dc01.contoso.local")
            .operation_id("op-001")
            .build();

        assert!(!span.is_disabled());
    }

    #[test]
    fn traces_tool_call() {
        init_test_subscriber();
        let span = trace_tool_call(TraceToolCallParams {
            role: "credential_access",
            team: Team::Red,
            tool_name: "secretsdump",
            target_ip: Some("192.168.58.10"),
            target_fqdn: Some("dc01.contoso.local"),
            target_user: Some("admin"),
            target_type: Some("domain_controller"),
            operation_id: Some("op-001"),
            task_id: Some("task-aaa"),
            is_error: false,
            error_message: None,
            defer_status: false,
        });
        assert!(!span.is_disabled());
    }

    type CapturedFields =
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>;

    struct FieldCapture(CapturedFields);

    impl tracing::field::Visit for FieldCapture {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0
                .lock()
                .expect("captured fields lock")
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .expect("captured fields lock")
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    struct CaptureLayer(CapturedFields);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            attrs.record(&mut FieldCapture(Arc::clone(&self.0)));
        }

        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            values.record(&mut FieldCapture(Arc::clone(&self.0)));
        }
    }

    fn with_captured_fields(f: impl FnOnce(&CapturedFields)) {
        let captured: CapturedFields =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer(Arc::clone(&captured)));
        tracing::subscriber::with_default(subscriber, || f(&captured));
    }

    fn captured(fields: &CapturedFields, key: &str) -> Option<String> {
        fields
            .lock()
            .expect("captured fields lock")
            .get(key)
            .cloned()
    }

    fn deferred_tool_span() -> tracing::Span {
        trace_tool_call(TraceToolCallParams {
            role: "lateral",
            team: Team::Red,
            tool_name: "psexec",
            target_ip: Some("192.168.58.20"),
            target_fqdn: Some("web01.fabrikam.local"),
            target_user: Some("alice"),
            target_type: Some("workstation"),
            operation_id: Some("op-002"),
            task_id: Some("task-bbb"),
            is_error: false,
            error_message: None,
            defer_status: true,
        })
    }

    #[test]
    fn deferred_status_stays_unset_until_recorded() {
        with_captured_fields(|fields| {
            let _span = deferred_tool_span();
            assert_eq!(captured(fields, "otel.status_code"), None);
            assert_eq!(captured(fields, "otel.status_message"), None);
            assert_eq!(captured(fields, "tool.status"), None);
        });
    }

    #[test]
    fn deferred_status_records_failure_after_the_fact() {
        with_captured_fields(|fields| {
            let span = deferred_tool_span();
            record_span_status(&span, Some("STATUS_LOGON_FAILURE"));
            assert_eq!(
                captured(fields, "otel.status_code").as_deref(),
                Some("ERROR")
            );
            assert_eq!(
                captured(fields, "otel.status_message").as_deref(),
                Some("STATUS_LOGON_FAILURE")
            );
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("error"));
            assert_eq!(
                captured(fields, "error.message").as_deref(),
                Some("STATUS_LOGON_FAILURE")
            );
        });
    }

    #[test]
    fn deferred_status_records_success_after_the_fact() {
        with_captured_fields(|fields| {
            let span = deferred_tool_span();
            record_span_status(&span, None);
            assert_eq!(captured(fields, "otel.status_code").as_deref(), Some("OK"));
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("success"));
        });
    }

    #[test]
    fn known_outcome_still_sets_status_at_construction() {
        with_captured_fields(|fields| {
            let _ok = AgentSpanBuilder::new("tool_call", "recon", Team::Red)
                .tool("nmap_scan")
                .target_ip("192.168.58.10")
                .build();
            assert_eq!(captured(fields, "otel.status_code").as_deref(), Some("OK"));
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("success"));
        });

        with_captured_fields(|fields| {
            let _err = AgentSpanBuilder::new("tool_call", "lateral", Team::Red)
                .tool("psexec")
                .error("connection refused")
                .build();
            assert_eq!(
                captured(fields, "otel.status_code").as_deref(),
                Some("ERROR")
            );
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("error"));
            assert_eq!(
                captured(fields, "error.message").as_deref(),
                Some("connection refused")
            );
        });
    }

    #[test]
    fn traces_discovery() {
        init_test_subscriber();
        let span = trace_discovery(TraceDiscoveryParams {
            discovery_type: "credential",
            source_agent: "recon",
            target_user: Some("admin"),
            target_domain: Some("contoso.local"),
            target_ip: Some("192.168.58.10"),
            target_fqdn: Some("dc01.contoso.local"),
            target_type: Some("domain_controller"),
            operation_id: Some("op-001"),
            task_id: Some("task-aaa"),
        });
        assert!(!span.is_disabled());
    }

    #[test]
    fn traces_decision() {
        init_test_subscriber();
        let tools = vec!["nmap_scan".to_string(), "smb_sweep".to_string()];
        let span = trace_decision(TraceDecisionParams {
            role: "recon",
            team: Team::Red,
            tool_chosen: "nmap_scan",
            tools_considered: &tools,
            confidence: Some(0.9),
            operation_id: Some("op-001"),
            task_id: Some("task-aaa"),
        });
        assert!(!span.is_disabled());
    }

    fn service_params<'a>(
        name: &'a str,
        role: &'a str,
        target_service: Option<&'a str>,
        defer_status: bool,
    ) -> ServiceSpanParams<'a> {
        ServiceSpanParams {
            name,
            role,
            team: Team::Red,
            target_service,
            defer_status,
        }
    }

    #[test]
    fn service_graph_spans() {
        init_test_subscriber();
        let c = client_span(service_params(
            "dispatch",
            "orchestrator",
            Some("ares-recon-agent"),
            false,
        ));
        assert!(!c.is_disabled());

        let s = server_span(service_params("handle_task", "recon", None, false));
        assert!(!s.is_disabled());

        let p = producer_span(service_params(
            "publish_task",
            "orchestrator",
            Some("ares-recon-agent"),
            false,
        ));
        assert!(!p.is_disabled());

        let co = consumer_span(service_params("consume_task", "recon", None, false));
        assert!(!co.is_disabled());
    }

    #[test]
    fn service_span_without_defer_records_success_at_construction() {
        with_captured_fields(|fields| {
            let _span = producer_span(service_params(
                "dispatch.secretsdump",
                "orchestrator",
                Some("ares-worker-credential_access"),
                false,
            ));
            assert_eq!(captured(fields, "otel.status_code").as_deref(), Some("OK"));
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("success"));
        });
    }

    #[test]
    fn deferred_service_span_stays_unset_until_recorded() {
        with_captured_fields(|fields| {
            let span = producer_span(service_params(
                "dispatch.psexec",
                "orchestrator",
                Some("ares-worker-lateral"),
                true,
            ));
            assert_eq!(captured(fields, "otel.status_code"), None);
            assert_eq!(captured(fields, "tool.status"), None);

            record_span_status(&span, Some("timed out after 600s"));
            assert_eq!(
                captured(fields, "otel.status_code").as_deref(),
                Some("ERROR")
            );
            assert_eq!(
                captured(fields, "otel.status_message").as_deref(),
                Some("timed out after 600s")
            );
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("error"));
        });
    }

    #[test]
    fn deferred_service_span_records_success() {
        with_captured_fields(|fields| {
            let span = consumer_span(service_params("tool_exec", "recon", None, true));
            record_span_status(&span, None);
            assert_eq!(captured(fields, "otel.status_code").as_deref(), Some("OK"));
            assert_eq!(captured(fields, "tool.status").as_deref(), Some("success"));
        });
    }

    #[test]
    fn error_span() {
        init_test_subscriber();
        let span = AgentSpanBuilder::new("tool_call", "lateral", Team::Red)
            .tool("psexec")
            .error("connection refused")
            .build();
        assert!(!span.is_disabled());
    }

    #[test]
    fn success_and_error_spans_carry_otel_status_code() {
        // The demo dashboard's Red Success Rate panel filters
        // `traces_spanmetrics_calls_total` on `status_code = "STATUS_CODE_OK"`.
        // That label is derived by the OTel Collector's spanmetrics processor
        // from the OTLP span Status enum, which tracing-opentelemetry sets
        // from the `otel.status_code` sentinel field on the tracing span.
        // Both branches (success and error) must build cleanly with the
        // sentinel present — otherwise the label never leaves the collector
        // and the panel reads zero.
        init_test_subscriber();
        let ok = AgentSpanBuilder::new("tool_call", "recon", Team::Red)
            .tool("nmap_scan")
            .target_ip("192.168.58.10")
            .build();
        assert!(!ok.is_disabled());

        let err = AgentSpanBuilder::new("tool_call", "lateral", Team::Red)
            .tool("psexec")
            .target_ip("192.168.58.10")
            .error("STATUS_LOGON_FAILURE")
            .build();
        assert!(!err.is_disabled());
    }
}
