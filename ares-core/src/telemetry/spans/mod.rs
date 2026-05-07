//! Span attribute builders for Ares agent telemetry.
//!
//! These helpers produce `tracing::Span` instances with structured attributes
//! matching the Python `tracing.py` conventions so both languages emit
//! identical span schemas to Tempo/Grafana.
//!
//! # Usage
//!
//! Library code should use `#[tracing::instrument]` directly. These helpers are
//! for application-level orchestration and worker code that needs domain-aware
//! span attributes (MITRE mappings, target metadata, etc.).

mod builder;
mod helpers;

// Re-export all public items at module level.
pub use builder::AgentSpanBuilder;
pub use helpers::{
    client_span, consumer_span, extract_target_from_args, producer_span, server_span,
    trace_decision, trace_discovery, trace_domain_admin, trace_tool_call,
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
        let span = trace_tool_call(
            "credential_access",
            Team::Red,
            "secretsdump",
            Some("192.168.58.10"),
            Some("dc01.contoso.local"),
            Some("admin"),
            Some("domain_controller"),
            Some("op-001"),
            Some("task-aaa"),
            false,
            None,
        );
        assert!(!span.is_disabled());
    }

    #[test]
    fn traces_discovery() {
        init_test_subscriber();
        let span = trace_discovery(
            "credential",
            "recon",
            Some("admin"),
            Some("contoso.local"),
            Some("192.168.58.10"),
            Some("dc01.contoso.local"),
            Some("domain_controller"),
            Some("op-001"),
            Some("task-aaa"),
        );
        assert!(!span.is_disabled());
    }

    #[test]
    fn traces_decision() {
        init_test_subscriber();
        let tools = vec!["nmap_scan".to_string(), "smb_sweep".to_string()];
        let span = trace_decision(
            "recon",
            Team::Red,
            "nmap_scan",
            &tools,
            Some(0.9),
            Some("op-001"),
            Some("task-aaa"),
        );
        assert!(!span.is_disabled());
    }

    #[test]
    fn service_graph_spans() {
        init_test_subscriber();
        let c = client_span("dispatch", "orchestrator", Team::Red, "ares-recon-agent");
        assert!(!c.is_disabled());

        let s = server_span("handle_task", "recon", Team::Red);
        assert!(!s.is_disabled());

        let p = producer_span(
            "publish_task",
            "orchestrator",
            Team::Red,
            "ares-recon-agent",
        );
        assert!(!p.is_disabled());

        let co = consumer_span("consume_task", "recon", Team::Red);
        assert!(!co.is_disabled());
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
}
