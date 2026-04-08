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

use crate::telemetry::mitre;

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

/// Builder for creating instrumented spans with Ares domain attributes.
///
/// # Example
///
/// ```ignore
/// use ares_core::telemetry::spans::{AgentSpanBuilder, Team};
///
/// let span = AgentSpanBuilder::new("tool_execution", "recon", Team::Red)
///     .tool("nmap_scan")
///     .target_ip("192.168.58.10")
///     .operation_id("op-123")
///     .build();
///
/// // The span is entered automatically; drop `_guard` to exit.
/// let _guard = span.enter();
/// ```
pub struct AgentSpanBuilder {
    name: String,
    role: String,
    team: Team,
    tool_name: Option<String>,
    target: Target,
    credential_domain: Option<String>,
    operation_id: Option<String>,
    span_kind: SpanKind,
    target_service: Option<String>,
    is_error: bool,
    error_message: Option<String>,
}

impl AgentSpanBuilder {
    pub fn new(name: impl Into<String>, role: impl Into<String>, team: Team) -> Self {
        Self {
            name: name.into(),
            role: role.into(),
            team,
            tool_name: None,
            target: Target::default(),
            credential_domain: None,
            operation_id: None,
            span_kind: SpanKind::Internal,
            target_service: None,
            is_error: false,
            error_message: None,
        }
    }

    pub fn tool(mut self, name: impl Into<String>) -> Self {
        self.tool_name = Some(name.into());
        self
    }

    pub fn target_ip(mut self, ip: impl Into<String>) -> Self {
        self.target.ip = Some(ip.into());
        self
    }

    pub fn target_fqdn(mut self, fqdn: impl Into<String>) -> Self {
        self.target.fqdn = Some(fqdn.into());
        self
    }

    pub fn target_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.target.hostname = Some(hostname.into());
        self
    }

    pub fn target_user(mut self, user: impl Into<String>) -> Self {
        self.target.user = Some(user.into());
        self
    }

    pub fn target_domain(mut self, domain: impl Into<String>) -> Self {
        self.target.domain = Some(domain.into());
        self
    }

    pub fn target_environment(mut self, env: impl Into<String>) -> Self {
        self.target.environment = Some(env.into());
        self
    }

    pub fn credential_domain(mut self, domain: impl Into<String>) -> Self {
        self.credential_domain = Some(domain.into());
        self
    }

    pub fn operation_id(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }

    pub fn kind(mut self, kind: SpanKind) -> Self {
        self.span_kind = kind;
        self
    }

    pub fn target_service(mut self, service: impl Into<String>) -> Self {
        self.target_service = Some(service.into());
        self
    }

    pub fn error(mut self, message: impl Into<String>) -> Self {
        self.is_error = true;
        self.error_message = Some(message.into());
        self
    }

    /// Build the `tracing::Span` with all configured attributes.
    ///
    /// The span name follows the Python convention:
    /// - Tool calls: `tool.{tool_name}`
    /// - General: the `name` passed to the builder
    pub fn build(&self) -> tracing::Span {
        let span_name = match &self.tool_name {
            Some(tool) => format!("tool.{tool}"),
            None => self.name.clone(),
        };

        // Resolve MITRE mappings.
        let (technique_id, tool_tactic) = self
            .tool_name
            .as_deref()
            .map(mitre::get_tool_mitre_info)
            .unwrap_or((None, None));

        let tool_category = self.tool_name.as_deref().and_then(mitre::get_tool_category);

        // Phase and tactic from role.
        let (phase_map, tactic_map) = match self.team {
            Team::Red => (&*mitre::ROLE_TO_PHASE, &*mitre::ROLE_TO_TACTIC),
            Team::Blue => (&*mitre::BLUE_ROLE_TO_PHASE, &*mitre::BLUE_ROLE_TO_TACTIC),
        };

        let attack_phase = phase_map.get(self.role.as_str()).copied().unwrap_or("");
        // Tool-specific tactic overrides role tactic.
        let mitre_tactic = tool_tactic
            .or_else(|| tactic_map.get(self.role.as_str()).copied())
            .unwrap_or("");

        let tool_status = if self.is_error { "error" } else { "success" };

        // Derive hostname from FQDN if not explicitly set.
        let hostname = self.target.hostname.clone().or_else(|| {
            self.target
                .fqdn
                .as_deref()
                .and_then(|f| f.split('.').next())
                .map(String::from)
        });

        // Derive domain from FQDN if not explicitly set.
        let target_domain = self.target.domain.clone().or_else(|| {
            self.target.fqdn.as_deref().and_then(|f| {
                let parts: Vec<&str> = f.splitn(2, '.').collect();
                if parts.len() == 2 {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            })
        });

        // Build the span with all attributes.
        tracing::info_span!(
            "ares.agent",
            otel.name = %span_name,
            otel.kind = self.span_kind.as_str(),
            // Core identity
            attack_team = self.team.as_str(),
            "agent.role" = %self.role,
            attack_phase = attack_phase,
            // MITRE
            "mitre.tactic" = mitre_tactic,
            "mitre.technique.id" = technique_id.unwrap_or(""),
            // Tool
            "tool.name" = self.tool_name.as_deref().unwrap_or(""),
            attack_tool_name = self.tool_name.as_deref().unwrap_or(""),
            attack_tool_category = tool_category.unwrap_or(""),
            "tool.status" = tool_status,
            // Target (OTel semantic conventions)
            "destination.address" = self.target.fqdn.as_deref().unwrap_or(""),
            "destination.ip" = self.target.ip.as_deref().unwrap_or(""),
            "server.address" = self.target.fqdn.as_deref().unwrap_or(""),
            "host.name" = hostname.as_deref().unwrap_or(""),
            "user.name" = self.target.user.as_deref().unwrap_or(""),
            attack_target_domain = target_domain.as_deref().unwrap_or(""),
            "target.environment" = self.target.environment.as_deref().unwrap_or(""),
            "credential.domain" = self.credential_domain.as_deref().unwrap_or(""),
            // Service graph
            "peer.service" = self.target_service.as_deref().unwrap_or(""),
            // Correlation
            attack_operation_id = self.operation_id.as_deref().unwrap_or(""),
            // Error
            error.message = self.error_message.as_deref().unwrap_or(""),
        )
    }
}

/// Create a tool call span (point-in-time recording).
///
/// Equivalent to Python's `trace_tool_call()`.
#[allow(clippy::too_many_arguments)]
pub fn trace_tool_call(
    role: &str,
    team: Team,
    tool_name: &str,
    target_ip: Option<&str>,
    target_fqdn: Option<&str>,
    operation_id: Option<&str>,
    is_error: bool,
    error_message: Option<&str>,
) -> tracing::Span {
    let mut builder = AgentSpanBuilder::new("tool_call", role, team).tool(tool_name);

    if let Some(ip) = target_ip {
        builder = builder.target_ip(ip);
    }
    if let Some(fqdn) = target_fqdn {
        builder = builder.target_fqdn(fqdn);
    }
    if let Some(op) = operation_id {
        builder = builder.operation_id(op);
    }
    if is_error {
        builder = builder.error(error_message.unwrap_or("unknown error"));
    }

    builder.build()
}

/// Create a discovery event span.
///
/// Equivalent to Python's `trace_discovery()`.
pub fn trace_discovery(
    discovery_type: &str,
    source_agent: &str,
    target_user: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&str>,
    operation_id: Option<&str>,
) -> tracing::Span {
    tracing::info_span!(
        "ares.discovery",
        otel.name = format!("discovery.{discovery_type}"),
        "service.namespace" = "ares",
        attack_team = "red",
        attack_phase = "discovery",
        "discovery.type" = discovery_type,
        "discovery.source_agent" = source_agent,
        "user.name" = target_user.unwrap_or(""),
        attack_target_domain = target_domain.unwrap_or(""),
        "destination.ip" = target_ip.unwrap_or(""),
        attack_operation_id = operation_id.unwrap_or(""),
    )
}

/// Create a decision span recording agent tool selection.
///
/// Equivalent to Python's `trace_decision()`.
pub fn trace_decision(
    role: &str,
    team: Team,
    tool_chosen: &str,
    tools_considered: &[String],
    confidence: Option<f64>,
    operation_id: Option<&str>,
) -> tracing::Span {
    let (technique_id, _) = mitre::get_tool_mitre_info(tool_chosen);
    let category = mitre::get_tool_category(tool_chosen);
    let considered_str = tools_considered
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");

    tracing::info_span!(
        "ares.decision",
        otel.name = format!("decision.{role}"),
        attack_team = team.as_str(),
        "agent.role" = role,
        "decision.type" = "tool_selection",
        "decision.tool_chosen" = tool_chosen,
        "decision.tools_considered" = %considered_str,
        "decision.tools_considered_count" = tools_considered.len(),
        "decision.confidence" = confidence.unwrap_or(0.0),
        "mitre.technique.id" = technique_id.unwrap_or(""),
        attack_tool_category = category.unwrap_or(""),
        attack_operation_id = operation_id.unwrap_or(""),
    )
}

/// Create a CLIENT span for outgoing service-to-service calls.
///
/// Equivalent to Python's `client_span()`.
pub fn client_span(name: &str, role: &str, team: Team, target_service: &str) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Client)
        .target_service(target_service)
        .build()
}

/// Create a SERVER span for incoming requests.
///
/// Equivalent to Python's `server_span()`.
pub fn server_span(name: &str, role: &str, team: Team) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Server)
        .build()
}

/// Create a PRODUCER span for async message publishing.
///
/// Equivalent to Python's `producer_span()`.
pub fn producer_span(name: &str, role: &str, team: Team, target_service: &str) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Producer)
        .target_service(target_service)
        .build()
}

/// Create a CONSUMER span for async message consumption.
///
/// Equivalent to Python's `consumer_span()`.
pub fn consumer_span(name: &str, role: &str, team: Team) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Consumer)
        .build()
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
    fn test_agent_span_builder_basic() {
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
    fn test_trace_tool_call() {
        init_test_subscriber();
        let span = trace_tool_call(
            "credential_access",
            Team::Red,
            "secretsdump",
            Some("192.168.58.10"),
            Some("dc01.contoso.local"),
            Some("op-001"),
            false,
            None,
        );
        assert!(!span.is_disabled());
    }

    #[test]
    fn test_trace_discovery() {
        init_test_subscriber();
        let span = trace_discovery(
            "credential",
            "recon",
            Some("admin"),
            Some("contoso.local"),
            Some("192.168.58.10"),
            Some("op-001"),
        );
        assert!(!span.is_disabled());
    }

    #[test]
    fn test_trace_decision() {
        init_test_subscriber();
        let tools = vec!["nmap_scan".to_string(), "smb_sweep".to_string()];
        let span = trace_decision("recon", Team::Red, "nmap_scan", &tools, Some(0.9), None);
        assert!(!span.is_disabled());
    }

    #[test]
    fn test_service_graph_spans() {
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
    fn test_error_span() {
        init_test_subscriber();
        let span = AgentSpanBuilder::new("tool_call", "lateral", Team::Red)
            .tool("psexec")
            .error("connection refused")
            .build();
        assert!(!span.is_disabled());
    }
}
