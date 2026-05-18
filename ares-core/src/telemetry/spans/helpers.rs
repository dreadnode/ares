//! Factory/helper functions for creating common span types.

use crate::telemetry::mitre;

use super::builder::AgentSpanBuilder;
use super::{SpanKind, Team};

pub struct TraceToolCallParams<'a> {
    pub role: &'a str,
    pub team: Team,
    pub tool_name: &'a str,
    pub target_ip: Option<&'a str>,
    pub target_fqdn: Option<&'a str>,
    pub target_user: Option<&'a str>,
    pub target_type: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub is_error: bool,
    pub error_message: Option<&'a str>,
}

/// Create a tool call span (point-in-time recording).
pub fn trace_tool_call(p: TraceToolCallParams<'_>) -> tracing::Span {
    let mut builder = AgentSpanBuilder::new("tool_call", p.role, p.team).tool(p.tool_name);

    if let Some(ip) = p.target_ip {
        builder = builder.target_ip(ip);
    }
    if let Some(fqdn) = p.target_fqdn {
        builder = builder.target_fqdn(fqdn);
    }
    if let Some(user) = p.target_user {
        builder = builder.target_user(user);
    }
    if let Some(tt) = p.target_type {
        builder = builder.target_type(tt);
    }
    if let Some(op) = p.operation_id {
        builder = builder.operation_id(op);
    }
    if let Some(t) = p.task_id {
        builder = builder.task_id(t);
    }
    if p.is_error {
        builder = builder.error(p.error_message.unwrap_or("unknown error"));
    }

    builder.build()
}

pub struct TraceDiscoveryParams<'a> {
    pub discovery_type: &'a str,
    pub source_agent: &'a str,
    pub target_user: Option<&'a str>,
    pub target_domain: Option<&'a str>,
    pub target_ip: Option<&'a str>,
    pub target_fqdn: Option<&'a str>,
    pub target_type: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
}

/// Create a discovery event span.
pub fn trace_discovery(p: TraceDiscoveryParams<'_>) -> tracing::Span {
    tracing::info_span!(
        "ares.discovery",
        otel.name = format!("discovery.{}", p.discovery_type),
        "service.namespace" = "ares",
        attack_team = "red",
        attack_phase = "discovery",
        "discovery.type" = p.discovery_type,
        "discovery.source_agent" = p.source_agent,
        "user.name" = p.target_user.unwrap_or(""),
        attack_target_type = p.target_type.unwrap_or(""),
        attack_target_domain = p.target_domain.unwrap_or(""),
        "destination.address" = p.target_fqdn.or(p.target_ip).unwrap_or(""),
        "destination.ip" = p.target_ip.unwrap_or(""),
        attack_operation_id = p.operation_id.unwrap_or(""),
        "op.id" = p.operation_id.unwrap_or(""),
        "task.id" = p.task_id.unwrap_or(""),
    )
}

pub struct TraceDecisionParams<'a> {
    pub role: &'a str,
    pub team: Team,
    pub tool_chosen: &'a str,
    pub tools_considered: &'a [String],
    pub confidence: Option<f64>,
    pub operation_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
}

/// Create a decision span recording agent tool selection.
pub fn trace_decision(p: TraceDecisionParams<'_>) -> tracing::Span {
    let (technique_id, _) = mitre::get_tool_mitre_info(p.tool_chosen);
    let category = mitre::get_tool_category(p.tool_chosen);
    let considered_str = p
        .tools_considered
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");

    tracing::info_span!(
        "ares.decision",
        otel.name = format!("decision.{}", p.role),
        attack_team = p.team.as_str(),
        "agent.role" = p.role,
        "decision.type" = "tool_selection",
        "decision.tool_chosen" = p.tool_chosen,
        "decision.tools_considered" = %considered_str,
        "decision.tools_considered_count" = p.tools_considered.len(),
        "decision.confidence" = p.confidence.unwrap_or(0.0),
        "mitre.technique.id" = technique_id.unwrap_or(""),
        attack_tool_category = category.unwrap_or(""),
        attack_operation_id = p.operation_id.unwrap_or(""),
        "op.id" = p.operation_id.unwrap_or(""),
        "task.id" = p.task_id.unwrap_or(""),
    )
}

/// Create a domain admin achievement span with the full attack path.
///
/// Emitted when DA is achieved. The `attack_path` attribute is queryable
/// in Grafana/Tempo to reconstruct how the operation reached domain admin.
pub fn trace_domain_admin(
    attack_path: &str,
    attack_depth: usize,
    operation_id: Option<&str>,
    task_id: Option<&str>,
) -> tracing::Span {
    tracing::info_span!(
        "ares.discovery",
        otel.name = "discovery.domain_admin",
        "service.namespace" = "ares",
        attack_team = "red",
        attack_phase = "credential-access",
        "discovery.type" = "domain_admin",
        attack_path = attack_path,
        "attack.depth" = attack_depth,
        "mitre.technique.id" = "T1003.006",
        "mitre.tactic" = "credential-access",
        attack_operation_id = operation_id.unwrap_or(""),
        "op.id" = operation_id.unwrap_or(""),
        "task.id" = task_id.unwrap_or(""),
    )
}

/// Extract target info from tool call arguments for span attributes.
///
/// Tool arguments commonly include `target` (IP/hostname), `username`/`user`,
/// and `domain`. This helper pulls them out so span builders can populate
/// `destination.address`, `user.name`, and `attack_target_domain`.
pub fn extract_target_from_args(
    args: &serde_json::Value,
) -> (Option<String>, Option<String>, Option<String>) {
    let target = args
        .get("target")
        .or_else(|| args.get("host"))
        .or_else(|| args.get("dc_ip"))
        .or_else(|| args.get("dc"))
        .or_else(|| args.get("ip"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    let user = args
        .get("username")
        .or_else(|| args.get("user"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    (target, user, domain)
}

/// Create a CLIENT span for outgoing service-to-service calls.
pub fn client_span(name: &str, role: &str, team: Team, target_service: &str) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Client)
        .target_service(target_service)
        .build()
}

/// Create a SERVER span for incoming requests.
pub fn server_span(name: &str, role: &str, team: Team) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Server)
        .build()
}

/// Create a PRODUCER span for async message publishing.
pub fn producer_span(name: &str, role: &str, team: Team, target_service: &str) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Producer)
        .target_service(target_service)
        .build()
}

/// Create a CONSUMER span for async message consumption.
pub fn consumer_span(name: &str, role: &str, team: Team) -> tracing::Span {
    AgentSpanBuilder::new(name, role, team)
        .kind(SpanKind::Consumer)
        .build()
}
