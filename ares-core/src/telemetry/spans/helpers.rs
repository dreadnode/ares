//! Factory/helper functions for creating common span types.

use crate::telemetry::mitre;

use super::builder::AgentSpanBuilder;
use super::{SpanKind, Team};

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
    target_user: Option<&str>,
    target_type: Option<&str>,
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
    if let Some(user) = target_user {
        builder = builder.target_user(user);
    }
    if let Some(tt) = target_type {
        builder = builder.target_type(tt);
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
#[allow(clippy::too_many_arguments)]
pub fn trace_discovery(
    discovery_type: &str,
    source_agent: &str,
    target_user: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&str>,
    target_fqdn: Option<&str>,
    target_type: Option<&str>,
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
        attack_target_type = target_type.unwrap_or(""),
        attack_target_domain = target_domain.unwrap_or(""),
        "destination.address" = target_fqdn.unwrap_or(""),
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

/// Create a domain admin achievement span with the full attack path.
///
/// Emitted when DA is achieved. The `attack_path` attribute is queryable
/// in Grafana/Tempo to reconstruct how the operation reached domain admin.
pub fn trace_domain_admin(
    attack_path: &str,
    attack_depth: usize,
    operation_id: Option<&str>,
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
        attack_operation_id = operation_id.unwrap_or(""),
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
