//! AgentSpanBuilder: typed builder for creating instrumented spans.

use crate::telemetry::mitre;

use super::{SpanKind, Target, Team};

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
    target_type: Option<String>,
    credential_domain: Option<String>,
    operation_id: Option<String>,
    task_id: Option<String>,
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
            target_type: None,
            credential_domain: None,
            operation_id: None,
            task_id: None,
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

    /// Set the target IP. Rejects CIDR ranges and multi-value strings.
    pub fn target_ip(mut self, ip: impl Into<String>) -> Self {
        let ip = ip.into();
        // Defense-in-depth: reject values that aren't single IP addresses.
        // extract_target_info should already sanitize, but guard here too.
        if !ip.contains('/') && !ip.contains(' ') && ip.parse::<std::net::IpAddr>().is_ok() {
            self.target.ip = Some(ip);
        }
        self
    }

    /// Set the target FQDN. Rejects multi-value strings.
    pub fn target_fqdn(mut self, fqdn: impl Into<String>) -> Self {
        let fqdn = fqdn.into();
        // Defense-in-depth: reject values containing spaces or slashes
        if !fqdn.contains(' ') && !fqdn.contains('/') {
            self.target.fqdn = Some(fqdn);
        }
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

    pub fn target_type(mut self, target_type: impl Into<String>) -> Self {
        self.target_type = Some(target_type.into());
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

    /// Per-task identifier within an operation. Distinct from `operation_id`:
    /// `op.id` correlates every span belonging to one red-team operation,
    /// `task.id` correlates every span belonging to one agent loop run.
    pub fn task_id(mut self, id: impl Into<String>) -> Self {
        self.task_id = Some(id.into());
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
    /// Span name:
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
        let tool_binary = self.tool_name.as_deref().and_then(mitre::get_tool_binary);
        let tool_yaml_category = self
            .tool_name
            .as_deref()
            .and_then(mitre::get_tool_yaml_category);

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
            "tool.binary" = tool_binary.unwrap_or(""),
            "tool.provisioned_category" = tool_yaml_category.unwrap_or(""),
            "tool.status" = tool_status,
            // Target (OTel semantic conventions)
            // Fall back to IP when no FQDN is available so IP-targeted tools
            // produce a non-empty destination.address for the attack graph.
            "destination.address" = self.target.fqdn.as_deref().or(self.target.ip.as_deref()).unwrap_or(""),
            "destination.ip" = self.target.ip.as_deref().unwrap_or(""),
            "server.address" = self.target.fqdn.as_deref().unwrap_or(""),
            "host.name" = hostname.as_deref().unwrap_or(""),
            "user.name" = self.target.user.as_deref().unwrap_or(""),
            attack_target_type = self.target_type.as_deref().unwrap_or(""),
            attack_target_domain = target_domain.as_deref().unwrap_or(""),
            "target.environment" = self.target.environment.as_deref().unwrap_or(""),
            "credential.domain" = self.credential_domain.as_deref().unwrap_or(""),
            // Service graph
            "peer.service" = self.target_service.as_deref().unwrap_or(""),
            // Correlation
            // `attack_operation_id` is retained for dashboards already
            // querying that field; `op.id` / `task.id` are the OTel-style
            // names new code and dashboards should prefer.
            attack_operation_id = self.operation_id.as_deref().unwrap_or(""),
            "op.id" = self.operation_id.as_deref().unwrap_or(""),
            "task.id" = self.task_id.as_deref().unwrap_or(""),
            // Error
            error.message = self.error_message.as_deref().unwrap_or(""),
        )
    }
}
