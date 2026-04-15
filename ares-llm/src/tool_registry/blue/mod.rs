//! Blue team tool definitions for investigation agents.
//!
//! Provides tool schemas for Loki log queries, evidence recording,
//! investigation state management, and agent callbacks.

mod callbacks;
mod detection;
mod grafana;
mod learning;
mod loki;
mod orchestrator;
mod prometheus;
mod state;

use crate::ToolDefinition;

/// Blue team agent roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlueAgentRole {
    /// Orchestrator coordinating multi-agent investigation
    Orchestrator,
    /// Initial alert triage
    Triage,
    /// Deep investigation using log analysis
    ThreatHunter,
    /// Lateral movement analysis
    LateralAnalyst,
    /// Escalation triage evaluation
    EscalationTriage,
}

impl BlueAgentRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Orchestrator => "blue_orchestrator",
            Self::Triage => "triage",
            Self::ThreatHunter => "threat_hunter",
            Self::LateralAnalyst => "lateral_analyst",
            Self::EscalationTriage => "escalation_triage",
        }
    }
}

/// Names of blue team callback tools handled in Rust (not dispatched to workers).
pub const BLUE_CALLBACK_TOOLS: &[&str] = &[
    "triage_complete",
    "hunt_complete",
    "lateral_complete",
    "complete_investigation",
    "escalate_investigation",
    "confirm_escalation",
    "downgrade_escalation",
    "request_reinvestigation",
    "route_to_team",
];

/// Check if a tool name is a blue team callback.
pub fn is_blue_callback_tool(name: &str) -> bool {
    BLUE_CALLBACK_TOOLS.contains(&name)
}

/// Get tool definitions for a blue team agent role.
pub fn blue_tools_for_role(role: BlueAgentRole) -> Vec<ToolDefinition> {
    let mut tools = match role {
        BlueAgentRole::Orchestrator => orchestrator::orchestrator_tool_definitions(),
        BlueAgentRole::Triage => triage_tool_definitions(),
        BlueAgentRole::ThreatHunter => threat_hunter_tool_definitions(),
        BlueAgentRole::LateralAnalyst => lateral_analyst_tool_definitions(),
        BlueAgentRole::EscalationTriage => callbacks::escalation_triage_tool_definitions(),
    };

    // Redis-backed investigation state mutation tools
    match role {
        BlueAgentRole::Triage
        | BlueAgentRole::ThreatHunter
        | BlueAgentRole::LateralAnalyst
        | BlueAgentRole::Orchestrator
        | BlueAgentRole::EscalationTriage => {
            tools.extend(state::investigation_state_tool_definitions());
        }
    }

    // Lateral connection tool only for lateral_analyst
    if role == BlueAgentRole::LateralAnalyst {
        tools.push(state::lateral_connection_tool_definition());
    }

    tools
}

// ---------------------------------------------------------------------------
// Role-specific tool set assembly
// ---------------------------------------------------------------------------

fn triage_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki::loki_tool_definitions();
    tools.extend(grafana::grafana_tool_definitions());
    tools.extend(learning::learning_tool_definitions());
    tools.extend(callbacks::worker_callback_definitions());
    tools
}

fn threat_hunter_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki::loki_tool_definitions();
    tools.extend(prometheus::prometheus_tool_definitions());
    tools.extend(grafana::grafana_tool_definitions());
    tools.extend(detection::detection_query_tool_definitions());
    tools.extend(learning::learning_tool_definitions());
    tools.extend(callbacks::worker_callback_definitions());
    tools
}

fn lateral_analyst_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki::loki_tool_definitions();
    tools.extend(grafana::grafana_tool_definitions());
    tools.extend(detection::detection_query_tool_definitions());
    tools.extend(learning::learning_tool_definitions());
    tools.extend(callbacks::worker_callback_definitions());
    tools
}
