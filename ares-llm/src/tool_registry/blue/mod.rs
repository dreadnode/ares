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

    if role == BlueAgentRole::LateralAnalyst {
        tools.push(state::lateral_connection_tool_definition());
    }

    tools
}

fn triage_tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = loki::loki_tool_definitions();
    tools.extend(grafana::grafana_tool_definitions());
    // Triage is stage 1 (initial scoping) and must be able to invoke the
    // pre-built detection templates (ADCS / AS-REP / cross-realm) directly,
    // not just re-derive their LogQL by hand.
    tools.extend(detection::detection_query_tool_definitions());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_names(role: BlueAgentRole) -> Vec<String> {
        blue_tools_for_role(role)
            .into_iter()
            .map(|t| t.name)
            .collect()
    }

    #[test]
    fn triage_has_detection_query_tools() {
        // Triage is stage 1 and must be able to invoke the pre-built ADCS /
        // AS-REP / cross-realm detection templates directly (P1).
        let names = tool_names(BlueAgentRole::Triage);
        assert!(
            names.iter().any(|n| n == "run_detection_query"),
            "triage should expose run_detection_query, got: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "run_parallel_detections"),
            "triage should expose run_parallel_detections, got: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "list_detection_templates"),
            "triage should expose list_detection_templates, got: {names:?}"
        );
    }

    #[test]
    fn threat_hunter_and_lateral_still_have_detection_tools() {
        for role in [BlueAgentRole::ThreatHunter, BlueAgentRole::LateralAnalyst] {
            let names = tool_names(role);
            assert!(
                names.iter().any(|n| n == "run_detection_query"),
                "{role:?} should expose run_detection_query, got: {names:?}"
            );
        }
    }

    #[test]
    fn create_detection_rule_is_offered_only_when_opted_in() {
        use ares_core::detection::RULE_CREATION_ENV;

        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var(RULE_CREATION_ENV).ok();

        let roles = [
            BlueAgentRole::Triage,
            BlueAgentRole::ThreatHunter,
            BlueAgentRole::LateralAnalyst,
        ];

        std::env::remove_var(RULE_CREATION_ENV);
        for role in roles {
            let names = tool_names(role);
            assert!(
                !names.iter().any(|n| n == "create_detection_rule"),
                "{role:?} must not be offered create_detection_rule while gated off, got: {names:?}"
            );
            assert!(
                names.iter().any(|n| n == "get_alerts_in_time_range"),
                "{role:?} should keep its other grafana tools, got: {names:?}"
            );
        }

        std::env::set_var(RULE_CREATION_ENV, "1");
        for role in roles {
            let names = tool_names(role);
            assert!(
                names.iter().any(|n| n == "create_detection_rule"),
                "{role:?} should regain create_detection_rule when opted in, got: {names:?}"
            );
        }

        match prior {
            Some(v) => std::env::set_var(RULE_CREATION_ENV, v),
            None => std::env::remove_var(RULE_CREATION_ENV),
        }
    }
}
