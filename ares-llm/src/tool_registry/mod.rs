//! Tool definition registry for LLM tool_use.
//!
//! Provides JSON Schema definitions for tools available to each agent role.
//! Callback tools (task_complete, request_assistance) are handled directly
//! in Rust without dispatching to Python workers.

mod acl;
#[cfg(feature = "blue")]
pub mod blue;
mod coercion;
mod cracker;
mod credential_access;
mod lateral;
mod orchestrator_tools;
mod privesc;
mod recon;
mod reporting;

use serde_json::json;

use crate::ToolDefinition;

/// Agent roles that can be assigned tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentRole {
    Recon,
    CredentialAccess,
    Cracker,
    Acl,
    Privesc,
    Lateral,
    Coercion,
    Orchestrator,
}

impl AgentRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::CredentialAccess => "credential_access",
            Self::Cracker => "cracker",
            Self::Acl => "acl",
            Self::Privesc => "privesc",
            Self::Lateral => "lateral",
            Self::Coercion => "coercion",
            Self::Orchestrator => "orchestrator",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "recon" => Some(Self::Recon),
            "credential_access" => Some(Self::CredentialAccess),
            "cracker" | "crack" => Some(Self::Cracker),
            "acl" | "acl_analysis" => Some(Self::Acl),
            "privesc" | "privesc_enumeration" => Some(Self::Privesc),
            "lateral" | "lateral_movement" => Some(Self::Lateral),
            "coercion" => Some(Self::Coercion),
            "orchestrator" => Some(Self::Orchestrator),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Callback tools (handled in Rust, not dispatched to workers)
// ---------------------------------------------------------------------------

/// Names of callback tools that the agent loop handles directly.
///
/// Includes orchestrator query and dispatch tools — these are handled by a
/// custom `CallbackHandler` (if provided) rather than being dispatched to workers.
pub const CALLBACK_TOOLS: &[&str] = &[
    // Universal callbacks
    "task_complete",
    "request_assistance",
    // NOTE: report_cracked_credential removed — cracked passwords come from parsed tool output
    "report_crack_failed",
    "report_finding",
    "report_lateral_success",
    "report_lateral_failed",
    "complete_operation",
    // Reporting tools (handled in-process, not dispatched to workers)
    // NOTE: record_credential removed — credentials come only from tool output parsing
    // NOTE: record_timeline_event removed — timeline events auto-generated from discoveries
    "record_compromised_host",
    "list_credentials",
    // Orchestrator query tools (handled by OrchestratorCallbackHandler)
    "get_credential_summary",
    "get_hash_summary",
    "get_all_credentials",
    "get_all_hashes",
    "get_hash_value",
    "get_pending_tasks",
    "get_agent_status",
    "get_operation_summary",
    // Orchestrator dispatch tools
    "dispatch_recon",
    "dispatch_credential_access",
    "dispatch_lateral_movement",
    "dispatch_privesc_exploit",
    "dispatch_coercion",
    "dispatch_crack",
];

/// Check if a tool name is a callback (handled in Rust, not dispatched).
pub fn is_callback_tool(name: &str) -> bool {
    CALLBACK_TOOLS.contains(&name)
}

fn callback_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "task_complete".into(),
            description: "Mark the current task as complete with a result summary.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID being completed"
                    },
                    "result": {
                        "type": "string",
                        "description": "Summary of findings and results"
                    }
                },
                "required": ["task_id", "result"]
            }),
        },
        ToolDefinition {
            name: "request_assistance".into(),
            description: "Request help from the orchestrator when stuck or unable to proceed."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "issue": {
                        "type": "string",
                        "description": "Description of the issue"
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context about what was attempted"
                    }
                },
                "required": ["issue"]
            }),
        },
        ToolDefinition {
            name: "report_finding".into(),
            description: "Report a security finding or vulnerability discovered during the task."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "finding_type": {
                        "type": "string",
                        "description": "Type of finding (e.g. vulnerability, misconfiguration)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the finding"
                    },
                    "target": {
                        "type": "string",
                        "description": "Affected target (IP, hostname, or service)"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    }
                },
                "required": ["finding_type", "description"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Get tool definitions for a given agent role.
///
/// Returns role-specific tools plus universal callback and reporting tools.
pub fn tools_for_role(role: AgentRole) -> Vec<ToolDefinition> {
    let mut tools = match role {
        AgentRole::Recon => {
            let mut t = recon::tool_definitions();
            // Netexec/ldapsearch tools are available on recon workers — include
            // the full set (password_policy, laps_dump, gpp_password_finder,
            // sysvol_script_search, domain_admin_checker, posture validation,
            // plus ldap_search_descriptions, password_spray, username_as_password).
            t.extend(credential_access::netexec_tools::definitions());
            t
        }
        AgentRole::CredentialAccess => credential_access::tool_definitions(),
        AgentRole::Cracker => cracker::tool_definitions(),
        AgentRole::Acl => acl::tool_definitions(),
        AgentRole::Privesc => {
            let mut t = privesc::tool_definitions();
            // MSSQL tools are implemented in the lateral module but privesc
            // agents need them for SQL Server privilege escalation. The privesc
            // container has impacket-mssqlclient installed.
            t.extend(lateral::mssql::definitions());
            t
        }
        AgentRole::Lateral => lateral::tool_definitions(),
        AgentRole::Coercion => coercion::tool_definitions(),
        AgentRole::Orchestrator => orchestrator_tools::tool_definitions(),
    };

    // Role-specific callback tools
    match role {
        AgentRole::Cracker => tools.extend(cracker::callback_definitions()),
        AgentRole::Lateral => tools.extend(lateral::callback_definitions()),
        _ => {}
    }

    // Universal tools for all roles
    tools.extend(reporting::tool_definitions());
    tools.extend(callback_tool_definitions());

    tools
}

/// Get tool definitions for a specific set of capability names.
///
/// This is used when the YAML config specifies which tools a role should have.
/// Returns only the tools whose names appear in `capabilities`.
pub fn tools_for_capabilities(capabilities: &[String]) -> Vec<ToolDefinition> {
    // Collect all role-specific tools (include cross-role shared definitions)
    let all_tools: Vec<ToolDefinition> = [
        recon::tool_definitions(),
        credential_access::tool_definitions(),
        cracker::tool_definitions(),
        acl::tool_definitions(),
        privesc::tool_definitions(),
        lateral::tool_definitions(),
        lateral::mssql::definitions(),
        coercion::tool_definitions(),
        orchestrator_tools::tool_definitions(),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Dedup by name — same tool may appear in multiple roles
    let mut seen = std::collections::HashSet::new();
    let mut matched: Vec<ToolDefinition> = all_tools
        .into_iter()
        .filter(|t| capabilities.iter().any(|c| c == &t.name))
        .filter(|t| seen.insert(t.name.clone()))
        .collect();

    // Always include reporting + callback tools
    matched.extend(reporting::tool_definitions());
    matched.extend(callback_tool_definitions());
    matched
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recon_tools_include_callbacks() {
        let tools = tools_for_role(AgentRole::Recon);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"task_complete"));
        assert!(names.contains(&"request_assistance"));
    }

    #[test]
    fn test_callback_tool_detection() {
        assert!(is_callback_tool("task_complete"));
        assert!(is_callback_tool("request_assistance"));
        assert!(is_callback_tool("report_lateral_success"));
        assert!(is_callback_tool("complete_operation"));
        // Reporting tools are callbacks (not dispatched to workers)
        assert!(is_callback_tool("record_compromised_host"));
        // Removed: record_weakness, record_timeline_event, report_cracked_credential
        assert!(!is_callback_tool("record_weakness"));
        assert!(!is_callback_tool("record_timeline_event"));
        assert!(!is_callback_tool("report_cracked_credential"));
        assert!(!is_callback_tool("list_weaknesses"));
        assert!(is_callback_tool("list_credentials"));
        assert!(!is_callback_tool("nmap_scan"));
        assert!(!is_callback_tool("secretsdump"));
    }

    #[test]
    fn test_tool_schemas_valid_json() {
        for role in [
            AgentRole::Recon,
            AgentRole::CredentialAccess,
            AgentRole::Cracker,
            AgentRole::Acl,
            AgentRole::Privesc,
            AgentRole::Lateral,
            AgentRole::Coercion,
            AgentRole::Orchestrator,
        ] {
            let tools = tools_for_role(role);
            for tool in &tools {
                assert!(
                    tool.input_schema.is_object(),
                    "Tool '{}' (role {:?}) has non-object schema",
                    tool.name,
                    role
                );
                assert!(
                    tool.input_schema.get("type").is_some(),
                    "Tool '{}' (role {:?}) missing 'type' in schema",
                    tool.name,
                    role
                );
            }
        }
    }

    #[test]
    fn test_tools_for_capabilities() {
        let caps = vec!["nmap_scan".to_string(), "secretsdump".to_string()];
        let tools = tools_for_capabilities(&caps);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"secretsdump"));
        assert!(!names.contains(&"enumerate_users"));
        // Reporting + callbacks always present
        assert!(names.contains(&"task_complete"));
    }

    #[test]
    fn test_agent_role_str() {
        assert_eq!(AgentRole::Recon.as_str(), "recon");
        assert_eq!(AgentRole::Orchestrator.as_str(), "orchestrator");
        assert_eq!(AgentRole::CredentialAccess.as_str(), "credential_access");
    }

    #[test]
    fn test_cracker_has_crack_callbacks() {
        let tools = tools_for_role(AgentRole::Cracker);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"crack_with_hashcat"));
        // report_cracked_credential removed — cracked passwords come from parsed tool output
        assert!(names.contains(&"report_crack_failed"));
    }

    #[test]
    fn test_lateral_has_lateral_callbacks() {
        let tools = tools_for_role(AgentRole::Lateral);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"psexec"));
        assert!(names.contains(&"secretsdump"));
        assert!(names.contains(&"secretsdump_kerberos"));
        assert!(names.contains(&"report_lateral_success"));
        assert!(names.contains(&"report_lateral_failed"));
    }

    #[test]
    fn test_orchestrator_has_management_tools() {
        let tools = tools_for_role(AgentRole::Orchestrator);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"get_pending_tasks"));
        assert!(names.contains(&"complete_operation"));
        assert!(names.contains(&"get_hash_summary"));
    }

    #[test]
    fn test_all_roles_have_reporting() {
        for role in [
            AgentRole::Recon,
            AgentRole::CredentialAccess,
            AgentRole::Cracker,
            AgentRole::Acl,
            AgentRole::Privesc,
            AgentRole::Lateral,
            AgentRole::Coercion,
            AgentRole::Orchestrator,
        ] {
            let tools = tools_for_role(role);
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            // record_compromised_host is the remaining reporting tool (log-only, no state write)
            assert!(
                names.contains(&"record_compromised_host"),
                "Role {:?} missing record_compromised_host",
                role
            );
            // Removed reporting tools must NOT be present
            assert!(
                !names.contains(&"record_weakness"),
                "Role {:?} has removed tool record_weakness",
                role
            );
            assert!(
                !names.contains(&"list_weaknesses"),
                "Role {:?} has removed tool list_weaknesses",
                role
            );
            assert!(
                !names.contains(&"record_timeline_event"),
                "Role {:?} has removed tool record_timeline_event",
                role
            );
        }
    }

    #[test]
    fn test_no_duplicate_tool_names_per_role() {
        for role in [
            AgentRole::Recon,
            AgentRole::CredentialAccess,
            AgentRole::Cracker,
            AgentRole::Acl,
            AgentRole::Privesc,
            AgentRole::Lateral,
            AgentRole::Coercion,
            AgentRole::Orchestrator,
        ] {
            let tools = tools_for_role(role);
            let mut seen = std::collections::HashSet::new();
            for tool in &tools {
                assert!(
                    seen.insert(&tool.name),
                    "Duplicate tool '{}' in role {:?}",
                    tool.name,
                    role
                );
            }
        }
    }

    #[test]
    fn test_credential_access_has_key_tools() {
        let tools = tools_for_role(AgentRole::CredentialAccess);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"secretsdump"));
        assert!(names.contains(&"kerberoast"));
        assert!(names.contains(&"lsassy"));
        assert!(names.contains(&"ntds_dit_extract"));
        // Netexec tools now included — cross-role routing sends them to recon workers
        assert!(names.contains(&"ldap_search_descriptions"));
        assert!(names.contains(&"password_spray"));
        assert!(names.contains(&"username_as_password"));
        assert!(names.contains(&"gpp_password_finder"));
        assert!(names.contains(&"sysvol_script_search"));
        assert!(names.contains(&"laps_dump"));
    }

    #[test]
    fn test_recon_has_credential_discovery_tools() {
        let tools = tools_for_role(AgentRole::Recon);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        // Shared credential discovery tools (from netexec_tools)
        assert!(names.contains(&"ldap_search_descriptions"));
        assert!(names.contains(&"username_as_password"));
        assert!(names.contains(&"password_spray"));
        // Previously missing tools now included via netexec_tools
        assert!(names.contains(&"password_policy"));
        assert!(names.contains(&"laps_dump"));
        assert!(names.contains(&"gpp_password_finder"));
        assert!(names.contains(&"sysvol_script_search"));
        assert!(names.contains(&"domain_admin_checker"));
        // Posture validation tools
        assert!(names.contains(&"check_credman_entries"));
        assert!(names.contains(&"check_autologon_registry"));
    }

    #[test]
    fn test_privesc_has_key_tools() {
        let tools = tools_for_role(AgentRole::Privesc);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"certipy_find"));
        assert!(names.contains(&"find_delegation"));
        assert!(names.contains(&"generate_golden_ticket"));
        assert!(names.contains(&"extract_trust_key"));
        // MSSQL tools shared from lateral module (privesc container has impacket-mssqlclient)
        assert!(names.contains(&"mssql_command"));
        assert!(names.contains(&"mssql_enum_impersonation"));
        assert!(names.contains(&"mssql_enum_linked_servers"));
    }

    #[test]
    fn test_coercion_has_relay_tools() {
        let tools = tools_for_role(AgentRole::Coercion);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"start_responder"));
        assert!(names.contains(&"ntlmrelayx_to_ldaps"));
        assert!(names.contains(&"coercer"));
    }
}
