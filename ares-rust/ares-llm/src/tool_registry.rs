//! Tool definition registry for LLM tool_use.
//!
//! Provides JSON Schema definitions for tools available to each agent role.
//! Callback tools (task_complete, request_assistance) are handled directly
//! in Rust without dispatching to Python workers.

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
}

// ---------------------------------------------------------------------------
// Callback tools (handled in Rust, not dispatched to workers)
// ---------------------------------------------------------------------------

/// Names of callback tools that the agent loop handles directly.
pub const CALLBACK_TOOLS: &[&str] = &[
    "task_complete",
    "request_assistance",
    "report_cracked_credential",
    "report_finding",
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
            name: "report_cracked_credential".into(),
            description: "Report a newly cracked credential (password recovered from hash).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "domain": {"type": "string"},
                    "password": {"type": "string"},
                    "hash_type": {"type": "string"}
                },
                "required": ["username", "password"]
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
// Recon tools
// ---------------------------------------------------------------------------

fn recon_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run an nmap scan against target IP(s) or subnet. Returns discovered hosts, open ports, and services.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g. '1-1000', '80,443,445', '-' for all ports)"
                    },
                    "arguments": {
                        "type": "string",
                        "description": "Additional nmap arguments (e.g. '-sV -sC -O')"
                    }
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "enumerate_users".into(),
            description: "Enumerate domain users via LDAP, RPC, or SMB. Returns usernames, groups, and properties.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["ldap", "rpc", "smb"],
                        "description": "Enumeration method"
                    }
                },
                "required": ["target", "domain"]
            }),
        },
        ToolDefinition {
            name: "enumerate_shares".into(),
            description: "Enumerate SMB shares on a target host. Returns share names, types, and permissions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "domain": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "smb_signing_check".into(),
            description: "Check SMB signing status on target hosts. Identifies relay targets (hosts without signing required).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range"
                    }
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "run_bloodhound".into(),
            description: "Run BloodHound data collection. Requires valid domain credentials.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "dc_ip": {"type": "string", "description": "Domain controller IP"},
                    "collection_method": {
                        "type": "string",
                        "description": "Collection method (default: All)"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "ldap_search".into(),
            description: "Execute an LDAP search query against a domain controller.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "DC IP or hostname"},
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "filter": {"type": "string", "description": "LDAP filter (e.g. '(objectClass=user)')"},
                    "attributes": {
                        "type": "string",
                        "description": "Comma-separated attributes to retrieve"
                    }
                },
                "required": ["target", "domain", "filter"]
            }),
        },
        ToolDefinition {
            name: "rpcclient_command".into(),
            description: "Execute an rpcclient command against a target.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "command": {"type": "string", "description": "rpcclient command (e.g. 'enumdomusers')"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "domain": {"type": "string"}
                },
                "required": ["target", "command"]
            }),
        },
        ToolDefinition {
            name: "dig_query".into(),
            description: "Execute a DNS query using dig.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "DNS query (e.g. 'contoso.local')"},
                    "record_type": {
                        "type": "string",
                        "description": "Record type (A, SRV, MX, NS, etc.)"
                    },
                    "server": {"type": "string", "description": "DNS server to query"}
                },
                "required": ["query"]
            }),
        },
        ToolDefinition {
            name: "enumerate_domain_trusts".into(),
            description: "Enumerate domain trust relationships via LDAP. Queries trustedDomain objects.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "DC IP"},
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["target", "domain"]
            }),
        },
        ToolDefinition {
            name: "check_rdp_reachability".into(),
            description: "Check if RDP (port 3389) is reachable on a target host.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "check_winrm_reachability".into(),
            description: "Check if WinRM (port 5985/5986) is reachable on a target host.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Get tool definitions for a given agent role.
///
/// Returns role-specific tools plus universal callback tools.
pub fn tools_for_role(role: AgentRole) -> Vec<ToolDefinition> {
    let mut tools = match role {
        AgentRole::Recon => recon_tool_definitions(),
        // Other roles will be added in Phase 2
        _ => Vec::new(),
    };

    // Add callback tools to all roles
    tools.extend(callback_tool_definitions());

    tools
}

/// Get tool definitions for a specific set of capability names.
///
/// This is used when the YAML config specifies which tools a role should have.
/// Returns only the tools whose names appear in `capabilities`.
pub fn tools_for_capabilities(capabilities: &[String]) -> Vec<ToolDefinition> {
    let all_tools = recon_tool_definitions();
    let mut matched: Vec<ToolDefinition> = all_tools
        .into_iter()
        .filter(|t| capabilities.iter().any(|c| c == &t.name))
        .collect();

    // Always include callback tools
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
        assert!(is_callback_tool("report_cracked_credential"));
        assert!(!is_callback_tool("nmap_scan"));
        assert!(!is_callback_tool("secretsdump"));
    }

    #[test]
    fn test_tool_schemas_valid_json() {
        let tools = tools_for_role(AgentRole::Recon);
        for tool in &tools {
            assert!(
                tool.input_schema.is_object(),
                "Tool '{}' has non-object schema",
                tool.name
            );
            assert!(
                tool.input_schema.get("type").is_some(),
                "Tool '{}' missing 'type' in schema",
                tool.name
            );
        }
    }

    #[test]
    fn test_tools_for_capabilities() {
        let caps = vec!["nmap_scan".to_string(), "run_bloodhound".to_string()];
        let tools = tools_for_capabilities(&caps);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"run_bloodhound"));
        assert!(!names.contains(&"enumerate_users"));
        // Callbacks always present
        assert!(names.contains(&"task_complete"));
    }

    #[test]
    fn test_agent_role_str() {
        assert_eq!(AgentRole::Recon.as_str(), "recon");
        assert_eq!(AgentRole::Orchestrator.as_str(), "orchestrator");
        assert_eq!(AgentRole::CredentialAccess.as_str(), "credential_access");
    }

    #[test]
    fn test_other_roles_have_callbacks_only() {
        // Roles without specific tools yet should still have callbacks
        let tools = tools_for_role(AgentRole::Cracker);
        assert!(tools.iter().any(|t| t.name == "task_complete"));
        assert!(tools.iter().all(|t| is_callback_tool(&t.name)));
    }
}
