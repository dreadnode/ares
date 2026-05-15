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

/// Names of supported callback tools that the agent loop handles directly.
///
/// Includes orchestrator query and dispatch tools — these are handled by a
/// custom `CallbackHandler` (if provided) rather than being dispatched to workers.
pub const CALLBACK_TOOLS: &[&str] = &[
    // Universal callbacks
    "task_complete",
    "request_assistance",
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

/// Removed callback names that are still trapped in-process so a hallucinated
/// call receives a deterministic "tool removed" response instead of being
/// dispatched to a worker.
const REMOVED_CALLBACK_TOOLS: &[&str] = &[
    "record_credential",
    "record_timeline_event",
    "report_cracked_credential",
];

/// Check if a tool name is a callback (handled in Rust, not dispatched).
pub fn is_callback_tool(name: &str) -> bool {
    CALLBACK_TOOLS.contains(&name) || REMOVED_CALLBACK_TOOLS.contains(&name)
}

/// JSON schema property keys that contain secret material.
///
/// These are stripped from every tool's `input_schema` before tool definitions
/// are sent to the LLM. The LLM names principals (`username`, `domain`); the
/// worker's credential resolver injects secrets from harvested operation state
/// at dispatch time.
///
/// Keep this in lock-step with `ares-cli/src/worker/credential_resolver.rs::CREDENTIAL_KEYS`.
pub const SECRET_SCHEMA_KEYS: &[&str] = &[
    "password",
    "hash",
    "nt_hash",
    "ntlm_hash",
    "aes_key",
    "aes256_key",
    "ticket_path",
    "krbtgt_hash",
    "child_krbtgt_hash",
    "parent_krbtgt_hash",
    "trust_key",
    "trust_aes_key",
    "trust_hash",
    "admin_hash",
    "coerce_password",
    "coerce_hash",
    "domain_sid",
    "source_sid",
    "target_sid",
    "extra_sid",
    "kerberos_keys",
];

/// Names of callback tools whose `password` / `hash` arguments are part of the
/// callback contract (e.g. tools that record harvested credentials). These are
/// exempt from secret-stripping.
const CALLBACK_NAMES_WITH_SECRETS: &[&str] = &[
    "list_credentials",
    "get_credential_summary",
    "get_hash_summary",
    "get_all_credentials",
    "get_all_hashes",
    "get_hash_value",
];

/// Per-tool exposed-key exemptions. For tools where a "secret-shaped" argument
/// is actually input *data* (e.g. `password_spray.password` is the candidate
/// password to spray, not a credential to look up), the named keys remain in
/// the LLM-visible schema. The credential resolver will not inject anything
/// for these keys because the calls have no `(username, domain)` principal.
fn exposed_secret_keys(tool_name: &str) -> &'static [&'static str] {
    match tool_name {
        "password_spray" => &["password"],
        _ => &[],
    }
}

/// Strip every secret-bearing property from a tool's input schema.
///
/// Mutates `input_schema.properties` to remove keys in `SECRET_SCHEMA_KEYS`,
/// and prunes those keys from the `required[]` array. The LLM never sees a
/// slot for them — except for keys explicitly exposed by `exposed_secret_keys`
/// for tools where the argument represents input data rather than a credential.
fn strip_secret_fields(tool: &mut ToolDefinition) {
    if CALLBACK_NAMES_WITH_SECRETS.contains(&tool.name.as_str()) {
        return;
    }
    let Some(obj) = tool.input_schema.as_object_mut() else {
        return;
    };

    let exposed = exposed_secret_keys(&tool.name);

    if let Some(props) = obj.get_mut("properties").and_then(|v| v.as_object_mut()) {
        for key in SECRET_SCHEMA_KEYS {
            if exposed.contains(key) {
                continue;
            }
            props.remove(*key);
        }
    }

    if let Some(req) = obj.get_mut("required").and_then(|v| v.as_array_mut()) {
        req.retain(|v| match v.as_str() {
            Some(s) => exposed.contains(&s) || !SECRET_SCHEMA_KEYS.contains(&s),
            None => true,
        });
    }
}

/// Apply `strip_secret_fields` to every tool in a definitions list.
fn strip_secrets_from_all(tools: &mut [ToolDefinition]) {
    for tool in tools.iter_mut() {
        strip_secret_fields(tool);
    }
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
            // secretsdump_kerberos lets the trust-follow automation forge an
            // inter-realm ticket and dump the target DC in one agent task.
            t.extend(lateral::execution::secretsdump_kerberos_definition());
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

    // Strip credential fields from every tool schema. The LLM names principals;
    // the worker's credential_resolver injects secrets at dispatch time.
    strip_secrets_from_all(&mut tools);

    tools
}

/// Get tool definitions for a specific set of capability names.
///
/// This is used when the YAML config specifies which tools a role should have.
/// Returns only the tools whose names appear in `capabilities`.
pub fn tools_for_capabilities(capabilities: &[String]) -> Vec<ToolDefinition> {
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

    // Strip credential fields — see tools_for_role.
    strip_secrets_from_all(&mut matched);

    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recon_tools_include_callbacks() {
        let tools = tools_for_role(AgentRole::Recon);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"task_complete"));
        assert!(names.contains(&"request_assistance"));
    }

    #[test]
    fn callback_tool_detection() {
        assert!(is_callback_tool("task_complete"));
        assert!(is_callback_tool("request_assistance"));
        assert!(is_callback_tool("report_lateral_success"));
        assert!(is_callback_tool("complete_operation"));
        // Reporting tools are callbacks (not dispatched to workers)
        assert!(is_callback_tool("record_compromised_host"));
        assert!(!is_callback_tool("record_weakness"));
        assert!(is_callback_tool("record_timeline_event"));
        assert!(is_callback_tool("record_credential"));
        assert!(is_callback_tool("report_cracked_credential"));
        assert!(!CALLBACK_TOOLS.contains(&"record_timeline_event"));
        assert!(!CALLBACK_TOOLS.contains(&"record_credential"));
        assert!(!CALLBACK_TOOLS.contains(&"report_cracked_credential"));
        assert!(!is_callback_tool("list_weaknesses"));
        assert!(is_callback_tool("list_credentials"));
        assert!(!is_callback_tool("nmap_scan"));
        assert!(!is_callback_tool("secretsdump"));
    }

    #[test]
    fn no_secret_fields_in_any_role_schema() {
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
                if CALLBACK_NAMES_WITH_SECRETS.contains(&tool.name.as_str()) {
                    continue;
                }
                let exposed = exposed_secret_keys(&tool.name);
                let props = tool
                    .input_schema
                    .get("properties")
                    .and_then(|v| v.as_object());
                if let Some(props) = props {
                    for key in SECRET_SCHEMA_KEYS {
                        if exposed.contains(key) {
                            continue;
                        }
                        assert!(
                            !props.contains_key(*key),
                            "Tool '{}' (role {:?}) leaks secret field '{}' to LLM",
                            tool.name,
                            role,
                            key
                        );
                    }
                }
                let req = tool.input_schema.get("required").and_then(|v| v.as_array());
                if let Some(req) = req {
                    for v in req {
                        if let Some(s) = v.as_str() {
                            assert!(
                                exposed.contains(&s) || !SECRET_SCHEMA_KEYS.contains(&s),
                                "Tool '{}' (role {:?}) requires secret field '{}'",
                                tool.name,
                                role,
                                s
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn no_secret_fields_in_capability_schemas() {
        let caps: Vec<String> = ["psexec", "secretsdump", "generate_golden_ticket"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let tools = tools_for_capabilities(&caps);
        for tool in &tools {
            if CALLBACK_NAMES_WITH_SECRETS.contains(&tool.name.as_str()) {
                continue;
            }
            let exposed = exposed_secret_keys(&tool.name);
            if let Some(props) = tool
                .input_schema
                .get("properties")
                .and_then(|v| v.as_object())
            {
                for key in SECRET_SCHEMA_KEYS {
                    if exposed.contains(key) {
                        continue;
                    }
                    assert!(
                        !props.contains_key(*key),
                        "Capability tool '{}' leaks secret field '{}' to LLM",
                        tool.name,
                        key
                    );
                }
            }
        }
    }

    #[test]
    fn tool_schemas_valid_json() {
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
    fn returns_tools_for_capabilities() {
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
    fn agent_role_str() {
        assert_eq!(AgentRole::Recon.as_str(), "recon");
        assert_eq!(AgentRole::Orchestrator.as_str(), "orchestrator");
        assert_eq!(AgentRole::CredentialAccess.as_str(), "credential_access");
    }

    #[test]
    fn cracker_has_crack_callbacks() {
        let tools = tools_for_role(AgentRole::Cracker);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"crack_with_hashcat"));
        assert!(names.contains(&"report_crack_failed"));
        assert!(!names.contains(&"report_cracked_credential"));
    }

    #[test]
    fn lateral_has_lateral_callbacks() {
        let tools = tools_for_role(AgentRole::Lateral);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"psexec"));
        assert!(names.contains(&"secretsdump"));
        assert!(names.contains(&"secretsdump_kerberos"));
        assert!(names.contains(&"report_lateral_success"));
        assert!(names.contains(&"report_lateral_failed"));
    }

    #[test]
    fn orchestrator_has_management_tools() {
        let tools = tools_for_role(AgentRole::Orchestrator);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"get_pending_tasks"));
        assert!(names.contains(&"complete_operation"));
        assert!(names.contains(&"get_hash_summary"));
    }

    #[test]
    fn all_roles_have_reporting() {
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
    fn no_duplicate_tool_names_per_role() {
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
    fn credential_access_has_key_tools() {
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
    fn recon_has_credential_discovery_tools() {
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
    fn privesc_has_key_tools() {
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
        // secretsdump_kerberos shared from lateral for cross-forest trust exploitation
        assert!(names.contains(&"secretsdump_kerberos"));
    }

    #[test]
    fn coercion_has_relay_tools() {
        let tools = tools_for_role(AgentRole::Coercion);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"start_responder"));
        assert!(names.contains(&"ntlmrelayx_to_ldaps"));
        assert!(names.contains(&"coercer"));
    }

    // ── AgentRole::parse ────────────────────────────────────────────

    #[test]
    fn parse_role_exact() {
        assert_eq!(AgentRole::parse("recon"), Some(AgentRole::Recon));
        assert_eq!(
            AgentRole::parse("credential_access"),
            Some(AgentRole::CredentialAccess)
        );
        assert_eq!(AgentRole::parse("cracker"), Some(AgentRole::Cracker));
        assert_eq!(AgentRole::parse("acl"), Some(AgentRole::Acl));
        assert_eq!(AgentRole::parse("privesc"), Some(AgentRole::Privesc));
        assert_eq!(AgentRole::parse("lateral"), Some(AgentRole::Lateral));
        assert_eq!(AgentRole::parse("coercion"), Some(AgentRole::Coercion));
        assert_eq!(
            AgentRole::parse("orchestrator"),
            Some(AgentRole::Orchestrator)
        );
    }

    #[test]
    fn parse_role_aliases() {
        assert_eq!(AgentRole::parse("crack"), Some(AgentRole::Cracker));
        assert_eq!(AgentRole::parse("acl_analysis"), Some(AgentRole::Acl));
        assert_eq!(
            AgentRole::parse("privesc_enumeration"),
            Some(AgentRole::Privesc)
        );
        assert_eq!(
            AgentRole::parse("lateral_movement"),
            Some(AgentRole::Lateral)
        );
    }

    #[test]
    fn parse_role_case_insensitive() {
        assert_eq!(AgentRole::parse("RECON"), Some(AgentRole::Recon));
        assert_eq!(AgentRole::parse("Lateral"), Some(AgentRole::Lateral));
        assert_eq!(
            AgentRole::parse("CREDENTIAL_ACCESS"),
            Some(AgentRole::CredentialAccess)
        );
    }

    #[test]
    fn parse_role_unknown() {
        assert!(AgentRole::parse("unknown").is_none());
        assert!(AgentRole::parse("").is_none());
        assert!(AgentRole::parse("blue").is_none());
    }

    #[test]
    fn parse_roundtrip() {
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
            assert_eq!(
                AgentRole::parse(role.as_str()),
                Some(role),
                "Roundtrip failed for {:?}",
                role
            );
        }
    }

    // -----------------------------------------------------------------------
    // Blue team tool registry tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "blue")]
    mod blue_tests {
        use crate::tool_registry::blue::{
            blue_tools_for_role, is_blue_callback_tool, BlueAgentRole, BLUE_CALLBACK_TOOLS,
        };

        #[test]
        fn blue_agent_role_as_str() {
            assert_eq!(BlueAgentRole::Orchestrator.as_str(), "blue_orchestrator");
            assert_eq!(BlueAgentRole::Triage.as_str(), "triage");
            assert_eq!(BlueAgentRole::ThreatHunter.as_str(), "threat_hunter");
            assert_eq!(BlueAgentRole::LateralAnalyst.as_str(), "lateral_analyst");
            assert_eq!(
                BlueAgentRole::EscalationTriage.as_str(),
                "escalation_triage"
            );
        }

        #[test]
        fn is_blue_callback_tool_positive() {
            for name in BLUE_CALLBACK_TOOLS {
                assert!(
                    is_blue_callback_tool(name),
                    "Expected '{name}' to be recognized as a blue callback tool"
                );
            }
        }

        #[test]
        fn is_blue_callback_tool_negative() {
            assert!(!is_blue_callback_tool("query_loki_logs"));
            assert!(!is_blue_callback_tool("add_evidence"));
            assert!(!is_blue_callback_tool("nmap_scan"));
            assert!(!is_blue_callback_tool(""));
        }

        #[test]
        fn blue_triage_tools_non_empty() {
            let tools = blue_tools_for_role(BlueAgentRole::Triage);
            assert!(!tools.is_empty(), "Triage role should have tools");
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            // Loki tools
            assert!(names.contains(&"query_loki_logs"));
            assert!(names.contains(&"query_logs_around_timestamp"));
            assert!(names.contains(&"query_logs_progressive"));
            assert!(names.contains(&"get_loki_label_values"));
            assert!(names.contains(&"execute_parallel_queries"));
            assert!(names.contains(&"query_logs_recent"));
            assert!(names.contains(&"combine_query_patterns"));
            // Grafana tools
            assert!(names.contains(&"get_grafana_alerts"));
            assert!(names.contains(&"get_grafana_annotations"));
            assert!(names.contains(&"search_grafana_dashboards"));
            assert!(names.contains(&"get_grafana_dashboard"));
            assert!(names.contains(&"get_alert_history"));
            assert!(names.contains(&"get_alerts_in_time_range"));
            assert!(names.contains(&"create_annotation"));
            assert!(names.contains(&"create_detection_rule"));
            assert!(names.contains(&"post_investigation_started"));
            assert!(names.contains(&"post_investigation_completed"));
            // Learning tools
            assert!(names.contains(&"lookup_technique"));
            assert!(names.contains(&"suggest_techniques"));
            assert!(names.contains(&"find_similar_investigations"));
            assert!(names.contains(&"get_effective_queries"));
            assert!(names.contains(&"check_false_positive_pattern"));
            assert!(names.contains(&"get_investigation_statistics"));
            assert!(names.contains(&"generate_mitre_questions"));
            assert!(names.contains(&"generate_pyramid_questions"));
            assert!(names.contains(&"assess_pyramid_state"));
            assert!(names.contains(&"get_combined_questions"));
            assert!(names.contains(&"get_attack_chain_precursors"));
            assert!(names.contains(&"get_detection_recipe"));
            assert!(names.contains(&"list_detection_recipes"));
            assert!(names.contains(&"get_attack_playbook"));
            assert!(names.contains(&"get_detection_queries_for_technique"));
            // Worker callbacks
            assert!(names.contains(&"triage_complete"));
            assert!(names.contains(&"get_investigation_context"));
            // Investigation state tools
            assert!(names.contains(&"add_evidence"));
            assert!(names.contains(&"add_evidence_batch"));
            assert!(names.contains(&"record_timeline_event"));
            assert!(names.contains(&"add_technique"));
            assert!(names.contains(&"get_investigation_summary"));
            assert!(names.contains(&"transition_stage"));
            assert!(names.contains(&"track_host_investigation"));
            assert!(names.contains(&"track_user_investigation"));
            assert!(names.contains(&"list_evidence"));
            assert!(names.contains(&"get_investigation_context"));
            assert!(names.contains(&"pop_all_queued"));
            assert!(names.contains(&"get_suggested_evidence"));
            assert!(names.contains(&"analyze_lateral_movement"));
            assert!(names.contains(&"get_correlated_alerts"));
            assert!(names.contains(&"get_queued_queries"));
            assert!(names.contains(&"get_formatted_summary"));
        }

        #[test]
        fn blue_threat_hunter_tools() {
            let tools = blue_tools_for_role(BlueAgentRole::ThreatHunter);
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            // Has loki
            assert!(names.contains(&"query_loki_logs"));
            // Has prometheus (hunter-specific)
            assert!(names.contains(&"query_prometheus"));
            assert!(names.contains(&"query_prometheus_range"));
            assert!(names.contains(&"get_metric_names"));
            // Has grafana
            assert!(names.contains(&"get_grafana_alerts"));
            // Has detection
            assert!(names.contains(&"run_detection_query"));
            assert!(names.contains(&"run_parallel_detections"));
            assert!(names.contains(&"list_detection_templates"));
            assert!(names.contains(&"get_host_activity"));
            assert!(names.contains(&"get_user_activity"));
            // Has learning
            assert!(names.contains(&"lookup_technique"));
            // Has callbacks
            assert!(names.contains(&"hunt_complete"));
            // Has investigation state
            assert!(names.contains(&"add_evidence"));
        }

        #[test]
        fn blue_lateral_analyst_tools() {
            let tools = blue_tools_for_role(BlueAgentRole::LateralAnalyst);
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            // Has loki
            assert!(names.contains(&"query_loki_logs"));
            // Has grafana
            assert!(names.contains(&"get_grafana_alerts"));
            // Has detection
            assert!(names.contains(&"run_detection_query"));
            // Has learning
            assert!(names.contains(&"lookup_technique"));
            // Has callbacks
            assert!(names.contains(&"lateral_complete"));
            // Has investigation state
            assert!(names.contains(&"add_evidence"));
            // Lateral-specific: add_lateral_connection
            assert!(
                names.contains(&"add_lateral_connection"),
                "LateralAnalyst should have add_lateral_connection tool"
            );
        }

        #[test]
        fn blue_orchestrator_tools() {
            let tools = blue_tools_for_role(BlueAgentRole::Orchestrator);
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            // Orchestrator-specific dispatch tools
            assert!(names.contains(&"dispatch_triage"));
            assert!(names.contains(&"dispatch_threat_hunt"));
            assert!(names.contains(&"dispatch_lateral_analysis"));
            assert!(names.contains(&"get_investigation_status"));
            assert!(names.contains(&"get_task_result"));
            assert!(names.contains(&"wait_for_all_tasks"));
            assert!(names.contains(&"complete_investigation"));
            assert!(names.contains(&"escalate_investigation"));
            // Has investigation state tools
            assert!(names.contains(&"add_evidence"));
            assert!(names.contains(&"get_investigation_summary"));
        }

        #[test]
        fn blue_escalation_triage_tools() {
            let tools = blue_tools_for_role(BlueAgentRole::EscalationTriage);
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            // Escalation-specific callbacks
            assert!(names.contains(&"confirm_escalation"));
            assert!(names.contains(&"downgrade_escalation"));
            assert!(names.contains(&"request_reinvestigation"));
            assert!(names.contains(&"route_to_team"));
            // Has investigation state tools
            assert!(names.contains(&"add_evidence"));
            assert!(names.contains(&"get_investigation_summary"));
        }

        #[test]
        fn lateral_analyst_only_role_with_lateral_connection() {
            for role in [
                BlueAgentRole::Orchestrator,
                BlueAgentRole::Triage,
                BlueAgentRole::ThreatHunter,
                BlueAgentRole::EscalationTriage,
            ] {
                let tools = blue_tools_for_role(role);
                let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
                assert!(
                    !names.contains(&"add_lateral_connection"),
                    "{:?} should NOT have add_lateral_connection",
                    role
                );
            }
        }

        #[test]
        fn blue_tool_schemas_valid_json() {
            for role in [
                BlueAgentRole::Orchestrator,
                BlueAgentRole::Triage,
                BlueAgentRole::ThreatHunter,
                BlueAgentRole::LateralAnalyst,
                BlueAgentRole::EscalationTriage,
            ] {
                let tools = blue_tools_for_role(role);
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
        fn no_duplicate_blue_tool_names_per_role() {
            // Known duplicate: get_investigation_context appears in both
            // escalation_triage callbacks and investigation_state tools.
            let known_dupes: std::collections::HashSet<(&str, &str)> =
                [("escalation_triage", "get_investigation_context")]
                    .into_iter()
                    .collect();
            for role in [
                BlueAgentRole::Orchestrator,
                BlueAgentRole::Triage,
                BlueAgentRole::ThreatHunter,
                BlueAgentRole::LateralAnalyst,
                BlueAgentRole::EscalationTriage,
            ] {
                let tools = blue_tools_for_role(role);
                let mut seen = std::collections::HashSet::new();
                for tool in &tools {
                    if !seen.insert(&tool.name) {
                        assert!(
                            known_dupes.contains(&(role.as_str(), tool.name.as_str())),
                            "Unexpected duplicate tool '{}' in blue role {:?}",
                            tool.name,
                            role
                        );
                    }
                }
            }
        }

        #[test]
        fn all_blue_roles_have_investigation_state_tools() {
            for role in [
                BlueAgentRole::Orchestrator,
                BlueAgentRole::Triage,
                BlueAgentRole::ThreatHunter,
                BlueAgentRole::LateralAnalyst,
                BlueAgentRole::EscalationTriage,
            ] {
                let tools = blue_tools_for_role(role);
                let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
                assert!(
                    names.contains(&"add_evidence"),
                    "{:?} missing add_evidence",
                    role
                );
                assert!(
                    names.contains(&"get_investigation_summary"),
                    "{:?} missing get_investigation_summary",
                    role
                );
                assert!(
                    names.contains(&"add_technique"),
                    "{:?} missing add_technique",
                    role
                );
            }
        }
    }
}
