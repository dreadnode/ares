//! Task execution — run_agent_task dispatches to ares-tools.
//!
//! The orchestrator submits high-level composite task types (e.g. "recon",
//! "credential_access") with a `technique`/`techniques` field in the payload.
//! This module expands those into individual tool calls that `ares_tools::dispatch`
//! understands, then parses the raw output into structured discoveries.

use std::time::Duration;

use serde_json::Value;
use tracing::{info, warn};

use super::types::AgentResult;

/// Execute a tool natively in Rust via ares-tools.
///
/// First attempts direct dispatch by `task_type`. If the task type is a
/// composite type (recon, credential_access, etc.), expands it into individual
/// tool calls based on the `technique`/`techniques` payload field.
///
/// Tool outputs are parsed to extract structured discoveries (hosts,
/// credentials, hashes, vulnerabilities) that the orchestrator can consume.
pub async fn run_agent_task(
    task_type: &str,
    params: &serde_json::Value,
    _timeout: Duration,
) -> anyhow::Result<AgentResult> {
    // Try expanding composite task types first
    let tools = expand_task(task_type, params);

    if tools.is_empty() {
        // Direct tool dispatch (task_type IS the tool name)
        info!(tool = task_type, "Executing tool natively");
        let output = ares_tools::dispatch(task_type, params).await?;
        let raw = output.combined_raw();
        let discoveries = ares_tools::parsers::parse_tool_output(task_type, &raw, params);
        return Ok(make_result_with_discoveries(output, discoveries));
    }

    // Run each expanded tool, collecting outputs and discoveries
    let mut outputs = Vec::new();
    let mut all_discoveries = Vec::new();
    let mut any_error = false;

    for (tool_name, tool_params) in &tools {
        info!(tool = %tool_name, parent_task = task_type, "Executing expanded tool");
        match ares_tools::dispatch(tool_name, tool_params).await {
            Ok(output) => {
                if !output.success {
                    any_error = true;
                }
                let raw = output.combined_raw();
                let combined = output.combined();
                let disc = ares_tools::parsers::parse_tool_output(tool_name, &raw, tool_params);
                all_discoveries.push(disc);
                outputs.push(format!("=== {} ===\n{}", tool_name, combined));
            }
            Err(e) => {
                warn!(tool = %tool_name, err = %e, "Expanded tool failed");
                any_error = true;
                outputs.push(format!("=== {} ===\nERROR: {}", tool_name, e));
            }
        }
    }

    let combined = outputs.join("\n\n");
    let discoveries = ares_tools::parsers::merge_discoveries(&all_discoveries);
    let error = if any_error {
        Some("one or more tools had errors".to_string())
    } else {
        None
    };

    Ok(AgentResult {
        output: combined,
        error,
        usage: None,
        discoveries: Some(discoveries),
    })
}

fn make_result_with_discoveries(output: ares_tools::ToolOutput, discoveries: Value) -> AgentResult {
    let combined = output.combined();
    let error = if output.success {
        None
    } else {
        Some(format!("tool exited with code {:?}", output.exit_code))
    };
    AgentResult {
        output: combined,
        error,
        usage: None,
        discoveries: if discoveries.as_object().is_none_or(|o| o.is_empty()) {
            None
        } else {
            Some(discoveries)
        },
    }
}

/// Expand a composite task type into individual (tool_name, params) pairs.
///
/// Returns an empty vec if the task_type is already a concrete tool name.
fn expand_task(task_type: &str, params: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    match task_type {
        "recon" | "credential_access" | "privesc_enumeration" | "lateral_movement" | "coercion" => {
            expand_technique_task(params)
        }
        "crack" => expand_crack_task(params),
        "exploit" => expand_exploit_task(params),
        // Already a concrete tool name — handled by direct dispatch
        _ => Vec::new(),
    }
}

/// Expand tasks that have `technique` (singular) or `techniques` (array) fields.
fn expand_technique_task(params: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    let mut tools = Vec::new();
    let normalized = normalize_params(params);

    // Handle singular "technique" field
    if let Some(technique) = params.get("technique").and_then(|v| v.as_str()) {
        let tool_name = map_technique_to_tool(technique);
        tools.push((tool_name, normalized.clone()));
        return tools;
    }

    // Handle "techniques" array
    if let Some(techniques) = params.get("techniques").and_then(|v| v.as_array()) {
        for tech in techniques {
            if let Some(name) = tech.as_str() {
                let tool_name = map_technique_to_tool(name);
                tools.push((tool_name, normalized.clone()));
            }
        }
    }

    tools
}

/// Normalize orchestrator payload field names to what ares-tools expects.
///
/// The orchestrator sends `target_ip` but tools expect `target`.
/// Credential objects are flattened into top-level fields.
fn normalize_params(params: &serde_json::Value) -> serde_json::Value {
    let mut p = params.clone();
    if let Some(obj) = p.as_object_mut() {
        // target_ip → target (tools expect "target")
        if !obj.contains_key("target") {
            if let Some(ip) = obj.get("target_ip").cloned() {
                obj.insert("target".to_string(), ip);
            }
        }
        // Also set "targets" for tools that want it (smb_sweep)
        if !obj.contains_key("targets") {
            if let Some(ip) = obj.get("target_ip").cloned() {
                obj.insert("targets".to_string(), ip);
            }
        }
        // Flatten credential object into top-level fields
        if let Some(cred) = obj.get("credential").cloned() {
            if let Some(cred_obj) = cred.as_object() {
                for (k, v) in cred_obj {
                    if !obj.contains_key(k) {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    p
}

/// Map technique names (from orchestrator payloads) to ares-tools dispatch names.
fn map_technique_to_tool(technique: &str) -> String {
    match technique {
        // Recon technique → tool mappings
        "network_scan" => "nmap_scan".to_string(),
        "user_enumeration" => "enumerate_users".to_string(),
        "share_enumeration" => "enumerate_shares".to_string(),
        "smb_enumeration" => "smb_sweep".to_string(),
        "bloodhound_collect" => "run_bloodhound".to_string(),
        "trust_enumeration" => "enumerate_domain_trusts".to_string(),

        // Credential access technique → tool mappings
        "share_spider" => "smbclient_spider".to_string(),
        "asrep_roast" | "asrep" => "asrep_roast".to_string(),

        // Most technique names already match tool names 1:1
        other => other.to_string(),
    }
}

/// Expand crack tasks to the appropriate cracking tool.
fn expand_crack_task(params: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    let normalized = normalize_params(params);
    let tool = if params
        .get("use_john")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        "crack_with_john"
    } else {
        "crack_with_hashcat"
    };
    vec![(tool.to_string(), normalized)]
}

/// Expand exploit tasks based on vuln_type.
fn expand_exploit_task(params: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    let vuln_type = params
        .get("vuln_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let tool = match vuln_type {
        "constrained_delegation" | "unconstrained_delegation" => "s4u_attack",
        "esc1" | "adcs_esc1" => "certipy_request",
        "esc4" | "adcs_esc4" => "certipy_esc4_full_chain",
        "esc8" | "adcs_esc8" => "ntlmrelayx_to_adcs",
        "krbtgt_hash" => "generate_golden_ticket",
        "rbcd" => "rbcd_write",
        "nopac" | "samaccountname" => "nopac",
        "printnightmare" => "printnightmare",
        "zerologon" => "zerologon_check",
        "krbrelayup" => "krbrelayup",
        "mssql_access" => "mssql_enum_impersonation",
        _ => {
            warn!(vuln_type, "No tool mapping for exploit vuln_type");
            return Vec::new();
        }
    };

    vec![(tool.to_string(), normalize_params(params))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- normalize_params ---

    #[test]
    fn test_normalize_params_target_ip_to_target() {
        let params = json!({"target_ip": "192.168.58.10"});
        let norm = normalize_params(&params);
        assert_eq!(norm["target"], "192.168.58.10");
        assert_eq!(norm["targets"], "192.168.58.10");
        // Original field preserved
        assert_eq!(norm["target_ip"], "192.168.58.10");
    }

    #[test]
    fn test_normalize_params_existing_target_not_overwritten() {
        let params = json!({"target": "192.168.58.10", "target_ip": "192.168.58.20"});
        let norm = normalize_params(&params);
        assert_eq!(norm["target"], "192.168.58.10"); // not overwritten
    }

    #[test]
    fn test_normalize_params_credential_flattening() {
        let params = json!({
            "target_ip": "192.168.58.10",
            "credential": {
                "username": "admin",
                "password": "P@ss1",
                "domain": "contoso.local"
            }
        });
        let norm = normalize_params(&params);
        assert_eq!(norm["username"], "admin");
        assert_eq!(norm["password"], "P@ss1");
        assert_eq!(norm["domain"], "contoso.local");
    }

    #[test]
    fn test_normalize_params_existing_fields_not_overwritten_by_cred() {
        let params = json!({
            "domain": "fabrikam.local",
            "credential": {
                "domain": "contoso.local",
                "username": "admin",
                "password": "pass"
            }
        });
        let norm = normalize_params(&params);
        assert_eq!(norm["domain"], "fabrikam.local"); // not overwritten
    }

    // --- map_technique_to_tool ---

    #[test]
    fn test_map_technique_to_tool_mapped() {
        assert_eq!(map_technique_to_tool("network_scan"), "nmap_scan");
        assert_eq!(map_technique_to_tool("user_enumeration"), "enumerate_users");
        assert_eq!(
            map_technique_to_tool("share_enumeration"),
            "enumerate_shares"
        );
        assert_eq!(map_technique_to_tool("smb_enumeration"), "smb_sweep");
        assert_eq!(
            map_technique_to_tool("bloodhound_collect"),
            "run_bloodhound"
        );
        assert_eq!(
            map_technique_to_tool("trust_enumeration"),
            "enumerate_domain_trusts"
        );
        assert_eq!(map_technique_to_tool("share_spider"), "smbclient_spider");
        assert_eq!(map_technique_to_tool("asrep_roast"), "asrep_roast");
        assert_eq!(map_technique_to_tool("asrep"), "asrep_roast");
    }

    #[test]
    fn test_map_technique_to_tool_passthrough() {
        assert_eq!(map_technique_to_tool("nmap_scan"), "nmap_scan");
        assert_eq!(map_technique_to_tool("secretsdump"), "secretsdump");
        assert_eq!(map_technique_to_tool("kerberoast"), "kerberoast");
    }

    // --- expand_task ---

    #[test]
    fn test_expand_task_recon_with_techniques() {
        let params = json!({"techniques": ["network_scan", "user_enumeration"], "target_ip": "192.168.58.10"});
        let tools = expand_task("recon", &params);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].0, "nmap_scan");
        assert_eq!(tools[1].0, "enumerate_users");
        // Params should be normalized
        assert_eq!(tools[0].1["target"], "192.168.58.10");
    }

    #[test]
    fn test_expand_task_credential_access_single_technique() {
        let params = json!({"technique": "secretsdump", "target_ip": "192.168.58.10"});
        let tools = expand_task("credential_access", &params);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0, "secretsdump");
    }

    #[test]
    fn test_expand_task_concrete_tool_returns_empty() {
        let params = json!({"target": "192.168.58.10"});
        let tools = expand_task("nmap_scan", &params);
        assert!(tools.is_empty());
    }

    // --- expand_crack_task ---

    #[test]
    fn test_expand_crack_task_default_hashcat() {
        let params = json!({"hash_value": "abc123", "hash_type": "ntlm"});
        let tools = expand_crack_task(&params);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0, "crack_with_hashcat");
    }

    #[test]
    fn test_expand_crack_task_john() {
        let params = json!({"hash_value": "abc123", "use_john": true});
        let tools = expand_crack_task(&params);
        assert_eq!(tools[0].0, "crack_with_john");
    }

    // --- expand_exploit_task ---

    #[test]
    fn test_expand_exploit_delegation() {
        let params = json!({"vuln_type": "constrained_delegation", "target_ip": "192.168.58.10"});
        let tools = expand_exploit_task(&params);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0, "s4u_attack");
    }

    #[test]
    fn test_expand_exploit_adcs_variants() {
        for (vuln_type, expected_tool) in &[
            ("esc1", "certipy_request"),
            ("adcs_esc1", "certipy_request"),
            ("esc4", "certipy_esc4_full_chain"),
            ("esc8", "ntlmrelayx_to_adcs"),
        ] {
            let params = json!({"vuln_type": vuln_type});
            let tools = expand_exploit_task(&params);
            assert_eq!(
                tools[0].0, *expected_tool,
                "Failed for vuln_type: {vuln_type}"
            );
        }
    }

    #[test]
    fn test_expand_exploit_other_types() {
        for (vuln_type, expected) in &[
            ("krbtgt_hash", "generate_golden_ticket"),
            ("rbcd", "rbcd_write"),
            ("nopac", "nopac"),
            ("zerologon", "zerologon_check"),
            ("mssql_access", "mssql_enum_impersonation"),
        ] {
            let params = json!({"vuln_type": vuln_type});
            let tools = expand_exploit_task(&params);
            assert_eq!(tools[0].0, *expected, "Failed for vuln_type: {vuln_type}");
        }
    }

    #[test]
    fn test_expand_exploit_unknown_type_empty() {
        let params = json!({"vuln_type": "unknown_vuln"});
        let tools = expand_exploit_task(&params);
        assert!(tools.is_empty());
    }
}
