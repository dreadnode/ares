//! MITRE ATT&CK mappings for Ares agent instrumentation.
//!
//! These static maps translate tool names and agent roles into MITRE technique
//! IDs, tactic names, and attack phases — used as span attributes for
//! observability dashboards.

use std::collections::HashMap;
use std::sync::LazyLock;

// =============================================================================
// Role → Tactic
// =============================================================================

/// Red team agent role → primary MITRE tactic.
pub static ROLE_TO_TACTIC: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("orchestrator", "command-and-control"),
        ("recon", "discovery"),
        ("credential_access", "credential-access"),
        ("cracker", "credential-access"),
        ("acl", "privilege-escalation"),
        ("privesc", "privilege-escalation"),
        ("lateral", "lateral-movement"),
        ("coercion", "credential-access"),
    ])
});

/// Blue team agent role → investigative tactic.
pub static BLUE_ROLE_TO_TACTIC: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("orchestrator", "collection"),
        ("triage", "discovery"),
        ("threat_hunter", "discovery"),
        ("lateral_analyst", "lateral-movement"),
    ])
});

// =============================================================================
// Role → Attack Phase
// =============================================================================

/// Red team agent role → attack phase.
pub static ROLE_TO_PHASE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("orchestrator", "coordination"),
        ("recon", "reconnaissance"),
        ("credential_access", "credential-theft"),
        ("cracker", "credential-theft"),
        ("acl", "privilege-escalation"),
        ("privesc", "privilege-escalation"),
        ("lateral", "lateral-movement"),
        ("coercion", "credential-theft"),
    ])
});

/// Blue team agent role → investigation phase.
pub static BLUE_ROLE_TO_PHASE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("orchestrator", "coordination"),
        ("triage", "initial-triage"),
        ("threat_hunter", "threat-hunting"),
        ("lateral_analyst", "lateral-analysis"),
    ])
});

// =============================================================================
// Tool → MITRE Technique ID
// =============================================================================

/// Tool name → MITRE ATT&CK technique ID.
pub static TOOL_TO_TECHNIQUE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        // Reconnaissance / Discovery
        ("nmap_scan", "T1046"),
        ("portscan", "T1046"),
        ("ping_sweep", "T1018"),
        ("smb_sweep", "T1046"),
        ("resolve_domain_controllers", "T1018"),
        ("ldap_domain_dump", "T1087.002"),
        ("ldap_search", "T1087.002"),
        ("ldap_search_descriptions", "T1087.002"),
        ("bloodhound_collection", "T1087.002"),
        ("run_bloodhound", "T1087.002"),
        ("sharphound", "T1087.002"),
        ("get_domain_info", "T1087.002"),
        ("enumerate_users", "T1087.002"),
        ("enum_domain_trusts", "T1482"),
        ("enumerate_forest", "T1482"),
        ("enum_constrained_delegation", "T1087.002"),
        ("enum_unconstrained_delegation", "T1087.002"),
        ("enum_rbcd_targets", "T1087.002"),
        ("smb_share_enum", "T1135"),
        ("enumerate_shares", "T1135"),
        ("smbclient_ls", "T1135"),
        // Credential Access
        ("secretsdump", "T1003.006"),
        ("secretsdump_kerberos", "T1003.006"),
        ("ntds_dit_extract", "T1003.003"),
        ("kerberoast", "T1558.003"),
        ("targeted_kerberoast", "T1558.003"),
        ("asrep_roast", "T1558.004"),
        ("certipy_auth", "T1649"),
        ("certipy_find", "T1649"),
        ("laps_dump", "T1003.008"),
        ("dump_lsass", "T1003.001"),
        ("gpp_password_finder", "T1552.006"),
        ("gmsa_dump_passwords", "T1003.006"),
        ("extract_trust_key", "T1003.006"),
        ("smbclient_spider", "T1552.001"),
        ("sysvol_script_search", "T1552.001"),
        // Credential Cracking
        ("hashcat_crack", "T1110.002"),
        ("crack_hash", "T1110.002"),
        // Privilege Escalation
        ("certipy_req", "T1649"),
        ("rbcd_attack", "T1134.001"),
        ("constrained_delegation_attack", "T1134.001"),
        ("unconstrained_delegation_attack", "T1558.001"),
        ("dcsync", "T1003.006"),
        ("add_shadow_credentials", "T1556.006"),
        ("set_rbcd", "T1098.001"),
        ("add_computer", "T1136.002"),
        // ACL Exploitation
        ("dacl_edit", "T1222.001"),
        ("add_user_to_group", "T1098.001"),
        ("modify_owner", "T1222.001"),
        ("modify_dacl", "T1222.001"),
        ("write_gpo", "T1484.001"),
        // Lateral Movement
        ("psexec", "T1021.002"),
        ("wmiexec", "T1047"),
        ("smbexec", "T1021.002"),
        ("atexec", "T1053.005"),
        ("dcomexec", "T1021.003"),
        ("evil_winrm", "T1021.006"),
        ("rdp_connect", "T1021.001"),
        ("ssh_connect", "T1021.004"),
        ("mssql_exec", "T1021.002"),
        // Coercion / Relay
        ("petitpotam", "T1187"),
        ("printerbug", "T1187"),
        ("dfscoerce", "T1187"),
        ("shadowcoerce", "T1187"),
        ("coerce_auth", "T1187"),
        ("ntlm_relay", "T1557.001"),
        ("relay_to_ldap", "T1557.001"),
        ("relay_to_smb", "T1557.001"),
        // MSSQL
        ("mssql_enum_impersonation", "T1078.002"),
        ("mssql_enum_linked_servers", "T1021.002"),
        ("mssql_impersonate", "T1134.001"),
        ("mssql_xp_cmdshell", "T1059.001"),
        // Golden Ticket / Persistence
        ("generate_golden_ticket", "T1558.001"),
        ("forge_golden_ticket", "T1558.001"),
        ("forge_silver_ticket", "T1558.002"),
        ("create_machine_account", "T1136.002"),
        // Reporting
        ("record_credential", "T1087.002"),
        ("record_timeline_event", "T1087"),
    ])
});

// =============================================================================
// Tool → Category
// =============================================================================

/// Tool name → toolset category (for dashboard grouping).
pub static TOOL_TO_CATEGORY: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        // NetworkEnumerationTools
        ("nmap_scan", "NetworkEnumerationTools"),
        ("portscan", "NetworkEnumerationTools"),
        ("ping_sweep", "NetworkEnumerationTools"),
        ("smb_sweep", "NetworkEnumerationTools"),
        ("resolve_domain_controllers", "NetworkEnumerationTools"),
        ("ldap_domain_dump", "NetworkEnumerationTools"),
        ("ldap_search", "NetworkEnumerationTools"),
        ("ldap_search_descriptions", "NetworkEnumerationTools"),
        ("bloodhound_collection", "NetworkEnumerationTools"),
        ("run_bloodhound", "BloodHoundTools"),
        ("sharphound", "NetworkEnumerationTools"),
        ("get_domain_info", "NetworkEnumerationTools"),
        ("enumerate_users", "NetworkEnumerationTools"),
        ("enum_domain_trusts", "NetworkEnumerationTools"),
        ("enumerate_forest", "NetworkEnumerationTools"),
        ("enum_constrained_delegation", "NetworkEnumerationTools"),
        ("enum_unconstrained_delegation", "NetworkEnumerationTools"),
        ("enum_rbcd_targets", "NetworkEnumerationTools"),
        ("smb_share_enum", "NetworkEnumerationTools"),
        ("enumerate_shares", "NetworkEnumerationTools"),
        ("smbclient_ls", "NetworkEnumerationTools"),
        // CredentialHarvestingTools
        ("secretsdump", "CredentialHarvestingTools"),
        ("secretsdump_kerberos", "CredentialHarvestingTools"),
        ("ntds_dit_extract", "CredentialHarvestingTools"),
        ("kerberoast", "CredentialHarvestingTools"),
        ("targeted_kerberoast", "CredentialHarvestingTools"),
        ("asrep_roast", "CredentialHarvestingTools"),
        ("laps_dump", "CredentialHarvestingTools"),
        ("dump_lsass", "CredentialHarvestingTools"),
        ("gpp_password_finder", "CredentialHarvestingTools"),
        // SharePilferingTools
        ("smbclient_spider", "SharePilferingTools"),
        ("sysvol_script_search", "SharePilferingTools"),
        // GMSATools
        ("gmsa_dump_passwords", "GMSATools"),
        // TrustAttackTools
        ("extract_trust_key", "TrustAttackTools"),
        // CertipyTools
        ("certipy_auth", "CertipyTools"),
        ("certipy_find", "CertipyTools"),
        ("certipy_req", "CertipyTools"),
        // CrackingTools
        ("hashcat_crack", "CrackingTools"),
        ("crack_hash", "CrackingTools"),
        // DelegationTools
        ("rbcd_attack", "DelegationTools"),
        ("constrained_delegation_attack", "DelegationTools"),
        ("unconstrained_delegation_attack", "DelegationTools"),
        ("set_rbcd", "DelegationTools"),
        // PrivilegeEscalationTools
        ("dcsync", "PrivilegeEscalationTools"),
        ("add_shadow_credentials", "PrivilegeEscalationTools"),
        ("add_computer", "PrivilegeEscalationTools"),
        // ACLExploitTools
        ("dacl_edit", "ACLExploitTools"),
        ("add_user_to_group", "ACLExploitTools"),
        ("modify_owner", "ACLExploitTools"),
        ("modify_dacl", "ACLExploitTools"),
        ("write_gpo", "ACLExploitTools"),
        // LateralMovementTools
        ("psexec", "LateralMovementTools"),
        ("wmiexec", "LateralMovementTools"),
        ("smbexec", "LateralMovementTools"),
        ("atexec", "LateralMovementTools"),
        ("dcomexec", "LateralMovementTools"),
        ("evil_winrm", "LateralMovementTools"),
        ("rdp_connect", "LateralMovementTools"),
        ("ssh_connect", "LateralMovementTools"),
        ("mssql_exec", "LateralMovementTools"),
        // CoercionTools
        ("petitpotam", "CoercionTools"),
        ("printerbug", "CoercionTools"),
        ("dfscoerce", "CoercionTools"),
        ("shadowcoerce", "CoercionTools"),
        ("coerce_auth", "CoercionTools"),
        ("ntlm_relay", "CoercionTools"),
        ("relay_to_ldap", "CoercionTools"),
        ("relay_to_smb", "CoercionTools"),
        // MSSQLTools
        ("mssql_enum_impersonation", "MSSQLTools"),
        ("mssql_enum_linked_servers", "MSSQLTools"),
        ("mssql_impersonate", "MSSQLTools"),
        ("mssql_xp_cmdshell", "MSSQLTools"),
        // GoldenTicketTools
        ("forge_golden_ticket", "GoldenTicketTools"),
        ("forge_silver_ticket", "GoldenTicketTools"),
        ("create_machine_account", "GoldenTicketTools"),
        // ReportingTools
        ("record_credential", "ReportingTools"),
        ("record_timeline_event", "ReportingTools"),
    ])
});

// =============================================================================
// Tool metadata from tools.yaml (generated at compile time)
// =============================================================================

include!(concat!(env!("OUT_DIR"), "/tool_meta.rs"));

/// Look up the tool binary from `tools.yaml`.
pub fn get_tool_binary(tool_name: &str) -> Option<&'static str> {
    tool_meta(tool_name).map(|m| m.binary)
}

/// Look up the human-readable category from `tools.yaml`.
pub fn get_tool_yaml_category(tool_name: &str) -> Option<&'static str> {
    tool_meta(tool_name).map(|m| m.category)
}

/// Look up the provisioning role from `tools.yaml`.
pub fn get_tool_role(tool_name: &str) -> Option<&'static str> {
    tool_meta(tool_name).map(|m| m.role)
}

/// Tool category → fallback tactic.
pub static TOOL_CATEGORY_TO_TACTIC: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("NetworkEnumerationTools", "discovery"),
        ("BloodHoundTools", "discovery"),
        ("PostureValidationTools", "discovery"),
        ("CredentialDiscoveryTools", "credential-access"),
        ("CredentialHarvestingTools", "credential-access"),
        ("SharePilferingTools", "collection"),
        ("CrackingTools", "credential-access"),
        ("ACLExploitTools", "privilege-escalation"),
        ("CertipyTools", "privilege-escalation"),
        ("DelegationTools", "privilege-escalation"),
        ("PrivilegeEscalationTools", "privilege-escalation"),
        ("MSSQLTools", "lateral-movement"),
        ("CVEExploitTools", "privilege-escalation"),
        ("GoldenTicketTools", "persistence"),
        ("TrustAttackTools", "privilege-escalation"),
        ("GMSATools", "credential-access"),
        ("LateralMovementTools", "lateral-movement"),
        ("CoercionTools", "credential-access"),
        ("CoercionNetworkTools", "credential-access"),
        ("ReportingTools", "discovery"),
    ])
});

// =============================================================================
// Lookup helpers
// =============================================================================

/// Derive a tactic name from a MITRE technique ID prefix.
pub fn tactic_from_technique(technique_id: &str) -> Option<&'static str> {
    let base = technique_id.split('.').next().unwrap_or(technique_id);
    match base {
        "T1087" | "T1018" | "T1046" | "T1135" | "T1482" | "T1518" => Some("discovery"),
        "T1003" | "T1558" | "T1187" | "T1557" | "T1552" | "T1110" | "T1649" => {
            Some("credential-access")
        }
        "T1134" | "T1098" | "T1078" | "T1222" | "T1484" | "T1556" => Some("privilege-escalation"),
        "T1021" | "T1047" | "T1053" => Some("lateral-movement"),
        "T1136" => Some("persistence"),
        "T1059" => Some("execution"),
        _ => None,
    }
}

/// Look up the MITRE technique ID and derived tactic for a tool.
pub fn get_tool_mitre_info(tool_name: &str) -> (Option<&'static str>, Option<&'static str>) {
    match TOOL_TO_TECHNIQUE.get(tool_name) {
        Some(&technique) => {
            let tactic = tactic_from_technique(technique);
            (Some(technique), tactic)
        }
        None => (None, None),
    }
}

/// Look up the tool category.
pub fn get_tool_category(tool_name: &str) -> Option<&'static str> {
    TOOL_TO_CATEGORY.get(tool_name).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_tactic_mappings() {
        assert_eq!(ROLE_TO_TACTIC.get("recon"), Some(&"discovery"));
        assert_eq!(
            ROLE_TO_TACTIC.get("credential_access"),
            Some(&"credential-access")
        );
        assert_eq!(ROLE_TO_TACTIC.get("lateral"), Some(&"lateral-movement"));
    }

    #[test]
    fn test_tool_to_technique() {
        assert_eq!(TOOL_TO_TECHNIQUE.get("nmap_scan"), Some(&"T1046"));
        assert_eq!(TOOL_TO_TECHNIQUE.get("secretsdump"), Some(&"T1003.006"));
        assert_eq!(TOOL_TO_TECHNIQUE.get("psexec"), Some(&"T1021.002"));
    }

    #[test]
    fn test_tool_to_category() {
        assert_eq!(
            TOOL_TO_CATEGORY.get("nmap_scan"),
            Some(&"NetworkEnumerationTools")
        );
        assert_eq!(
            TOOL_TO_CATEGORY.get("psexec"),
            Some(&"LateralMovementTools")
        );
    }

    #[test]
    fn test_tactic_from_technique() {
        assert_eq!(tactic_from_technique("T1046"), Some("discovery"));
        assert_eq!(
            tactic_from_technique("T1003.006"),
            Some("credential-access")
        );
        assert_eq!(tactic_from_technique("T1021.002"), Some("lateral-movement"));
        assert_eq!(tactic_from_technique("T1059.001"), Some("execution"));
        assert_eq!(tactic_from_technique("T9999"), None);
    }

    #[test]
    fn test_get_tool_mitre_info() {
        let (tech, tactic) = get_tool_mitre_info("kerberoast");
        assert_eq!(tech, Some("T1558.003"));
        assert_eq!(tactic, Some("credential-access"));

        let (tech, tactic) = get_tool_mitre_info("nonexistent_tool");
        assert_eq!(tech, None);
        assert_eq!(tactic, None);
    }

    #[test]
    fn test_get_tool_category() {
        assert_eq!(
            get_tool_category("secretsdump"),
            Some("CredentialHarvestingTools")
        );
        assert_eq!(get_tool_category("nonexistent"), None);
    }
}
