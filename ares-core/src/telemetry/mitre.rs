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
//
// Keys MUST match the tool names in ares_tools::dispatch().
// =============================================================================

/// Tool name → MITRE ATT&CK technique ID.
pub static TOOL_TO_TECHNIQUE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        // ── Reconnaissance / Discovery ──────────────────────────────────
        ("nmap_scan", "T1046"),
        ("smb_sweep", "T1046"),
        ("smb_signing_check", "T1046"),
        ("enumerate_users", "T1087.002"),
        ("enumerate_shares", "T1135"),
        ("run_bloodhound", "T1087.002"),
        ("ldap_search", "T1087.002"),
        ("ldap_search_descriptions", "T1087.002"),
        ("rpcclient_command", "T1087.002"),
        ("dig_query", "T1018"),
        ("enumerate_domain_trusts", "T1482"),
        ("check_rdp_reachability", "T1046"),
        ("check_winrm_reachability", "T1046"),
        ("zerologon_check", "T1518.001"),
        ("adidnsdump", "T1018"),
        ("smbclient_kerberos_shares", "T1135"),
        ("save_users_to_file", "T1087.002"),
        // ── Credential Access ───────────────────────────────────────────
        ("secretsdump", "T1003.006"),
        ("secretsdump_kerberos", "T1003.006"),
        ("ntds_dit_extract", "T1003.003"),
        ("kerberoast", "T1558.003"),
        ("targeted_kerberoast", "T1558.003"),
        ("asrep_roast", "T1558.004"),
        ("certipy_auth", "T1649"),
        ("certipy_find", "T1649"),
        ("laps_dump", "T1003.008"),
        ("lsassy", "T1003.001"),
        ("gpp_password_finder", "T1552.006"),
        ("gmsa_dump_passwords", "T1003.006"),
        ("extract_trust_key", "T1003.006"),
        ("smbclient_spider", "T1552.001"),
        ("sysvol_script_search", "T1552.001"),
        ("kerberos_user_enum_noauth", "T1087.002"),
        ("domain_admin_checker", "T1087.002"),
        ("password_policy", "T1087.002"),
        ("password_spray", "T1110.003"),
        ("username_as_password", "T1110.001"),
        ("check_credman_entries", "T1552.001"),
        ("check_autologon_registry", "T1552.001"),
        // ── Credential Cracking ─────────────────────────────────────────
        ("crack_with_hashcat", "T1110.002"),
        ("crack_with_john", "T1110.002"),
        // ── Privilege Escalation ────────────────────────────────────────
        ("certipy_request", "T1649"),
        ("certipy_shadow", "T1556.006"),
        ("certipy_template_esc4", "T1649"),
        ("certipy_esc4_full_chain", "T1649"),
        ("rbcd_write", "T1134.001"),
        ("s4u_attack", "T1134.001"),
        ("find_delegation", "T1087.002"),
        ("unconstrained_tgt_dump", "T1558.001"),
        ("unconstrained_coerce_and_capture", "T1558.001"),
        ("generate_golden_ticket", "T1558.001"),
        ("add_computer", "T1136.002"),
        ("addspn", "T1098.001"),
        ("krbrelayup", "T1134.001"),
        ("raise_child", "T1134.001"),
        ("create_inter_realm_ticket", "T1558.001"),
        ("get_sid", "T1087.002"),
        ("dnstool", "T1484.001"),
        ("nopac", "T1068"),
        ("printnightmare", "T1068"),
        ("petitpotam_unauth", "T1187"),
        // ── ACL Exploitation ────────────────────────────────────────────
        ("dacl_edit", "T1222.001"),
        ("bloodyad_add_group_member", "T1098.001"),
        ("bloodyad_set_password", "T1098.001"),
        ("bloodyad_add_genericall", "T1222.001"),
        ("adminsd_holder_add_ace", "T1222.001"),
        ("gmsa_read_password_bloodyad", "T1003.006"),
        ("pywhisker", "T1556.006"),
        ("sharpgpoabuse", "T1484.001"),
        ("pygpoabuse_immediate_task", "T1484.001"),
        // ── Lateral Movement ────────────────────────────────────────────
        ("psexec", "T1021.002"),
        ("psexec_kerberos", "T1021.002"),
        ("wmiexec", "T1047"),
        ("wmiexec_kerberos", "T1047"),
        ("smbexec", "T1021.002"),
        ("smbexec_kerberos", "T1021.002"),
        ("atexec", "T1053.005"),
        ("dcomexec", "T1021.003"),
        ("evil_winrm", "T1021.006"),
        ("xfreerdp", "T1021.001"),
        ("ssh_with_password", "T1021.004"),
        ("pth_winexe", "T1021.002"),
        ("pth_smbclient", "T1021.002"),
        ("pth_rpcclient", "T1021.002"),
        ("pth_wmic", "T1047"),
        ("get_tgt", "T1558"),
        ("mssql_command", "T1021.002"),
        ("mssql_enable_xp_cmdshell", "T1059.001"),
        ("mssql_exec_linked", "T1021.002"),
        ("mssql_linked_enable_xpcmdshell", "T1059.001"),
        ("mssql_linked_xpcmdshell", "T1059.001"),
        ("mssql_ntlm_coerce", "T1187"),
        // ── Coercion / Relay ────────────────────────────────────────────
        ("petitpotam", "T1187"),
        ("dfscoerce", "T1187"),
        ("coercer", "T1187"),
        ("start_responder", "T1557.001"),
        ("start_mitm6", "T1557.001"),
        ("ntlmrelayx_to_ldaps", "T1557.001"),
        ("ntlmrelayx_to_adcs", "T1557.001"),
        ("ntlmrelayx_to_smb", "T1557.001"),
        ("ntlmrelayx_multirelay", "T1557.001"),
        // ── MSSQL ───────────────────────────────────────────────────────
        ("mssql_enum_impersonation", "T1078.002"),
        ("mssql_enum_linked_servers", "T1021.002"),
        ("mssql_impersonate", "T1134.001"),
    ])
});

// =============================================================================
// Tool → Category
//
// Keys MUST match the tool names in ares_tools::dispatch().
// =============================================================================

/// Tool name → toolset category (for dashboard grouping).
pub static TOOL_TO_CATEGORY: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        // ── NetworkEnumerationTools ─────────────────────────────────────
        ("nmap_scan", "NetworkEnumerationTools"),
        ("smb_sweep", "NetworkEnumerationTools"),
        ("smb_signing_check", "NetworkEnumerationTools"),
        ("enumerate_users", "NetworkEnumerationTools"),
        ("enumerate_shares", "NetworkEnumerationTools"),
        ("ldap_search", "NetworkEnumerationTools"),
        ("ldap_search_descriptions", "NetworkEnumerationTools"),
        ("rpcclient_command", "NetworkEnumerationTools"),
        ("dig_query", "NetworkEnumerationTools"),
        ("enumerate_domain_trusts", "NetworkEnumerationTools"),
        ("check_rdp_reachability", "NetworkEnumerationTools"),
        ("check_winrm_reachability", "NetworkEnumerationTools"),
        ("zerologon_check", "NetworkEnumerationTools"),
        ("adidnsdump", "NetworkEnumerationTools"),
        ("smbclient_kerberos_shares", "NetworkEnumerationTools"),
        ("save_users_to_file", "NetworkEnumerationTools"),
        ("kerberos_user_enum_noauth", "NetworkEnumerationTools"),
        ("password_policy", "NetworkEnumerationTools"),
        ("get_sid", "NetworkEnumerationTools"),
        ("find_delegation", "NetworkEnumerationTools"),
        // ── BloodHoundTools ─────────────────────────────────────────────
        ("run_bloodhound", "BloodHoundTools"),
        // ── CredentialHarvestingTools ────────────────────────────────────
        ("secretsdump", "CredentialHarvestingTools"),
        ("secretsdump_kerberos", "CredentialHarvestingTools"),
        ("ntds_dit_extract", "CredentialHarvestingTools"),
        ("kerberoast", "CredentialHarvestingTools"),
        ("targeted_kerberoast", "CredentialHarvestingTools"),
        ("asrep_roast", "CredentialHarvestingTools"),
        ("laps_dump", "CredentialHarvestingTools"),
        ("lsassy", "CredentialHarvestingTools"),
        ("gpp_password_finder", "CredentialHarvestingTools"),
        ("domain_admin_checker", "CredentialHarvestingTools"),
        ("password_spray", "CredentialHarvestingTools"),
        ("username_as_password", "CredentialHarvestingTools"),
        ("check_credman_entries", "CredentialHarvestingTools"),
        ("check_autologon_registry", "CredentialHarvestingTools"),
        ("get_tgt", "CredentialHarvestingTools"),
        // ── SharePilferingTools ─────────────────────────────────────────
        ("smbclient_spider", "SharePilferingTools"),
        ("sysvol_script_search", "SharePilferingTools"),
        // ── GMSATools ───────────────────────────────────────────────────
        ("gmsa_dump_passwords", "GMSATools"),
        ("gmsa_read_password_bloodyad", "GMSATools"),
        // ── TrustAttackTools ────────────────────────────────────────────
        ("extract_trust_key", "TrustAttackTools"),
        ("raise_child", "TrustAttackTools"),
        ("create_inter_realm_ticket", "TrustAttackTools"),
        // ── CertipyTools ────────────────────────────────────────────────
        ("certipy_auth", "CertipyTools"),
        ("certipy_find", "CertipyTools"),
        ("certipy_request", "CertipyTools"),
        ("certipy_shadow", "CertipyTools"),
        ("certipy_template_esc4", "CertipyTools"),
        ("certipy_esc4_full_chain", "CertipyTools"),
        // ── CrackingTools ───────────────────────────────────────────────
        ("crack_with_hashcat", "CrackingTools"),
        ("crack_with_john", "CrackingTools"),
        // ── DelegationTools ─────────────────────────────────────────────
        ("rbcd_write", "DelegationTools"),
        ("s4u_attack", "DelegationTools"),
        ("unconstrained_tgt_dump", "DelegationTools"),
        ("unconstrained_coerce_and_capture", "DelegationTools"),
        ("addspn", "DelegationTools"),
        // ── PrivilegeEscalationTools ────────────────────────────────────
        ("krbrelayup", "PrivilegeEscalationTools"),
        ("dnstool", "PrivilegeEscalationTools"),
        ("add_computer", "PrivilegeEscalationTools"),
        // ── CVEExploitTools ─────────────────────────────────────────────
        ("nopac", "CVEExploitTools"),
        ("printnightmare", "CVEExploitTools"),
        ("petitpotam_unauth", "CVEExploitTools"),
        // ── ACLExploitTools ─────────────────────────────────────────────
        ("dacl_edit", "ACLExploitTools"),
        ("bloodyad_add_group_member", "ACLExploitTools"),
        ("bloodyad_set_password", "ACLExploitTools"),
        ("bloodyad_add_genericall", "ACLExploitTools"),
        ("adminsd_holder_add_ace", "ACLExploitTools"),
        ("pywhisker", "ACLExploitTools"),
        ("sharpgpoabuse", "ACLExploitTools"),
        ("pygpoabuse_immediate_task", "ACLExploitTools"),
        // ── LateralMovementTools ────────────────────────────────────────
        ("psexec", "LateralMovementTools"),
        ("psexec_kerberos", "LateralMovementTools"),
        ("wmiexec", "LateralMovementTools"),
        ("wmiexec_kerberos", "LateralMovementTools"),
        ("smbexec", "LateralMovementTools"),
        ("smbexec_kerberos", "LateralMovementTools"),
        ("atexec", "LateralMovementTools"),
        ("dcomexec", "LateralMovementTools"),
        ("evil_winrm", "LateralMovementTools"),
        ("xfreerdp", "LateralMovementTools"),
        ("ssh_with_password", "LateralMovementTools"),
        ("pth_winexe", "LateralMovementTools"),
        ("pth_smbclient", "LateralMovementTools"),
        ("pth_rpcclient", "LateralMovementTools"),
        ("pth_wmic", "LateralMovementTools"),
        ("mssql_command", "LateralMovementTools"),
        // ── CoercionTools ───────────────────────────────────────────────
        ("petitpotam", "CoercionTools"),
        ("dfscoerce", "CoercionTools"),
        ("coercer", "CoercionTools"),
        ("mssql_ntlm_coerce", "CoercionTools"),
        ("ntlmrelayx_to_ldaps", "CoercionTools"),
        ("ntlmrelayx_to_adcs", "CoercionTools"),
        ("ntlmrelayx_to_smb", "CoercionTools"),
        ("ntlmrelayx_multirelay", "CoercionTools"),
        // ── CoercionNetworkTools ────────────────────────────────────────
        ("start_responder", "CoercionNetworkTools"),
        ("start_mitm6", "CoercionNetworkTools"),
        // ── MSSQLTools ──────────────────────────────────────────────────
        ("mssql_enum_impersonation", "MSSQLTools"),
        ("mssql_enum_linked_servers", "MSSQLTools"),
        ("mssql_impersonate", "MSSQLTools"),
        ("mssql_enable_xp_cmdshell", "MSSQLTools"),
        ("mssql_exec_linked", "MSSQLTools"),
        ("mssql_linked_enable_xpcmdshell", "MSSQLTools"),
        ("mssql_linked_xpcmdshell", "MSSQLTools"),
        // ── GoldenTicketTools ───────────────────────────────────────────
        ("generate_golden_ticket", "GoldenTicketTools"),
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
        "T1134" | "T1098" | "T1078" | "T1222" | "T1484" | "T1556" | "T1068" => {
            Some("privilege-escalation")
        }
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
        // Verify corrected dispatch names
        assert_eq!(TOOL_TO_TECHNIQUE.get("lsassy"), Some(&"T1003.001"));
        assert_eq!(TOOL_TO_TECHNIQUE.get("xfreerdp"), Some(&"T1021.001"));
        assert_eq!(
            TOOL_TO_TECHNIQUE.get("crack_with_hashcat"),
            Some(&"T1110.002")
        );
        assert_eq!(TOOL_TO_TECHNIQUE.get("coercer"), Some(&"T1187"));
        assert_eq!(TOOL_TO_TECHNIQUE.get("certipy_request"), Some(&"T1649"));
        assert_eq!(TOOL_TO_TECHNIQUE.get("rbcd_write"), Some(&"T1134.001"));
        assert_eq!(
            TOOL_TO_TECHNIQUE.get("bloodyad_add_group_member"),
            Some(&"T1098.001")
        );
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
        // Verify corrected dispatch names
        assert_eq!(
            TOOL_TO_CATEGORY.get("lsassy"),
            Some(&"CredentialHarvestingTools")
        );
        assert_eq!(
            TOOL_TO_CATEGORY.get("xfreerdp"),
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
        assert_eq!(tactic_from_technique("T1068"), Some("privilege-escalation"));
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
