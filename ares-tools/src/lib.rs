//! Native tool execution for the Ares red team platform.
//!
//! Each tool is a thin wrapper around a CLI command (nmap, impacket, netexec, etc.)
//! executed as a subprocess with timeout. Tools are dispatched by name from LLM
//! tool_use calls via [`dispatch`].

pub mod acl;
pub mod args;
#[cfg(feature = "blue")]
pub mod blue;
pub mod coercion;
pub mod cracker;
pub mod credential_access;
pub mod credentials;
pub mod executor;
pub mod filter;
pub mod lateral;
pub mod parsers;
pub mod privesc;
pub mod recon;
pub mod scope;

use anyhow::Result;
use serde_json::Value;

/// Output from a tool execution.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub success: bool,
}

impl ToolOutput {
    /// Merge stdout and stderr into a single output string for the LLM.
    ///
    /// Applies noise filtering (MOTD banners, box-drawing, "command not found",
    /// etc.) so the LLM sees clean, actionable output.
    pub fn combined(&self) -> String {
        let mut out = self.stdout.clone();
        if !self.stderr.is_empty() {
            if !out.is_empty() {
                out.push_str("\n\n--- stderr ---\n");
            }
            out.push_str(&self.stderr);
        }
        filter::filter_output(&out)
    }

    /// Merge stdout and stderr without filtering (for structured parsers that
    /// need the raw bytes).
    pub fn combined_raw(&self) -> String {
        let mut out = self.stdout.clone();
        if !self.stderr.is_empty() {
            if !out.is_empty() {
                out.push_str("\n\n--- stderr ---\n");
            }
            out.push_str(&self.stderr);
        }
        out
    }
}

/// Dispatch a tool call by name, executing the corresponding CLI command.
///
/// Returns the tool output or an error if the tool is unknown or execution
/// fails. Calls whose `target` / `target_ip` is a literal IP outside the
/// configured operation scope are rejected before any subprocess runs (see
/// [`scope::validate_in_scope`]).
pub async fn dispatch(tool_name: &str, arguments: &Value) -> Result<ToolOutput> {
    scope::validate_in_scope(tool_name, arguments)?;
    match tool_name {
        // ── Reconnaissance ──────────────────────────────────────────
        "nmap_scan" => recon::nmap_scan(arguments).await,
        "smb_sweep" => recon::smb_sweep(arguments).await,
        "enumerate_users" => recon::enumerate_users(arguments).await,
        "enumerate_shares" => recon::enumerate_shares(arguments).await,
        "smb_signing_check" => recon::smb_signing_check(arguments).await,
        "run_bloodhound" => recon::run_bloodhound(arguments).await,
        "ldap_search" => recon::ldap_search(arguments).await,
        "rpcclient_command" => recon::rpcclient_command(arguments).await,
        "dig_query" => recon::dig_query(arguments).await,
        "enumerate_domain_trusts" => recon::enumerate_domain_trusts(arguments).await,
        "check_rdp_reachability" => recon::check_rdp_reachability(arguments).await,
        "check_winrm_reachability" => recon::check_winrm_reachability(arguments).await,
        "zerologon_check" => recon::zerologon_check(arguments).await,
        "adidnsdump" => recon::adidnsdump(arguments).await,
        "save_users_to_file" => recon::save_users_to_file(arguments).await,
        "smbclient_kerberos_shares" => recon::smbclient_kerberos_shares(arguments).await,

        // ── Credential Access ───────────────────────────────────────
        "kerberoast" => credential_access::kerberoast(arguments).await,
        "asrep_roast" => credential_access::asrep_roast(arguments).await,
        "kerberos_user_enum_noauth" => {
            credential_access::kerberos_user_enum_noauth(arguments).await
        }
        "secretsdump" => credential_access::secretsdump(arguments).await,
        "lsassy" => credential_access::lsassy(arguments).await,
        "domain_admin_checker" => credential_access::domain_admin_checker(arguments).await,
        "gpp_password_finder" => credential_access::gpp_password_finder(arguments).await,
        "sysvol_script_search" => credential_access::sysvol_script_search(arguments).await,
        "laps_dump" => credential_access::laps_dump(arguments).await,
        "ldap_search_descriptions" => credential_access::ldap_search_descriptions(arguments).await,
        "smbclient_spider" => credential_access::smbclient_spider(arguments).await,
        "ntds_dit_extract" => credential_access::ntds_dit_extract(arguments).await,
        "password_policy" => credential_access::password_policy(arguments).await,
        "password_spray" => credential_access::password_spray(arguments).await,
        "username_as_password" => credential_access::username_as_password(arguments).await,
        "check_credman_entries" => credential_access::check_credman_entries(arguments).await,
        "check_autologon_registry" => credential_access::check_autologon_registry(arguments).await,

        // ── Cracking ────────────────────────────────────────────────
        "crack_with_hashcat" => cracker::crack_with_hashcat(arguments).await,
        "crack_with_john" => cracker::crack_with_john(arguments).await,

        // ── Lateral Movement ────────────────────────────────────────
        "psexec" => lateral::psexec(arguments).await,
        "psexec_kerberos" => lateral::psexec_kerberos(arguments).await,
        "wmiexec" => lateral::wmiexec(arguments).await,
        "wmiexec_kerberos" => lateral::wmiexec_kerberos(arguments).await,
        "smbexec" => lateral::smbexec(arguments).await,
        "smbexec_kerberos" => lateral::smbexec_kerberos(arguments).await,
        "evil_winrm" => lateral::evil_winrm(arguments).await,
        "xfreerdp" => lateral::xfreerdp(arguments).await,
        "ssh_with_password" => lateral::ssh_with_password(arguments).await,
        "secretsdump_kerberos" => lateral::secretsdump_kerberos(arguments).await,
        "pth_winexe" => lateral::pth_winexe(arguments).await,
        "pth_smbclient" => lateral::pth_smbclient(arguments).await,
        "pth_rpcclient" => lateral::pth_rpcclient(arguments).await,
        "pth_wmic" => lateral::pth_wmic(arguments).await,
        "get_tgt" => lateral::get_tgt(arguments).await,
        "mssql_command" => lateral::mssql_command(arguments).await,
        "mssql_enable_xp_cmdshell" => lateral::mssql_enable_xp_cmdshell(arguments).await,
        "mssql_enum_impersonation" => lateral::mssql_enum_impersonation(arguments).await,
        "mssql_impersonate" => lateral::mssql_impersonate(arguments).await,
        "mssql_enum_linked_servers" => lateral::mssql_enum_linked_servers(arguments).await,
        "mssql_exec_linked" => lateral::mssql_exec_linked(arguments).await,
        "mssql_linked_enable_xpcmdshell" => {
            lateral::mssql_linked_enable_xpcmdshell(arguments).await
        }
        "mssql_linked_xpcmdshell" => lateral::mssql_linked_xpcmdshell(arguments).await,
        "mssql_ntlm_coerce" => lateral::mssql_ntlm_coerce(arguments).await,

        // ── Privilege Escalation ────────────────────────────────────
        "certipy_find" => privesc::certipy_find(arguments).await,
        "certipy_request" => privesc::certipy_request(arguments).await,
        "certipy_auth" => privesc::certipy_auth(arguments).await,
        "certipy_shadow" => privesc::certipy_shadow(arguments).await,
        "certipy_template_esc4" => privesc::certipy_template_esc4(arguments).await,
        "certipy_esc4_full_chain" => privesc::certipy_esc4_full_chain(arguments).await,
        "find_delegation" => privesc::find_delegation(arguments).await,
        "s4u_attack" => privesc::s4u_attack(arguments).await,
        "generate_golden_ticket" => privesc::generate_golden_ticket(arguments).await,
        "add_computer" => privesc::add_computer(arguments).await,
        "addspn" => privesc::addspn(arguments).await,
        "rbcd_write" => privesc::rbcd_write(arguments).await,
        "krbrelayup" => privesc::krbrelayup(arguments).await,
        "raise_child" => privesc::raise_child(arguments).await,
        "extract_trust_key" => privesc::extract_trust_key(arguments).await,
        "create_inter_realm_ticket" => privesc::create_inter_realm_ticket(arguments).await,
        "get_sid" => privesc::get_sid(arguments).await,
        "dnstool" => privesc::dnstool(arguments).await,
        "gmsa_dump_passwords" => privesc::gmsa_dump_passwords(arguments).await,
        "unconstrained_tgt_dump" => privesc::unconstrained_tgt_dump(arguments).await,
        "unconstrained_coerce_and_capture" => {
            privesc::unconstrained_coerce_and_capture(arguments).await
        }
        "nopac" => privesc::nopac(arguments).await,
        "printnightmare" => privesc::printnightmare(arguments).await,
        "petitpotam_unauth" => privesc::petitpotam_unauth(arguments).await,

        // ── ACL Exploitation ────────────────────────────────────────
        "bloodyad_add_group_member" => acl::bloodyad_add_group_member(arguments).await,
        "bloodyad_set_password" => acl::bloodyad_set_password(arguments).await,
        "bloodyad_add_genericall" => acl::bloodyad_add_genericall(arguments).await,
        "adminsd_holder_add_ace" => acl::adminsd_holder_add_ace(arguments).await,
        "gmsa_read_password_bloodyad" => acl::gmsa_read_password_bloodyad(arguments).await,
        "pywhisker" => acl::pywhisker(arguments).await,
        "targeted_kerberoast" => acl::targeted_kerberoast(arguments).await,
        "sharpgpoabuse" => acl::sharpgpoabuse(arguments).await,
        "pygpoabuse_immediate_task" => acl::pygpoabuse_immediate_task(arguments).await,
        "dacl_edit" => acl::dacl_edit(arguments).await,

        // ── Coercion & Relay ────────────────────────────────────────
        "start_responder" => coercion::start_responder(arguments).await,
        "start_mitm6" => coercion::start_mitm6(arguments).await,
        "coercer" => coercion::coercer(arguments).await,
        "petitpotam" => coercion::petitpotam(arguments).await,
        "dfscoerce" => coercion::dfscoerce(arguments).await,
        "ntlmrelayx_to_ldaps" => coercion::ntlmrelayx_to_ldaps(arguments).await,
        "ntlmrelayx_to_adcs" => coercion::ntlmrelayx_to_adcs(arguments).await,
        "ntlmrelayx_to_smb" => coercion::ntlmrelayx_to_smb(arguments).await,
        "ntlmrelayx_multirelay" => coercion::ntlmrelayx_multirelay(arguments).await,

        _ => Err(anyhow::anyhow!("unknown tool: {tool_name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ToolOutput::combined ─────────────────────────────────────────────────

    #[test]
    fn combined_stdout_and_stderr_joined_with_separator() {
        let out = ToolOutput {
            stdout: "scan results here".to_string(),
            stderr: "some warning".to_string(),
            exit_code: Some(0),
            success: true,
        };
        let combined = out.combined();
        // Both pieces must appear in the merged output
        assert!(combined.contains("scan results here"), "stdout missing");
        assert!(combined.contains("some warning"), "stderr missing");
        // Separator between them
        assert!(combined.contains("--- stderr ---"), "separator missing");
    }

    #[test]
    fn combined_empty_stderr_no_separator() {
        let out = ToolOutput {
            stdout: "clean output".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        };
        let combined = out.combined();
        assert!(combined.contains("clean output"), "stdout missing");
        assert!(!combined.contains("--- stderr ---"), "unexpected separator");
    }

    #[test]
    fn combined_empty_stdout_with_stderr() {
        let out = ToolOutput {
            stdout: String::new(),
            stderr: "error message".to_string(),
            exit_code: Some(1),
            success: false,
        };
        let combined = out.combined();
        assert!(combined.contains("error message"), "stderr missing");
        // No separator when stdout was empty
        assert!(
            !combined.contains("--- stderr ---"),
            "unexpected separator with empty stdout"
        );
    }

    #[test]
    fn combined_both_empty() {
        let out = ToolOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        };
        assert_eq!(out.combined(), "");
    }

    // ── ToolOutput::combined_raw ─────────────────────────────────────────────

    #[test]
    fn combined_raw_stdout_and_stderr_joined() {
        let out = ToolOutput {
            stdout: "raw stdout".to_string(),
            stderr: "raw stderr".to_string(),
            exit_code: Some(0),
            success: true,
        };
        let raw = out.combined_raw();
        assert!(raw.contains("raw stdout"));
        assert!(raw.contains("raw stderr"));
        assert!(raw.contains("--- stderr ---"));
    }

    #[test]
    fn combined_raw_empty_stderr_no_separator() {
        let out = ToolOutput {
            stdout: "data".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        };
        let raw = out.combined_raw();
        assert_eq!(raw, "data");
    }

    #[test]
    fn combined_raw_does_not_filter_noise() {
        // combined_raw must NOT strip MOTD/noise — it's for structured parsers.
        // We verify that a known-noise string is preserved verbatim.
        let motd = "Last login: Mon Apr  7 12:00:00 2025 from 192.168.58.1";
        let out = ToolOutput {
            stdout: motd.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        };
        assert_eq!(out.combined_raw(), motd);
        // combined() would strip it; combined_raw() must not
        assert!(out.combined_raw().contains("Last login"));
    }

    // ── dispatch ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_unknown_tool_returns_error() {
        let args = serde_json::json!({});
        let result = dispatch("__no_such_tool__", &args).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("unknown tool"),
            "expected 'unknown tool' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_unknown_tool_includes_name_in_error() {
        let args = serde_json::json!({});
        let result = dispatch("definitely_not_real", &args).await;
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("definitely_not_real"),
            "expected tool name in error message, got: {msg}"
        );
    }
}
