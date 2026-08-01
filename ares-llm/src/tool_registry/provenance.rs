//! Stdout trust classification for tool output.
//!
//! The orchestrator runs a regex safety net over raw tool stdout
//! (`ares-cli`'s `output_extraction`) to catch credentials, hashes, hosts,
//! users, and shares the per-tool parsers missed. Not every tool's stdout is
//! equally trustworthy: some tools echo whatever command the LLM chose, and
//! some echo AD attribute or file content an attacker can plant. This module is
//! the single source of truth for that classification.
//!
//! It lives beside the tool definitions on purpose. The classification keys on
//! the *registered* tool name (the same string that lands in
//! `ToolOutput::name`), so it can never silently drift from the registry — the
//! `every_classified_tool_is_registered` test fails the build if a name here
//! stops matching a real tool. That guard exists because the previous
//! hand-maintained blocklist in the extraction module keyed on plausible-
//! sounding binary names (`mssqlclient`, `evil-winrm`, `rpcclient`) that never
//! matched the actual tool names (`mssql_command`, `evil_winrm`,
//! `rpcclient_command`), so the gate was a no-op for most of the surface it
//! claimed to cover.

/// How much of a tool's stdout can be trusted as a genuine discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdoutProvenance {
    /// LLM-directed command shell (`smbexec`, `wmiexec`, `mssql_command`, …).
    /// stdout is whatever command the LLM chose to run, so *nothing* parsed
    /// from it is a genuine finding — every extractor is suppressed. A
    /// hallucinated or prompt-injected `echo "[+] DOMAIN\admin:Pw"` (or a
    /// forged host banner steering the agent to a honeypot) must never reach
    /// state.
    LlmDirectedShell,
    /// AD-attribute / directory enumerator (`rpcclient_command`, `ldap_search`,
    /// …). Its stdout echoes attribute values an attacker with write access to
    /// a `description` field or a share can plant, so credentials and hashes
    /// are suppressed — but users, hosts, and shares still extract because
    /// these tools are the *primary* legitimate source of that data and gating
    /// it would break real enumeration workflows.
    AttributeEnumerator,
    /// Trusted: authenticators (`smb_login_check`, `password_spray`), hash
    /// dumpers (`secretsdump`, `ntds_dit_extract`), and credential extractors
    /// (`lsassy`, `kerberoast`, `laps_dump`). Every extractor runs.
    Trusted,
}

/// LLM-directed remote command shells. Each executes an OS/SQL command the LLM
/// chose and echoes arbitrary stdout, so no extractor can trust their output.
const LLM_DIRECTED_SHELLS: &[&str] = &[
    "smbexec",
    "smbexec_kerberos",
    "wmiexec",
    "wmiexec_kerberos",
    "psexec",
    "psexec_kerberos",
    "evil_winrm",
    "mssql_command",
    "mssql_exec_linked",
    "mssql_linked_xpcmdshell",
    "windows_stage_and_run",
    "pth_winexe",
    "pth_wmic",
    "ssh_with_password",
];

/// AD-attribute / directory enumerators. Their stdout reflects attribute values
/// or share/directory contents an attacker can plant, so credentials and hashes
/// are blocked — but users/hosts/shares are trusted because these tools are the
/// primary legitimate source of that data.
const ATTRIBUTE_ENUMERATORS: &[&str] = &[
    "rpcclient_command",
    "pth_rpcclient",
    "ldap_search",
    "ldap_search_descriptions",
    "ldap_acl_enumeration",
    "enumerate_users",
    "enumerate_shares",
    "enumerate_domain_trusts",
    "kerberos_user_enum_noauth",
    "run_bloodhound",
    "adidnsdump",
    "smbclient_kerberos_shares",
    "pth_smbclient",
];

/// Classify a tool's stdout trust level by its registered name.
///
/// `name` must be the normalized registered tool name — callers receiving a raw
/// invocation name should lowercase, strip any path/extension, and fold `-`→`_`
/// first. Unknown names default to [`StdoutProvenance::Trusted`] to preserve
/// behavior for the many authenticators and dumpers that legitimately produce
/// credentials and hashes.
pub fn stdout_provenance(name: &str) -> StdoutProvenance {
    if LLM_DIRECTED_SHELLS.contains(&name) {
        StdoutProvenance::LlmDirectedShell
    } else if ATTRIBUTE_ENUMERATORS.contains(&name) {
        StdoutProvenance::AttributeEnumerator
    } else {
        StdoutProvenance::Trusted
    }
}

/// True when the tool is an LLM-directed command shell, whose stdout must not
/// feed *any* extractor (credentials, hashes, users, hosts, or shares).
pub fn is_llm_directed_shell(name: &str) -> bool {
    matches!(stdout_provenance(name), StdoutProvenance::LlmDirectedShell)
}

/// True when the tool's stdout can be trusted for the high-value extractors
/// (credentials, hashes, cracked plaintexts) — i.e. it is neither a command
/// shell nor an attribute enumerator.
pub fn stdout_trusts_secrets(name: &str) -> bool {
    matches!(stdout_provenance(name), StdoutProvenance::Trusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_registry::{tools_for_role, AgentRole};
    use std::collections::HashSet;

    const ALL_ROLES: &[AgentRole] = &[
        AgentRole::Recon,
        AgentRole::CredentialAccess,
        AgentRole::Cracker,
        AgentRole::Acl,
        AgentRole::Privesc,
        AgentRole::Lateral,
        AgentRole::Coercion,
    ];

    fn all_registered_tool_names() -> HashSet<String> {
        let mut names = HashSet::new();
        for &role in ALL_ROLES {
            for tool in tools_for_role(role) {
                names.insert(tool.name);
            }
        }
        names
    }

    /// The guard that makes this classification trustworthy: every name we
    /// classify must correspond to a tool the LLM can actually invoke. A name
    /// that matches nothing is dead weight that makes the gate look more
    /// complete than it is — exactly the bug this module replaced.
    #[test]
    fn every_classified_tool_is_registered() {
        let registered = all_registered_tool_names();
        for name in LLM_DIRECTED_SHELLS
            .iter()
            .chain(ATTRIBUTE_ENUMERATORS.iter())
        {
            assert!(
                registered.contains(*name),
                "provenance classifies '{name}' but no registered tool has that \
                 name — the classifier has drifted from the registry",
            );
        }
    }

    #[test]
    fn tiers_are_disjoint() {
        for name in LLM_DIRECTED_SHELLS {
            assert!(
                !ATTRIBUTE_ENUMERATORS.contains(name),
                "'{name}' is classified in both tiers",
            );
        }
    }

    #[test]
    fn command_shells_classify_as_shells() {
        for name in [
            "smbexec",
            "smbexec_kerberos",
            "wmiexec",
            "psexec",
            "evil_winrm",
            "mssql_command",
            "mssql_linked_xpcmdshell",
            "pth_winexe",
            "ssh_with_password",
        ] {
            assert_eq!(
                stdout_provenance(name),
                StdoutProvenance::LlmDirectedShell,
                "{name} should be an LLM-directed shell",
            );
            assert!(is_llm_directed_shell(name));
            assert!(!stdout_trusts_secrets(name));
        }
    }

    #[test]
    fn enumerators_classify_as_enumerators() {
        for name in [
            "rpcclient_command",
            "ldap_search",
            "ldap_search_descriptions",
        ] {
            assert_eq!(
                stdout_provenance(name),
                StdoutProvenance::AttributeEnumerator,
                "{name} should be an attribute enumerator",
            );
            assert!(!is_llm_directed_shell(name));
            assert!(!stdout_trusts_secrets(name));
        }
    }

    /// Real authenticators / hash dumpers / credential finders must stay
    /// trusted — misclassifying one would silently drop genuine findings.
    #[test]
    fn credential_sources_stay_trusted() {
        for name in [
            "secretsdump",
            "secretsdump_kerberos",
            "ntds_dit_extract",
            "lsassy",
            "kerberoast",
            "asrep_roast",
            "certipy_auth",
            "laps_dump",
            "gmsa_dump_passwords",
            "gpp_password_finder",
            "smb_login_check",
            "password_spray",
            "username_as_password",
            // The far-host hive dump internally hardcodes `reg save` +
            // `impacket-secretsdump LOCAL` — the LLM never chooses the
            // command, so the resulting hash rows are trusted.
            "mssql_far_host_secretsdump",
        ] {
            assert_eq!(
                stdout_provenance(name),
                StdoutProvenance::Trusted,
                "{name} is a legitimate credential/hash source and must stay trusted",
            );
            assert!(stdout_trusts_secrets(name));
        }
    }

    #[test]
    fn unknown_names_default_to_trusted() {
        assert_eq!(stdout_provenance("nmap_scan"), StdoutProvenance::Trusted);
        assert_eq!(
            stdout_provenance("totally_unknown"),
            StdoutProvenance::Trusted
        );
    }
}
