//! Tool availability check at worker startup.
//!
//! Probes which external binaries are installed so we can log warnings
//! for missing tools and optionally report the inventory to the orchestrator
//! via Redis.
//!
//! Expected tools per role are defined by Ansible provisioning — see
//! `docs/red.md` § "Installed Tools by Agent Role" for the authoritative
//! reference. Binary names here match what the Rust tool dispatch
//! (`ares-tools`) actually invokes via `CommandBuilder::new`.

use std::collections::BTreeMap;

use tracing::{info, warn};

/// All worker roles that have tool requirements.
#[cfg(test)]
const WORKER_ROLES: &[&str] = &[
    "recon",
    "credential_access",
    "cracker",
    "acl",
    "privesc",
    "lateral",
    "coercion",
];

/// Tools expected on each worker role's container image.
///
/// Source of truth: `docs/red.md` § "Installed Tools by Agent Role",
/// cross-referenced with `ares-tools/src/` `CommandBuilder::new` calls.
fn tools_for_role(role: &str) -> &'static [&'static str] {
    match role {
        // Provisioned by: ansible/playbooks/ares/recon.yml
        "recon" => &[
            // Network scanning
            "nmap",
            // SMB/AD enumeration
            "netexec",
            "enum4linux",
            "enum4linux-ng",
            "rpcclient",
            // LDAP
            "ldapsearch",
            // DNS
            "dig",
            "nslookup",
            "whois",
            "adidnsdump",
            // AD tools
            "bloodhound-python",
            "certipy",
            // Impacket
            "impacket-GetNPUsers",
            "impacket-GetUserSPNs",
        ],
        // Provisioned by: ansible/playbooks/ares/credential_access.yml
        // NOTE: netexec is NOT installed on this agent (only on RECON)
        "credential_access" => &[
            // SMB
            "smbclient",
            "rpcclient",
            // Password spraying
            "sprayhound",
            // Kerberoasting
            "targetedKerberoast",
            // Credential extraction
            "lsassy",
            "gMSADumper.py",
            // Impacket
            "impacket-GetNPUsers",
            "impacket-GetUserSPNs",
            "impacket-secretsdump",
        ],
        // Provisioned by: ansible/playbooks/ares/cracker.yml
        "cracker" => &["hashcat", "john"],
        // Provisioned by: ansible/playbooks/ares/acl_abuse.yml
        "acl" => &[
            // ACL abuse
            "bloodyAD",
            "pywhisker",
            // Kerberoasting
            "targetedKerberoast",
            // SMB
            "rpcclient",
            // Impacket
            "impacket-dacledit",
            // Alternate script names (some installs use .py suffix)
            "dacledit.py",
        ],
        // Provisioned by: ansible/playbooks/ares/privesc.yml
        "privesc" => &[
            // ADCS
            "certipy",
            // Credential extraction
            "lsassy",
            // CVE exploits
            "noPac.py",
            "CVE-2021-1675.py",
            // Kerberos relay toolkit (krbrelayx)
            "printerbug.py",
            "addspn.py",
            "dnstool.py",
            // Delegation & kerberos
            "KrbRelayUp",
            "pygpoabuse",
            "raiseChild.py",
            // Impacket
            "impacket-findDelegation",
            "impacket-getST",
            "impacket-getTGT",
            "impacket-rbcd",
            "impacket-addcomputer",
            "impacket-lookupsid",
            "impacket-mssqlclient",
            "impacket-ticketer",
            "impacket-secretsdump",
            "impacket-psexec",
        ],
        // Provisioned by: ansible/playbooks/ares/lateral_movement.yml
        "lateral" => &[
            // WinRM
            "evil-winrm",
            // RDP
            "xfreerdp",
            // SSH
            "sshpass",
            // SMB
            "smbclient",
            // Pivoting
            "proxychains4",
            // Pass-the-Hash
            "pth-winexe",
            "pth-smbclient",
            "pth-rpcclient",
            "pth-net",
            "pth-wmic",
            // Impacket
            "impacket-psexec",
            "impacket-wmiexec",
            "impacket-smbexec",
            "impacket-secretsdump",
        ],
        // Provisioned by: ansible/playbooks/ares/coercion.yml
        "coercion" => &[
            // Poisoning
            "responder",
            "mitm6",
            // Coercion
            "coercer",
            "petitpotam",
            "dfscoerce",
            // Kerberos relay toolkit (krbrelayx)
            "printerbug.py",
            "addspn.py",
            "dnstool.py",
            // NTLM relay
            "impacket-ntlmrelayx",
        ],
        // ToolExec workers may handle any role's tools
        _ => &[],
    }
}

/// Check which tools are available in $PATH for the given role.
///
/// Returns a map of tool_name → available (true/false).
/// Logs warnings for missing tools but does not fail.
pub async fn check_tools(role: &str) -> BTreeMap<String, bool> {
    let tools = tools_for_role(role);
    let mut inventory = BTreeMap::new();

    for &tool in tools {
        let available = is_in_path(tool).await;
        inventory.insert(tool.to_string(), available);
    }

    let available: Vec<&str> = inventory
        .iter()
        .filter(|(_, &v)| v)
        .map(|(k, _)| k.as_str())
        .collect();
    let missing: Vec<&str> = inventory
        .iter()
        .filter(|(_, &v)| !v)
        .map(|(k, _)| k.as_str())
        .collect();

    info!(
        role = role,
        available_count = available.len(),
        missing_count = missing.len(),
        "Tool availability check complete"
    );

    if !missing.is_empty() {
        warn!(
            role = role,
            missing = ?missing,
            "Some tools are not installed — tasks requiring them will fail"
        );
    }

    inventory
}

/// Publish tool inventory to Redis so the orchestrator can see what
/// each worker has available.
pub async fn publish_inventory(
    conn: &mut redis::aio::ConnectionManager,
    agent_name: &str,
    inventory: &BTreeMap<String, bool>,
) {
    use redis::AsyncCommands;

    let key = format!("ares:tools:{agent_name}");
    let available: Vec<&str> = inventory
        .iter()
        .filter(|(_, &v)| v)
        .map(|(k, _)| k.as_str())
        .collect();

    match serde_json::to_string(&available) {
        Ok(json) => {
            let result: Result<(), _> = conn.set_ex(&key, &json, 3600).await;
            if let Err(e) = result {
                warn!("Failed to publish tool inventory: {e}");
            }
        }
        Err(e) => warn!("Failed to serialize tool inventory: {e}"),
    }
}

/// Check if a binary is available in PATH using `which`.
async fn is_in_path(binary: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All known worker roles must have a non-empty tool list.
    #[test]
    fn all_roles_have_tools() {
        for role in WORKER_ROLES {
            let tools = tools_for_role(role);
            assert!(!tools.is_empty(), "Role {role} should have tools");
        }
    }

    #[test]
    fn unknown_role_returns_empty() {
        assert!(tools_for_role("nonexistent").is_empty());
    }

    /// No duplicate entries within a single role's tool list.
    #[test]
    fn no_duplicate_tools_per_role() {
        for role in WORKER_ROLES {
            let tools = tools_for_role(role);
            let mut seen = std::collections::HashSet::new();
            for tool in tools {
                assert!(
                    seen.insert(tool),
                    "Duplicate tool '{tool}' in role '{role}'"
                );
            }
        }
    }

    // ---------------------------------------------------------------
    // Per-role expected tool assertions.
    //
    // These mirror the "Installed Tools by Agent Role" tables in
    // docs/red.md. When Ansible provisioning changes, update both
    // docs/red.md and these tests.
    // ---------------------------------------------------------------

    #[test]
    fn recon_has_expected_tools() {
        let tools = tools_for_role("recon");
        for expected in &[
            "nmap",
            "netexec",
            "bloodhound-python",
            "ldapsearch",
            "enum4linux",
            "certipy",
            "impacket-GetNPUsers",
            "impacket-GetUserSPNs",
        ] {
            assert!(
                tools.contains(expected),
                "recon missing expected tool: {expected}"
            );
        }
    }

    #[test]
    fn credential_access_has_expected_tools() {
        let tools = tools_for_role("credential_access");
        for expected in &[
            "impacket-GetUserSPNs",
            "impacket-GetNPUsers",
            "impacket-secretsdump",
            "lsassy",
            "smbclient",
        ] {
            assert!(
                tools.contains(expected),
                "credential_access missing expected tool: {expected}"
            );
        }
        // netexec is NOT installed on credential_access (only on RECON)
        assert!(
            !tools.contains(&"netexec"),
            "credential_access must NOT have netexec (recon-only)"
        );
    }

    #[test]
    fn cracker_has_expected_tools() {
        let tools = tools_for_role("cracker");
        assert!(tools.contains(&"hashcat"));
        assert!(tools.contains(&"john"));
    }

    #[test]
    fn acl_has_expected_tools() {
        let tools = tools_for_role("acl");
        for expected in &["bloodyAD", "pywhisker", "impacket-dacledit", "rpcclient"] {
            assert!(
                tools.contains(expected),
                "acl missing expected tool: {expected}"
            );
        }
    }

    #[test]
    fn privesc_has_expected_tools() {
        let tools = tools_for_role("privesc");
        for expected in &[
            "certipy",
            "lsassy",
            "impacket-findDelegation",
            "impacket-getST",
            "impacket-ticketer",
            "impacket-secretsdump",
            "impacket-psexec",
            "KrbRelayUp",
        ] {
            assert!(
                tools.contains(expected),
                "privesc missing expected tool: {expected}"
            );
        }
    }

    #[test]
    fn lateral_has_expected_tools() {
        let tools = tools_for_role("lateral");
        for expected in &[
            "evil-winrm",
            "impacket-psexec",
            "impacket-wmiexec",
            "impacket-smbexec",
            "impacket-secretsdump",
            "xfreerdp",
            "sshpass",
            "proxychains4",
            "pth-winexe",
        ] {
            assert!(
                tools.contains(expected),
                "lateral missing expected tool: {expected}"
            );
        }
    }

    #[test]
    fn coercion_has_expected_tools() {
        let tools = tools_for_role("coercion");
        for expected in &[
            "responder",
            "mitm6",
            "coercer",
            "dfscoerce",
            "impacket-ntlmrelayx",
        ] {
            assert!(
                tools.contains(expected),
                "coercion missing expected tool: {expected}"
            );
        }
    }

    #[tokio::test]
    async fn which_finds_basic_commands() {
        // `which` itself should always be available
        assert!(is_in_path("which").await);
        // A nonsense binary should not be found
        assert!(!is_in_path("nonexistent_binary_xyz_12345").await);
    }
}
