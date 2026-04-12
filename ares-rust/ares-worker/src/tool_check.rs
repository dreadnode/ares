//! Tool availability check at worker startup.
//!
//! Probes which external binaries are installed so we can log warnings
//! for missing tools and optionally report the inventory to the orchestrator
//! via Redis.

use std::collections::BTreeMap;

use tracing::{info, warn};

/// Tools needed by each worker role.
///
/// Only lists tools that are actually installed in each role's container
/// image. Tools are checked via `which` at startup.
fn tools_for_role(role: &str) -> &'static [&'static str] {
    match role {
        "recon" => &[
            "nmap",
            "netexec",
            "bloodhound-python",
            "ldapsearch",
            "rpcclient",
            "dig",
            "adidnsdump",
            "impacket-lookupsid",
        ],
        "credential_access" => &[
            "impacket-GetUserSPNs",
            "impacket-GetNPUsers",
            "impacket-secretsdump",
            "impacket-lookupsid",
            "lsassy",
        ],
        "cracker" => &["hashcat", "john"],
        "lateral" => &[
            "impacket-psexec",
            "impacket-wmiexec",
            "impacket-smbexec",
            "impacket-secretsdump",
            "impacket-mssqlclient",
            "impacket-getTGT",
            "impacket-getST",
            "evil-winrm",
            "sshpass",
            "xfreerdp",
            "pth-winexe",
            "pth-smbclient",
            "pth-rpcclient",
            "pth-wmis",
        ],
        "privesc" => &[
            "certipy",
            "impacket-findDelegation",
            "impacket-addcomputer",
            "impacket-rbcd",
            "impacket-getST",
            "impacket-ticketer",
            "impacket-secretsdump",
            "impacket-lookupsid",
            "impacket-mssqlclient",
            "raiseChild.py",
            "lsassy",
        ],
        "acl" => &[
            "bloodyAD",
            "dacledit.py",
            "impacket-secretsdump",
            "impacket-dacledit",
            "pywhisker.py",
            "targetedKerberoast.py",
        ],
        "coercion" => &[
            "responder",
            "impacket-ntlmrelayx",
            "coercer",
            "mitm6",
            "dfscoerce",
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

    #[test]
    fn all_roles_have_tools() {
        for role in &[
            "recon",
            "credential_access",
            "cracker",
            "lateral",
            "privesc",
            "acl",
            "coercion",
        ] {
            let tools = tools_for_role(role);
            assert!(!tools.is_empty(), "Role {role} should have tools");
        }
    }

    #[test]
    fn unknown_role_returns_empty() {
        assert!(tools_for_role("nonexistent").is_empty());
    }

    #[tokio::test]
    async fn which_finds_basic_commands() {
        // `which` itself should always be available
        assert!(is_in_path("which").await);
        // A nonsense binary should not be found
        assert!(!is_in_path("nonexistent_binary_xyz_12345").await);
    }
}
