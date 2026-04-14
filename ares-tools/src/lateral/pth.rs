//! Pass-the-Hash tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Build a pth-style credential string: `domain/username%hash` or `username%hash`.
fn pth_cred_string(domain: Option<&str>, username: &str, hash: &str) -> String {
    match domain {
        Some(d) if !d.is_empty() => format!("{d}/{username}%{hash}"),
        _ => format!("{username}%{hash}"),
    }
}

/// Execute a command on a remote host via pth-winexe.
///
/// Required args: `target`, `username`, `hash`
/// Optional args: `domain`, `command`
pub async fn pth_winexe(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let hash = required_str(args, "hash")?;
    let domain = optional_str(args, "domain");
    let command = optional_str(args, "command").unwrap_or("cmd.exe /c whoami");

    let cred = pth_cred_string(domain, username, hash);

    CommandBuilder::new("pth-winexe")
        .flag("-U", &cred)
        .arg(format!("//{target}"))
        .arg(command)
        .timeout_secs(120)
        .execute()
        .await
}

/// Access an SMB share on a remote host via pth-smbclient.
///
/// Required args: `target`, `username`, `hash`
/// Optional args: `domain`, `share`, `command`
pub async fn pth_smbclient(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let hash = required_str(args, "hash")?;
    let domain = optional_str(args, "domain");
    let share = optional_str(args, "share").unwrap_or("C$");
    let command = optional_str(args, "command").unwrap_or("dir");

    let cred = pth_cred_string(domain, username, hash);

    CommandBuilder::new("pth-smbclient")
        .arg(format!("//{target}/{share}"))
        .flag("-U", &cred)
        .flag("-c", command)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute an RPC command on a remote host via pth-rpcclient.
///
/// Required args: `target`, `username`, `hash`
/// Optional args: `domain`, `command`
pub async fn pth_rpcclient(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let hash = required_str(args, "hash")?;
    let domain = optional_str(args, "domain");
    let command = optional_str(args, "command").unwrap_or("getusername");

    let cred = pth_cred_string(domain, username, hash);

    CommandBuilder::new("pth-rpcclient")
        .flag("-U", &cred)
        .arg(target)
        .flag("-c", command)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a WMI query on a remote host via pth-wmis.
///
/// Required args: `target`, `username`, `hash`
/// Optional args: `domain`, `query`
pub async fn pth_wmic(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let hash = required_str(args, "hash")?;
    let domain = optional_str(args, "domain");
    let query = optional_str(args, "query").unwrap_or("SELECT * FROM Win32_OperatingSystem");

    let cred = pth_cred_string(domain, username, hash);

    CommandBuilder::new("pth-wmis")
        .flag("-U", &cred)
        .arg(format!("//{target}"))
        .arg(query)
        .timeout_secs(120)
        .execute()
        .await
}
