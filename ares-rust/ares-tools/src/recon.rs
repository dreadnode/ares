//! Reconnaissance tool executors.
//!
//! Each function accepts a JSON `Value` containing the tool arguments and
//! returns a `ToolOutput` produced by running a CLI subprocess via
//! `CommandBuilder`.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a domain name to an LDAP base DN.
///
/// e.g. `"contoso.local"` -> `"DC=contoso,DC=local"`
fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// Run an nmap TCP connect scan against a target.
///
/// Required args: `target`
/// Optional args: `ports`, `arguments`
pub async fn nmap_scan(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let ports = optional_str(args, "ports");
    let extra = optional_str(args, "arguments");

    let mut cmd = CommandBuilder::new("nmap")
        .args(["-Pn", "-sT", "-T4", "--open"])
        .timeout_secs(300);

    // Append any caller-supplied extra arguments first.
    if let Some(extra_args) = extra {
        for a in extra_args.split_whitespace() {
            cmd = cmd.arg(a);
        }
    }

    // Port specification — default to top-100 if nothing was provided.
    match ports {
        Some(p) => cmd = cmd.flag("-p", p),
        None => cmd = cmd.arg("--top-ports").arg("100"),
    }

    cmd = cmd.arg(target);
    cmd.execute().await
}

/// Sweep a subnet/range with netexec SMB to discover live hosts.
///
/// Required args: `targets`
pub async fn smb_sweep(args: &Value) -> Result<ToolOutput> {
    let targets = required_str(args, "targets")?;

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(targets)
        .timeout_secs(120)
        .execute()
        .await
}

/// Enumerate domain users via netexec SMB.
///
/// Required args: `target`
/// Optional args: `username`, `password`, `hash`, `domain`, `null_session`
pub async fn enumerate_users(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let null_session = optional_bool(args, "null_session").unwrap_or(false);

    let mut cmd = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .timeout_secs(120);

    if null_session {
        cmd = cmd.args(["-u", "", "-p", ""]);
    } else {
        let creds = credentials::netexec_creds(
            optional_str(args, "username"),
            optional_str(args, "password"),
            optional_str(args, "hash"),
            optional_str(args, "domain"),
        );
        cmd = cmd.args(creds);
    }

    cmd = cmd.arg("--users");
    cmd.execute().await
}

/// Enumerate SMB shares on a target.
///
/// Required args: `target`, `username`, `password`
/// Optional args: `hash`, `domain`
pub async fn enumerate_shares(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;

    let creds = credentials::netexec_creds(
        optional_str(args, "username"),
        optional_str(args, "password"),
        optional_str(args, "hash"),
        optional_str(args, "domain"),
    );

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(creds)
        .arg("--shares")
        .timeout_secs(120)
        .execute()
        .await
}

/// Check SMB signing configuration via nmap script.
///
/// Required args: `target`
pub async fn smb_signing_check(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;

    CommandBuilder::new("nmap")
        .args(["-Pn", "-p", "445", "--script", "smb2-security-mode"])
        .arg(target)
        .timeout_secs(60)
        .execute()
        .await
}

/// Collect BloodHound data via bloodhound-python.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`
pub async fn run_bloodhound(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    CommandBuilder::new("bloodhound-python")
        .flag("-d", domain)
        .flag("-u", username)
        .flag("-p", password)
        .flag("-ns", dc_ip)
        .flag("-c", "All")
        .timeout_secs(300)
        .execute()
        .await
}

/// Run an LDAP search query against a target.
///
/// Required args: `target`, `domain`, `username`, `password`
/// Optional args: `base_dn`, `filter`, `attributes`
pub async fn ldap_search(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let base_dn = optional_str(args, "base_dn");
    let filter = optional_str(args, "filter");
    let attributes = optional_str(args, "attributes");

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };

    let bind_dn = format!("{username}@{domain}");
    let uri = format!("ldap://{target}");

    let mut cmd = CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", uri)
        .flag("-D", bind_dn)
        .flag("-w", password)
        .flag("-b", computed_base_dn)
        .timeout_secs(120);

    if let Some(f) = filter {
        cmd = cmd.arg(f);
    }

    if let Some(attrs) = attributes {
        for attr in attrs.split_whitespace() {
            cmd = cmd.arg(attr);
        }
    }

    cmd.execute().await
}

/// Execute an rpcclient command against a target.
///
/// Required args: `target`, `command`
/// Optional args: `username`, `password`, `domain`, `null_session`
pub async fn rpcclient_command(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let command = required_str(args, "command")?;
    let null_session = optional_bool(args, "null_session").unwrap_or(false);

    let mut cmd = CommandBuilder::new("rpcclient").timeout_secs(120);

    if null_session {
        cmd = cmd.args(["-U", "", "-N"]);
    } else {
        let domain = optional_str(args, "domain");
        let username = optional_str(args, "username").unwrap_or("");
        let password = optional_str(args, "password").unwrap_or("");

        let user_spec = match domain {
            Some(d) => format!("{d}/{username}%{password}"),
            None => format!("{username}%{password}"),
        };
        cmd = cmd.flag("-U", user_spec);
    }

    cmd = cmd.arg(target).flag("-c", command);
    cmd.execute().await
}

/// Perform a DNS lookup with dig.
///
/// Required args: `query`
/// Optional args: `server`, `record_type`
pub async fn dig_query(args: &Value) -> Result<ToolOutput> {
    let query = required_str(args, "query")?;
    let server = optional_str(args, "server");
    let record_type = optional_str(args, "record_type");

    let mut cmd = CommandBuilder::new("dig").timeout_secs(30);

    if let Some(srv) = server {
        cmd = cmd.arg(format!("@{srv}"));
    }

    cmd = cmd.arg(query);

    if let Some(rt) = record_type {
        cmd = cmd.arg(rt);
    }

    cmd.execute().await
}

/// Enumerate Active Directory domain trusts via LDAP.
///
/// Required args: `target`, `domain`, `username`, `password`
/// Optional args: `base_dn`
pub async fn enumerate_domain_trusts(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let base_dn = optional_str(args, "base_dn");

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };

    let bind_dn = format!("{username}@{domain}");
    let uri = format!("ldap://{target}");

    CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", uri)
        .flag("-D", bind_dn)
        .flag("-w", password)
        .flag("-b", computed_base_dn)
        .arg("(objectClass=trustedDomain)")
        .args([
            "cn",
            "trustDirection",
            "trustType",
            "trustAttributes",
            "flatName",
        ])
        .timeout_secs(120)
        .execute()
        .await
}

/// Check if RDP (port 3389) is reachable on a target.
///
/// Required args: `target`
pub async fn check_rdp_reachability(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;

    CommandBuilder::new("nmap")
        .args(["-Pn", "-p", "3389"])
        .arg(target)
        .timeout_secs(30)
        .execute()
        .await
}

/// Check if WinRM (ports 5985/5986) is reachable on a target.
///
/// Required args: `target`
pub async fn check_winrm_reachability(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;

    CommandBuilder::new("nmap")
        .args(["-Pn", "-p", "5985,5986"])
        .arg(target)
        .timeout_secs(30)
        .execute()
        .await
}

/// Check for ZeroLogon vulnerability via netexec module.
///
/// Required args: `dc_ip`
pub async fn zerologon_check(args: &Value) -> Result<ToolOutput> {
    let dc_ip = required_str(args, "dc_ip")?;

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(dc_ip)
        .args(["-u", "", "-p", ""])
        .args(["-M", "zerologon"])
        .timeout_secs(60)
        .execute()
        .await
}

/// Dump Active Directory Integrated DNS records.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`
pub async fn adidnsdump(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_spec = format!("{domain}\\{username}");

    CommandBuilder::new("adidnsdump")
        .flag("-u", user_spec)
        .flag("-p", password)
        .arg(dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

/// Enumerate users via netexec and save output (same as enumerate_users,
/// intended for downstream file-based processing).
///
/// Required args: `target`, `username`, `password`
/// Optional args: `hash`, `domain`
pub async fn save_users_to_file(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;

    let creds = credentials::netexec_creds(
        optional_str(args, "username"),
        optional_str(args, "password"),
        optional_str(args, "hash"),
        optional_str(args, "domain"),
    );

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(creds)
        .arg("--users")
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

    #[test]
    fn test_domain_to_base_dn_simple() {
        assert_eq!(domain_to_base_dn("contoso.local"), "DC=contoso,DC=local");
    }

    #[test]
    fn test_domain_to_base_dn_nested() {
        assert_eq!(
            domain_to_base_dn("north.contoso.local"),
            "DC=north,DC=contoso,DC=local"
        );
    }

    #[test]
    fn test_domain_to_base_dn_single() {
        assert_eq!(domain_to_base_dn("local"), "DC=local");
    }
}
