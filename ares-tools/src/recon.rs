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

/// Run a multi-phase nmap TCP connect scan against a target.
///
/// Runs fast port discovery, then service version detection on discovered ports,
/// then NetBIOS enrichment for hosts missing hostnames.
///
/// Required args: `target`
/// Optional args: `ports`, `arguments`
pub async fn nmap_scan(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let ports = optional_str(args, "ports");
    let extra = optional_str(args, "arguments");

    let mut cmd = CommandBuilder::new("nmap")
        .args(["-Pn", "-sT", "-T4", "--open"])
        .timeout_secs(120);

    if let Some(extra_args) = extra {
        for a in extra_args.split_whitespace() {
            cmd = cmd.arg(a);
        }
    }

    match ports {
        Some(p) => {
            // Cap full-port scans to top 10000 to avoid timeouts
            let capped = match p.trim() {
                "-" | "0-65535" | "1-65535" => "1-10000",
                other => other,
            };
            cmd = cmd.flag("-p", capped);
        }
        None => cmd = cmd.arg("--top-ports").arg("100"),
    }

    cmd = cmd.arg(target);
    let phase1 = cmd.execute().await?;

    let mut discovered_ports: Vec<String> = Vec::new();
    for line in phase1.stdout.lines() {
        let line = line.trim();
        if line.contains("/tcp") && line.contains("open") {
            if let Some(port) = line.split('/').next() {
                discovered_ports.push(port.trim().to_string());
            }
        }
    }

    if discovered_ports.is_empty() {
        return Ok(phase1);
    }

    // Service version detection on discovered ports (-sV only, skip -sC/-O to avoid slow scans)
    let port_spec = discovered_ports.join(",");
    let cmd2 = CommandBuilder::new("nmap")
        .args(["-Pn", "-sT", "-T4", "--open", "-sV", "--reason"])
        .flag("-p", &port_spec)
        .timeout_secs(120)
        .arg(target);
    let phase2 = cmd2.execute().await?;

    // Find IPs without hostnames for NetBIOS enrichment
    let mut ips_needing_nbstat: Vec<String> = Vec::new();
    for line in phase2.stdout.lines() {
        let line = line.trim();
        if line.starts_with("Nmap scan report for") {
            let rest = line.trim_start_matches("Nmap scan report for").trim();
            // If there's no parenthesized IP, the report is just an IP (no hostname)
            if !rest.contains('(') && crate::parsers::looks_like_ip_pub(rest) {
                ips_needing_nbstat.push(rest.to_string());
            }
        }
    }

    if ips_needing_nbstat.is_empty() {
        return Ok(phase2);
    }

    // Run NetBIOS scan for hostname resolution
    let nbstat_targets = ips_needing_nbstat.join(" ");
    let nbstat_result = CommandBuilder::new("nmap")
        .args(["-Pn", "-sU", "-p", "137", "--script", "nbstat"])
        .arg(nbstat_targets)
        .timeout_secs(60)
        .execute()
        .await;

    match nbstat_result {
        Ok(nbstat) if !nbstat.stdout.is_empty() => {
            let mut combined_stdout = phase2.stdout;
            combined_stdout.push_str("\n\n--- NetBIOS Enrichment ---\n");
            combined_stdout.push_str(&nbstat.stdout);
            Ok(ToolOutput {
                stdout: combined_stdout,
                stderr: phase2.stderr,
                exit_code: phase2.exit_code,
                success: phase2.success,
            })
        }
        _ => Ok(phase2),
    }
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
/// Runs `--users` first; if no users are found, falls back to `--rid-brute`
/// (which works better for null sessions and some DC configurations).
///
/// Required args: `target`
/// Optional args: `username`, `password`, `hash`, `domain`, `null_session`
pub async fn enumerate_users(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let null_session = optional_bool(args, "null_session").unwrap_or(false);

    let build_creds = || -> Vec<String> {
        if null_session {
            vec!["-u".into(), "".into(), "-p".into(), "".into()]
        } else {
            credentials::netexec_creds(
                optional_str(args, "username"),
                optional_str(args, "password"),
                optional_str(args, "hash"),
                optional_str(args, "domain"),
            )
        }
    };

    let result = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(build_creds())
        .arg("--users")
        .timeout_secs(120)
        .execute()
        .await?;

    // Check if --users returned actual user data (look for -Username- header
    // followed by data lines, or any DOMAIN\user lines)
    let has_users = result.stdout.contains("-Username-")
        && result.stdout.lines().any(|l| {
            let l = l.trim();
            l.starts_with("SMB")
                && !l.contains("[*]")
                && !l.contains("[+]")
                && !l.contains("[-]")
                && !l.contains("-Username-")
                && l.split_whitespace().count() >= 8
        });

    if has_users {
        return Ok(result);
    }

    // --users returned no data, fall back to --rid-brute
    let rid_result = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(build_creds())
        .arg("--rid-brute")
        .timeout_secs(120)
        .execute()
        .await?;

    // If rid-brute found users, return it; otherwise return the original --users output
    // so the LLM still sees the banner/error info
    if rid_result.stdout.contains('\\') && rid_result.stdout.contains("SidType") {
        Ok(rid_result)
    } else {
        Ok(result)
    }
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
/// Required args: `target`, `domain`
/// Optional args: `username`, `password`, `base_dn`, `filter`, `attributes`
pub async fn ldap_search(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let base_dn = optional_str(args, "base_dn");
    let filter = optional_str(args, "filter");
    let attributes = optional_str(args, "attributes");

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };

    let uri = format!("ldap://{target}");

    let mut cmd = CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", &uri)
        .timeout_secs(120);

    if let (Some(u), Some(p)) = (username, password) {
        let bind_dn = format!("{u}@{domain}");
        cmd = cmd.flag("-D", bind_dn).flag("-w", p);
    }

    cmd = cmd.flag("-b", computed_base_dn);

    if let Some(f) = filter {
        cmd = cmd.arg(f);
    }

    if let Some(attrs) = attributes {
        for attr in attrs.split(|c: char| c == ',' || c.is_whitespace()) {
            let attr = attr.trim();
            if !attr.is_empty() {
                cmd = cmd.arg(attr);
            }
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
/// Required args: `target`, `domain`
/// Optional args: `username`, `password`, `base_dn`
pub async fn enumerate_domain_trusts(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let base_dn = optional_str(args, "base_dn");

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };

    let uri = format!("ldap://{target}");

    let mut cmd = CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", &uri)
        .timeout_secs(120);

    if let (Some(u), Some(p)) = (username, password) {
        let bind_dn = format!("{u}@{domain}");
        cmd = cmd.flag("-D", bind_dn).flag("-w", p);
    }

    cmd.flag("-b", computed_base_dn)
        .arg("(objectClass=trustedDomain)")
        .args([
            "cn",
            "trustDirection",
            "trustType",
            "trustAttributes",
            "flatName",
        ])
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

/// Enumerate SMB shares using Kerberos ticket authentication (smbclient.py -k).
///
/// Requires a valid TGT already in the ccache — no username/password needed.
/// Useful after obtaining a Kerberos ticket (e.g., via S4U, golden ticket, ADCS).
///
/// Required args: `target`
/// Optional args: `target_ip`
pub async fn smbclient_kerberos_shares(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let target_ip = optional_str(args, "target_ip");

    let mut cmd = CommandBuilder::new("smbclient.py")
        .args(["-k", "-no-pass"])
        .timeout_secs(180);

    if let Some(ip) = target_ip {
        cmd = cmd.flag("-target-ip", ip);
    }

    // Impacket smbclient.py uses @host to list shares
    cmd.arg(format!("@{target}")).execute().await
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
