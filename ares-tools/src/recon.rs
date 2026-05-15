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
/// Optional args: `username`, `password`, `bind_domain`, `base_dn`, `filter`, `attributes`
///
/// `domain` controls the base DN (the partition being queried).
/// `bind_domain` (optional) overrides the domain used in the bind DN
/// (`user@bind_domain`). Use this when authenticating with a credential
/// from a different domain than the one being searched — e.g. querying
/// a parent DC with a child-domain credential. Defaults to `domain`.
pub async fn ldap_search(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let bind_domain = optional_str(args, "bind_domain");
    let base_dn = optional_str(args, "base_dn");
    let filter = optional_str(args, "filter");
    let attributes = optional_str(args, "attributes");
    let ticket_path = optional_str(args, "ticket_path");

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };

    let uri = format!("ldap://{target}");

    let mut cmd = CommandBuilder::new("ldapsearch")
        .flag("-H", &uri)
        .timeout_secs(120);

    if let Some(ccache) = ticket_path {
        // Kerberos GSSAPI bind via cached ticket. Caller must ensure `target`
        // is an FQDN so ldapsearch can derive the ldap/<host>@<REALM> SPN.
        cmd = cmd.env("KRB5CCNAME", ccache).arg("-Y").arg("GSSAPI");
    } else if let (Some(u), Some(p)) = (username, password) {
        let auth_domain = bind_domain.unwrap_or(domain);
        let bind_dn = format!("{u}@{auth_domain}");
        cmd = cmd.arg("-x").flag("-D", bind_dn).flag("-w", p);
    } else {
        cmd = cmd.arg("-x");
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
/// Optional args: `username`, `password`, `domain`, `null_session`, `hash`
pub async fn rpcclient_command(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let command = required_str(args, "command")?;
    let null_session = optional_bool(args, "null_session").unwrap_or(false);
    let hash = optional_str(args, "hash");

    let mut cmd = CommandBuilder::new("rpcclient").timeout_secs(120);

    if null_session {
        cmd = cmd.args(["-U", "", "-N"]);
    } else if let Some(ntlm_hash) = hash {
        // Pass-the-hash: use --pw-nt-hash and supply the NTLM hash as the password.
        // rpcclient --pw-nt-hash expects only the NT hash (32 hex chars), not LM:NT.
        // If the hash is in LM:NT format (e.g. "aad3b435...:2e993405..."), extract
        // just the NT part (after the colon).
        let nt_hash = if ntlm_hash.contains(':') {
            ntlm_hash.rsplit(':').next().unwrap_or(ntlm_hash)
        } else {
            ntlm_hash
        };
        let domain = optional_str(args, "domain");
        let username = optional_str(args, "username").unwrap_or("Administrator");
        let user_spec = match domain {
            Some(d) => format!("{d}/{username}%{nt_hash}"),
            None => format!("{username}%{nt_hash}"),
        };
        cmd = cmd.flag("-U", user_spec).arg("--pw-nt-hash");
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
/// Optional args: `username`, `password`, `hash`, `base_dn`
///
/// When `hash` is provided (NTLM format `lm:nt`), uses `netexec ldap` for
/// pass-the-hash authentication instead of `ldapsearch` simple bind.
pub async fn enumerate_domain_trusts(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let base_dn = optional_str(args, "base_dn");
    // Cross-realm auth: orchestrator sets `bind_domain` to the cred's actual
    // realm when the credential lives in a different forest from the search
    // target (e.g. cred is `user@contoso.local` querying `fabrikam.local` DC).
    // Without this, the bind DN gets the target realm and the foreign DC
    // rejects with `invalidCredentials`. Falls back to `domain` when absent.
    let bind_domain = optional_str(args, "bind_domain").unwrap_or(domain);

    // Hash-based auth: use impacket LDAP client with pass-the-hash (NTLM)
    if let (Some(u), Some(h)) = (username, hash) {
        let computed_base_dn = match base_dn {
            Some(dn) => dn.to_string(),
            None => domain_to_base_dn(domain),
        };
        // Strip LM hash prefix if present (e.g. "aad3b435b51404ee:nthash" → "nthash")
        let nt_hash = if h.contains(':') {
            h.rsplit(':').next().unwrap_or(h)
        } else {
            h
        };
        // Use impacket's LDAP client for pass-the-hash authentication.
        // Output mimics ldapsearch format so the trust parser can handle it.
        //
        // `securityIdentifier` is requested + decoded inline so the parser
        // gets it in canonical `S-1-5-21-X-Y-Z` form (LDAP returns it as a
        // binary SID blob). This is what `auto_trust_follow` reads to
        // satisfy the parent-SID gate on child→parent forge dispatch
        // without a separate SAMR lookup against the foreign DC — that
        // lookup is the load-bearing blocker on hardened 2019+ parent DCs
        // where cross-realm NTLM SAMR is rejected and null-session
        // lsaquery is disabled by default.
        let ldap_query = format!(
            r#"python3 -c "
from impacket.ldap import ldap as ldap_mod
from impacket.ldap.ldaptypes import LDAP_SID
conn = ldap_mod.LDAPConnection('ldap://{target}', '{base_dn}', '{target}')
conn.login('{u}', '', '{bind_domain}', lmhash='', nthash='{nt_hash}')
sc = ldap_mod.SimplePagedResultsControl(size=1000)
resp = conn.search(searchFilter='(objectClass=trustedDomain)', attributes=['cn','trustDirection','trustType','trustAttributes','flatName','securityIdentifier'], searchControls=[sc])
for item in resp:
    try:
        dn = str(item['objectName'])
        if not dn:
            continue
        print(f'dn: {{dn}}')
        for attr in item['attributes']:
            name = str(attr['type'])
            for val in attr['vals']:
                if name == 'securityIdentifier':
                    try:
                        sid_obj = LDAP_SID(bytes(val))
                        print(f'securityIdentifier: {{sid_obj.formatCanonical()}}')
                    except Exception:
                        pass
                else:
                    print(f'{{name}}: {{val}}')
        print()
    except Exception:
        pass
"
"#,
            target = target,
            bind_domain = bind_domain,
            u = u,
            nt_hash = nt_hash,
            base_dn = computed_base_dn,
        );
        return CommandBuilder::new("bash")
            .args(["-c", &ldap_query])
            .timeout_secs(120)
            .execute()
            .await;
    }

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
        let bind_dn = format!("{u}@{bind_domain}");
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
            // securityIdentifier comes back as base64 (binary SID); the
            // parser decodes it. Required for child→parent forge — see
            // the comment block above the impacket variant.
            "securityIdentifier",
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

/// Enumerate ACL attack paths via LDAP nTSecurityDescriptor queries.
///
/// Queries all user, group, and computer objects requesting nTSecurityDescriptor,
/// sAMAccountName, objectClass, and objectSid. The binary SD data is parsed
/// by the ntsd parser to identify dangerous ACEs.
///
/// Required args: `target`, `domain`
/// Optional args: `username`, `password`, `bind_domain`, `hash`
pub async fn ldap_acl_enumeration(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let bind_domain = optional_str(args, "bind_domain");
    let hash = optional_str(args, "hash");
    let ticket_path = optional_str(args, "ticket_path");

    let base_dn = domain_to_base_dn(domain);
    let uri = format!("ldap://{target}");

    // Kerberos GSSAPI bind for cross-forest LDAP enumeration. Takes precedence
    // over hash/password — when a forged inter-realm ticket is present we MUST
    // use it, otherwise simple bind with source-realm cred fails 0x52e.
    if let Some(ccache) = ticket_path {
        return CommandBuilder::new("ldapsearch")
            .env("KRB5CCNAME", ccache)
            .flag("-H", &uri)
            .arg("-Y")
            .arg("GSSAPI")
            .timeout_secs(300)
            .flag("-b", &base_dn)
            .args(["-E", "1.2.840.113556.1.4.801=::MAMCAQQ="])
            .arg("(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectCategory=groupPolicyContainer))")
            .args([
                "sAMAccountName",
                "objectClass",
                "objectSid",
                "nTSecurityDescriptor",
                // GPO containers carry their identity in `cn` (the
                // `{GUID}` directory name) and `displayName` (the friendly
                // name like "Default Domain Policy") — neither has a
                // sAMAccountName. The parser uses `cn` to construct the
                // gpo_<right>_<GUID> vuln_id.
                "cn",
                "displayName",
            ])
            .execute()
            .await;
    }

    // If hash is provided, use impacket LDAP for pass-the-hash
    if let (Some(u), Some(h)) = (username, hash) {
        let nt_hash = if h.contains(':') {
            h.rsplit(':').next().unwrap_or(h)
        } else {
            h
        };
        let ldap_query = format!(
            r#"python3 -c "
import base64
from impacket.ldap import ldap as ldap_mod
conn = ldap_mod.LDAPConnection('ldap://{target}', '{base_dn}', '{target}')
conn.login('{u}', '', '{domain}', lmhash='', nthash='{nt_hash}')
sc = ldap_mod.SimplePagedResultsControl(size=1000)
resp = conn.search(
    searchFilter='(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectCategory=groupPolicyContainer))',
    attributes=['sAMAccountName','objectClass','objectSid','nTSecurityDescriptor','cn','displayName'],
    searchControls=[sc],
    sizeLimit=0,
)
for item in resp:
    try:
        dn = str(item['objectName'])
        if not dn:
            continue
        print(f'dn: {{dn}}')
        for attr in item['attributes']:
            name = str(attr['type'])
            for val in attr['vals']:
                if name == 'nTSecurityDescriptor':
                    b = bytes(val)
                    print(f'nTSecurityDescriptor:: {{base64.b64encode(b).decode()}}')
                elif name == 'objectSid':
                    b = bytes(val)
                    print(f'objectSid:: {{base64.b64encode(b).decode()}}')
                else:
                    print(f'{{name}}: {{val}}')
        print()
    except Exception:
        pass
"
"#,
            target = target,
            domain = domain,
            u = u,
            nt_hash = nt_hash,
            base_dn = base_dn,
        );
        return CommandBuilder::new("bash")
            .args(["-c", &ldap_query])
            .timeout_secs(300)
            .execute()
            .await;
    }

    // Password-based: use ldapsearch with LDAP_SERVER_SD_FLAGS_OID control
    // to request DACL (value 4) in the nTSecurityDescriptor attribute
    let mut cmd = CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", &uri)
        .timeout_secs(300);

    if let (Some(u), Some(p)) = (username, password) {
        let auth_domain = bind_domain.unwrap_or(domain);
        let bind_dn = format!("{u}@{auth_domain}");
        cmd = cmd.flag("-D", bind_dn).flag("-w", p);
    }

    cmd = cmd
        .flag("-b", &base_dn)
        // Request DACL only via SD_FLAGS control (0x04 = DACL)
        // BER: SEQUENCE { INTEGER 4 } = 30 03 02 01 04 → base64 MAMCAQQ=
        .args(["-E", "1.2.840.113556.1.4.801=::MAMCAQQ="])
        .arg("(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectCategory=groupPolicyContainer))")
        .args([
            "sAMAccountName",
            "objectClass",
            "objectSid",
            "nTSecurityDescriptor",
            "cn",
            "displayName",
        ]);

    cmd.execute().await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_to_base_dn_simple() {
        assert_eq!(domain_to_base_dn("contoso.local"), "DC=contoso,DC=local");
    }

    #[test]
    fn domain_to_base_dn_nested() {
        assert_eq!(
            domain_to_base_dn("child.contoso.local"),
            "DC=child,DC=contoso,DC=local"
        );
    }

    #[test]
    fn domain_to_base_dn_single() {
        assert_eq!(domain_to_base_dn("local"), "DC=local");
    }

    // --- mock executor tests: exercise full CommandBuilder code paths ---

    use crate::executor::mock;
    use serde_json::json;

    #[tokio::test]
    async fn nmap_scan_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1"});
        let result = nmap_scan(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn nmap_scan_with_ports() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "ports": "80,443"});
        let result = nmap_scan(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn nmap_scan_caps_full_port_range() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "ports": "-"});
        let result = nmap_scan(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn nmap_scan_with_extra_args() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "arguments": "-sV --reason"});
        let result = nmap_scan(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn nmap_scan_phase2_on_discovered_ports() {
        // Phase 1 returns discovered ports, triggering phase 2
        mock::push(mock::success_with_stdout(
            "80/tcp  open  http\n443/tcp open  https\n",
        ));
        mock::push(mock::success_with_stdout(
            "Nmap scan report for 192.168.58.1\n",
        ));
        let args = json!({"target": "192.168.58.1"});
        let result = nmap_scan(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn smb_sweep_builds_command() {
        mock::push(mock::success());
        let args = json!({"targets": "192.168.58.0/24"});
        let result = smb_sweep(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn smb_sweep_missing_targets() {
        let args = json!({});
        assert!(smb_sweep(&args).await.is_err());
    }

    #[tokio::test]
    async fn enumerate_users_builds_command() {
        mock::push(mock::success());
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "username": "admin", "password": "P@ss", "domain": "contoso.local"});
        let result = enumerate_users(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_users_null_session() {
        mock::push(mock::success());
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "null_session": true});
        let result = enumerate_users(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_shares_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "username": "admin", "password": "P@ss"});
        let result = enumerate_shares(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn smb_signing_check_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1"});
        let result = smb_signing_check(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_bloodhound_builds_command() {
        mock::push(mock::success());
        let args = json!({"domain": "contoso.local", "username": "admin", "password": "P@ss", "dc_ip": "192.168.58.1"});
        let result = run_bloodhound(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ldap_search_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "domain": "contoso.local"});
        let result = ldap_search(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ldap_search_with_auth_and_filter() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss",
            "filter": "(objectClass=user)",
            "attributes": "cn,sAMAccountName"
        });
        let result = ldap_search(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ldap_search_with_custom_base_dn() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "base_dn": "OU=Users,DC=contoso,DC=local"
        });
        let result = ldap_search(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rpcclient_command_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "command": "enumdomusers"});
        let result = rpcclient_command(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rpcclient_null_session() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "command": "srvinfo", "null_session": true});
        let result = rpcclient_command(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rpcclient_with_domain_creds() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1",
            "command": "getusername",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss"
        });
        let result = rpcclient_command(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn dig_query_builds_command() {
        mock::push(mock::success());
        let args = json!({"query": "contoso.local"});
        let result = dig_query(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn dig_query_with_server_and_type() {
        mock::push(mock::success());
        let args =
            json!({"query": "contoso.local", "server": "192.168.58.1", "record_type": "SRV"});
        let result = dig_query(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_domain_trusts_ldap() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss"
        });
        let result = enumerate_domain_trusts(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_domain_trusts_pth() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435:aabbccdd"
        });
        let result = enumerate_domain_trusts(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_domain_trusts_cross_realm_bind_domain() {
        // Cross-forest: cred is for contoso.local but we're querying
        // fabrikam.local DC. The tool must bind with the cred's realm,
        // not the target realm.
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.20",
            "domain": "fabrikam.local",
            "bind_domain": "contoso.local",
            "username": "admin",
            "password": "P@ss"
        });
        let result = enumerate_domain_trusts(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_domain_trusts_cross_realm_pth_bind_domain() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.20",
            "domain": "fabrikam.local",
            "bind_domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435:aabbccdd"
        });
        let result = enumerate_domain_trusts(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_rdp_reachability_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1"});
        let result = check_rdp_reachability(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_winrm_reachability_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1"});
        let result = check_winrm_reachability(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn zerologon_check_builds_command() {
        mock::push(mock::success());
        let args = json!({"dc_ip": "192.168.58.1"});
        let result = zerologon_check(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn adidnsdump_builds_command() {
        mock::push(mock::success());
        let args = json!({"domain": "contoso.local", "username": "admin", "password": "P@ss", "dc_ip": "192.168.58.1"});
        let result = adidnsdump(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn save_users_to_file_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "username": "admin", "password": "P@ss"});
        let result = save_users_to_file(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn smbclient_kerberos_shares_builds_command() {
        mock::push(mock::success());
        let args = json!({"target": "dc01.contoso.local"});
        let result = smbclient_kerberos_shares(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn smbclient_kerberos_shares_with_target_ip() {
        mock::push(mock::success());
        let args = json!({"target": "dc01.contoso.local", "target_ip": "192.168.58.1"});
        let result = smbclient_kerberos_shares(&args).await;
        assert!(result.is_ok());
    }
}
