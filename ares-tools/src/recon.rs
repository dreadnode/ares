//! Reconnaissance tool executors.
//!
//! Each function accepts a JSON `Value` containing the tool arguments and
//! returns a `ToolOutput` produced by running a CLI subprocess via
//! `CommandBuilder`.

use anyhow::{Context, Result};
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
            cmd = cmd.flag_visible("-p", capped);
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
        .flag_visible("-p", &port_spec)
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
        .args(["-Pn", "-sU"])
        .flag_visible("-p", "137")
        .args(["--script", "nbstat"])
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
    // followed by data lines, or any DOMAIN\user lines). A data row is
    // `SMB IP PORT HOST USER <PW-set> BADPW [DESC..]`; the PW-set column is
    // one token ("<never>") or two ("DATE TIME"), so a real row can be as
    // short as 7 fields. Match the parser's `>= 6` floor here — a rigid
    // `>= 8` gate wrongly declared "no users" for DCs whose accounts have
    // never-set passwords / empty descriptions and forced a needless
    // rid-brute fallback.
    let has_users = result.stdout.contains("-Username-")
        && result.stdout.lines().any(|l| {
            let l = l.trim();
            l.starts_with("SMB")
                && !l.contains("[*]")
                && !l.contains("[+]")
                && !l.contains("[-]")
                && !l.contains("-Username-")
                && l.split_whitespace().count() >= 6
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
        .arg("-Pn")
        .flag_visible("-p", "445")
        .args(["--script", "smb2-security-mode"])
        .arg(target)
        .timeout_secs(60)
        .execute()
        .await
}

/// Temp-directory prefix for BloodHound collector output.
const BLOODHOUND_DIR_PREFIX: &str = "ares-bloodhound-";

/// How long a collector output directory is kept before it is reclaimed.
/// Comfortably longer than the collector's own 300s timeout plus the parse
/// that follows, so pruning can never race a concurrent collection.
const BLOODHOUND_DIR_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(2 * 60 * 60);

/// Reclaim BloodHound output directories left by earlier collections.
///
/// The parser reads these after the tool returns, so the tool cannot delete
/// its own; without this every collection leaks its JSON onto the worker's
/// disk for the life of the pod.
fn prune_stale_bloodhound_dirs() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_ours = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(BLOODHOUND_DIR_PREFIX));
        if !is_ours || !path.is_dir() {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > BLOODHOUND_DIR_MAX_AGE);
        if stale {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// Collect BloodHound data via bloodhound-python.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`
///
/// bloodhound-python writes its `*_users.json` / `*_groups.json` /
/// `*_computers.json` / `*_domains.json` documents into the process working
/// directory. The run is pinned to a private directory and the path echoed as
/// [`crate::parsers::BLOODHOUND_OUTPUT_DIR_MARKER`] so
/// [`crate::parsers::parse_bloodhound_collection`] can turn the ACEs into ACL
/// edges instead of the collection being write-only.
pub async fn run_bloodhound(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    prune_stale_bloodhound_dirs();

    let output_dir = std::env::temp_dir().join(format!(
        "{BLOODHOUND_DIR_PREFIX}{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("creating BloodHound output dir {}", output_dir.display()))?;

    let mut output = CommandBuilder::new("bloodhound-python")
        .flag("-d", domain)
        .flag("-u", username)
        .flag("-p", password)
        .flag("-ns", dc_ip)
        .flag("-c", "All")
        .current_dir(&output_dir)
        .timeout_secs(300)
        .execute()
        .await?;

    output.stdout.push_str(&format!(
        "\n{}{}\n",
        crate::parsers::BLOODHOUND_OUTPUT_DIR_MARKER,
        output_dir.display()
    ));
    Ok(output)
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
    build_ldap_search(args)?.execute().await
}

/// Simple paged results control. Active Directory caps an unpaged search at
/// `MaxPageSize` (1000 by default) and returns `Size limit exceeded` instead
/// of the rest, so a roster or ACL sweep of any real domain silently returns a
/// prefix of the directory. The impacket branches of these same tools already
/// page via `SimplePagedResultsControl`; the `ldapsearch` branches did not.
const LDAP_PAGED_RESULTS: &[&str] = &["-E", "pr=1000/noprompt"];

/// Build the `ldapsearch` invocation for [`ldap_search`].
///
/// Exposed so the resolver-side Bug B contract test can verify the
/// `ticket_path` arg actually surfaces as `KRB5CCNAME` in the spawned
/// subprocess (and that an injected `password` actually reaches `-w`).
/// Without that pin, a future refactor could drop the cred read on the
/// tool side while leaving the resolver-side allowlist intact —
/// silently dropping every cross-forest LDAP enumeration.
#[doc(hidden)]
pub fn build_ldap_search(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let bind_domain = optional_str(args, "bind_domain");
    let base_dn = optional_str(args, "base_dn");
    let filter = optional_str(args, "filter");
    let attributes = optional_str(args, "attributes");
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };

    let uri = format!("ldap://{target}");

    let mut cmd = CommandBuilder::new("ldapsearch")
        .flag_visible("-H", &uri)
        .timeout_secs(120)
        .args(LDAP_PAGED_RESULTS.iter().copied());

    if let Some(ccache) = ticket_path {
        // Kerberos GSSAPI bind via cached ticket — preferred over simple
        // bind when both are available because forged inter-realm tickets
        // only authenticate via GSSAPI. Caller must ensure `target` is an
        // FQDN so ldapsearch can derive the ldap/<host>@<REALM> SPN.
        //
        // KRB5_CONFIG points at the per-ccache shim written by
        // create_inter_realm_ticket so MIT libkrb5 can resolve the target
        // domain to its realm; without it MIT falls back to the system
        // default_realm and misses the cached service ticket.
        cmd = cmd
            .env("KRB5CCNAME", ccache)
            .env("KRB5_CONFIG", format!("{ccache}.krb5.conf:/etc/krb5.conf"))
            .arg("-Y")
            .arg("GSSAPI");
    } else if let (Some(u), Some(p)) = (username, password) {
        let auth_domain = bind_domain.unwrap_or(domain);
        let bind_dn = format!("{u}@{auth_domain}");
        cmd = cmd.arg("-x").flag("-D", bind_dn).flag("-w", p);
    } else if let Some(u) = username {
        anyhow::bail!(
            "ldap_search was told to bind as '{u}' but carries neither a password nor a \
             ticket_path. Refusing to substitute an anonymous bind: its result would be \
             recorded as if '{u}' had queried the directory."
        );
    } else {
        cmd = cmd.arg("-x");
    }

    cmd = cmd.flag("-b", computed_base_dn);

    if let Some(f) = filter {
        cmd = cmd.arg(f);
    }

    if let Some(attrs) = attributes {
        // Always request objectClass alongside whatever the caller asked for.
        // The orchestrator's user extractor drops group/computer records by
        // matching an `objectClass: group` line; if the LLM enumerates groups
        // with `attributes=sAMAccountName,cn` and omits objectClass, every
        // group's sAMAccountName leaks in as a truncated `ldap_extraction`
        // user ("Backup Operators" -> "Backup"). With no explicit attribute
        // list ldapsearch returns them all (objectClass included), so this
        // only matters when the caller narrows the request.
        let mut requested: Vec<&str> = attrs
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .collect();
        if !requested
            .iter()
            .any(|a| a.eq_ignore_ascii_case("objectClass"))
        {
            requested.push("objectClass");
        }
        if !requested.iter().any(|a| a.eq_ignore_ascii_case("memberOf")) {
            requested.push("memberOf");
        }
        for attr in requested {
            cmd = cmd.arg(attr);
        }
    }

    Ok(cmd)
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
/// Optional args: `username`, `password`, `hash`, `ticket_path`, `base_dn`
///
/// Auth precedence (first match wins):
///   1. `ticket_path` → Kerberos GSSAPI bind via `KRB5CCNAME` + `-Y GSSAPI`.
///      Required for cross-forest enumeration where the only usable cred is
///      a forged inter-realm ticket; simple/NTLM binds get rejected with
///      0x52e on a foreign DC.
///   2. `username` + `hash` (NTLM `lm:nt` or bare nt) → impacket LDAP
///      pass-the-hash.
///   3. `username` + `password` → ldapsearch simple bind.
///   4. Neither → anonymous bind (fails on hardened DCs).
pub async fn enumerate_domain_trusts(args: &Value) -> Result<ToolOutput> {
    build_enumerate_domain_trusts(args)?.execute().await
}

/// Build the subprocess invocation for [`enumerate_domain_trusts`].
///
/// Exposed for the resolver-side Bug B contract test — the helper lets the
/// test assert that an injected `ticket_path` actually reaches the child
/// process as `KRB5CCNAME`. Without this guard the ticket is injected into
/// args but silently dropped by the tool impl.
#[doc(hidden)]
pub fn build_enumerate_domain_trusts(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let base_dn = optional_str(args, "base_dn");
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    // Cross-realm auth: orchestrator sets `bind_domain` to the cred's actual
    // realm when the credential lives in a different forest from the search
    // target (e.g. cred is `user@contoso.local` querying `fabrikam.local` DC).
    // Without this, the bind DN gets the target realm and the foreign DC
    // rejects with `invalidCredentials`. Falls back to `domain` when absent.
    let bind_domain = optional_str(args, "bind_domain").unwrap_or(domain);

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain_to_base_dn(domain),
    };
    let uri = format!("ldap://{target}");

    // Kerberos GSSAPI bind via cached ticket — preferred over hash/password
    // because forged inter-realm tickets only authenticate via GSSAPI. This
    // is the load-bearing path for the child→parent forest enumeration
    // sequence: the resolver injects `ticket_path` when an Administrator
    // ccache exists for the target realm, but without this branch the tool
    // silently falls through to NTLM and the foreign DC rejects the bind
    // (Bug B silent-drop class).
    if let Some(ccache) = ticket_path {
        return Ok(CommandBuilder::new("ldapsearch")
            .env("KRB5CCNAME", ccache)
            .env("KRB5_CONFIG", format!("{ccache}.krb5.conf:/etc/krb5.conf"))
            .flag_visible("-H", &uri)
            .arg("-Y")
            .arg("GSSAPI")
            .timeout_secs(120)
            .flag("-b", &computed_base_dn)
            .arg("(objectClass=trustedDomain)")
            .args([
                "cn",
                "trustDirection",
                "trustType",
                "trustAttributes",
                "flatName",
                // securityIdentifier comes back as base64 (binary SID); the
                // parser decodes it. Required for child→parent forge.
                "securityIdentifier",
            ]));
    }

    // Hash-based auth: use impacket LDAP client with pass-the-hash (NTLM)
    if let (Some(u), Some(h)) = (username, hash) {
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
        return Ok(CommandBuilder::new("bash")
            .args(["-c", &ldap_query])
            .timeout_secs(120));
    }

    let mut cmd = CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag_visible("-H", &uri)
        .timeout_secs(120);

    if let (Some(u), Some(p)) = (username, password) {
        let bind_dn = format!("{u}@{bind_domain}");
        cmd = cmd.flag("-D", bind_dn).flag("-w", p);
    }

    Ok(cmd
        .flag("-b", computed_base_dn)
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
        ]))
}

/// Check if RDP (port 3389) is reachable on a target.
///
/// Required args: `target`
pub async fn check_rdp_reachability(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;

    CommandBuilder::new("nmap")
        .arg("-Pn")
        .flag_visible("-p", "3389")
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
        .arg("-Pn")
        .flag_visible("-p", "5985,5986")
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
/// Optional args: `target_ip`, `ticket_path`
///
/// When `ticket_path` is supplied the resolver-injected ccache is exported
/// via `KRB5CCNAME` so smbclient.py can find it without relying on the
/// default `/tmp/krb5cc_<uid>` location. Without this export the cross-forest
/// inter-realm ticket injection is silently dropped (Bug B) — the worker
/// inherits no Kerberos context and the bind fails with "CCache file is not
/// found".
pub async fn smbclient_kerberos_shares(args: &Value) -> Result<ToolOutput> {
    build_smbclient_kerberos_shares(args)?.execute().await
}

#[doc(hidden)]
pub fn build_smbclient_kerberos_shares(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let target_ip = optional_str(args, "target_ip");
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());

    let mut cmd = CommandBuilder::new("smbclient.py")
        .args(["-k", "-no-pass"])
        .timeout_secs(180);

    if let Some(tpath) = ticket_path {
        cmd = cmd
            .env("KRB5CCNAME", tpath)
            .env("KRB5_CONFIG", format!("{tpath}.krb5.conf:/etc/krb5.conf"));
    }

    if let Some(ip) = target_ip {
        cmd = cmd.flag("-target-ip", ip);
    }

    // Impacket smbclient.py uses @host to list shares
    Ok(cmd.arg(format!("@{target}")))
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
    build_ldap_acl_enumeration(args)?.execute().await
}

/// Object classes whose security descriptors carry ACL attack paths.
///
/// A gMSA's `objectCategory` is its own schema class, not `computer`, so the
/// category-based clauses miss it entirely; the extra `objectClass` clause is
/// what puts `msDS-GroupMSAMembership` — the gMSA reader list — in reach.
const ACL_ENUM_FILTER: &str = "(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectCategory=groupPolicyContainer)(objectClass=msDS-GroupManagedServiceAccount))";

/// Attributes requested for every object the ACL enumeration returns.
///
/// The LAPS expiry attributes are the readable marker for a LAPS-managed
/// computer; the password attributes beside them are confidential and are
/// deliberately not requested. A directory without either LAPS generation
/// installed simply omits them.
const ACL_ENUM_ATTRIBUTES: &[&str] = &[
    "sAMAccountName",
    "objectClass",
    "objectSid",
    "nTSecurityDescriptor",
    "cn",
    "displayName",
    "msDS-GroupMSAMembership",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
];

/// Build the subprocess invocation for [`ldap_acl_enumeration`].
///
/// Exposed so the resolver-side Bug B contract test can verify the
/// `ticket_path` arg surfaces as `KRB5CCNAME` and the injected password
/// reaches `-w`. The hash branch builds a `bash -c "python3 -c ..."`
/// invocation; the nthash is interpolated into the script body.
#[doc(hidden)]
pub fn build_ldap_acl_enumeration(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let bind_domain = optional_str(args, "bind_domain");
    let hash = optional_str(args, "hash");
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());

    let base_dn = domain_to_base_dn(domain);
    let uri = format!("ldap://{target}");

    // Kerberos GSSAPI bind for cross-forest LDAP enumeration. Takes precedence
    // over hash/password — when a forged inter-realm ticket is present we MUST
    // use it, otherwise simple bind with source-realm cred fails 0x52e.
    if let Some(ccache) = ticket_path {
        return Ok(CommandBuilder::new("ldapsearch")
            .env("KRB5CCNAME", ccache)
            .env("KRB5_CONFIG", format!("{ccache}.krb5.conf:/etc/krb5.conf"))
            .flag_visible("-H", &uri)
            .arg("-Y")
            .arg("GSSAPI")
            .timeout_secs(300)
            .flag("-b", &base_dn)
            .args(["-E", "1.2.840.113556.1.4.801=::MAMCAQQ="])
            .args(LDAP_PAGED_RESULTS.iter().copied())
            .arg(ACL_ENUM_FILTER)
            .args(ACL_ENUM_ATTRIBUTES.iter().copied()));
    }

    // If hash is provided, use impacket LDAP for pass-the-hash
    if let (Some(u), Some(h)) = (username, hash) {
        let nt_hash = if h.contains(':') {
            h.rsplit(':').next().unwrap_or(h)
        } else {
            h
        };
        let attributes = ACL_ENUM_ATTRIBUTES
            .iter()
            .map(|a| format!("'{a}'"))
            .collect::<Vec<_>>()
            .join(",");
        let ldap_query = format!(
            r#"python3 -c "
import base64
from impacket.ldap import ldap as ldap_mod
conn = ldap_mod.LDAPConnection('ldap://{target}', '{base_dn}', '{target}')
conn.login('{u}', '', '{domain}', lmhash='', nthash='{nt_hash}')
sc = ldap_mod.SimplePagedResultsControl(size=1000)
resp = conn.search(
    searchFilter='{filter}',
    attributes=[{attributes}],
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
                if name in ('nTSecurityDescriptor', 'msDS-GroupMSAMembership', 'objectSid'):
                    b = bytes(val)
                    print(f'{{name}}:: {{base64.b64encode(b).decode()}}')
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
            filter = ACL_ENUM_FILTER,
            attributes = attributes,
        );
        return Ok(CommandBuilder::new("bash")
            .args(["-c", &ldap_query])
            .timeout_secs(300));
    }

    // Password-based: use ldapsearch with LDAP_SERVER_SD_FLAGS_OID control
    // to request DACL (value 4) in the nTSecurityDescriptor attribute
    let mut cmd = CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag_visible("-H", &uri)
        .timeout_secs(300);

    if let (Some(u), Some(p)) = (username, password) {
        let auth_domain = bind_domain.unwrap_or(domain);
        let bind_dn = format!("{u}@{auth_domain}");
        cmd = cmd.flag("-D", bind_dn).flag("-w", p);
    }

    Ok(cmd
        .flag("-b", &base_dn)
        // Request DACL only via SD_FLAGS control (0x04 = DACL)
        // BER: SEQUENCE { INTEGER 4 } = 30 03 02 01 04 → base64 MAMCAQQ=
        .args(["-E", "1.2.840.113556.1.4.801=::MAMCAQQ="])
        .args(LDAP_PAGED_RESULTS.iter().copied())
        .arg(ACL_ENUM_FILTER)
        .args(ACL_ENUM_ATTRIBUTES.iter().copied()))
}

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

    // mock executor tests: exercise full CommandBuilder code paths

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

    // Bug B (ldap_search): ticket_path → KRB5CCNAME / password → -w

    #[test]
    fn ldap_search_invocation_exports_krb5ccname_when_ticket_path_set() {
        // When the orchestrator dispatches ldap_search with a forged
        // inter-realm ccache injected by the resolver, the tool impl must
        // export KRB5CCNAME and switch ldapsearch into GSSAPI mode —
        // otherwise the ccache is silently dropped and the bind falls back
        // to anonymous.
        let args = json!({
            "target": "dc02.fabrikam.local",
            "domain": "fabrikam.local",
            "ticket_path": "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache",
            "filter": "(objectClass=user)",
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let envs = cmd.env_vars_for_test();
        assert!(
            envs.iter().any(|(k, v)| k == "KRB5CCNAME"
                && v == "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache"),
            "ticket_path must export KRB5CCNAME so ldapsearch loads the cross-forest ccache"
        );
        // KRB5_CONFIG points at the per-ccache shim so MIT libkrb5 can
        // resolve `<target-fqdn> → TARGET.REALM` and hit the cached service
        // ticket. Without this MIT falls back to the system default_realm
        // (EC2.INTERNAL on the ares AMI) and the GSSAPI bind fails with
        // "Matching credential not found" despite a valid ccache.
        assert!(
            envs.iter()
                .any(|(k, v)| k == "KRB5_CONFIG"
                    && v
                        == "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache.krb5.conf:/etc/krb5.conf"),
            "ticket_path must export KRB5_CONFIG pointing at the per-ccache shim, got envs: {envs:?}"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-Y"));
        assert!(args_vec.iter().any(|a| a == "GSSAPI"));
        // No simple-bind flags when GSSAPI is in play.
        assert!(args_vec.iter().all(|a| a != "-w"));
        assert!(args_vec.iter().all(|a| a != "-D"));
    }

    #[test]
    fn ldap_search_invocation_passes_password_to_w_flag() {
        // The op-time bug: the orchestrator supplied
        // `username=carol@fabrikam.local` + `password=P@ssw0rd!` and
        // expected a simple bind. Without ticket_path the tool MUST issue
        // `-x -D carol@fabrikam.local -w P@ssw0rd!`.
        let args = json!({
            "target": "dc02.fabrikam.local",
            "domain": "fabrikam.local",
            "username": "carol",
            "password": "P@ssw0rd!",
            "filter": "(objectClass=user)",
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(
            args_vec.iter().any(|a| a == "-x"),
            "expected simple-bind flag"
        );
        let w_idx = args_vec
            .iter()
            .position(|a| a == "-w")
            .expect("password must reach -w flag");
        assert_eq!(
            args_vec.get(w_idx + 1).map(String::as_str),
            Some("P@ssw0rd!")
        );
        let d_idx = args_vec
            .iter()
            .position(|a| a == "-D")
            .expect("bind DN must reach -D flag");
        assert_eq!(
            args_vec.get(d_idx + 1).map(String::as_str),
            Some("carol@fabrikam.local")
        );
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .all(|(k, _)| k != "KRB5CCNAME"),
            "simple-bind branch must not export KRB5CCNAME"
        );
    }

    #[test]
    fn ldap_search_forces_objectclass_attribute() {
        // A narrowed attribute list that omits objectClass must still request
        // it, so the orchestrator's user extractor can tell group/computer
        // records from real users. Without it, group sAMAccountNames leak in
        // as truncated `ldap_extraction` users ("Backup Operators" -> "Backup").
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "filter": "(objectClass=group)",
            "attributes": "sAMAccountName,cn"
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(
            args_vec.iter().any(|a| a == "sAMAccountName"),
            "caller's attributes must be preserved"
        );
        assert!(
            args_vec.iter().any(|a| a == "objectClass"),
            "objectClass must be appended when omitted, got: {args_vec:?}"
        );
    }

    #[test]
    fn ldap_search_forces_memberof_attribute() {
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "filter": "(objectCategory=person)",
            "attributes": "sAMAccountName,description"
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(
            args_vec.iter().any(|a| a == "memberOf"),
            "memberOf must be appended when omitted, got: {args_vec:?}"
        );
    }

    #[test]
    fn ldap_search_does_not_duplicate_memberof() {
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "attributes": "sAMAccountName,memberof"
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert_eq!(
            args_vec
                .iter()
                .filter(|a| a.eq_ignore_ascii_case("memberof"))
                .count(),
            1,
            "got: {args_vec:?}"
        );
    }

    #[test]
    fn ldap_search_does_not_duplicate_objectclass() {
        // Already-present objectClass (any case) must not be appended twice.
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "attributes": "samaccountname,ObjectClass"
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert_eq!(
            args_vec
                .iter()
                .filter(|a| a.eq_ignore_ascii_case("objectClass"))
                .count(),
            1,
            "objectClass must appear exactly once, got: {args_vec:?}"
        );
    }

    #[test]
    fn ldap_search_anonymous_when_no_creds() {
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
        });
        let cmd = super::build_ldap_search(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(
            args_vec.iter().any(|a| a == "-x"),
            "expected anonymous simple-bind"
        );
        assert!(args_vec.iter().all(|a| a != "-w"));
        assert!(args_vec.iter().all(|a| a != "-Y"));
    }

    #[test]
    fn ldap_search_refuses_an_anonymous_bind_once_a_principal_is_named() {
        let args = json!({
            "target": "192.168.58.10",
            "domain": "contoso.local",
            "username": "alice",
        });
        let Err(err) = super::build_ldap_search(&args) else {
            panic!("a named principal with no credential must not degrade to -x");
        };
        let msg = err.to_string();
        assert!(msg.contains("alice"), "{msg}");
        assert!(msg.contains("anonymous bind"), "{msg}");
    }

    // Bug B (enumerate_domain_trusts): ticket_path → KRB5CCNAME

    #[test]
    fn enumerate_domain_trusts_invocation_exports_krb5ccname_when_ticket_path_set() {
        // enumerate_domain_trusts is on the Bug B allowlist; if the tool
        // impl doesn't read `ticket_path` the resolver-injected ccache goes
        // to /dev/null and cross-forest enumeration silently degrades to an
        // unauthenticated bind.
        let args = json!({
            "target": "dc02.fabrikam.local",
            "domain": "fabrikam.local",
            "ticket_path": "/tmp/ares-tickets/child_fabrikam_local__fabrikam_local__Administrator.ccache",
        });
        let cmd = super::build_enumerate_domain_trusts(&args).unwrap();
        assert!(
            cmd.env_vars_for_test().iter().any(|(k, v)| k == "KRB5CCNAME"
                && v
                    == "/tmp/ares-tickets/child_fabrikam_local__fabrikam_local__Administrator.ccache"),
            "ticket_path must export KRB5CCNAME for enumerate_domain_trusts"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-Y"));
        assert!(args_vec.iter().any(|a| a == "GSSAPI"));
        assert!(
            args_vec.iter().any(|a| a == "(objectClass=trustedDomain)"),
            "GSSAPI branch must still issue the trustedDomain query filter"
        );
        // GSSAPI bind cannot also have simple-bind flags or NTLM bind would
        // be re-attempted on a fallback.
        assert!(args_vec.iter().all(|a| a != "-w"));
        assert!(args_vec.iter().all(|a| a != "-D"));
    }

    #[test]
    fn enumerate_domain_trusts_password_branch_unchanged() {
        // Regression guard: without ticket_path the legacy simple-bind args
        // are still produced. Pins the conditional in build_enumerate_domain_trusts.
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss",
        });
        let cmd = super::build_enumerate_domain_trusts(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .all(|(k, _)| k != "KRB5CCNAME"),
            "simple-bind branch must not export KRB5CCNAME"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-x"));
        let w_idx = args_vec
            .iter()
            .position(|a| a == "-w")
            .expect("password must reach -w");
        assert_eq!(args_vec.get(w_idx + 1).map(String::as_str), Some("P@ss"));
    }

    #[test]
    fn enumerate_domain_trusts_ticket_path_wins_over_password() {
        // If both ticket_path AND password are in args (post-resolver state),
        // GSSAPI must win — the forged inter-realm ticket is the only auth
        // the foreign DC will honor.
        let args = json!({
            "target": "dc02.fabrikam.local",
            "domain": "fabrikam.local",
            "username": "Administrator",
            "password": "P@ss",
            "ticket_path": "/tmp/ares-tickets/x.ccache",
        });
        let cmd = super::build_enumerate_domain_trusts(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "GSSAPI"));
        assert!(
            args_vec.iter().all(|a| a != "-w"),
            "password must NOT reach -w when ticket_path is present"
        );
    }

    // Bug B (ldap_acl_enumeration): ticket_path → KRB5CCNAME

    #[test]
    fn ldap_acl_enumeration_invocation_exports_krb5ccname_when_ticket_path_set() {
        let args = json!({
            "target": "dc02.fabrikam.local",
            "domain": "fabrikam.local",
            "ticket_path": "/tmp/ares-tickets/y.ccache",
        });
        let cmd = super::build_ldap_acl_enumeration(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/y.ccache"),
            "ticket_path must export KRB5CCNAME for ldap_acl_enumeration"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "GSSAPI"));
    }

    #[test]
    fn ldap_acl_enumeration_password_branch_passes_w_flag() {
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss",
        });
        let cmd = super::build_ldap_acl_enumeration(&args).unwrap();
        let args_vec = cmd.args_for_test();
        let w_idx = args_vec
            .iter()
            .position(|a| a == "-w")
            .expect("password must reach -w for ldap_acl_enumeration");
        assert_eq!(args_vec.get(w_idx + 1).map(String::as_str), Some("P@ss"));
    }

    fn assert_pages(args: &[String]) {
        let idx = args
            .iter()
            .position(|a| a == "pr=1000/noprompt")
            .unwrap_or_else(|| panic!("paged results control missing from {args:?}"));
        assert_eq!(args.get(idx - 1).map(String::as_str), Some("-E"));
    }

    #[test]
    fn ldapsearch_branches_page_so_the_directory_is_not_truncated_at_maxpagesize() {
        let bindings = [
            json!({
                "target": "192.168.58.10",
                "domain": "contoso.local",
                "username": "alice",
                "password": "P@ssw0rd!",
            }),
            json!({
                "target": "dc01.contoso.local",
                "domain": "contoso.local",
                "ticket_path": "/tmp/ares-tickets/z.ccache",
            }),
            json!({
                "target": "192.168.58.10",
                "domain": "contoso.local",
            }),
        ];
        for args in &bindings {
            assert_pages(super::build_ldap_search(args).unwrap().args_for_test());
        }
        for args in &bindings[..2] {
            assert_pages(
                super::build_ldap_acl_enumeration(args)
                    .unwrap()
                    .args_for_test(),
            );
        }
    }

    #[test]
    fn ldap_acl_enumeration_hash_branch_pages_via_impacket() {
        let args = json!({
            "target": "192.168.58.10",
            "domain": "contoso.local",
            "username": "alice",
            "hash": "aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890",
        });
        let script = super::build_ldap_acl_enumeration(&args)
            .unwrap()
            .args_for_test()
            .join(" ");
        assert!(script.contains("SimplePagedResultsControl(size=1000)"));
        assert!(script.contains("sizeLimit=0"));
    }

    #[test]
    fn ldap_acl_enumeration_requests_the_gmsa_and_laps_attributes() {
        for args in [
            json!({
                "target": "192.168.58.10",
                "domain": "contoso.local",
                "username": "alice",
                "password": "P@ssw0rd!",
            }),
            json!({
                "target": "192.168.58.10",
                "domain": "contoso.local",
                "ticket_path": "/tmp/ares-tickets/z.ccache",
            }),
        ] {
            let cmd = super::build_ldap_acl_enumeration(&args).unwrap();
            let args_vec = cmd.args_for_test();
            for attr in [
                "msDS-GroupMSAMembership",
                "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-PasswordExpirationTime",
            ] {
                assert!(
                    args_vec.iter().any(|a| a == attr),
                    "{attr} must be requested, got {args_vec:?}"
                );
            }
            assert!(
                args_vec
                    .iter()
                    .any(|a| a.contains("objectClass=msDS-GroupManagedServiceAccount")),
                "gMSA objects must be in the search filter, got {args_vec:?}"
            );
        }
    }

    #[test]
    fn ldap_acl_enumeration_hash_branch_carries_the_same_filter_and_attributes() {
        let args = json!({
            "target": "192.168.58.10",
            "domain": "contoso.local",
            "username": "alice",
            "hash": "aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890",
        });
        let cmd = super::build_ldap_acl_enumeration(&args).unwrap();
        let script = cmd.args_for_test().join(" ");
        assert!(script.contains("objectClass=msDS-GroupManagedServiceAccount"));
        assert!(script.contains("'msDS-GroupMSAMembership'"));
        assert!(script.contains("'ms-Mcs-AdmPwdExpirationTime'"));
        assert!(
            script.contains("'msDS-GroupMSAMembership', 'objectSid'"),
            "the SD-syntax attributes must be base64-encoded, not printed raw"
        );
    }

    #[test]
    fn smbclient_kerberos_shares_invocation_receives_krb5ccname_env() {
        // Bug B: resolver writes ticket_path into the args map, but if the
        // tool impl doesn't surface it as KRB5CCNAME in the child env then
        // smbclient.py inherits no Kerberos context and the inter-realm
        // ccache injection is silently dropped.
        let args = json!({
            "target": "dc02.fabrikam.local",
            "ticket_path": "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache",
        });
        let cmd = super::build_smbclient_kerberos_shares(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .any(|(k, v)| k == "KRB5CCNAME"
                    && v
                        == "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache"),
            "ticket_path must export KRB5CCNAME so smbclient.py loads the cross-forest ccache"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-k"));
        assert!(args_vec.iter().any(|a| a == "-no-pass"));
    }
}
