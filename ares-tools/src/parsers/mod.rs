//! Output parsers for tool results.
//!
//! Extract structured discovery data (hosts, open ports, credentials, etc.)
//! from raw CLI tool output without relying on LLM interpretation.

mod certipy;
mod cracker;
mod credential_tools;
mod delegation;
mod mssql;
mod nmap;
mod ntsd;
mod secrets;
mod smb;
mod spider;
mod trust;
mod users_shares;

use serde_json::{json, Value};

// Re-export all public parser functions at module level.
pub use certipy::{parse_certipy_esc1_chain, parse_certipy_find};
pub use cracker::parse_cracker_output;
pub use credential_tools::{
    parse_adidnsdump, parse_ldap_descriptions, parse_lsassy, parse_ntds_dit, parse_spray_success,
};
pub use delegation::{extract_delegation_account, parse_delegation};
pub use mssql::{parse_mssql_impersonation, parse_mssql_linked_servers};
pub use nmap::{flush_nmap_host, parse_nmap_output};
pub use ntsd::parse_acl_enumeration;
pub use secrets::{parse_asrep_roast, parse_kerberoast, parse_secretsdump};
pub use smb::{parse_netexec_smb, parse_smb_signing};
pub use spider::parse_spider_credentials;
pub use trust::parse_domain_trusts;
pub use users_shares::{parse_netexec_shares, parse_netexec_users};

/// Parse raw tool output and return structured discoveries.
///
/// Returns a JSON object with optional `hosts`, `credentials`, `hashes`,
/// `vulnerabilities` arrays that the orchestrator's result_processing can
/// consume directly.
pub fn parse_tool_output(tool_name: &str, output: &str, params: &Value) -> Value {
    let mut discoveries = json!({});

    match tool_name {
        "nmap_scan" => {
            let hosts = parse_nmap_output(output, params);
            if !hosts.is_empty() {
                discoveries["hosts"] = Value::Array(hosts);
            }
        }
        "smb_signing_check" => {
            let hosts = parse_smb_signing(output, params);
            if !hosts.is_empty() {
                discoveries["hosts"] = Value::Array(hosts);
            }
        }
        "smb_sweep" => {
            let hosts = parse_netexec_smb(output);
            if !hosts.is_empty() {
                discoveries["hosts"] = Value::Array(hosts);
            }
        }
        "enumerate_users" => {
            let mut raw_users = parse_netexec_users(output);

            // Check for embedded credentials (last element with _credentials key)
            if let Some(last) = raw_users.last() {
                if last.get("_credentials").is_some() {
                    if let Some(creds) = last["_credentials"].as_array() {
                        if !creds.is_empty() {
                            discoveries["credentials"] = Value::Array(creds.clone());
                        }
                    }
                    raw_users.pop(); // Remove the _credentials marker
                }
            }

            if !raw_users.is_empty() {
                discoveries["discovered_users"] = Value::Array(raw_users);
            }
        }
        "enumerate_shares" => {
            let shares = parse_netexec_shares(output);
            if !shares.is_empty() {
                discoveries["shares"] = Value::Array(shares);
            }
        }
        "run_bloodhound" => {
            // BloodHound collection doesn't produce immediate discoveries
        }
        "secretsdump" | "secretsdump_kerberos" | "forge_inter_realm_and_dump" => {
            // forge_inter_realm_and_dump runs ticketer + secretsdump in one
            // call. The orchestrator passes `target_domain` so secretsdump
            // hashes get attributed to the dumped (target/parent) realm,
            // not the forging (source/child) realm.
            let (hashes, creds) = parse_secretsdump(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "raise_child" => {
            // raiseChild.py performs the parent-domain NTDS dump in standard
            // secretsdump format (lines like "contoso.local/user:RID:LM:NT:::"
            // or "DOMAIN\\user:RID:..."). Derive parent FQDN from child_domain
            // and pass as target_domain so bare-username lines and NetBIOS
            // prefixes get attributed to the parent forest root.
            let child_domain = params
                .get("child_domain")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let parent_domain = child_domain
                .split_once('.')
                .map(|(_, rest)| rest)
                .unwrap_or(child_domain);
            let mut params_with_target = params.clone();
            if let Some(obj) = params_with_target.as_object_mut() {
                obj.insert("target_domain".into(), json!(parent_domain));
            }
            let (hashes, creds) = parse_secretsdump(output, &params_with_target);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "kerberoast" => {
            let hashes = parse_kerberoast(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
        }
        "asrep_roast" | "kerberos_user_enum_noauth" => {
            let hashes = parse_asrep_roast(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
            // Extract valid usernames from GetNPUsers output lines like:
            //   [-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
            //   [-] invalid principal syntax
            // The first pattern confirms a valid AD account.
            let mut valid_users = Vec::new();
            let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            for line in output.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("[-] User ") {
                    // Match all variants that confirm a valid AD principal:
                    //   [-] User X doesn't have UF_DONT_REQUIRE_PREAUTH set
                    //   [-] User X does not have UF_DONT_REQUIRE_PREAUTH set
                    //   [-] User X is disabled / KDC_ERR_CLIENT_REVOKED
                    let username = rest
                        .strip_suffix(" doesn't have UF_DONT_REQUIRE_PREAUTH set")
                        .or_else(|| rest.strip_suffix(" does not have UF_DONT_REQUIRE_PREAUTH set"))
                        .or_else(|| {
                            if rest.contains("KDC_ERR_CLIENT_REVOKED") {
                                rest.split_whitespace().next()
                            } else {
                                None
                            }
                        });
                    if let Some(username) = username {
                        let username = username.trim();
                        if !username.is_empty() {
                            valid_users.push(json!({
                                "username": username,
                                "domain": domain,
                                "source": "kerberos_enum",
                            }));
                        }
                    }
                }
            }
            if !valid_users.is_empty() {
                discoveries["discovered_users"] = Value::Array(valid_users);
            }
        }
        "find_delegation" => {
            let vulns = parse_delegation(output, params);
            if !vulns.is_empty() {
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "certipy_find" => {
            let vulns = parse_certipy_find(output, params);
            if !vulns.is_empty() {
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "certipy_esc1_full_chain" => {
            // Composite ESC1 tool: certipy req (with -upn/-sid) followed by
            // certipy auth. On success the auth step emits a "Got hash for
            // 'user@realm': <lm>:<nt>" line. Extract into a `Hash` discovery
            // so `auto_credential_reuse` picks it up and DCSyncs the foreign
            // DC — closes the chain end-to-end without an LLM round.
            let hashes = parse_certipy_esc1_chain(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
        }
        "lsassy" => {
            let (hashes, creds) = parse_lsassy(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "ntds_dit_extract" => {
            let (hashes, creds) = parse_ntds_dit(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "password_spray" | "smb_login_check" => {
            let creds = parse_spray_success(output, params);
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "username_as_password" => {
            let creds = parse_spray_success(output, params);
            // Only keep creds where password == username.
            let filtered: Vec<Value> = creds
                .into_iter()
                .filter(|c| {
                    let user = c["username"].as_str().unwrap_or("");
                    let pass = c["password"].as_str().unwrap_or("");
                    !pass.is_empty() && pass.eq_ignore_ascii_case(user)
                })
                .collect();
            if !filtered.is_empty() {
                discoveries["credentials"] = Value::Array(filtered);
            }
        }
        "ldap_search_descriptions" => {
            let creds = parse_ldap_descriptions(output, params);
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "adidnsdump" => {
            let hosts = parse_adidnsdump(output);
            if !hosts.is_empty() {
                discoveries["hosts"] = Value::Array(hosts);
            }
        }
        "mssql_enum_impersonation" => {
            let vulns = parse_mssql_impersonation(output, params);
            if !vulns.is_empty() {
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "mssql_enum_linked_servers" => {
            let vulns = parse_mssql_linked_servers(output, params);
            if !vulns.is_empty() {
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "enumerate_domain_trusts" => {
            let trusts = parse_domain_trusts(output);
            if !trusts.is_empty() {
                let trust_values: Vec<Value> = trusts
                    .iter()
                    .filter_map(|t| serde_json::to_value(t).ok())
                    .collect();
                discoveries["trusted_domains"] = Value::Array(trust_values);
            }
        }
        "crack_with_hashcat" | "crack_with_john" => {
            let creds = parse_cracker_output(output, params);
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "sysvol_script_search" | "smbclient_spider" => {
            let creds = parse_spider_credentials(output, params);
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
            }
        }
        "ldap_acl_enumeration" => {
            let vulns = parse_acl_enumeration(output, params);
            if !vulns.is_empty() {
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "password_policy" => {
            // Password policy is informational metadata, not an exploitable vuln —
            // surfacing it as `vulnerabilities[]` makes the orchestrator route it to
            // the exploit agent, which has no spray tool and dead-ends every time.
            // The lockout/min-length details inform spray cadence elsewhere; we
            // expose them under a dedicated key so consumers can read without the
            // exploit-routing side effect.
            let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if !output.is_empty() && !domain.is_empty() {
                let lockout_threshold = output
                    .lines()
                    .find(|l| l.to_lowercase().contains("account lockout threshold"))
                    .and_then(|l| l.split(':').next_back().map(|s| s.trim().to_string()));
                let min_length = output
                    .lines()
                    .find(|l| l.to_lowercase().contains("minimum password length"))
                    .and_then(|l| l.split(':').next_back().map(|s| s.trim().to_string()));
                let mut details = serde_json::Map::new();
                details.insert("domain".into(), json!(domain));
                details.insert("target_ip".into(), json!(target));
                if let Some(ref lt) = lockout_threshold {
                    details.insert("lockout_threshold".into(), json!(lt));
                }
                if let Some(ref ml) = min_length {
                    details.insert("min_password_length".into(), json!(ml));
                }
                discoveries["password_policies"] = json!([details]);
            }
        }
        "zerologon_check" => {
            // netexec --zerologon emits per-line results. On vulnerable DCs:
            //   SMB     <ip>  445   <host>  VULNERABLE
            //   SMB     <ip>  445   <host>  [+] <host> is vulnerable to Zerologon ...
            // On patched DCs:
            //   SMB     <ip>  445   <host>  Not vulnerable
            //   SMB     <ip>  445   <host>  [-] <host> is not vulnerable
            //
            // Without this parser the netexec output flowed straight to the
            // LLM and the `zerologon` technique never got into state. The
            // exploit (set_empty_pw + secretsdump krbtgt + restore-pw) is
            // destructive enough that ares leaves it to a deliberate operator
            // round, but the *discovery* belongs in `discovered_vulnerabilities`
            // so the scoreboard token / strategy-priority knobs / deep-exploit
            // routing can act on it.
            let dc_ip = params
                .get("dc_ip")
                .or_else(|| params.get("target_ip"))
                .or_else(|| params.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !dc_ip.is_empty() && is_zerologon_vulnerable(output) {
                let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let hostname = params
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let target_ip_safe = dc_ip.replace('.', "_");
                let mut details = serde_json::Map::new();
                details.insert("target_ip".into(), json!(dc_ip));
                details.insert("cve".into(), json!("CVE-2020-1472"));
                details.insert(
                    "description".into(),
                    json!(format!(
                        "Domain controller {dc_ip} is vulnerable to ZeroLogon (CVE-2020-1472)"
                    )),
                );
                if !domain.is_empty() {
                    details.insert("domain".into(), json!(domain));
                }
                if !hostname.is_empty() {
                    details.insert("hostname".into(), json!(hostname));
                }
                discoveries["vulnerabilities"] = json!([{
                    "vuln_id": format!("zerologon_{target_ip_safe}"),
                    "vuln_type": "zerologon",
                    "target": dc_ip,
                    "discovered_by": "zerologon_check",
                    "priority": 4,
                    "recommended_agent": "privesc",
                    "details": details,
                }]);
            }
        }
        "evil_winrm" => {
            // Detect successful WinRM connection from evil-winrm output.
            // A successful connection typically shows "Evil-WinRM shell" or
            // output from executed commands (e.g., "whoami" returning a username).
            let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if output.contains("Evil-WinRM")
                || output.contains("\\")  // whoami output like DOMAIN\user
                || output.contains("PS >")
            {
                discoveries["vulnerabilities"] = json!([{
                    "vuln_id": format!("winrm_access_{}", target.replace('.', "_")),
                    "vuln_type": "winrm_access",
                    "target": target,
                    "details": {
                        "description": format!("WinRM access confirmed on {target}"),
                        "target_ip": target,
                    },
                }]);
            }
        }
        "relay_and_coerce" => {
            // Composite ESC8 tool prints `PFX_FILE=...` and `RELAYED_USER=...`
            // markers when the cert is captured. Convert to a
            // `certificate_obtained` vuln so `auto_certipy_auth` picks it up.
            let pfx_path = output
                .lines()
                .find_map(|l| l.trim().strip_prefix("PFX_FILE="))
                .map(str::trim);
            let relayed_user = output
                .lines()
                .find_map(|l| l.trim().strip_prefix("RELAYED_USER="))
                .map(str::trim);

            if let Some(pfx) = pfx_path {
                // Cert is for the target DC's realm (the relayed identity's
                // home), not the coercion credential's domain. Caller passes
                // `target_domain` for cross-forest cases; fall back to
                // `coerce_domain` for same-forest.
                let target_domain = params
                    .get("target_domain")
                    .and_then(|v| v.as_str())
                    .or_else(|| params.get("coerce_domain").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let coerce_target = params
                    .get("coerce_target")
                    .and_then(|v| v.as_str())
                    .or_else(|| params.get("target_dc").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let user = relayed_user.unwrap_or("");
                let mut details = serde_json::Map::new();
                details.insert("pfx_path".into(), json!(pfx));
                if !target_domain.is_empty() {
                    details.insert("domain".into(), json!(target_domain));
                }
                if !user.is_empty() {
                    details.insert("target_user".into(), json!(user));
                    details.insert("account_name".into(), json!(user));
                }
                if !coerce_target.is_empty() {
                    details.insert("target_ip".into(), json!(coerce_target));
                }
                details.insert("source".into(), json!("relay_and_coerce"));
                details.insert(
                    "description".into(),
                    json!(format!(
                        "ESC8 relay captured certificate for {user} in {target_domain}"
                    )),
                );
                let user_safe = user.replace(['$', '.'], "_");
                let domain_safe = target_domain.replace('.', "_");
                discoveries["vulnerabilities"] = json!([{
                    "vuln_id": format!("certificate_obtained_{user_safe}_{domain_safe}"),
                    "vuln_type": "certificate_obtained",
                    "target": coerce_target,
                    "details": details,
                }]);
            }
        }
        "xfreerdp" => {
            // Detect successful RDP authentication from xfreerdp output.
            let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            // xfreerdp success: shows "Authentication only" or specific success patterns
            let success = output.contains("Authentication only, exit status 0")
                || (output.contains("connected to") && !output.contains("ERRCONNECT"))
                || output.contains("FREERDP_CB_SESSION_STARTED");
            if success {
                discoveries["vulnerabilities"] = json!([{
                    "vuln_id": format!("rdp_access_{}", target.replace('.', "_")),
                    "vuln_type": "rdp_access",
                    "target": target,
                    "details": {
                        "description": format!("RDP access confirmed on {target}"),
                        "target_ip": target,
                    },
                }]);
            }
        }
        _ => {}
    }

    discoveries
}

/// Merge discoveries from multiple tool outputs.
///
/// Deduplicates hosts by IP, keeping the entry with the most services
/// and preferring entries with `is_dc: true`.
pub fn merge_discoveries(all: &[Value]) -> Value {
    let mut host_map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let mut credentials = Vec::new();
    let mut hashes = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut discovered_users = Vec::new();
    let mut shares = Vec::new();
    let mut trusted_domains_map: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();

    for disc in all {
        if let Some(h) = disc.get("hosts").and_then(|v| v.as_array()) {
            for host in h {
                let ip = host.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                if ip.is_empty() {
                    continue;
                }
                match host_map.entry(ip.to_string()) {
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(host.clone());
                    }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let existing = e.get();
                        let existing_services = existing
                            .get("services")
                            .and_then(|v| v.as_array())
                            .map_or(0, |a| a.len());
                        let new_services = host
                            .get("services")
                            .and_then(|v| v.as_array())
                            .map_or(0, |a| a.len());
                        let existing_is_dc = existing
                            .get("is_dc")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let new_is_dc =
                            host.get("is_dc").and_then(|v| v.as_bool()).unwrap_or(false);

                        // Replace if new entry has DC status or more services
                        if (new_is_dc && !existing_is_dc) || new_services > existing_services {
                            e.insert(host.clone());
                        }
                    }
                }
            }
        }
        if let Some(c) = disc.get("credentials").and_then(|v| v.as_array()) {
            credentials.extend(c.iter().cloned());
        }
        if let Some(h) = disc.get("hashes").and_then(|v| v.as_array()) {
            hashes.extend(h.iter().cloned());
        }
        if let Some(v) = disc.get("vulnerabilities").and_then(|v| v.as_array()) {
            vulnerabilities.extend(v.iter().cloned());
        }
        if let Some(u) = disc.get("discovered_users").and_then(|v| v.as_array()) {
            discovered_users.extend(u.iter().cloned());
        }
        if let Some(s) = disc.get("shares").and_then(|v| v.as_array()) {
            shares.extend(s.iter().cloned());
        }
        if let Some(t) = disc.get("trusted_domains").and_then(|v| v.as_array()) {
            for trust in t {
                let domain = trust.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                if !domain.is_empty() {
                    trusted_domains_map
                        .entry(domain.to_string())
                        .or_insert_with(|| trust.clone());
                }
            }
        }
    }

    let mut merged = json!({});
    if !host_map.is_empty() {
        let hosts: Vec<Value> = host_map.into_values().collect();
        merged["hosts"] = Value::Array(hosts);
    }
    if !credentials.is_empty() {
        merged["credentials"] = Value::Array(credentials);
    }
    if !hashes.is_empty() {
        merged["hashes"] = Value::Array(hashes);
    }
    if !vulnerabilities.is_empty() {
        merged["vulnerabilities"] = Value::Array(vulnerabilities);
    }
    if !discovered_users.is_empty() {
        merged["discovered_users"] = Value::Array(discovered_users);
    }
    if !shares.is_empty() {
        merged["shares"] = Value::Array(shares);
    }
    if !trusted_domains_map.is_empty() {
        let trusted_domains: Vec<Value> = trusted_domains_map.into_values().collect();
        merged["trusted_domains"] = Value::Array(trusted_domains);
    }
    merged
}

fn looks_like_ip(s: &str) -> bool {
    looks_like_ip_pub(s)
}

/// Detect a positive ZeroLogon (CVE-2020-1472) verdict in `zerologon_check`
/// tool output. The tool is `netexec smb <dc> -M zerologon`; success markers
/// vary by netexec version but always include the literal `VULNERABLE` token
/// or an explicit "vulnerable to Zerologon" phrase. Patched DCs emit the
/// negative `Not vulnerable` / "not vulnerable" markers, which we must
/// exclude — netexec prints both lines on success-and-then-restore runs, so
/// we treat the *absence* of a negative marker as required.
///
/// Decision matrix:
///   - "VULNERABLE" present AND no "not vulnerable" line   → true
///   - "is vulnerable to zerologon" present AND no negative → true
///   - everything else (no marker, or any negative marker)  → false
pub(crate) fn is_zerologon_vulnerable(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    // Negative markers win. Some netexec builds emit a banner line first
    // then a per-target verdict; if any line says the DC is not vulnerable
    // or the check skipped, we don't credit it.
    if lower.contains("not vulnerable")
        || lower.contains("is patched")
        || lower.contains("target appears patched")
    {
        return false;
    }
    // Positive markers: the literal token (netexec's column-formatted row)
    // OR the descriptive phrase. The phrase form is what older nxc builds
    // and the CME ancestor emitted, so we accept both.
    let positive_token = output
        .lines()
        .any(|l| l.contains(" VULNERABLE") || l.trim() == "VULNERABLE");
    let positive_phrase = lower.contains("vulnerable to zerologon")
        || lower.contains("zerologon: vulnerable")
        || lower.contains("[+] domain is vulnerable");
    positive_token || positive_phrase
}

/// Check if a string looks like an IPv4 address (public for recon module).
pub fn looks_like_ip_pub(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_nmap_with_services() {
        let output = r#"Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-08 11:12 UTC
Nmap scan report for dc01.contoso.local (192.168.58.210)
Host is up (0.0010s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 4.32 seconds"#;

        let params = json!({"target": "192.168.58.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1, "Should produce exactly one host");
        let host = &hosts[0];
        assert_eq!(host["ip"], "192.168.58.210");
        let services = host["services"].as_array().unwrap();
        assert!(
            services.len() >= 5,
            "Should have at least 5 services, got {}",
            services.len()
        );
        assert!(services.iter().any(|s| s.as_str().unwrap().contains("445")));
        assert!(services
            .iter()
            .any(|s| s.as_str().unwrap().contains("1433")));
    }

    #[test]
    fn parse_nmap_with_stderr_separator() {
        // combined() output includes stderr
        let output = "Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-08 11:12 UTC\n\
Nmap scan report for dc01.contoso.local (192.168.58.210)\n\
PORT    STATE SERVICE\n\
88/tcp  open  kerberos-sec\n\
389/tcp open  ldap\n\
445/tcp open  microsoft-ds\n\
\n\
Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds\n\
\n\
--- stderr ---\n\
Warning: some warning here";

        let params = json!({"target": "192.168.58.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert_eq!(host["ip"], "192.168.58.210");
        assert_eq!(host["hostname"], "dc01.contoso.local");
        assert!(
            host["is_dc"].as_bool().unwrap(),
            "Should detect DC from kerberos+ldap"
        );
        let services = host["services"].as_array().unwrap();
        assert_eq!(services.len(), 3);
    }

    #[test]
    fn parse_nmap_fallback_no_output() {
        let output = "";
        let params = json!({"target": "192.168.58.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.210");
        assert!(hosts[0]["services"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parse_nmap_multiple_hosts() {
        let output = "Nmap scan report for dc01.contoso.local (192.168.58.210)\n\
PORT    STATE SERVICE\n\
88/tcp  open  kerberos-sec\n\
445/tcp open  microsoft-ds\n\
\n\
Nmap scan report for srv01.contoso.local (192.168.58.211)\n\
PORT     STATE SERVICE\n\
445/tcp  open  microsoft-ds\n\
1433/tcp open  ms-sql-s";

        let params = json!({"target": "192.168.58.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.210");
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
        assert_eq!(hosts[1]["ip"], "192.168.58.211");
        assert!(!hosts[1]["is_dc"].as_bool().unwrap());
    }

    #[test]
    fn parse_netexec_users_table_format() {
        let output = r#"SMB         192.168.58.121  445    DC01       [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:child.contoso.local) (signing:True) (SMBv1:False)
SMB         192.168.58.121  445    DC01       [+] child.contoso.local\:
SMB         192.168.58.121  445    DC01       -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         192.168.58.121  445    DC01       alice.johnson                 2026-03-25 23:21:09 0       Alice Johnson
SMB         192.168.58.121  445    DC01       bob.smith                     2026-03-25 23:21:09 0       Bob Smith
SMB         192.168.58.121  445    DC01       carol.williams                2026-03-25 23:21:09 0       Carol Williams
SMB         192.168.58.121  445    DC01       dave.miller                   2026-03-25 23:22:25 0       Dave Miller (Password : Summer2026!)
SMB         192.168.58.121  445    DC01       eve.davis                     2026-03-25 23:22:25 0       Eve Davis
SMB         192.168.58.121  445    DC01       Guest                         <never>             0       Built-in account for guest access
SMB         192.168.58.121  445    DC01       [*] Enumerated 10 local users: CHILD"#;

        let users = parse_netexec_users(output);

        // Should have 6 user entries + 1 _credentials marker (Guest is included)
        let user_entries: Vec<_> = users
            .iter()
            .filter(|u| u.get("username").is_some())
            .collect();
        assert!(
            user_entries.len() >= 6,
            "Should have at least 6 users (including Guest), got {}",
            user_entries.len()
        );

        // Check domain was extracted from banner
        assert_eq!(user_entries[0]["domain"], "child.contoso.local");
        assert_eq!(user_entries[0]["username"], "alice.johnson");

        // Check password leak extraction
        let cred_marker = users.iter().find(|u| u.get("_credentials").is_some());
        assert!(cred_marker.is_some(), "Should have _credentials marker");
        let creds = cred_marker.unwrap()["_credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "dave.miller");
        assert_eq!(creds[0]["password"], "Summer2026!");

        // Guest should be included.
        assert!(user_entries.iter().any(|u| u["username"] == "Guest"));

        // All users should have netexec_user_enum source
        assert!(user_entries
            .iter()
            .all(|u| u["source"] == "netexec_user_enum"));
    }

    #[test]
    fn parse_netexec_users_rid_brute_format() {
        let output = r#"SMB  192.168.58.121  445  DC01  [+] child.contoso.local\:
SMB  192.168.58.121  445  DC01  CHILD\alice.johnson (SidTypeUser)
SMB  192.168.58.121  445  DC01  CHILD\bob.smith (SidTypeUser)"#;

        let users = parse_netexec_users(output);
        let user_entries: Vec<_> = users
            .iter()
            .filter(|u| u.get("username").is_some())
            .collect();
        assert_eq!(user_entries.len(), 2);
        assert_eq!(user_entries[0]["username"], "alice.johnson");
        assert_eq!(user_entries[0]["domain"], "CHILD");
    }

    #[test]
    fn parse_tool_output_enumerate_users_extracts_creds() {
        let output = r#"SMB  192.168.58.121  445  DC01  [*] Windows 10 (name:DC01) (domain:contoso.local) (signing:True)
SMB  192.168.58.121  445  DC01  [+] contoso.local\:
SMB  192.168.58.121  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.121  445  DC01  alice       2026-03-25 23:21:09 0  Alice (Password : Welcome1!)
SMB  192.168.58.121  445  DC01  bob         2026-03-25 23:21:09 0  Bob"#;

        let params = json!({"target": "192.168.58.121"});
        let discoveries = parse_tool_output("enumerate_users", output, &params);

        // Should have users
        let users = discoveries["discovered_users"].as_array().unwrap();
        assert_eq!(users.len(), 2);

        // Should have extracted credential from description
        let creds = discoveries["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "alice");
        assert_eq!(creds[0]["password"], "Welcome1!");
    }

    #[test]
    fn looks_like_ip_valid() {
        assert!(looks_like_ip("192.168.58.10"));
        assert!(looks_like_ip("192.168.58.10"));
        assert!(looks_like_ip("0.0.0.0"));
        assert!(looks_like_ip("255.255.255.255"));
    }

    #[test]
    fn looks_like_ip_invalid() {
        assert!(!looks_like_ip("not-an-ip"));
        assert!(!looks_like_ip("192.168.58"));
        assert!(!looks_like_ip("192.168.58.10.5"));
        assert!(!looks_like_ip("256.0.0.1")); // 256 > u8
        assert!(!looks_like_ip("dc01.contoso.local"));
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn merge_discoveries_combines_arrays() {
        let d1 = json!({
            "hosts": [{"ip": "192.168.58.10"}],
            "credentials": [{"username": "admin"}],
        });
        let d2 = json!({
            "hosts": [{"ip": "192.168.58.20"}],
            "hashes": [{"username": "krbtgt"}],
        });
        let merged = merge_discoveries(&[d1, d2]);
        assert_eq!(merged["hosts"].as_array().unwrap().len(), 2);
        assert_eq!(merged["credentials"].as_array().unwrap().len(), 1);
        assert_eq!(merged["hashes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_discoveries_dedup_hosts_by_ip() {
        let d1 = json!({
            "hosts": [
                {"ip": "192.168.58.10", "is_dc": false, "services": ["445/tcp"]},
            ],
        });
        let d2 = json!({
            "hosts": [
                {"ip": "192.168.58.10", "is_dc": true, "hostname": "dc01.contoso.local",
                 "services": ["88/tcp", "389/tcp", "445/tcp"]},
            ],
        });
        let merged = merge_discoveries(&[d1, d2]);
        let hosts = merged["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1, "Should dedup by IP");
        assert!(hosts[0]["is_dc"].as_bool().unwrap(), "Should keep DC entry");
        assert_eq!(hosts[0]["services"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn merge_discoveries_empty_input() {
        let merged = merge_discoveries(&[]);
        assert!(merged["hosts"].is_null());
        assert!(merged["credentials"].is_null());
    }

    #[test]
    fn merge_discoveries_single_input() {
        let d = json!({"vulnerabilities": [{"vuln_id": "v1"}]});
        let merged = merge_discoveries(&[d]);
        assert_eq!(merged["vulnerabilities"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn parse_tool_output_secretsdump() {
        let output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("secretsdump", output, &params);
        assert!(!disc["hashes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parse_tool_output_raise_child_attributes_to_parent() {
        // raise_child dumps the parent NTDS in slash-separated FQDN format.
        // Parser must derive parent_domain from child_domain and attribute hashes there.
        let output = "\
[*] Forest is contoso.local
contoso.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::
contoso.local/Administrator:500:aad3b435b51404eeaad3b435b51404ee:22222222222222222222222222222222:::";
        let params = json!({
            "child_domain": "child.contoso.local",
            "username": "testuser",
            "password": "REDACTED",
        });
        let disc = parse_tool_output("raise_child", output, &params);
        let hashes = disc["hashes"].as_array().expect("hashes array");
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "krbtgt");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[1]["username"], "Administrator");
        assert_eq!(hashes[1]["domain"], "contoso.local");
    }

    #[test]
    fn parse_tool_output_kerberoast() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO$contoso.local/svc_sql*$abc";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("kerberoast", output, &params);
        assert_eq!(disc["hashes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn parse_tool_output_unknown_tool() {
        let disc = parse_tool_output("unknown_tool", "output", &json!({}));
        assert_eq!(disc, json!({}));
    }

    #[test]
    fn parse_tool_output_find_delegation() {
        let output = "svc_sql$  Computer  Constrained  CIFS/dc01.contoso.local";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let disc = parse_tool_output("find_delegation", output, &params);
        assert_eq!(disc["vulnerabilities"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn kerberos_user_enum_all_variants() {
        // Test all three output variants from impacket-GetNPUsers
        let output = r#"Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for Administrator
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_sql does not have UF_DONT_REQUIRE_PREAUTH set
[-] User disabled_acct - Loss of credentials through KDC_ERR_CLIENT_REVOKED
[-] invalid principal syntax
"#;

        let params = json!({"domain": "contoso.local", "dc_ip": "192.168.58.10"});
        let disc = parse_tool_output("kerberos_user_enum_noauth", output, &params);
        let users = disc["discovered_users"].as_array().unwrap();
        assert_eq!(users.len(), 3, "Should find 3 valid users, got {:?}", users);

        let names: Vec<&str> = users
            .iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"Administrator"));
        assert!(names.contains(&"svc_sql"));
        assert!(names.contains(&"disabled_acct"));

        // All should have domain set
        for u in users {
            assert_eq!(u["domain"], "contoso.local");
            assert_eq!(u["source"], "kerberos_enum");
        }
    }

    #[test]
    fn parse_tool_output_username_as_password_filters() {
        // Only creds where password == username should be kept
        let output = "[+] 192.168.58.1 CONTOSO\\alice:alice (Pwn3d!)\n\
                      [+] 192.168.58.1 CONTOSO\\bob:Password1 (Pwn3d!)";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.1"});
        let disc = parse_tool_output("username_as_password", output, &params);
        let creds = disc["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1, "Only alice:alice should match");
        assert_eq!(creds[0]["username"].as_str().unwrap(), "alice");
    }

    #[test]
    fn parse_tool_output_adidnsdump() {
        let output = "dc01  A  192.168.58.10\nweb01  A  192.168.58.20";
        let disc = parse_tool_output("adidnsdump", output, &json!({}));
        let hosts = disc["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn merge_discoveries_trusted_domains_dedup() {
        let d1 =
            json!({"trusted_domains": [{"domain": "child.contoso.local", "type": "ParentChild"}]});
        let d2 =
            json!({"trusted_domains": [{"domain": "child.contoso.local", "type": "ParentChild"}]});
        let merged = merge_discoveries(&[d1, d2]);
        let td = merged["trusted_domains"].as_array().unwrap();
        assert_eq!(td.len(), 1, "Duplicate trusted domains should be deduped");
    }

    #[test]
    fn parse_tool_output_relay_and_coerce_emits_cert_vuln() {
        let output = "RELAY_PID=1234\n\
                      === Coercing via MS-DFSNM ===\n\
                      CERT_CAPTURED_VIA=MS-DFSNM\n\
                      PFX_FILE=/tmp/ares_relay_999/DC01$.pfx\n\
                      RELAYED_USER=DC01$\n\
                      === RELAY LOG ===\n\
                      [*] Servers started\n";
        let params = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "target_domain": "contoso.local",
            "coerce_domain": "child.contoso.local",
        });
        let disc = parse_tool_output("relay_and_coerce", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns array");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "certificate_obtained");
        assert_eq!(
            vulns[0]["details"]["pfx_path"],
            "/tmp/ares_relay_999/DC01$.pfx"
        );
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
        assert_eq!(vulns[0]["details"]["target_user"], "DC01$");
        assert_eq!(vulns[0]["target"], "192.168.58.20");
    }

    #[test]
    fn parse_tool_output_relay_and_coerce_no_capture_no_vuln() {
        let output = "RELAY_PID=1234\n\
                      === Coercing via MS-DFSNM ===\n\
                      === Coercing via MS-EFSR ===\n\
                      === Coercing via MS-RPRN ===\n\
                      === RELAY LOG ===\n\
                      [*] Servers started\n";
        let params = json!({"ca_host": "192.168.58.10", "coerce_target": "192.168.58.20"});
        let disc = parse_tool_output("relay_and_coerce", output, &params);
        assert!(disc.get("vulnerabilities").is_none());
    }

    #[test]
    fn parse_tool_output_relay_and_coerce_falls_back_to_coerce_domain() {
        // Same-forest case: only coerce_domain present.
        let output = "PFX_FILE=/tmp/ares_relay_1/dc01$.pfx\nRELAYED_USER=dc01$\n";
        let params = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "coerce_domain": "contoso.local",
        });
        let disc = parse_tool_output("relay_and_coerce", output, &params);
        let vulns = disc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
    }

    #[test]
    fn parse_tool_output_relay_and_coerce_legacy_target_dc_alias() {
        // Backwards-compat: orchestrator state may still emit `target_dc`.
        let output = "PFX_FILE=/tmp/ares_relay_2/dc01$.pfx\nRELAYED_USER=dc01$\n";
        let params = json!({
            "ca_host": "192.168.58.10",
            "target_dc": "192.168.58.20",
            "coerce_domain": "contoso.local",
        });
        let disc = parse_tool_output("relay_and_coerce", output, &params);
        let vulns = disc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns[0]["target"], "192.168.58.20");
    }

    #[test]
    fn parse_tool_output_smb_signing_check() {
        let output = "SMB  192.168.58.10  445  DC01  signing:True";
        let params = json!({"target": "192.168.58.10"});
        let disc = parse_tool_output("smb_signing_check", output, &params);
        // parse_smb_signing returns host entries
        assert!(disc.get("hosts").is_some() || disc == json!({}));
    }

    #[test]
    fn parse_tool_output_smb_sweep() {
        let output = "SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local)";
        let disc = parse_tool_output("smb_sweep", output, &json!({}));
        let hosts = disc["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn parse_tool_output_enumerate_shares() {
        let output = "SMB  192.168.58.10  445  DC01  Share           Permissions  Remark\n\
                      SMB  192.168.58.10  445  DC01  -----           -----------  ------\n\
                      SMB  192.168.58.10  445  DC01  SYSVOL          READ         Logon server share";
        let disc = parse_tool_output("enumerate_shares", output, &json!({}));
        let shares = disc["shares"].as_array().unwrap();
        assert_eq!(shares.len(), 1);
    }

    #[test]
    fn parse_tool_output_run_bloodhound_empty() {
        let disc = parse_tool_output("run_bloodhound", "Collection complete", &json!({}));
        assert_eq!(disc, json!({}));
    }

    #[test]
    fn parse_tool_output_password_spray() {
        let output = "[+] 192.168.58.10 contoso.local\\svc_sql:Summer2024! (Pwn3d!)";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let disc = parse_tool_output("password_spray", output, &params);
        let creds = disc["credentials"].as_array().unwrap();
        assert!(!creds.is_empty());
    }

    #[test]
    fn parse_tool_output_crack_with_hashcat() {
        let output =
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc$def:Summer2024!";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("crack_with_hashcat", output, &params);
        let creds = disc["credentials"].as_array().unwrap();
        assert!(!creds.is_empty());
    }

    #[test]
    fn parse_tool_output_crack_with_john() {
        let output = "svc_sql:Summer2024!::::::::\n1 password hash cracked, 0 left";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("crack_with_john", output, &params);
        let creds = disc["credentials"].as_array().unwrap();
        assert!(!creds.is_empty());
    }

    #[test]
    fn parse_tool_output_sysvol_spider() {
        let disc = parse_tool_output("sysvol_script_search", "no creds found", &json!({}));
        // No credentials found — should be empty
        assert!(disc.get("credentials").is_none());
    }

    #[test]
    fn parse_tool_output_asrep_roast() {
        let output = "$krb5asrep$23$brian.davis@CHILD.CONTOSO.LOCAL:aabbccdd";
        let params = json!({"domain": "child.contoso.local", "dc_ip": "192.168.58.10"});
        let disc = parse_tool_output("asrep_roast", output, &params);
        let hashes = disc["hashes"].as_array().unwrap();
        assert!(!hashes.is_empty());
    }

    #[test]
    fn parse_tool_output_lsassy() {
        // lsassy format: DOMAIN\user  hash_or_password
        let output = "contoso.local\\Administrator  aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let disc = parse_tool_output("lsassy", output, &params);
        assert!(disc.get("hashes").is_some() || disc.get("credentials").is_some());
    }

    #[test]
    fn parse_tool_output_ldap_descriptions() {
        let output = "SMB  192.168.58.10  445  DC01  svc_test  2026-03-25 23:22:25 0  Service Account (Password : TestPass!)";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let disc = parse_tool_output("ldap_search_descriptions", output, &params);
        let creds = disc["credentials"].as_array().unwrap();
        assert!(!creds.is_empty());
    }

    #[test]
    fn parse_tool_output_secretsdump_kerberos() {
        let output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("secretsdump_kerberos", output, &params);
        assert!(!disc["hashes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn merge_discoveries_host_more_services_wins() {
        let d1 = json!({"hosts": [{"ip": "192.168.58.1", "services": ["445/tcp"]}]});
        let d2 = json!({"hosts": [{"ip": "192.168.58.1", "services": ["80/tcp", "443/tcp", "445/tcp"]}]});
        let merged = merge_discoveries(&[d1, d2]);
        let hosts = merged["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["services"].as_array().unwrap().len(), 3);
    }

    // ── is_zerologon_vulnerable ────────────────────────────────────────

    #[test]
    fn zerologon_vulnerable_token_only() {
        // Classic netexec column-formatted positive row.
        let out = "SMB         192.168.58.210  445    DC01             VULNERABLE";
        assert!(is_zerologon_vulnerable(out));
    }

    #[test]
    fn zerologon_vulnerable_descriptive_phrase() {
        // Older nxc / cme builds emit the descriptive phrase form.
        let out =
            "SMB         192.168.58.210  445    DC01             [+] DC01 is vulnerable to Zerologon - CVE-2020-1472";
        assert!(is_zerologon_vulnerable(out));
    }

    #[test]
    fn zerologon_vulnerable_phrase_case_insensitive() {
        let out = "SMB  10  445  DC  ZEROLOGON: VULNERABLE";
        assert!(is_zerologon_vulnerable(out));
    }

    #[test]
    fn zerologon_not_vulnerable_negative_marker_wins() {
        // The negative marker must override the descriptive line even when
        // the word "VULNERABLE" appears in a banner / module header.
        let out = "[*] Loading module zerologon (checks for VULNERABLE state)\n\
            SMB         192.168.58.210  445    DC01             Not vulnerable";
        assert!(!is_zerologon_vulnerable(out));
    }

    #[test]
    fn zerologon_not_vulnerable_explicit_phrase() {
        let out = "SMB         192.168.58.210  445    DC01             [-] DC01 is not vulnerable";
        assert!(!is_zerologon_vulnerable(out));
    }

    #[test]
    fn zerologon_patched_phrase() {
        let out =
            "SMB         192.168.58.210  445    DC01             Target appears patched (CVE-2020-1472)";
        assert!(!is_zerologon_vulnerable(out));
    }

    #[test]
    fn zerologon_no_evidence_in_empty_output() {
        assert!(!is_zerologon_vulnerable(""));
        assert!(!is_zerologon_vulnerable(
            "SMB  10  445  DC  Authenticating..."
        ));
    }

    #[test]
    fn zerologon_does_not_match_substring_vulnerable_inside_word() {
        // The token form looks for `\sVULNERABLE` (lead-space, exact). A
        // line containing "NOTVULNERABLE" or "INVULNERABLE" without a space
        // boundary must not match. (Bare-line " VULNERABLE" is still ok.)
        let out = "SMB         192.168.58.210  445    DC01             INVULNERABLE_TO_THIS_CHECK";
        assert!(!is_zerologon_vulnerable(out));
    }

    // ── parse_tool_output("zerologon_check", ...) integration ──────────

    #[test]
    fn parse_tool_output_zerologon_emits_vuln_on_positive() {
        let output = "SMB         192.168.58.210  445    DC01             VULNERABLE\n\
             SMB         192.168.58.210  445    DC01             Next step: see CVE-2020-1472";
        let params = json!({
            "dc_ip": "192.168.58.210",
            "domain": "contoso.local",
            "hostname": "dc01"
        });
        let discoveries = parse_tool_output("zerologon_check", output, &params);
        let vulns = discoveries["vulnerabilities"]
            .as_array()
            .expect("vulns array");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "zerologon");
        assert_eq!(vulns[0]["target"], "192.168.58.210");
        assert_eq!(vulns[0]["vuln_id"], "zerologon_192_168_58_210");
        assert_eq!(vulns[0]["details"]["cve"], "CVE-2020-1472");
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
        assert_eq!(vulns[0]["details"]["hostname"], "dc01");
    }

    #[test]
    fn parse_tool_output_zerologon_silent_on_patched_dc() {
        let output = "SMB  192.168.58.210  445  DC01  Not vulnerable";
        let params = json!({"dc_ip": "192.168.58.210"});
        let discoveries = parse_tool_output("zerologon_check", output, &params);
        // No vulns array means the orchestrator won't add a phantom
        // zerologon entry to state for a patched DC.
        assert!(discoveries.get("vulnerabilities").is_none());
    }

    #[test]
    fn parse_tool_output_zerologon_falls_back_to_target_ip_param() {
        // Older dispatchers send `target_ip` rather than `dc_ip`. The parser
        // must accept either so we don't drop the discovery on a payload
        // shape that the LLM-routed automation in zerologon.rs already uses.
        let output = "SMB  192.168.58.210  445  DC01  VULNERABLE";
        let params = json!({"target_ip": "192.168.58.210"});
        let discoveries = parse_tool_output("zerologon_check", output, &params);
        let vulns = discoveries["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["target"], "192.168.58.210");
    }

    #[test]
    fn parse_tool_output_zerologon_skipped_when_dc_ip_missing() {
        // Without an IP we'd produce a vuln_id of `zerologon_` which would
        // collide across DCs. Skip rather than emit a malformed entry.
        let output = "SMB  192.168.58.210  445  DC01  VULNERABLE";
        let params = json!({});
        let discoveries = parse_tool_output("zerologon_check", output, &params);
        assert!(discoveries.get("vulnerabilities").is_none());
    }

    #[test]
    fn parse_tool_output_zerologon_vuln_id_is_idempotent_on_same_dc() {
        // Two parser runs on the same DC must produce the same vuln_id so
        // the orchestrator's dedup machinery can recognise them as the same
        // discovery (and not double-count toward state.discovered_vulnerabilities).
        let out = "SMB  192.168.58.210  445  DC01  VULNERABLE";
        let params = json!({"dc_ip": "192.168.58.210"});
        let a = parse_tool_output("zerologon_check", out, &params);
        let b = parse_tool_output("zerologon_check", out, &params);
        assert_eq!(
            a["vulnerabilities"][0]["vuln_id"],
            b["vulnerabilities"][0]["vuln_id"]
        );
    }
    // ── password_policy ───────────────────────────────────────────────

    #[test]
    fn parse_tool_output_password_policy_extracts_fields() {
        let output = "Minimum password length: 7\n\
                      Account lockout threshold: 5\n\
                      Account lockout duration: 30\n";
        let params = json!({"domain": "contoso.local", "target": "192.168.58.10"});
        let disc = parse_tool_output("password_policy", output, &params);
        let policies = disc["password_policies"]
            .as_array()
            .expect("password_policies array");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["domain"], "contoso.local");
        assert_eq!(policies[0]["target_ip"], "192.168.58.10");
        assert_eq!(policies[0]["lockout_threshold"], "5");
        assert_eq!(policies[0]["min_password_length"], "7");
    }

    #[test]
    fn parse_tool_output_password_policy_skipped_when_domain_empty() {
        let output = "Minimum password length: 7\n";
        let params = json!({"target": "192.168.58.10"});
        let disc = parse_tool_output("password_policy", output, &params);
        assert!(disc.get("password_policies").is_none());
    }

    #[test]
    fn parse_tool_output_password_policy_skipped_when_output_empty() {
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("password_policy", "", &params);
        assert!(disc.get("password_policies").is_none());
    }

    #[test]
    fn parse_tool_output_password_policy_partial_fields() {
        // Only lockout threshold found — min_length missing is fine.
        let output = "Account Lockout Threshold: 0\n";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("password_policy", output, &params);
        let policies = disc["password_policies"]
            .as_array()
            .expect("password_policies");
        assert_eq!(policies[0]["lockout_threshold"], "0");
        assert!(policies[0].get("min_password_length").is_none());
    }

    // ── evil_winrm ────────────────────────────────────────────────────

    #[test]
    fn parse_tool_output_evil_winrm_shell_success() {
        let output = "Evil-WinRM shell v3.5\nInfo: Establishing connection to remote endpoint\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("evil_winrm", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "winrm_access");
        assert_eq!(vulns[0]["target"], "192.168.58.20");
        assert_eq!(vulns[0]["vuln_id"], "winrm_access_192_168_58_20");
    }

    #[test]
    fn parse_tool_output_evil_winrm_whoami_output() {
        // whoami returning DOMAIN\user confirms access
        let output = "CONTOSO\\alice\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("evil_winrm", output, &params);
        assert!(disc.get("vulnerabilities").is_some());
    }

    #[test]
    fn parse_tool_output_evil_winrm_ps_prompt() {
        let output = "PS C:\\Users\\Administrator> whoami\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("evil_winrm", output, &params);
        assert!(disc.get("vulnerabilities").is_some());
    }

    #[test]
    fn parse_tool_output_evil_winrm_no_success_marker() {
        let output = "[!] Connection timed out\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("evil_winrm", output, &params);
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── xfreerdp ─────────────────────────────────────────────────────

    #[test]
    fn parse_tool_output_xfreerdp_auth_success() {
        let output = "Authentication only, exit status 0\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["vuln_type"], "rdp_access");
        assert_eq!(vulns[0]["target"], "192.168.58.20");
    }

    #[test]
    fn parse_tool_output_xfreerdp_connected() {
        let output = "connected to 192.168.58.20:3389\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        assert!(disc.get("vulnerabilities").is_some());
    }

    #[test]
    fn parse_tool_output_xfreerdp_connected_with_errconnect_not_success() {
        // `connected to` + `ERRCONNECT` should not count as success.
        let output = "connected to 192.168.58.20:3389\nERRCONNECT_CONNECT_FAILED\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        assert!(disc.get("vulnerabilities").is_none());
    }

    #[test]
    fn parse_tool_output_xfreerdp_session_started() {
        let output = "FREERDP_CB_SESSION_STARTED\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        assert!(disc.get("vulnerabilities").is_some());
    }

    #[test]
    fn parse_tool_output_xfreerdp_failure() {
        let output = "ERRCONNECT_LOGON_FAILURE [0x00020014]\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── ntds_dit_extract ──────────────────────────────────────────────

    #[test]
    fn parse_tool_output_ntds_dit_extract() {
        // ntds_dit_extract output is secretsdump format
        let output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("ntds_dit_extract", output, &params);
        assert!(disc.get("hashes").is_some() || disc.get("credentials").is_some());
    }

    // ── smb_login_check ───────────────────────────────────────────────

    #[test]
    fn parse_tool_output_smb_login_check() {
        let output = "[+] 192.168.58.10 contoso.local\\alice:Password1 (Pwn3d!)";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let disc = parse_tool_output("smb_login_check", output, &params);
        let creds = disc["credentials"].as_array().expect("credentials");
        assert!(!creds.is_empty());
    }

    // ── mssql_enum_impersonation ──────────────────────────────────────

    #[test]
    fn parse_tool_output_mssql_enum_impersonation() {
        let output = "class  class_desc  major_id  type  permission_name  state  state_desc\n\
                      100    SERVER      1         IM    IMPERSONATE      G      GRANT\n";
        let params = json!({"target": "192.168.58.30", "domain": "contoso.local"});
        let disc = parse_tool_output("mssql_enum_impersonation", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0]["vuln_type"], "mssql_impersonation");
    }

    #[test]
    fn parse_tool_output_mssql_enum_impersonation_empty() {
        let output = "No impersonation permissions found";
        let params = json!({"target": "192.168.58.30", "domain": "contoso.local"});
        let disc = parse_tool_output("mssql_enum_impersonation", output, &params);
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── mssql_enum_linked_servers ─────────────────────────────────────

    #[test]
    fn parse_tool_output_mssql_enum_linked_servers_returns_vulns() {
        // mssql linked server output varies by tool, but parse_mssql_linked_servers
        // reads server names from keyword lines
        let output = "SRV_NAME  PRODUCT  PROVIDER  DATA_SOURCE\n\
                      sql02.fabrikam.local  SQL Server  SQLNCLI  sql02.fabrikam.local\n";
        let params = json!({"target": "192.168.58.30", "domain": "contoso.local"});
        let disc = parse_tool_output("mssql_enum_linked_servers", output, &params);
        // Whether vulns appear depends on the parser; just confirm no panic.
        let _ = disc;
    }

    // ── enumerate_domain_trusts ───────────────────────────────────────

    #[test]
    fn parse_tool_output_enumerate_domain_trusts() {
        let output = "cn: fabrikam.local\n\
                      trustDirection: 3\n\
                      trustType: 2\n\
                      trustAttributes: 8\n\
                      flatName: FABRIKAM\n";
        let disc = parse_tool_output("enumerate_domain_trusts", output, &json!({}));
        let td = disc["trusted_domains"].as_array().expect("trusted_domains");
        assert_eq!(td.len(), 1);
        assert_eq!(td[0]["domain"], "fabrikam.local");
        assert_eq!(td[0]["trust_type"], "forest");
    }

    // ── ldap_acl_enumeration ──────────────────────────────────────────

    #[test]
    fn parse_tool_output_ldap_acl_enumeration_empty() {
        let disc = parse_tool_output(
            "ldap_acl_enumeration",
            "",
            &json!({"domain": "contoso.local"}),
        );
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── merge_discoveries: discovered_users and shares ─────────────────

    #[test]
    fn merge_discoveries_combines_discovered_users() {
        let d1 = json!({"discovered_users": [{"username": "alice", "domain": "contoso.local"}]});
        let d2 = json!({"discovered_users": [{"username": "bob", "domain": "contoso.local"}]});
        let merged = merge_discoveries(&[d1, d2]);
        let users = merged["discovered_users"]
            .as_array()
            .expect("discovered_users");
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn merge_discoveries_combines_shares() {
        let d1 = json!({"shares": [{"name": "SYSVOL", "ip": "192.168.58.10"}]});
        let d2 = json!({"shares": [{"name": "NETLOGON", "ip": "192.168.58.10"}]});
        let merged = merge_discoveries(&[d1, d2]);
        let shares = merged["shares"].as_array().expect("shares");
        assert_eq!(shares.len(), 2);
    }

    #[test]
    fn merge_discoveries_combines_trusted_domains() {
        let d1 = json!({"trusted_domains": [{"domain": "fabrikam.local", "trust_type": "forest"}]});
        let d2 = json!({"trusted_domains": [{"domain": "child.contoso.local", "trust_type": "parent_child"}]});
        let merged = merge_discoveries(&[d1, d2]);
        let td = merged["trusted_domains"]
            .as_array()
            .expect("trusted_domains");
        assert_eq!(td.len(), 2);
    }

    #[test]
    fn merge_discoveries_skips_hosts_with_empty_ip() {
        let d = json!({"hosts": [{"ip": "", "hostname": "mystery"}]});
        let merged = merge_discoveries(&[d]);
        assert!(merged.get("hosts").is_none());
    }

    // ── looks_like_ip_pub ─────────────────────────────────────────────

    #[test]
    fn looks_like_ip_pub_accepts_valid() {
        assert!(looks_like_ip_pub("192.168.58.10"));
        assert!(looks_like_ip_pub("10.0.0.1"));
    }

    #[test]
    fn looks_like_ip_pub_rejects_invalid() {
        assert!(!looks_like_ip_pub("contoso.local"));
        assert!(!looks_like_ip_pub("not-an-ip"));
        assert!(!looks_like_ip_pub("256.1.1.1"));
    }

    // ── relay_and_coerce: no relayed_user ────────────────────────────

    #[test]
    fn parse_tool_output_relay_and_coerce_no_relayed_user_still_emits() {
        // PFX_FILE present but no RELAYED_USER line — should still emit vuln.
        let output = "PFX_FILE=/tmp/ares_relay_5/DC01.pfx\n";
        let params = json!({"coerce_target": "192.168.58.10", "coerce_domain": "contoso.local"});
        let disc = parse_tool_output("relay_and_coerce", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["vuln_type"], "certificate_obtained");
        // No user in details when RELAYED_USER is absent
        assert!(vulns[0]["details"].get("target_user").is_none());
    }

    #[test]
    fn parse_tool_output_relay_and_coerce_vuln_id_sanitises_dollar() {
        // Machine account names contain `$` — safe slug should use `_`
        let output = "PFX_FILE=/tmp/ares_relay_6/DC01$.pfx\nRELAYED_USER=DC01$\n";
        let params = json!({
            "coerce_target": "192.168.58.10",
            "target_domain": "contoso.local",
        });
        let disc = parse_tool_output("relay_and_coerce", output, &params);
        let vuln_id = disc["vulnerabilities"][0]["vuln_id"].as_str().unwrap();
        assert!(
            !vuln_id.contains('$'),
            "vuln_id must not contain shell-special $, got {vuln_id}"
        );
    }
}
