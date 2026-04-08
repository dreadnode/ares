//! Output parsers for tool results.
//!
//! Extract structured discovery data (hosts, open ports, credentials, etc.)
//! from raw CLI tool output. This replaces the LLM-based interpretation that
//! the Python workers used.

mod certipy;
mod credential_tools;
mod delegation;
mod nmap;
mod secrets;
mod smb;
mod users_shares;

use serde_json::{json, Value};

// Re-export all public parser functions at module level.
pub use certipy::parse_certipy_find;
pub use credential_tools::{
    parse_adidnsdump, parse_ldap_descriptions, parse_lsassy, parse_ntds_dit, parse_spray_success,
};
pub use delegation::{extract_delegation_account, parse_delegation};
pub use nmap::{flush_nmap_host, parse_nmap_output};
pub use secrets::{parse_asrep_roast, parse_kerberoast, parse_secretsdump};
pub use smb::{parse_netexec_smb, parse_smb_signing};
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
                discoveries["discovered_shares"] = Value::Array(shares);
            }
        }
        "run_bloodhound" => {
            // BloodHound collection doesn't produce immediate discoveries
        }
        "secretsdump" | "secretsdump_kerberos" => {
            let (hashes, creds) = parse_secretsdump(output, params);
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
        "asrep_roast" => {
            let hashes = parse_asrep_roast(output, params);
            if !hashes.is_empty() {
                discoveries["hashes"] = Value::Array(hashes);
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
        "password_spray" | "username_as_password" => {
            let creds = parse_spray_success(output, params);
            if !creds.is_empty() {
                discoveries["credentials"] = Value::Array(creds);
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
        _ => {}
    }

    discoveries
}

/// Merge discoveries from multiple tool outputs.
pub fn merge_discoveries(all: &[Value]) -> Value {
    let mut hosts = Vec::new();
    let mut credentials = Vec::new();
    let mut hashes = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut discovered_users = Vec::new();

    for disc in all {
        if let Some(h) = disc.get("hosts").and_then(|v| v.as_array()) {
            hosts.extend(h.iter().cloned());
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
    }

    let mut merged = json!({});
    if !hosts.is_empty() {
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
    merged
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_nmap_with_services() {
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
    fn test_parse_nmap_with_stderr_separator() {
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
    fn test_parse_nmap_fallback_no_output() {
        let output = "";
        let params = json!({"target": "192.168.58.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.210");
        assert!(hosts[0]["services"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_parse_nmap_multiple_hosts() {
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
    fn test_parse_netexec_users_table_format() {
        let output = r#"SMB         192.168.58.121  445    DC01       [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:north.contoso.local) (signing:True) (SMBv1:False)
SMB         192.168.58.121  445    DC01       [+] north.contoso.local\:
SMB         192.168.58.121  445    DC01       -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         192.168.58.121  445    DC01       alice.johnson                 2026-03-25 23:21:09 0       Alice Johnson
SMB         192.168.58.121  445    DC01       bob.smith                     2026-03-25 23:21:09 0       Bob Smith
SMB         192.168.58.121  445    DC01       carol.williams                2026-03-25 23:21:09 0       Carol Williams
SMB         192.168.58.121  445    DC01       dave.miller                   2026-03-25 23:22:25 0       Dave Miller (Password : Summer2026!)
SMB         192.168.58.121  445    DC01       eve.davis                     2026-03-25 23:22:25 0       Eve Davis
SMB         192.168.58.121  445    DC01       Guest                         <never>             0       Built-in account for guest access
SMB         192.168.58.121  445    DC01       [*] Enumerated 10 local users: NORTH"#;

        let users = parse_netexec_users(output);

        // Should have 5 user entries + 1 _credentials marker
        let user_entries: Vec<_> = users
            .iter()
            .filter(|u| u.get("username").is_some())
            .collect();
        assert!(
            user_entries.len() >= 5,
            "Should have at least 5 users, got {}",
            user_entries.len()
        );

        // Check domain was extracted from banner
        assert_eq!(user_entries[0]["domain"], "north.contoso.local");
        assert_eq!(user_entries[0]["username"], "alice.johnson");

        // Check password leak extraction
        let cred_marker = users.iter().find(|u| u.get("_credentials").is_some());
        assert!(cred_marker.is_some(), "Should have _credentials marker");
        let creds = cred_marker.unwrap()["_credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "dave.miller");
        assert_eq!(creds[0]["password"], "Summer2026!");

        // Guest should be excluded
        assert!(!user_entries.iter().any(|u| u["username"] == "Guest"));
    }

    #[test]
    fn test_parse_netexec_users_rid_brute_format() {
        let output = r#"SMB  192.168.58.121  445  DC01  [+] north.contoso.local\:
SMB  192.168.58.121  445  DC01  NORTH\alice.johnson (SidTypeUser)
SMB  192.168.58.121  445  DC01  NORTH\bob.smith (SidTypeUser)"#;

        let users = parse_netexec_users(output);
        let user_entries: Vec<_> = users
            .iter()
            .filter(|u| u.get("username").is_some())
            .collect();
        assert_eq!(user_entries.len(), 2);
        assert_eq!(user_entries[0]["username"], "alice.johnson");
        assert_eq!(user_entries[0]["domain"], "NORTH");
    }

    #[test]
    fn test_parse_tool_output_enumerate_users_extracts_creds() {
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
}
