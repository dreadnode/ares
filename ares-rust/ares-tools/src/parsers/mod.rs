//! Output parsers for tool results.
//!
//! Extract structured discovery data (hosts, open ports, credentials, etc.)
//! from raw CLI tool output. This replaces the LLM-based interpretation that
//! the Python workers used.

mod certipy;
mod delegation;
mod nmap;
mod secrets;
mod smb;
mod users_shares;

use serde_json::{json, Value};

// Re-export all public parser functions at module level.
pub use certipy::parse_certipy_find;
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
            // User enumeration doesn't produce hosts/creds directly,
            // but we extract usernames for downstream spray attacks
            let users = parse_netexec_users(output);
            if !users.is_empty() {
                discoveries["discovered_users"] = Value::Array(users);
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
Nmap scan report for ip-10-1-2-210.us-west-2.compute.internal (10.1.2.210)
Host is up (0.0010s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 4.32 seconds"#;

        let params = json!({"target": "10.1.2.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1, "Should produce exactly one host");
        let host = &hosts[0];
        assert_eq!(host["ip"], "10.1.2.210");
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
Nmap scan report for dc01.contoso.local (10.1.2.210)\n\
PORT    STATE SERVICE\n\
88/tcp  open  kerberos-sec\n\
389/tcp open  ldap\n\
445/tcp open  microsoft-ds\n\
\n\
Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds\n\
\n\
--- stderr ---\n\
Warning: some warning here";

        let params = json!({"target": "10.1.2.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert_eq!(host["ip"], "10.1.2.210");
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
        let params = json!({"target": "10.1.2.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "10.1.2.210");
        assert!(hosts[0]["services"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_parse_nmap_multiple_hosts() {
        let output = "Nmap scan report for dc01.contoso.local (10.1.2.210)\n\
PORT    STATE SERVICE\n\
88/tcp  open  kerberos-sec\n\
445/tcp open  microsoft-ds\n\
\n\
Nmap scan report for srv01.contoso.local (10.1.2.211)\n\
PORT     STATE SERVICE\n\
445/tcp  open  microsoft-ds\n\
1433/tcp open  ms-sql-s";

        let params = json!({"target": "10.1.2.210"});
        let hosts = parse_nmap_output(output, &params);

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "10.1.2.210");
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
        assert_eq!(hosts[1]["ip"], "10.1.2.211");
        assert!(!hosts[1]["is_dc"].as_bool().unwrap());
    }
}
