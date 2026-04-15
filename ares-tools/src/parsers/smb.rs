//! SMB-related output parsers (signing check, NetExec SMB sweep).

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::looks_like_ip;

static RE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(name:([^)]+)\)").unwrap());
static RE_DOMAIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(domain:([^)]+)\)").unwrap());

/// Extract `(name:X)` and `(domain:Y)` from a NetExec banner line and
/// construct an FQDN: `x.y` (lowercased).  Falls back to the positional
/// NetBIOS name when the parenthesised fields are absent.
fn extract_fqdn_from_line(line: &str, positional_name: &str) -> String {
    let name = RE_NAME
        .captures(line)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .unwrap_or_else(|| positional_name.to_string());

    let domain = RE_DOMAIN.captures(line).map(|c| {
        c.get(1)
            .unwrap()
            .as_str()
            .trim_end_matches("0.")
            .trim_end_matches('.')
            .to_string()
    });

    match domain {
        Some(d) if !d.is_empty() && !name.is_empty() && !name.contains('.') => {
            format!("{}.{}", name.to_lowercase(), d.to_lowercase())
        }
        _ => positional_name.to_string(),
    }
}

pub fn parse_smb_signing(output: &str, params: &Value) -> Vec<Value> {
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hosts = Vec::new();

    // Look for "message_signing: disabled" or "not required"
    let signing_disabled = output.to_lowercase().contains("signing: disabled")
        || output.to_lowercase().contains("not required")
        || output.to_lowercase().contains("message_signing: disabled");

    // Try to extract hostname from the output (NetExec banner lines)
    let hostname = output
        .lines()
        .find(|l| l.contains("SMB"))
        .map(|l| extract_fqdn_from_line(l, ""))
        .unwrap_or_default();

    if !target_ip.is_empty() {
        let mut services = vec!["445/tcp (microsoft-ds)".to_string()];
        if signing_disabled {
            services.push("smb_signing_disabled".to_string());
        }

        hosts.push(json!({
            "ip": target_ip,
            "hostname": hostname,
            "os": "",
            "roles": [],
            "services": services,
            "is_dc": false,
            "owned": false,
        }));
    }

    hosts
}

pub fn parse_netexec_smb(output: &str) -> Vec<Value> {
    let mut hosts = Vec::new();

    // NetExec SMB output:
    //   "SMB  192.168.58.12  445  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:contoso.local) (signing:True)"
    for line in output.lines() {
        if !line.contains("SMB") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Look for IP-like token
        for (i, part) in parts.iter().enumerate() {
            if looks_like_ip(part) {
                let netbios_name = parts.get(i + 2).copied().unwrap_or("");
                let hostname = extract_fqdn_from_line(line, netbios_name);
                let os = parts[i + 3..]
                    .iter()
                    .skip_while(|p| p.starts_with('['))
                    .take_while(|p| !p.starts_with('['))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");

                // DCs have signing:True and typically run kerberos (88) + ldap (389)
                let signing_true = line.contains("(signing:True)");
                let mut services = vec!["445/tcp (microsoft-ds)".to_string()];
                if signing_true {
                    services.push("88/tcp (kerberos-sec)".to_string());
                    services.push("389/tcp (ldap)".to_string());
                }

                hosts.push(json!({
                    "ip": part,
                    "hostname": hostname,
                    "os": os,
                    "roles": [],
                    "services": services,
                    "is_dc": signing_true,
                    "owned": false,
                }));
                break;
            }
        }
    }

    hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_smb_signing_disabled() {
        let output = "SMB signing: disabled";
        let params = json!({"target_ip": "192.168.58.10"});
        let hosts = parse_smb_signing(output, &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        let services = hosts[0]["services"].as_array().unwrap();
        assert!(services.iter().any(|s| s == "smb_signing_disabled"));
    }

    #[test]
    fn test_parse_smb_signing_enabled() {
        let output = "SMB signing: required";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_smb_signing(output, &params);
        assert_eq!(hosts.len(), 1);
        let services = hosts[0]["services"].as_array().unwrap();
        assert!(!services.iter().any(|s| s == "smb_signing_disabled"));
    }

    #[test]
    fn test_parse_smb_signing_not_required() {
        let output = "message_signing: not required";
        let params = json!({"target_ip": "192.168.58.20"});
        let hosts = parse_smb_signing(output, &params);
        let services = hosts[0]["services"].as_array().unwrap();
        assert!(services.iter().any(|s| s == "smb_signing_disabled"));
    }

    #[test]
    fn test_parse_smb_signing_no_target() {
        let hosts = parse_smb_signing("signing: disabled", &json!({}));
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_netexec_smb_with_fqdn() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:contoso.local) (signing:True)
SMB  192.168.58.20  445  SRV01  [*] Windows Server 2016 Build 14393 x64 (name:SRV01) (domain:contoso.local) (signing:False)";
        let hosts = parse_netexec_smb(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
        assert_eq!(hosts[1]["ip"], "192.168.58.20");
        assert_eq!(hosts[1]["hostname"], "srv01.contoso.local");
    }

    #[test]
    fn test_parse_netexec_smb_without_domain() {
        // Fallback: no (name:...) (domain:...) → bare NetBIOS name
        let output = "SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 Build 17763 x64";
        let hosts = parse_netexec_smb(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["hostname"], "DC01");
    }

    #[test]
    fn test_parse_netexec_smb_empty() {
        let hosts = parse_netexec_smb("No SMB hosts found");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_extract_fqdn_from_line() {
        let line = "SMB  192.168.58.12  445  DC01  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:contoso.local) (signing:True)";
        assert_eq!(extract_fqdn_from_line(line, "DC01"), "dc01.contoso.local");
    }

    #[test]
    fn test_extract_fqdn_trailing_zero() {
        let line = "SMB  192.168.58.22  445  SRV01  [*] ... (name:SRV01) (domain:child.contoso.local0.) (signing:False)";
        assert_eq!(
            extract_fqdn_from_line(line, "SRV01"),
            "srv01.child.contoso.local"
        );
    }

    #[test]
    fn test_extract_fqdn_no_domain() {
        let line = "SMB  192.168.58.12  445  DC01  [*] Windows Server 2019";
        assert_eq!(extract_fqdn_from_line(line, "DC01"), "DC01");
    }
}
