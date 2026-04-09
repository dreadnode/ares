//! SMB-related output parsers (signing check, NetExec SMB sweep).

use serde_json::{json, Value};

use super::looks_like_ip;

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

    if !target_ip.is_empty() {
        let mut services = vec!["445/tcp (microsoft-ds)".to_string()];
        if signing_disabled {
            services.push("smb_signing_disabled".to_string());
        }

        hosts.push(json!({
            "ip": target_ip,
            "hostname": "",
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

    // NetExec SMB output: "SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 ..."
    for line in output.lines() {
        if !line.contains("SMB") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Look for IP-like token
        for (i, part) in parts.iter().enumerate() {
            if looks_like_ip(part) {
                let hostname = parts.get(i + 2).copied().unwrap_or("");
                let os = parts[i + 3..]
                    .iter()
                    .skip_while(|p| p.starts_with('['))
                    .take_while(|p| !p.starts_with('['))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");

                hosts.push(json!({
                    "ip": part,
                    "hostname": hostname,
                    "os": os,
                    "roles": [],
                    "services": ["445/tcp (microsoft-ds)"],
                    "is_dc": false,
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
    fn test_parse_netexec_smb() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 Build 17763 x64
SMB  192.168.58.20  445  SRV01  [*] Windows Server 2016 Build 14393 x64";
        let hosts = parse_netexec_smb(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "DC01");
        assert_eq!(hosts[1]["ip"], "192.168.58.20");
        assert_eq!(hosts[1]["hostname"], "SRV01");
    }

    #[test]
    fn test_parse_netexec_smb_empty() {
        let hosts = parse_netexec_smb("No SMB hosts found");
        assert!(hosts.is_empty());
    }
}
