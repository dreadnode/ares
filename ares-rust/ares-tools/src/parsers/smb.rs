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

    // NetExec SMB output: "SMB  10.1.2.3  445  DC01  [*] Windows Server 2019 ..."
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
