//! NetExec user and share enumeration parsers.

use serde_json::{json, Value};

pub fn parse_netexec_users(output: &str) -> Vec<Value> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        // Lines like: "SMB  10.1.2.3  445  DC01  [+] Enumerated domain user(s)"
        // or user lines after enumeration
        if line.contains("\\") && !line.contains("[*]") && !line.contains("[+]") {
            // DOMAIN\username format
            if let Some(user_str) = line.split_whitespace().find(|p| p.contains('\\')) {
                let parts: Vec<&str> = user_str.splitn(2, '\\').collect();
                if parts.len() == 2 {
                    let domain = parts[0].to_string();
                    let username = parts[1].to_string();
                    let key = format!("{}\\{}", domain.to_lowercase(), username.to_lowercase());
                    if seen.insert(key) {
                        users.push(json!({
                            "username": username,
                            "domain": domain,
                            "source": "enumerate_users",
                        }));
                    }
                }
            }
        }
    }

    users
}

pub fn parse_netexec_shares(output: &str) -> Vec<Value> {
    let mut shares = Vec::new();

    for line in output.lines() {
        // Share lines: "SMB  10.1.2.3  445  DC01  SHARENAME  READ,WRITE"
        if line.contains("READ") || line.contains("WRITE") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                // Find the share name (usually after the hostname)
                for (i, part) in parts.iter().enumerate() {
                    if *part == "READ" || *part == "WRITE" || part.contains("READ") {
                        if i > 0 {
                            shares.push(json!({
                                "name": parts[i - 1],
                                "access": part,
                            }));
                        }
                        break;
                    }
                }
            }
        }
    }

    shares
}
