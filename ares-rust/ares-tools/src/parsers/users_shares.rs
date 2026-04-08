//! NetExec user and share enumeration parsers.

use serde_json::{json, Value};

/// Parse netexec user enumeration output.
///
/// Handles two formats:
/// 1. `DOMAIN\username` lines (e.g. from `--rid-brute`)
/// 2. Table format from `--users`:
///    ```text
///    SMB  10.1.2.121  445  WINTERFELL  -Username-  -Last PW Set-  -BadPW- -Description-
///    SMB  10.1.2.121  445  WINTERFELL  arya.stark  2026-03-25 23:21:09  0  Arya Stark
///    ```
///
/// Also extracts embedded passwords from description fields like
/// `(Password : Heartsbane)`.
pub fn parse_netexec_users(output: &str) -> Vec<Value> {
    let mut users = Vec::new();
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Extract domain from SMB banner: (domain:north.sevenkingdoms.local)
    let mut detected_domain = String::new();
    for line in output.lines() {
        if let Some(start) = line.find("(domain:") {
            let rest = &line[start + 8..];
            if let Some(end) = rest.find(')') {
                detected_domain = rest[..end].trim().to_string();
                break;
            }
        }
    }

    let mut in_table = false;

    for line in output.lines() {
        let line = line.trim();

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // Format 1: DOMAIN\username lines (rid-brute style)
        if line.contains('\\')
            && !line.contains("[*]")
            && !line.contains("[+]")
            && !line.contains("[-]")
        {
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
            continue;
        }

        // Detect table header: "-Username-"
        if line.contains("-Username-") {
            in_table = true;
            continue;
        }

        // Format 2: Table rows after header
        // SMB  10.1.2.121  445  WINTERFELL  arya.stark  2026-03-25 23:21:09  0  Arya Stark
        if in_table && line.starts_with("SMB") {
            // Skip bracket lines
            if line.contains("[*]") || line.contains("[+]") || line.contains("[-]") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            // Minimum: SMB IP PORT HOSTNAME USERNAME DATE TIME BADPW
            // parts:   0   1  2    3        4        5    6    7    8..
            if parts.len() >= 8 {
                let username = parts[4].to_string();

                // Skip header remnants and special accounts
                if username.starts_with('-') || username.to_lowercase() == "guest" {
                    continue;
                }

                let domain = if !detected_domain.is_empty() {
                    detected_domain.clone()
                } else {
                    parts[3].to_string() // hostname as fallback
                };

                let key = format!("{}\\{}", domain.to_lowercase(), username.to_lowercase());
                if seen.insert(key) {
                    // Collect description (everything after badpw count at index 7)
                    let description = if parts.len() > 8 {
                        parts[8..].join(" ")
                    } else {
                        String::new()
                    };

                    users.push(json!({
                        "username": username,
                        "domain": domain,
                        "source": "enumerate_users",
                    }));

                    // Check for embedded passwords in description: (Password : XXX)
                    if let Some(pw_start) = description.find("(Password") {
                        let rest = &description[pw_start..];
                        if let Some(colon) = rest.find(':') {
                            let after_colon = &rest[colon + 1..];
                            let pw = if let Some(paren) = after_colon.find(')') {
                                after_colon[..paren].trim()
                            } else {
                                after_colon.trim()
                            };
                            if !pw.is_empty() {
                                credentials.push(json!({
                                    "id": format!("leaked-{}-{}", domain, username),
                                    "username": username,
                                    "password": pw,
                                    "domain": domain,
                                    "source": "user_description_leak",
                                    "is_admin": false,
                                    "attack_step": 0,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // If we found credentials from description leaks, append them as a special entry
    // so the caller can extract them. We use a convention: last element has _credentials key.
    if !credentials.is_empty() {
        users.push(json!({
            "_credentials": credentials,
        }));
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
