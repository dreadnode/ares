//! NetExec user and share enumeration parsers.

use serde_json::{json, Value};

/// Parse netexec user enumeration output.
///
/// Handles two formats:
/// 1. `DOMAIN\username` lines (e.g. from `--rid-brute`)
/// 2. Table format from `--users`:
///    ```text
///    SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
///    SMB  192.168.58.10  445  DC01  alice.johnson  2026-03-25 23:21:09  0  Alice Johnson
///    ```
///
/// Also extracts embedded passwords from description fields like
/// `(Password : Summer2026!)`.
pub fn parse_netexec_users(output: &str) -> Vec<Value> {
    let mut users = Vec::new();
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Extract domain from SMB banner: (domain:contoso.local)
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
        // SMB  192.168.58.10  445  DC01  alice.johnson  2026-03-25 23:21:09  0  Alice Johnson
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
        // Share lines: "SMB  192.168.58.10  445  DC01  SHARENAME  READ,WRITE"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_netexec_users_rid_brute() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Enumerating users
CONTOSO\\Administrator  (SidTypeUser)
CONTOSO\\jdoe  (SidTypeUser)
CONTOSO\\svc_sql  (SidTypeUser)";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 3);
        assert_eq!(users[0]["username"], "Administrator");
        assert_eq!(users[0]["domain"], "CONTOSO");
        assert_eq!(users[1]["username"], "jdoe");
        assert_eq!(users[2]["username"], "svc_sql");
    }

    #[test]
    fn test_parse_netexec_users_table_format() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  alice.j  2026-03-25 23:21:09  0  Alice Johnson
SMB  192.168.58.10  445  DC01  bob.s    2026-03-20 10:00:00  0  Bob Smith";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], "alice.j");
        assert_eq!(users[0]["domain"], "contoso.local"); // from domain: banner
        assert_eq!(users[1]["username"], "bob.s");
    }

    #[test]
    fn test_parse_netexec_users_with_password_leak() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  svc_test  2026-01-01 00:00:00  0  Service (Password : Summer2026!)";
        let users = parse_netexec_users(output);
        // Should have user + _credentials marker
        assert!(users.len() >= 2);
        let last = users.last().unwrap();
        let creds = last["_credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "svc_test");
        assert_eq!(creds[0]["password"], "Summer2026!");
        assert_eq!(creds[0]["source"], "user_description_leak");
    }

    #[test]
    fn test_parse_netexec_users_dedup() {
        let output = "\
CONTOSO\\jdoe  (SidTypeUser)
CONTOSO\\jdoe  (SidTypeUser)
CONTOSO\\JDOE  (SidTypeUser)";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1); // all three are the same user
    }

    #[test]
    fn test_parse_netexec_users_empty() {
        let users = parse_netexec_users("[*] No users found");
        assert!(users.is_empty());
    }

    #[test]
    fn test_parse_netexec_shares() {
        let output = "\
SMB  192.168.58.10  445  DC01  SYSVOL  READ
SMB  192.168.58.10  445  DC01  NETLOGON  READ
SMB  192.168.58.10  445  DC01  IT_Share  READ,WRITE";
        let shares = parse_netexec_shares(output);
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0]["name"], "SYSVOL");
        assert_eq!(shares[0]["access"], "READ");
        assert_eq!(shares[2]["name"], "IT_Share");
    }

    #[test]
    fn test_parse_netexec_shares_empty() {
        let shares = parse_netexec_shares("[*] No shares enumerated");
        assert!(shares.is_empty());
    }
}
