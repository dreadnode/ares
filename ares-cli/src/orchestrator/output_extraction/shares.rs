use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::Share;

static RE_SMB_IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+").unwrap());

static RE_SMB_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^SMB\s+\S+\s+\d+\s+\S+\s+").unwrap());

pub fn extract_shares(output: &str) -> Vec<Share> {
    let mut shares = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_ip = String::new();
    let mut in_table = false;
    let valid_perms = ["read", "write", "read,write", "write,read"];

    for line in output.lines() {
        let stripped = line.trim();

        // Track current IP
        if let Some(caps) = RE_SMB_IP.captures(stripped) {
            current_ip = caps.get(1).unwrap().as_str().to_string();
        }

        // Strip SMB prefix to get body
        let body = RE_SMB_PREFIX.replace(stripped, "").to_string();
        let body = body.trim();

        if body.is_empty() {
            continue;
        }

        // Detect table header
        let body_lower = body.to_lowercase();
        if body_lower.starts_with("share") && body_lower.contains("permission") {
            in_table = true;
            continue;
        }

        // Skip separator lines
        if body.chars().all(|c| c == '-' || c == ' ') {
            continue;
        }

        if in_table && !current_ip.is_empty() {
            // Table ends at enumeration summary or empty body
            if body.starts_with('[') {
                in_table = false;
                continue;
            }

            // Split on whitespace runs (columns are separated by multiple spaces)
            let parts: Vec<&str> = body.split_whitespace().collect();
            if parts.len() >= 2 {
                let share_name = parts[0].to_string();
                let perm = parts[1].to_lowercase();
                if valid_perms.contains(&perm.as_str()) {
                    let comment = if parts.len() >= 3 {
                        parts[2..].join(" ")
                    } else {
                        String::new()
                    };
                    let key = format!("{}:{}", current_ip, share_name);
                    if seen.insert(key) {
                        shares.push(Share {
                            host: current_ip.clone(),
                            name: share_name,
                            permissions: perm.to_uppercase(),
                            comment,
                        });
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
    fn extract_shares_from_table() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*]  Windows Server 2019 Build 17763 (name:DC01) (domain:contoso.local) (signing:True)
SMB  192.168.58.10  445  DC01  Share           Permissions     Remark
SMB  192.168.58.10  445  DC01  -----           -----------     ------
SMB  192.168.58.10  445  DC01  ADMIN$          READ,WRITE      Remote Admin
SMB  192.168.58.10  445  DC01  C$              READ,WRITE      Default share
SMB  192.168.58.10  445  DC01  NETLOGON        READ            Logon server share
SMB  192.168.58.10  445  DC01  SYSVOL          READ            Logon server share";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 4);
        assert_eq!(shares[0].host, "192.168.58.10");
        assert_eq!(shares[0].name, "ADMIN$");
        assert_eq!(shares[0].permissions, "READ,WRITE");
    }

    #[test]
    fn extract_shares_dedup_by_ip_name() {
        let output = "\
SMB  192.168.58.10  445  DC01  Share           Permissions     Remark
SMB  192.168.58.10  445  DC01  -----           -----------     ------
SMB  192.168.58.10  445  DC01  SYSVOL          READ            Logon server share
SMB  192.168.58.10  445  DC01  SYSVOL          READ            Logon server share";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 1);
    }

    #[test]
    fn extract_shares_empty_input() {
        assert!(extract_shares("").is_empty());
    }

    #[test]
    fn extract_shares_no_table() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Some banner info";
        assert!(extract_shares(output).is_empty());
    }

    #[test]
    fn extract_shares_with_comment() {
        let output = "\
SMB  192.168.58.10  445  DC01  Share           Permissions     Remark
SMB  192.168.58.10  445  DC01  -----           -----------     ------
SMB  192.168.58.10  445  DC01  Data$           READ            Company data share";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].comment, "Company data share");
    }
}
