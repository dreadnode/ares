//! SMB share extraction from netexec/crackmapexec output.

use regex::Regex;
use std::sync::LazyLock;

use super::types::ParsedShare;

static SMB_SHARE_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+").expect("smb share prefix regex")
});

static SHARE_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(\S+)\s+(READ,\s*WRITE|READ|WRITE|NO ACCESS)\s*(.*)?$")
        .expect("share line regex")
});

/// Extract SMB shares from netexec/crackmapexec output.
///
/// Lines are expected to start with `SMB  <ip>` followed by share information.
pub fn extract_shares(output: &str) -> Vec<ParsedShare> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Extract host IP from SMB prefix
        let host = match SMB_SHARE_PREFIX_RE.captures(line) {
            Some(caps) => caps[1].to_string(),
            None => continue,
        };

        // Remove the SMB prefix to get share details
        let after_prefix = SMB_SHARE_PREFIX_RE.replace(line, "");
        let rest = after_prefix.trim();

        // Skip non-share lines (banners, status lines)
        if rest.starts_with('[') || rest.is_empty() {
            continue;
        }

        // Skip lines that have [*] or [+] or [-] markers (status lines, not shares)
        if rest.contains("[*]") || rest.contains("[+]") || rest.contains("[-]") {
            continue;
        }

        // Try to parse share line: after "port hostname" we have "sharename perms comment"
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        // tokens[0] = port (e.g., "445"), tokens[1] = hostname
        // tokens[2..] = share name, permissions, comment
        let remaining = tokens[2..].join(" ");

        // Try to match: SHARENAME  PERMISSIONS  COMMENT
        if let Some(caps) = SHARE_LINE_RE.captures(&remaining) {
            let name = caps[1].to_string();
            let permissions = caps[2].to_string();
            let comment = caps
                .get(3)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();

            results.push(ParsedShare {
                host: host.clone(),
                name,
                permissions,
                comment,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_shares() {
        let output = "SMB  192.168.58.10  445  DC01  ADMIN$  READ  Remote Admin\nSMB  192.168.58.10  445  DC01  C$  READ,WRITE  Default share\nSMB  192.168.58.10  445  DC01  IPC$  READ  Remote IPC\nSMB  192.168.58.10  445  DC01  NETLOGON  READ  Logon server share\n";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 4);

        assert_eq!(shares[0].host, "192.168.58.10");
        assert_eq!(shares[0].name, "ADMIN$");
        assert_eq!(shares[0].permissions, "READ");
        assert_eq!(shares[0].comment, "Remote Admin");

        assert_eq!(shares[1].name, "C$");
        assert_eq!(shares[1].permissions, "READ,WRITE");
    }

    #[test]
    fn test_extract_shares_skips_banners() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Windows Server 2019\nSMB  192.168.58.10  445  DC01  SYSVOL  READ  Logon server share\n";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "SYSVOL");
    }

    #[test]
    fn test_extract_shares_empty() {
        assert!(extract_shares("").is_empty());
    }
}
