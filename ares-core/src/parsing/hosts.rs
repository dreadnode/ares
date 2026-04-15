//! Host extraction from netexec/crackmapexec SMB output.

use regex::Regex;
use std::sync::LazyLock;

use super::types::ParsedHost;

static SMB_BANNER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.\-]+)\s+\[\*\]\s+(.+)")
        .expect("smb banner regex")
});

static SMB_SIMPLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_\-]+)\s+")
        .expect("smb simple regex")
});

static SMB_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(name:([^)]+)\)").expect("smb name regex"));

static SMB_DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(domain:([^)]+)\)").expect("smb domain regex"));

static SMB_OS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([^(]+?)\s+\(name:").expect("smb os regex"));

/// Extract host information from netexec/crackmapexec SMB output.
pub fn extract_hosts(output: &str) -> Vec<ParsedHost> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try detailed banner pattern first
        if let Some(caps) = SMB_BANNER_RE.captures(line) {
            let ip = caps[1].to_string();
            let hostname_from_header = caps[2].to_string();
            let details = &caps[3];

            let hostname = SMB_NAME_RE
                .captures(details)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| hostname_from_header.clone());

            let domain = SMB_DOMAIN_RE
                .captures(details)
                .map(|c| c[1].to_string())
                .unwrap_or_default();

            let os = SMB_OS_RE
                .captures(details)
                .map(|c| c[1].trim().to_string())
                .unwrap_or_default();

            results.push(ParsedHost {
                ip,
                hostname,
                os,
                domain,
            });
            continue;
        }

        // Try simple pattern
        if let Some(caps) = SMB_SIMPLE_RE.captures(line) {
            results.push(ParsedHost {
                ip: caps[1].to_string(),
                hostname: caps[2].to_string(),
                os: String::new(),
                domain: String::new(),
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hosts_banner() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Windows Server 2019 Standard (name:DC01) (domain:contoso.local) (signing:True)\nSMB  192.168.58.11  445  SRV01  [*]  Windows Server 2019 Standard (name:SRV01) (domain:contoso.local)\n";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0].ip, "192.168.58.10");
        assert_eq!(hosts[0].hostname, "DC01");
        assert_eq!(hosts[0].domain, "contoso.local");
        assert_eq!(hosts[0].os, "Windows Server 2019 Standard");

        assert_eq!(hosts[1].ip, "192.168.58.11");
        assert_eq!(hosts[1].hostname, "SRV01");
        assert_eq!(hosts[1].domain, "contoso.local");
    }

    #[test]
    fn test_extract_hosts_simple() {
        let output = "SMB  192.168.58.1  445  HOST01  some other data\n";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.58.1");
        assert_eq!(hosts[0].hostname, "HOST01");
    }

    #[test]
    fn test_extract_hosts_empty() {
        assert!(extract_hosts("").is_empty());
        assert!(extract_hosts("no smb output here\n").is_empty());
    }

    #[test]
    fn test_hosts_with_signing_info() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Windows Server 2022 (name:DC01) (domain:contoso.local) (signing:True) (SMBv1:False)\n";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "DC01");
        assert_eq!(hosts[0].os, "Windows Server 2022");
        assert_eq!(hosts[0].domain, "contoso.local");
    }
}
