use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::Host;

static RE_SMB_BANNER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.\-]+)\s+\[\*\]\s+(.+)")
        .unwrap()
});

static RE_SMB_BANNER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(name:([^)]+)\)").unwrap());

static RE_SMB_BANNER_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(domain:([^)]+)\)").unwrap());

static RE_SMB_BANNER_OS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([^(]+?)\s+\(name:").unwrap());

static RE_SMB_SIMPLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_\-]+)\s+").unwrap()
});

pub fn extract_hosts(output: &str) -> Vec<Host> {
    let mut hosts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        let stripped = line.trim();

        // Banner line with OS info: SMB IP PORT HOST [*] details
        if let Some(caps) = RE_SMB_BANNER.captures(stripped) {
            let ip = caps.get(1).unwrap().as_str().to_string();
            if !seen.insert(ip.clone()) {
                continue;
            }
            let details = caps.get(3).unwrap().as_str();
            let netbios_name = RE_SMB_BANNER_NAME
                .captures(details)
                .map(|c| c.get(1).unwrap().as_str().to_string())
                .unwrap_or_default();
            let domain = RE_SMB_BANNER_DOMAIN
                .captures(details)
                .map(|c| {
                    // netexec appends trailing artifacts like "0." — strip them
                    c.get(1)
                        .unwrap()
                        .as_str()
                        .trim_end_matches("0.")
                        .trim_end_matches('.')
                        .to_string()
                })
                .unwrap_or_default();
            let os = RE_SMB_BANNER_OS
                .captures(details)
                .map(|c| c.get(1).unwrap().as_str().trim().to_string())
                .unwrap_or_default();

            let hostname =
                if !netbios_name.is_empty() && !domain.is_empty() && !netbios_name.contains('.') {
                    format!("{}.{}", netbios_name.to_lowercase(), domain.to_lowercase())
                } else {
                    netbios_name
                };

            let is_dc = details.contains("(signing:True)");
            let mut roles = Vec::new();
            if is_dc {
                roles.push("AD DC".to_string());
            }

            hosts.push(Host {
                ip,
                hostname,
                os,
                roles,
                services: vec![],
                is_dc,
                owned: false,
            });
            continue;
        }

        // Fallback simple line
        if let Some(caps) = RE_SMB_SIMPLE.captures(stripped) {
            let ip = caps.get(1).unwrap().as_str().to_string();
            let host_col = caps.get(2).unwrap().as_str();
            // Skip table header words
            let skip = ["share", "name", "permissions", "remark"];
            if skip.contains(&host_col.to_lowercase().as_str()) {
                continue;
            }
            if seen.insert(ip.clone()) {
                hosts.push(Host {
                    ip,
                    hostname: host_col.to_string(),
                    os: String::new(),
                    roles: vec![],
                    services: vec![],
                    is_dc: false,
                    owned: false,
                });
            }
        }
    }

    hosts
}
