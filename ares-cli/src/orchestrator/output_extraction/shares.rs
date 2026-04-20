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
