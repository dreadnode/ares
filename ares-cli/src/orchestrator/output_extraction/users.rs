use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::User;

static RE_DOMAIN_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(domain:([^)]+)\)").unwrap());

pub(crate) static RE_DOMAIN_BACKSLASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-$]+)").unwrap());

pub(crate) static RE_UPN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z0-9_.\-]+)@([A-Za-z0-9_.\-]+\.[A-Za-z0-9_.\-]+)").unwrap()
});

pub(crate) static RE_USER_BRACKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)user:\[([^\]]+)\]").unwrap());

pub(crate) static RE_ACCOUNT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Account:\s*([A-Za-z0-9_.\-]+)").unwrap());

static RE_SAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)samaccountname:\s*([A-Za-z0-9_.\-]+)").unwrap());

static RE_SMB_TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+\d{4}-\d{2}-\d{2}").unwrap()
});

/// Reject garbage usernames and invalid domains from regex extraction.
pub fn is_valid_extracted_user(username: &str, domain: &str) -> bool {
    if username.is_empty() || username.ends_with('$') {
        return false;
    }
    if username.bytes().any(|b| b < 0x20) || domain.bytes().any(|b| b < 0x20) {
        return false;
    }
    if username.len() <= 1 {
        return false;
    }
    let lower = username.to_lowercase();
    const NOISE: &[&str] = &[
        "anonymous",
        "none",
        "null",
        "unknown",
        "n/a",
        "default",
        "test",
        "local",
        "localhost",
        "domain",
        "workgroup",
    ];
    if NOISE.contains(&lower.as_str()) {
        return false;
    }
    if username.starts_with('_') || domain.starts_with('_') {
        return false;
    }
    if !domain.contains('.') {
        if domain.len() > 15 || domain.is_empty() {
            return false;
        }
        if !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    if !username.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    true
}

pub fn extract_users(output: &str, default_domain: &str) -> Vec<User> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_domain = default_domain.to_string();

    for line in output.lines() {
        let stripped = line.trim();

        if let Some(caps) = RE_DOMAIN_CONTEXT.captures(stripped) {
            current_domain = caps
                .get(1)
                .unwrap()
                .as_str()
                .trim_end_matches('.')
                .to_string();
        }

        let mut found = Vec::new();

        if let Some(caps) = RE_DOMAIN_BACKSLASH.captures(stripped) {
            let dom = caps.get(1).unwrap().as_str();
            let user = caps.get(2).unwrap().as_str();
            found.push((user.to_string(), dom.to_string()));
        }

        if let Some(caps) = RE_UPN.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            let dom = caps.get(2).unwrap().as_str();
            found.push((user.to_string(), dom.to_string()));
        }

        for caps in RE_USER_BRACKET.captures_iter(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_ACCOUNT.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_SAM.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_SMB_TIMESTAMP.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        for (raw_username, raw_domain) in found {
            let username = raw_username.trim().trim_end_matches('.').to_string();
            let domain = raw_domain.trim().trim_end_matches('.').to_string();
            if !is_valid_extracted_user(&username, &domain) {
                continue;
            }
            let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                users.push(User {
                    username,
                    domain,
                    description: String::new(),
                    is_admin: false,
                    source: "output_extraction".to_string(),
                });
            }
        }
    }

    users
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_extracted_user_accepts_normal() {
        assert!(is_valid_extracted_user("alice", "corp.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_machine_account() {
        assert!(!is_valid_extracted_user("DC01$", "corp.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_empty() {
        assert!(!is_valid_extracted_user("", "corp.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_single_char() {
        assert!(!is_valid_extracted_user("a", "corp.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_noise_names() {
        for name in &["anonymous", "none", "null", "unknown", "local"] {
            assert!(
                !is_valid_extracted_user(name, "corp.local"),
                "should reject: {name}"
            );
        }
    }

    #[test]
    fn is_valid_extracted_user_rejects_underscore_domain() {
        assert!(!is_valid_extracted_user("alice", "_corp.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_long_netbios() {
        // NetBIOS names > 15 chars without a dot are invalid
        assert!(!is_valid_extracted_user("alice", "TOOLONGNETBIOSNAME"));
    }

    #[test]
    fn extract_users_domain_backslash() {
        let users = extract_users("CORP\\alice (SidTypeUser)", "corp.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[0].domain, "CORP");
    }

    #[test]
    fn extract_users_upn_format() {
        let users = extract_users("bob@corp.local", "corp.local");
        assert!(users.iter().any(|u| u.username == "bob"));
    }

    #[test]
    fn extract_users_skips_machine_accounts() {
        let users = extract_users("CORP\\DC01$", "corp.local");
        assert!(users.is_empty());
    }

    #[test]
    fn extract_users_empty_output() {
        assert!(extract_users("", "corp.local").is_empty());
    }
}
