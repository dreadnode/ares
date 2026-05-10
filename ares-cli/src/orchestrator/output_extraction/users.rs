use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::User;

static RE_DOMAIN_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(domain:([^)]+)\)").unwrap());

static RE_NAME_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(name:([^)]+)\)").unwrap());

/// True when a `(domain:Y)` value paired with `(name:X)` on an SMB banner line
/// is a workgroup or self-named pseudo-domain rather than a real Kerberos
/// realm. Mirrors the heuristic in `ares-tools::parsers::smb` — kept local to
/// avoid a cross-crate dep just for one helper. Non-domain-joined Windows
/// hosts emit `(domain:WORKGROUP)` or `(domain:WIN-XXX.AUTOGEN.LOCAL)` where
/// the first label of the domain is the host's own NetBIOS name; pinning
/// `current_domain` to that string later attributes extracted users (and any
/// hashes that get tagged from this context) to a phantom AD domain.
fn is_workgroup_domain(name: &str, domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return false;
    }
    if domain.eq_ignore_ascii_case("WORKGROUP") || domain.eq_ignore_ascii_case("MSHOME") {
        return true;
    }
    if !name.is_empty() {
        let first_label = domain.split('.').next().unwrap_or("");
        if first_label.eq_ignore_ascii_case(name) {
            return true;
        }
    }
    false
}

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
            let candidate = caps
                .get(1)
                .unwrap()
                .as_str()
                .trim_end_matches('.')
                .to_string();
            let line_name = RE_NAME_CONTEXT
                .captures(stripped)
                .map(|c| c.get(1).unwrap().as_str().trim().to_string())
                .unwrap_or_default();
            if !is_workgroup_domain(&line_name, &candidate) {
                current_domain = candidate;
            }
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
        assert!(is_valid_extracted_user("alice", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_machine_account() {
        assert!(!is_valid_extracted_user("DC01$", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_empty() {
        assert!(!is_valid_extracted_user("", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_single_char() {
        assert!(!is_valid_extracted_user("a", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_noise_names() {
        for name in &["anonymous", "none", "null", "unknown", "local"] {
            assert!(
                !is_valid_extracted_user(name, "contoso.local"),
                "should reject: {name}"
            );
        }
    }

    #[test]
    fn is_valid_extracted_user_rejects_underscore_domain() {
        assert!(!is_valid_extracted_user("alice", "_contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_long_netbios() {
        // NetBIOS names > 15 chars without a dot are invalid
        assert!(!is_valid_extracted_user("alice", "TOOLONGNETBIOSNAME"));
    }

    #[test]
    fn extract_users_domain_backslash() {
        let users = extract_users("CONTOSO\\alice (SidTypeUser)", "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[0].domain, "CONTOSO");
    }

    #[test]
    fn extract_users_upn_format() {
        let users = extract_users("bob@contoso.local", "contoso.local");
        assert!(users.iter().any(|u| u.username == "bob"));
    }

    #[test]
    fn extract_users_skips_machine_accounts() {
        let users = extract_users("CONTOSO\\DC01$", "contoso.local");
        assert!(users.is_empty());
    }

    #[test]
    fn extract_users_empty_output() {
        assert!(extract_users("", "contoso.local").is_empty());
    }

    #[test]
    fn extract_users_ignores_workgroup_domain_context() {
        // SMB banner from a non-domain-joined host (the attacker's own kali
        // box) appears in the same enumeration output as a real target. The
        // workgroup `(domain:WIN-ABCDEFGHIJK.WGRP.LOCAL)` must NOT overwrite
        // `current_domain`, so the user extracted on the next line stays
        // attributed to the operator's intended `default_domain` rather than
        // a phantom AD realm.
        let output = "\
SMB  192.168.58.178  445  WIN-ABCDEFGHIJK  [*] Windows 10 (name:WIN-ABCDEFGHIJK) (domain:WIN-ABCDEFGHIJK.WGRP.LOCAL) (signing:False)
SMB  192.168.58.178  445  WIN-ABCDEFGHIJK  [+] user:[svc_local]";
        let users = extract_users(output, "contoso.local");
        let svc = users
            .iter()
            .find(|u| u.username == "svc_local")
            .expect("svc_local should be extracted");
        assert_eq!(
            svc.domain, "contoso.local",
            "workgroup banner must not overwrite default_domain"
        );
    }

    #[test]
    fn extract_users_keeps_real_domain_context() {
        // Sanity check — real AD `(domain:contoso.local)` still updates
        // current_domain.
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local) (signing:True)
SMB  192.168.58.10  445  DC01  [+] user:[alice]";
        let users = extract_users(output, "");
        let alice = users.iter().find(|u| u.username == "alice").unwrap();
        assert_eq!(alice.domain, "contoso.local");
    }

    #[test]
    fn is_workgroup_domain_detects_self_named() {
        assert!(is_workgroup_domain(
            "WIN-ABCDEFGHIJK",
            "WIN-ABCDEFGHIJK.WGRP.LOCAL"
        ));
        assert!(is_workgroup_domain("anything", "WORKGROUP"));
        assert!(!is_workgroup_domain("DC01", "contoso.local"));
        assert!(!is_workgroup_domain("DC01", ""));
    }
}
