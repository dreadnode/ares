use std::collections::HashMap;

use ares_core::models::User;

use super::strip_trailing_dot;

/// Noise usernames that should be filtered.
pub(super) const NOISE_USERNAMES: &[&str] = &[
    "none",
    "null",
    "(none)",
    "(null)",
    "anonymous",
    "unknown",
    "n/a",
    "default",
    "test",
    "local",
    "localhost",
    "domain",
    "workgroup",
    // Built-in / service accounts — not useful attack targets
    "guest",
    "defaultaccount",
    "krbtgt",
    "ssm-user",
    "ansible",
];

/// Prefixes for machine-local service accounts that should be filtered.
/// e.g. SQLServer2005SQLBrowserUser$SQL01
pub(super) const NOISE_USERNAME_PREFIXES: &[&str] = &["sqlserver", "mssql", "healthmailbox"];

/// Resolve a NetBIOS domain name to FQDN using the netbios_to_fqdn map.
pub(super) fn resolve_netbios_domain(
    domain: &str,
    netbios_to_fqdn: &HashMap<String, String>,
) -> String {
    let lower = domain.to_lowercase();
    if lower.contains('.') {
        return strip_trailing_dot(&lower).to_string();
    }
    let upper = domain.to_uppercase();
    if let Some(fqdn) = netbios_to_fqdn.get(&upper) {
        return fqdn.to_lowercase();
    }
    for (nb, fqdn) in netbios_to_fqdn {
        if nb.to_lowercase() == lower {
            return fqdn.to_lowercase();
        }
    }
    lower
}

/// Sources that produce verified users (KDC-confirmed or enumerated).
/// `output_extraction` is excluded — its DOMAIN\user regex matches every
/// wordlist entry in kerbrute/ASREProast output, not just confirmed users.
const TRUSTED_USER_SOURCES: &[&str] = &["kerberos_enum", "netexec_user_enum"];

pub(crate) fn dedup_users(users: &[User], netbios_to_fqdn: &HashMap<String, String>) -> Vec<User> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        let raw_domain = strip_trailing_dot(u.domain.trim());
        let domain = resolve_netbios_domain(raw_domain, netbios_to_fqdn).to_lowercase();
        let username = u.username.trim().to_lowercase();

        if !u.source.is_empty() && !TRUSTED_USER_SOURCES.contains(&u.source.as_str()) {
            continue;
        }

        if username.is_empty()
            || username.len() <= 1
            || username.contains('/')
            || username.starts_with('_')
            || username.bytes().any(|b| b < 0x20)
            || !username.bytes().all(|b| b.is_ascii_graphic())
            || NOISE_USERNAMES.contains(&username.as_str())
            || NOISE_USERNAME_PREFIXES
                .iter()
                .any(|p| username.starts_with(p))
        {
            continue;
        }
        if domain.starts_with('_') || domain.is_empty() {
            continue;
        }

        let key = (domain.clone(), username);
        if seen.insert(key) {
            let mut cleaned = u.clone();
            cleaned.domain =
                resolve_netbios_domain(strip_trailing_dot(cleaned.domain.trim()), netbios_to_fqdn)
                    .to_lowercase();
            result.push(cleaned);
        }
    }
    result
}
