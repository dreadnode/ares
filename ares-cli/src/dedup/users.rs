use std::collections::HashMap;

use ares_core::models::User;

use super::{is_ghost_machine_account, strip_trailing_dot};

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
///
/// `output_extraction` is excluded — its DOMAIN\user regex matches every
/// wordlist entry in kerbrute/ASREProast output, not just confirmed users.
///
/// `ldap_extraction` IS trusted: it is the high-confidence sibling of
/// `output_extraction`, keyed on the server-emitted `sAMAccountName` attribute
/// which only appears in genuine LDAP output. Group/computer objects are
/// dropped at the source (`output_extraction::users`), and machine-account
/// residue is filtered below. Without this, users first discovered via LDAP
/// (whole trusted-domain rosters — cross-forest users the recon agent only
/// reaches over LDAP) were silently dropped from the report because the state
/// store is first-writer-wins by (domain, username): a later netexec run
/// cannot re-tag a user already recorded as `ldap_extraction`.
///
/// `secretsdump_implicit` IS trusted: it is the User backfill written by
/// `publish_hash` when a hash lands for a non-machine principal (see
/// `orchestrator/state/publishing/credentials.rs`). NTDS/LSA secrets are
/// KDC-authoritative — the presence of the hash is proof the account exists —
/// so dropping the backfill here made hashes appear for users the loot view
/// silently omitted (e.g. cross-forest accounts recovered only via secretsdump
/// when LDAP enum was blocked).
const TRUSTED_USER_SOURCES: &[&str] = &[
    "kerberos_enum",
    "netexec_user_enum",
    "ldap_extraction",
    "secretsdump_implicit",
];

pub(crate) fn dedup_users(users: &[User], netbios_to_fqdn: &HashMap<String, String>) -> Vec<User> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        // A username may arrive in UPN form (`sam@realm`) — e.g. a kerberos
        // enum echoing a UPN-form userlist entry. Split off the `@realm` so it
        // renders as a bare sAMAccountName and dedups against the same user
        // discovered as `sam` by another source; adopt the realm as the domain
        // only when the record carried none.
        let raw_username = u.username.trim();
        let (bare_username, upn_domain) = match raw_username.split_once('@') {
            Some((sam, realm)) if !sam.is_empty() && realm.contains('.') => (sam, Some(realm)),
            _ => (raw_username, None),
        };

        let mut raw_domain = strip_trailing_dot(u.domain.trim());
        if raw_domain.is_empty() {
            if let Some(realm) = upn_domain {
                raw_domain = strip_trailing_dot(realm.trim());
            }
        }
        let domain = resolve_netbios_domain(raw_domain, netbios_to_fqdn).to_lowercase();
        let username = bare_username.to_lowercase();

        if !u.source.is_empty() && !TRUSTED_USER_SOURCES.contains(&u.source.as_str()) {
            continue;
        }

        if username.is_empty()
            || username.len() <= 1
            || username.contains('/')
            || username.starts_with('_')
            || username.ends_with('$')
            || username.starts_with("win-")
            || username.starts_with("desktop-")
            || username.bytes().any(|b| b < 0x20)
            || !username.bytes().all(|b| b.is_ascii_graphic())
            || NOISE_USERNAMES.contains(&username.as_str())
            || NOISE_USERNAME_PREFIXES
                .iter()
                .any(|p| username.starts_with(p))
            || is_ghost_machine_account(&username)
            // A username equal to a discovered host's NetBIOS name is that
            // host's computer account (e.g. `dc01`, `ca01`), whose trailing
            // `$` the sAMAccountName regex may have stripped.
            || netbios_to_fqdn.contains_key(&username.to_uppercase())
        {
            continue;
        }
        if domain.starts_with('_') || domain.is_empty() {
            continue;
        }

        let key = (domain.clone(), username);
        if seen.insert(key) {
            let mut cleaned = u.clone();
            // Store the normalized principal: bare sAMAccountName (original
            // case preserved) and the resolved domain (which already adopted
            // the UPN realm when the record had no domain of its own).
            cleaned.username = bare_username.to_string();
            cleaned.domain = domain;
            result.push(cleaned);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_passthrough() {
        let map = HashMap::new();
        assert_eq!(
            resolve_netbios_domain("contoso.local", &map),
            "contoso.local"
        );
    }

    #[test]
    fn netbios_resolved_to_fqdn() {
        let mut map = HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());
        assert_eq!(resolve_netbios_domain("CONTOSO", &map), "contoso.local");
    }

    #[test]
    fn netbios_case_insensitive() {
        let mut map = HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());
        assert_eq!(resolve_netbios_domain("contoso", &map), "contoso.local");
    }

    #[test]
    fn netbios_unresolved_returns_lowercase() {
        let map = HashMap::new();
        assert_eq!(resolve_netbios_domain("UNKNOWN", &map), "unknown");
    }

    #[test]
    fn strips_trailing_dot_from_fqdn() {
        let map = HashMap::new();
        assert_eq!(
            resolve_netbios_domain("contoso.local.", &map),
            "contoso.local"
        );
    }

    #[test]
    fn noise_usernames_list_is_nonempty() {
        assert!(!NOISE_USERNAMES.is_empty());
        assert!(NOISE_USERNAMES.contains(&"guest"));
        assert!(NOISE_USERNAMES.contains(&"krbtgt"));
    }

    #[test]
    fn noise_prefixes_list_is_nonempty() {
        assert!(!NOISE_USERNAME_PREFIXES.is_empty());
        assert!(NOISE_USERNAME_PREFIXES.contains(&"sqlserver"));
    }

    fn make_user(username: &str, domain: &str, source: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: source.to_string(),
            member_of: Vec::new(),
        }
    }

    #[test]
    fn dedup_filters_noise_usernames() {
        let users = vec![
            make_user("guest", "contoso.local", "kerberos_enum"),
            make_user("krbtgt", "contoso.local", "kerberos_enum"),
        ];
        let result = dedup_users(&users, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_filters_untrusted_sources() {
        let users = vec![make_user("jsmith", "contoso.local", "output_extraction")];
        let result = dedup_users(&users, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_keeps_trusted_sources() {
        let users = vec![make_user("jsmith", "contoso.local", "kerberos_enum")];
        let result = dedup_users(&users, &HashMap::new());
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_keeps_ldap_extraction_source() {
        // Whole trusted-domain rosters are reached only over LDAP; they must
        // survive to the report.
        let users = vec![make_user(
            "bran.davies",
            "child.contoso.local",
            "ldap_extraction",
        )];
        let result = dedup_users(&users, &HashMap::new());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].username, "bran.davies");
    }

    #[test]
    fn dedup_filters_machine_account_dollar_suffix() {
        let users = vec![make_user("DC01$", "contoso.local", "ldap_extraction")];
        let result = dedup_users(&users, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_filters_win_netbios_username() {
        let users = vec![make_user(
            "WIN-G7FPA5ZZXZV",
            "contoso.local",
            "ldap_extraction",
        )];
        let result = dedup_users(&users, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_filters_username_matching_known_host_netbios() {
        // A computer whose sAMAccountName had its `$` stripped (`DC01`) matches
        // a discovered host NetBIOS name and must be filtered.
        let mut map = HashMap::new();
        map.insert("DC01".to_string(), "dc01.contoso.local".to_string());
        let users = vec![make_user("dc01", "contoso.local", "ldap_extraction")];
        let result = dedup_users(&users, &map);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_removes_duplicate_users() {
        let users = vec![
            make_user("jsmith", "contoso.local", "kerberos_enum"),
            make_user("jsmith", "contoso.local", "kerberos_enum"),
        ];
        let result = dedup_users(&users, &HashMap::new());
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_filters_short_usernames() {
        let users = vec![make_user("a", "contoso.local", "kerberos_enum")];
        let result = dedup_users(&users, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_strips_upn_suffix_and_dedups_against_bare() {
        // A kerberos enum that echoed a UPN-form userlist entry stores the
        // whole `sam@realm` as the username. It must render as the bare
        // sAMAccountName and collapse onto the same user seen elsewhere as
        // `sam`, rather than inflating the count with a doubled principal.
        let users = vec![
            make_user(
                "bob@child.contoso.local",
                "child.contoso.local",
                "kerberos_enum",
            ),
            make_user("bob", "child.contoso.local", "netexec_user_enum"),
        ];
        let result = dedup_users(&users, &HashMap::new());
        assert_eq!(result.len(), 1, "UPN and bare form must dedup to one user");
        assert_eq!(result[0].username, "bob");
        assert_eq!(result[0].domain, "child.contoso.local");
    }

    #[test]
    fn dedup_adopts_upn_realm_when_domain_empty() {
        // A domainless record whose username is a UPN keeps the realm as its
        // domain instead of being dropped by the empty-domain guard.
        let users = vec![make_user("carol@contoso.local", "", "kerberos_enum")];
        let result = dedup_users(&users, &HashMap::new());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].username, "carol");
        assert_eq!(result[0].domain, "contoso.local");
    }

    #[test]
    fn dedup_resolves_netbios_domain() {
        let mut map = HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());
        let users = vec![make_user("jsmith", "CONTOSO", "kerberos_enum")];
        let result = dedup_users(&users, &map);
        assert_eq!(result[0].domain, "contoso.local");
    }
}
