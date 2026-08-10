//! Credential, hash, and user deduplication.

use std::collections::HashSet;

use crate::models::{Credential, Hash, User};

/// Deduplicate credentials by (domain, username, password) case-insensitively.
/// Also normalizes is_admin for known admin usernames.
pub fn dedup_credentials(creds: &[Credential]) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for c in creds {
        let key = (
            c.domain.trim().to_lowercase(),
            c.username.trim().to_lowercase(),
            c.password.clone(),
        );
        if seen.insert(key) {
            let mut c = c.clone();
            if matches!(
                c.username.to_lowercase().as_str(),
                "administrator" | "krbtgt"
            ) {
                c.is_admin = true;
            }
            result.push(c);
        }
    }
    result
}

/// Canonicalize a domain string for dedup keys.
///
/// Strips whitespace and lowercases. AD realms are case-insensitive, so
/// `CONTOSO.LOCAL` and `contoso.local` must collapse into one bucket. A
/// future pass could prefer FQDN over NetBIOS form using a `netbios_to_fqdn`
/// map, but write-time sanitization (`publish_hash`, `sanitize_credential`)
/// already canonicalizes on the way in, so this dedup-time pass only needs
/// to be case-insensitive.
fn canonicalize_domain(domain: &str) -> String {
    domain.trim().to_lowercase()
}

/// Deduplicate hashes by (canonical_domain, username, hash_value,
/// source_host) case-insensitively.
///
/// `source_host` is part of the key so multiple hosts' local-SAM
/// `Administrator` / `Guest` / `ssm-user` rows don't collapse into a single
/// entry — without it, four different DCs each contributing an
/// `Administrator:500:...` row would render as one, hiding the lateral
/// movement opportunity. Domain-qualified rows leave `source_host` empty and
/// rely on the realm to disambiguate.
///
/// Empty-domain entries (from secretsdump local account dumps) are dropped
/// when a domain-qualified entry with the same username and hash value
/// already exists.
///
/// Sorts with Administrator and krbtgt first.
pub fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let key = (
            canonicalize_domain(&h.domain),
            h.username.trim().to_lowercase(),
            h.hash_value.trim().to_lowercase(),
            h.source_host
                .as_deref()
                .map(|s| s.trim().to_lowercase())
                .unwrap_or_default(),
        );
        if seen.insert(key) {
            result.push(h.clone());
        }
    }

    let qualified: HashSet<(String, String)> = result
        .iter()
        .filter(|h| !h.domain.trim().is_empty())
        .map(|h| {
            (
                h.username.trim().to_lowercase(),
                h.hash_value.trim().to_lowercase(),
            )
        })
        .collect();

    result.retain(|h| {
        if h.domain.trim().is_empty() {
            let key = (
                h.username.trim().to_lowercase(),
                h.hash_value.trim().to_lowercase(),
            );
            !qualified.contains(&key)
        } else {
            true
        }
    });

    // Sort: Administrator first, then krbtgt, then alphabetical
    result.sort_by(|a, b| {
        fn priority(name: &str) -> u8 {
            match name.to_lowercase().as_str() {
                "administrator" => 0,
                "krbtgt" => 1,
                _ => 2,
            }
        }
        let pa = priority(&a.username);
        let pb = priority(&b.username);
        pa.cmp(&pb)
            .then_with(|| a.username.to_lowercase().cmp(&b.username.to_lowercase()))
    });

    result
}

/// Sources that produce verified users (KDC-confirmed or enumerated).
/// `output_extraction` is excluded — its DOMAIN\user regex matches every
/// wordlist entry in kerbrute/ASREProast output, not just confirmed users.
///
/// `secretsdump_implicit` is a synthesized source: when `publish_hash` lands
/// a new hash with a non-empty domain and non-machine username, we
/// backfill a corresponding `User` row so the user table reflects the
/// identity even when LDAP enum was blocked / cross-forest. The user must
/// already have been authenticated by the KDC during the NTDS dump, so
/// treating it as verified is safe.
///
/// `ldap_extraction` is the high-confidence `sAMAccountName` source (group and
/// computer objects are filtered out where LDAP records are recognized). It is
/// trusted so that users first discovered over LDAP — e.g. whole trusted-domain
/// rosters the recon agent only reaches via cross-realm LDAP — are not dropped
/// from the report. The state store is first-writer-wins by (domain, username),
/// so a user recorded under `ldap_extraction` can never be re-tagged by a later
/// netexec run; excluding the source hid those users entirely.
const TRUSTED_USER_SOURCES: &[&str] = &[
    "kerberos_enum",
    "netexec_user_enum",
    "secretsdump_implicit",
    "ldap_extraction",
];

/// True if `username` is a machine/computer account rather than a real user:
/// a trailing `$` (sometimes stripped upstream), or a Windows auto-generated
/// host NetBIOS name (`WIN-…`, `DESKTOP-…`).
fn is_machine_account(username: &str) -> bool {
    let lower = username.to_lowercase();
    username.ends_with('$') || lower.starts_with("win-") || lower.starts_with("desktop-")
}

/// Deduplicate users by (domain, username) case-insensitively.
/// Filters to trusted parser sources only and normalizes is_admin for known
/// admin usernames.
pub fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        if !u.source.is_empty() && !TRUSTED_USER_SOURCES.contains(&u.source.as_str()) {
            continue;
        }
        // Machine accounts leak into `ldap_extraction` via sAMAccountName —
        // they are hosts, not users.
        if is_machine_account(&u.username) {
            continue;
        }
        let key = (u.domain.to_lowercase(), u.username.to_lowercase());
        if seen.insert(key) {
            let mut u = u.clone();
            if matches!(
                u.username.to_lowercase().as_str(),
                "administrator" | "krbtgt"
            ) {
                u.is_admin = true;
            }
            result.push(u);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Hash, User};

    fn make_cred(username: &str, domain: &str, password: &str) -> Credential {
        Credential {
            id: "id".to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(username: &str, domain: &str, hash_value: &str) -> Hash {
        Hash {
            id: "id".to_string(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn make_hash_with_source_host(
        username: &str,
        domain: &str,
        hash_value: &str,
        source_host: &str,
    ) -> Hash {
        let mut h = make_hash(username, domain, hash_value);
        h.source_host = Some(source_host.to_string());
        h
    }

    fn make_user(username: &str, domain: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
            member_of: Vec::new(),
        }
    }

    #[test]
    fn dedup_credentials_removes_case_insensitive_duplicates() {
        let creds = vec![
            make_cred("Admin", "CONTOSO.LOCAL", "pass"),
            make_cred("admin", "contoso.local", "pass"),
        ];
        let result = dedup_credentials(&creds);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_credentials_keeps_different_passwords() {
        let creds = vec![
            make_cred("admin", "contoso.local", "pass1"),
            make_cred("admin", "contoso.local", "pass2"),
        ];
        let result = dedup_credentials(&creds);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn dedup_credentials_sets_is_admin_for_administrator() {
        let creds = vec![make_cred("administrator", "contoso.local", "pass")];
        let result = dedup_credentials(&creds);
        assert!(result[0].is_admin);
    }

    #[test]
    fn dedup_credentials_sets_is_admin_for_krbtgt() {
        let creds = vec![make_cred("krbtgt", "contoso.local", "pass")];
        let result = dedup_credentials(&creds);
        assert!(result[0].is_admin);
    }

    #[test]
    fn dedup_hashes_sorts_administrator_first() {
        let hashes = vec![
            make_hash("user1", "contoso.local", "hash1"),
            make_hash("administrator", "contoso.local", "hash2"),
            make_hash("krbtgt", "contoso.local", "hash3"),
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result[0].username, "administrator");
        assert_eq!(result[1].username, "krbtgt");
        assert_eq!(result[2].username, "user1");
    }

    #[test]
    fn dedup_hashes_removes_exact_duplicates() {
        let hashes = vec![
            make_hash("admin", "contoso.local", "samehash"),
            make_hash("admin", "contoso.local", "samehash"),
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_users_removes_case_insensitive_duplicates() {
        let users = vec![
            make_user("Alice", "CONTOSO.LOCAL"),
            make_user("alice", "contoso.local"),
        ];
        let result = dedup_users(&users);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_users_keeps_different_domains() {
        let users = vec![
            make_user("alice", "contoso.local"),
            make_user("alice", "fabrikam.local"),
        ];
        let result = dedup_users(&users);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn dedup_users_sets_is_admin_for_administrator() {
        let users = vec![make_user("administrator", "contoso.local")];
        let result = dedup_users(&users);
        assert!(result[0].is_admin);
    }

    #[test]
    fn dedup_users_sets_is_admin_for_krbtgt() {
        let users = vec![make_user("krbtgt", "contoso.local")];
        let result = dedup_users(&users);
        assert!(result[0].is_admin);
    }

    #[test]
    fn dedup_users_empty_input() {
        let result = dedup_users(&[]);
        assert!(result.is_empty());
    }

    fn make_user_src(username: &str, domain: &str, source: &str) -> User {
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
    fn dedup_users_trusts_ldap_extraction() {
        let users = vec![make_user_src(
            "carol",
            "child.contoso.local",
            "ldap_extraction",
        )];
        let result = dedup_users(&users);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_users_drops_untrusted_source() {
        let users = vec![make_user_src(
            "wordlisthit",
            "contoso.local",
            "output_extraction",
        )];
        let result = dedup_users(&users);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_users_filters_machine_accounts() {
        let users = vec![
            make_user_src("DC01$", "contoso.local", "ldap_extraction"),
            make_user_src("WIN-G7FPA5ZZXZV", "contoso.local", "ldap_extraction"),
        ];
        let result = dedup_users(&users);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_hashes_collapses_empty_domain_when_qualified_exists() {
        let hashes = vec![
            make_hash("Administrator", "contoso.local", "aabb1122"),
            make_hash("Administrator", "", "aabb1122"), // secretsdump local
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].domain, "contoso.local");
    }

    #[test]
    fn dedup_hashes_keeps_empty_domain_when_no_qualified() {
        let hashes = vec![make_hash("localuser", "", "aabb1122")];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_hashes_keeps_per_host_local_sam_rows() {
        // Four hosts each contributing an `Administrator:500:...` local-SAM
        // row with the same hash value would collapse to one entry under
        // the old (domain, username, hash_value) key. Now source_host is
        // part of the key — they all survive so the operator can see all
        // four reachable hosts.
        let hashes = vec![
            make_hash_with_source_host("Administrator", "", "aabb1122", "dc01"),
            make_hash_with_source_host("Administrator", "", "aabb1122", "sql01"),
            make_hash_with_source_host("Administrator", "", "aabb1122", "ws01"),
            make_hash_with_source_host("Administrator", "", "aabb1122", "ca01"),
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn dedup_hashes_collapses_same_source_host_duplicate() {
        // Within a single source_host, the same Administrator hash arriving
        // twice (e.g. a re-run of secretsdump on the same target) must still
        // dedup to one entry.
        let hashes = vec![
            make_hash_with_source_host("Administrator", "", "aabb1122", "dc01"),
            make_hash_with_source_host("Administrator", "", "aabb1122", "dc01"),
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_hashes_canonicalizes_realm_casing() {
        // Same (user, domain, hash) arriving with mixed-case realms must
        // collapse — AD realms are case-insensitive.
        let hashes = vec![
            make_hash("alice", "CONTOSO.LOCAL", "aabb1122"),
            make_hash("alice", "contoso.local", "aabb1122"),
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_hashes_collapses_multiple_empty_domain_entries() {
        let hashes = vec![
            make_hash("admin", "contoso.local", "hash1"),
            make_hash("admin", "", "hash1"),
            make_hash("svc_user", "fabrikam.local", "hash2"),
            make_hash("svc_user", "", "hash2"),
        ];
        let result = dedup_hashes(&hashes);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|h| !h.domain.is_empty()));
    }
}
