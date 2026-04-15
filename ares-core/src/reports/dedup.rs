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

/// Deduplicate hashes by (domain, username, hash_value) case-insensitively.
///
/// Empty-domain entries (from secretsdump local account dumps) are dropped when
/// a domain-qualified entry with the same username and hash value already exists.
///
/// Sorts with Administrator and krbtgt first.
pub fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let key = (
            h.domain.trim().to_lowercase(),
            h.username.trim().to_lowercase(),
            h.hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(h.clone());
        }
    }

    // Build a set of (username, hash_value) pairs that have a domain-qualified entry.
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

    // Drop empty-domain entries that are duplicated by a domain-qualified entry.
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
const TRUSTED_USER_SOURCES: &[&str] = &["kerberos_enum", "netexec_user_enum"];

/// Deduplicate users by (domain, username) case-insensitively.
/// Filters to trusted parser sources only and normalizes is_admin for known
/// admin usernames.
pub fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        // Only accept users from trusted parser sources
        if !u.source.is_empty() && !TRUSTED_USER_SOURCES.contains(&u.source.as_str()) {
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
        }
    }

    fn make_user(username: &str, domain: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
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
