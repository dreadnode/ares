use std::collections::HashSet;

use ares_core::models::{Credential, Hash, User};

pub(crate) fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        let key = (
            u.domain.trim().to_lowercase(),
            u.username.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(u.clone());
        }
    }
    result
}

pub(crate) fn dedup_credentials(creds: &[Credential]) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for c in creds {
        let key = (
            c.domain.trim().to_lowercase(),
            c.username.trim().to_lowercase(),
            c.password.clone(),
        );
        if seen.insert(key) {
            result.push(c.clone());
        }
    }
    result
}

pub(crate) fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let key = (
            h.domain.trim().to_lowercase(),
            h.username.trim().to_lowercase(),
            h.hash_type.trim().to_lowercase(),
            h.hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(h.clone());
        }
    }
    result
}

pub(crate) fn extract_weakness_title(block: &str) -> &str {
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("### ") {
            return rest.trim();
        }
        if trimmed.starts_with("**") && trimmed.ends_with("**") && !trimmed.contains(":**") {
            let inner = trimmed.trim_matches('*').trim();
            if !inner.is_empty() {
                return inner;
            }
        }
    }
    let first = block.lines().next().unwrap_or("Untitled Weakness");
    if first.len() > 60 {
        &first[..60]
    } else {
        first
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(domain: &str, username: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        }
    }

    fn make_cred(domain: &str, username: &str, password: &str) -> Credential {
        Credential {
            id: String::new(),
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

    fn make_hash(domain: &str, username: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: String::new(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }
    }

    #[test]
    fn test_dedup_users_basic() {
        let users = vec![
            make_user("contoso.local", "admin"),
            make_user("contoso.local", "admin"), // dup
            make_user("contoso.local", "jdoe"),
        ];
        let deduped = dedup_users(&users);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_users_case_insensitive() {
        let users = vec![
            make_user("CONTOSO.LOCAL", "Admin"),
            make_user("contoso.local", "admin"),
        ];
        let deduped = dedup_users(&users);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_users_different_domains() {
        let users = vec![
            make_user("contoso.local", "admin"),
            make_user("fabrikam.local", "admin"),
        ];
        let deduped = dedup_users(&users);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_credentials_basic() {
        let creds = vec![
            make_cred("contoso.local", "admin", "P@ss1"),
            make_cred("contoso.local", "admin", "P@ss1"), // dup
            make_cred("contoso.local", "admin", "P@ss2"), // different password
        ];
        let deduped = dedup_credentials(&creds);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_credentials_case_insensitive_username() {
        let creds = vec![
            make_cred("contoso.local", "Admin", "P@ss1"),
            make_cred("CONTOSO.LOCAL", "admin", "P@ss1"),
        ];
        let deduped = dedup_credentials(&creds);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_hashes_basic() {
        let hashes = vec![
            make_hash("contoso.local", "admin", "ntlm", "aabbccdd"),
            make_hash("contoso.local", "admin", "ntlm", "aabbccdd"), // dup
            make_hash("contoso.local", "admin", "aes256", "eeff0011"), // different type
        ];
        let deduped = dedup_hashes(&hashes);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_hashes_case_insensitive() {
        let hashes = vec![
            make_hash("contoso.local", "Admin", "NTLM", "AABBCCDD"),
            make_hash("CONTOSO.LOCAL", "admin", "ntlm", "aabbccdd"),
        ];
        let deduped = dedup_hashes(&hashes);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_extract_weakness_title_h3() {
        let block = "### SMB Signing Disabled\nSome details...";
        assert_eq!(extract_weakness_title(block), "SMB Signing Disabled");
    }

    #[test]
    fn test_extract_weakness_title_bold() {
        let block = "**Kerberoastable Account**\nDetails...";
        assert_eq!(extract_weakness_title(block), "Kerberoastable Account");
    }

    #[test]
    fn test_extract_weakness_title_fallback_first_line() {
        let block = "Some weakness description\nMore details";
        assert_eq!(extract_weakness_title(block), "Some weakness description");
    }

    #[test]
    fn test_extract_weakness_title_long_fallback_truncated() {
        let block = "A".repeat(100);
        assert_eq!(extract_weakness_title(&block).len(), 60);
    }

    #[test]
    fn test_extract_weakness_title_empty() {
        assert_eq!(extract_weakness_title(""), "Untitled Weakness");
    }
}
