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

/// Deduplicate users by (domain, username) case-insensitively.
/// Also normalizes is_admin for known admin usernames.
pub fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
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
