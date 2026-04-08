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
