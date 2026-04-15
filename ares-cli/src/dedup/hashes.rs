use std::collections::HashSet;

use ares_core::models::Hash;

use super::credentials::strip_ansi;
use super::strip_trailing_dot;

fn normalize_hash_type(hash_type: &str) -> String {
    match hash_type.trim().to_lowercase().as_str() {
        "ntlm" => "NTLM".to_string(),
        "kerberoast" => "Kerberoast".to_string(),
        "asrep" | "as-rep" | "asreproast" => "AS-REP".to_string(),
        "aes256" | "aes-256" => "AES256".to_string(),
        "aes128" | "aes-128" => "AES128".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let domain = strip_trailing_dot(h.domain.trim()).to_lowercase();
        let hash_value = strip_ansi(&h.hash_value);
        let key = (
            domain.clone(),
            h.username.trim().to_lowercase(),
            h.hash_type.trim().to_lowercase(),
            hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            let mut cleaned = h.clone();
            cleaned.domain = strip_trailing_dot(cleaned.domain.trim()).to_lowercase();
            cleaned.hash_type = normalize_hash_type(&cleaned.hash_type);
            cleaned.hash_value = hash_value.trim().to_string();
            cleaned.username = strip_ansi(&cleaned.username);
            result.push(cleaned);
        }
    }
    result
}
