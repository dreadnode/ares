//! Hash deduplication logic.

use std::collections::HashSet;

use tracing::info;

use ares_core::models::Hash;

/// Deduplicate hashes, keeping first occurrence.
///
/// - **AS-REP hashes**: dedup by `(domain.lower(), username.lower())` since
///   each AS-REP request generates a different hash but cracks to the same
///   password.
/// - **Kerberoast/TGS hashes**: dedup by `(domain.lower(), username.lower(),
///   spn_key)` where spn_key is extracted from the hash format.
/// - **NTLM/other hashes**: dedup by exact `hash_value`.
pub fn dedupe_hashes(hashes: Vec<Hash>) -> Vec<Hash> {
    let mut seen_asrep: HashSet<(String, String)> = HashSet::new();
    let mut seen_kerberoast: HashSet<(String, String, String)> = HashSet::new();
    let mut seen_other: HashSet<String> = HashSet::new();
    let mut result = Vec::with_capacity(hashes.len());
    let original_len = hashes.len();

    for h in hashes {
        let hash_type = h.hash_type.trim().to_lowercase();
        let hash_value = &h.hash_value;
        let username = h.username.trim().to_lowercase();
        let domain = h.domain.trim().to_lowercase();

        let is_asrep = matches!(hash_type.as_str(), "as-rep" | "asrep" | "krb5asrep")
            || hash_value.starts_with("$krb5asrep$");

        let is_kerberoast = matches!(
            hash_type.as_str(),
            "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
        ) || hash_value.starts_with("$krb5tgs$");

        if is_asrep {
            let key = (domain, username);
            if seen_asrep.contains(&key) {
                continue;
            }
            seen_asrep.insert(key);
        } else if is_kerberoast {
            let spn_key = extract_kerberoast_spn_key(hash_value).unwrap_or_default();
            let key = (domain, username, spn_key);
            if seen_kerberoast.contains(&key) {
                continue;
            }
            seen_kerberoast.insert(key);
        } else {
            if seen_other.contains(hash_value) {
                continue;
            }
            seen_other.insert(hash_value.clone());
        }

        result.push(h);
    }

    let removed = original_len - result.len();
    if removed > 0 {
        info!(removed = removed, "Deduplicated hashes");
    }
    result
}

/// Extract SPN and encryption type from a Kerberoast hash for deduplication.
///
/// Hash format: `$krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted`
pub(crate) fn extract_kerberoast_spn_key(hash_value: &str) -> Option<String> {
    if !hash_value.starts_with("$krb5tgs$") {
        return None;
    }
    let dollar_parts: Vec<&str> = hash_value.split('$').collect();
    if dollar_parts.len() < 4 {
        return None;
    }
    let etype = dollar_parts[2];
    let asterisk_parts: Vec<&str> = hash_value.split('*').collect();
    if asterisk_parts.len() < 2 {
        return None;
    }
    let inner_parts: Vec<&str> = asterisk_parts[1].split('$').collect();
    if inner_parts.len() < 3 {
        return None;
    }
    let spn = inner_parts[2];
    Some(format!("{etype}:{spn}"))
}
