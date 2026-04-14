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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(username: &str, domain: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: String::new(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }
    }

    // --- extract_kerberoast_spn_key ---

    #[test]
    fn test_extract_spn_key_valid() {
        let hash = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$aabb$ccdd";
        let key = extract_kerberoast_spn_key(hash);
        assert!(key.is_some());
        let key = key.unwrap();
        assert!(key.starts_with("23:"));
        assert!(key.contains("MSSQLSvc"));
    }

    #[test]
    fn test_extract_spn_key_not_krb5tgs() {
        assert_eq!(extract_kerberoast_spn_key("$krb5asrep$23$user"), None);
    }

    #[test]
    fn test_extract_spn_key_too_short() {
        assert_eq!(extract_kerberoast_spn_key("$krb5tgs$"), None);
    }

    // --- dedupe_hashes ---

    #[test]
    fn test_dedupe_ntlm_by_hash_value() {
        let hashes = vec![
            make_hash(
                "admin",
                "contoso.local",
                "ntlm",
                "aabbccdd11223344aabbccdd11223344",
            ),
            make_hash(
                "admin",
                "contoso.local",
                "ntlm",
                "aabbccdd11223344aabbccdd11223344",
            ), // dup
            make_hash(
                "admin",
                "contoso.local",
                "ntlm",
                "eeff0011eeff0011eeff0011eeff0011",
            ),
        ];
        let deduped = dedupe_hashes(hashes);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedupe_asrep_by_domain_user() {
        let hashes = vec![
            make_hash(
                "svc_web",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$svc_web@CONTOSO.LOCAL:aabb",
            ),
            make_hash(
                "svc_web",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$svc_web@CONTOSO.LOCAL:ccdd",
            ),
        ];
        let deduped = dedupe_hashes(hashes);
        assert_eq!(deduped.len(), 1); // same user+domain → deduped
    }

    #[test]
    fn test_dedupe_asrep_different_users() {
        let hashes = vec![
            make_hash(
                "svc_web",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$svc_web:aabb",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$svc_sql:ccdd",
            ),
        ];
        let deduped = dedupe_hashes(hashes);
        assert_eq!(deduped.len(), 2); // different users → kept
    }

    #[test]
    fn test_dedupe_kerberoast_by_spn() {
        let hashes = vec![
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$aabb$cc",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$ddee$ff",
            ),
        ];
        let deduped = dedupe_hashes(hashes);
        assert_eq!(deduped.len(), 1); // same SPN → deduped
    }

    #[test]
    fn test_dedupe_mixed_types() {
        let hashes = vec![
            make_hash(
                "admin",
                "contoso.local",
                "ntlm",
                "aabbccdd11223344aabbccdd11223344",
            ),
            make_hash(
                "svc_web",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$svc_web:aabb",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc*$aa$bb",
            ),
        ];
        let deduped = dedupe_hashes(hashes);
        assert_eq!(deduped.len(), 3); // all unique
    }

    #[test]
    fn test_dedupe_empty() {
        let deduped = dedupe_hashes(vec![]);
        assert!(deduped.is_empty());
    }

    #[test]
    fn test_dedupe_case_insensitive() {
        let hashes = vec![
            make_hash(
                "Admin",
                "CONTOSO.LOCAL",
                "as-rep",
                "$krb5asrep$23$Admin:aabb",
            ),
            make_hash(
                "admin",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$admin:ccdd",
            ),
        ];
        let deduped = dedupe_hashes(hashes);
        assert_eq!(deduped.len(), 1);
    }
}
