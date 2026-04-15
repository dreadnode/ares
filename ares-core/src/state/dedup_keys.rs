//! Deduplication key builders for credentials and hashes.

use crate::models::{Credential, Hash};

/// Build credential dedup key matching Python format:
/// `cred:{domain}:{username}:{md5(password)[:16]}`
pub fn build_credential_dedup_key(cred: &Credential) -> String {
    use md5::{Digest, Md5};

    let domain = cred.domain.trim().to_lowercase();
    let username = cred.username.trim().to_lowercase();
    let mut hasher = Md5::new();
    hasher.update(cred.password.as_bytes());
    let digest = hasher.finalize();
    let password_hash = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let password_hash_short = &password_hash[..16.min(password_hash.len())];

    format!("cred:{domain}:{username}:{password_hash_short}")
}

/// Build hash dedup key matching Python's `_build_hash_dedup_key()`.
///
/// Dedup key format varies by hash type:
/// - AS-REP: `asrep:{domain}:{username}`
/// - Kerberoast: `krb:{domain}:{username}:{etype}:{spn}` or `krb:{domain}:{username}:{hash[:32]}`
/// - NTLM/other: `ntlm:{domain}:{username}:{hash[:32]}`
pub fn build_hash_dedup_key(hash: &Hash) -> String {
    let hash_type = hash.hash_type.trim().to_lowercase();
    let hash_value = &hash.hash_value;
    let username = hash.username.trim().to_lowercase();
    let domain = hash.domain.trim().to_lowercase();

    // AS-REP detection
    let is_asrep = matches!(hash_type.as_str(), "as-rep" | "asrep" | "krb5asrep")
        || hash_value.starts_with("$krb5asrep$");
    if is_asrep {
        return format!("asrep:{domain}:{username}");
    }

    // Kerberoast detection
    let is_kerberoast = matches!(
        hash_type.as_str(),
        "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
    ) || hash_value.starts_with("$krb5tgs$");
    if is_kerberoast {
        if let Some(spn_key) = extract_kerberoast_spn_key(hash_value) {
            return format!("krb:{domain}:{username}:{spn_key}");
        }
        let prefix = &hash_value[..32.min(hash_value.len())];
        return format!("krb:{domain}:{username}:{prefix}");
    }

    // NTLM/other
    let prefix = &hash_value[..32.min(hash_value.len())];
    format!("ntlm:{domain}:{username}:{prefix}")
}

/// Extract SPN and encryption type from a Kerberoast hash for deduplication.
///
/// Hash format: `$krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted`
fn extract_kerberoast_spn_key(hash_value: &str) -> Option<String> {
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

    fn make_cred(user: &str, domain: &str, pass: &str) -> Credential {
        Credential {
            id: String::new(),
            username: user.to_string(),
            password: pass.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(user: &str, domain: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: String::new(),
            username: user.to_string(),
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

    // ─── build_credential_dedup_key ──────────────────────────────────────

    #[test]
    fn test_cred_dedup_key_format() {
        let cred = make_cred("admin", "contoso.local", "P@ss1");
        let key = build_credential_dedup_key(&cred);
        assert!(key.starts_with("cred:contoso.local:admin:"));
        // MD5 prefix should be 16 hex chars
        let parts: Vec<&str> = key.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[3].len(), 16);
    }

    #[test]
    fn test_cred_dedup_key_lowercased() {
        let cred = make_cred("Admin", "CONTOSO.LOCAL", "P@ss1");
        let key = build_credential_dedup_key(&cred);
        assert!(key.starts_with("cred:contoso.local:admin:"));
    }

    #[test]
    fn test_cred_dedup_key_different_passwords() {
        let c1 = make_cred("admin", "contoso.local", "P@ss1");
        let c2 = make_cred("admin", "contoso.local", "P@ss2");
        let k1 = build_credential_dedup_key(&c1);
        let k2 = build_credential_dedup_key(&c2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_cred_dedup_key_same_password_deterministic() {
        let c1 = make_cred("admin", "contoso.local", "P@ss1");
        let c2 = make_cred("admin", "contoso.local", "P@ss1");
        assert_eq!(
            build_credential_dedup_key(&c1),
            build_credential_dedup_key(&c2)
        );
    }

    #[test]
    fn test_cred_dedup_key_trims_whitespace() {
        let cred = make_cred(" admin ", " contoso.local ", "P@ss1");
        let key = build_credential_dedup_key(&cred);
        assert!(key.starts_with("cred:contoso.local:admin:"));
    }

    // ─── build_hash_dedup_key ────────────────────────────────────────────

    #[test]
    fn test_hash_dedup_key_ntlm() {
        let h = make_hash(
            "admin",
            "contoso.local",
            "NTLM",
            "aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634",
        );
        let key = build_hash_dedup_key(&h);
        assert!(key.starts_with("ntlm:contoso.local:admin:"));
    }

    #[test]
    fn test_hash_dedup_key_asrep_by_type() {
        let h = make_hash(
            "jsmith",
            "contoso.local",
            "asrep",
            "$krb5asrep$23$jsmith@CONTOSO.LOCAL:abc123",
        );
        let key = build_hash_dedup_key(&h);
        assert_eq!(key, "asrep:contoso.local:jsmith");
    }

    #[test]
    fn test_hash_dedup_key_asrep_by_value() {
        let h = make_hash(
            "jsmith",
            "contoso.local",
            "kerberos",
            "$krb5asrep$23$jsmith@CONTOSO.LOCAL:abc123",
        );
        let key = build_hash_dedup_key(&h);
        assert_eq!(key, "asrep:contoso.local:jsmith");
    }

    #[test]
    fn test_hash_dedup_key_kerberoast_with_spn() {
        let h = make_hash(
            "svc_sql",
            "contoso.local",
            "kerberoast",
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local*$checksum$encrypted",
        );
        let key = build_hash_dedup_key(&h);
        assert!(key.starts_with("krb:contoso.local:svc_sql:"));
        assert!(key.contains("23:")); // etype
    }

    #[test]
    fn test_hash_dedup_key_kerberoast_no_spn() {
        let h = make_hash(
            "svc_sql",
            "contoso.local",
            "kerberoast",
            "short_hash_no_spn",
        );
        let key = build_hash_dedup_key(&h);
        assert!(key.starts_with("krb:contoso.local:svc_sql:"));
    }

    #[test]
    fn test_hash_dedup_key_case_insensitive() {
        let h1 = make_hash(
            "Admin",
            "CONTOSO.LOCAL",
            "NTLM",
            "aabbccdd11223344aabbccdd11223344",
        );
        let h2 = make_hash(
            "admin",
            "contoso.local",
            "ntlm",
            "aabbccdd11223344aabbccdd11223344",
        );
        assert_eq!(build_hash_dedup_key(&h1), build_hash_dedup_key(&h2));
    }

    // ─── extract_kerberoast_spn_key ──────────────────────────────────────

    #[test]
    fn test_extract_kerberoast_spn_key_valid() {
        let hash = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local*$checksum$encrypted";
        let key = extract_kerberoast_spn_key(hash);
        assert!(key.is_some());
        let k = key.unwrap();
        assert!(k.starts_with("23:"));
    }

    #[test]
    fn test_extract_kerberoast_spn_key_not_krb() {
        assert!(extract_kerberoast_spn_key("not_a_kerberos_hash").is_none());
    }

    #[test]
    fn test_extract_kerberoast_spn_key_too_few_parts() {
        assert!(extract_kerberoast_spn_key("$krb5tgs$").is_none());
    }
}
