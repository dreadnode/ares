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
    let password_hash = format!("{:x}", hasher.finalize());
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
