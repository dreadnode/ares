//! State normalization: fix NetBIOS -> FQDN domain mismatches.

use std::collections::HashMap;

use ares_core::models::{Credential, Hash};

/// If `domain` is a NetBIOS name (no dots, uppercase-ish), look it up in the
/// map and return the FQDN if found. Returns `None` if no fixup is needed.
pub fn resolve_domain(domain: &str, netbios_map: &HashMap<String, String>) -> Option<String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() || trimmed.contains('.') {
        // Already FQDN or empty
        return None;
    }
    // Look up the NetBIOS name (case-insensitive)
    let upper = trimmed.to_uppercase();
    netbios_map
        .get(&upper)
        .or_else(|| netbios_map.get(trimmed))
        .or_else(|| netbios_map.get(&trimmed.to_lowercase()))
        .cloned()
}

/// Generic domain normalizer: applies `resolve_domain` to each item's domain,
/// mutating in place via the provided accessor. Returns the count of items fixed.
fn normalize_domains<T, F>(
    items: &mut [T],
    netbios_map: &HashMap<String, String>,
    get_domain: F,
) -> usize
where
    F: Fn(&mut T) -> &mut String,
{
    let mut fixed = 0;
    for item in items.iter_mut() {
        let domain = get_domain(item);
        if let Some(fqdn) = resolve_domain(domain, netbios_map) {
            *domain = fqdn;
            fixed += 1;
        }
    }
    fixed
}

/// Fix credential domains: replace NetBIOS names with FQDNs where the
/// `netbios_to_fqdn` map provides a mapping.
///
/// Returns the number of credentials fixed.
pub fn normalize_credential_domains(
    credentials: &mut [Credential],
    netbios_map: &HashMap<String, String>,
) -> usize {
    normalize_domains(credentials, netbios_map, |c| &mut c.domain)
}

/// Fix hash domains: replace NetBIOS names with FQDNs where the
/// `netbios_to_fqdn` map provides a mapping.
///
/// Returns the number of hashes fixed.
pub fn normalize_hash_domains(hashes: &mut [Hash], netbios_map: &HashMap<String, String>) -> usize {
    normalize_domains(hashes, netbios_map, |h| &mut h.domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("CONTOSO".to_string(), "contoso.local".to_string());
        m.insert("FABRIKAM".to_string(), "fabrikam.local".to_string());
        m
    }

    #[test]
    fn test_resolve_domain_netbios_to_fqdn() {
        let map = make_map();
        assert_eq!(
            resolve_domain("CONTOSO", &map),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn test_resolve_domain_case_insensitive() {
        let map = make_map();
        assert_eq!(
            resolve_domain("contoso", &map),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn test_resolve_domain_already_fqdn() {
        let map = make_map();
        assert_eq!(resolve_domain("contoso.local", &map), None);
    }

    #[test]
    fn test_resolve_domain_empty() {
        let map = make_map();
        assert_eq!(resolve_domain("", &map), None);
    }

    #[test]
    fn test_resolve_domain_unknown_netbios() {
        let map = make_map();
        assert_eq!(resolve_domain("UNKNOWN", &map), None);
    }

    #[test]
    fn test_normalize_credential_domains() {
        let map = make_map();
        let mut creds = vec![
            Credential {
                id: String::new(),
                username: "admin".to_string(),
                password: "P@ss1".to_string(),
                domain: "CONTOSO".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            Credential {
                id: String::new(),
                username: "jdoe".to_string(),
                password: "P@ss2".to_string(),
                domain: "contoso.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
        ];
        let fixed = normalize_credential_domains(&mut creds, &map);
        assert_eq!(fixed, 1);
        assert_eq!(creds[0].domain, "contoso.local");
        assert_eq!(creds[1].domain, "contoso.local"); // unchanged
    }

    #[test]
    fn test_normalize_hash_domains() {
        let map = make_map();
        let mut hashes = vec![Hash {
            id: String::new(),
            username: "admin".to_string(),
            hash_value: "aabbccdd".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "FABRIKAM".to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }];
        let fixed = normalize_hash_domains(&mut hashes, &map);
        assert_eq!(fixed, 1);
        assert_eq!(hashes[0].domain, "fabrikam.local");
    }

    #[test]
    fn test_normalize_empty_slice() {
        let map = make_map();
        let mut creds: Vec<Credential> = vec![];
        assert_eq!(normalize_credential_domains(&mut creds, &map), 0);
    }
}
