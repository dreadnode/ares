//! Credential lookup for a given domain.

use std::collections::HashMap;

use ares_core::models::Credential;

use super::domain::normalize_domain;

/// Find a credential for a given domain.
///
/// Prefers credentials with a password over those with only a hash.
/// Falls back to any credential for the domain.
pub fn find_domain_credential<'a>(
    domain: &str,
    credentials: &'a [Credential],
    netbios_to_fqdn: &HashMap<String, String>,
) -> Option<&'a Credential> {
    let normalized = normalize_domain(domain, netbios_to_fqdn);

    // First pass: credential with non-empty password matching domain
    let with_password = credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        cred_domain == normalized && !c.password.is_empty()
    });

    if with_password.is_some() {
        return with_password;
    }

    // Second pass: any credential matching domain
    credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        cred_domain == normalized
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred(username: &str, domain: &str, password: &str) -> Credential {
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

    #[test]
    fn test_find_domain_credential_with_password() {
        let map = HashMap::new();
        let creds = vec![
            make_cred("admin", "contoso.local", "P@ss1"),
            make_cred("jdoe", "contoso.local", ""),
        ];
        let found = find_domain_credential("contoso.local", &creds, &map);
        assert!(found.is_some());
        assert_eq!(found.unwrap().username, "admin");
    }

    #[test]
    fn test_find_domain_credential_prefers_password() {
        let map = HashMap::new();
        let creds = vec![
            make_cred("hash_user", "contoso.local", ""),
            make_cred("pass_user", "contoso.local", "Secret"),
        ];
        let found = find_domain_credential("contoso.local", &creds, &map);
        assert_eq!(found.unwrap().username, "pass_user");
    }

    #[test]
    fn test_find_domain_credential_falls_back_to_no_password() {
        let map = HashMap::new();
        let creds = vec![make_cred("hash_user", "contoso.local", "")];
        let found = find_domain_credential("contoso.local", &creds, &map);
        assert_eq!(found.unwrap().username, "hash_user");
    }

    #[test]
    fn test_find_domain_credential_none_for_wrong_domain() {
        let map = HashMap::new();
        let creds = vec![make_cred("admin", "fabrikam.local", "P@ss1")];
        let found = find_domain_credential("contoso.local", &creds, &map);
        assert!(found.is_none());
    }

    #[test]
    fn test_find_domain_credential_netbios_resolution() {
        let mut map = HashMap::new();
        map.insert("contoso".to_string(), "contoso.local".to_string());
        let creds = vec![make_cred("admin", "CONTOSO", "P@ss1")];
        let found = find_domain_credential("contoso.local", &creds, &map);
        assert!(found.is_some());
    }

    #[test]
    fn test_find_domain_credential_empty() {
        let map = HashMap::new();
        let creds: Vec<Credential> = vec![];
        assert!(find_domain_credential("contoso.local", &creds, &map).is_none());
    }
}
