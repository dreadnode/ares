//! Credential lookup and trust-scope validation for a given domain.

use std::collections::HashMap;

use ares_core::models::{Credential, TrustInfo};

use super::domain::normalize_domain;

/// Check if a credential is valid for authenticating to a target domain.
///
/// Enforces AD trust-scope rules:
/// - Same domain: always valid
/// - Parent → child: parent-domain creds can authenticate to child domain LDAP
/// - Child → parent: valid (NTLM/Kerberos auth traverses parent-child trust)
/// - Cross-forest bidirectional: valid (NTLM auth traverses forest trust)
/// - Cross-forest one-way inbound only: blocked
pub fn is_valid_credential_for_domain(
    cred_domain: &str,
    target_domain: &str,
    trusted_domains: &HashMap<String, TrustInfo>,
) -> bool {
    let cred_lower = cred_domain.to_lowercase();
    let target_lower = target_domain.to_lowercase();

    // Same domain: always valid
    if cred_lower == target_lower {
        return true;
    }

    // Parent → child: target has more FQDN parts and ends with cred domain
    // e.g. cred=contoso.local, target=child.contoso.local
    if target_lower.ends_with(&format!(".{cred_lower}")) {
        return true;
    }

    // Child → parent: valid — NTLM/Kerberos authentication traverses the
    // parent-child trust bidirectionally. The target DC forwards the auth
    // request to the child domain DC via the trust's secure channel.
    // e.g. cred=child.contoso.local, target=contoso.local
    if cred_lower.ends_with(&format!(".{target_lower}")) {
        return true;
    }

    // Cross-forest: allow if bidirectional trust exists
    if let Some(trust) = trusted_domains.get(&target_lower) {
        if trust.direction == "bidirectional" || trust.direction == "outbound" {
            return true;
        }
    }
    if let Some(trust) = trusted_domains.get(&cred_lower) {
        if trust.direction == "bidirectional" || trust.direction == "inbound" {
            return true;
        }
    }

    // Unknown relationship: block by default (cross-domain LDAP without trust info is risky)
    false
}

/// Find a credential for a given domain with trust-scope enforcement.
///
/// Prefers credentials with a password over those with only a hash.
/// Falls back to parent-domain credentials for child domains.
pub fn find_domain_credential<'a>(
    domain: &str,
    credentials: &'a [Credential],
    netbios_to_fqdn: &HashMap<String, String>,
    trusted_domains: &HashMap<String, TrustInfo>,
) -> Option<&'a Credential> {
    let normalized = normalize_domain(domain, netbios_to_fqdn);

    // First pass: same-domain credential with non-empty password
    let with_password = credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        cred_domain == normalized && !c.password.is_empty()
    });

    if with_password.is_some() {
        return with_password;
    }

    // Second pass: same-domain credential (any)
    let same_domain = credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        cred_domain == normalized
    });

    if same_domain.is_some() {
        return same_domain;
    }

    // Third pass: parent-domain credential (for child domains only)
    credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        !cred_domain.is_empty()
            && is_valid_credential_for_domain(&cred_domain, &normalized, trusted_domains)
            && !c.password.is_empty()
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
    fn find_domain_credential_with_password() {
        let map = HashMap::new();
        let trusts = HashMap::new();
        let creds = vec![
            make_cred("admin", "contoso.local", "P@ss1"),
            make_cred("jdoe", "contoso.local", ""),
        ];
        let found = find_domain_credential("contoso.local", &creds, &map, &trusts);
        assert!(found.is_some());
        assert_eq!(found.unwrap().username, "admin");
    }

    #[test]
    fn find_domain_credential_prefers_password() {
        let map = HashMap::new();
        let trusts = HashMap::new();
        let creds = vec![
            make_cred("hash_user", "contoso.local", ""),
            make_cred("pass_user", "contoso.local", "Secret"),
        ];
        let found = find_domain_credential("contoso.local", &creds, &map, &trusts);
        assert_eq!(found.unwrap().username, "pass_user");
    }

    #[test]
    fn find_domain_credential_falls_back_to_no_password() {
        let map = HashMap::new();
        let trusts = HashMap::new();
        let creds = vec![make_cred("hash_user", "contoso.local", "")];
        let found = find_domain_credential("contoso.local", &creds, &map, &trusts);
        assert_eq!(found.unwrap().username, "hash_user");
    }

    #[test]
    fn find_domain_credential_none_for_wrong_domain() {
        let map = HashMap::new();
        let trusts = HashMap::new();
        let creds = vec![make_cred("admin", "fabrikam.local", "P@ss1")];
        let found = find_domain_credential("contoso.local", &creds, &map, &trusts);
        assert!(found.is_none());
    }

    #[test]
    fn find_domain_credential_netbios_resolution() {
        let mut map = HashMap::new();
        map.insert("contoso".to_string(), "contoso.local".to_string());
        let trusts = HashMap::new();
        let creds = vec![make_cred("admin", "CONTOSO", "P@ss1")];
        let found = find_domain_credential("contoso.local", &creds, &map, &trusts);
        assert!(found.is_some());
    }

    #[test]
    fn find_domain_credential_empty() {
        let map = HashMap::new();
        let trusts = HashMap::new();
        let creds: Vec<Credential> = vec![];
        assert!(find_domain_credential("contoso.local", &creds, &map, &trusts).is_none());
    }

    #[test]
    fn same_domain_valid() {
        let trusts = HashMap::new();
        assert!(is_valid_credential_for_domain(
            "contoso.local",
            "contoso.local",
            &trusts
        ));
    }

    #[test]
    fn parent_to_child_valid() {
        let trusts = HashMap::new();
        assert!(is_valid_credential_for_domain(
            "contoso.local",
            "child.contoso.local",
            &trusts
        ));
    }

    #[test]
    fn child_to_parent_valid() {
        let trusts = HashMap::new();
        assert!(is_valid_credential_for_domain(
            "child.contoso.local",
            "contoso.local",
            &trusts
        ));
    }

    #[test]
    fn cross_forest_bidirectional_valid() {
        let mut trusts = HashMap::new();
        trusts.insert(
            "fabrikam.local".to_string(),
            TrustInfo {
                domain: "fabrikam.local".to_string(),
                flat_name: "FABRIKAM".to_string(),
                direction: "bidirectional".to_string(),
                trust_type: "forest".to_string(),
                sid_filtering: true,
                security_identifier: None,
            },
        );
        assert!(is_valid_credential_for_domain(
            "contoso.local",
            "fabrikam.local",
            &trusts
        ));
    }

    #[test]
    fn cross_forest_no_trust_blocked() {
        let trusts = HashMap::new();
        // No trust info at all → blocked
        assert!(!is_valid_credential_for_domain(
            "contoso.local",
            "fabrikam.local",
            &trusts
        ));
    }

    #[test]
    fn parent_cred_for_child_domain() {
        let trusts = HashMap::new();
        let creds = vec![make_cred("admin", "contoso.local", "P@ss1")];
        let map = HashMap::new();
        let found = find_domain_credential("child.contoso.local", &creds, &map, &trusts);
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain, "contoso.local");
    }

    #[test]
    fn child_cred_valid_for_parent_domain() {
        let trusts = HashMap::new();
        let creds = vec![make_cred("admin", "child.contoso.local", "P@ss1")];
        let map = HashMap::new();
        let found = find_domain_credential("contoso.local", &creds, &map, &trusts);
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain, "child.contoso.local");
    }
}
