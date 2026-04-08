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
