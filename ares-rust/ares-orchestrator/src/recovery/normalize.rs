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
