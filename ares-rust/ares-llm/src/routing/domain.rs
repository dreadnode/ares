//! Domain normalization and hostname matching.

use std::collections::HashMap;

/// Normalize a domain name: resolve NetBIOS to FQDN, lowercase.
///
/// If the domain contains a dot, it's assumed to be an FQDN and returned as-is
/// (lowercased). Otherwise, the NetBIOS-to-FQDN map is consulted.
pub fn normalize_domain(domain: &str, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let lower = domain.to_lowercase();
    if lower.contains('.') {
        return lower;
    }
    // Try lowercase key
    if let Some(fqdn) = netbios_to_fqdn.get(&lower) {
        return fqdn.to_lowercase();
    }
    // Also try uppercase key (Python dict was case-insensitive)
    if let Some(fqdn) = netbios_to_fqdn.get(&domain.to_uppercase()) {
        return fqdn.to_lowercase();
    }
    lower
}

/// Check if a hostname belongs to a domain.
///
/// Extracts the domain portion from the hostname (everything after the first
/// dot) and compares exactly with the target domain. This prevents parent
/// domain false positives (e.g. `dc01.contoso.local` won't match
/// `child.contoso.local`).
pub(crate) fn hostname_matches_domain(hostname: &str, domain: &str) -> bool {
    if hostname.is_empty() || domain.is_empty() {
        return false;
    }
    let hostname_lower = hostname.to_lowercase();
    let domain_lower = domain.to_lowercase();

    // Extract domain from hostname: dc01.child.contoso.local -> child.contoso.local
    if let Some(dot_pos) = hostname_lower.find('.') {
        let hostname_domain = &hostname_lower[dot_pos + 1..];
        if hostname_domain == domain_lower {
            return true;
        }
    }

    // Fallback: hostname IS the domain (rare edge case)
    hostname_lower == domain_lower
}
