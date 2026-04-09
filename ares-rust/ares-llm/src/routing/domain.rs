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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("contoso".to_string(), "contoso.local".to_string());
        m.insert("FABRIKAM".to_string(), "fabrikam.local".to_string());
        m
    }

    // --- normalize_domain ---

    #[test]
    fn test_normalize_domain_fqdn_passthrough() {
        let map = make_map();
        assert_eq!(normalize_domain("contoso.local", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_fqdn_lowercased() {
        let map = make_map();
        assert_eq!(normalize_domain("CONTOSO.LOCAL", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_netbios_lowercase_key() {
        let map = make_map();
        assert_eq!(normalize_domain("contoso", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_netbios_uppercase_key() {
        let map = make_map();
        assert_eq!(normalize_domain("FABRIKAM", &map), "fabrikam.local");
    }

    #[test]
    fn test_normalize_domain_netbios_mixed_case() {
        let map = make_map();
        // "Fabrikam" → to_lowercase "fabrikam" not in map, to_uppercase "FABRIKAM" IS in map
        assert_eq!(normalize_domain("Fabrikam", &map), "fabrikam.local");
    }

    #[test]
    fn test_normalize_domain_unknown_netbios() {
        let map = make_map();
        assert_eq!(normalize_domain("UNKNOWN", &map), "unknown");
    }

    #[test]
    fn test_normalize_domain_empty() {
        let map = make_map();
        assert_eq!(normalize_domain("", &map), "");
    }

    // --- hostname_matches_domain ---

    #[test]
    fn test_hostname_matches_domain_basic() {
        assert!(hostname_matches_domain(
            "dc01.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn test_hostname_matches_domain_case_insensitive() {
        assert!(hostname_matches_domain(
            "DC01.CONTOSO.LOCAL",
            "contoso.local"
        ));
    }

    #[test]
    fn test_hostname_matches_domain_child_not_parent() {
        // dc01.child.contoso.local should match child.contoso.local, NOT contoso.local
        assert!(hostname_matches_domain(
            "dc01.child.contoso.local",
            "child.contoso.local"
        ));
        assert!(!hostname_matches_domain(
            "dc01.child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn test_hostname_matches_domain_empty_inputs() {
        assert!(!hostname_matches_domain("", "contoso.local"));
        assert!(!hostname_matches_domain("dc01.contoso.local", ""));
        assert!(!hostname_matches_domain("", ""));
    }

    #[test]
    fn test_hostname_matches_domain_no_dots() {
        assert!(!hostname_matches_domain("dc01", "contoso.local"));
    }

    #[test]
    fn test_hostname_is_domain() {
        assert!(hostname_matches_domain("contoso.local", "contoso.local"));
    }
}
