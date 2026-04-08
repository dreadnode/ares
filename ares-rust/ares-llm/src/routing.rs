//! Routing enrichment — DC discovery, credential matching, domain normalization.
//!
//! Ports pure logic from `src/ares/core/dispatcher/routing.py`.
//! Phase 1 provides domain normalization and credential lookup.
//! Phase 2 will add full DC discovery tiers and payload enrichment.

use std::collections::HashMap;

use ares_core::models::Credential;

/// Normalize a domain name: resolve NetBIOS to FQDN, lowercase.
///
/// If the domain contains a dot, it's assumed to be an FQDN and returned as-is
/// (lowercased). Otherwise, the NetBIOS-to-FQDN map is consulted.
pub fn normalize_domain(domain: &str, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let lower = domain.to_lowercase();
    if lower.contains('.') {
        return lower;
    }
    // Try NetBIOS lookup
    if let Some(fqdn) = netbios_to_fqdn.get(&lower) {
        return fqdn.to_lowercase();
    }
    // Also try uppercase key (Python dict was case-insensitive)
    if let Some(fqdn) = netbios_to_fqdn.get(&domain.to_uppercase()) {
        return fqdn.to_lowercase();
    }
    lower
}

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

/// Find a DC IP for a domain from the cached domain_controllers map.
///
/// This is tier 0 of the DC discovery hierarchy. Higher tiers (hostname
/// matching, service detection, DNS SRV, LDAP rootDSE) will be added in
/// Phase 2.
pub fn find_dc_ip_cached(
    domain: &str,
    domain_controllers: &HashMap<String, String>,
    netbios_to_fqdn: &HashMap<String, String>,
) -> Option<String> {
    let normalized = normalize_domain(domain, netbios_to_fqdn);
    domain_controllers.get(&normalized).cloned()
}

/// Check if a hash value is NTLM format (suitable for pass-the-hash).
///
/// Valid formats: 32 hex chars, or `LM:NT` (32:32 hex pair).
pub fn is_pass_the_hash_compatible(hash_value: &str) -> bool {
    let hash = hash_value.trim();
    if hash.is_empty() || hash.contains('$') {
        return false;
    }

    // Check for LM:NT format (64 chars with colon in middle)
    if let Some((lm, nt)) = hash.split_once(':') {
        return lm.len() == 32
            && nt.len() == 32
            && lm.chars().all(|c| c.is_ascii_hexdigit())
            && nt.chars().all(|c| c.is_ascii_hexdigit());
    }

    // Check for single 32-char hex (NT hash only)
    hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract a .ccache ticket path from command output.
pub fn extract_ticket_path(output: &str) -> Option<String> {
    // Try "Saving ticket in <path>.ccache"
    let saving_re = regex::Regex::new(r"Saving ticket in ([^\s]+\.ccache)").ok()?;
    if let Some(caps) = saving_re.captures(output) {
        return Some(caps[1].to_string());
    }

    // Fallback: any .ccache filename
    let fallback_re = regex::Regex::new(r"([A-Za-z0-9_.-]+\.ccache)").ok()?;
    if let Some(caps) = fallback_re.captures(output) {
        return Some(caps[1].to_string());
    }

    None
}

/// Extract the hostname from a SPN (e.g. "MSSQLSvc/db01.contoso.local" → "db01.contoso.local").
pub fn extract_host_from_spn(spn: &str) -> Option<String> {
    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    if parts.len() == 2 && parts[1].contains('.') {
        Some(parts[1].to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_netbios_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("CONTOSO".to_string(), "contoso.local".to_string());
        m.insert("FABRIKAM".to_string(), "fabrikam.local".to_string());
        m
    }

    #[test]
    fn test_normalize_domain_fqdn() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("contoso.local", &map), "contoso.local");
        assert_eq!(normalize_domain("CONTOSO.LOCAL", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_netbios() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("CONTOSO", &map), "contoso.local");
        assert_eq!(normalize_domain("contoso", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_unknown() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("UNKNOWN", &map), "unknown");
    }

    #[test]
    fn test_find_domain_credential() {
        let map = sample_netbios_map();
        let creds = vec![
            Credential {
                id: "c1".into(),
                username: "user1".into(),
                domain: "contoso.local".into(),
                password: String::new(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            Credential {
                id: "c2".into(),
                username: "admin".into(),
                domain: "contoso.local".into(),
                password: "P@ss1".into(),
                source: String::new(),
                discovered_at: None,
                is_admin: true,
                parent_id: None,
                attack_step: 0,
            },
        ];
        let found = find_domain_credential("CONTOSO", &creds, &map).unwrap();
        assert_eq!(found.username, "admin"); // Prefers one with password
    }

    #[test]
    fn test_find_dc_ip_cached() {
        let map = sample_netbios_map();
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let ip = find_dc_ip_cached("contoso.local", &dcs, &map);
        assert_eq!(ip.as_deref(), Some("192.168.58.10"));
    }

    #[test]
    fn test_is_pass_the_hash_compatible() {
        // Valid LM:NT format
        assert!(is_pass_the_hash_compatible(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        ));
        // Valid NT-only format
        assert!(is_pass_the_hash_compatible(
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        ));
        // Invalid: bcrypt
        assert!(!is_pass_the_hash_compatible("$2b$10$abcdef"));
        // Invalid: empty
        assert!(!is_pass_the_hash_compatible(""));
        // Invalid: wrong length
        assert!(!is_pass_the_hash_compatible("abc123"));
    }

    #[test]
    fn test_extract_ticket_path() {
        let output = "Saving ticket in Administrator.ccache\nDone.";
        assert_eq!(
            extract_ticket_path(output),
            Some("Administrator.ccache".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_spn() {
        assert_eq!(
            extract_host_from_spn("MSSQLSvc/db01.contoso.local"),
            Some("db01.contoso.local".to_string())
        );
        assert_eq!(extract_host_from_spn("krbtgt"), None);
    }
}
