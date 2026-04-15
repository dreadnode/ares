//! Routing utility functions.

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
    use std::sync::OnceLock;
    static SAVING_RE: OnceLock<regex::Regex> = OnceLock::new();
    static FALLBACK_RE: OnceLock<regex::Regex> = OnceLock::new();

    let saving_re = SAVING_RE.get_or_init(|| {
        regex::Regex::new(r"Saving ticket in ([^\s]+\.ccache)").expect("valid regex")
    });
    if let Some(caps) = saving_re.captures(output) {
        return Some(caps[1].to_string());
    }

    let fallback_re = FALLBACK_RE
        .get_or_init(|| regex::Regex::new(r"([A-Za-z0-9_.-]+\.ccache)").expect("valid regex"));
    if let Some(caps) = fallback_re.captures(output) {
        return Some(caps[1].to_string());
    }

    None
}

/// Extract the hostname from an SPN (e.g. "MSSQLSvc/db01.contoso.local" -> "db01.contoso.local").
pub fn extract_host_from_spn(spn: &str) -> Option<String> {
    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    if parts.len() == 2 && parts[1].contains('.') {
        // Strip port suffix if present (e.g. "db01.contoso.local:1433")
        let host = parts[1].split(':').next().unwrap_or(parts[1]);
        Some(host.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_pass_the_hash_compatible ---

    #[test]
    fn test_pth_compatible_lm_nt_format() {
        assert!(is_pass_the_hash_compatible(
            "aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c"
        ));
    }

    #[test]
    fn test_pth_compatible_nt_only() {
        assert!(is_pass_the_hash_compatible(
            "313b6f423a71d74c0a1b8a2f43b22d4c"
        ));
    }

    #[test]
    fn test_pth_not_compatible_empty() {
        assert!(!is_pass_the_hash_compatible(""));
    }

    #[test]
    fn test_pth_not_compatible_dollar_sign() {
        assert!(!is_pass_the_hash_compatible("$krb5tgs$23$svc_sql"));
    }

    #[test]
    fn test_pth_not_compatible_short() {
        assert!(!is_pass_the_hash_compatible("aabbccdd"));
    }

    #[test]
    fn test_pth_not_compatible_non_hex() {
        assert!(!is_pass_the_hash_compatible(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_pth_compatible_with_whitespace() {
        assert!(is_pass_the_hash_compatible(
            "  313b6f423a71d74c0a1b8a2f43b22d4c  "
        ));
    }

    // --- extract_ticket_path ---

    #[test]
    fn test_extract_ticket_path_saving_format() {
        let output = "[*] Saving ticket in admin.ccache";
        assert_eq!(
            extract_ticket_path(output),
            Some("admin.ccache".to_string())
        );
    }

    #[test]
    fn test_extract_ticket_path_fallback() {
        let output = "Ticket written to krbtgt_contoso.ccache";
        assert_eq!(
            extract_ticket_path(output),
            Some("krbtgt_contoso.ccache".to_string())
        );
    }

    #[test]
    fn test_extract_ticket_path_none() {
        assert_eq!(extract_ticket_path("No ticket found"), None);
    }

    #[test]
    fn test_extract_ticket_path_empty() {
        assert_eq!(extract_ticket_path(""), None);
    }

    // --- extract_host_from_spn ---

    #[test]
    fn test_extract_host_from_spn_mssql() {
        assert_eq!(
            extract_host_from_spn("MSSQLSvc/db01.contoso.local"),
            Some("db01.contoso.local".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_spn_with_port() {
        assert_eq!(
            extract_host_from_spn("MSSQLSvc/db01.contoso.local:1433"),
            Some("db01.contoso.local".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_spn_cifs() {
        assert_eq!(
            extract_host_from_spn("CIFS/dc01.contoso.local"),
            Some("dc01.contoso.local".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_spn_no_slash() {
        assert_eq!(extract_host_from_spn("krbtgt"), None);
    }

    #[test]
    fn test_extract_host_from_spn_no_dots() {
        assert_eq!(extract_host_from_spn("HTTP/localhost"), None);
    }
}
