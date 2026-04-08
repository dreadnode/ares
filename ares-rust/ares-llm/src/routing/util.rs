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
    let saving_re = regex::Regex::new(r"Saving ticket in ([^\s]+\.ccache)").ok()?;
    if let Some(caps) = saving_re.captures(output) {
        return Some(caps[1].to_string());
    }

    let fallback_re = regex::Regex::new(r"([A-Za-z0-9_.-]+\.ccache)").ok()?;
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
