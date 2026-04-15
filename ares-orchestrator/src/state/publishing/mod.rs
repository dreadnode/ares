//! Publishing methods — add credentials, hashes, hosts, and vulnerabilities
//! to both in-memory state and Redis.

mod credentials;
mod entities;
mod hosts;
mod milestones;

use regex::Regex;
use std::sync::LazyLock;

/// Regex matching `Password` (case-insensitive) followed by optional `:` and space.
pub(super) static PASSWORD_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^password\s*:\s*").unwrap());

/// Regex matching trailing parenthetical metadata like ` (Guest)`, ` (Pwn3d!)`.
pub(super) static TRAILING_PAREN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+\([^)]+\)\s*$").unwrap());

/// Sanitize and validate a credential before storage.
///
/// Mirrors Python's `add_credential()` — strips noise from password values,
/// normalizes `user@domain@domain` usernames, resolves NetBIOS domains to FQDN,
/// and rejects invalid entries. Returns `None` if the credential should be dropped.
pub(super) fn sanitize_credential(
    mut cred: ares_core::models::Credential,
    netbios_to_fqdn: &std::collections::HashMap<String, String>,
) -> Option<ares_core::models::Credential> {
    use crate::output_extraction::strip_ansi;

    // Strip ANSI escape codes (tools like NetExec emit colored output)
    cred.username = strip_ansi(&cred.username);
    cred.password = strip_ansi(&cred.password);
    cred.domain = strip_ansi(&cred.domain);

    // Trim whitespace
    cred.username = cred.username.trim().to_string();
    cred.password = cred.password.trim().to_string();
    cred.domain = cred.domain.trim().to_string();

    // Strip "Password: " / "Password:" prefix from password
    if PASSWORD_PREFIX_RE.is_match(&cred.password) {
        cred.password = PASSWORD_PREFIX_RE.replace(&cred.password, "").to_string();
    }

    // Strip trailing parenthetical metadata: "svc_test (Guest)" → "svc_test"
    if TRAILING_PAREN_RE.is_match(&cred.password) {
        cred.password = TRAILING_PAREN_RE.replace(&cred.password, "").to_string();
    }

    // Strip ellipsis truncation artifacts (matches Python add_credential)
    while cred.password.ends_with("...") {
        cred.password = cred.password[..cred.password.len() - 3].trim().to_string();
    }
    while cred.password.ends_with('\u{2026}') {
        cred.password.pop();
        cred.password = cred.password.trim().to_string();
    }

    // Normalize username with embedded @domain suffixes
    // e.g. "sam.wilson@child.contoso.local@fabrikam.local"
    //   → username="sam.wilson", domain="child.contoso.local"
    if cred.username.contains('@') {
        let username_clone = cred.username.clone();
        let parts: Vec<&str> = username_clone.splitn(2, '@').collect();
        if parts.len() == 2 && !parts[0].is_empty() {
            let base_username = parts[0].to_string();
            let domain_part = parts[1].split('@').next().unwrap_or(parts[1]).to_string();
            if domain_part.contains('.') {
                cred.username = base_username;
                cred.domain = domain_part;
            }
        }
    }

    // Resolve NetBIOS domain to FQDN (e.g. "CHILD" → "child.contoso.local")
    if !cred.domain.is_empty() && !cred.domain.contains('.') {
        let domain_upper = cred.domain.to_uppercase();
        if let Some(fqdn) = netbios_to_fqdn.get(&domain_upper) {
            // netbios_to_fqdn maps SHORTNAME → host.domain.local
            // Extract the domain suffix
            let parts: Vec<&str> = fqdn.split('.').collect();
            if parts.len() >= 3 {
                cred.domain = parts[1..].join(".");
            } else {
                cred.domain = fqdn.clone();
            }
        } else {
            // Try matching domain as prefix of any FQDN domain suffix
            let domain_lower = cred.domain.to_lowercase();
            for fqdn in netbios_to_fqdn.values() {
                let fqdn_parts: Vec<&str> = fqdn.split('.').collect();
                if fqdn_parts.len() >= 3 {
                    let domain_suffix = fqdn_parts[1..].join(".");
                    let first_label = fqdn_parts[1].to_lowercase();
                    if first_label == domain_lower {
                        cred.domain = domain_suffix;
                        break;
                    }
                }
            }
        }
    }

    // Validate after sanitization
    if !crate::output_extraction::is_valid_credential(&cred.username, &cred.password) {
        return None;
    }

    Some(cred)
}

/// Check if a hostname is an AWS internal PTR name.
pub(super) fn is_aws_hostname(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();
    lower.starts_with("ip-") && lower.contains("compute.internal")
}
