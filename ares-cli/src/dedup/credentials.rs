use std::collections::HashSet;

use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::Credential;

use super::strip_trailing_dot;

/// Strip ANSI escape sequences from text.
pub(super) static RE_ANSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*m").unwrap());

pub(super) fn strip_ansi(s: &str) -> String {
    RE_ANSI.replace_all(s, "").to_string()
}

/// Regex matching `Password` (case-insensitive) followed by optional `:` and space.
static PASSWORD_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^password\s*:\s*").unwrap());

/// Regex matching trailing parenthetical metadata like ` (Guest)`, ` (Pwn3d!)`.
static TRAILING_PAREN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+\([^)]+\)\s*$").unwrap());

/// Sanitize credentials in-place: strip noise from passwords, normalize usernames
/// with embedded `@domain` suffixes, and remove garbage entries.
pub(crate) fn sanitize_credentials(creds: &mut Vec<Credential>) {
    for cred in creds.iter_mut() {
        cred.username = strip_ansi(&cred.username);
        cred.password = strip_ansi(&cred.password);
        cred.domain = strip_ansi(&cred.domain);
        cred.domain = strip_trailing_dot(cred.domain.trim()).to_string();

        if PASSWORD_PREFIX_RE.is_match(&cred.password) {
            cred.password = PASSWORD_PREFIX_RE.replace(&cred.password, "").to_string();
        }

        if TRAILING_PAREN_RE.is_match(&cred.password) {
            cred.password = TRAILING_PAREN_RE.replace(&cred.password, "").to_string();
        }

        // e.g. "sam.wilson@child.contoso.local@fabrikam.local"
        //   → username="sam.wilson", domain="child.contoso.local"
        if cred.username.contains('@') {
            let username_clone = cred.username.clone();
            let parts: Vec<&str> = username_clone.splitn(2, '@').collect();
            if parts.len() == 2 && !parts[0].is_empty() {
                let base_username = parts[0].to_string();
                // The first @domain part is the real domain; strip any further @domain suffixes
                let domain_part = parts[1].split('@').next().unwrap_or(parts[1]).to_string();
                if domain_part.contains('.') {
                    cred.username = base_username;
                    cred.domain = strip_trailing_dot(&domain_part).to_string();
                }
            }
        }
    }

    creds.retain(|c| {
        let pw = c.password.trim();
        let username = c.username.trim().to_lowercase();
        if pw.is_empty() || pw.to_lowercase() == "password" {
            return false;
        }
        if pw.eq_ignore_ascii_case("discovered") {
            return false;
        }
        if pw.contains("[NT]") || pw.contains("[SHA1]") {
            return false;
        }
        if username.contains('/') || username.contains('\\') {
            return false;
        }
        if username.starts_with("evil") && username.ends_with('$') {
            return false;
        }
        true
    });
}

pub(crate) fn dedup_credentials(creds: &[Credential]) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for c in creds {
        if c.password.is_empty() {
            continue;
        }
        let key = (
            c.domain.trim().to_lowercase(),
            c.username.trim().to_lowercase(),
            c.password.clone(),
        );
        if seen.insert(key) {
            let mut normalized = c.clone();
            normalized.domain = c.domain.trim().to_lowercase();
            normalized.username = c.username.trim().to_lowercase();
            result.push(normalized);
        }
    }
    result
}
