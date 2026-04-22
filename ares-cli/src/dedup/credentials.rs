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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred(user: &str, pass: &str, domain: &str) -> Credential {
        Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: user.to_string(),
            password: pass.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    // ── strip_ansi ──────────────────────────────────────────────────

    #[test]
    fn strip_ansi_removes_color_codes() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn strip_ansi_passthrough_clean() {
        assert_eq!(strip_ansi("clean text"), "clean text");
    }

    // ── sanitize_credentials ────────────────────────────────────────

    #[test]
    fn sanitize_strips_password_prefix() {
        let mut creds = vec![make_cred("admin", "Password: Secret123", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert_eq!(creds[0].password, "Secret123");
    }

    #[test]
    fn sanitize_strips_trailing_paren() {
        let mut creds = vec![make_cred("admin", "Secret123 (Pwn3d!)", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert_eq!(creds[0].password, "Secret123");
    }

    #[test]
    fn sanitize_removes_empty_password() {
        let mut creds = vec![make_cred("admin", "", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn sanitize_removes_password_literal() {
        let mut creds = vec![make_cred("admin", "password", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn sanitize_removes_discovered_marker() {
        let mut creds = vec![make_cred("admin", "discovered", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn sanitize_removes_hash_markers() {
        let mut creds = vec![
            make_cred("admin", "abc [NT]", "contoso.local"),
            make_cred("admin", "def [SHA1]", "contoso.local"),
        ];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn sanitize_removes_slash_usernames() {
        let mut creds = vec![make_cred("domain/admin", "pass", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn sanitize_removes_evil_machine_accounts() {
        let mut creds = vec![make_cred("evil$", "pass", "contoso.local")];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn sanitize_extracts_domain_from_upn() {
        let mut creds = vec![make_cred(
            "sam.wilson@child.contoso.local",
            "pass",
            "old_domain",
        )];
        sanitize_credentials(&mut creds);
        assert_eq!(creds[0].username, "sam.wilson");
        assert_eq!(creds[0].domain, "child.contoso.local");
    }

    #[test]
    fn sanitize_strips_trailing_dot_from_domain() {
        let mut creds = vec![make_cred("admin", "pass", "contoso.local.")];
        sanitize_credentials(&mut creds);
        assert_eq!(creds[0].domain, "contoso.local");
    }

    // ── dedup_credentials ───────────────────────────────────────────

    #[test]
    fn dedup_removes_duplicates() {
        let creds = vec![
            make_cred("admin", "pass1", "contoso.local"),
            make_cred("admin", "pass1", "contoso.local"),
        ];
        let result = dedup_credentials(&creds);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_keeps_different_passwords() {
        let creds = vec![
            make_cred("admin", "pass1", "contoso.local"),
            make_cred("admin", "pass2", "contoso.local"),
        ];
        let result = dedup_credentials(&creds);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn dedup_skips_empty_passwords() {
        let creds = vec![make_cred("admin", "", "contoso.local")];
        let result = dedup_credentials(&creds);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_case_insensitive_key() {
        let creds = vec![
            make_cred("Admin", "pass1", "CONTOSO.LOCAL"),
            make_cred("admin", "pass1", "contoso.local"),
        ];
        let result = dedup_credentials(&creds);
        assert_eq!(result.len(), 1);
    }
}
