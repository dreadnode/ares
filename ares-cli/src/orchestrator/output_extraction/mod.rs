//! Regex-based extraction of discoveries from raw tool output text.
//!
//! This is the orchestrator-level safety net that mirrors Python's
//! `_process_output_text()` in `result_processing.py`. It parses raw
//! text from task results to catch credentials, hashes, hosts, shares,
//! and users that the per-tool parsers or LLM may have missed.
//!
//! The per-tool parsers in `ares_tools::parsers` are the primary extraction
//! mechanism (they run at tool-call time). This module runs on the full task
//! result text as a secondary pass.

mod hashes;
mod hosts;
mod passwords;
mod shares;
#[cfg(test)]
mod tests;
mod users;

use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::{Credential, Hash, Host, Share, User};

pub use hashes::{extract_cracked_passwords, extract_hashes};
pub use hosts::extract_hosts;
pub use passwords::extract_plaintext_passwords;
pub use shares::extract_shares;
pub use users::extract_users;

/// Strip ANSI escape sequences from text (e.g., color codes from tool output).
pub(crate) fn strip_ansi(s: &str) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*m").unwrap());
    RE.replace_all(s, "").into_owned()
}

/// All discoveries extracted from raw output text.
#[derive(Debug, Default)]
pub struct TextExtractions {
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub shares: Vec<Share>,
}

impl TextExtractions {
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
            && self.hashes.is_empty()
            && self.hosts.is_empty()
            && self.users.is_empty()
            && self.shares.is_empty()
    }
}

/// Extract all discoverable entities from raw output text.
///
/// Runs all extraction passes and returns the combined results.
pub fn extract_from_output_text(output: &str, default_domain: &str) -> TextExtractions {
    let mut result = TextExtractions::default();
    if output.is_empty() {
        return result;
    }

    result.hosts = extract_hosts(output);
    result.users = extract_users(output, default_domain);
    result.credentials = extract_plaintext_passwords(output, default_domain);
    result.shares = extract_shares(output);
    result.hashes = extract_hashes(output, default_domain);

    let cracked = extract_cracked_passwords(output, default_domain);
    result.credentials.extend(cracked);

    result
}

/// Validate a credential pair — matches Python's add_credential() rejection checks.
pub(crate) fn is_valid_credential(username: &str, password: &str) -> bool {
    if username.is_empty() || password.is_empty() {
        return false;
    }
    if username.contains('/') || username.contains('\\') || username.ends_with(".txt") {
        return false;
    }
    if password.contains('/') || password.contains('\\') || password.ends_with(".txt") {
        return false;
    }
    let user_lower = username.to_lowercase();
    if matches!(user_lower.as_str(), "(none)" | "none" | "null" | "(null)") {
        return false;
    }
    let user_upper = username.to_uppercase();
    if user_upper.starts_with("EVIL") && user_upper.ends_with('$') {
        let middle = &user_upper[4..user_upper.len() - 1];
        if middle.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    let pw_lower = password.to_lowercase();
    if matches!(
        pw_lower.as_str(),
        "(null)"
            | "(null:null)"
            | "*blank*"
            | "<blank>"
            | "n/a"
            | "[+]"
            | "[-]"
            | "password"
            | "no"
            | "yes"
            | "true"
            | "false"
            | "unknown"
            | "none"
            | "null"
            | "fail"
            | "failed"
            | "error"
            | "status"
            | "success"
            | "enabled"
            | "disabled"
            | "required"
            | "allowed"
            | "denied"
    ) {
        return false;
    }
    if password.len() < 3 {
        return false;
    }
    if password.len() > 128 {
        return false;
    }
    if password.len() > 40 && password.chars().all(|c| c.is_ascii_hexdigit() || c == '$') {
        return false;
    }
    true
}

pub(crate) fn make_credential(
    username: &str,
    password: &str,
    domain: &str,
    source: &str,
) -> Credential {
    Credential {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.to_string(),
        password: password.to_string(),
        domain: domain.to_string(),
        source: source.to_string(),
        discovered_at: Some(chrono::Utc::now()),
        is_admin: false,
        parent_id: None,
        attack_step: 0,
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn is_valid_credential_accepts_normal() {
        assert!(is_valid_credential("alice", "P@ssw0rd!"));
    }

    #[test]
    fn is_valid_credential_rejects_empty_user() {
        assert!(!is_valid_credential("", "P@ssw0rd!"));
    }

    #[test]
    fn is_valid_credential_rejects_empty_pass() {
        assert!(!is_valid_credential("alice", ""));
    }

    #[test]
    fn is_valid_credential_rejects_path_in_user() {
        assert!(!is_valid_credential("alice/bob", "P@ssw0rd!"));
    }

    #[test]
    fn is_valid_credential_rejects_txt_suffix_pass() {
        assert!(!is_valid_credential("alice", "users.txt"));
    }

    #[test]
    fn is_valid_credential_rejects_none_user() {
        assert!(!is_valid_credential("none", "P@ssw0rd!"));
        assert!(!is_valid_credential("(none)", "P@ssw0rd!"));
    }

    #[test]
    fn is_valid_credential_rejects_short_pass() {
        assert!(!is_valid_credential("alice", "ab"));
    }

    #[test]
    fn is_valid_credential_rejects_long_pass() {
        let long = "a".repeat(129);
        assert!(!is_valid_credential("alice", &long));
    }

    #[test]
    fn is_valid_credential_rejects_hash_body_pass() {
        // >40 chars, all hex+$ → hash fragment
        let hash = "aabbccddeeff00112233445566778899aabbccdd$";
        assert!(!is_valid_credential("alice", hash));
    }

    #[test]
    fn is_valid_credential_rejects_evil_machine_account() {
        assert!(!is_valid_credential("EVIL123$", "P@ssw0rd!"));
    }

    #[test]
    fn is_valid_credential_rejects_noise_passwords() {
        for pw in &["(null)", "*blank*", "<blank>", "password", "none", "fail"] {
            assert!(!is_valid_credential("alice", pw), "should reject: {pw}");
        }
    }

    #[test]
    fn strip_ansi_removes_color_codes() {
        let input = "\x1b[32mGreen\x1b[0m text";
        assert_eq!(strip_ansi(input), "Green text");
    }

    #[test]
    fn strip_ansi_no_codes_unchanged() {
        let input = "plain text";
        assert_eq!(strip_ansi(input), "plain text");
    }

    #[test]
    fn text_extractions_is_empty_default() {
        let e = TextExtractions::default();
        assert!(e.is_empty());
    }

    #[test]
    fn extract_from_output_text_empty() {
        let result = extract_from_output_text("", "corp.local");
        assert!(result.is_empty());
    }
}
