//! Regex-based extraction of discoveries from raw tool output text.
//!
//! Orchestrator-level safety net: parses raw text from task results to catch
//! credentials, hashes, hosts, shares, and users that the per-tool parsers or
//! LLM may have missed.
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

/// Tool-call context paired with stdout, used by `extract_from_output_text`
/// to gate noisy regexes on the invoking tool's arguments.
///
/// `arguments` is best-effort: when None (e.g. legacy bare-string tool_outputs
/// payloads), extractors fall back to untyped behavior.
pub struct ToolOutputCtx<'a> {
    pub arguments: Option<&'a serde_json::Value>,
    pub output: &'a str,
}

impl<'a> ToolOutputCtx<'a> {
    /// Returns true when the invoking arguments indicate the tool was authenticated
    /// with a hash rather than a plaintext password. Tools like nxc/netexec echo the
    /// supplied secret back on success lines (`[+] DOMAIN\user:secret (Pwn3d!)`),
    /// so a hash-auth invocation produces a hash where credential regexes expect a
    /// password. Extractors must short-circuit `password` regexes for these calls.
    pub(crate) fn is_hash_auth(&self) -> bool {
        let Some(args) = self.arguments else {
            return false;
        };
        let Some(obj) = args.as_object() else {
            return false;
        };
        for (k, v) in obj {
            let key = k.to_lowercase();
            // Common spellings across our tool wrappers (nxc, impacket-*, etc.)
            let is_hash_key = matches!(
                key.as_str(),
                "hash" | "hashes" | "nthash" | "lmhash" | "ntlm_hash" | "nt_hash" | "lm_hash"
            );
            if !is_hash_key {
                continue;
            }
            let nonempty = match v {
                serde_json::Value::String(s) => !s.trim().is_empty(),
                serde_json::Value::Array(a) => !a.is_empty(),
                serde_json::Value::Null => false,
                _ => true,
            };
            if nonempty {
                return true;
            }
        }
        false
    }
}

/// Extract all discoverable entities from raw output text.
///
/// Runs all extraction passes and returns the combined results.
pub fn extract_from_output_text(ctx: &ToolOutputCtx<'_>, default_domain: &str) -> TextExtractions {
    let mut result = TextExtractions::default();
    if ctx.output.is_empty() {
        return result;
    }

    result.hosts = extract_hosts(ctx.output);
    result.users = extract_users(ctx.output, default_domain);
    result.credentials = extract_plaintext_passwords(ctx, default_domain);
    result.shares = extract_shares(ctx.output);
    result.hashes = extract_hashes(ctx.output, default_domain);

    let cracked = extract_cracked_passwords(ctx.output, default_domain);
    result.credentials.extend(cracked);

    result
}

/// Validate a credential pair — rejects path-like or empty values.
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
    // Reject hash-shaped strings being stored as cleartext credentials.
    //
    // Hashes belong in `state.hashes`, not `state.credentials`. When a hash
    // leaks into the credentials list the credential resolver will inject it
    // as a `-p <hex>` cleartext password to impacket / netexec / etc., which
    // is never going to authenticate. Worse, those failed auth attempts
    // increment badPwdCount on the real account, eventually locking out the
    // legitimate user before the chain can use the real cracked password.
    // Hashes are dense hex and have well-known lengths — reject all-hex
    // passwords at the boundary so they can't pollute the credential set
    // even if an upstream extractor mistakenly emits them.
    //
    // Common shapes we reject:
    //   32 hex            → NTLM single hash
    //   16 hex            → LM single hash
    //   40 hex            → SHA1 / older NT
    //   64 hex            → SHA256
    //   65 hex incl ':'   → LM:NTLM with separator
    //   $-prefixed        → hashcat-style multi-field hashes
    let pw_no_sep: String = password
        .chars()
        .filter(|c| !matches!(*c, ':' | '$'))
        .collect();
    if !pw_no_sep.is_empty()
        && pw_no_sep.chars().all(|c| c.is_ascii_hexdigit())
        && matches!(
            pw_no_sep.len(),
            16 | 32 | 40 | 48 | 56 | 64 | 65 | 80 | 96 | 128
        )
    {
        return false;
    }
    if password.len() > 40 && password.chars().all(|c| c.is_ascii_hexdigit() || c == '$') {
        return false;
    }
    if password.starts_with("$krb5") || password.starts_with("$NT$") || password.starts_with("$LM$")
    {
        return false;
    }
    // Reject "ef961e2fd18a412...6bf150" — LLM-truncated hash display being
    // mis-matched as a cleartext plaintext by the cracker regex. An ellipsis
    // in the middle of a candidate password is never a real password; it's
    // a hash that an LLM summarized for human display and an extraction
    // regex then captured as if it were the cracked plaintext.
    if password.contains("...") {
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
    fn is_valid_credential_rejects_ntlm_hash() {
        // 32 hex chars — NTLM hash mis-shoved into the password field
        assert!(!is_valid_credential(
            "alice",
            "831486ac7f26860c9e2f51ac91e1a07a"
        ));
    }

    #[test]
    fn is_valid_credential_rejects_lm_ntlm_with_separator() {
        // LM:NTLM concatenation — 65 chars including the ':'
        assert!(!is_valid_credential(
            "alice",
            "aad3b435b51404eeaad3b435b51404ee:831486ac7f26860c9e2f51ac91e1a07a"
        ));
    }

    #[test]
    fn is_valid_credential_rejects_sha256_hash() {
        assert!(!is_valid_credential(
            "alice",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn is_valid_credential_rejects_krb5asrep_blob() {
        let blob = "$krb5asrep$23$alice@CONTOSO.LOCAL:hashbody:plaintext";
        assert!(!is_valid_credential("alice", blob));
    }

    #[test]
    fn is_valid_credential_rejects_llm_truncated_hash() {
        // LLMs summarize hashes with ellipsis when reporting to the orchestrator.
        // The cracked-AS-REP regex then captures the truncated display as the
        // "plaintext" group. Reject anything containing "..." — never a real password.
        assert!(!is_valid_credential("alice", "ef961e2fd18a412...6bf150"));
    }

    #[test]
    fn is_valid_credential_accepts_short_hex_word() {
        // Legitimately short hex-looking password ("decade", "facade" etc.) —
        // 6 chars, all hex, but NOT a known hash length. Must still accept.
        assert!(is_valid_credential("alice", "decade"));
        assert!(is_valid_credential("alice", "facade"));
    }

    #[test]
    fn is_valid_credential_accepts_short_hex_at_known_length_but_not_pure_hex() {
        // 32 chars but contains non-hex — not a hash, should accept.
        assert!(is_valid_credential(
            "alice",
            "P@ssw0rd-with-32-chars-of-stuff!"
        ));
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
        let ctx = ToolOutputCtx {
            arguments: None,
            output: "",
        };
        let result = extract_from_output_text(&ctx, "contoso.local");
        assert!(result.is_empty());
    }

    #[test]
    fn is_hash_auth_detects_common_keys() {
        let args = serde_json::json!({"hashes": "aad3:abcd"});
        let ctx = ToolOutputCtx {
            arguments: Some(&args),
            output: "",
        };
        assert!(ctx.is_hash_auth());

        let args = serde_json::json!({"nthash": "abcd"});
        let ctx = ToolOutputCtx {
            arguments: Some(&args),
            output: "",
        };
        assert!(ctx.is_hash_auth());

        let args = serde_json::json!({"hashes": ""});
        let ctx = ToolOutputCtx {
            arguments: Some(&args),
            output: "",
        };
        assert!(!ctx.is_hash_auth());

        let args = serde_json::json!({"password": "P@ss"});
        let ctx = ToolOutputCtx {
            arguments: Some(&args),
            output: "",
        };
        assert!(!ctx.is_hash_auth());

        let ctx = ToolOutputCtx {
            arguments: None,
            output: "",
        };
        assert!(!ctx.is_hash_auth());
    }
}
