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
use ares_llm::tool_registry::provenance;

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
/// to gate noisy regexes on the invoking tool's name and arguments.
///
/// `name` and `arguments` are best-effort: when None (e.g. legacy bare-string
/// tool_outputs payloads), extractors fall back to untyped behavior — treating
/// the output as anonymous stdout with no auth-context guarantee. Prefer the
/// structured form so provenance gating is available.
pub struct ToolOutputCtx<'a> {
    pub name: Option<&'a str>,
    pub arguments: Option<&'a serde_json::Value>,
    pub output: &'a str,
}

impl<'a> ToolOutputCtx<'a> {
    /// Normalized invoking tool name (lowercased, path/extension stripped,
    /// `-` folded to `_`). None when no `name` was carried through (legacy
    /// bare-string outputs).
    ///
    /// The `-`→`_` fold keeps the provenance classifier robust against a tool
    /// registered as `evil_winrm` being written `evil-winrm` (or vice versa):
    /// a single-character skew must never silently disable a security gate.
    pub(crate) fn tool_name_normalized(&self) -> Option<String> {
        normalize_tool_name(self.name?)
    }

    /// Returns true when this tool's stdout is trustworthy for the *high-value*
    /// extractors (credentials, hashes, cracked-hash plaintexts) — i.e. the
    /// tool is neither an LLM-directed command shell nor an AD-attribute
    /// enumerator. The classification is owned by the tool registry (see
    /// [`provenance`]) and keyed on the registered tool name, so it stays in
    /// lock-step with the tools the LLM can actually invoke.
    ///
    /// - **LLM-directed shells** (`smbexec`, `wmiexec`, `mssql_command`, …)
    ///   echo whatever command the LLM chose, so a hallucinated or
    ///   prompt-injected `echo "[+] DOMAIN\admin:Pw"` would look legitimate.
    /// - **Attribute enumerators** (`rpcclient_command`, `ldap_search`,
    ///   `ldap_search_descriptions`, …) echo attribute values an attacker can
    ///   plant in a `description` field or a share.
    ///
    /// A `None` tool name (legacy bare-string outputs, tests) is treated as
    /// trustworthy to preserve behavior for existing structured extractors —
    /// stricter gating (e.g. anchored regex prefix) still applies at the
    /// regex layer.
    pub(crate) fn is_authenticating_tool(&self) -> bool {
        match self.tool_name_normalized() {
            Some(name) => provenance::stdout_trusts_secrets(&name),
            None => true,
        }
    }

    /// Alias used by non-credential extractors (hashes, cracked passwords) to
    /// make the intent at the call site legible. Same underlying gate as
    /// `is_authenticating_tool` — the same channels that can forge `[+] u:p`
    /// can forge `USER:RID:LM:NT:::`, so credentials AND hashes are gated
    /// together against both families of untrusted stdout.
    pub(crate) fn stdout_is_extraction_trustworthy(&self) -> bool {
        self.is_authenticating_tool()
    }

    /// Returns true when the tool is an LLM-directed remote command shell
    /// (`smbexec`/`wmiexec`/`psexec`/`evil_winrm`/`mssql_command`/`pth_winexe`/
    /// `ssh_with_password`/…). These tools have *no legitimate reason* to
    /// produce discovery output — they exist to execute LLM-chosen commands and
    /// echo the result. Any user/host/share extracted from their stdout is
    /// either the LLM inventing structure or an attacker planting one. Gated
    /// separately (via [`provenance::StdoutProvenance::LlmDirectedShell`]) from the
    /// attribute enumerators because those legitimately populate `state.users`
    /// on every operation and blocking them would break real enumeration
    /// workflows.
    pub(crate) fn is_llm_directed_shell(&self) -> bool {
        match self.tool_name_normalized() {
            Some(name) => provenance::is_llm_directed_shell(&name),
            None => false,
        }
    }

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
///
/// **Tiered provenance gating** (classification owned by the tool registry —
/// see [`provenance`] — and keyed on the registered tool name):
///
/// - **LLM-directed shells** (`smbexec`/`wmiexec`/`psexec`/`evil_winrm`/
///   `mssql_command`/`mssql_linked_xpcmdshell`/`pth_winexe`/`pth_wmic`/
///   `ssh_with_password`) — *every* extractor is suppressed. These tools have
///   no legitimate discovery output; their entire job is to echo an LLM-chosen
///   command. Any user/host/share/cred parsed from their stdout is either LLM
///   confabulation or an attacker planting one — including the "honeypot steer"
///   case, a forged host banner at an attacker-controlled IP.
/// - **Attribute enumerators** (`rpcclient_command`/`ldap_search`/
///   `ldap_search_descriptions`/`enumerate_users`/`run_bloodhound`/…) —
///   credentials and hashes are suppressed (attackers can plant `[+] u:p` in a
///   `description` field). Users/hosts/shares still extract — these tools are
///   the *primary* legitimate source of that data and blocking them would break
///   real enumeration workflows.
pub fn extract_from_output_text(ctx: &ToolOutputCtx<'_>, default_domain: &str) -> TextExtractions {
    let mut result = TextExtractions::default();
    if ctx.output.is_empty() {
        return result;
    }

    // LLM-directed shells emit zero legitimate discovery output — no user,
    // host, or share is ever a genuine finding from `echo`. Bail out entirely.
    if ctx.is_llm_directed_shell() {
        return result;
    }

    // Strip color/formatting escapes before every regex extractor. netexec /
    // rich-based tools sometimes force ANSI on their piped output; the SMB
    // banner regex uses `\s+` between columns which will not match a
    // `\x1b[32m` sequence, silently dropping the host row (leaving state with
    // only the seeded IP and no hostname/OS/services).
    let cleaned = strip_ansi(ctx.output);
    let ctx = ToolOutputCtx {
        name: ctx.name,
        arguments: ctx.arguments,
        output: cleaned.as_str(),
    };

    result.hosts = extract_hosts(ctx.output);
    result.users = extract_users(ctx.output, default_domain);
    result.shares = extract_shares(ctx.output);

    if ctx.stdout_is_extraction_trustworthy() {
        result.credentials = extract_plaintext_passwords(&ctx, default_domain);
        result.hashes = extract_hashes(ctx.output, default_domain);
        let cracked = extract_cracked_passwords(ctx.output, default_domain);
        result.credentials.extend(cracked);
    }

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

/// Normalized tool name (lowercased, path/extension stripped, `-` folded to
/// `_`) — the form the provenance classifier keys on.
pub(crate) fn normalize_tool_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let last = raw.rsplit(['/', '\\']).next()?;
    let base = last.trim_end_matches(".exe").trim_end_matches(".py");
    Some(base.to_ascii_lowercase().replace('-', "_"))
}

/// Apply the stdout-provenance rule to the *primary* parser's output.
///
/// [`provenance`] is the declared single source of truth for how far a tool's
/// stdout can be trusted, but it was wired only into this module — the regex
/// safety net — and not into `ares_tools::parsers::parse_tool_output`, which
/// produces the `discoveries` that actually reach state. So the module whose
/// contract says *nothing* parsed from an LLM-directed shell is a genuine
/// finding did not guard the path that matters.
///
/// Only the secret-bearing sections are dropped. The per-tool arms are
/// structured recognizers of a tool's own success banners, unlike the regex
/// net, so the attribute-enumerator rule is deliberately not applied here:
/// `enumerate_users` legitimately yields credentials out of `description`
/// attributes, and that is a real initial-access path, not a leak.
///
/// (`ares-tools` cannot see `ares-llm`, which is why this is applied by the
/// caller rather than inside the parser.)
pub(crate) fn gate_parsed_discoveries(
    tool: &str,
    mut discoveries: serde_json::Value,
) -> serde_json::Value {
    let is_shell = normalize_tool_name(tool).is_some_and(|n| provenance::is_llm_directed_shell(&n));
    if !is_shell {
        return discoveries;
    }
    if let Some(obj) = discoveries.as_object_mut() {
        for key in ["credentials", "hashes"] {
            if obj.remove(key).is_some() {
                tracing::warn!(
                    tool,
                    key,
                    "Dropped a secret parsed from an LLM-directed shell's stdout"
                );
            }
        }
    }
    discoveries
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
            name: None,
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
            name: None,
            arguments: Some(&args),
            output: "",
        };
        assert!(ctx.is_hash_auth());

        let args = serde_json::json!({"nthash": "abcd"});
        let ctx = ToolOutputCtx {
            name: None,
            arguments: Some(&args),
            output: "",
        };
        assert!(ctx.is_hash_auth());

        let args = serde_json::json!({"hashes": ""});
        let ctx = ToolOutputCtx {
            name: None,
            arguments: Some(&args),
            output: "",
        };
        assert!(!ctx.is_hash_auth());

        let args = serde_json::json!({"password": "P@ss"});
        let ctx = ToolOutputCtx {
            name: None,
            arguments: Some(&args),
            output: "",
        };
        assert!(!ctx.is_hash_auth());

        let ctx = ToolOutputCtx {
            name: None,
            arguments: None,
            output: "",
        };
        assert!(!ctx.is_hash_auth());
    }
}
