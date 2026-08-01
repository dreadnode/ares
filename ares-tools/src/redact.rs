//! Fail-closed redaction of subprocess command lines.
//!
//! Tool argv reaches DEBUG logs, OTel span attributes, and — via the timeout
//! error — anyhow chains that the agent loop feeds back to the LLM. Every
//! decision in this module defaults to hiding the value: a flag whose meaning
//! varies between call sites (`-p` is a password to netexec and a port spec to
//! nmap) is treated as secret, and a call site that needs its value back
//! declares it with [`crate::executor::CommandBuilder::flag_visible`].

use std::collections::HashSet;

use serde_json::Value;

/// Placeholder written in place of every masked value.
pub const REDACTED: &str = "***";

const SECRET_FLAGS: &[&str] = &[
    "-hashes",
    "--hashes",
    "-nthash",
    "-aesKey",
    "-password",
    "--password",
    "--pfx-password",
    "-pfx",
    "-ca-pfx",
    "-computer-pass",
    "-cp",
    "-U",
    "-w",
];

const AMBIGUOUS_FLAGS: &[&str] = &["-p", "-H"];

const SECRET_VALUE_PREFIXES: &[&str] = &["/p:", "/pth:"];

/// Redact `program args…` into a single line safe to log, trace, and surface
/// to the LLM.
///
/// Masking is fail-closed: any argument that follows a credential-bearing flag
/// is replaced wholesale with [`REDACTED`], and every remaining argument is
/// scanned for embedded secrets (`domain/user:PASSWORD@host`, `user%SECRET`,
/// `/p:PASSWORD`, bare `LMHASH:NTHASH`) with the identity kept and the secret
/// masked.
pub fn redact_command_line(program: &str, args: &[String]) -> String {
    redact_command_line_with_visible(program, args, &HashSet::new())
}

/// [`redact_command_line`] with an explicit opt-out set.
///
/// `visible` holds argument indices whose values a call site has declared
/// non-secret via [`crate::executor::CommandBuilder::flag_visible`]; those
/// arguments are emitted verbatim. Every other index is masked by the normal
/// fail-closed rules.
pub fn redact_command_line_with_visible(
    program: &str,
    args: &[String],
    visible: &HashSet<usize>,
) -> String {
    let mut line = String::from(program);
    let mut pending: Option<bool> = None;
    for (index, arg) in args.iter().enumerate() {
        line.push(' ');
        let opted_out = visible.contains(&index);
        if let Some(identity_bearing) = pending.take() {
            if opted_out || arg.is_empty() {
                line.push_str(arg);
            } else if identity_bearing {
                line.push_str(&mask_identity_bearing(arg));
            } else {
                line.push_str(REDACTED);
            }
            continue;
        }
        if takes_secret_value(arg) {
            pending = Some(IDENTITY_BEARING_FLAGS.contains(&arg.as_str()));
            line.push_str(arg);
            continue;
        }
        if opted_out {
            line.push_str(arg);
            continue;
        }
        line.push_str(&redact_embedded(arg));
    }
    line
}

fn takes_secret_value(arg: &str) -> bool {
    SECRET_FLAGS.contains(&arg) || AMBIGUOUS_FLAGS.contains(&arg)
}

/// Secret flags whose value also carries the principal's identity, e.g.
/// `-U domain/user%nthash`. Masking these wholesale would discard the
/// attribution the span exists to record, so only the secret half is hidden.
///
/// Deliberately narrow. Applying the same surgical treatment to every secret
/// flag would partially expose a password that happens to contain `:` and `@`,
/// which is why the general case still masks the whole value.
const IDENTITY_BEARING_FLAGS: &[&str] = &["-U"];

fn mask_identity_bearing(arg: &str) -> String {
    redact_user_pass_at_host(arg)
        .or_else(|| redact_percent_secret(arg))
        .unwrap_or_else(|| REDACTED.to_string())
}

fn redact_embedded(arg: &str) -> String {
    if let Some(masked) = redact_prefixed_secret(arg) {
        return masked;
    }
    if let Some(masked) = redact_user_pass_at_host(arg) {
        return masked;
    }
    if let Some(masked) = redact_percent_secret(arg) {
        return masked;
    }
    if is_hash_shaped(arg) {
        return REDACTED.to_string();
    }
    arg.to_string()
}

fn redact_prefixed_secret(arg: &str) -> Option<String> {
    SECRET_VALUE_PREFIXES.iter().find_map(|prefix| {
        let rest = arg.strip_prefix(prefix)?;
        (!rest.is_empty()).then(|| format!("{prefix}{REDACTED}"))
    })
}

fn redact_user_pass_at_host(arg: &str) -> Option<String> {
    let at = arg.rfind('@')?;
    if at + 1 >= arg.len() {
        return None;
    }
    let identity = &arg[..at];
    let scheme_end = identity.find("://").map_or(0, |i| i + 3);
    let colon = identity[scheme_end..].find(':')? + scheme_end;
    if colon + 1 >= at {
        return None;
    }
    Some(format!("{}{REDACTED}{}", &arg[..=colon], &arg[at..]))
}

fn redact_percent_secret(arg: &str) -> Option<String> {
    let percent = arg.find('%')?;
    if percent + 1 >= arg.len() {
        return None;
    }
    Some(format!("{}{REDACTED}", &arg[..=percent]))
}

fn is_hash_shaped(arg: &str) -> bool {
    fn is_hex_key(s: &str) -> bool {
        matches!(s.len(), 32 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
    }
    arg.contains(':') && arg.split(':').any(is_hex_key)
}

/// Redact secrets from free-form text — captured tool stdout/stderr, an error
/// string, any blob a call site would otherwise log verbatim.
///
/// The text is tokenized on whitespace and each token is put through the same
/// embedded-secret rules [`redact_command_line`] applies to positional
/// arguments: `domain/user:PASSWORD@host` keeps the identity and masks the
/// secret, `user%SECRET` and `/p:PASSWORD` mask the secret, and hash-shaped
/// tokens (`LMHASH:NTHASH`, `:NTHASH`, a secretsdump row) are masked
/// wholesale. Whitespace is emitted verbatim, so the line structure of a
/// captured output tail survives redaction.
///
/// This is a token filter, not a parser: a secret that a tool prints without
/// any of those shapes is not recognized. Prefer logging a structured field
/// over a raw blob wherever the shape of the value is known.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !token.is_empty() {
                out.push_str(&redact_embedded(&token));
                token.clear();
            }
            out.push(ch);
        } else {
            token.push(ch);
        }
    }
    if !token.is_empty() {
        out.push_str(&redact_embedded(&token));
    }
    out
}

/// Tool-call argument keys whose value is auth material.
///
/// Drawn from the argument names the tool wrappers actually read (see
/// [`crate::credentials::CREDENTIAL_KEYS`], which the worker credential
/// resolver injects, plus the per-tool keys `new_password`,
/// `computer_password`, `create_password` and `hash_value`). A drift test
/// asserts every entry of `CREDENTIAL_KEYS` is classified here or in
/// [`IDENTITY_ARG_KEYS`], so a new credential key cannot be added upstream
/// without a decision about logging it.
const SECRET_ARG_KEYS: &[&str] = &[
    "password",
    "new_password",
    "create_password",
    "computer_password",
    "coerce_password",
    "pfx_password",
    "hash",
    "hashes",
    "hash_value",
    "nt_hash",
    "nthash",
    "ntlm_hash",
    "lm_hash",
    "coerce_hash",
    "admin_hash",
    "trust_hash",
    "krbtgt_hash",
    "child_krbtgt_hash",
    "parent_krbtgt_hash",
    "aes_key",
    "aesKey",
    "aes256_key",
    "trust_aes_key",
    "trust_key",
    "kerberos_keys",
    "dpapi_key",
    "ticket",
];

/// Credential-resolver argument keys that identify a principal rather than
/// authenticate as one. SIDs are enumerable from any domain-joined context and
/// a ccache path names a file on the worker — masking them would strip the
/// fields operators debug forged-ticket automation with, without hiding a
/// secret.
#[cfg(test)]
const IDENTITY_ARG_KEYS: &[&str] = &[
    "domain_sid",
    "source_sid",
    "target_sid",
    "extra_sid",
    "ticket_path",
];

/// Mask every secret-bearing value in an LLM tool-call argument map so the
/// remaining structure is safe to log.
///
/// Keys are matched case-insensitively against [`SECRET_ARG_KEYS`] and their
/// values replaced wholesale with [`REDACTED`] — including composite values,
/// so an object or array parked under a secret key cannot leak through a
/// nested field. Every other value is walked recursively; benign keys keep
/// their values verbatim.
pub fn redact_tool_arguments(arguments: &Value) -> Value {
    match arguments {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let masked = if is_secret_arg_key(key) {
                        Value::String(REDACTED.to_string())
                    } else {
                        redact_tool_arguments(value)
                    };
                    (key.clone(), masked)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_tool_arguments).collect()),
        other => other.clone(),
    }
}

fn is_secret_arg_key(key: &str) -> bool {
    SECRET_ARG_KEYS
        .iter()
        .any(|secret| secret.eq_ignore_ascii_case(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::CommandBuilder;

    const PASSWORD: &str = "P@ssw0rd!";
    const LM: &str = "aad3b435b51404eeaad3b435b51404ee";
    const NT: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

    fn redact(args: &[&str]) -> String {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        redact_command_line("tool", &owned)
    }

    // ── Layer 1: unambiguous secret flags ────────────────────────────────────

    #[test]
    fn every_secret_flag_masks_its_value() {
        for flag in SECRET_FLAGS {
            let line = redact(&[flag, PASSWORD, "192.168.58.10"]);
            assert_eq!(
                line,
                format!("tool {flag} {REDACTED} 192.168.58.10"),
                "flag {flag} did not mask its value"
            );
            assert!(!line.contains(PASSWORD), "secret survived {flag}: {line}");
        }
    }

    #[test]
    fn hashes_flag_masks_lm_nt_pair() {
        let line = redact(&["-hashes", &format!("{LM}:{NT}"), "contoso.local/alice@dc01"]);
        assert_eq!(
            line,
            format!("tool -hashes {REDACTED} contoso.local/alice@dc01")
        );
    }

    #[test]
    fn upper_u_flag_masks_only_the_hash_half() {
        let line = redact(&["-U", &format!("contoso.local/bob%{NT}"), "//dc01/C$"]);
        assert!(!line.contains(NT), "NT hash survived -U: {line}");
        assert_eq!(
            line,
            format!("tool -U contoso.local/bob%{REDACTED} //dc01/C$")
        );
    }

    // ── Layer 2: ambiguous flags default to masking ──────────────────────────

    #[test]
    fn ambiguous_p_masks_even_a_port_spec() {
        let line = redact(&["-Pn", "-p", "445", "192.168.58.10"]);
        assert_eq!(line, format!("tool -Pn -p {REDACTED} 192.168.58.10"));
    }

    #[test]
    fn ambiguous_h_masks_even_an_ldap_uri() {
        let line = redact(&[
            "-H",
            "ldap://dc01.contoso.local",
            "-b",
            "dc=contoso,dc=local",
        ]);
        assert_eq!(line, format!("tool -H {REDACTED} -b dc=contoso,dc=local"));
    }

    #[test]
    fn ambiguous_h_masks_an_ntlm_hash() {
        let line = redact(&["-u", "alice", "-H", &format!("{LM}:{NT}")]);
        assert!(!line.contains(NT), "NT hash survived -H: {line}");
    }

    // ── Boundary: secret flag with no following value ────────────────────────

    #[test]
    fn secret_flag_as_last_arg_does_not_panic() {
        for flag in SECRET_FLAGS.iter().chain(AMBIGUOUS_FLAGS) {
            let line = redact(&["smb", "192.168.58.10", flag]);
            assert_eq!(line, format!("tool smb 192.168.58.10 {flag}"));
        }
    }

    #[test]
    fn empty_argv_yields_program_only() {
        assert_eq!(redact_command_line("nmap", &[]), "nmap");
    }

    // ── Boundary: an empty value is the absence of a secret ──────────────────

    #[test]
    fn empty_values_are_never_masked() {
        for flag in SECRET_FLAGS.iter().chain(AMBIGUOUS_FLAGS) {
            let line = redact(&[flag, "", "192.168.58.10"]);
            assert_eq!(
                line,
                format!("tool {flag}  192.168.58.10"),
                "empty value after {flag} was masked"
            );
        }
    }

    #[test]
    fn null_session_user_does_not_look_like_a_credential() {
        let line = redact(&["-U", "", "-N", "192.168.58.240", "-c", "enumdomusers"]);
        assert!(
            !line.contains(REDACTED),
            "null session rendered as a redacted credential: {line}"
        );
        assert_eq!(line, "tool -U  -N 192.168.58.240 -c enumdomusers");

        let netexec = redact(&["smb", "192.168.58.240", "-u", "", "-p", ""]);
        assert!(
            !netexec.contains(REDACTED),
            "null session rendered as a redacted credential: {netexec}"
        );
    }

    // ── Benign lookalikes stay intact ────────────────────────────────────────

    #[test]
    fn valueless_kerberos_booleans_do_not_swallow_the_next_arg() {
        for flag in ["-k", "-no-pass", "--no-pass"] {
            let line = redact(&[flag, "dc01.contoso.local"]);
            assert_eq!(line, format!("tool {flag} dc01.contoso.local"));
        }
    }

    #[test]
    fn pw_nt_hash_boolean_does_not_swallow_the_next_arg() {
        let line = redact(&[
            "-U",
            &format!("contoso.local/admin%{NT}"),
            "--pw-nt-hash",
            "192.168.58.240",
            "-c",
            "enumdomusers",
        ]);
        assert!(!line.contains(NT), "NT hash survived -U: {line}");
        assert_eq!(
            line,
            format!(
                "tool -U contoso.local/admin%{REDACTED} --pw-nt-hash 192.168.58.240 -c enumdomusers"
            )
        );
    }

    #[test]
    fn netexec_module_name_is_not_a_secret() {
        let line = redact(&["smb", "192.168.58.10", "-M", "gpp_password"]);
        assert_eq!(line, "tool smb 192.168.58.10 -M gpp_password");
    }

    #[test]
    fn empty_openssl_passout_is_not_masked() {
        let line = redact(&["pkcs12", "-passout", "pass:", "-out", "/tmp/ca01.pem"]);
        assert_eq!(line, "tool pkcs12 -passout pass: -out /tmp/ca01.pem");
    }

    #[test]
    fn bare_ldap_uri_is_not_masked() {
        let line = redact(&["ldap://192.168.58.10", "-b", "dc=contoso,dc=local"]);
        assert_eq!(line, "tool ldap://192.168.58.10 -b dc=contoso,dc=local");
    }

    #[test]
    fn principal_without_password_is_not_masked() {
        let line = redact(&[
            "contoso.local/alice@192.168.58.10",
            "krbtgt/CONTOSO.LOCAL@CONTOSO.LOCAL",
            "alice@contoso.local",
        ]);
        assert_eq!(
            line,
            "tool contoso.local/alice@192.168.58.10 krbtgt/CONTOSO.LOCAL@CONTOSO.LOCAL alice@contoso.local"
        );
    }

    // ── Layer 3: embedded secrets in positional args ─────────────────────────

    #[test]
    fn impacket_target_keeps_identity_masks_password() {
        let line = redact(&[&format!("contoso.local/alice:{PASSWORD}@192.168.58.10")]);
        assert_eq!(
            line,
            format!("tool contoso.local/alice:{REDACTED}@192.168.58.10")
        );
    }

    #[test]
    fn impacket_target_without_domain_keeps_identity() {
        let line = redact(&[&format!("bob:{PASSWORD}@dc01.contoso.local")]);
        assert_eq!(line, format!("tool bob:{REDACTED}@dc01.contoso.local"));
    }

    #[test]
    fn password_containing_at_sign_is_fully_masked() {
        let line = redact(&[&format!("fabrikam.local/svc_sql:{PASSWORD}@sql01")]);
        assert!(
            !line.contains("ssw0rd"),
            "password fragment survived: {line}"
        );
        assert_eq!(
            line,
            format!("tool fabrikam.local/svc_sql:{REDACTED}@sql01")
        );
    }

    #[test]
    fn empty_password_in_target_is_left_alone() {
        let line = redact(&["contoso.local/carol:@web01"]);
        assert_eq!(line, "tool contoso.local/carol:@web01");
    }

    #[test]
    fn percent_form_keeps_user_masks_secret() {
        let line = redact(&[
            &format!("contoso.local/bob%{PASSWORD}"),
            &format!("carol%{LM}:{NT}"),
        ]);
        assert_eq!(
            line,
            format!("tool contoso.local/bob%{REDACTED} carol%{REDACTED}")
        );
    }

    #[test]
    fn trailing_percent_with_no_secret_is_left_alone() {
        assert_eq!(
            redact(&["contoso.local/admin%"]),
            "tool contoso.local/admin%"
        );
    }

    #[test]
    fn xfreerdp_password_and_hash_prefixes_are_masked() {
        let line = redact(&[
            "/v:192.168.58.10",
            "/u:alice",
            &format!("/p:{PASSWORD}"),
            "/d:contoso.local",
        ]);
        assert_eq!(
            line,
            format!("tool /v:192.168.58.10 /u:alice /p:{REDACTED} /d:contoso.local")
        );

        let pth = redact(&[&format!("/pth:{LM}:{NT}")]);
        assert_eq!(pth, format!("tool /pth:{REDACTED}"));
    }

    #[test]
    fn bare_hash_shapes_are_masked() {
        assert_eq!(redact(&[&format!("{LM}:{NT}")]), format!("tool {REDACTED}"));
        assert_eq!(redact(&[&format!(":{NT}")]), format!("tool {REDACTED}"));
    }

    #[test]
    fn non_hash_colon_values_are_left_alone() {
        let line = redact(&[
            "-o",
            "DOWNLOAD_FLAG=True",
            "dc=contoso,dc=local",
            "sql01:1433",
        ]);
        assert_eq!(
            line,
            "tool -o DOWNLOAD_FLAG=True dc=contoso,dc=local sql01:1433"
        );
    }

    // ── Opt-out ──────────────────────────────────────────────────────────────

    #[test]
    fn visible_index_is_left_unmasked() {
        let args = vec![
            "-w".to_string(),
            "3".to_string(),
            "-p".to_string(),
            PASSWORD.to_string(),
        ];
        let visible = HashSet::from([1usize]);
        let line = redact_command_line_with_visible("hashcat", &args, &visible);
        assert_eq!(line, format!("hashcat -w 3 -p {REDACTED}"));
    }

    #[test]
    fn command_builder_flag_visible_survives_redaction() {
        let cmd = CommandBuilder::new("nice")
            .arg("-n")
            .arg("10")
            .arg("hashcat")
            .flag_visible("-w", "3")
            .flag("-p", PASSWORD);
        assert_eq!(
            cmd.redacted_command_line(),
            format!("nice -n 10 hashcat -w 3 -p {REDACTED}")
        );
        assert_eq!(cmd.args_for_test().len(), 7);
    }

    #[test]
    fn command_builder_defaults_to_masking_without_opt_out() {
        let cmd = CommandBuilder::new("hashcat").flag("-w", "3");
        assert_eq!(
            cmd.redacted_command_line(),
            format!("hashcat -w {REDACTED}")
        );
    }

    // ── End-to-end argv shapes ───────────────────────────────────────────────

    #[test]
    fn full_netexec_argv_leaks_nothing() {
        let line = redact(&[
            "smb",
            "192.168.58.10",
            "-u",
            "alice",
            "-p",
            PASSWORD,
            "-d",
            "contoso.local",
            "--shares",
        ]);
        assert!(!line.contains(PASSWORD), "password survived: {line}");
        assert!(
            line.contains("-u alice"),
            "identity was over-masked: {line}"
        );
        assert!(line.contains("--shares"), "benign flag lost: {line}");
    }

    #[test]
    fn user_spec_flag_keeps_the_principal_and_hides_only_the_secret() {
        let line = redact(&["-U", &format!("contoso.local/alice%{NT}")]);
        assert!(!line.contains(NT), "NT hash survived: {line}");
        assert!(
            line.contains("contoso.local/alice"),
            "-U must keep the principal for attribution: {line}"
        );
    }

    #[test]
    fn identity_bearing_treatment_does_not_leak_a_punctuated_password() {
        let line = redact(&["-p", "we:ird@pass"]);
        assert!(!line.contains("we"), "password fragment survived: {line}");
        assert!(!line.contains("pass"), "password fragment survived: {line}");
    }

    #[test]
    fn full_secretsdump_argv_leaks_nothing() {
        let line = redact(&[
            &format!("contoso.local/admin:{PASSWORD}@192.168.58.240"),
            "-hashes",
            &format!("{LM}:{NT}"),
            "-just-dc-user",
            "krbtgt",
        ]);
        assert!(!line.contains(PASSWORD), "password survived: {line}");
        assert!(!line.contains(NT), "NT hash survived: {line}");
        assert!(
            line.contains("contoso.local/admin"),
            "identity lost: {line}"
        );
        assert!(
            line.contains("-just-dc-user krbtgt"),
            "benign args lost: {line}"
        );
    }

    // ── Free-text redaction ──────────────────────────────────────────────────

    #[test]
    fn ordinary_prose_passes_through_untouched() {
        for text in [
            "Inter-realm ticket forged for contoso.local",
            "KDC_ERR_S_PRINCIPAL_UNKNOWN while requesting cifs/dc01.contoso.local",
            "[*] Saving ticket in admin.ccache",
            "STATUS_LOGON_FAILURE against 192.168.58.240 (dc01.contoso.local)",
            "alice@contoso.local is a member of Domain Admins",
            "sql01:1433 open, ldap://dc01.contoso.local reachable",
            "dumped 0 hashes; DRSUAPI returned rpc_s_access_denied",
            "",
        ] {
            assert_eq!(redact_text(text), text, "prose was mangled: {text}");
        }
    }

    #[test]
    fn free_text_whitespace_and_line_structure_survive() {
        let text = "line one\n  line two\t| line three\r\n";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn free_text_masks_impacket_target_keeping_identity() {
        let text = format!("[*] connecting as contoso.local/alice:{PASSWORD}@192.168.58.240 now");
        let out = redact_text(&text);
        assert!(!out.contains(PASSWORD), "password survived: {out}");
        assert_eq!(
            out,
            format!("[*] connecting as contoso.local/alice:{REDACTED}@192.168.58.240 now")
        );
    }

    #[test]
    fn free_text_masks_percent_form_keeping_user() {
        let out = redact_text(&format!("auth fabrikam.local/svc_sql%{PASSWORD} ok"));
        assert_eq!(out, format!("auth fabrikam.local/svc_sql%{REDACTED} ok"));
    }

    #[test]
    fn free_text_masks_prefixed_secret() {
        let out = redact_text(&format!("xfreerdp /u:bob /p:{PASSWORD} /v:192.168.58.10"));
        assert!(!out.contains(PASSWORD), "password survived: {out}");
        assert_eq!(
            out,
            format!("xfreerdp /u:bob /p:{REDACTED} /v:192.168.58.10")
        );
    }

    #[test]
    fn free_text_masks_bare_hash_tokens() {
        let out = redact_text(&format!("pair {LM}:{NT} and lone :{NT} done"));
        assert!(!out.contains(NT), "NT hash survived: {out}");
        assert_eq!(out, format!("pair {REDACTED} and lone {REDACTED} done"));
    }

    #[test]
    fn free_text_masks_a_secretsdump_row() {
        let row = format!("krbtgt:502:{LM}:{NT}:::");
        let out = redact_text(&format!("[*] {row}"));
        assert!(
            !out.contains(NT),
            "NT hash survived a secretsdump row: {out}"
        );
        assert!(
            !out.contains(LM),
            "LM hash survived a secretsdump row: {out}"
        );
    }

    #[test]
    fn free_text_masks_a_kerberos_key_row() {
        let aes = "1e0a3b8c9d5f7e2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a";
        let out = redact_text(&format!(
            "contoso.local\\krbtgt:aes256-cts-hmac-sha1-96:{aes}"
        ));
        assert!(!out.contains(aes), "AES key survived: {out}");
    }

    #[test]
    fn free_text_masks_every_secret_on_a_multi_secret_line() {
        let text =
            format!("forge contoso.local/admin:{PASSWORD}@dc01 with {LM}:{NT} then bob%{PASSWORD}");
        let out = redact_text(&text);
        assert!(!out.contains(PASSWORD), "password survived: {out}");
        assert!(!out.contains(NT), "NT hash survived: {out}");
        assert!(out.contains("contoso.local/admin"), "identity lost: {out}");
        assert!(out.contains("@dc01"), "host lost: {out}");
    }

    #[test]
    fn free_text_agrees_with_the_argv_path_on_the_same_token() {
        for token in [
            format!("contoso.local/alice:{PASSWORD}@192.168.58.10"),
            format!("contoso.local/bob%{NT}"),
            format!("/p:{PASSWORD}"),
            format!("{LM}:{NT}"),
            format!(":{NT}"),
            "dc=contoso,dc=local".to_string(),
            "sql01:1433".to_string(),
        ] {
            assert_eq!(
                format!("tool {}", redact_text(&token)),
                redact(&[token.as_str()]),
                "free-text and argv paths diverged on {token}"
            );
        }
    }

    #[test]
    fn free_text_output_tail_of_a_forge_leaks_nothing() {
        let tail = format!(
            "[*] Impersonating admin\n\
             [*] \tServiceTicket\n\
             [*] Saving ticket in /tmp/admin.ccache\n\
             krbtgt:502:{LM}:{NT}:::\n\
             ARES_TICKET_PATH=/tmp/admin.ccache"
        );
        let out = redact_text(&tail);
        assert!(!out.contains(NT), "krbtgt hash survived the tail: {out}");
        assert!(
            out.contains("ARES_TICKET_PATH=/tmp/admin.ccache"),
            "actionable field lost: {out}"
        );
        assert!(
            out.contains("Saving ticket in /tmp/admin.ccache"),
            "benign line lost: {out}"
        );
    }

    #[test]
    fn every_secret_arg_key_is_masked() {
        for key in SECRET_ARG_KEYS {
            let mut map = serde_json::Map::new();
            map.insert((*key).to_string(), serde_json::json!(PASSWORD));
            map.insert("target".to_string(), serde_json::json!("192.168.58.10"));
            let masked = redact_tool_arguments(&Value::Object(map));
            assert_eq!(
                masked[*key],
                serde_json::json!(REDACTED),
                "key {key} was not masked"
            );
            assert_eq!(masked["target"], serde_json::json!("192.168.58.10"));
        }
    }

    #[test]
    fn secret_arg_keys_match_case_insensitively() {
        let args = serde_json::json!({"AES_Key": "0123456789abcdef", "NTHash": NT});
        let masked = redact_tool_arguments(&args);
        assert_eq!(masked["AES_Key"], serde_json::json!(REDACTED));
        assert_eq!(masked["NTHash"], serde_json::json!(REDACTED));
    }

    #[test]
    fn benign_keys_keep_their_values() {
        let args = serde_json::json!({
            "target": "192.168.58.240",
            "target_dc_fqdn": "dc01.contoso.local",
            "username": "alice",
            "domain": "contoso.local",
            "source_domain": "fabrikam.local",
            "domain_sid": "S-1-5-21-1111111111-2222222222-3333333333",
            "ticket_path": "/tmp/alice.ccache",
            "spn": "cifs/dc01.contoso.local",
            "port": 445,
            "verbose": true,
        });
        assert_eq!(redact_tool_arguments(&args), args);
    }

    #[test]
    fn inter_realm_ticket_arguments_leak_nothing() {
        let args = serde_json::json!({
            "action": "forge",
            "source_domain": "fabrikam.local",
            "target_domain": "contoso.local",
            "username": "admin",
            "trust_key": NT,
            "trust_aes_key": "1e0a3b8c9d5f7e2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a",
            "aes_key": "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
            "hash": format!("{LM}:{NT}"),
            "password": PASSWORD,
            "target_dc_ip": "192.168.58.240",
        });
        let rendered = redact_tool_arguments(&args).to_string();
        assert!(!rendered.contains(NT), "hash survived: {rendered}");
        assert!(
            !rendered.contains(PASSWORD),
            "password survived: {rendered}"
        );
        assert!(
            !rendered.contains("9f8e7d6c"),
            "aes key survived: {rendered}"
        );
        assert!(rendered.contains("192.168.58.240"), "target lost");
        assert!(rendered.contains("fabrikam.local"), "source domain lost");
    }

    #[test]
    fn nested_objects_and_arrays_are_walked() {
        let args = serde_json::json!({
            "credential": {
                "username": "svc_sql",
                "password": PASSWORD,
                "nested": {"nt_hash": NT, "domain": "contoso.local"},
            },
            "targets": [
                {"host": "sql01.contoso.local", "hashes": format!("{LM}:{NT}")},
                {"host": "web01.contoso.local", "password": PASSWORD},
            ],
        });
        let masked = redact_tool_arguments(&args);
        assert_eq!(
            masked["credential"]["password"],
            serde_json::json!(REDACTED)
        );
        assert_eq!(
            masked["credential"]["username"],
            serde_json::json!("svc_sql")
        );
        assert_eq!(
            masked["credential"]["nested"]["nt_hash"],
            serde_json::json!(REDACTED)
        );
        assert_eq!(
            masked["credential"]["nested"]["domain"],
            serde_json::json!("contoso.local")
        );
        assert_eq!(masked["targets"][0]["hashes"], serde_json::json!(REDACTED));
        assert_eq!(
            masked["targets"][0]["host"],
            serde_json::json!("sql01.contoso.local")
        );
        assert_eq!(
            masked["targets"][1]["password"],
            serde_json::json!(REDACTED)
        );
    }

    #[test]
    fn composite_value_under_a_secret_key_is_masked_wholesale() {
        let args = serde_json::json!({
            "kerberos_keys": {"aes256": NT, "rc4": NT},
            "hashes": [NT, format!("{LM}:{NT}")],
        });
        let rendered = redact_tool_arguments(&args).to_string();
        assert!(!rendered.contains(NT), "nested secret survived: {rendered}");
    }

    #[test]
    fn non_object_arguments_pass_through() {
        assert_eq!(
            redact_tool_arguments(&serde_json::json!("a string")),
            serde_json::json!("a string")
        );
        assert_eq!(
            redact_tool_arguments(&serde_json::json!(null)),
            serde_json::json!(null)
        );
        assert_eq!(
            redact_tool_arguments(&serde_json::json!({})),
            serde_json::json!({})
        );
    }

    #[test]
    fn every_resolver_credential_key_is_classified() {
        for key in crate::credentials::CREDENTIAL_KEYS {
            let classified = is_secret_arg_key(key) || IDENTITY_ARG_KEYS.contains(key);
            assert!(
                classified,
                "credential key {key} is neither masked nor listed as an identity key — \
                 decide whether it carries auth material before it reaches a log sink"
            );
        }
    }

    #[test]
    fn identity_keys_are_never_masked() {
        for key in IDENTITY_ARG_KEYS {
            assert!(
                !is_secret_arg_key(key),
                "{key} is classified both ways — the two lists must be disjoint"
            );
        }
    }
}
