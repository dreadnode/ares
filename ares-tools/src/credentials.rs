use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::executor::CommandBuilder;

/// Argument keys that hold secret material. Mirrors `CREDENTIAL_KEYS` in
/// `ares-cli/src/worker/credential_resolver.rs` — keep in sync.
///
/// The LLM must never supply values for these keys; the worker resolver
/// injects them from operation state and strips placeholders. This list is
/// used by [`validate_arguments`] to fail dispatch loudly if a placeholder
/// somehow survives upstream stripping.
pub const CREDENTIAL_KEYS: &[&str] = &[
    "password",
    "hash",
    "hashes",
    "nt_hash",
    "nthash",
    "ntlm_hash",
    "lm_hash",
    "aes_key",
    "aesKey",
    "aes256_key",
    "ticket_path",
    "krbtgt_hash",
    "child_krbtgt_hash",
    "parent_krbtgt_hash",
    "trust_key",
    "trust_aes_key",
    "trust_hash",
    "admin_hash",
    "domain_sid",
    "source_sid",
    "target_sid",
    "extra_sid",
    "kerberos_keys",
    "dpapi_key",
    "pfx_password",
    "coerce_password",
    "coerce_hash",
];

/// Validate that no credential argument carries a placeholder/literal value.
///
/// Defense-in-depth backstop for the worker credential resolver. The schema
/// strip in `ares-llm` keeps credential fields out of LLM tool calls, and
/// the worker resolver injects real values from operation state and strips
/// placeholders. If a placeholder still reaches dispatch, something upstream
/// is wrong — fail loudly rather than send `password='[TGT]'` to a subprocess.
pub fn validate_arguments(tool_name: &str, arguments: &Value) -> Result<()> {
    let Some(obj) = arguments.as_object() else {
        return Ok(());
    };
    for &key in CREDENTIAL_KEYS {
        if let Some(v) = obj.get(key) {
            if is_placeholder_value(v) {
                anyhow::bail!(
                    "tool '{tool_name}' argument '{key}' has placeholder value {v} — \
                     credentials must be resolved from operation state, not invented \
                     by the LLM. Check the worker credential resolver and prompt templates."
                );
            }
        }
    }
    Ok(())
}

fn is_placeholder_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => is_placeholder_str(s),
        _ => false,
    }
}

fn is_placeholder_str(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    if (t.starts_with('[') && t.ends_with(']')) || (t.starts_with('<') && t.ends_with('>')) {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "n/a"
            | "na"
            | "null"
            | "none"
            | "nil"
            | "unknown"
            | "tbd"
            | "todo"
            | "password"
            | "hash"
            | "ntlm"
            | "nthash"
            | "tgt"
            | "ticket"
            | "ccache"
            | "aes"
            | "aes_key"
            | "trust_key"
            | "domain_sid"
            | "krbtgt_hash"
            | "placeholder"
            | "<value>"
            | "<password>"
            | "<hash>"
            | "<tgt>"
            | "<pwd>"
    )
}

/// Build an impacket-style authentication target string.
///
/// Format: `domain/username:password@target` or `username@target` (for hash auth).
pub fn impacket_target(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    target: &str,
) -> String {
    let user_part = match domain {
        Some(d) if !d.is_empty() => format!("{d}/{username}"),
        _ => username.to_string(),
    };
    match password {
        Some(p) => format!("{user_part}:{p}@{target}"),
        None => format!("{user_part}@{target}"),
    }
}

/// Build `-hashes` args for impacket tools using pass-the-hash.
///
/// Returns `["-hashes", ":NTHASH"]`.
pub fn hash_args(hash: &str) -> Vec<String> {
    let h = if hash.contains(':') {
        hash.to_string()
    } else {
        format!(":{hash}")
    };
    vec!["-hashes".to_string(), h]
}

/// Extract the NT hash from a hash string that may be in `LM:NT` colon form.
///
/// `impacket-ticketer -nthash` rejects the concatenated `LM:NT` form with
/// `'Odd-length string'` because it expects a 32-char hex NT hash. This helper
/// returns the right-most colon-delimited segment, trimmed.
pub fn nt_hash_only(hash: &str) -> &str {
    hash.rsplit(':').next().unwrap_or(hash).trim()
}

/// Build netexec-style credential args: `-u user -p pass -d domain` or `-u user -H hash`.
pub fn netexec_creds(
    username: Option<&str>,
    password: Option<&str>,
    hash: Option<&str>,
    domain: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(u) = username {
        args.extend(["-u".to_string(), u.to_string()]);
    }
    if let Some(h) = hash {
        let h = if h.contains(':') {
            h.to_string()
        } else {
            format!(":{h}")
        };
        args.extend(["-H".to_string(), h]);
    } else if let Some(p) = password {
        args.extend(["-p".to_string(), p.to_string()]);
    }
    if let Some(d) = domain {
        args.extend(["-d".to_string(), d.to_string()]);
    }
    args
}

/// Build bloodyAD-style credential prefix args: `-d domain -u user -p pass --host dc_ip`.
pub fn bloodyad_creds(domain: &str, username: &str, password: &str, dc_ip: &str) -> Vec<String> {
    vec![
        "-d".to_string(),
        domain.to_string(),
        "-u".to_string(),
        username.to_string(),
        "-p".to_string(),
        password.to_string(),
        "--host".to_string(),
        dc_ip.to_string(),
    ]
}

/// The all-zero LM half every modern NTLM stack expects in front of an NT
/// hash. Tools that take `LMHASH:NTHASH` reject a bare 32-hex NT hash.
pub const EMPTY_LM_HASH: &str = "aad3b435b51404eeaad3b435b51404ee";

/// Argument keys the credential resolver uses for NTLM hash material, in
/// lookup order.
pub const NTLM_HASH_KEYS: &[&str] = &["hash", "nt_hash", "ntlm_hash"];

/// Error returned when a tool has no usable auth material at all.
pub const NO_AUTH_MATERIAL: &str = "missing auth material: supply one of `ticket_path` \
     (Kerberos ccache), `hash`/`nt_hash`/`ntlm_hash` (NTLM pass-the-hash), or `password`";

/// First non-empty NTLM hash argument, checked in [`NTLM_HASH_KEYS`] order.
pub fn ntlm_hash_arg(args: &Value) -> Option<&str> {
    NTLM_HASH_KEYS.iter().find_map(|key| {
        optional_str(args, key)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    })
}

/// Normalize an NTLM hash argument to the `LMHASH:NTHASH` form.
///
/// A bare 32-hex NT hash gains the empty-LM prefix; an existing `LM:NT` pair
/// (including impacket's `:NT` short form) passes through with the LM half
/// filled in. Anything else is rejected — a malformed value handed to
/// bloodyAD or impacket is silently treated as a cleartext password and burns
/// a bind attempt against the account lockout counter.
pub fn lm_nt_hash_pair(raw: &str) -> Result<String> {
    fn is_hex32(s: &str) -> bool {
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    let trimmed = raw.trim();
    match trimmed.split_once(':') {
        Some((lm, nt)) if is_hex32(nt) && lm.is_empty() => Ok(format!("{EMPTY_LM_HASH}:{nt}")),
        Some((lm, nt)) if is_hex32(nt) && is_hex32(lm) => Ok(format!("{lm}:{nt}")),
        None if is_hex32(trimmed) => Ok(format!("{EMPTY_LM_HASH}:{trimmed}")),
        _ => anyhow::bail!(
            "malformed NTLM hash argument ({} chars): expected a 32-hex NT hash \
             or LMHASH:NTHASH",
            trimmed.len()
        ),
    }
}

/// Build a `bloodyAD` command with authentication already applied, ready for
/// the caller to append the subcommand (`add groupMember …`, `set password …`,
/// `add genericAll …`, `add spn …`) and a timeout.
///
/// Auth precedence: `ticket_path` > NTLM hash (`hash`/`nt_hash`/`ntlm_hash`) >
/// `password`. A non-empty `ticket_path` wins because the cross-forest
/// credential resolver injects an inter-realm ccache that an NTLM bind would
/// reject with 0x52e (Bug B). The hash branch feeds bloodyAD's `-p` flag,
/// which accepts `LMHASH:NTHASH` for NTLM authentication — without it every
/// ACL edge discovered from a hash-only foothold converts to zero exploitation
/// because the tool bails with "missing required argument: password".
///
/// bloodyAD's `-k` is variadic (`nargs='*'`) and takes keyword arguments like
/// `ccache=<path>`; there is NO `-K` flag. Passing `-k -K <path>` made argparse
/// consume `-K` as an unknown token and `<path>` landed in the subcommand slot,
/// so bloodyAD rejected the whole call. `KRB5CCNAME`/`KRB5_CONFIG` are exported
/// as a belt-and-braces fallback that recent bloodyAD versions read directly.
pub fn bloodyad_base(args: &Value, domain: &str, dc_ip: &str) -> Result<CommandBuilder> {
    if let Some(tpath) = optional_str(args, "ticket_path").filter(|s| !s.is_empty()) {
        let (ccname_key, ccname_val) = kerberos_env(tpath);
        let (cfg_key, cfg_val) = krb5_config_env(tpath);
        return Ok(CommandBuilder::new("bloodyAD")
            .flag("-d", domain)
            .flag("--host", dc_ip)
            .arg("-k")
            .arg(format!("ccache={tpath}"))
            .env(ccname_key, ccname_val)
            .env(cfg_key, cfg_val));
    }

    let username = required_str(args, "username")?;

    if let Some(raw) = ntlm_hash_arg(args) {
        return Ok(CommandBuilder::new("bloodyAD")
            .flag("-d", domain)
            .flag("-u", username)
            .flag("-p", lm_nt_hash_pair(raw)?)
            .flag("--host", dc_ip));
    }

    let password = optional_str(args, "password")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{NO_AUTH_MATERIAL}"))?;
    Ok(CommandBuilder::new("bloodyAD").args(bloodyad_creds(domain, username, password, dc_ip)))
}

/// Determine auth strategy from available credentials and return
/// (target_string, extra_args) for impacket tools.
pub fn impacket_auth(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    hash: Option<&str>,
    target: &str,
) -> (String, Vec<String>) {
    if let Some(h) = hash {
        let target_str = impacket_target(domain, username, None, target);
        let extra = hash_args(h);
        (target_str, extra)
    } else {
        let target_str = impacket_target(domain, username, password, target);
        (target_str, vec![])
    }
}

/// Build KRB5CCNAME env var for Kerberos ticket-based auth.
pub fn kerberos_env(ticket_path: &str) -> (String, String) {
    ("KRB5CCNAME".to_string(), ticket_path.to_string())
}

/// Build the `KRB5_CONFIG` env value that pairs with `KRB5CCNAME=<ticket>`.
///
/// The forge tool writes a per-ccache shim at `<ticket>.krb5.conf` with
/// `[domain_realm]` mappings for the source and target realms — without
/// these, MIT libkrb5 falls back to the system `default_realm` and misses
/// the cached service ticket ("Matching credential not found"). Fall back
/// to `/etc/krb5.conf` so a missing shim doesn't nuke the system config.
pub fn krb5_config_env(ticket_path: &str) -> (String, String) {
    (
        "KRB5_CONFIG".to_string(),
        format!("{ticket_path}.krb5.conf:/etc/krb5.conf"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impacket_target_with_domain_and_password() {
        let result = impacket_target(Some("CONTOSO"), "admin", Some("P@ss"), "192.168.58.1");
        assert_eq!(result, "CONTOSO/admin:P@ss@192.168.58.1");
    }

    #[test]
    fn impacket_target_no_domain() {
        let result = impacket_target(None, "admin", Some("pass"), "dc01");
        assert_eq!(result, "admin:pass@dc01");
    }

    #[test]
    fn impacket_target_empty_domain() {
        let result = impacket_target(Some(""), "admin", Some("pass"), "dc01");
        assert_eq!(result, "admin:pass@dc01");
    }

    #[test]
    fn impacket_target_no_password() {
        let result = impacket_target(Some("CONTOSO"), "admin", None, "dc01");
        assert_eq!(result, "CONTOSO/admin@dc01");
    }

    #[test]
    fn impacket_target_no_domain_no_password() {
        let result = impacket_target(None, "user", None, "target");
        assert_eq!(result, "user@target");
    }

    #[test]
    fn hash_args_plain_nthash() {
        let args = hash_args("aabbccdd");
        assert_eq!(args, vec!["-hashes", ":aabbccdd"]);
    }

    #[test]
    fn hash_args_lm_nt_pair() {
        let args = hash_args("aad3b435:aabbccdd");
        assert_eq!(args, vec!["-hashes", "aad3b435:aabbccdd"]);
    }

    #[test]
    fn nt_hash_only_strips_lm_half() {
        assert_eq!(
            nt_hash_only("aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078"),
            "d350c5900e26d2c95f501e94cf95b078"
        );
    }

    #[test]
    fn nt_hash_only_passes_through_plain_nt() {
        assert_eq!(
            nt_hash_only("d350c5900e26d2c95f501e94cf95b078"),
            "d350c5900e26d2c95f501e94cf95b078"
        );
    }

    #[test]
    fn nt_hash_only_trims_whitespace() {
        assert_eq!(nt_hash_only("  abcd  "), "abcd");
        assert_eq!(nt_hash_only("aad3b435:abcd\n"), "abcd");
    }

    #[test]
    fn nt_hash_only_empty_string() {
        assert_eq!(nt_hash_only(""), "");
    }

    #[test]
    fn netexec_creds_password_auth() {
        let args = netexec_creds(Some("admin"), Some("P@ss"), None, Some("CONTOSO"));
        assert_eq!(args, vec!["-u", "admin", "-p", "P@ss", "-d", "CONTOSO"]);
    }

    #[test]
    fn netexec_creds_hash_auth() {
        let args = netexec_creds(
            Some("admin"),
            Some("ignored"),
            Some("aabbccdd"),
            Some("CONTOSO"),
        );
        // Hash takes priority over password
        assert_eq!(
            args,
            vec!["-u", "admin", "-H", ":aabbccdd", "-d", "CONTOSO"]
        );
    }

    #[test]
    fn netexec_creds_hash_with_colon() {
        let args = netexec_creds(Some("admin"), None, Some("lm:nt"), None);
        assert_eq!(args, vec!["-u", "admin", "-H", "lm:nt"]);
    }

    #[test]
    fn netexec_creds_no_username() {
        let args = netexec_creds(None, Some("pass"), None, None);
        assert_eq!(args, vec!["-p", "pass"]);
    }

    #[test]
    fn netexec_creds_empty() {
        let args = netexec_creds(None, None, None, None);
        assert!(args.is_empty());
    }

    #[test]
    fn bloodyad_creds_builds_correct_args() {
        let args = bloodyad_creds("contoso.local", "admin", "P@ssw0rd", "192.168.58.1");
        assert_eq!(
            args,
            vec![
                "-d",
                "contoso.local",
                "-u",
                "admin",
                "-p",
                "P@ssw0rd",
                "--host",
                "192.168.58.1",
            ]
        );
    }

    #[test]
    fn impacket_auth_with_hash() {
        let (target, extra) = impacket_auth(
            Some("CONTOSO"),
            "admin",
            Some("ignored"),
            Some("aabbccdd"),
            "dc01",
        );
        assert_eq!(target, "CONTOSO/admin@dc01");
        assert_eq!(extra, vec!["-hashes", ":aabbccdd"]);
    }

    #[test]
    fn impacket_auth_with_password() {
        let (target, extra) = impacket_auth(Some("CONTOSO"), "admin", Some("P@ss"), None, "dc01");
        assert_eq!(target, "CONTOSO/admin:P@ss@dc01");
        assert!(extra.is_empty());
    }

    #[test]
    fn impacket_auth_no_creds() {
        let (target, extra) = impacket_auth(None, "user", None, None, "host");
        assert_eq!(target, "user@host");
        assert!(extra.is_empty());
    }

    #[test]
    fn kerberos_env_builds_tuple() {
        let (key, val) = kerberos_env("/tmp/krb5cc_admin");
        assert_eq!(key, "KRB5CCNAME");
        assert_eq!(val, "/tmp/krb5cc_admin");
    }

    #[test]
    fn validate_arguments_passes_real_credentials() {
        let args = serde_json::json!({
            "target": "192.168.58.10",
            "username": "admin",
            "password": "P@ssw0rd!",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "krbtgt_hash": "aad3b435b51404eeaad3b435b51404ee",
            "ticket_path": "/tmp/admin.ccache",
            "domain_sid": "S-1-5-21-1234-5678-9012",
        });
        validate_arguments("secretsdump", &args).expect("real values must pass");
    }

    #[test]
    fn validate_arguments_rejects_bracketed_placeholder() {
        let args = serde_json::json!({
            "target": "dc01",
            "password": "[TGT]",
        });
        let err = validate_arguments("nmap_scan", &args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("password"), "{msg}");
        assert!(msg.contains("[TGT]"), "{msg}");
        assert!(msg.contains("nmap_scan"), "{msg}");
    }

    #[test]
    fn validate_arguments_rejects_angle_placeholder() {
        let args = serde_json::json!({
            "hash": "<parent_administrator_NTLM_hash>",
        });
        let err = validate_arguments("generate_golden_ticket", &args).unwrap_err();
        assert!(err.to_string().contains("hash"));
    }

    #[test]
    fn validate_arguments_rejects_n_a_string() {
        let args = serde_json::json!({"password": "N/A"});
        assert!(validate_arguments("psexec", &args).is_err());
    }

    #[test]
    fn validate_arguments_rejects_null_value() {
        let args = serde_json::json!({"trust_key": null});
        assert!(validate_arguments("create_inter_realm_ticket", &args).is_err());
    }

    #[test]
    fn validate_arguments_rejects_bare_word_placeholder() {
        let args = serde_json::json!({"krbtgt_hash": "HASH"});
        assert!(validate_arguments("generate_golden_ticket", &args).is_err());
    }

    #[test]
    fn validate_arguments_rejects_empty_string() {
        let args = serde_json::json!({"password": ""});
        assert!(validate_arguments("psexec", &args).is_err());
    }

    #[test]
    fn validate_arguments_ignores_non_credential_keys() {
        let args = serde_json::json!({
            "target": "<placeholder>",
            "command": "[whoami]",
        });
        validate_arguments("psexec", &args).expect("non-credential keys are not validated");
    }

    #[test]
    fn validate_arguments_handles_non_object_arguments() {
        let args = serde_json::json!("just a string");
        validate_arguments("any_tool", &args).expect("non-object arguments pass through");
    }

    #[test]
    fn validate_arguments_handles_missing_credential_keys() {
        let args = serde_json::json!({"target": "192.168.58.10"});
        validate_arguments("nmap_scan", &args).expect("absent keys are not validated");
    }
}
