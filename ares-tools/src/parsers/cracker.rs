//! Parser for hashcat / john the ripper cracked output.
//!
//! Extracts cracked credentials from `hashcat --show` and `john --show` output
//! sections that the cracker tools append to their stdout.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Hashcat cracked TGS: $krb5tgs$23$*user$DOMAIN$spn*$hash:plaintext
static RE_CRACKED_TGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^*]+\*\$[a-fA-F0-9$]+:(.+)$").unwrap()
});

/// Cracked AS-REP: $krb5asrep$23$user@DOMAIN:hash:plaintext (hashcat)
/// or $krb5asrep$23$user@DOMAIN:plaintext (john --show, no hex section)
static RE_CRACKED_ASREP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):(?:[a-fA-F0-9$]+:)?(.+)$").unwrap()
});

/// Hashcat cracked NTLM: 32-char-hex:plaintext
static RE_CRACKED_NTLM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{32}:(.+)$").unwrap());

/// John --show output: user:plaintext:RID:LM:NT:...
static RE_JOHN_SHOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:\s$][^:]*):([^:]+):\d*:(?:[a-fA-F0-9]*:){0,3}:*\s*$").unwrap()
});

/// John --show unknown user: ?:plaintext (john can't determine username from TGS hashes)
static RE_JOHN_UNKNOWN_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\?:(.+)$").unwrap());

/// Extract username/domain from TGS hash value: $krb5tgs$TYPE$*USERNAME$REALM$...
static RE_TGS_HASH_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)").unwrap());

/// Extract username/domain from AS-REP hash value: $krb5asrep$TYPE$USERNAME@REALM:...
static RE_ASREP_HASH_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+)").unwrap());

/// Parse cracker tool output and return credentials.
///
/// Looks for the `--- hashcat --show ---` or `--- john --show ---` section
/// and extracts cracked hash:password pairs.
pub fn parse_cracker_output(output: &str, params: &Value) -> Vec<Value> {
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    // Extract username from hash_value param (for NTLM where username isn't in the hash)
    let username_from_params = params
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Focus on the --show section if present, but also scan full output
    let is_john_output =
        output.contains("password hash cracked") || output.contains("password hashes cracked");

    for line in output.lines() {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }

        // Hashcat cracked TGS (Kerberoast)
        if let Some(caps) = RE_CRACKED_TGS.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            let hash_domain = caps.get(2).unwrap().as_str();
            let password = caps.get(3).unwrap().as_str();
            let key = format!("{}@{}", user.to_lowercase(), hash_domain.to_lowercase());
            if seen.insert(key) && is_valid_password(password) {
                credentials.push(json!({
                    "username": user,
                    "password": password,
                    "domain": hash_domain,
                    "source": "cracked:hashcat",
                }));
            }
            continue;
        }

        // Hashcat cracked AS-REP
        if let Some(caps) = RE_CRACKED_ASREP.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            let hash_domain = caps.get(2).unwrap().as_str();
            let password = caps.get(3).unwrap().as_str();
            let key = format!("{}@{}", user.to_lowercase(), hash_domain.to_lowercase());
            if seen.insert(key) && is_valid_password(password) {
                credentials.push(json!({
                    "username": user,
                    "password": password,
                    "domain": hash_domain,
                    "source": "cracked:hashcat",
                }));
            }
            continue;
        }

        // Hashcat cracked NTLM (only in --show section)
        if stripped.contains("hashcat --show") {
            continue;
        }
        if let Some(caps) = RE_CRACKED_NTLM.captures(stripped) {
            let password = caps.get(1).unwrap().as_str();
            if !username_from_params.is_empty() && is_valid_password(password) {
                let key = format!(
                    "{}@{}",
                    username_from_params.to_lowercase(),
                    domain.to_lowercase()
                );
                if seen.insert(key) {
                    credentials.push(json!({
                        "username": username_from_params,
                        "password": password,
                        "domain": domain,
                        "source": "cracked:hashcat",
                    }));
                }
            }
            continue;
        }

        // John --show output (only if we detected john context)
        if is_john_output {
            // John --show with unknown user: ?:password (common for TGS hashes)
            if let Some(caps) = RE_JOHN_UNKNOWN_USER.captures(stripped) {
                let password = caps.get(1).unwrap().as_str().trim();
                if is_valid_password(password) {
                    // Extract username/domain from the hash_value parameter
                    let hash_value = params
                        .get("hash_value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let (user, hash_domain) =
                        if let Some(tgs_caps) = RE_TGS_HASH_USER.captures(hash_value) {
                            (
                                tgs_caps.get(1).unwrap().as_str().to_string(),
                                tgs_caps.get(2).unwrap().as_str().to_string(),
                            )
                        } else if let Some(asrep_caps) = RE_ASREP_HASH_USER.captures(hash_value) {
                            (
                                asrep_caps.get(1).unwrap().as_str().to_string(),
                                asrep_caps.get(2).unwrap().as_str().to_string(),
                            )
                        } else {
                            continue; // Can't determine username
                        };
                    let key = format!("{}@{}", user.to_lowercase(), hash_domain.to_lowercase());
                    if seen.insert(key) {
                        credentials.push(json!({
                            "username": user,
                            "password": password,
                            "domain": hash_domain,
                            "source": "cracked:john",
                        }));
                    }
                }
                continue;
            }

            if let Some(caps) = RE_JOHN_SHOW.captures(stripped) {
                let user = caps.get(1).unwrap().as_str();
                let password = caps.get(2).unwrap().as_str();
                // Skip john summary lines (pure digits as username)
                if user.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                if is_valid_password(password) {
                    let key = format!("{}@{}", user.to_lowercase(), domain.to_lowercase());
                    if seen.insert(key) {
                        credentials.push(json!({
                            "username": user,
                            "password": password,
                            "domain": domain,
                            "source": "cracked:john",
                        }));
                    }
                }
            }
        }
    }

    credentials
}

fn is_valid_password(password: &str) -> bool {
    let p = password.trim();
    if p.is_empty() || p.len() > 128 {
        return false;
    }
    // Reject hex-only strings at known hash lengths. Hashes belong in
    // state.hashes — never in state.credentials; a hash stored as a
    // cleartext password gets injected as `-p <hex>` and lockouts the
    // real account via failed-auth badPwdCount increments.
    let p_no_sep: String = p.chars().filter(|c| !matches!(*c, ':' | '$')).collect();
    if !p_no_sep.is_empty()
        && p_no_sep.chars().all(|c| c.is_ascii_hexdigit())
        && matches!(
            p_no_sep.len(),
            16 | 32 | 40 | 48 | 56 | 64 | 65 | 80 | 96 | 128
        )
    {
        return false;
    }
    // Reject ellipsis-truncated displays. Hashcat / john never emit `...` in
    // their --show output; a candidate "plaintext" containing `...` means
    // something upstream truncated a hash for human display and the regex
    // captured that truncation as if it were the cracked password.
    if p.contains("...") {
        return false;
    }
    // Reject hashcat-style multi-field hash blobs being mis-captured.
    if p.starts_with("$krb5") || p.starts_with("$NT$") || p.starts_with("$LM$") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_hashcat_tgs_cracked() {
        let output = r#"hashcat (v6.2.6) starting...
Session....: hashcat
Status......: Cracked

--- hashcat --show ---
$krb5tgs$23$*sarah.connor$CHILD.CONTOSO.LOCAL$child.contoso.local/sarah.connor*$abc123:MyPassword1
"#;
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "sarah.connor");
        assert_eq!(creds[0]["password"], "MyPassword1");
        assert_eq!(creds[0]["domain"], "CHILD.CONTOSO.LOCAL");
        assert_eq!(creds[0]["source"], "cracked:hashcat");
    }

    #[test]
    fn parse_hashcat_asrep_cracked() {
        let output = r#"--- hashcat --show ---
$krb5asrep$23$michelle@FABRIKAM.LOCAL:8a7a0b3264590ef6:fr3edom
"#;
        let params = json!({"domain": "fabrikam.local"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "michelle");
        assert_eq!(creds[0]["password"], "fr3edom");
        assert_eq!(creds[0]["domain"], "FABRIKAM.LOCAL");
    }

    #[test]
    fn parse_hashcat_ntlm_cracked() {
        let output = "--- hashcat --show ---\ne19ccf75ee54e06b06a5907af13cef42:Summer2024!\n";
        let params = json!({"domain": "contoso.local", "username": "Administrator"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "Administrator");
        assert_eq!(creds[0]["password"], "Summer2024!");
    }

    #[test]
    fn rejects_truncated_hash_as_plaintext() {
        // Concrete regression: hashcat (or upstream) emitted a line with a
        // truncated AS-REP blob (no real plaintext at the end). The optional
        // hex group in the regex fails to match because `.` is not hex, then
        // `(.+)$` greedy-captures the truncation itself as if it were the
        // cleartext password. Validator must drop it.
        let output = r#"--- hashcat --show ---
$krb5asrep$23$alice@CONTOSO.LOCAL:ef961e2fd18a412...6bf150
"#;
        let params = json!({"domain": "contoso.local"});
        let creds = parse_cracker_output(output, &params);
        assert!(
            creds.is_empty(),
            "Truncated hash must not be stored as a cracked credential, got: {creds:?}"
        );
    }

    #[test]
    fn rejects_ntlm_hash_as_plaintext() {
        // Hash:hash mismatch — if for any reason the regex were to capture a
        // 32-char hex string as the plaintext, the validator must drop it.
        let output = "--- hashcat --show ---\n\
                      e19ccf75ee54e06b06a5907af13cef42:831486ac7f26860c9e2f51ac91e1a07a\n";
        let params = json!({"domain": "contoso.local", "username": "alice"});
        let creds = parse_cracker_output(output, &params);
        assert!(
            creds.is_empty(),
            "32-char hex must not be stored as a cleartext, got: {creds:?}"
        );
    }

    #[test]
    fn parse_john_show_cracked() {
        let output = "Using default input encoding: UTF-8\n\
            Loaded 1 password hash\n\
            sarah.connor:MyPassword1:1234:::\n\
            1 password hash cracked, 0 left\n";
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "sarah.connor");
        assert_eq!(creds[0]["password"], "MyPassword1");
        assert_eq!(creds[0]["source"], "cracked:john");
    }

    #[test]
    fn no_cracked_output() {
        let output = "hashcat (v6.2.6) starting...\nExhausted\n--- hashcat --show ---\n";
        let params = json!({"domain": "contoso.local"});
        let creds = parse_cracker_output(output, &params);
        assert!(creds.is_empty());
    }

    #[test]
    fn john_show_asrep_no_hex_section() {
        // John --show for AS-REP omits the hex hash — just user@REALM:password
        let output = "--- john --show ---\n\
            $krb5asrep$23$brian.davis@CHILD.CONTOSO.LOCAL:letmein2025\n\n\
            1 password hash cracked, 0 left\n";
        let params = json!({
            "hash_value": "$krb5asrep$23$brian.davis@CHILD.CONTOSO.LOCAL:abcdef1234$5678"
        });
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "brian.davis");
        assert_eq!(creds[0]["password"], "letmein2025");
        assert_eq!(creds[0]["domain"], "CHILD.CONTOSO.LOCAL");
    }

    #[test]
    fn john_show_tgs_unknown_user() {
        // John --show for TGS shows ?:password (can't determine username)
        let output = "--- john --show ---\n\
            ?:P@ssw0rd!\n\n\
            1 password hash cracked, 0 left\n";
        let params = json!({
            "hash_value": "$krb5tgs$23$*john.smith$CHILD.CONTOSO.LOCAL$CIFS/filesvr01*$abcdef$123456"
        });
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "john.smith");
        assert_eq!(creds[0]["password"], "P@ssw0rd!");
        assert_eq!(creds[0]["domain"], "CHILD.CONTOSO.LOCAL");
        assert_eq!(creds[0]["source"], "cracked:john");
    }

    #[test]
    fn john_show_tgs_unknown_user_no_hash_param() {
        // Without hash_value param, ?:password is skipped
        let output = "--- john --show ---\n\
            ?:P@ssw0rd!\n\n\
            1 password hash cracked, 0 left\n";
        let params = json!({"domain": "contoso.local"});
        let creds = parse_cracker_output(output, &params);
        assert!(creds.is_empty());
    }
}
