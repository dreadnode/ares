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

/// Hashcat cracked AS-REP: $krb5asrep$23$user@DOMAIN:hash:plaintext
static RE_CRACKED_ASREP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+:(.+)$").unwrap()
});

/// Hashcat cracked NTLM: 32-char-hex:plaintext
static RE_CRACKED_NTLM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{32}:(.+)$").unwrap());

/// John --show output: user:plaintext:RID:LM:NT:...
static RE_JOHN_SHOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:\s$][^:]*):([^:]+):\d*:(?:[a-fA-F0-9]*:){0,3}:*\s*$").unwrap()
});

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
    // Reject hex-only strings that look like hash fragments
    if p.len() == 32 && p.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_hashcat_tgs_cracked() {
        let output = r#"hashcat (v6.2.6) starting...
Session....: hashcat
Status......: Cracked

--- hashcat --show ---
$krb5tgs$23$*sansa.stark$NORTH.SEVENKINGDOMS.LOCAL$north.sevenkingdoms.local/sansa.stark*$abc123:MyPassword1
"#;
        let params = json!({"domain": "north.sevenkingdoms.local"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "sansa.stark");
        assert_eq!(creds[0]["password"], "MyPassword1");
        assert_eq!(creds[0]["domain"], "NORTH.SEVENKINGDOMS.LOCAL");
        assert_eq!(creds[0]["source"], "cracked:hashcat");
    }

    #[test]
    fn test_parse_hashcat_asrep_cracked() {
        let output = r#"--- hashcat --show ---
$krb5asrep$23$missandei@ESSOS.LOCAL:8a7a0b3264590ef6:fr3edom
"#;
        let params = json!({"domain": "essos.local"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "missandei");
        assert_eq!(creds[0]["password"], "fr3edom");
        assert_eq!(creds[0]["domain"], "ESSOS.LOCAL");
    }

    #[test]
    fn test_parse_hashcat_ntlm_cracked() {
        let output = "--- hashcat --show ---\ne19ccf75ee54e06b06a5907af13cef42:Summer2024!\n";
        let params = json!({"domain": "contoso.local", "username": "Administrator"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "Administrator");
        assert_eq!(creds[0]["password"], "Summer2024!");
    }

    #[test]
    fn test_parse_john_show_cracked() {
        let output = "Using default input encoding: UTF-8\n\
            Loaded 1 password hash\n\
            sansa.stark:MyPassword1:1234:::\n\
            1 password hash cracked, 0 left\n";
        let params = json!({"domain": "north.sevenkingdoms.local"});
        let creds = parse_cracker_output(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "sansa.stark");
        assert_eq!(creds[0]["password"], "MyPassword1");
        assert_eq!(creds[0]["source"], "cracked:john");
    }

    #[test]
    fn test_no_cracked_output() {
        let output = "hashcat (v6.2.6) starting...\nExhausted\n--- hashcat --show ---\n";
        let params = json!({"domain": "contoso.local"});
        let creds = parse_cracker_output(output, &params);
        assert!(creds.is_empty());
    }
}
