//! Parsers for lsassy, password spray, username-as-password, NTDS.DIT,
//! LDAP description passwords, and adidnsdump.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

// ── Lsassy ──────────────────────────────────────────────────────────────────

/// Real ANSI escape sequences (e.g. `\x1b[1;33m`).
static ANSI_ESC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("ansi esc regex"));

/// Bare-text ANSI leftovers when ESC bytes are stripped during transport.
/// Matches things like `[1;33m`, `[0m`, `[32m` — but NOT arbitrary bracketed
/// text like `[LSASSY]` or `[NT]`.
static ANSI_BARE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[\d+(?:;\d+)*m").expect("ansi bare regex"));

/// Match the first plausibly-clean `DOMAIN\username` token in a line.
///
/// Domain: starts with alphanumeric, allows alphanumerics/`._-`, no spaces or
/// brackets — keeps us from sucking up `"SMB 192.168.58.10 445 DC01 [+] contoso.local"`
/// as the "domain" when the real domain prefix appears later in the line.
///
/// Captures: 1=domain, 2=username, 3=remainder of line.
static LSASSY_DOMAIN_USER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[\s\]\)>])([A-Za-z0-9][A-Za-z0-9._-]*)\\([A-Za-z0-9._$@-]+)(.*)$")
        .expect("lsassy domain\\user regex")
});

/// Match `[NT] <hash>` (with optional `[SHA1] <sha>` suffix) in lsassy output.
/// Captures: 1=NT hash (32 hex chars).
static LSASSY_NT_HASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[NT\]\s+([0-9a-fA-F]{32})\b").expect("lsassy NT hash regex"));

/// Parse lsassy output for cleartext credentials and NTLM hashes.
///
/// Handles several output flavors:
/// ```text
/// CONTOSO\alice  Password123
/// CONTOSO\bob    aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
/// SMB  192.168.58.10  445  DC01  [LSASSY] CONTOSO\carol [NT] 31d6... [SHA1] f9e3...
/// ```
/// ANSI color codes (real ESC sequences and bare-text leftovers like `[1;33m`)
/// are stripped before parsing.
pub fn parse_lsassy(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    let default_domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();
    let mut creds = Vec::new();

    for line in output.lines() {
        let line = strip_ansi(line.trim());
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if is_lsassy_noise(line) {
            continue;
        }

        if let Some((domain, username, secret)) = parse_lsassy_line(line) {
            let domain = if domain.is_empty() {
                default_domain.to_string()
            } else {
                domain
            };

            if looks_like_ntlm_hash(&secret) {
                hashes.push(json!({
                    "username": username,
                    "domain": domain,
                    "hash_value": secret,
                    "hash_type": "ntlm",
                    "source": "lsassy",
                }));
            } else if !secret.is_empty() && secret != "(null)" {
                creds.push(json!({
                    "id": format!("lsassy_{}_{}", username, domain),
                    "username": username,
                    "password": secret,
                    "domain": domain,
                    "source": "lsassy",
                    "is_admin": false,
                }));
            }
        }
    }

    (hashes, creds)
}

/// Strip ANSI color codes and bare-text leftovers (when ESC bytes were dropped).
fn strip_ansi(s: &str) -> String {
    let s = ANSI_ESC_RE.replace_all(s, "");
    ANSI_BARE_RE.replace_all(&s, "").to_string()
}

/// Identify lines that lsassy emits but contain no credential we can parse.
fn is_lsassy_noise(line: &str) -> bool {
    line.starts_with("INFO")
        || line.starts_with("WARNING")
        || line.starts_with("ERROR")
        || line.contains("authentication")
        // Lines that are pure status (start with `[`/`(`) and contain no `\`
        // can't carry a DOMAIN\user pair — skip them up-front.
        || ((line.starts_with('[') || line.starts_with('('))
            && !line.contains('\\'))
}

fn parse_lsassy_line(line: &str) -> Option<(String, String, String)> {
    // Special-case `[NT] hash` form first — it's unambiguous and the regex
    // anchors are friendlier to a clean DOMAIN\user lookahead.
    if let Some(nt_caps) = LSASSY_NT_HASH_RE.captures(line) {
        if let Some(caps) = LSASSY_DOMAIN_USER_RE.captures(line) {
            let domain = caps.get(1)?.as_str();
            let username = caps.get(2)?.as_str();
            if is_clean_domain(domain) && !username.is_empty() {
                return Some((
                    domain.to_string(),
                    username.to_string(),
                    nt_caps[1].to_string(),
                ));
            }
        }
    }

    // General DOMAIN\user form: parse the first clean DOMAIN\user token, then
    // pull a secret out of the remainder.
    let caps = LSASSY_DOMAIN_USER_RE.captures(line)?;
    let domain = caps.get(1)?.as_str();
    let username = caps.get(2)?.as_str();
    let rest = caps.get(3)?.as_str();

    if !is_clean_domain(domain) || username.is_empty() {
        return None;
    }

    // Colon-prefixed (DOMAIN\user:secret) — preserve full LM:NT pair. This is
    // a terminal branch: once we see the colon delimiter the secret (or lack
    // thereof) is unambiguous, so falling through to the whitespace branch
    // below would just re-parse the same `:marker` string as a bare token.
    if let Some(stripped) = rest.strip_prefix(':') {
        let secret = stripped.trim();
        if secret.is_empty() || is_lsassy_marker(secret) {
            return None;
        }
        return Some((domain.to_string(), username.to_string(), secret.to_string()));
    }

    // Whitespace-separated (DOMAIN\user  secret).
    let secret = rest.trim();
    if !secret.is_empty() {
        // Take only the first whitespace-delimited token to avoid swallowing
        // trailing `[SHA1] …` decorations into the password.
        let first = secret.split_whitespace().next().unwrap_or("");
        if !first.is_empty() && !is_lsassy_marker(first) {
            return Some((domain.to_string(), username.to_string(), first.to_string()));
        }
    }

    None
}

/// Recognize lsassy field-marker tokens (e.g. `[PWD]`, `[TGT]`, `[LM]`,
/// `[SHA1]`). These are *labels* lsassy emits when it found a credential
/// of that type but redacted/elided the value — they are not secrets.
/// Storing them as passwords poisoned operation state and caused tools to
/// receive literal `[PWD]`/`[TGT]` strings as auth values.
fn is_lsassy_marker(s: &str) -> bool {
    let t = s.trim();
    t.starts_with('[') && t.ends_with(']') && t.len() <= 16
}

/// Validate a DOMAIN string looks like an AD domain prefix, not garbage.
fn is_clean_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() < 64
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && d.chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
}

fn looks_like_ntlm_hash(s: &str) -> bool {
    // NTLM hash: 32 hex chars, or LM:NT format (32:32)
    let s = s.trim();
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if s.len() == 65 && s.chars().nth(32) == Some(':') {
        let (lm, nt) = s.split_at(32);
        let nt = &nt[1..];
        return lm.chars().all(|c| c.is_ascii_hexdigit())
            && nt.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}

// ── Password spray / username-as-password ───────────────────────────────────

/// Parse netexec password spray output for successful authentications.
///
/// Successful auth lines contain `[+]` with domain\user:password.
/// ```text
/// SMB  192.168.58.121  445  DC01  [+] contoso.local\alice:Password1
/// ```
pub fn parse_spray_success(output: &str, params: &Value) -> Vec<Value> {
    let default_domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut creds = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if !line.contains("[+]") {
            continue;
        }

        // Skip Guest fallback — SMB accepted the connection but mapped it to the
        // built-in Guest account.  The supplied password was NOT validated.
        if line.contains("(Guest)") {
            continue;
        }

        if let Some(after_plus) = line.split("[+]").nth(1) {
            let after_plus = after_plus.trim();
            // Format: domain\user:password or domain\user password
            if let Some(backslash) = after_plus.find('\\') {
                let domain_part = &after_plus[..backslash];
                let rest = &after_plus[backslash + 1..];

                let (username, password) = if let Some(colon) = rest.find(':') {
                    (&rest[..colon], rest[colon + 1..].trim())
                } else {
                    let parts: Vec<&str> = rest.splitn(2, char::is_whitespace).collect();
                    if parts.len() == 2 {
                        (parts[0], parts[1].trim())
                    } else {
                        continue;
                    }
                };

                let is_admin = line.contains("Pwn3d!");

                // Handle hash-auth Pwn3d! lines where there's no cleartext password
                // e.g. "DOMAIN\user (Pwn3d!)" — password field is "(Pwn3d!)" or empty
                if password.is_empty()
                    || password.starts_with("(Pwn3d!)")
                    || password.starts_with('(')
                {
                    // Still record admin status even without a cleartext password
                    if is_admin {
                        let domain = if domain_part.is_empty() {
                            default_domain
                        } else {
                            domain_part
                        };
                        creds.push(json!({
                            "id": format!("spray_{}_{}", username, domain),
                            "username": username,
                            "password": "",
                            "domain": domain,
                            "source": "password_spray",
                            "is_admin": true,
                        }));
                    }
                    continue;
                }

                // Clean trailing markers like "(Pwn3d!)"
                let password = password.split("(Pwn3d!)").next().unwrap_or(password).trim();

                let domain = if domain_part.is_empty() {
                    default_domain
                } else {
                    domain_part
                };

                creds.push(json!({
                    "id": format!("spray_{}_{}", username, domain),
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "source": "password_spray",
                    "is_admin": is_admin,
                }));
            }
        }
    }

    creds
}

// ── NTDS.DIT extract (same format as secretsdump) ───────────────────────────

/// Parse NTDS.DIT extraction output — identical format to secretsdump.
pub fn parse_ntds_dit(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    // NTDS.DIT output uses the same format as secretsdump
    super::parse_secretsdump(output, params)
}

// ── LDAP description password search ────────────────────────────────────────

/// Regex to find passwords embedded in LDAP description fields.
/// Common patterns: "Password: xxx", "pwd=xxx", "pass: xxx"
static DESC_PASSWORD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:password|pass|pwd)\s*[=:]\s*(\S+)").unwrap());

/// Parse ldap_search_descriptions output for passwords in user descriptions.
///
/// Handles two formats:
///
/// 1. netexec SMB output:
/// ```text
/// SMB  192.168.58.121  445  DC01  svc_sql  Password: Summer2026!
/// ```
///
/// 2. ldapsearch LDIF output (attribute order NOT guaranteed by LDAP):
/// ```text
/// dn: CN=Sam Wilson,CN=Users,DC=child,DC=contoso,DC=local
/// sAMAccountName: sam.wilson
/// description: Sam Wilson (Password : Summer2025)
/// ```
pub fn parse_ldap_descriptions(output: &str, params: &Value) -> Vec<Value> {
    let default_domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut creds = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = DESC_PASSWORD_RE.captures(line) {
            let password = caps[1]
                .trim_matches('\'')
                .trim_matches('"')
                .trim_end_matches(')')
                .to_string();

            // Try to extract username from the line
            // netexec format: "SMB ... DC01  username  Description with Password: xxx"
            let username = extract_username_from_description_line(line);
            if let Some(username) = username {
                creds.push(json!({
                    "id": format!("ldap_desc_{}_{}", username, default_domain),
                    "username": username,
                    "password": password,
                    "domain": default_domain,
                    "source": "ldap_description",
                    "is_admin": false,
                }));
            }
        }
    }

    // LDAP doesn't guarantee attribute order, so we must collect each entry's
    // sAMAccountName and description before matching passwords.
    if creds.is_empty() {
        let mut current_sam = String::new();
        let mut current_desc = String::new();

        for line in output.lines() {
            let line = line.trim();

            // Blank line = end of LDIF entry
            if line.is_empty() {
                if !current_sam.is_empty() && !current_desc.is_empty() {
                    if let Some(caps) = DESC_PASSWORD_RE.captures(&current_desc) {
                        let password = caps[1]
                            .trim_matches('\'')
                            .trim_matches('"')
                            .trim_end_matches(')')
                            .to_string();
                        creds.push(json!({
                            "id": format!("ldap_desc_{}_{}", current_sam, default_domain),
                            "username": current_sam.clone(),
                            "password": password,
                            "domain": default_domain,
                            "source": "ldap_description",
                            "is_admin": false,
                        }));
                    }
                }
                current_sam.clear();
                current_desc.clear();
                continue;
            }

            // Skip comments and dn lines
            if line.starts_with('#') || line.starts_with("dn:") {
                continue;
            }

            if let Some(val) = line
                .strip_prefix("sAMAccountName: ")
                .or_else(|| line.strip_prefix("sAMAccountName:"))
            {
                current_sam = val.trim().to_string();
            } else if let Some(val) = line
                .strip_prefix("description: ")
                .or_else(|| line.strip_prefix("description:"))
            {
                current_desc = val.trim().to_string();
            }
        }

        // Handle last entry (no trailing blank line)
        if !current_sam.is_empty() && !current_desc.is_empty() {
            if let Some(caps) = DESC_PASSWORD_RE.captures(&current_desc) {
                let password = caps[1]
                    .trim_matches('\'')
                    .trim_matches('"')
                    .trim_end_matches(')')
                    .to_string();
                creds.push(json!({
                    "id": format!("ldap_desc_{}_{}", current_sam, default_domain),
                    "username": current_sam,
                    "password": password,
                    "domain": default_domain,
                    "source": "ldap_description",
                    "is_admin": false,
                }));
            }
        }
    }

    creds
}

fn extract_username_from_description_line(line: &str) -> Option<String> {
    // netexec format: "SMB  IP  PORT  HOST  username  description..."
    // After the host field, the next token is the username
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 5 && parts[0] == "SMB" {
        // parts[0]=SMB, [1]=IP, [2]=port, [3]=host, [4]=username
        let candidate = parts[4];
        // Validate it looks like a username (not a noise word)
        if !candidate.starts_with('[')
            && !candidate.starts_with('-')
            && candidate.len() < 64
            && !candidate.contains(':')
        {
            return Some(candidate.to_string());
        }
    }
    None
}

// ── adidnsdump ──────────────────────────────────────────────────────────────

/// Parse adidnsdump output for DNS records that map to host IPs.
///
/// Output format:
/// ```text
/// dc01.contoso.local.   A   192.168.58.210
/// srv01.contoso.local.   A   192.168.58.211
/// ```
pub fn parse_adidnsdump(output: &str) -> Vec<Value> {
    let mut hosts = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: hostname  A  IP
        if parts.len() >= 3 && parts[1] == "A" {
            let hostname = parts[0].trim_end_matches('.');
            let ip = parts[2];

            if super::looks_like_ip(ip) && !hostname.is_empty() {
                hosts.push(json!({
                    "ip": ip,
                    "hostname": hostname,
                    "source": "adidnsdump",
                }));
            }
        }
    }

    hosts
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsassy_extracts_cleartext_creds() {
        let output = "\
CONTOSO\\alice.johnson  Password123
CONTOSO\\bob.smith  SecretPass!";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert!(hashes.is_empty());
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0]["username"], "alice.johnson");
        assert_eq!(creds[0]["password"], "Password123");
        assert_eq!(creds[0]["domain"], "CONTOSO");
    }

    #[test]
    fn lsassy_extracts_ntlm_hashes() {
        let output =
            "CONTOSO\\svc_sql  aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert_eq!(hashes.len(), 1);
        assert!(creds.is_empty());
        assert_eq!(hashes[0]["username"], "svc_sql");
        assert_eq!(hashes[0]["hash_type"], "ntlm");
    }

    #[test]
    fn lsassy_skips_null_and_noise() {
        let output = "\
[INFO] Connecting to 192.168.58.121
CONTOSO\\alice  (null)
[WARNING] Some warning";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert!(hashes.is_empty());
        assert!(creds.is_empty());
    }

    #[test]
    fn spray_extracts_successful_auth() {
        let output = "\
SMB  192.168.58.121  445  DC01  [-] contoso.local\\alice:WrongPass
SMB  192.168.58.121  445  DC01  [+] contoso.local\\bob:Summer2026!
SMB  192.168.58.121  445  DC01  [+] contoso.local\\admin:Admin123 (Pwn3d!)";
        let params = json!({"domain": "contoso.local"});
        let creds = parse_spray_success(output, &params);
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0]["username"], "bob");
        assert_eq!(creds[0]["password"], "Summer2026!");
        assert!(!creds[0]["is_admin"].as_bool().unwrap());
        assert_eq!(creds[1]["username"], "admin");
        assert_eq!(creds[1]["password"], "Admin123");
        assert!(creds[1]["is_admin"].as_bool().unwrap());
    }

    #[test]
    fn spray_ignores_failures() {
        let output = "SMB  192.168.58.121  445  DC01  [-] contoso.local\\alice:WrongPass";
        let params = json!({"domain": "contoso.local"});
        let creds = parse_spray_success(output, &params);
        assert!(creds.is_empty());
    }

    #[test]
    fn spray_filters_guest_sessions() {
        let output = "\
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\admin:admin (Guest)
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\jdoe:jdoe (Guest)
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\realuser:realpass";
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_spray_success(output, &params);
        assert_eq!(creds.len(), 1, "Guest sessions should be filtered out");
        assert_eq!(creds[0]["username"], "realuser");
        assert_eq!(creds[0]["password"], "realpass");
    }

    #[test]
    fn ldap_descriptions_extracts_passwords_nxc() {
        let output = "\
SMB  192.168.58.121  445  DC01  svc_sql  Service account (Password: Summer2026!)
SMB  192.168.58.121  445  DC01  alice    No password here
SMB  192.168.58.121  445  DC01  backup   Backup svc pwd=BackupPass1";
        let params = json!({"domain": "contoso.local"});
        let creds = parse_ldap_descriptions(output, &params);
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0]["username"], "svc_sql");
        assert_eq!(creds[0]["password"], "Summer2026!");
        assert_eq!(creds[1]["username"], "backup");
        assert_eq!(creds[1]["password"], "BackupPass1");
    }

    /// LDIF format from ldapsearch — attributes can appear in any order.
    #[test]
    fn ldap_descriptions_extracts_from_ldif() {
        let output = "\
# john.smith, Users, child.contoso.local
dn: CN=John Smith,CN=Users,DC=child,DC=contoso,DC=local
sAMAccountName: john.smith
description: John Smith
userPrincipalName: john.smith@child.contoso.local

# sam.wilson, Users, child.contoso.local
dn: CN=Sam Wilson,CN=Users,DC=child,DC=contoso,DC=local
sAMAccountName: sam.wilson
description: Sam Wilson (Password : Summer2025)
userPrincipalName: sam.wilson@child.contoso.local";
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_ldap_descriptions(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "sam.wilson");
        assert_eq!(creds[0]["password"], "Summer2025");
        assert_eq!(creds[0]["source"], "ldap_description");
    }

    /// LDIF with description BEFORE sAMAccountName (LDAP doesn't guarantee order).
    #[test]
    fn ldap_descriptions_ldif_reverse_attribute_order() {
        let output = "\
# john.smith, Users, child.contoso.local
dn: CN=John Smith,CN=Users,DC=child,DC=contoso,DC=local
description: John Smith
sAMAccountName: john.smith

# sam.wilson, Users, child.contoso.local
dn: CN=Sam Wilson,CN=Users,DC=child,DC=contoso,DC=local
description: Sam Wilson (Password : Summer2025)
sAMAccountName: sam.wilson";
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_ldap_descriptions(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "sam.wilson");
        assert_eq!(creds[0]["password"], "Summer2025");
    }

    #[test]
    fn adidnsdump_extracts_dns_records() {
        let output = "\
# DNS records
dc01.contoso.local.   A   192.168.58.210
srv01.contoso.local.   A   192.168.58.211
_msdcs.contoso.local.  CNAME  dc01.contoso.local.";
        let hosts = parse_adidnsdump(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.210");
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
        assert_eq!(hosts[1]["ip"], "192.168.58.211");
    }

    #[test]
    fn adidnsdump_skips_non_a_records() {
        let output = "_msdcs.contoso.local.  CNAME  dc01.contoso.local.";
        let hosts = parse_adidnsdump(output);
        assert!(hosts.is_empty());
    }

    #[test]
    fn ntlm_hash_detection() {
        assert!(looks_like_ntlm_hash("aad3b435b51404eeaad3b435b51404ee"));
        assert!(looks_like_ntlm_hash(
            "aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c"
        ));
        assert!(!looks_like_ntlm_hash("Password123"));
        assert!(!looks_like_ntlm_hash("short"));
    }

    #[test]
    fn lsassy_colon_format() {
        let output = "CONTOSO\\alice:Password123";
        let params = json!({"domain": "contoso.local"});
        let (_, creds) = parse_lsassy(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "alice");
        assert_eq!(creds[0]["password"], "Password123");
    }

    #[test]
    fn lsassy_handles_nxc_prefix_with_nt_hash_marker() {
        // Real lsassy-via-nxc line format: a transport prefix, then the
        // credential block. Domain prefix appears mid-line, not at the start.
        let output = "\
SMB         192.168.58.10   445    DC01             [LSASSY] CONTOSO\\Administrator [NT] 31d6cfe0d16ae931b73c59d7e0c089c0 [SHA1] f9e37e83b83c47a93c2f09f66408631b16769e6a";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert_eq!(hashes.len(), 1, "should pick up the [NT] hash");
        assert!(creds.is_empty());
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[0]["domain"], "CONTOSO");
        assert_eq!(hashes[0]["hash_value"], "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn lsassy_strips_real_ansi_escape_sequences() {
        // Real ANSI from the wire — the parser must not see them.
        let output =
            "\x1b[1;33mCONTOSO\\alice\x1b[0m  \x1b[1;32m[NT]\x1b[0m 31d6cfe0d16ae931b73c59d7e0c089c0";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_lsassy(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["domain"], "CONTOSO");
    }

    #[test]
    fn lsassy_strips_bare_text_ansi_leftovers() {
        // When ESC bytes are stripped during transport, the visible style
        // codes (`[1;33m`, `[0m`) survive as bare text. Strip them too.
        let output = "[1;33mCONTOSO\\alice[0m  [1;32m[NT][0m 31d6cfe0d16ae931b73c59d7e0c089c0";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_lsassy(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["domain"], "CONTOSO");
        assert_eq!(hashes[0]["hash_value"], "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn lsassy_rejects_garbage_domain_from_naive_first_backslash() {
        // The nxc prefix has no backslash, but `contoso.local\Administrator:HASH`
        // sits in the line. Naive first-backslash parsing would stuff the
        // entire prefix ("SMB ... DC01 [+] contoso.local") into `domain` —
        // must extract a clean domain ("contoso.local") instead.
        let output = "\
SMB         192.168.58.10   445    DC01             [+] contoso.local\\Administrator:31d6cfe0d16ae931b73c59d7e0c089c0";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert_eq!(hashes.len(), 1);
        assert!(creds.is_empty());
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[0]["username"], "Administrator");
    }

    #[test]
    fn lsassy_rejects_path_like_backslashes() {
        // Backslashes in Windows paths shouldn't be treated as DOMAIN\user.
        // The token after `\` here is empty / has no secret following.
        let output = "[*] Loading file C:\\Windows\\Temp\\dump.dmp";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert!(hashes.is_empty());
        assert!(creds.is_empty());
    }

    #[test]
    fn lsassy_rejects_pwd_tgt_field_markers_as_passwords() {
        // lsassy emits `[PWD]` / `[TGT]` as *labels* when it found a credential
        // of that type but redacted/elided the value. Storing the marker as a
        // password poisoned operation state and made tools receive literal
        // `[PWD]`/`[TGT]` strings as auth values, breaking lateral movement.
        let output = "\
CHILD\\DC01$ [PWD]
CHILD\\eve [TGT]
CHILD\\eve:[PWD]
CONTOSO\\real_user RealPassword123";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert!(hashes.is_empty());
        assert_eq!(
            creds.len(),
            1,
            "only the real password should be stored, got: {creds:?}"
        );
        assert_eq!(creds[0]["username"], "real_user");
        assert_eq!(creds[0]["password"], "RealPassword123");
    }

    #[test]
    fn lsassy_does_not_swallow_sha1_decoration_into_password() {
        // Whitespace-separated form with `[SHA1] …` trailing decoration.
        // The parser should pick the NT hash, not concatenate the rest.
        let output = "CONTOSO\\bob 31d6cfe0d16ae931b73c59d7e0c089c0 [SHA1] f9e37e83b83c47a93c2f09f66408631b16769e6a";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_lsassy(output, &params);
        assert_eq!(hashes.len(), 1);
        assert!(creds.is_empty());
        assert_eq!(hashes[0]["hash_value"], "31d6cfe0d16ae931b73c59d7e0c089c0");
    }
}
