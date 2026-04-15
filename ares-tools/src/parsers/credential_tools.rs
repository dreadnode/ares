//! Parsers for lsassy, password spray, username-as-password, NTDS.DIT,
//! LDAP description passwords, and adidnsdump.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

// ── Lsassy ──────────────────────────────────────────────────────────────────

/// Parse lsassy output for cleartext credentials and NTLM hashes.
///
/// Lsassy dumps credentials from LSASS memory:
/// ```text
/// CONTOSO\alice.johnson  Password123
/// CONTOSO\bob.smith      31d6...hash...
/// ```
pub fn parse_lsassy(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    let default_domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();
    let mut creds = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        // Skip noise lines
        if line.is_empty()
            || line.starts_with('[')
            || line.starts_with("INFO")
            || line.starts_with("WARNING")
            || line.starts_with("ERROR")
            || line.contains("authentication")
        {
            continue;
        }

        // Try DOMAIN\username:password or DOMAIN\username password
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

fn parse_lsassy_line(line: &str) -> Option<(String, String, String)> {
    // Format: DOMAIN\username  password  OR  DOMAIN\username:password
    if let Some(backslash_pos) = line.find('\\') {
        let domain = line[..backslash_pos].trim().to_string();
        let rest = &line[backslash_pos + 1..];

        // Try splitting on whitespace first (most common lsassy format)
        // This must come before colon check because NTLM hashes contain colons
        let parts: Vec<&str> = rest.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 && !parts[1].trim().is_empty() {
            let username = parts[0].trim().to_string();
            let secret = parts[1].trim().to_string();
            if !username.is_empty() && !secret.is_empty() {
                return Some((domain, username, secret));
            }
        }

        // Fallback: colon-separated (DOMAIN\username:password)
        if let Some(colon_pos) = rest.find(':') {
            let username = rest[..colon_pos].trim().to_string();
            let after_colon = rest[colon_pos + 1..].trim().to_string();
            if !username.is_empty() && !after_colon.is_empty() {
                return Some((domain, username, after_colon));
            }
        }
    }
    None
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

        // Extract the part after [+]
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

    // --- Strategy 1: netexec SMB format (same-line extraction) ---
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

    // --- Strategy 2: LDIF format (two-pass: collect entries, then match) ---
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
}
