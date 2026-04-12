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

use once_cell::sync::Lazy;
use regex::Regex;

use ares_core::models::{Credential, Hash, Host, Share, User};

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
    result
}

// ---------------------------------------------------------------------------
// Host extraction — SMB banner lines
// ---------------------------------------------------------------------------

static RE_SMB_BANNER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.\-]+)\s+\[\*\]\s+(.+)")
        .unwrap()
});

static RE_SMB_BANNER_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"\(name:([^)]+)\)").unwrap());

static RE_SMB_BANNER_DOMAIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\(domain:([^)]+)\)").unwrap());

static RE_SMB_BANNER_OS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*([^(]+?)\s+\(name:").unwrap());

static RE_SMB_SIMPLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_\-]+)\s+").unwrap()
});

fn extract_hosts(output: &str) -> Vec<Host> {
    let mut hosts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        let stripped = line.trim();

        // Banner line with OS info: SMB IP PORT HOST [*] details
        if let Some(caps) = RE_SMB_BANNER.captures(stripped) {
            let ip = caps.get(1).unwrap().as_str().to_string();
            if !seen.insert(ip.clone()) {
                continue;
            }
            let details = caps.get(3).unwrap().as_str();
            let netbios_name = RE_SMB_BANNER_NAME
                .captures(details)
                .map(|c| c.get(1).unwrap().as_str().to_string())
                .unwrap_or_default();
            let domain = RE_SMB_BANNER_DOMAIN
                .captures(details)
                .map(|c| {
                    // netexec appends trailing artifacts like "0." — strip them
                    c.get(1)
                        .unwrap()
                        .as_str()
                        .trim_end_matches("0.")
                        .trim_end_matches('.')
                        .to_string()
                })
                .unwrap_or_default();
            let os = RE_SMB_BANNER_OS
                .captures(details)
                .map(|c| c.get(1).unwrap().as_str().trim().to_string())
                .unwrap_or_default();

            // Construct FQDN from NetBIOS name + domain (matches Python smb_sweep)
            let hostname =
                if !netbios_name.is_empty() && !domain.is_empty() && !netbios_name.contains('.') {
                    format!("{}.{}", netbios_name.to_lowercase(), domain.to_lowercase())
                } else {
                    netbios_name
                };

            // DCs require signing — use (signing:True) as the indicator.
            // (domain:...) is present on ALL domain-joined hosts, not just DCs.
            let is_dc = details.contains("(signing:True)");
            let mut roles = Vec::new();
            if is_dc {
                roles.push("AD DC".to_string());
            }

            hosts.push(Host {
                ip,
                hostname,
                os,
                roles,
                services: vec![],
                is_dc,
                owned: false,
            });
            continue;
        }

        // Fallback simple line
        if let Some(caps) = RE_SMB_SIMPLE.captures(stripped) {
            let ip = caps.get(1).unwrap().as_str().to_string();
            let host_col = caps.get(2).unwrap().as_str();
            // Skip table header words
            let skip = ["share", "name", "permissions", "remark"];
            if skip.contains(&host_col.to_lowercase().as_str()) {
                continue;
            }
            if seen.insert(ip.clone()) {
                hosts.push(Host {
                    ip,
                    hostname: host_col.to_string(),
                    os: String::new(),
                    roles: vec![],
                    services: vec![],
                    is_dc: false,
                    owned: false,
                });
            }
        }
    }

    hosts
}

// ---------------------------------------------------------------------------
// User extraction
// ---------------------------------------------------------------------------

static RE_DOMAIN_CONTEXT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\(domain:([^)]+)\)").unwrap());

static RE_DOMAIN_BACKSLASH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-$]+)").unwrap());

static RE_UPN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([A-Za-z0-9_.\-]+)@([A-Za-z0-9_.\-]+\.[A-Za-z0-9_.\-]+)").unwrap());

static RE_USER_BRACKET: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)user:\[([^\]]+)\]").unwrap());

static RE_ACCOUNT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Account:\s*([A-Za-z0-9_.\-]+)").unwrap());

static RE_SAM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)samaccountname:\s*([A-Za-z0-9_.\-]+)").unwrap());

static RE_SMB_TIMESTAMP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+\d{4}-\d{2}-\d{2}").unwrap()
});

fn extract_users(output: &str, default_domain: &str) -> Vec<User> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_domain = default_domain.to_string();

    for line in output.lines() {
        let stripped = line.trim();

        // Update current domain from (domain:XXX) context
        if let Some(caps) = RE_DOMAIN_CONTEXT.captures(stripped) {
            current_domain = caps.get(1).unwrap().as_str().to_string();
        }

        let mut found = Vec::new();

        // DOMAIN\user
        if let Some(caps) = RE_DOMAIN_BACKSLASH.captures(stripped) {
            let dom = caps.get(1).unwrap().as_str();
            let user = caps.get(2).unwrap().as_str();
            found.push((user.to_string(), dom.to_string()));
        }

        // user@domain (UPN)
        if let Some(caps) = RE_UPN.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            let dom = caps.get(2).unwrap().as_str();
            found.push((user.to_string(), dom.to_string()));
        }

        // user:[XXX] (RPC format)
        for caps in RE_USER_BRACKET.captures_iter(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        // Account: XXX
        if let Some(caps) = RE_ACCOUNT.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        // samaccountname: XXX
        if let Some(caps) = RE_SAM.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        // SMB timestamp line: SMB IP PORT HOST username 2024-...
        if let Some(caps) = RE_SMB_TIMESTAMP.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        for (username, domain) in found {
            if username.is_empty() || username.ends_with('$') {
                continue;
            }
            if username.eq_ignore_ascii_case("anonymous") {
                continue;
            }
            let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                users.push(User {
                    username,
                    domain,
                    description: String::new(),
                    is_admin: false,
                    source: "output_extraction".to_string(),
                });
            }
        }
    }

    users
}

// ---------------------------------------------------------------------------
// Plaintext password extraction
// ---------------------------------------------------------------------------

static RE_DEFAULT_PASSWORD_CRED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([^\\]+)\\([^:]+):(.+)$").unwrap());

static RE_PASSWORD_VALUE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)Password\s*:\s*([^\s)]+)").unwrap());

static RE_SMB_TIMESTAMP_PASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+\d{4}-\d{2}-\d{2}.*(?i)Password\s*:\s*",
    )
    .unwrap()
});

fn extract_plaintext_passwords(output: &str, default_domain: &str) -> Vec<Credential> {
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_user = String::new();
    let mut current_domain = default_domain.to_string();
    let mut expecting_default_password = false;

    let lines: Vec<&str> = output.lines().collect();
    for line in &lines {
        let stripped = line.trim();

        // DefaultPassword block
        if stripped.contains("[*] DefaultPassword") {
            expecting_default_password = true;
            continue;
        }

        if expecting_default_password {
            expecting_default_password = false;
            if let Some(caps) = RE_DEFAULT_PASSWORD_CRED.captures(stripped) {
                let domain = caps.get(1).unwrap().as_str().to_string();
                let user = caps.get(2).unwrap().as_str().to_string();
                let pass = caps.get(3).unwrap().as_str().to_string();
                if is_valid_credential(&user, &pass) {
                    let key = format!("{}\\{}:{}", domain, user, pass);
                    if seen.insert(key) {
                        credentials.push(make_credential(
                            &user,
                            &pass,
                            &domain,
                            "autologon_registry",
                        ));
                    }
                }
                continue;
            }
        }

        // Track current context
        if let Some(caps) = RE_DOMAIN_BACKSLASH.captures(stripped) {
            current_domain = caps.get(1).unwrap().as_str().to_string();
            current_user = caps.get(2).unwrap().as_str().to_string();
        } else if let Some(caps) = RE_UPN.captures(stripped) {
            current_user = caps.get(1).unwrap().as_str().to_string();
            current_domain = caps.get(2).unwrap().as_str().to_string();
        } else if let Some(caps) = RE_USER_BRACKET.captures(stripped) {
            current_user = caps.get(1).unwrap().as_str().to_string();
        } else if let Some(caps) = RE_ACCOUNT.captures(stripped) {
            current_user = caps.get(1).unwrap().as_str().to_string();
        } else if let Some(caps) = RE_SAM.captures(stripped) {
            current_user = caps.get(1).unwrap().as_str().to_string();
        }

        // Password extraction (only on lines containing "password")
        if !stripped.to_lowercase().contains("password") {
            continue;
        }

        if let Some(caps) = RE_PASSWORD_VALUE.captures(stripped) {
            let password = caps
                .get(1)
                .unwrap()
                .as_str()
                .trim_end_matches(|c| ".,;:()".contains(c))
                .to_string();

            // Try to find username from the same line
            let username = if let Some(smb_caps) = RE_SMB_TIMESTAMP_PASSWORD.captures(stripped) {
                smb_caps.get(1).unwrap().as_str().to_string()
            } else if let Some(acct_caps) = RE_ACCOUNT.captures(stripped) {
                acct_caps.get(1).unwrap().as_str().to_string()
            } else if let Some(bracket_caps) = RE_USER_BRACKET.captures(stripped) {
                bracket_caps.get(1).unwrap().as_str().to_string()
            } else {
                current_user.clone()
            };

            if !username.is_empty() && is_valid_credential(&username, &password) {
                let key = format!("{}\\{}:{}", current_domain, username, password);
                if seen.insert(key) {
                    credentials.push(make_credential(
                        &username,
                        &password,
                        &current_domain,
                        "description_field",
                    ));
                }
            }
        }
    }

    credentials
}

/// Validate a credential pair — matches Python's add_credential() rejection checks.
pub(crate) fn is_valid_credential(username: &str, password: &str) -> bool {
    if username.is_empty() || password.is_empty() {
        return false;
    }
    // Reject paths / filenames
    if username.contains('/') || username.contains('\\') || username.ends_with(".txt") {
        return false;
    }
    if password.contains('/') || password.contains('\\') || password.ends_with(".txt") {
        return false;
    }
    // Reject null/none sentinel usernames (matches Python add_credential)
    let user_lower = username.to_lowercase();
    if matches!(user_lower.as_str(), "(none)" | "none" | "null" | "(null)") {
        return false;
    }
    // Reject EVIL###$ impacket RBCD artifacts
    let user_upper = username.to_uppercase();
    if user_upper.starts_with("EVIL") && user_upper.ends_with('$') {
        let middle = &user_upper[4..user_upper.len() - 1];
        if middle.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    // Reject noise password values
    let pw_lower = password.to_lowercase();
    if matches!(
        pw_lower.as_str(),
        "(null)" | "(null:null)" | "*blank*" | "<blank>" | "n/a" | "[+]" | "password"
    ) {
        return false;
    }
    true
}

fn make_credential(username: &str, password: &str, domain: &str, source: &str) -> Credential {
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

// ---------------------------------------------------------------------------
// Share extraction — SMB share table parser
// ---------------------------------------------------------------------------

static RE_SMB_IP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+").unwrap());

static RE_SMB_PREFIX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^SMB\s+\S+\s+\d+\s+\S+\s+").unwrap());

fn extract_shares(output: &str) -> Vec<Share> {
    let mut shares = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_ip = String::new();
    let mut in_table = false;
    let valid_perms = ["read", "write", "read,write", "write,read"];

    for line in output.lines() {
        let stripped = line.trim();

        // Track current IP
        if let Some(caps) = RE_SMB_IP.captures(stripped) {
            current_ip = caps.get(1).unwrap().as_str().to_string();
        }

        // Strip SMB prefix to get body
        let body = RE_SMB_PREFIX.replace(stripped, "").to_string();
        let body = body.trim();

        if body.is_empty() {
            continue;
        }

        // Detect table header
        let body_lower = body.to_lowercase();
        if body_lower.starts_with("share") && body_lower.contains("permission") {
            in_table = true;
            continue;
        }

        // Skip separator lines
        if body.chars().all(|c| c == '-' || c == ' ') {
            continue;
        }

        if in_table && !current_ip.is_empty() {
            // Table ends at enumeration summary or empty body
            if body.starts_with('[') {
                in_table = false;
                continue;
            }

            // Split on whitespace runs (columns are separated by multiple spaces)
            let parts: Vec<&str> = body.split_whitespace().collect();
            if parts.len() >= 2 {
                let share_name = parts[0].to_string();
                let perm = parts[1].to_lowercase();
                if valid_perms.contains(&perm.as_str()) {
                    let comment = if parts.len() >= 3 {
                        parts[2..].join(" ")
                    } else {
                        String::new()
                    };
                    let key = format!("{}:{}", current_ip, share_name);
                    if seen.insert(key) {
                        shares.push(Share {
                            host: current_ip.clone(),
                            name: share_name,
                            permissions: perm.to_uppercase(),
                            comment,
                        });
                    }
                }
            }
        }
    }

    shares
}

// ---------------------------------------------------------------------------
// Hash extraction — NTLM, Kerberoast (TGS), AS-REP
// ---------------------------------------------------------------------------

static RE_TGS_HASH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+)").unwrap()
});

static RE_ASREP_HASH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+)").unwrap());

// domain\user:rid:lmhash:nthash:::
static RE_NTLM_DOMAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([^\\:\s]+)\\([^:\\]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

// user:rid:lmhash:nthash:::
static RE_NTLM_PLAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([^:\\$\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

// Partial NTLM line (line-wrapped secretsdump)
static RE_NTLM_PARTIAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[^:\s]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]+$").unwrap());

static RE_NTLM_CONTINUATION: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]+:::$").unwrap());

fn extract_hashes(output: &str, default_domain: &str) -> Vec<Hash> {
    let mut hashes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // First pass: unwrap line-wrapped NTLM hashes
    let lines: Vec<&str> = output.lines().collect();
    let mut unwrapped: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if RE_NTLM_PARTIAL.is_match(line) && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            if RE_NTLM_CONTINUATION.is_match(next) {
                unwrapped.push(format!("{}{}", line, next));
                i += 2;
                continue;
            }
        }
        unwrapped.push(line.to_string());
        i += 1;
    }

    for line in &unwrapped {
        // Priority: TGS → AS-REP → NTLM (first match wins)

        // TGS (Kerberoast)
        if let Some(caps) = RE_TGS_HASH.captures(line) {
            let hash_value = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let domain = caps.get(3).unwrap().as_str();
            let key = format!("tgs:{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value: hash_value.to_string(),
                    hash_type: "kerberoast".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
            continue;
        }

        // AS-REP
        if let Some(caps) = RE_ASREP_HASH.captures(line) {
            let hash_value = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let domain = caps.get(3).unwrap().as_str();
            let key = format!(
                "asrep:{}@{}",
                username.to_lowercase(),
                domain.to_lowercase()
            );
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value: hash_value.to_string(),
                    hash_type: "asrep".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
            continue;
        }

        // NTLM with domain prefix
        if let Some(caps) = RE_NTLM_DOMAIN.captures(line) {
            let domain = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let lm = caps.get(3).unwrap().as_str();
            let nt = caps.get(4).unwrap().as_str();
            let hash_value = format!("{lm}:{nt}");
            let key = format!("ntlm:{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value,
                    hash_type: "ntlm".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
            continue;
        }

        // NTLM without domain prefix
        if let Some(caps) = RE_NTLM_PLAIN.captures(line) {
            let username = caps.get(1).unwrap().as_str();
            let lm = caps.get(3).unwrap().as_str();
            let nt = caps.get(4).unwrap().as_str();
            let hash_value = format!("{lm}:{nt}");
            let key = format!(
                "ntlm:{}@{}",
                username.to_lowercase(),
                default_domain.to_lowercase()
            );
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value,
                    hash_type: "ntlm".to_string(),
                    domain: default_domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
        }
    }

    hashes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Hash extraction ---

    #[test]
    fn test_extract_ntlm_with_domain() {
        let output =
            "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "Administrator");
        assert_eq!(hashes[0].domain, "CONTOSO");
        assert_eq!(hashes[0].hash_type, "ntlm");
        assert!(hashes[0]
            .hash_value
            .contains("e19ccf75ee54e06b06a5907af13cef42"));
    }

    #[test]
    fn test_extract_ntlm_without_domain() {
        let output =
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "Administrator");
        assert_eq!(hashes[0].domain, "contoso.local");
    }

    #[test]
    fn test_extract_tgs_hash() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc123def456";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
        assert_eq!(hashes[0].hash_type, "kerberoast");
    }

    #[test]
    fn test_extract_asrep_hash() {
        let output = "$krb5asrep$23$jdoe@CONTOSO.LOCAL:abc123def456789012345678901234567890abcdef";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "jdoe");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
        assert_eq!(hashes[0].hash_type, "asrep");
    }

    #[test]
    fn test_extract_line_wrapped_ntlm() {
        let output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75\nee54e06b06a5907af13cef42:::";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "Administrator");
    }

    #[test]
    fn test_extract_hashes_dedup() {
        let output = "\
CONTOSO\\admin:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::\n\
CONTOSO\\admin:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1, "Should dedup identical hashes");
    }

    // --- Host extraction ---

    #[test]
    fn test_extract_hosts_banner() {
        let output = "SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local) (signing:True)";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.58.10");
        assert_eq!(hosts[0].hostname, "dc01.contoso.local"); // FQDN constructed from name+domain
        assert!(hosts[0].is_dc);
    }

    #[test]
    fn test_extract_hosts_banner_fqdn_construction() {
        // Verify FQDN is built from (name:X)(domain:Y) → x.y
        let output = "SMB  10.1.2.150  445  WINTERFELL  [*] Windows Server 2019 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True)";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "winterfell.north.sevenkingdoms.local");
        assert!(hosts[0].is_dc);
    }

    #[test]
    fn test_extract_hosts_banner_domain_trailing_zero() {
        // netexec sometimes appends "0." to domain — verify it's stripped
        let output = "SMB  10.1.2.150  445  WINTERFELL  [*] Windows Server 2019 (name:WINTERFELL) (domain:sevenkingdoms.local0.) (signing:True)";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "winterfell.sevenkingdoms.local");
    }

    #[test]
    fn test_extract_hosts_simple() {
        let output = "SMB  192.168.58.20  445  SRV01  some output";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.58.20");
        assert_eq!(hosts[0].hostname, "SRV01");
    }

    #[test]
    fn test_extract_hosts_dedup() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows (name:DC01) (domain:contoso.local)\n\
SMB  192.168.58.10  445  DC01  something else";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1, "Should dedup by IP");
        assert_eq!(hosts[0].hostname, "dc01.contoso.local");
    }

    // --- User extraction ---

    #[test]
    fn test_extract_users_domain_backslash() {
        let output = "CONTOSO\\alice.johnson (SidTypeUser)";
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice.johnson");
        assert_eq!(users[0].domain, "CONTOSO");
    }

    #[test]
    fn test_extract_users_upn() {
        let output = "Found user: bob@contoso.local";
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "bob");
        assert_eq!(users[0].domain, "contoso.local");
    }

    #[test]
    fn test_extract_users_rpc_format() {
        let output = "user:[admin] rid:[0x1f4]";
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].domain, "contoso.local");
    }

    #[test]
    fn test_extract_users_samaccountname() {
        let output = "sAMAccountName: svc_sql";
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "svc_sql");
    }

    #[test]
    fn test_extract_users_skip_machine_accounts() {
        let output = "CONTOSO\\DC01$ (SidTypeUser)";
        let users = extract_users(output, "contoso.local");
        assert!(
            users.is_empty(),
            "Machine accounts (ending in $) should be skipped"
        );
    }

    #[test]
    fn test_extract_users_skip_anonymous() {
        let output = "user:[anonymous] rid:[0x1f5]";
        let users = extract_users(output, "contoso.local");
        assert!(users.is_empty());
    }

    #[test]
    fn test_extract_users_smb_timestamp() {
        let output = "SMB  192.168.58.10  445  DC01  alice.johnson  2026-03-25 23:21:09 0  Alice";
        let users = extract_users(output, "contoso.local");
        assert!(users.iter().any(|u| u.username == "alice.johnson"));
    }

    #[test]
    fn test_extract_users_domain_context_propagation() {
        let output = "\
[*] Windows (name:DC01) (domain:north.contoso.local)\n\
user:[alice] rid:[0x1f4]";
        let users = extract_users(output, "contoso.local");
        let alice = users.iter().find(|u| u.username == "alice").unwrap();
        assert_eq!(alice.domain, "north.contoso.local");
    }

    // --- Plaintext password extraction ---

    #[test]
    fn test_extract_password_from_description() {
        let output =
            "SMB  192.168.58.10  445  DC01  dave.miller  2026-03-25 23:22:25 0  Dave Miller (Password : Summer2026!)";
        let creds = extract_plaintext_passwords(output, "contoso.local");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "dave.miller");
        assert_eq!(creds[0].password, "Summer2026!");
    }

    #[test]
    fn test_extract_default_password() {
        let output = "\
[*] DefaultPassword\n\
CONTOSO\\svc_backup:BackupPass123!";
        let creds = extract_plaintext_passwords(output, "contoso.local");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "svc_backup");
        assert_eq!(creds[0].password, "BackupPass123!");
        assert_eq!(creds[0].domain, "CONTOSO");
    }

    #[test]
    fn test_extract_password_rejects_paths() {
        let output = "Password : /tmp/users.txt";
        let creds = extract_plaintext_passwords(output, "contoso.local");
        assert!(creds.is_empty());
    }

    // --- Share extraction ---

    #[test]
    fn test_extract_shares() {
        let output = "\
SMB  192.168.58.10  445  DC01  Share           Permissions  Remark\n\
SMB  192.168.58.10  445  DC01  -----           -----------  ------\n\
SMB  192.168.58.10  445  DC01  SYSVOL          READ         Logon server share\n\
SMB  192.168.58.10  445  DC01  ADMIN$          READ,WRITE\n\
SMB  192.168.58.10  445  DC01  [*] Enumerated 2 shares";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].name, "SYSVOL");
        assert_eq!(shares[0].permissions, "READ");
        assert_eq!(shares[0].host, "192.168.58.10");
        assert_eq!(shares[1].name, "ADMIN$");
        assert_eq!(shares[1].permissions, "READ,WRITE");
    }

    // --- Full extraction ---

    #[test]
    fn test_full_extraction() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local) (signing:True)\n\
SMB  192.168.58.10  445  DC01  [+] contoso.local\\:\n\
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-\n\
SMB  192.168.58.10  445  DC01  alice       2026-03-25 23:21:09 0  Alice (Password : Welcome1!)\n\
SMB  192.168.58.10  445  DC01  bob         2026-03-25 23:21:09 0  Bob\n\
CONTOSO\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c:::";

        let result = extract_from_output_text(output, "contoso.local");
        assert!(!result.hosts.is_empty(), "Should extract hosts");
        assert!(!result.users.is_empty(), "Should extract users");
        assert!(!result.credentials.is_empty(), "Should extract credentials");
        assert!(!result.hashes.is_empty(), "Should extract hashes");
    }

    #[test]
    fn test_empty_output() {
        let result = extract_from_output_text("", "contoso.local");
        assert!(result.is_empty());
    }

    // --- is_valid_credential tests ---

    #[test]
    fn test_valid_credential_rejects_null_usernames() {
        assert!(!is_valid_credential("(none)", "pass"));
        assert!(!is_valid_credential("none", "pass"));
        assert!(!is_valid_credential("null", "pass"));
        assert!(!is_valid_credential("(null)", "pass"));
        assert!(!is_valid_credential("(None)", "pass"));
    }

    #[test]
    fn test_valid_credential_rejects_evil_artifacts() {
        assert!(!is_valid_credential("EVIL625686$", "pass"));
        assert!(!is_valid_credential("evil12345$", "pass"));
        // Non-numeric middle should pass
        assert!(is_valid_credential("EVILBOT$", "pass"));
    }

    #[test]
    fn test_valid_credential_rejects_noise_passwords() {
        assert!(!is_valid_credential("user", "(null)"));
        assert!(!is_valid_credential("user", "*BLANK*"));
        assert!(!is_valid_credential("user", "<BLANK>"));
        assert!(!is_valid_credential("user", "N/A"));
        assert!(!is_valid_credential("user", "[+]"));
        assert!(!is_valid_credential("user", "Password"));
        assert!(!is_valid_credential("user", "password"));
    }

    #[test]
    fn test_valid_credential_accepts_real_passwords() {
        assert!(is_valid_credential("admin", "P@ss1"));
        assert!(is_valid_credential("hodor", "hodor"));
        assert!(is_valid_credential("svc_test", "svc_test"));
    }
}
