//! Parser for spider_plus downloaded file contents.
//!
//! Extracts credentials from SYSVOL scripts, config files, and text files
//! that spider_plus downloads during SMB share spidering.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

/// PowerShell/batch password assignment: `$password = "value"`, `password=value`, etc.
static RE_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)^\s*\$?(?:password|pass|passwd|pwd)\s*[=:]\s*(?:"([^"]+)"|'([^']+)'|(\S+))"#)
        .unwrap()
});

/// PowerShell/batch username assignment: `$username = "value"`, `user=value`, etc.
static RE_USERNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?im)^\s*\$?(?:username|user|login|account)\s*[=:]\s*(?:"([^"]+)"|'([^']+)'|(\S+))"#,
    )
    .unwrap()
});

/// `net use \\server /user:DOMAIN\user password` pattern.
static RE_NET_USE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)net\s+use\s+\S+\s+/user:(?:(\S+?)\\)?(\S+)\s+(\S+)").unwrap()
});

/// `-Password "value"` or `-Pass "value"` PowerShell parameter patterns.
static RE_PS_PARAM_PASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)-(?:Password|Pass|Passwd)\s+(?:"([^"]+)"|'([^']+)'|(\S+))"#).unwrap()
});

/// `-UserName "value"` or `-User "value"` PowerShell parameter patterns.
static RE_PS_PARAM_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)-(?:UserName|User|Credential)\s+(?:"([^"]+)"|'([^']+)'|(\S+))"#).unwrap()
});

/// Extract the first non-None capture group from a regex match.
fn first_capture(cap: &regex::Captures<'_>, groups: &[usize]) -> Option<String> {
    for &g in groups {
        if let Some(m) = cap.get(g) {
            let s = m.as_str().trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Split `DOMAIN\username` into `(domain, username)`.  If no backslash, returns
/// `(None, original)`.
fn split_domain_user(raw: &str) -> (Option<&str>, &str) {
    if let Some(pos) = raw.find('\\') {
        (Some(&raw[..pos]), &raw[pos + 1..])
    } else {
        (None, raw)
    }
}

/// Resolve a NetBIOS domain name to FQDN if it matches the first label.
/// e.g., "CHILD" + fqdn "child.contoso.local" → "child.contoso.local".
/// Returns the extracted domain unchanged if it doesn't match.
fn resolve_domain_from_fqdn<'a>(extracted: &str, fqdn: &'a str) -> Option<&'a str> {
    if fqdn.is_empty() || extracted.is_empty() {
        return None;
    }
    let first_label = fqdn.split('.').next().unwrap_or("");
    if extracted.eq_ignore_ascii_case(first_label) {
        Some(fqdn)
    } else {
        None
    }
}

/// Extract credentials from spider-downloaded file contents.
///
/// The spider output uses `--- path/to/file.ext ---` delimiters between
/// file sections. This parser processes each section looking for common
/// credential patterns in PowerShell scripts, batch files, and config files.
pub fn parse_spider_credentials(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let mut creds = Vec::new();

    // Split on file section delimiters: "--- path/file ---\n"
    for section in output.split("\n--- ") {
        // Skip metadata/header sections
        if section.starts_with("=== ") || section.trim().is_empty() {
            continue;
        }

        // Get the content after the delimiter line
        let content = match section.split_once(" ---\n") {
            Some((_, c)) => c,
            None => section,
        };

        // Pattern 1: net use /user:DOMAIN\user password
        for cap in RE_NET_USE.captures_iter(content) {
            let cred_domain = cap
                .get(1)
                .map(|m| m.as_str())
                .filter(|s| !s.is_empty())
                .map(|d| resolve_domain_from_fqdn(d, domain).unwrap_or(d))
                .unwrap_or(domain);
            let username = &cap[2];
            let password = &cap[3];
            if is_plausible_password(password) {
                creds.push(json!({
                    "username": username,
                    "password": password,
                    "domain": cred_domain,
                    "source": "sysvol_script",
                }));
            }
        }

        // Pattern 2: Variable assignment pairs ($user = "x", $password = "y")
        let usernames: Vec<String> = RE_USERNAME
            .captures_iter(content)
            .filter_map(|cap| first_capture(&cap, &[1, 2, 3]))
            .collect();

        let passwords: Vec<String> = RE_PASSWORD
            .captures_iter(content)
            .filter_map(|cap| first_capture(&cap, &[1, 2, 3]))
            .filter(|p| is_plausible_password(p))
            .collect();

        // Pair usernames with passwords (positional within the same file)
        if !passwords.is_empty() {
            for (i, password) in passwords.iter().enumerate() {
                let raw_user = if i < usernames.len() {
                    &usernames[i]
                } else if !usernames.is_empty() {
                    &usernames[usernames.len() - 1]
                } else {
                    // Password found but no username variable — skip
                    continue;
                };
                let (user_domain, username) = split_domain_user(raw_user);
                let cred_domain = match user_domain {
                    Some(d) => resolve_domain_from_fqdn(d, domain).unwrap_or(d),
                    None => domain,
                };
                creds.push(json!({
                    "username": username,
                    "password": password,
                    "domain": cred_domain,
                    "source": "sysvol_script",
                }));
            }
        }

        // Pattern 3: PowerShell parameter style (-UserName X -Password Y)
        let ps_users: Vec<String> = RE_PS_PARAM_USER
            .captures_iter(content)
            .filter_map(|cap| first_capture(&cap, &[1, 2, 3]))
            .collect();

        let ps_passes: Vec<String> = RE_PS_PARAM_PASS
            .captures_iter(content)
            .filter_map(|cap| first_capture(&cap, &[1, 2, 3]))
            .filter(|p| is_plausible_password(p))
            .collect();

        if !ps_passes.is_empty() {
            for (i, password) in ps_passes.iter().enumerate() {
                let raw_user = if i < ps_users.len() {
                    &ps_users[i]
                } else if !ps_users.is_empty() {
                    &ps_users[ps_users.len() - 1]
                } else {
                    continue;
                };
                let (user_domain, username) = split_domain_user(raw_user);
                let cred_domain = match user_domain {
                    Some(d) => resolve_domain_from_fqdn(d, domain).unwrap_or(d),
                    None => domain,
                };
                creds.push(json!({
                    "username": username,
                    "password": password,
                    "domain": cred_domain,
                    "source": "sysvol_script",
                }));
            }
        }
    }

    // Dedup by username+password
    creds.sort_by(|a, b| {
        let ka = format!("{}:{}", a["username"], a["password"]);
        let kb = format!("{}:{}", b["username"], b["password"]);
        ka.cmp(&kb)
    });
    creds.dedup_by(|a, b| a["username"] == b["username"] && a["password"] == b["password"]);

    creds
}

/// Quick check that a value looks like a plausible password (not a variable ref,
/// not too short, not a common placeholder).
fn is_plausible_password(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    // Skip variable references like $var, %var%
    if s.starts_with('$') || s.starts_with('%') {
        return false;
    }
    // Skip common placeholders
    let lower = s.to_lowercase();
    !matches!(
        lower.as_str(),
        "changeme" | "password" | "pass" | "xxx" | "todo" | "null" | "none" | "empty"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_powershell_variable_assignments() {
        // Matches actual GOAD script format
        let output = r#"
=== Downloaded File Contents ===

--- NETLOGON/script.ps1 ---
# fake script in netlogon with creds
$task = '/c TODO'
$taskName = "fake task"
$user = "CHILD\jeff.morgan"
$password = "_S3cur3P@ss_"

# passwords in sysvol still ...
"#;
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_spider_credentials(output, &params);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "jeff.morgan");
        assert_eq!(creds[0]["password"], "_S3cur3P@ss_");
        // NetBIOS "CHILD" resolved to FQDN since first label matches param domain
        assert_eq!(creds[0]["domain"], "child.contoso.local");
    }

    #[test]
    fn test_net_use_command() {
        let output = r#"
--- SYSVOL/scripts/map_drive.bat ---
net use \\dc02\share /user:CHILD\jeff.morgan _S3cur3P@ss_
"#;
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_spider_credentials(output, &params);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "jeff.morgan");
        assert_eq!(creds[0]["password"], "_S3cur3P@ss_");
        assert_eq!(creds[0]["domain"], "child.contoso.local");
    }

    #[test]
    fn test_powershell_params() {
        let output = r#"
--- scripts/setup.ps1 ---
New-SmbMapping -RemotePath "\\dc01\share" -UserName "svc_sql" -Password "SqlP@ss123"
"#;
        let params = json!({"domain": "contoso.local"});
        let creds = parse_spider_credentials(output, &params);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "svc_sql");
        assert_eq!(creds[0]["password"], "SqlP@ss123");
    }

    #[test]
    fn test_skips_variable_refs() {
        let output = r#"
--- scripts/template.ps1 ---
$user = "admin"
$pass = $env:SECRET_KEY
"#;
        let params = json!({"domain": "contoso.local"});
        let creds = parse_spider_credentials(output, &params);
        // Should skip $env:SECRET_KEY (variable reference)
        assert!(creds.is_empty());
    }

    #[test]
    fn test_multiple_files() {
        let output = r#"
=== Downloaded File Contents ===

--- SYSVOL/scripts/script1.ps1 ---
$user = "alice"
$password = "Welcome1!"

--- SYSVOL/scripts/script2.ps1 ---
$username = "bob"
$pass = "P@ssw0rd"
"#;
        let params = json!({"domain": "contoso.local"});
        let creds = parse_spider_credentials(output, &params);

        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn test_empty_output() {
        let creds = parse_spider_credentials("", &json!({}));
        assert!(creds.is_empty());
    }
}
