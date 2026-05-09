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
            if is_plausible_username(username) && is_plausible_password(password) {
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
            .filter(|u| is_plausible_username(u))
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
                // Re-validate post-split: a raw capture like `DOMAIN\$User.UserName`
                // passes the pre-split filter (doesn't start with `$`) but yields a
                // bogus `$User.UserName` username after the prefix is stripped.
                if !is_plausible_username(username) {
                    continue;
                }
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
            .filter(|u| is_plausible_username(u))
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
                if !is_plausible_username(username) {
                    continue;
                }
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
    // Skip PowerShell cmdlet tokens like `New-Object`, `Get-Credential`,
    // `ConvertTo-SecureString` — common when a script's RHS expression starts
    // with a cmdlet rather than a literal value.
    if RE_PS_CMDLET.is_match(s) {
        return false;
    }
    // Skip common placeholders
    let lower = s.to_lowercase();
    !matches!(
        lower.as_str(),
        "changeme" | "password" | "pass" | "xxx" | "todo" | "null" | "none" | "empty"
    )
}

/// PowerShell cmdlet token: `Verb-Noun` (capitalized words separated by `-`),
/// e.g. `New-Object`, `Get-Credential`, `ConvertTo-SecureString`.
static RE_PS_CMDLET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Za-z]+-[A-Z][A-Za-z]+$").unwrap());

fn is_plausible_username(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Skip variable references — `$var`, `$user.username`, `%var%`.
    // (Real AD usernames like `alice.jones` contain `.` but never start
    // with `$` or `%`.)
    if s.starts_with('$') || s.starts_with('%') {
        return false;
    }
    // Skip PowerShell cmdlet tokens — same shape as the password check.
    if RE_PS_CMDLET.is_match(s) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn powershell_variable_assignments() {
        let output = r#"
=== Downloaded File Contents ===

--- NETLOGON/script.ps1 ---
# fake script in netlogon with creds
$task = '/c TODO'
$taskName = "fake task"
$user = "CHILD\alice.jones"
$password = "P@ssw0rd!"

# passwords in sysvol still ...
"#;
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_spider_credentials(output, &params);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "alice.jones");
        assert_eq!(creds[0]["password"], "P@ssw0rd!");
        // NetBIOS "CHILD" resolved to FQDN since first label matches param domain
        assert_eq!(creds[0]["domain"], "child.contoso.local");
    }

    #[test]
    fn net_use_command() {
        let output = r#"
--- SYSVOL/scripts/map_drive.bat ---
net use \\dc02\share /user:CHILD\alice.jones P@ssw0rd!
"#;
        let params = json!({"domain": "child.contoso.local"});
        let creds = parse_spider_credentials(output, &params);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "alice.jones");
        assert_eq!(creds[0]["password"], "P@ssw0rd!");
        assert_eq!(creds[0]["domain"], "child.contoso.local");
    }

    #[test]
    fn powershell_params() {
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
    fn skips_variable_refs() {
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
    fn multiple_files() {
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
    fn empty_output() {
        let creds = parse_spider_credentials("", &json!({}));
        assert!(creds.is_empty());
    }

    // ── split_domain_user ─────────────────────────────────────────

    #[test]
    fn split_domain_user_with_backslash() {
        let (domain, user) = split_domain_user("CONTOSO\\admin");
        assert_eq!(domain, Some("CONTOSO"));
        assert_eq!(user, "admin");
    }

    #[test]
    fn split_domain_user_no_backslash() {
        let (domain, user) = split_domain_user("admin");
        assert!(domain.is_none());
        assert_eq!(user, "admin");
    }

    #[test]
    fn split_domain_user_empty() {
        let (domain, user) = split_domain_user("");
        assert!(domain.is_none());
        assert_eq!(user, "");
    }

    // ── resolve_domain_from_fqdn ──────────────────────────────────

    #[test]
    fn resolve_fqdn_matching() {
        assert_eq!(
            resolve_domain_from_fqdn("CHILD", "child.contoso.local"),
            Some("child.contoso.local")
        );
    }

    #[test]
    fn resolve_fqdn_case_insensitive() {
        assert_eq!(
            resolve_domain_from_fqdn("child", "CHILD.contoso.local"),
            Some("CHILD.contoso.local")
        );
    }

    #[test]
    fn resolve_fqdn_no_match() {
        assert_eq!(
            resolve_domain_from_fqdn("OTHER", "child.contoso.local"),
            None
        );
    }

    #[test]
    fn resolve_fqdn_empty_inputs() {
        assert_eq!(resolve_domain_from_fqdn("", "child.contoso.local"), None);
        assert_eq!(resolve_domain_from_fqdn("CHILD", ""), None);
    }

    // ── is_plausible_password ─────────────────────────────────────

    #[test]
    fn plausible_password_valid() {
        assert!(is_plausible_password("Summer2025!"));
        assert!(is_plausible_password("ab"));
    }

    #[test]
    fn plausible_password_too_short() {
        assert!(!is_plausible_password("a"));
        assert!(!is_plausible_password(""));
    }

    #[test]
    fn plausible_password_variable_refs() {
        assert!(!is_plausible_password("$env:SECRET"));
        assert!(!is_plausible_password("%PASSWORD%"));
    }

    #[test]
    fn plausible_password_placeholders() {
        assert!(!is_plausible_password("changeme"));
        assert!(!is_plausible_password("PASSWORD"));
        assert!(!is_plausible_password("xxx"));
        assert!(!is_plausible_password("TODO"));
        assert!(!is_plausible_password("null"));
        assert!(!is_plausible_password("none"));
        assert!(!is_plausible_password("empty"));
    }

    // ── first_capture ─────────────────────────────────────────────

    #[test]
    fn first_capture_finds_group() {
        let re = regex::Regex::new(r"(foo)|(bar)").unwrap();
        let cap = re.captures("bar").unwrap();
        let result = first_capture(&cap, &[1, 2]);
        assert_eq!(result, Some("bar".to_string()));
    }

    #[test]
    fn first_capture_prefers_first() {
        let re = regex::Regex::new(r"(abc)(def)").unwrap();
        let cap = re.captures("abcdef").unwrap();
        let result = first_capture(&cap, &[1, 2]);
        assert_eq!(result, Some("abc".to_string()));
    }

    #[test]
    fn first_capture_no_match() {
        let re = regex::Regex::new(r"(foo)|(bar)").unwrap();
        let cap = re.captures("bar").unwrap();
        // group 1 is None, group 3 doesn't exist
        let result = first_capture(&cap, &[1, 3]);
        assert_eq!(result, None);
    }

    #[test]
    fn rejects_powershell_variable_username_and_cmdlet_password() {
        // Regression: a SYSVOL script that builds a PSCredential reused the
        // `username` / `pass` variable names against PowerShell tokens, and
        // the parser produced a bogus `$user.username:New-Object` credential.
        let output = r#"
=== Downloaded File Contents ===

--- NETLOGON/login.ps1 ---
$user = Get-CurrentUser
$username = $user.username
$pass = New-Object Security.PSCredential
"#;
        let creds = parse_spider_credentials(output, &json!({"domain": "contoso.local"}));
        assert!(
            creds.is_empty(),
            "should reject variable-ref usernames and cmdlet passwords, got: {:?}",
            creds
        );
    }

    #[test]
    fn rejects_dollar_var_username_after_domain_prefix_strip() {
        // Regression: the raw capture `FABRIKAM\$User.UserName` passes
        // `is_plausible_username` (doesn't start with `$`), but after
        // `split_domain_user` strips the `FABRIKAM\` prefix the username becomes
        // `$User.UserName` — a PowerShell variable expression, not a real
        // account. Verify the post-split validation rejects it.
        let output = r#"
=== Downloaded File Contents ===

--- NETLOGON/login.ps1 ---
$user = "FABRIKAM\$User.UserName"
$password = "P@ssw0rd!"
"#;
        let creds = parse_spider_credentials(output, &json!({"domain": "fabrikam.local"}));
        assert!(
            creds.is_empty(),
            "should reject `$User.UserName` username after stripping `FABRIKAM\\` prefix, got: {:?}",
            creds
        );
    }

    #[test]
    fn rejects_cmdlet_username_in_net_use() {
        // Regression: net use pattern lacked `is_plausible_username` validation,
        // so a literal cmdlet token in the user field could leak through.
        let output = r#"
--- SYSVOL/scripts/setup.bat ---
net use \\dc01\share /user:CONTOSO\Get-Credential P@ssw0rd!
"#;
        let creds = parse_spider_credentials(output, &json!({"domain": "contoso.local"}));
        assert!(
            creds.is_empty(),
            "should reject cmdlet-shaped username in net use, got: {:?}",
            creds
        );
    }

    #[test]
    fn still_extracts_real_dotted_username_with_quoted_password() {
        // Make sure the new filters don't reject `firstname.lastname` style
        // accounts when paired with a real password literal.
        let output = r#"
--- NETLOGON/script.ps1 ---
$username = "alice.jones"
$password = "P@ssw0rd!"
"#;
        let creds = parse_spider_credentials(output, &json!({"domain": "contoso.local"}));
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "alice.jones");
        assert_eq!(creds[0]["password"], "P@ssw0rd!");
    }
}
