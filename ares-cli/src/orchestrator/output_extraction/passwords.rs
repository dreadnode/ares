use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::Credential;

use super::users::{RE_ACCOUNT, RE_DOMAIN_BACKSLASH, RE_UPN, RE_USER_BRACKET};
use super::{is_valid_credential, make_credential};

static RE_DEFAULT_PASSWORD_CRED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^\\]+)\\([^:]+):(.+)$").unwrap());

static RE_PASSWORD_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Password\s*:\s*([^\s)]+)").unwrap());

static RE_SMB_TIMESTAMP_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+\d{4}-\d{2}-\d{2}.*(?i)Password\s*:\s*",
    )
    .unwrap()
});

/// General nxc SMB line with a username field followed eventually by "Password":
/// `SMB  IP  PORT  HOST  username  ... Password : xxx`
/// Broader than RE_SMB_TIMESTAMP_PASSWORD — doesn't require a timestamp.
static RE_SMB_LINE_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+.*(?i)Password\s*:\s*").unwrap()
});

/// Netexec [+] success line: `SMB IP PORT HOST [+] DOMAIN\user:password`
static RE_NETEXEC_SUCCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[\+\]\s+([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-$]+):([^\s(]+)").unwrap()
});

/// Regex for rpcclient `queryuser` output: `User Name   :\tjdoe`
static RE_RPC_USER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*User\s+Name\s*:\s*(\S+)").unwrap());

/// Extract credentials from rpcclient queryuser blocks where "User Name" and
/// "Description" (containing a password) appear on separate lines.
///
/// This is safe because rpcclient queryuser output is deterministic: attributes
/// always belong to the same user within a single query response block.
fn extract_rpcclient_description_passwords(
    output: &str,
    default_domain: &str,
    seen: &mut std::collections::HashSet<String>,
) -> Vec<Credential> {
    let mut credentials = Vec::new();
    let mut current_user: Option<String> = None;

    for line in output.lines() {
        let stripped = line.trim();
        // Track the current user from "User Name : xxx"
        if let Some(caps) = RE_RPC_USER_NAME.captures(stripped) {
            current_user = Some(caps.get(1).unwrap().as_str().to_string());
            continue;
        }
        // Empty line or new block separator resets user context
        if stripped.is_empty() {
            current_user = None;
            continue;
        }
        // Look for password in Description field
        if let Some(ref username) = current_user {
            if stripped.to_lowercase().contains("description")
                && stripped.to_lowercase().contains("password")
            {
                if let Some(caps) = RE_PASSWORD_VALUE.captures(stripped) {
                    let password = caps
                        .get(1)
                        .unwrap()
                        .as_str()
                        .trim_end_matches(|c: char| ".,;:()".contains(c))
                        .trim_matches('\'')
                        .trim_matches('"')
                        .to_string();
                    if is_valid_credential(username, &password) {
                        let key = format!("{}\\{}:{}", default_domain, username, password);
                        if seen.insert(key) {
                            credentials.push(make_credential(
                                username,
                                &password,
                                default_domain,
                                "description_field",
                            ));
                        }
                    }
                }
            }
        }
    }
    credentials
}

pub fn extract_plaintext_passwords(
    ctx: &super::ToolOutputCtx<'_>,
    default_domain: &str,
) -> Vec<Credential> {
    let output = ctx.output;
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // First pass: extract from rpcclient queryuser blocks (multi-line)
    credentials.extend(extract_rpcclient_description_passwords(
        output,
        default_domain,
        &mut seen,
    ));

    const FAILURE_MARKERS: &[&str] = &[
        "STATUS_LOGON_FAILURE",
        "STATUS_PASSWORD_EXPIRED",
        "STATUS_PASSWORD_MUST_CHANGE",
        "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_ACCOUNT_DISABLED",
        "STATUS_ACCOUNT_RESTRICTION",
        "STATUS_NO_LOGON_SERVERS",
        "STATUS_ACCESS_DENIED",
        "STATUS_INVALID_LOGON_HOURS",
        "STATUS_INVALID_WORKSTATION",
        "LOGON FAILURE",
        "LOGON_FAILURE",
        "ACCESS_DENIED",
        // Guest fallback — SMB accepted the connection but mapped it to the
        // built-in Guest account.  The supplied password was NOT validated.
        "(GUEST)",
    ];

    // Skip the `[+] DOMAIN\user:secret` netexec-auth pattern when the tool was
    // invoked with hash auth — the "secret" is the supplied NT/LM hash echoed
    // back, not a discovered plaintext password. Without this gate, every
    // successful pass-the-hash sweep ingests the hash a second time as a fake
    // credential row (`frank:6dccf1c567c56a40e56691a723a49664`).
    let skip_netexec_auth = ctx.is_hash_auth();

    if !skip_netexec_auth {
        for line in output.lines() {
            let stripped = line.trim();
            if !stripped.contains("[+]") {
                continue;
            }
            let upper = stripped.to_uppercase();
            if FAILURE_MARKERS.iter().any(|m| upper.contains(m)) {
                continue;
            }
            if let Some(caps) = RE_NETEXEC_SUCCESS.captures(stripped) {
                let domain = caps.get(1).unwrap().as_str().to_string();
                let user = caps.get(2).unwrap().as_str().to_string();
                let pass = caps
                    .get(3)
                    .unwrap()
                    .as_str()
                    .trim_end_matches("(Pwn3d!)")
                    .trim()
                    .to_string();
                if is_valid_credential(&user, &pass) {
                    let key = format!("{}\\{}:{}", domain, user, pass);
                    if seen.insert(key) {
                        credentials.push(make_credential(&user, &pass, &domain, "netexec_auth"));
                    }
                }
            }
        }
    }
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

        // Track current domain context (for dedup key and credential domain).
        // Only domain is tracked — tracking username here would cause
        // stale-context misattribution (LDAP doesn't guarantee attribute order).
        // Guard against machine hostnames (e.g. WIN-xxx from Kali's own SMB banner)
        // overriding the task's default domain.
        if let Some(caps) = RE_DOMAIN_BACKSLASH.captures(stripped) {
            let dom = caps.get(1).unwrap().as_str();
            if !super::users::is_machine_hostname_domain(dom) {
                current_domain = dom.to_string();
            }
        } else if let Some(caps) = RE_UPN.captures(stripped) {
            let dom = caps.get(2).unwrap().as_str();
            if !super::users::is_machine_hostname_domain(dom) {
                current_domain = dom.to_string();
            }
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
                .trim_matches('\'')
                .trim_matches('"')
                .to_string();

            // Extract username from the SAME line only. Never fall back to
            // current_user — LDAP doesn't guarantee attribute order, so
            // description may appear before sAMAccountName within an entry,
            // causing stale current_user from a previous entry to be
            // misattributed (e.g. john.smith:Summer2025 instead of
            // sam.wilson:Summer2025). Per-tool parsers handle structured
            // extraction; this safety net only catches same-line patterns.
            let username = if let Some(smb_caps) = RE_SMB_TIMESTAMP_PASSWORD.captures(stripped) {
                smb_caps.get(1).unwrap().as_str().to_string()
            } else if let Some(smb_caps) = RE_SMB_LINE_PASSWORD.captures(stripped) {
                smb_caps.get(1).unwrap().as_str().to_string()
            } else if let Some(acct_caps) = RE_ACCOUNT.captures(stripped) {
                acct_caps.get(1).unwrap().as_str().to_string()
            } else if let Some(bracket_caps) = RE_USER_BRACKET.captures(stripped) {
                bracket_caps.get(1).unwrap().as_str().to_string()
            } else {
                // No same-line username found — skip this password.
                // The per-tool parser handles structured extraction.
                continue;
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
