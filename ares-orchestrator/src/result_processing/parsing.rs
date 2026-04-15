//! Pure parsing functions for result payloads -- no IO, no Redis.

use serde_json::Value;

use ares_core::models::{Credential, Hash, Host, Share, User, VulnerabilityInfo};

/// Parsed discoveries from a JSON result payload.
#[derive(Debug, Default)]
pub(crate) struct ParsedDiscoveries {
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub shares: Vec<Share>,
}

/// Resolve the parent credential or hash for a newly discovered item.
pub(crate) fn resolve_parent_id(
    credentials: &[Credential],
    hashes: &[Hash],
    source: &str,
    username: &str,
    domain: &str,
    input_username: Option<&str>,
    input_domain: Option<&str>,
) -> (Option<String>, i32) {
    if source.starts_with("cracked") {
        if let Some(h) = hashes.iter().rev().find(|h| {
            h.username.eq_ignore_ascii_case(username)
                && (domain.is_empty() || h.domain.eq_ignore_ascii_case(domain))
        }) {
            return (Some(h.id.clone()), h.attack_step + 1);
        }
    }
    if let Some(in_user) = input_username.filter(|u| !u.is_empty()) {
        let in_domain = input_domain.unwrap_or("");
        let is_same = in_user.eq_ignore_ascii_case(username)
            && (in_domain.eq_ignore_ascii_case(domain)
                || in_domain.is_empty()
                || domain.is_empty());
        if !is_same {
            if let Some(c) = credentials.iter().rev().find(|c| {
                c.username.eq_ignore_ascii_case(in_user)
                    && (in_domain.is_empty()
                        || c.domain.is_empty()
                        || c.domain.eq_ignore_ascii_case(in_domain))
            }) {
                return (Some(c.id.clone()), c.attack_step + 1);
            }
            if let Some(h) = hashes.iter().rev().find(|h| {
                h.username.eq_ignore_ascii_case(in_user)
                    && (in_domain.is_empty()
                        || h.domain.is_empty()
                        || h.domain.eq_ignore_ascii_case(in_domain))
            }) {
                return (Some(h.id.clone()), h.attack_step + 1);
            }
        }
    }
    (None, 0)
}

pub(crate) fn parse_discoveries(payload: &Value) -> ParsedDiscoveries {
    let mut result = ParsedDiscoveries::default();

    if let Some(creds) = payload.get("credentials").and_then(|v| v.as_array()) {
        for cred_val in creds {
            if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
                result.credentials.push(cred);
            }
        }
    }
    if let Some(cred_val) = payload.get("credential") {
        if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
            result.credentials.push(cred);
        }
    }
    if let Some(cracked) = payload.get("cracked_password").and_then(|v| v.as_str()) {
        if let Some(username) = payload.get("username").and_then(|v| v.as_str()) {
            let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            result.credentials.push(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                password: cracked.to_string(),
                domain: domain.to_string(),
                source: "cracked".to_string(),
                discovered_at: Some(chrono::Utc::now()),
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            });
        }
    }
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Ok(hash) = serde_json::from_value::<Hash>(hash_val.clone()) {
                result.hashes.push(hash);
            }
        }
    }
    if let Some(hosts) = payload.get("hosts").and_then(|v| v.as_array()) {
        for host_val in hosts {
            if let Ok(host) = serde_json::from_value::<Host>(host_val.clone()) {
                result.hosts.push(host);
            }
        }
    }
    // Users -- defense-in-depth: only accept entries with a parser-verified source.
    const TRUSTED_USER_SOURCES: &[&str] = &["kerberos_enum", "netexec_user_enum"];
    if let Some(users) = payload.get("discovered_users").and_then(|v| v.as_array()) {
        for user_val in users {
            if let Ok(user) = serde_json::from_value::<User>(user_val.clone()) {
                if TRUSTED_USER_SOURCES.contains(&user.source.as_str()) {
                    result.users.push(user);
                }
            }
        }
    }
    if let Some(vulns) = payload.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln_val in vulns {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }
    if result.vulnerabilities.is_empty() {
        if let Some(vuln_val) = payload.get("vulnerability") {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }
    if let Some(shares) = payload.get("shares").and_then(|v| v.as_array()) {
        for share_val in shares {
            if let Ok(share) = serde_json::from_value::<Share>(share_val.clone()) {
                result.shares.push(share);
            }
        }
    }
    result
}

/// Check if a payload contains domain admin indicators. Pure function.
pub(crate) fn has_domain_admin_indicator(payload: &Value) -> bool {
    if payload.get("has_domain_admin").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Some(username) = hash_val.get("username").and_then(|v| v.as_str()) {
                if username.to_lowercase() == "krbtgt" {
                    return true;
                }
            }
        }
    }
    false
}
