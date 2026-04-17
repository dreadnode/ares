use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::{Credential, Hash};

use super::{is_valid_credential, make_credential};

static RE_TGS_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+)").unwrap()
});

static RE_ASREP_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+)").unwrap());

// domain\user:rid:lmhash:nthash:::
static RE_NTLM_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([^\\:\s]+)\\([^:\\]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

// user:rid:lmhash:nthash:::
static RE_NTLM_PLAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:\\$\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

// Partial NTLM line (line-wrapped secretsdump)
static RE_NTLM_PARTIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^:\s]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]+$").unwrap());

static RE_NTLM_CONTINUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]+:::$").unwrap());

pub fn extract_hashes(output: &str, default_domain: &str) -> Vec<Hash> {
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

/// Hashcat cracked TGS: $krb5tgs$23$*user$DOMAIN$spn*$hash:plaintext
static RE_CRACKED_TGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^*]+\*\$[a-fA-F0-9$]+:(.+)$").unwrap()
});

/// Cracked AS-REP: $krb5asrep$23$user@DOMAIN:hash:plaintext (hashcat)
/// or $krb5asrep$23$user@DOMAIN:plaintext (john --show, no hex section)
static RE_CRACKED_ASREP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):(?:[a-fA-F0-9$]+:)?(.+)$").unwrap()
});

/// John --show output: user:plaintext (with optional trailing :::... fields)
/// Only matches lines that look like john --show format — username followed by
/// password, then optional RID and empty LM/NT fields.
static RE_JOHN_SHOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:\s$][^:]*):([^:]+):\d*:(?:[a-fA-F0-9]*:){0,3}:*\s*$").unwrap()
});

/// John --show unknown user: ?:plaintext (john can't determine username from TGS hashes)
static RE_JOHN_UNKNOWN_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\?:(.+)$").unwrap());

/// Extract username/domain from a TGS hash in the output text.
static RE_TGS_HASH_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)").unwrap());

pub fn extract_cracked_passwords(output: &str, default_domain: &str) -> Vec<Credential> {
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Detect john --show context (john outputs "N password hash cracked")
    let is_john_output =
        output.contains("password hash cracked") || output.contains("password hashes cracked");

    for line in output.lines() {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }

        // Hashcat cracked TGS (Kerberoast)
        if let Some(caps) = RE_CRACKED_TGS.captures(stripped) {
            let username = caps.get(1).unwrap().as_str();
            let domain = caps.get(2).unwrap().as_str();
            let password = caps.get(3).unwrap().as_str();
            if is_valid_credential(username, password) {
                let key = format!(
                    "cracked:{}@{}",
                    username.to_lowercase(),
                    domain.to_lowercase()
                );
                if seen.insert(key) {
                    credentials.push(make_credential(
                        username,
                        password,
                        domain,
                        "cracked:hashcat",
                    ));
                }
            }
            continue;
        }

        // Hashcat cracked AS-REP
        if let Some(caps) = RE_CRACKED_ASREP.captures(stripped) {
            let username = caps.get(1).unwrap().as_str();
            let domain = caps.get(2).unwrap().as_str();
            let password = caps.get(3).unwrap().as_str();
            if is_valid_credential(username, password) {
                let key = format!(
                    "cracked:{}@{}",
                    username.to_lowercase(),
                    domain.to_lowercase()
                );
                if seen.insert(key) {
                    credentials.push(make_credential(
                        username,
                        password,
                        domain,
                        "cracked:hashcat",
                    ));
                }
            }
            continue;
        }

        // John --show output (only if we detected john context)
        if is_john_output {
            // John --show unknown user: ?:password (TGS hashes)
            // Try to extract username from a $krb5tgs$ line in the same output.
            if let Some(caps) = RE_JOHN_UNKNOWN_USER.captures(stripped) {
                let password = caps.get(1).unwrap().as_str().trim();
                if is_valid_credential("?", password) {
                    // Scan output for a TGS hash line to get username/domain
                    if let Some(tgs_caps) = RE_TGS_HASH_USER.captures(output) {
                        let username = tgs_caps.get(1).unwrap().as_str();
                        let domain = tgs_caps.get(2).unwrap().as_str();
                        let key = format!(
                            "cracked:{}@{}",
                            username.to_lowercase(),
                            domain.to_lowercase()
                        );
                        if seen.insert(key) {
                            credentials.push(make_credential(
                                username,
                                password,
                                domain,
                                "cracked:john",
                            ));
                        }
                    }
                }
                continue;
            }

            if let Some(caps) = RE_JOHN_SHOW.captures(stripped) {
                let username = caps.get(1).unwrap().as_str();
                let password = caps.get(2).unwrap().as_str();
                // Skip john summary lines
                if username.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                if is_valid_credential(username, password) {
                    let key = format!(
                        "cracked:{}@{}",
                        username.to_lowercase(),
                        default_domain.to_lowercase()
                    );
                    if seen.insert(key) {
                        credentials.push(make_credential(
                            username,
                            password,
                            default_domain,
                            "cracked:john",
                        ));
                    }
                }
            }
        }
    }

    credentials
}
