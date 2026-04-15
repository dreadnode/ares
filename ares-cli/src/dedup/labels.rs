use std::collections::HashMap;

use regex::Regex;
use std::sync::LazyLock;

pub(super) static TASK_INPUT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\((\w+)_[a-f0-9]+\)").unwrap());

pub(super) static TASK_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\w+)_[a-f0-9]{8,}$").unwrap());

pub(super) static LABEL_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    // Task types
    m.insert("exploit", "Exploitation");
    m.insert("recon", "Reconnaissance");
    m.insert("lateral", "Lateral Movement");
    m.insert("privesc", "Privilege Escalation");
    m.insert("privesc_enumeration", "Privesc Enumeration");
    m.insert("credential_access", "Credential Access");
    m.insert("acl_analysis", "ACL Analysis");
    m.insert("crack", "Password Cracking");
    // Tool-based sources
    m.insert("netexec_user_enum", "NetExec User Enum");
    m.insert("netexec_smb", "NetExec SMB");
    m.insert("bloodhound", "BloodHound");
    m.insert("kerberoast", "Kerberoasting");
    m.insert("asreproast", "AS-REP Roasting");
    m.insert("secretsdump", "Secretsdump");
    m.insert("lsassy", "LSASSY");
    m.insert("share_spider", "Share Spider");
    m.insert("gpp_password", "GPP Passwords");
    m.insert("ldap_search", "LDAP Search");
    m.insert("kerberos_noauth", "Kerberos Enum");
    m.insert("user_description", "LDAP Description");
    m.insert("manual-inject", "Manual Injection");
    // Generic fallbacks
    m.insert("worker", "Agent Discovery");
    m.insert("task", "Task Output");
    m.insert("unknown", "Unknown");
    m
});

pub(crate) fn normalize_source_label(source: &str) -> String {
    if source.is_empty() {
        return "Unknown".to_string();
    }

    let mut source = source.to_string();

    // Deduplicate "recon:recon" -> "recon"
    if source.contains(':') {
        let parts: Vec<&str> = source.split(':').collect();
        if parts.len() >= 2 && parts[0] == parts[1] {
            source = parts[0].to_string();
        }
    }

    // Extract task type from "task input (recon_abc123)" patterns
    let lower = source.to_lowercase();
    if lower.contains("task input") {
        if let Some(caps) = TASK_INPUT_RE.captures(&source) {
            source = caps[1].to_string();
        }
    }

    let lower = source.to_lowercase();

    // Exact match
    if let Some(label) = LABEL_MAP.get(lower.as_str()) {
        return label.to_string();
    }

    // Prefix match
    for (key, label) in LABEL_MAP.iter() {
        if lower.starts_with(key) {
            return label.to_string();
        }
    }

    // Task ID suffix match (e.g., "recon_abc12345" -> "recon")
    if let Some(caps) = TASK_SUFFIX_RE.captures(&lower) {
        let task_type = &caps[1];
        if let Some(label) = LABEL_MAP.get(task_type) {
            return label.to_string();
        }
    }

    // Fallback: replace underscores and title-case
    source
        .replace('_', " ")
        .split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
