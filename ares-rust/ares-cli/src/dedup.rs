use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use ares_core::models::{Credential, Hash, User};

pub(crate) fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        let key = (
            u.domain.trim().to_lowercase(),
            u.username.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(u.clone());
        }
    }
    result
}

/// Regex matching `Password` (case-insensitive) followed by optional `:` and space.
static PASSWORD_PREFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^password\s*:\s*").unwrap());

/// Regex matching trailing parenthetical metadata like ` (Guest)`, ` (Pwn3d!)`.
static TRAILING_PAREN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+\([^)]+\)\s*$").unwrap());

/// Sanitize credentials in-place: strip noise from passwords, normalize usernames
/// with embedded `@domain` suffixes, and remove garbage entries.
pub(crate) fn sanitize_credentials(creds: &mut Vec<Credential>) {
    for cred in creds.iter_mut() {
        // Strip "Password: " / "Password:" prefix from password values
        // e.g. "Password: hodor" → "hodor"
        if PASSWORD_PREFIX_RE.is_match(&cred.password) {
            cred.password = PASSWORD_PREFIX_RE.replace(&cred.password, "").to_string();
        }

        // Strip trailing parenthetical metadata from password
        // e.g. "svc_test (Guest)" → "svc_test"
        if TRAILING_PAREN_RE.is_match(&cred.password) {
            cred.password = TRAILING_PAREN_RE.replace(&cred.password, "").to_string();
        }

        // Normalize username with embedded @domain suffixes
        // e.g. "samwell.tarly@north.sevenkingdoms.local@essos.local"
        //   → username="samwell.tarly", domain="north.sevenkingdoms.local"
        if cred.username.contains('@') {
            let username_clone = cred.username.clone();
            let parts: Vec<&str> = username_clone.splitn(2, '@').collect();
            if parts.len() == 2 && !parts[0].is_empty() {
                let base_username = parts[0].to_string();
                // The first @domain part is the real domain; strip any further @domain suffixes
                let domain_part = parts[1].split('@').next().unwrap_or(parts[1]).to_string();
                if domain_part.contains('.') {
                    cred.username = base_username;
                    cred.domain = domain_part;
                }
            }
        }
    }

    // Remove credentials with empty or noise-only passwords
    creds.retain(|c| {
        let pw = c.password.trim();
        !pw.is_empty() && pw.to_lowercase() != "password"
    });
}

pub(crate) fn dedup_credentials(creds: &[Credential]) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for c in creds {
        // Skip credentials with empty passwords (hash-only entries)
        if c.password.is_empty() {
            continue;
        }
        let key = (
            c.domain.trim().to_lowercase(),
            c.username.trim().to_lowercase(),
            c.password.clone(),
        );
        if seen.insert(key) {
            result.push(c.clone());
        }
    }
    result
}

pub(crate) fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let key = (
            h.domain.trim().to_lowercase(),
            h.username.trim().to_lowercase(),
            h.hash_type.trim().to_lowercase(),
            h.hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(h.clone());
        }
    }
    result
}

pub(crate) fn extract_weakness_title(block: &str) -> &str {
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("### ") {
            return rest.trim();
        }
        if trimmed.starts_with("**") && trimmed.ends_with("**") && !trimmed.contains(":**") {
            let inner = trimmed.trim_matches('*').trim();
            if !inner.is_empty() {
                return inner;
            }
        }
    }
    let first = block.lines().next().unwrap_or("Untitled Weakness");
    if first.len() > 60 {
        &first[..60]
    } else {
        first
    }
}

// ---------------------------------------------------------------------------
// Source label normalization (matches Python _normalize_source_label)
// ---------------------------------------------------------------------------

static TASK_INPUT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\((\w+)_[a-f0-9]+\)").unwrap());

static TASK_SUFFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\w+)_[a-f0-9]{8,}$").unwrap());

static LABEL_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
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

// ---------------------------------------------------------------------------
// Weakness noise filtering (matches Python _filter_real_weaknesses)
// ---------------------------------------------------------------------------

const WEAKNESS_NOISE_PREFIXES: &[&str] = &[
    "next step:",
    "next action:",
    "next task",
    "task suggestion:",
    "recommendation:",
    "todo:",
    "to do:",
    "action item:",
];

static WEAKNESS_FIELD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\*\*([^*:]+):\*\*\s*(.*)$").unwrap());

/// Parsed weakness fields for display.
pub(crate) struct ParsedWeaknessDisplay {
    pub title: String,
    pub vulnerability: String,
    pub affected_resource: String,
    pub impact: String,
}

pub(crate) fn parse_weakness_block_display(block: &str) -> ParsedWeaknessDisplay {
    let mut result = ParsedWeaknessDisplay {
        title: String::new(),
        vulnerability: String::new(),
        affected_resource: String::new(),
        impact: String::new(),
    };
    if block.is_empty() {
        return result;
    }

    for raw_line in block.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() {
            continue;
        }

        if let Some(rest) = stripped.strip_prefix("### ") {
            result.title = rest.trim().to_string();
        } else if stripped.starts_with("**")
            && !stripped.contains(":**")
            && stripped.ends_with("**")
        {
            result.title = stripped.trim_matches('*').trim().to_string();
        } else if stripped.contains(":**") {
            let clean = stripped.trim_start_matches('-').trim();
            if let Some(caps) = WEAKNESS_FIELD_RE.captures(clean) {
                let key = caps[1].trim().to_lowercase().replace(' ', "_");
                let value = caps[2].trim().to_string();
                match key.as_str() {
                    "vulnerability" => result.vulnerability = value,
                    "affected_resource" => result.affected_resource = value,
                    "impact" => result.impact = value,
                    "title" => result.title = value,
                    _ => {}
                }
            }
        }
    }

    if result.title.is_empty() {
        result.title = extract_weakness_title(block).to_string();
    }

    result
}

/// Filter out agent task suggestions incorrectly recorded as weaknesses.
/// Returns (raw_block, parsed) tuples for real weaknesses only.
pub(crate) fn filter_real_weaknesses(weaknesses: &[String]) -> Vec<(&str, ParsedWeaknessDisplay)> {
    let mut result = Vec::new();
    for w in weaknesses {
        let parsed = parse_weakness_block_display(w);
        let title_lower = parsed.title.trim().to_lowercase();
        let is_noise = WEAKNESS_NOISE_PREFIXES
            .iter()
            .any(|prefix| title_lower.starts_with(prefix));
        if !is_noise {
            result.push((w.as_str(), parsed));
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Domain normalization (matches Python normalize_*_domains_to_users / cleanup_invalid_domains)
// ---------------------------------------------------------------------------

const WELL_KNOWN_ACCOUNTS: &[&str] = &["krbtgt", "administrator", "guest", "defaultaccount"];

pub(crate) fn normalize_state_domains(
    users: &[User],
    credentials: &mut Vec<Credential>,
    hashes: &mut Vec<Hash>,
    domains: &mut Vec<String>,
    hosts: &[ares_core::models::Host],
    target_domain: Option<&str>,
) {
    // Build user domain lookup: username -> set of domains
    let mut user_domains: HashMap<String, HashSet<String>> = HashMap::new();
    for user in users {
        let username_lower = user.username.to_lowercase();
        if !user.domain.is_empty() {
            user_domains
                .entry(username_lower)
                .or_default()
                .insert(user.domain.to_lowercase());
        }
    }

    // --- Normalize credential domains ---
    {
        // Group credentials by username:password
        let mut cred_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, cred) in credentials.iter().enumerate() {
            let key = format!("{}:{}", cred.username.to_lowercase(), cred.password);
            cred_groups.entry(key).or_default().push(i);
        }

        let mut keep = vec![false; credentials.len()];
        for indices in cred_groups.values() {
            let username_lower = credentials[indices[0]].username.to_lowercase();

            // Never normalize well-known accounts across domains
            if WELL_KNOWN_ACCOUNTS.contains(&username_lower.as_str()) {
                for &i in indices {
                    keep[i] = true;
                }
                continue;
            }

            let domains_for_user = user_domains.get(&username_lower);

            if indices.len() == 1 {
                let i = indices[0];
                keep[i] = true;
                // Correct domain if user exists in exactly one domain
                if let Some(ds) = domains_for_user {
                    if ds.len() == 1 {
                        let correct = ds.iter().next().unwrap().clone();
                        if credentials[i].domain.to_lowercase() != correct {
                            credentials[i].domain = correct;
                        }
                    }
                }
            } else {
                match domains_for_user {
                    None => {
                        // Keep most specific (longest domain)
                        let best = *indices
                            .iter()
                            .max_by_key(|&&i| credentials[i].domain.len())
                            .unwrap();
                        keep[best] = true;
                    }
                    Some(ds) if ds.len() == 1 => {
                        let correct = ds.iter().next().unwrap();
                        // Keep only matching credential, or correct the best one
                        let matching = indices
                            .iter()
                            .find(|&&i| credentials[i].domain.to_lowercase() == *correct);
                        if let Some(&i) = matching {
                            keep[i] = true;
                        } else {
                            let best = *indices
                                .iter()
                                .max_by_key(|&&i| credentials[i].domain.len())
                                .unwrap();
                            credentials[best].domain = correct.clone();
                            keep[best] = true;
                        }
                    }
                    Some(ds) => {
                        // Keep only creds whose domain matches a known user domain
                        for &i in indices {
                            if ds.contains(&credentials[i].domain.to_lowercase()) {
                                keep[i] = true;
                            }
                        }
                    }
                }
            }
        }

        let mut j = 0;
        credentials.retain(|_| {
            let k = keep[j];
            j += 1;
            k
        });
    }

    // --- Normalize hash domains ---
    {
        // Build known valid domains from authoritative sources
        let mut known_domains: HashSet<String> = HashSet::new();
        for ds in user_domains.values() {
            known_domains.extend(ds.iter().cloned());
        }
        for host in hosts {
            if !host.hostname.is_empty() && host.hostname.contains('.') {
                let lower = host.hostname.to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                if parts.len() > 1 {
                    known_domains.insert(parts[1..].join("."));
                }
            }
        }
        if let Some(td) = target_domain {
            known_domains.insert(td.to_lowercase());
        }

        let mut seen: HashSet<String> = HashSet::new();
        let mut keep = vec![false; hashes.len()];

        for (i, h) in hashes.iter_mut().enumerate() {
            let username_lower = h.username.to_lowercase();
            let hash_domain = h.domain.to_lowercase();

            if WELL_KNOWN_ACCOUNTS.contains(&username_lower.as_str()) {
                let dedup_key = format!("{}:{}:{}", hash_domain, username_lower, h.hash_value);
                if seen.insert(dedup_key) {
                    keep[i] = true;
                }
                continue;
            }

            let domains_for_user = user_domains.get(&username_lower);
            if !known_domains.contains(&hash_domain) {
                if let Some(ds) = domains_for_user {
                    if ds.len() == 1 {
                        h.domain = ds.iter().next().unwrap().clone();
                    }
                }
            }

            let dedup_key = format!(
                "{}:{}:{}",
                h.domain.to_lowercase(),
                username_lower,
                h.hash_value
            );
            if seen.insert(dedup_key) {
                keep[i] = true;
            }
        }

        let mut j = 0;
        hashes.retain(|_| {
            let k = keep[j];
            j += 1;
            k
        });
    }

    // --- Cleanup invalid domains ---
    {
        let mut valid_domains: HashSet<String> = HashSet::new();
        if let Some(td) = target_domain {
            valid_domains.insert(td.to_lowercase());
        }
        for host in hosts {
            if !host.hostname.is_empty() && host.hostname.contains('.') {
                let lower = host.hostname.to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                if parts.len() > 1 {
                    valid_domains.insert(parts[1..].join("."));
                }
            }
        }
        for user in users {
            if !user.domain.is_empty() {
                valid_domains.insert(user.domain.to_lowercase());
            }
        }

        domains.retain(|d| valid_domains.contains(&d.to_lowercase()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(domain: &str, username: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        }
    }

    fn make_cred(domain: &str, username: &str, password: &str) -> Credential {
        Credential {
            id: String::new(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_hash(domain: &str, username: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: String::new(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }
    }

    #[test]
    fn test_dedup_users_basic() {
        let users = vec![
            make_user("contoso.local", "admin"),
            make_user("contoso.local", "admin"), // dup
            make_user("contoso.local", "jdoe"),
        ];
        let deduped = dedup_users(&users);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_users_case_insensitive() {
        let users = vec![
            make_user("CONTOSO.LOCAL", "Admin"),
            make_user("contoso.local", "admin"),
        ];
        let deduped = dedup_users(&users);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_users_different_domains() {
        let users = vec![
            make_user("contoso.local", "admin"),
            make_user("fabrikam.local", "admin"),
        ];
        let deduped = dedup_users(&users);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_credentials_basic() {
        let creds = vec![
            make_cred("contoso.local", "admin", "P@ss1"),
            make_cred("contoso.local", "admin", "P@ss1"), // dup
            make_cred("contoso.local", "admin", "P@ss2"), // different password
        ];
        let deduped = dedup_credentials(&creds);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_credentials_case_insensitive_username() {
        let creds = vec![
            make_cred("contoso.local", "Admin", "P@ss1"),
            make_cred("CONTOSO.LOCAL", "admin", "P@ss1"),
        ];
        let deduped = dedup_credentials(&creds);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_hashes_basic() {
        let hashes = vec![
            make_hash("contoso.local", "admin", "ntlm", "aabbccdd"),
            make_hash("contoso.local", "admin", "ntlm", "aabbccdd"), // dup
            make_hash("contoso.local", "admin", "aes256", "eeff0011"), // different type
        ];
        let deduped = dedup_hashes(&hashes);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_hashes_case_insensitive() {
        let hashes = vec![
            make_hash("contoso.local", "Admin", "NTLM", "AABBCCDD"),
            make_hash("CONTOSO.LOCAL", "admin", "ntlm", "aabbccdd"),
        ];
        let deduped = dedup_hashes(&hashes);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_extract_weakness_title_h3() {
        let block = "### SMB Signing Disabled\nSome details...";
        assert_eq!(extract_weakness_title(block), "SMB Signing Disabled");
    }

    #[test]
    fn test_extract_weakness_title_bold() {
        let block = "**Kerberoastable Account**\nDetails...";
        assert_eq!(extract_weakness_title(block), "Kerberoastable Account");
    }

    #[test]
    fn test_extract_weakness_title_fallback_first_line() {
        let block = "Some weakness description\nMore details";
        assert_eq!(extract_weakness_title(block), "Some weakness description");
    }

    #[test]
    fn test_extract_weakness_title_long_fallback_truncated() {
        let block = "A".repeat(100);
        assert_eq!(extract_weakness_title(&block).len(), 60);
    }

    #[test]
    fn test_extract_weakness_title_empty() {
        assert_eq!(extract_weakness_title(""), "Untitled Weakness");
    }

    // --- normalize_source_label tests ---

    #[test]
    fn test_normalize_source_label_empty() {
        assert_eq!(normalize_source_label(""), "Unknown");
    }

    #[test]
    fn test_normalize_source_label_exact_match() {
        assert_eq!(normalize_source_label("recon"), "Reconnaissance");
        assert_eq!(normalize_source_label("privesc"), "Privilege Escalation");
        assert_eq!(normalize_source_label("bloodhound"), "BloodHound");
        assert_eq!(normalize_source_label("secretsdump"), "Secretsdump");
    }

    #[test]
    fn test_normalize_source_label_case_insensitive() {
        assert_eq!(normalize_source_label("RECON"), "Reconnaissance");
        assert_eq!(normalize_source_label("BloodHound"), "BloodHound");
    }

    #[test]
    fn test_normalize_source_label_dedup_colon() {
        assert_eq!(normalize_source_label("recon:recon"), "Reconnaissance");
    }

    #[test]
    fn test_normalize_source_label_prefix_match() {
        assert_eq!(
            normalize_source_label("privesc_enumeration"),
            "Privesc Enumeration"
        );
        assert_eq!(
            normalize_source_label("credential_access_foo"),
            "Credential Access"
        );
    }

    #[test]
    fn test_normalize_source_label_task_suffix() {
        assert_eq!(
            normalize_source_label("recon_abc12345678"),
            "Reconnaissance"
        );
    }

    #[test]
    fn test_normalize_source_label_fallback() {
        assert_eq!(
            normalize_source_label("some_custom_source"),
            "Some Custom Source"
        );
    }

    // --- filter_real_weaknesses tests ---

    #[test]
    fn test_filter_real_weaknesses_removes_noise() {
        let weaknesses = vec![
            "### SMB Signing Disabled\n**Vulnerability:** Not required".to_string(),
            "### Next step: do something".to_string(),
            "### Task suggestion: try this".to_string(),
            "### Kerberoast\n**Vulnerability:** Weak SPN".to_string(),
        ];
        let filtered = filter_real_weaknesses(&weaknesses);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].1.title, "SMB Signing Disabled");
        assert_eq!(filtered[1].1.title, "Kerberoast");
    }

    #[test]
    fn test_filter_real_weaknesses_keeps_all_real() {
        let weaknesses = vec!["### Constrained Delegation\n**Impact:** High".to_string()];
        let filtered = filter_real_weaknesses(&weaknesses);
        assert_eq!(filtered.len(), 1);
    }

    // --- parse_weakness_block_display tests ---

    #[test]
    fn test_parse_weakness_block_display_full() {
        let block = "\
### ADCS ESC1
- **Vulnerability:** Certificate template misconfiguration
- **Affected Resource:** contoso-DC01-CA
- **Impact:** Domain admin escalation";
        let parsed = parse_weakness_block_display(block);
        assert_eq!(parsed.title, "ADCS ESC1");
        assert_eq!(
            parsed.vulnerability,
            "Certificate template misconfiguration"
        );
        assert_eq!(parsed.affected_resource, "contoso-DC01-CA");
        assert_eq!(parsed.impact, "Domain admin escalation");
    }

    #[test]
    fn test_parse_weakness_block_display_empty() {
        let parsed = parse_weakness_block_display("");
        assert_eq!(parsed.title, "");
    }

    #[test]
    fn test_parse_weakness_block_display_no_title() {
        let parsed = parse_weakness_block_display("just some text without a title marker");
        // Falls back to extract_weakness_title which uses first line
        assert_eq!(parsed.title, "just some text without a title marker");
    }

    // --- normalize_state_domains tests ---

    #[test]
    fn test_normalize_state_domains_corrects_cred_domain() {
        let users = vec![make_user("contoso.local", "admin")];
        let mut creds = vec![make_cred("WRONG.local", "admin", "P@ss1")];
        let mut hashes = vec![];
        let mut domains = vec!["contoso.local".to_string(), "WRONG.local".to_string()];
        let hosts = vec![];

        normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].domain, "contoso.local");
        // WRONG.local should be cleaned up since no users/hosts reference it
        assert!(!domains.iter().any(|d| d.to_lowercase() == "wrong.local"));
    }

    #[test]
    fn test_normalize_state_domains_dedupes_cross_domain_creds() {
        let users = vec![make_user("contoso.local", "admin")];
        let mut creds = vec![
            make_cred("contoso.local", "admin", "P@ss1"),
            make_cred("child.contoso.local", "admin", "P@ss1"),
        ];
        let mut hashes = vec![];
        let mut domains = vec!["contoso.local".to_string()];
        let hosts = vec![];

        normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].domain, "contoso.local");
    }

    #[test]
    fn test_normalize_state_domains_preserves_well_known() {
        let users = vec![
            make_user("contoso.local", "administrator"),
            make_user("child.contoso.local", "administrator"),
        ];
        let mut creds = vec![
            make_cred("contoso.local", "administrator", "P@ss1"),
            make_cred("child.contoso.local", "administrator", "P@ss2"),
        ];
        let mut hashes = vec![];
        let mut domains = vec![
            "contoso.local".to_string(),
            "child.contoso.local".to_string(),
        ];
        let hosts = vec![];

        normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

        // Well-known accounts should all be preserved
        assert_eq!(creds.len(), 2);
    }

    // --- sanitize_credentials tests ---

    #[test]
    fn test_sanitize_strips_password_prefix() {
        let mut creds = vec![
            make_cred("contoso.local", "hodor", "Password: hodor"),
            make_cred("contoso.local", "admin", "password:secret"),
            make_cred("contoso.local", "user1", "PASSWORD: MyPass123"),
        ];
        sanitize_credentials(&mut creds);
        assert_eq!(creds[0].password, "hodor");
        assert_eq!(creds[1].password, "secret");
        assert_eq!(creds[2].password, "MyPass123");
    }

    #[test]
    fn test_sanitize_removes_password_only() {
        let mut creds = vec![
            make_cred("contoso.local", "hodor", "Password"),
            make_cred("contoso.local", "admin", "password"),
            make_cred("contoso.local", "user1", "RealPassword"),
        ];
        sanitize_credentials(&mut creds);
        // "Password" and "password" should be removed, "RealPassword" kept
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "user1");
        assert_eq!(creds[0].password, "RealPassword");
    }

    #[test]
    fn test_sanitize_strips_trailing_paren_metadata() {
        let mut creds = vec![
            make_cred("contoso.local", "svc_test", "svc_test (Guest)"),
            make_cred("contoso.local", "admin", "P@ss1 (Pwn3d!)"),
        ];
        sanitize_credentials(&mut creds);
        assert_eq!(creds[0].password, "svc_test");
        assert_eq!(creds[1].password, "P@ss1");
    }

    #[test]
    fn test_sanitize_normalizes_username_with_at_domain() {
        let mut creds = vec![
            make_cred(
                "essos.local",
                "samwell.tarly@north.sevenkingdoms.local@essos.local",
                "Heartsbane",
            ),
            make_cred(
                "essos.local",
                "samwell.tarly@north.sevenkingdoms.local",
                "Heartsbane",
            ),
        ];
        sanitize_credentials(&mut creds);
        // Both should resolve to username=samwell.tarly, domain=north.sevenkingdoms.local
        assert_eq!(creds[0].username, "samwell.tarly");
        assert_eq!(creds[0].domain, "north.sevenkingdoms.local");
        assert_eq!(creds[1].username, "samwell.tarly");
        assert_eq!(creds[1].domain, "north.sevenkingdoms.local");
    }

    #[test]
    fn test_sanitize_preserves_clean_credentials() {
        let mut creds = vec![
            make_cred("contoso.local", "admin", "P@ss1"),
            make_cred("contoso.local", "user1", "Secret123!"),
        ];
        let orig_len = creds.len();
        sanitize_credentials(&mut creds);
        assert_eq!(creds.len(), orig_len);
        assert_eq!(creds[0].password, "P@ss1");
        assert_eq!(creds[1].password, "Secret123!");
    }

    #[test]
    fn test_sanitize_removes_empty_password_after_strip() {
        let mut creds = vec![
            make_cred("contoso.local", "hodor", "Password: "),
            make_cred("contoso.local", "admin", ""),
        ];
        sanitize_credentials(&mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn test_sanitize_then_dedup_collapses_variants() {
        // Simulates the real scenario: hodor appears with multiple dirty variants
        let mut creds = vec![
            make_cred("contoso.local", "hodor", "hodor"),
            make_cred("contoso.local", "hodor", "Password: hodor"),
            make_cred("contoso.local", "hodor", "Password"),
        ];
        sanitize_credentials(&mut creds);
        let deduped = dedup_credentials(&creds);
        // "Password" removed, "Password: hodor" → "hodor" deduped with existing "hodor"
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].password, "hodor");
    }
}
