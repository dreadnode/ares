use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use ares_core::models::{Credential, Hash, User};

/// Strip trailing DNS root dot from domain strings (e.g. `north.sevenkingdoms.local.` → `north.sevenkingdoms.local`).
fn strip_trailing_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// Noise usernames that should be filtered.
const NOISE_USERNAMES: &[&str] = &[
    "none",
    "null",
    "(none)",
    "(null)",
    "anonymous",
    "unknown",
    "n/a",
    "default",
    "test",
    "local",
    "localhost",
    "domain",
    "workgroup",
    // Built-in / service accounts — not useful attack targets
    "guest",
    "defaultaccount",
    "krbtgt",
    "ssm-user",
    "ansible",
];

/// Prefixes for machine-local service accounts that should be filtered.
/// e.g. SQLServer2005SQLBrowserUser$BRAAVOS
const NOISE_USERNAME_PREFIXES: &[&str] = &["sqlserver", "mssql", "healthmailbox"];

/// Resolve a NetBIOS domain name to FQDN using the netbios_to_fqdn map.
fn resolve_netbios_domain(domain: &str, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let lower = domain.to_lowercase();
    // Already an FQDN (contains dots)
    if lower.contains('.') {
        return strip_trailing_dot(&lower).to_string();
    }
    // Try direct lookup — netbios_to_fqdn keys are UPPERCASE (from publish_netbios)
    let upper = domain.to_uppercase();
    if let Some(fqdn) = netbios_to_fqdn.get(&upper) {
        return fqdn.to_lowercase();
    }
    // Try matching as prefix of known FQDNs
    for (nb, fqdn) in netbios_to_fqdn {
        if nb.to_lowercase() == lower {
            return fqdn.to_lowercase();
        }
    }
    // Return as-is lowercased
    lower
}

/// Sources that produce verified users (KDC-confirmed or enumerated).
/// `output_extraction` is excluded — its DOMAIN\user regex matches every
/// wordlist entry in kerbrute/ASREProast output, not just confirmed users.
const TRUSTED_USER_SOURCES: &[&str] = &["kerberos_enum", "netexec_user_enum"];

pub(crate) fn dedup_users(users: &[User], netbios_to_fqdn: &HashMap<String, String>) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        let raw_domain = strip_trailing_dot(u.domain.trim());
        let domain = resolve_netbios_domain(raw_domain, netbios_to_fqdn).to_lowercase();
        let username = u.username.trim().to_lowercase();

        // Only accept users from trusted parser sources
        if !u.source.is_empty() && !TRUSTED_USER_SOURCES.contains(&u.source.as_str()) {
            continue;
        }

        // Filter garbage entries
        if username.is_empty()
            || username.len() <= 1
            || username.contains('/')
            || username.starts_with('_')  // DNS service prefixes (_udp, _tcp, _msdcs)
            || username.bytes().any(|b| b < 0x20)  // control characters
            || !username.bytes().all(|b| b.is_ascii_graphic())  // non-printable
            || NOISE_USERNAMES.contains(&username.as_str())
            || NOISE_USERNAME_PREFIXES.iter().any(|p| username.starts_with(p))
        {
            continue;
        }
        // Filter domains that look like DNS artifacts
        if domain.starts_with('_') || domain.is_empty() {
            continue;
        }

        let key = (domain.clone(), username);
        if seen.insert(key) {
            let mut cleaned = u.clone();
            cleaned.domain =
                resolve_netbios_domain(strip_trailing_dot(cleaned.domain.trim()), netbios_to_fqdn)
                    .to_lowercase();
            result.push(cleaned);
        }
    }
    result
}

/// Strip ANSI escape sequences from text.
static RE_ANSI: Lazy<Regex> = Lazy::new(|| Regex::new(r"\x1b\[[0-9;]*m").unwrap());

fn strip_ansi(s: &str) -> String {
    RE_ANSI.replace_all(s, "").to_string()
}

/// Regex matching `Password` (case-insensitive) followed by optional `:` and space.
static PASSWORD_PREFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^password\s*:\s*").unwrap());

/// Regex matching trailing parenthetical metadata like ` (Guest)`, ` (Pwn3d!)`.
static TRAILING_PAREN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+\([^)]+\)\s*$").unwrap());

/// Sanitize credentials in-place: strip noise from passwords, normalize usernames
/// with embedded `@domain` suffixes, and remove garbage entries.
pub(crate) fn sanitize_credentials(creds: &mut Vec<Credential>) {
    for cred in creds.iter_mut() {
        // Strip ANSI escape codes from all fields
        cred.username = strip_ansi(&cred.username);
        cred.password = strip_ansi(&cred.password);
        cred.domain = strip_ansi(&cred.domain);

        // Strip trailing dots from domains
        cred.domain = strip_trailing_dot(cred.domain.trim()).to_string();

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
                    cred.domain = strip_trailing_dot(&domain_part).to_string();
                }
            }
        }
    }

    // Remove credentials with empty or noise-only passwords
    creds.retain(|c| {
        let pw = c.password.trim();
        let username = c.username.trim().to_lowercase();
        if pw.is_empty() || pw.to_lowercase() == "password" {
            return false;
        }
        // Filter "Discovered" as password (not a real credential)
        if pw.eq_ignore_ascii_case("discovered") {
            return false;
        }
        // Filter hash markers misclassified as credentials (NetExec LSA dump)
        if pw.contains("[NT]") || pw.contains("[SHA1]") {
            return false;
        }
        // Filter usernames containing path separators (file path artifacts)
        if username.contains('/') || username.contains('\\') {
            return false;
        }
        // Filter credentials where password matches username (case-insensitive)
        if pw.to_lowercase() == username {
            return false;
        }
        // Filter EVIL\d+$ impacket RBCD artifacts
        if username.starts_with("evil") && username.ends_with('$') {
            return false;
        }
        true
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
            let mut normalized = c.clone();
            normalized.domain = c.domain.trim().to_lowercase();
            normalized.username = c.username.trim().to_lowercase();
            result.push(normalized);
        }
    }
    result
}

/// Normalize hash type for display: `ntlm` → `NTLM`, `kerberoast` → `Kerberoast`, `asrep` → `AS-REP`.
fn normalize_hash_type(hash_type: &str) -> String {
    match hash_type.trim().to_lowercase().as_str() {
        "ntlm" => "NTLM".to_string(),
        "kerberoast" => "Kerberoast".to_string(),
        "asrep" | "as-rep" | "asreproast" => "AS-REP".to_string(),
        "aes256" | "aes-256" => "AES256".to_string(),
        "aes128" | "aes-128" => "AES128".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let domain = strip_trailing_dot(h.domain.trim()).to_lowercase();
        let hash_value = strip_ansi(&h.hash_value);
        let key = (
            domain.clone(),
            h.username.trim().to_lowercase(),
            h.hash_type.trim().to_lowercase(),
            hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            let mut cleaned = h.clone();
            cleaned.domain = strip_trailing_dot(cleaned.domain.trim()).to_lowercase();
            cleaned.hash_type = normalize_hash_type(&cleaned.hash_type);
            cleaned.hash_value = hash_value.trim().to_string();
            cleaned.username = strip_ansi(&cleaned.username);
            result.push(cleaned);
        }
    }
    result
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
    // Normalize all domain strings: strip trailing dots
    for d in domains.iter_mut() {
        *d = strip_trailing_dot(d.trim()).to_string();
    }
    for cred in credentials.iter_mut() {
        cred.domain = strip_trailing_dot(cred.domain.trim()).to_string();
    }
    for h in hashes.iter_mut() {
        h.domain = strip_trailing_dot(h.domain.trim()).to_string();
    }

    // Build user domain lookup: username -> set of domains
    let mut user_domains: HashMap<String, HashSet<String>> = HashMap::new();
    for user in users {
        let username_lower = user.username.to_lowercase();
        let domain = strip_trailing_dot(user.domain.trim()).to_lowercase();
        if !domain.is_empty() {
            user_domains
                .entry(username_lower)
                .or_default()
                .insert(domain);
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
        let nb = HashMap::new();
        let users = vec![
            make_user("contoso.local", "admin"),
            make_user("contoso.local", "admin"), // dup
            make_user("contoso.local", "jdoe"),
        ];
        let deduped = dedup_users(&users, &nb);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_users_case_insensitive() {
        let nb = HashMap::new();
        let users = vec![
            make_user("CONTOSO.LOCAL", "Admin"),
            make_user("contoso.local", "admin"),
        ];
        let deduped = dedup_users(&users, &nb);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_users_different_domains() {
        let nb = HashMap::new();
        let users = vec![
            make_user("contoso.local", "admin"),
            make_user("fabrikam.local", "admin"),
        ];
        let deduped = dedup_users(&users, &nb);
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
        // "Password: hodor" → "hodor" → filtered (password == username)
        // "password:secret" → "secret" → kept
        // "PASSWORD: MyPass123" → "MyPass123" → kept
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].password, "secret");
        assert_eq!(creds[1].password, "MyPass123");
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
        // "svc_test (Guest)" → "svc_test" → filtered (password == username)
        // "P@ss1 (Pwn3d!)" → "P@ss1" → kept
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "P@ss1");
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
        // All variants resolve to password == username, so all get filtered
        let mut creds = vec![
            make_cred("contoso.local", "hodor", "hodor"),
            make_cred("contoso.local", "hodor", "Password: hodor"),
            make_cred("contoso.local", "hodor", "Password"),
        ];
        sanitize_credentials(&mut creds);
        let deduped = dedup_credentials(&creds);
        assert_eq!(deduped.len(), 0);
    }

    #[test]
    fn test_sanitize_filters_password_equals_username() {
        let mut creds = vec![
            make_cred("contoso.local", "admin", "admin"),
            make_cred("contoso.local", "user1", "DifferentPass"),
            make_cred("contoso.local", "jdoe", "Discovered"),
        ];
        sanitize_credentials(&mut creds);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "user1");
    }
}
