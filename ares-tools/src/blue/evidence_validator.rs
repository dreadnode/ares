//! Evidence validation against recent query results.
//!
//! Stores recent Loki/Prometheus query results in a module-level deque,
//! extracts IOCs (IPs, hostnames, users, hashes) via regex, and validates
//! evidence values against the stored results for confidence adjustment.

use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use regex::Regex;

/// Maximum stored query results.
const MAX_STORED_RESULTS: usize = 10;

/// Confidence penalty when evidence is not validated against query results.
const UNVALIDATED_PENALTY: f64 = 0.15;

/// Maximum suggested IOCs to return.
const MAX_SUGGESTED_IOCS: usize = 50;

// ---------------------------------------------------------------------------
// Stored query result
// ---------------------------------------------------------------------------

struct StoredQueryResult {
    query_id: String,
    extracted_values: HashSet<String>,
}

struct ValidatorState {
    results: VecDeque<StoredQueryResult>,
    counter: u32,
}

fn state() -> &'static Mutex<ValidatorState> {
    static STATE: OnceLock<Mutex<ValidatorState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(ValidatorState {
            results: VecDeque::with_capacity(MAX_STORED_RESULTS),
            counter: 0,
        })
    })
}

// ---------------------------------------------------------------------------
// Compiled regex patterns (lazy)
// ---------------------------------------------------------------------------

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap())
}

fn hostname_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-zA-Z][a-zA-Z0-9-]*\.[a-zA-Z0-9.-]+)\b").unwrap())
}

fn domain_user_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-zA-Z0-9_-]{2,}\\[a-zA-Z0-9_.-]{2,})\b").unwrap())
}

fn json_user_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""(?:TargetUserName|SubjectUserName|User|Account|AccountName|UserName)":\s*"([^"]+)""#).unwrap()
    })
}

fn json_computer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#""(?:Computer|WorkstationName|Workstation|ComputerName|HostName)":\s*"([^"]+)""#,
        )
        .unwrap()
    })
}

fn json_process_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""(?:ProcessName|NewProcessName|ParentProcessName|Image)":\s*"([^"]+)""#)
            .unwrap()
    })
}

fn json_service_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""(?:ServiceName|Service)":\s*"([^"]+)""#).unwrap())
}

fn md5_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-fA-F0-9]{32})\b").unwrap())
}

fn sha1_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-fA-F0-9]{40})\b").unwrap())
}

fn sha256_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-fA-F0-9]{64})\b").unwrap())
}

// ---------------------------------------------------------------------------
// File extension exclusion list for hostname matching
// ---------------------------------------------------------------------------

const EXCLUDED_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".log", ".txt", ".xml",
    ".json", ".ini", ".cfg", ".tmp",
];

fn is_hostname_like(value: &str) -> bool {
    if value.len() < 4 || value.len() > 255 {
        return false;
    }
    if !value.contains('.') {
        return false;
    }
    // Must not start with a digit (would be an IP)
    if value
        .as_bytes()
        .first()
        .map(|b| b.is_ascii_digit())
        .unwrap_or(true)
    {
        return false;
    }
    // Must not end in a known file extension
    let lower = value.to_lowercase();
    for ext in EXCLUDED_EXTENSIONS {
        if lower.ends_with(ext) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// IOC extraction from raw text
// ---------------------------------------------------------------------------

/// Extract IOC values from a text string (query result output).
fn extract_iocs_from_text(text: &str) -> HashSet<String> {
    let mut values = HashSet::new();

    // IPv4 addresses
    for cap in ipv4_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let ip = m.as_str();
            // Basic validation: octets 0-255
            if ip
                .split('.')
                .all(|octet| octet.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
            {
                values.insert(ip.to_lowercase());
            }
        }
    }

    // Hostnames/FQDNs
    for cap in hostname_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let host = m.as_str();
            if is_hostname_like(host) {
                values.insert(host.to_lowercase());
            }
        }
    }

    // DOMAIN\user
    for cap in domain_user_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let user = m.as_str();
            if user.len() > 5 {
                // Exclude Windows path prefixes
                let lower = user.to_lowercase();
                if !lower.starts_with("c:\\")
                    && !lower.starts_with("d:\\")
                    && !lower.starts_with("\\\\")
                {
                    values.insert(lower);
                }
            }
        }
    }

    // JSON user fields
    for cap in json_user_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let user = m.as_str().trim();
            if user.len() >= 2 && user != "-" && user != "SYSTEM" {
                values.insert(user.to_lowercase());
            }
        }
    }

    // JSON computer fields
    for cap in json_computer_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let host = m.as_str().trim();
            if host.len() >= 2 {
                values.insert(host.to_lowercase());
            }
        }
    }

    // JSON process fields (only .exe or .dll)
    for cap in json_process_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let proc = m.as_str().trim();
            let lower = proc.to_lowercase();
            if lower.contains(".exe") || lower.contains(".dll") {
                values.insert(lower);
            }
        }
    }

    // JSON service fields
    for cap in json_service_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let svc = m.as_str().trim();
            if svc.len() >= 2 && svc != "-" {
                values.insert(svc.to_lowercase());
            }
        }
    }

    // Hashes (check longest first to avoid substring matches)
    for cap in sha256_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            values.insert(m.as_str().to_lowercase());
        }
    }
    for cap in sha1_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            values.insert(m.as_str().to_lowercase());
        }
    }
    for cap in md5_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            values.insert(m.as_str().to_lowercase());
        }
    }

    values
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Store a query result and extract IOCs for later validation.
///
/// Returns the assigned query ID.
pub fn store_query_result(result_text: &str) -> String {
    let extracted = extract_iocs_from_text(result_text);

    let mut st = state().lock().unwrap();
    st.counter += 1;
    let query_id = format!("q-{:04}", st.counter);

    if st.results.len() >= MAX_STORED_RESULTS {
        st.results.pop_front();
    }

    st.results.push_back(StoredQueryResult {
        query_id: query_id.clone(),
        extracted_values: extracted,
    });

    query_id
}

/// Check if an evidence value was seen in any recent query result.
///
/// Returns `(validated, source_query_id)`.
pub fn validate_evidence_value(value: &str) -> (bool, Option<String>) {
    // MITRE technique IDs are always valid
    let lower = value.to_lowercase();
    if lower.starts_with('t') && lower.len() >= 5 && lower[1..5].chars().all(|c| c.is_ascii_digit())
    {
        return (true, None);
    }

    let normalized = lower.trim().to_string();
    let st = state().lock().unwrap();

    // Search most recent first
    for result in st.results.iter().rev() {
        if result.extracted_values.contains(&normalized) {
            return (true, Some(result.query_id.clone()));
        }
    }

    (false, None)
}

/// Adjust evidence confidence based on validation status.
pub fn adjust_confidence(confidence: f64, validated: bool) -> f64 {
    if validated {
        confidence
    } else {
        (confidence - UNVALIDATED_PENALTY).max(0.1)
    }
}

/// IOC classification result.
pub struct ClassifiedIoc {
    pub ioc_type: &'static str,
    pub value: String,
    pub source_query_id: String,
}

/// Get suggested IOCs from recent query results.
///
/// Returns auto-extracted IOCs classified by type, deduped across all stored results.
pub fn get_suggested_iocs() -> Vec<ClassifiedIoc> {
    let st = state().lock().unwrap();
    let mut seen = HashSet::new();
    let mut iocs = Vec::new();

    // Iterate most-recent-first
    for result in st.results.iter().rev() {
        for value in &result.extracted_values {
            if seen.contains(value) {
                continue;
            }
            seen.insert(value.clone());

            if let Some(ioc_type) = classify_ioc(value) {
                iocs.push(ClassifiedIoc {
                    ioc_type,
                    value: value.clone(),
                    source_query_id: result.query_id.clone(),
                });
                if iocs.len() >= MAX_SUGGESTED_IOCS {
                    return iocs;
                }
            }
        }
    }

    iocs
}

/// Classify an IOC value by type.
fn classify_ioc(value: &str) -> Option<&'static str> {
    // IP address
    if value.split('.').count() == 4
        && value.chars().all(|c| c.is_ascii_digit() || c == '.')
        && value
            .split('.')
            .all(|o| o.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
    {
        return Some("ip");
    }

    // Hashes
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("hash");
    }
    if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("hash");
    }
    if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("hash");
    }

    // DOMAIN\user
    if value.contains('\\') && !value.starts_with("c:\\") && !value.starts_with("\\\\") {
        return Some("user");
    }

    // user@domain
    if value.contains('@') && value.contains('.') {
        return Some("user");
    }

    // Hostname/FQDN
    if is_hostname_like(value) {
        return Some("hostname");
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ips() {
        let text = "Source IP: 192.168.58.10, Destination: 192.168.58.10";
        let iocs = extract_iocs_from_text(text);
        assert!(iocs.contains("192.168.58.10"));
        assert!(iocs.contains("192.168.58.10"));
    }

    #[test]
    fn test_extract_hostnames() {
        let text = r#"Computer: dc01.contoso.local, accessing share on web01.contoso.local"#;
        let iocs = extract_iocs_from_text(text);
        assert!(iocs.contains("dc01.contoso.local"));
        assert!(iocs.contains("web01.contoso.local"));
    }

    #[test]
    fn test_extract_users() {
        let text = r#""TargetUserName": "jsmith", "Computer": "DC01""#;
        let iocs = extract_iocs_from_text(text);
        assert!(iocs.contains("jsmith"));
    }

    #[test]
    fn test_extract_hashes() {
        let text = "Hash: aad3b435b51404eeaad3b435b51404ee";
        let iocs = extract_iocs_from_text(text);
        assert!(iocs.contains("aad3b435b51404eeaad3b435b51404ee"));
    }

    #[test]
    fn test_exclude_file_extensions() {
        assert!(!is_hostname_like("cmd.exe"));
        assert!(!is_hostname_like("config.json"));
        assert!(is_hostname_like("dc01.contoso.local"));
    }

    #[test]
    fn test_validate_mitre_technique() {
        let (valid, _) = validate_evidence_value("T1003.006");
        assert!(valid);
    }

    #[test]
    fn test_store_and_validate() {
        store_query_result("Connected from 192.168.58.50 to dc01.contoso.local");
        let (valid, qid) = validate_evidence_value("192.168.58.50");
        assert!(valid);
        assert!(qid.is_some());
    }

    #[test]
    fn test_adjust_confidence() {
        assert_eq!(adjust_confidence(0.8, true), 0.8);
        assert!((adjust_confidence(0.8, false) - 0.65).abs() < 0.001);
        assert!((adjust_confidence(0.1, false) - 0.1).abs() < 0.001); // floor at 0.1
    }

    #[test]
    fn test_classify_ioc() {
        assert_eq!(classify_ioc("192.168.58.10"), Some("ip"));
        assert_eq!(classify_ioc("dc01.contoso.local"), Some("hostname"));
        assert_eq!(
            classify_ioc("aad3b435b51404eeaad3b435b51404ee"),
            Some("hash")
        );
        assert_eq!(classify_ioc("CONTOSO\\jsmith"), Some("user"));
        assert_eq!(classify_ioc("jsmith@contoso.local"), Some("user"));
        assert_eq!(classify_ioc("random"), None);
    }
}
