//! Lateral movement pattern detection — loads regex patterns from the shared
//! `detections.yaml` via [`crate::detection::detection_config`].

use regex::Regex;
use std::sync::LazyLock;

/// Regex for FQDN-like hostnames.
pub static HOSTNAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([a-zA-Z][a-zA-Z0-9-]*\.[a-zA-Z0-9.-]+)\b").unwrap());

/// Regex for bare IPv4 addresses.
pub static IP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

/// Compiled connection-type pattern entry.
struct CompiledPattern {
    conn_type: &'static str,
    regexes: Vec<Regex>,
}

/// Compiled lateral movement patterns, built once from YAML config.
static COMPILED: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    let config = crate::detection::detection_config();
    config
        .lateral_patterns
        .iter()
        .map(|(conn_type, pats)| {
            let regexes = pats
                .iter()
                .filter_map(|p| Regex::new(&format!("(?i){p}")).ok())
                .collect();
            CompiledPattern {
                conn_type: conn_type.as_str(),
                regexes,
            }
        })
        .collect()
});

/// Regex patterns for detecting lateral movement connection types.
pub struct LateralPatterns;

impl Default for LateralPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl LateralPatterns {
    pub fn new() -> Self {
        // Force lazy init so compilation happens eagerly if desired
        LazyLock::force(&COMPILED);
        Self
    }

    pub fn detect(&self, text: &str) -> &'static str {
        for entry in COMPILED.iter() {
            for re in &entry.regexes {
                if re.is_match(text) {
                    return entry.conn_type;
                }
            }
        }
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_re_matches_fqdn() {
        assert!(HOSTNAME_RE.is_match("dc01.contoso.local"));
    }

    #[test]
    fn hostname_re_no_match_bare_word() {
        assert!(!HOSTNAME_RE.is_match("dc01"));
    }

    #[test]
    fn ip_re_matches_ipv4() {
        assert!(IP_RE.is_match("192.168.58.1"));
        assert!(IP_RE.is_match("192.168.58.1"));
    }

    #[test]
    fn ip_re_no_match_hostname() {
        assert!(!IP_RE.is_match("dc01.contoso.local"));
    }

    #[test]
    fn ip_re_no_match_partial() {
        assert!(!IP_RE.is_match("192.168.1"));
    }

    #[test]
    fn lateral_patterns_default() {
        let p = LateralPatterns;
        let _ = p.detect("some text");
    }

    #[test]
    fn lateral_patterns_unknown_text() {
        let p = LateralPatterns::new();
        let result = p.detect("completely unrelated text");
        assert_eq!(result, "unknown");
    }
}
