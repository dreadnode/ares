//! Weakness parsing and deduplication.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

static WEAKNESS_FIELD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\*\*([^*:]+):\*\*\s*(.*)$").unwrap());

/// Parsed weakness block fields.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParsedWeakness {
    pub title: String,
    pub vulnerability: String,
    pub affected_resource: String,
    pub discovery_method: String,
    pub impact: String,
}

/// Parse a markdown weakness block into structured fields.
pub(crate) fn parse_weakness_block(block: &str) -> ParsedWeakness {
    let mut result = ParsedWeakness::default();
    if block.is_empty() {
        return result;
    }

    for raw_line in block.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() {
            continue;
        }

        // Title from ### heading
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
                    "discovery_method" => result.discovery_method = value,
                    "impact" => result.impact = value,
                    "title" => result.title = value,
                    _ => {}
                }
            }
        }
    }

    result
}

/// Parse and deduplicate weaknesses by normalized title.
pub fn deduplicate_weaknesses(weaknesses: &[String]) -> Vec<ParsedWeakness> {
    let mut seen_titles: HashSet<String> = HashSet::new();
    let mut result = Vec::new();

    for w in weaknesses {
        let parsed = parse_weakness_block(w);
        let title = parsed.title.trim().to_string();
        // Normalize: lowercase, normalize dashes
        let normalized = title
            .to_lowercase()
            .replace(['\u{2014}', '\u{2013}'], "-")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        if !normalized.is_empty() && seen_titles.contains(&normalized) {
            continue;
        }
        if !normalized.is_empty() {
            seen_titles.insert(normalized);
        }
        result.push(parsed);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_weakness_block_h3_title() {
        let block = "### SMB Signing Disabled\n**Vulnerability:** SMB signing not required";
        let parsed = parse_weakness_block(block);
        assert_eq!(parsed.title, "SMB Signing Disabled");
        assert_eq!(parsed.vulnerability, "SMB signing not required");
    }

    #[test]
    fn test_parse_weakness_block_bold_title() {
        let block = "**Kerberoastable Account**\n- **Vulnerability:** Weak service account";
        let parsed = parse_weakness_block(block);
        assert_eq!(parsed.title, "Kerberoastable Account");
        assert_eq!(parsed.vulnerability, "Weak service account");
    }

    #[test]
    fn test_parse_weakness_block_all_fields() {
        let block = "\
### ADCS ESC1
- **Vulnerability:** Certificate template misconfiguration
- **Affected Resource:** contoso-DC01-CA
- **Discovery Method:** certipy find
- **Impact:** Domain admin escalation";
        let parsed = parse_weakness_block(block);
        assert_eq!(parsed.title, "ADCS ESC1");
        assert_eq!(
            parsed.vulnerability,
            "Certificate template misconfiguration"
        );
        assert_eq!(parsed.affected_resource, "contoso-DC01-CA");
        assert_eq!(parsed.discovery_method, "certipy find");
        assert_eq!(parsed.impact, "Domain admin escalation");
    }

    #[test]
    fn test_parse_weakness_block_empty() {
        let parsed = parse_weakness_block("");
        assert_eq!(parsed.title, "");
        assert_eq!(parsed.vulnerability, "");
    }

    #[test]
    fn test_parse_weakness_block_title_field() {
        let block = "**Title:** Custom Title\n**Vulnerability:** Something";
        let parsed = parse_weakness_block(block);
        assert_eq!(parsed.title, "Custom Title");
    }

    #[test]
    fn test_deduplicate_weaknesses_removes_dupes() {
        let weaknesses = vec![
            "### SMB Signing\n**Vulnerability:** Not required".to_string(),
            "### SMB Signing\n**Vulnerability:** Not required on host B".to_string(),
            "### Kerberoast\n**Vulnerability:** Weak SPN".to_string(),
        ];
        let deduped = deduplicate_weaknesses(&weaknesses);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_deduplicate_weaknesses_case_insensitive() {
        let weaknesses = vec!["### SMB Signing".to_string(), "### smb signing".to_string()];
        let deduped = deduplicate_weaknesses(&weaknesses);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_deduplicate_weaknesses_empty_titles_kept() {
        let weaknesses = vec!["just some text".to_string(), "other text".to_string()];
        let deduped = deduplicate_weaknesses(&weaknesses);
        // Both have empty titles, empty titles are not deduped against each other
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_deduplicate_weaknesses_unicode_dashes_normalized() {
        let weaknesses = vec![
            "### SMB\u{2014}Signing".to_string(),
            "### SMB-Signing".to_string(),
        ];
        let deduped = deduplicate_weaknesses(&weaknesses);
        assert_eq!(deduped.len(), 1);
    }
}
