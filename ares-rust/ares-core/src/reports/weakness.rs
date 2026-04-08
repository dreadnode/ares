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
