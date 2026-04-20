//! Detection configuration — re-exports shared types from ares-core and
//! provides the LogQL query builder (Loki-specific, stays in ares-tools).

// Re-export shared types so the rest of this module doesn't change imports.
pub use ares_core::detection::{detection_config, find_template, TemplateEntry};

use super::{build_event_filter, build_pattern_filter, build_selector, WIN_SECURITY, WIN_SYSTEM};

// ─── LogQL builder ─────────────────────────────────────────────────────────

/// Compose a LogQL query from a template entry and optional hostname.
pub fn build_template_logql(entry: &TemplateEntry, host: Option<&str>) -> String {
    let job = match entry.log_source.as_str() {
        "windows-system" => WIN_SYSTEM,
        _ => WIN_SECURITY,
    };
    let sel = build_selector(job, host);

    let ids: Vec<&str> = entry.event_ids.iter().map(|s| s.as_str()).collect();
    let event_filter = build_event_filter(&ids);

    let mut logql = format!("{sel}{event_filter}");

    // `patterns` = single filter stage (OR within)
    if !entry.patterns.is_empty() {
        let refs: Vec<&str> = entry.patterns.iter().map(|s| s.as_str()).collect();
        logql.push_str(&build_pattern_filter(&refs));
    }

    // `filter_stages` = multiple chained filters (AND between stages)
    for stage in &entry.filter_stages {
        let refs: Vec<&str> = stage.iter().map(|s| s.as_str()).collect();
        logql.push_str(&build_pattern_filter(&refs));
    }

    // Negative filters — exclude noise (machine accounts, SYSTEM, etc.)
    if !entry.exclude_patterns.is_empty() {
        let refs: Vec<&str> = entry.exclude_patterns.iter().map(|s| s.as_str()).collect();
        logql.push_str(&format!(r#" !~ "(?i)({})""#, refs.join("|")));
    }

    // Some templates also match host as a line filter
    if entry.host_as_filter {
        if let Some(ip) = host {
            logql.push_str(&format!(r#" |= "{ip}""#));
        }
    }

    logql
}
