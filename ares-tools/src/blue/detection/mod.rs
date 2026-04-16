//! Pre-built query templates for detecting red team attack patterns.
//!
//! Provides ready-to-use LogQL queries mapped to MITRE ATT&CK techniques,
//! designed to detect attacks performed by the Ares red team agent.
//!
//! Query optimization follows Grafana Loki best practices:
//! - Label selectors are the most important filter — narrow them first
//! - Use `|=` (contains) before `|~` (regex) — contains is faster
//! - Put most selective filters (event IDs) first
//! - Avoid broad patterns like `{job=~".+"}` — use specific labels

mod catalog;
pub(super) mod config;
mod runner;
mod templates;

#[cfg(test)]
mod tests;

// ─── Label constants ────────────────────────────────────────────────────────

pub(super) const WIN_SECURITY: &str = r#"job="windows-security""#;
pub(super) const WIN_SYSTEM: &str = r#"job="windows-system""#;

// ─── Query builder helpers ──────────────────────────────────────────────────

/// Build an optimized label selector.
///
/// Starts with a base job label, auto-injects `deployment` from env var
/// to narrow stream selection, optionally adds computer regex match.
/// The `computer` label contains the FQDN (e.g. `dc01.contoso.local`),
/// so regex match (`=~`) is used to allow partial hostname or IP matches.
pub(super) fn build_selector(base: &str, hostname: Option<&str>) -> String {
    let deployment = std::env::var("ARES_DEPLOYMENT").ok();
    let mut labels = base.to_string();
    if let Some(dep) = &deployment {
        labels.push_str(&format!(r#", deployment="{dep}""#));
    }
    match hostname {
        Some(host) => format!("{{{labels}, computer=~\"{host}\"}}"),
        None => format!("{{{labels}}}"),
    }
}

/// Build an optimized filter for Windows Event IDs.
///
/// Uses `|=` (contains) for single IDs and `|~` (regex alternation) for
/// multiple. Per Grafana docs: "Loki evaluates contains faster than regex."
pub(super) fn build_event_filter(ids: &[&str]) -> String {
    match ids.len() {
        0 => String::new(),
        1 => format!(r#" |= "{}""#, ids[0]),
        _ => format!(r#" |~ "({})""#, ids.join("|")),
    }
}

/// Build a case-insensitive regex filter for tool/attack patterns.
pub(super) fn build_pattern_filter(patterns: &[&str]) -> String {
    if patterns.is_empty() {
        return String::new();
    }
    format!(r#" |~ "(?i)({})""#, patterns.join("|"))
}

// ─── Re-exports ──────────────────────────────────────────────────────────────

pub use catalog::list_detection_templates;
pub use runner::{
    get_host_activity, get_user_activity, run_detection_query, run_parallel_detections,
};
