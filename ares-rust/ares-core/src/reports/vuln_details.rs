//! Vulnerability detail formatting.

use std::collections::HashSet;

/// Format vulnerability details into a human-readable string.
pub fn format_vuln_details(
    details: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    if details.is_empty() {
        return "-".to_string();
    }

    // Ordered key display names
    let key_display: &[(&str, &str)] = &[
        ("account", "Account"),
        ("account_name", "Account"),
        ("username", "Username"),
        ("domain", "Domain"),
        ("target_spn", "Target SPN"),
        ("delegation_type", "Type"),
        ("dc_ip", "DC IP"),
        ("ca_name", "CA Name"),
        ("ca_host", "CA Host"),
        ("hostname", "Hostname"),
        ("hash", "Hash"),
        ("note", "Note"),
        ("attack_type", "Attack Type"),
        ("adcs_server", "ADCS Server"),
    ];

    let skip_keys: HashSet<&str> = [
        "has_credentials",
        "discovered_by",
        "services",
        "available_credentials",
        "attack_steps",
        "is_sql_account",
    ]
    .into_iter()
    .collect();

    let mut parts = Vec::new();
    let mut seen_keys = HashSet::new();

    // Ordered keys first
    for &(key, display_name) in key_display {
        if skip_keys.contains(key) {
            continue;
        }
        if let Some(value) = details.get(key) {
            seen_keys.insert(key);
            if let Some(s) = value_to_display(value) {
                parts.push(format!("{display_name}: {s}"));
            }
        }
    }

    // Remaining keys (not in ordered list or skip list)
    for (key, value) in details {
        let key_str = key.as_str();
        if seen_keys.contains(key_str) || skip_keys.contains(key_str) {
            continue;
        }
        // Skip complex types
        if value.is_array() || value.is_object() {
            continue;
        }
        if let Some(s) = value_to_display(value) {
            let display_key = key.replace('_', " ");
            // Title case
            let display_key: String = display_key
                .split_whitespace()
                .map(|w| {
                    let mut chars = w.chars();
                    match chars.next() {
                        Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            parts.push(format!("{display_key}: {s}"));
        }
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("; ")
    }
}

pub(crate) fn value_to_display(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) if s.is_empty() => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
