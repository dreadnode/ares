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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_format_vuln_details_empty() {
        let details = HashMap::new();
        assert_eq!(format_vuln_details(&details), "-");
    }

    #[test]
    fn test_format_vuln_details_ordered_keys() {
        let mut details = HashMap::new();
        details.insert("account_name".to_string(), serde_json::json!("svc_sql$"));
        details.insert("domain".to_string(), serde_json::json!("contoso.local"));
        let result = format_vuln_details(&details);
        assert!(result.contains("Account: svc_sql$"));
        assert!(result.contains("Domain: contoso.local"));
    }

    #[test]
    fn test_format_vuln_details_skip_keys() {
        let mut details = HashMap::new();
        details.insert("has_credentials".to_string(), serde_json::json!(true));
        details.insert("services".to_string(), serde_json::json!(["smb"]));
        details.insert("domain".to_string(), serde_json::json!("contoso.local"));
        let result = format_vuln_details(&details);
        assert!(!result.contains("has_credentials"));
        assert!(!result.contains("services"));
        assert!(result.contains("Domain: contoso.local"));
    }

    #[test]
    fn test_format_vuln_details_custom_keys_title_cased() {
        let mut details = HashMap::new();
        details.insert("custom_field".to_string(), serde_json::json!("value"));
        let result = format_vuln_details(&details);
        assert!(result.contains("Custom Field: value"));
    }

    #[test]
    fn test_format_vuln_details_skips_null_and_empty() {
        let mut details = HashMap::new();
        details.insert("domain".to_string(), serde_json::Value::Null);
        details.insert("account".to_string(), serde_json::json!(""));
        let result = format_vuln_details(&details);
        assert_eq!(result, "-");
    }

    #[test]
    fn test_format_vuln_details_bool_and_number() {
        let mut details = HashMap::new();
        details.insert("some_flag".to_string(), serde_json::json!(true));
        details.insert("some_count".to_string(), serde_json::json!(42));
        let result = format_vuln_details(&details);
        assert!(result.contains("true"));
        assert!(result.contains("42"));
    }

    #[test]
    fn test_format_vuln_details_skips_complex_types() {
        let mut details = HashMap::new();
        details.insert("nested".to_string(), serde_json::json!({"a": 1}));
        details.insert("list".to_string(), serde_json::json!([1, 2, 3]));
        let result = format_vuln_details(&details);
        assert_eq!(result, "-");
    }

    #[test]
    fn test_value_to_display() {
        assert_eq!(value_to_display(&serde_json::Value::Null), None);
        assert_eq!(value_to_display(&serde_json::json!("")), None);
        assert_eq!(
            value_to_display(&serde_json::json!("hello")),
            Some("hello".to_string())
        );
        assert_eq!(
            value_to_display(&serde_json::json!(true)),
            Some("true".to_string())
        );
        assert_eq!(
            value_to_display(&serde_json::json!(42)),
            Some("42".to_string())
        );
        assert_eq!(value_to_display(&serde_json::json!([1])), None);
        assert_eq!(value_to_display(&serde_json::json!({"a": 1})), None);
    }
}
