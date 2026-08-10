//! Vulnerability detail formatting.

use std::collections::HashSet;

/// Maximum length (in characters) for a single rendered detail entry.
/// Long blobs — embedded NTDS hashes, base64 ticket payloads, multi-line
/// pwsh fragments — must not flood the report table cell. Anything over
/// this cap is truncated to `DETAIL_MAX_CHARS - 1` chars + ellipsis (`…`).
/// This is per-entry; the count of rendered details is never truncated.
pub(crate) const DETAIL_MAX_CHARS: usize = 100;

/// Truncate a single detail string to `DETAIL_MAX_CHARS` chars + ellipsis.
/// Char-boundary safe (uses `chars()` not byte slicing).
pub(crate) fn truncate_detail(s: &str) -> String {
    if s.chars().count() <= DETAIL_MAX_CHARS {
        return s.to_string();
    }
    let prefix: String = s.chars().take(DETAIL_MAX_CHARS - 1).collect();
    format!("{prefix}\u{2026}")
}

/// Format vulnerability details into a human-readable string.
pub fn format_vuln_details(
    details: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    if details.is_empty() {
        return "-".to_string();
    }

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
                parts.push(truncate_detail(&format!("{display_name}: {s}")));
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
            parts.push(truncate_detail(&format!("{display_key}: {s}")));
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
    fn format_vuln_details_empty() {
        let details = HashMap::new();
        assert_eq!(format_vuln_details(&details), "-");
    }

    #[test]
    fn format_vuln_details_ordered_keys() {
        let mut details = HashMap::new();
        details.insert("account_name".to_string(), serde_json::json!("svc_sql$"));
        details.insert("domain".to_string(), serde_json::json!("contoso.local"));
        let result = format_vuln_details(&details);
        assert!(result.contains("Account: svc_sql$"));
        assert!(result.contains("Domain: contoso.local"));
    }

    #[test]
    fn format_vuln_details_skip_keys() {
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
    fn format_vuln_details_custom_keys_title_cased() {
        let mut details = HashMap::new();
        details.insert("custom_field".to_string(), serde_json::json!("value"));
        let result = format_vuln_details(&details);
        assert!(result.contains("Custom Field: value"));
    }

    #[test]
    fn format_vuln_details_skips_null_and_empty() {
        let mut details = HashMap::new();
        details.insert("domain".to_string(), serde_json::Value::Null);
        details.insert("account".to_string(), serde_json::json!(""));
        let result = format_vuln_details(&details);
        assert_eq!(result, "-");
    }

    #[test]
    fn format_vuln_details_bool_and_number() {
        let mut details = HashMap::new();
        details.insert("some_flag".to_string(), serde_json::json!(true));
        details.insert("some_count".to_string(), serde_json::json!(42));
        let result = format_vuln_details(&details);
        assert!(result.contains("true"));
        assert!(result.contains("42"));
    }

    #[test]
    fn format_vuln_details_skips_complex_types() {
        let mut details = HashMap::new();
        details.insert("nested".to_string(), serde_json::json!({"a": 1}));
        details.insert("list".to_string(), serde_json::json!([1, 2, 3]));
        let result = format_vuln_details(&details);
        assert_eq!(result, "-");
    }

    #[test]
    fn truncate_detail_passes_through_short_strings() {
        let s = "Account: alice";
        assert_eq!(truncate_detail(s), s);
    }

    #[test]
    fn truncate_detail_cuts_long_strings_with_ellipsis() {
        // 200 ASCII chars — well over the 100-char cap.
        let s = "Hash: ".to_string() + &"a".repeat(200);
        let out = truncate_detail(&s);
        // DETAIL_MAX_CHARS - 1 chars + 1 ellipsis = DETAIL_MAX_CHARS chars
        assert_eq!(out.chars().count(), DETAIL_MAX_CHARS);
        assert!(out.ends_with('\u{2026}'));
        assert!(out.starts_with("Hash: aaaa"));
    }

    #[test]
    fn truncate_detail_char_boundary_safe() {
        // Multi-byte characters must not panic. Build a 200-char string of
        // 4-byte emoji (\u{1F600} = 😀).
        let s = "\u{1F600}".repeat(200);
        let out = truncate_detail(&s);
        assert_eq!(out.chars().count(), DETAIL_MAX_CHARS);
        assert!(out.ends_with('\u{2026}'));
    }

    #[test]
    fn format_vuln_details_truncates_long_values() {
        // A 200-char hash detail must come out under the cap. The count of
        // entries is not affected — only each entry's length is capped.
        let mut details = std::collections::HashMap::new();
        details.insert(
            "hash".to_string(),
            serde_json::json!("a".repeat(500).as_str()),
        );
        details.insert("domain".to_string(), serde_json::json!("contoso.local"));
        let result = format_vuln_details(&details);
        // Each part is delimited by "; "; split and assert no part exceeds
        // the cap.
        for part in result.split("; ") {
            assert!(
                part.chars().count() <= DETAIL_MAX_CHARS,
                "part exceeds cap: {part}"
            );
        }
        assert!(result.contains('\u{2026}'), "ellipsis missing in output");
        // Both details survive — truncation is per-entry, not a global limit.
        assert!(result.contains("Domain: contoso.local"));
        assert!(result.contains("Hash:"));
    }

    #[test]
    fn converts_value_to_display() {
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
