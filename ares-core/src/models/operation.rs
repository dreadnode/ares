//! Operation metadata and shared red team state.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

use super::core::{Credential, Hash, Host, Share, Target, TrustInfo, User};
use super::task::VulnerabilityInfo;

/// Operation metadata stored in the `ares:op:{id}:meta` Redis HASH.
///
/// Fields are stored as individual hash fields, not a single JSON blob.
#[derive(Debug, Clone, Default)]
pub struct OperationMeta {
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub red_completed_at: Option<DateTime<Utc>>,
    pub red_completion_reason: Option<String>,
    pub red_blocked_on_blue: bool,
    pub target_ip: Option<String>,
    pub target_domain: Option<String>,
    pub target_ips: Vec<String>,
}

impl OperationMeta {
    /// Parse from a Redis HGETALL result (HashMap<String, String>).
    ///
    /// Meta values are stored by Python as `json.dumps(value)`, so:
    /// - Booleans are stored as `"true"` or `"false"` (JSON-encoded)
    /// - Strings are stored as `"\"some string\""` (double-quoted JSON)
    /// - Arrays may be stored as `"[\"ip1\",\"ip2\"]"` (JSON array)
    /// - Or as plain comma-separated values (legacy format)
    pub fn from_redis_hash(data: &HashMap<String, String>) -> Self {
        let started_at = data
            .get("started_at")
            .and_then(|s| parse_meta_datetime(s))
            .map(|dt| dt.with_timezone(&Utc));

        let completed_at = data
            .get("completed_at")
            .and_then(|s| parse_meta_datetime(s))
            .map(|dt| dt.with_timezone(&Utc));

        let red_completed_at = data
            .get("red_completed_at")
            .and_then(|s| parse_meta_datetime(s))
            .map(|dt| dt.with_timezone(&Utc));

        let target_ips = data
            .get("target_ips")
            .map(|s| parse_meta_string_list(s))
            .unwrap_or_default();

        Self {
            has_domain_admin: data
                .get("has_domain_admin")
                .map(|v| parse_meta_bool(v))
                .unwrap_or(false),
            has_golden_ticket: data
                .get("has_golden_ticket")
                .map(|v| parse_meta_bool(v))
                .unwrap_or(false),
            domain_admin_path: data
                .get("domain_admin_path")
                .and_then(|s| parse_meta_string(s)),
            started_at,
            completed_at,
            red_completed_at,
            red_completion_reason: data
                .get("red_completion_reason")
                .and_then(|s| parse_meta_string(s)),
            red_blocked_on_blue: data
                .get("red_blocked_on_blue")
                .map(|v| parse_meta_bool(v))
                .unwrap_or(false),
            target_ip: data.get("target_ip").and_then(|s| parse_meta_string(s)),
            target_domain: data.get("target_domain").and_then(|s| parse_meta_string(s)),
            target_ips,
        }
    }
}

/// Parse a meta boolean value.
///
/// Python stores booleans via `json.dumps(True)` = `"true"`, `json.dumps(False)` = `"false"`.
/// Also handles legacy `"True"`/`"False"` and `"1"`/`"0"`.
pub(crate) fn parse_meta_bool(raw: &str) -> bool {
    matches!(raw, "true" | "True" | "1")
}

/// Parse a meta string value.
///
/// Python stores strings via `json.dumps("value")` = `"\"value\""` (JSON-encoded string).
/// Returns `None` for empty/null values.
pub(crate) fn parse_meta_string(raw: &str) -> Option<String> {
    // Try JSON-decoding first (handles `"\"quoted string\""`)
    if let Ok(serde_json::Value::String(s)) = serde_json::from_str::<serde_json::Value>(raw) {
        if s.is_empty() {
            return None;
        }
        return Some(s);
    }
    // Fall back to raw value (unquoted strings from legacy or direct writes)
    if raw.is_empty() || raw == "null" {
        return None;
    }
    Some(raw.to_string())
}

/// Parse a meta datetime value.
///
/// Python stores datetimes via `json.dumps(value, default=str)`, which produces
/// either a JSON-encoded string `"\"2025-01-28T12:00:00+00:00\""` or a bare string.
pub(crate) fn parse_meta_datetime(raw: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    // Try JSON-decoding first to strip outer quotes
    let s = if let Ok(serde_json::Value::String(inner)) =
        serde_json::from_str::<serde_json::Value>(raw)
    {
        inner
    } else {
        raw.to_string()
    };
    if s.is_empty() || s == "null" {
        return None;
    }
    DateTime::parse_from_rfc3339(&s)
        .ok()
        .or_else(|| s.parse().ok())
}

/// Parse a meta value that should be a list of strings.
///
/// Python may store this as:
/// - A JSON array: `'["ip1","ip2"]'` (from `json.dumps(["ip1","ip2"])`)
/// - A comma-separated string: `'"ip1,ip2"'` (from `json.dumps("ip1,ip2")`)
/// - A plain comma-separated string: `"ip1,ip2"` (legacy)
fn parse_meta_string_list(raw: &str) -> Vec<String> {
    // Try parsing as JSON array first
    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(raw) {
        return arr
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect();
    }

    // Try as JSON string (unwrap quotes), then split by comma
    let s = if let Ok(serde_json::Value::String(inner)) =
        serde_json::from_str::<serde_json::Value>(raw)
    {
        inner
    } else {
        raw.to_string()
    };

    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_meta_bool_true_variants() {
        assert!(parse_meta_bool("true"));
        assert!(parse_meta_bool("True"));
        assert!(parse_meta_bool("1"));
    }

    #[test]
    fn parse_meta_bool_false_variants() {
        assert!(!parse_meta_bool("false"));
        assert!(!parse_meta_bool("False"));
        assert!(!parse_meta_bool("0"));
        assert!(!parse_meta_bool(""));
        assert!(!parse_meta_bool("yes"));
        assert!(!parse_meta_bool("random"));
    }

    #[test]
    fn parse_meta_string_json_quoted() {
        assert_eq!(
            parse_meta_string(r#""contoso.local""#),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn parse_meta_string_raw() {
        assert_eq!(
            parse_meta_string("contoso.local"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn parse_meta_string_null() {
        assert_eq!(parse_meta_string("null"), None);
    }

    #[test]
    fn parse_meta_string_empty() {
        assert_eq!(parse_meta_string(""), None);
    }

    #[test]
    fn parse_meta_string_json_empty() {
        assert_eq!(parse_meta_string(r#""""#), None);
    }

    #[test]
    fn parse_meta_string_with_spaces() {
        assert_eq!(
            parse_meta_string(r#""admin -> DA via secretsdump""#),
            Some("admin -> DA via secretsdump".to_string())
        );
    }

    #[test]
    fn parse_meta_datetime_rfc3339() {
        assert!(parse_meta_datetime("2025-01-28T12:00:00+00:00").is_some());
    }

    #[test]
    fn parse_meta_datetime_json_quoted() {
        assert!(parse_meta_datetime(r#""2025-01-28T12:00:00+00:00""#).is_some());
    }

    #[test]
    fn parse_meta_datetime_null() {
        assert!(parse_meta_datetime("null").is_none());
    }

    #[test]
    fn parse_meta_datetime_empty() {
        assert!(parse_meta_datetime("").is_none());
    }

    #[test]
    fn parse_meta_datetime_invalid() {
        assert!(parse_meta_datetime("not-a-date").is_none());
    }

    #[test]
    fn parse_meta_datetime_utc_z() {
        assert!(parse_meta_datetime("2025-01-28T12:00:00Z").is_some());
    }

    #[test]
    fn parse_meta_string_list_json_array() {
        let list = parse_meta_string_list(r#"["192.168.58.10","192.168.58.20"]"#);
        assert_eq!(list, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn parse_meta_string_list_comma_separated() {
        let list = parse_meta_string_list("192.168.58.10,192.168.58.20");
        assert_eq!(list, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn parse_meta_string_list_json_encoded_comma() {
        let list = parse_meta_string_list(r#""192.168.58.10,192.168.58.20""#);
        assert_eq!(list, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn parse_meta_string_list_single() {
        let list = parse_meta_string_list("192.168.58.10");
        assert_eq!(list, vec!["192.168.58.10"]);
    }

    #[test]
    fn parse_meta_string_list_empty() {
        assert!(parse_meta_string_list("").is_empty());
    }

    #[test]
    fn parse_meta_string_list_with_spaces() {
        let list = parse_meta_string_list("192.168.58.10, 192.168.58.20 , 192.168.58.30");
        assert_eq!(
            list,
            vec!["192.168.58.10", "192.168.58.20", "192.168.58.30"]
        );
    }

    #[test]
    fn parse_meta_string_list_filters_empty() {
        let list = parse_meta_string_list(r#"["192.168.58.10","","192.168.58.20"]"#);
        assert_eq!(list, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn operation_meta_empty_hash() {
        let data = HashMap::new();
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(!meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.domain_admin_path.is_none());
        assert!(meta.started_at.is_none());
        assert!(meta.completed_at.is_none());
        assert!(meta.target_ip.is_none());
        assert!(meta.target_domain.is_none());
        assert!(meta.target_ips.is_empty());
    }

    #[test]
    fn operation_meta_full() {
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "true".to_string());
        data.insert("has_golden_ticket".to_string(), "true".to_string());
        data.insert(
            "domain_admin_path".to_string(),
            r#""secretsdump -> golden ticket""#.to_string(),
        );
        data.insert(
            "started_at".to_string(),
            r#""2025-01-28T12:00:00+00:00""#.to_string(),
        );
        data.insert(
            "completed_at".to_string(),
            r#""2025-01-28T13:00:00+00:00""#.to_string(),
        );
        data.insert("target_ip".to_string(), r#""192.168.58.10""#.to_string());
        data.insert(
            "target_domain".to_string(),
            r#""contoso.local""#.to_string(),
        );
        data.insert(
            "target_ips".to_string(),
            r#"["192.168.58.10","192.168.58.20"]"#.to_string(),
        );

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
        assert!(meta.has_golden_ticket);
        assert_eq!(
            meta.domain_admin_path.as_deref(),
            Some("secretsdump -> golden ticket")
        );
        assert!(meta.started_at.is_some());
        assert!(meta.completed_at.is_some());
        assert_eq!(meta.target_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(meta.target_domain.as_deref(), Some("contoso.local"));
        assert_eq!(meta.target_ips.len(), 2);
    }

    #[test]
    fn operation_meta_completed_at_bare() {
        let mut data = HashMap::new();
        data.insert(
            "completed_at".to_string(),
            "2025-01-28T13:30:00Z".to_string(),
        );
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.completed_at.is_some());
    }

    #[test]
    fn operation_meta_red_completion_fields() {
        let mut data = HashMap::new();
        data.insert(
            "red_completed_at".to_string(),
            r#""2026-05-15T22:04:43+00:00""#.to_string(),
        );
        data.insert(
            "red_completion_reason".to_string(),
            r#""all forests dominated (post-exploitation complete)""#.to_string(),
        );
        data.insert("red_blocked_on_blue".to_string(), "true".to_string());

        let meta = OperationMeta::from_redis_hash(&data);

        assert!(meta.red_completed_at.is_some());
        assert_eq!(
            meta.red_completion_reason.as_deref(),
            Some("all forests dominated (post-exploitation complete)")
        );
        assert!(meta.red_blocked_on_blue);
    }

    #[test]
    fn operation_meta_default_derives() {
        let meta = OperationMeta::default();
        assert!(!meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.red_completed_at.is_none());
        assert!(meta.red_completion_reason.is_none());
        assert!(!meta.red_blocked_on_blue);
        assert!(meta.target_ips.is_empty());
    }

    #[test]
    fn parse_meta_bool_whitespace() {
        assert!(!parse_meta_bool(" true"));
        assert!(!parse_meta_bool("true "));
    }

    #[test]
    fn parse_meta_bool_json_encoded_true() {
        // Python json.dumps(True) = "true", json.dumps(False) = "false"
        assert!(parse_meta_bool("true"));
        assert!(!parse_meta_bool("false"));
    }

    #[test]
    fn parse_meta_string_ip_address() {
        assert_eq!(
            parse_meta_string(r#""192.168.58.10""#),
            Some("192.168.58.10".to_string())
        );
    }

    #[test]
    fn parse_meta_string_raw_ip() {
        assert_eq!(
            parse_meta_string("192.168.58.10"),
            Some("192.168.58.10".to_string())
        );
    }

    #[test]
    fn parse_meta_string_json_number_falls_through() {
        // A JSON number shouldn't parse as a JSON string
        assert_eq!(parse_meta_string("42"), Some("42".to_string()));
    }

    #[test]
    fn parse_meta_string_json_boolean_falls_through() {
        assert_eq!(parse_meta_string("true"), Some("true".to_string()));
        assert_eq!(parse_meta_string("false"), Some("false".to_string()));
    }

    #[test]
    fn parse_meta_string_nested_quotes() {
        // Double-encoded string (rare but possible)
        let result = parse_meta_string(r#""contoso.local\\admin""#);
        assert_eq!(result, Some(r"contoso.local\admin".to_string()));
    }

    #[test]
    fn parse_meta_string_unicode() {
        assert_eq!(
            parse_meta_string(r#""dc01\u002econtoso.local""#),
            Some("dc01.contoso.local".to_string())
        );
    }

    #[test]
    fn parse_meta_datetime_with_offset() {
        let result = parse_meta_datetime("2025-06-15T08:30:00+05:30");
        assert!(result.is_some());
    }

    #[test]
    fn parse_meta_datetime_negative_offset() {
        let result = parse_meta_datetime("2025-06-15T08:30:00-07:00");
        assert!(result.is_some());
    }

    #[test]
    fn parse_meta_datetime_json_null_string() {
        assert!(parse_meta_datetime(r#""null""#).is_none());
    }

    #[test]
    fn parse_meta_datetime_json_empty_string() {
        assert!(parse_meta_datetime(r#""""#).is_none());
    }

    #[test]
    fn parse_meta_datetime_partial_date() {
        assert!(parse_meta_datetime("2025-06-15").is_none());
    }

    #[test]
    fn parse_meta_string_list_json_array_single() {
        let list = parse_meta_string_list(r#"["192.168.58.10"]"#);
        assert_eq!(list, vec!["192.168.58.10"]);
    }

    #[test]
    fn parse_meta_string_list_json_array_empty() {
        let list = parse_meta_string_list("[]");
        assert!(list.is_empty());
    }

    #[test]
    fn parse_meta_string_list_trailing_comma() {
        let list = parse_meta_string_list("192.168.58.10,192.168.58.20,");
        assert_eq!(list, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn parse_meta_string_list_leading_comma() {
        let list = parse_meta_string_list(",192.168.58.10");
        assert_eq!(list, vec!["192.168.58.10"]);
    }

    #[test]
    fn parse_meta_string_list_all_empty_entries() {
        let list = parse_meta_string_list(",,,");
        assert!(list.is_empty());
    }

    #[test]
    fn parse_meta_string_list_json_array_with_numbers() {
        // Non-string JSON array elements are filtered out
        let list = parse_meta_string_list(r#"[1, 2, 3]"#);
        assert!(list.is_empty());
    }

    #[test]
    fn operation_meta_legacy_bool_values() {
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "True".to_string());
        data.insert("has_golden_ticket".to_string(), "1".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
        assert!(meta.has_golden_ticket);
    }

    #[test]
    fn operation_meta_false_bool_values() {
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "false".to_string());
        data.insert("has_golden_ticket".to_string(), "0".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(!meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
    }

    #[test]
    fn operation_meta_target_ips_comma_separated() {
        let mut data = HashMap::new();
        data.insert(
            "target_ips".to_string(),
            "192.168.58.10,192.168.58.20,192.168.58.30".to_string(),
        );
        let meta = OperationMeta::from_redis_hash(&data);
        assert_eq!(meta.target_ips.len(), 3);
        assert_eq!(meta.target_ips[0], "192.168.58.10");
        assert_eq!(meta.target_ips[2], "192.168.58.30");
    }

    #[test]
    fn operation_meta_target_ips_json_encoded_comma() {
        let mut data = HashMap::new();
        data.insert(
            "target_ips".to_string(),
            r#""192.168.58.10,192.168.58.20""#.to_string(),
        );
        let meta = OperationMeta::from_redis_hash(&data);
        assert_eq!(meta.target_ips.len(), 2);
    }

    #[test]
    fn operation_meta_null_domain_admin_path() {
        let mut data = HashMap::new();
        data.insert("domain_admin_path".to_string(), "null".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.domain_admin_path.is_none());
    }

    #[test]
    fn operation_meta_invalid_datetime() {
        let mut data = HashMap::new();
        data.insert("started_at".to_string(), "not-a-date".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.started_at.is_none());
    }

    #[test]
    fn operation_meta_extra_unknown_fields_ignored() {
        let mut data = HashMap::new();
        data.insert("unknown_field".to_string(), "some_value".to_string());
        data.insert("has_domain_admin".to_string(), "true".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
    }

    #[test]
    fn operation_meta_empty_target_ips() {
        let mut data = HashMap::new();
        data.insert("target_ips".to_string(), "".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.target_ips.is_empty());
    }

    #[test]
    fn operation_meta_empty_json_array_target_ips() {
        let mut data = HashMap::new();
        data.insert("target_ips".to_string(), "[]".to_string());
        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.target_ips.is_empty());
    }

    #[test]
    fn shared_state_new() {
        let state = SharedRedTeamState::new("op-test-001".to_string());
        assert_eq!(state.operation_id, "op-test-001");
        assert!(state.target.is_none());
        assert!(state.target_ips.is_empty());
        assert!(state.completed_at.is_none());
        assert!(state.all_credentials.is_empty());
        assert!(state.all_hashes.is_empty());
        assert!(state.all_hosts.is_empty());
        assert!(state.all_users.is_empty());
        assert!(state.all_shares.is_empty());
        assert!(state.discovered_vulnerabilities.is_empty());
        assert!(state.exploited_vulnerabilities.is_empty());
        assert!(!state.has_domain_admin);
        assert!(!state.has_golden_ticket);
        assert!(state.domain_admin_path.is_none());
        assert!(state.domain_controllers.is_empty());
        assert!(state.netbios_to_fqdn.is_empty());
        assert!(state.trusted_domains.is_empty());
        assert!(state.all_timeline_events.is_empty());
        assert!(state.all_techniques.is_empty());
    }

    #[test]
    fn build_attack_chain_empty_state() {
        let state = SharedRedTeamState::new("op-chain-empty".to_string());
        let chain = state.build_attack_chain("nonexistent-id");
        assert!(chain.is_empty());
    }

    #[test]
    fn build_attack_chain_single_credential() {
        let mut state = SharedRedTeamState::new("op-chain-single".to_string());
        state.all_credentials.push(Credential {
            id: "cred-1".to_string(),
            username: "admin".to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "kerberoast".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 1,
        });
        let chain = state.build_attack_chain("cred-1");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].username, "admin");
        assert_eq!(chain[0].domain, "contoso.local");
        assert_eq!(chain[0].source, "kerberoast");
        assert_eq!(chain[0].item_type, "credential");
    }

    #[test]
    fn build_attack_chain_multi_step() {
        let mut state = SharedRedTeamState::new("op-chain-multi".to_string());
        state.all_credentials.push(Credential {
            id: "cred-1".to_string(),
            username: "svc_sql".to_string(),
            password: "SqlP@ss!".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "kerberoast".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 1,
        });
        state.all_hashes.push(Hash {
            id: "hash-1".to_string(),
            username: "krbtgt".to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "secretsdump".to_string(),
            discovered_at: None,
            parent_id: Some("cred-1".to_string()),
            attack_step: 2,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        let chain = state.build_attack_chain("hash-1");
        assert_eq!(chain.len(), 2);
        // Forward order: initial access first
        assert_eq!(chain[0].username, "svc_sql");
        assert_eq!(chain[0].item_type, "credential");
        assert_eq!(chain[1].username, "krbtgt");
        assert_eq!(chain[1].item_type, "hash");
    }

    #[test]
    fn build_attack_chain_cycle_guard() {
        let mut state = SharedRedTeamState::new("op-cycle".to_string());
        // Create a cycle: cred-1 -> cred-2 -> cred-1
        state.all_credentials.push(Credential {
            id: "cred-1".to_string(),
            username: "user1".to_string(),
            password: "pass1".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: Some("cred-2".to_string()),
            attack_step: 1,
        });
        state.all_credentials.push(Credential {
            id: "cred-2".to_string(),
            username: "user2".to_string(),
            password: "pass2".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: Some("cred-1".to_string()),
            attack_step: 2,
        });
        let chain = state.build_attack_chain("cred-1");
        // Should not infinite loop; should have at most 2 entries
        assert!(chain.len() <= 2);
    }

    #[test]
    fn build_domain_admin_chain_no_krbtgt() {
        let state = SharedRedTeamState::new("op-no-krbtgt".to_string());
        let chain = state.build_domain_admin_chain();
        assert!(chain.is_empty());
    }

    #[test]
    fn build_domain_admin_chain_with_krbtgt() {
        let mut state = SharedRedTeamState::new("op-da".to_string());
        state.all_credentials.push(Credential {
            id: "cred-init".to_string(),
            username: "svc_backup".to_string(),
            password: "Backup123!".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "password_spray".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 1,
        });
        state.all_hashes.push(Hash {
            id: "hash-krbtgt".to_string(),
            username: "krbtgt".to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "secretsdump".to_string(),
            discovered_at: None,
            parent_id: Some("cred-init".to_string()),
            attack_step: 2,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        let chain = state.build_domain_admin_chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].username, "svc_backup");
        assert_eq!(chain[1].username, "krbtgt");
    }

    #[test]
    fn build_domain_admin_chain_case_insensitive_krbtgt() {
        let mut state = SharedRedTeamState::new("op-da-case".to_string());
        state.all_hashes.push(Hash {
            id: "hash-krbtgt".to_string(),
            username: "KRBTGT".to_string(), // uppercase
            hash_value: "abc123".to_string(),
            hash_type: "NTLM".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "dcsync".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 1,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        let chain = state.build_domain_admin_chain();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].username, "KRBTGT");
    }

    #[test]
    fn build_domain_admin_chain_ignores_non_ntlm_krbtgt() {
        let mut state = SharedRedTeamState::new("op-da-aes".to_string());
        state.all_hashes.push(Hash {
            id: "hash-aes".to_string(),
            username: "krbtgt".to_string(),
            hash_value: "abc123".to_string(),
            hash_type: "aes256".to_string(), // Not NTLM
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "dcsync".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 1,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        let chain = state.build_domain_admin_chain();
        assert!(chain.is_empty());
    }

    #[test]
    fn format_attack_chain_empty() {
        let result = SharedRedTeamState::format_attack_chain(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn format_attack_chain_single_credential() {
        let chain = vec![AttackChainStep {
            step_number: 1,
            item_type: "credential".to_string(),
            username: "admin".to_string(),
            domain: "contoso.local".to_string(),
            source: "password_spray".to_string(),
            hash_type: String::new(),
            item_id: "cred-1".to_string(),
        }];
        let result = SharedRedTeamState::format_attack_chain(&chain);
        assert!(result.contains("password_spray"));
        assert!(result.contains(r"contoso.local\admin (password)"));
    }

    #[test]
    fn format_attack_chain_credential_then_hash() {
        let chain = vec![
            AttackChainStep {
                step_number: 1,
                item_type: "credential".to_string(),
                username: "svc_sql".to_string(),
                domain: "contoso.local".to_string(),
                source: "kerberoast".to_string(),
                hash_type: String::new(),
                item_id: "cred-1".to_string(),
            },
            AttackChainStep {
                step_number: 2,
                item_type: "hash".to_string(),
                username: "krbtgt".to_string(),
                domain: "contoso.local".to_string(),
                source: "secretsdump".to_string(),
                hash_type: "ntlm".to_string(),
                item_id: "hash-1".to_string(),
            },
        ];
        let result = SharedRedTeamState::format_attack_chain(&chain);
        assert!(result.contains("kerberoast"), "Should contain first source");
        assert!(
            result.contains("secretsdump"),
            "Should contain second source"
        );
        assert!(
            result.contains(r"contoso.local\krbtgt (ntlm hash)"),
            "Should format hash step"
        );
    }

    #[test]
    fn format_attack_chain_no_source() {
        let chain = vec![AttackChainStep {
            step_number: 1,
            item_type: "credential".to_string(),
            username: "admin".to_string(),
            domain: "fabrikam.local".to_string(),
            source: String::new(),
            hash_type: String::new(),
            item_id: "cred-1".to_string(),
        }];
        let result = SharedRedTeamState::format_attack_chain(&chain);
        assert!(result.contains(r"fabrikam.local\admin (password)"));
        // No arrow prefix since source is empty
        assert!(!result.starts_with(" "));
    }
}

/// Read-only view of the shared red team state, loaded from Redis.
///
/// This matches the Python `SharedRedTeamState` dataclass but only includes
/// fields needed by the CLI (loot, status, runtime, etc.).
#[derive(Debug, Clone)]
pub struct SharedRedTeamState {
    pub operation_id: String,
    pub target: Option<Target>,
    pub target_ips: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub red_completed_at: Option<DateTime<Utc>>,
    pub red_completion_reason: Option<String>,
    pub red_blocked_on_blue: bool,

    // Global discoveries
    pub all_domains: Vec<String>,
    pub all_credentials: Vec<Credential>,
    pub all_hashes: Vec<Hash>,
    pub all_hosts: Vec<Host>,
    pub all_users: Vec<User>,
    pub all_shares: Vec<Share>,

    // Vulnerability registry
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,

    // Success flags
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,

    // Domain controller cache
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,

    // Trust relationships (domain FQDN → trust metadata)
    pub trusted_domains: HashMap<String, TrustInfo>,

    // Timeline and MITRE ATT&CK tracking
    pub all_timeline_events: Vec<serde_json::Value>,
    pub all_techniques: Vec<String>,
}

/// A single step in a credential attack chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackChainStep {
    pub step_number: i32,
    /// `"credential"` or `"hash"`
    pub item_type: String,
    pub username: String,
    pub domain: String,
    pub source: String,
    /// Hash type if this step is a hash (e.g., `"ntlm"`, `"aes256"`).
    pub hash_type: String,
    pub item_id: String,
}

impl SharedRedTeamState {
    /// Create a new empty state for an operation.
    pub fn new(operation_id: String) -> Self {
        Self {
            operation_id,
            target: None,
            target_ips: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            red_completed_at: None,
            red_completion_reason: None,
            red_blocked_on_blue: false,
            all_domains: Vec::new(),
            all_credentials: Vec::new(),
            all_hashes: Vec::new(),
            all_hosts: Vec::new(),
            all_users: Vec::new(),
            all_shares: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            trusted_domains: HashMap::new(),
            all_timeline_events: Vec::new(),
            all_techniques: Vec::new(),
        }
    }

    /// Build the credential attack chain by walking `parent_id` backward.
    ///
    /// Starting from a credential or hash, follows the `parent_id` links back
    /// to the initial access credential. Returns steps in forward order
    /// (initial access first, target item last).
    pub fn build_attack_chain(&self, item_id: &str) -> Vec<AttackChainStep> {
        let mut chain = Vec::new();
        let mut current_id = Some(item_id.to_string());
        let mut visited = HashSet::new();

        while let Some(ref id) = current_id {
            if visited.contains(id) {
                break; // cycle guard
            }
            visited.insert(id.clone());

            // Try credentials first
            if let Some(cred) = self.all_credentials.iter().find(|c| c.id == *id) {
                chain.push(AttackChainStep {
                    step_number: cred.attack_step,
                    item_type: "credential".to_string(),
                    username: cred.username.clone(),
                    domain: cred.domain.clone(),
                    source: cred.source.clone(),
                    hash_type: String::new(),
                    item_id: cred.id.clone(),
                });
                current_id = cred.parent_id.clone();
                continue;
            }

            // Then hashes
            if let Some(hash) = self.all_hashes.iter().find(|h| h.id == *id) {
                chain.push(AttackChainStep {
                    step_number: hash.attack_step,
                    item_type: "hash".to_string(),
                    username: hash.username.clone(),
                    domain: hash.domain.clone(),
                    source: hash.source.clone(),
                    hash_type: hash.hash_type.clone(),
                    item_id: hash.id.clone(),
                });
                current_id = hash.parent_id.clone();
                continue;
            }

            break; // ID not found
        }

        chain.reverse(); // Forward order: initial access → target
        chain
    }

    /// Build the attack chain to domain admin (krbtgt hash).
    ///
    /// Finds the krbtgt NTLM hash and walks its `parent_id` chain backward.
    /// Returns an empty vec if no krbtgt hash exists or DA was not achieved.
    pub fn build_domain_admin_chain(&self) -> Vec<AttackChainStep> {
        // Find the krbtgt hash (the DA indicator)
        let krbtgt = self.all_hashes.iter().find(|h| {
            h.username.eq_ignore_ascii_case("krbtgt") && h.hash_type.to_lowercase().contains("ntlm")
        });

        match krbtgt {
            Some(h) => self.build_attack_chain(&h.id),
            None => Vec::new(),
        }
    }

    /// Format an attack chain as an arrow-delimited string.
    ///
    /// Example: `kerberoast → contoso.local\svc_sql (password) → secretsdump → contoso.local\krbtgt (ntlm hash)`
    pub fn format_attack_chain(chain: &[AttackChainStep]) -> String {
        if chain.is_empty() {
            return String::new();
        }

        let mut parts = Vec::new();
        for step in chain {
            let cred_desc = if step.item_type == "hash" {
                format!(
                    "{}\\{} ({} hash)",
                    step.domain, step.username, step.hash_type
                )
            } else {
                format!("{}\\{} (password)", step.domain, step.username)
            };

            if !step.source.is_empty() && parts.is_empty() {
                // First step: show source → credential
                parts.push(step.source.clone());
            } else if !step.source.is_empty() {
                // Subsequent steps: show source before credential
                parts.push(step.source.clone());
            }
            parts.push(cred_desc);
        }

        parts.join(" → ")
    }
}
