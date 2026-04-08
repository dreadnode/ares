//! Operation metadata and shared red team state.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

use super::core::{Credential, Hash, Host, Share, Target, User};
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

    // Global discoveries
    pub all_domains: Vec<String>,
    pub all_credentials: Vec<Credential>,
    pub all_hashes: Vec<Hash>,
    pub all_hosts: Vec<Host>,
    pub all_users: Vec<User>,
    pub all_shares: Vec<Share>,
    pub all_weaknesses: Vec<String>,

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
            all_domains: Vec::new(),
            all_credentials: Vec::new(),
            all_hashes: Vec::new(),
            all_hosts: Vec::new(),
            all_users: Vec::new(),
            all_shares: Vec::new(),
            all_weaknesses: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
        }
    }
}
