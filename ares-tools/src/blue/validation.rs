//! Evidence validation for blue team investigation tools.
//!
//! Validates evidence types, values, MITRE technique IDs, and assigns
//! Pyramid of Pain levels automatically.

use std::net::IpAddr;

/// Result of validating an evidence field or technique ID.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub warnings: Vec<String>,
    pub normalized_type: String,
}

/// Known evidence types accepted by the investigation system.
const KNOWN_EVIDENCE_TYPES: &[&str] = &[
    "suspicious_ip",
    "malicious_process",
    "lateral_movement",
    "credential_access",
    "persistence_mechanism",
    "c2_communication",
    "privilege_escalation",
    "network_artifact",
    "file_artifact",
    "registry_artifact",
    "log_entry",
    "user_activity",
    "authentication_event",
];

/// Maximum length for evidence values.
const MAX_VALUE_LENGTH: usize = 10000;

/// Validate evidence fields before writing to Redis.
///
/// Checks:
/// - `evidence_type` is one of the known types
/// - `value` is non-empty and within length limits
/// - `source` is non-empty
/// - For IP-type evidence, the value is a valid IP address
pub fn validate_evidence(evidence_type: &str, value: &str, source: &str) -> ValidationResult {
    let mut warnings: Vec<String> = Vec::new();
    let mut valid = true;

    // Check evidence_type is known
    let normalized_type = evidence_type.to_lowercase();
    if !KNOWN_EVIDENCE_TYPES.contains(&normalized_type.as_str()) {
        valid = false;
        warnings.push(format!(
            "Unknown evidence type '{}'. Known types: {}",
            evidence_type,
            KNOWN_EVIDENCE_TYPES.join(", "),
        ));
    }

    // Check value is non-empty
    if value.trim().is_empty() {
        valid = false;
        warnings.push("Evidence value must not be empty".to_string());
    }

    // Check value length
    if value.len() > MAX_VALUE_LENGTH {
        valid = false;
        warnings.push(format!(
            "Evidence value exceeds maximum length of {} characters (got {})",
            MAX_VALUE_LENGTH,
            value.len(),
        ));
    }

    // Check source is non-empty
    if source.trim().is_empty() {
        valid = false;
        warnings.push("Evidence source must not be empty".to_string());
    }

    // For IP-type evidence, validate IP format
    if normalized_type == "suspicious_ip"
        && !value.trim().is_empty()
        && value.parse::<IpAddr>().is_err()
    {
        warnings.push(format!(
            "Evidence type is 'suspicious_ip' but value '{}' is not a valid IP address",
            value,
        ));
        // This is a warning, not a hard failure -- the agent might be
        // storing a hostname or CIDR that we still want to record.
    }

    ValidationResult {
        valid,
        warnings,
        normalized_type,
    }
}

/// Validate a MITRE ATT&CK technique ID.
///
/// Must match `T\d{4}` or `T\d{4}\.\d{3}` (e.g., T1003, T1003.001).
/// Normalizes to uppercase.
pub fn validate_technique_id(technique_id: &str) -> ValidationResult {
    let normalized = technique_id.trim().to_uppercase();

    let re = regex::Regex::new(r"^T\d{4}(\.\d{3})?$").expect("valid regex");

    if re.is_match(&normalized) {
        ValidationResult {
            valid: true,
            warnings: Vec::new(),
            normalized_type: normalized,
        }
    } else {
        ValidationResult {
            valid: false,
            warnings: vec![format!(
                "Invalid MITRE technique ID '{}'. Expected format: T1234 or T1234.567",
                technique_id,
            )],
            normalized_type: normalized,
        }
    }
}

/// Map an evidence type to a Pyramid of Pain level string.
///
/// Returns the pyramid level name suitable for the `pyramid_level` field
/// in evidence records.
pub fn assign_pyramid_level(evidence_type: &str) -> &'static str {
    match evidence_type {
        "suspicious_ip" => "ip_addresses",
        "malicious_process" | "file_artifact" => "tools",
        "c2_communication" | "network_artifact" => "network_host_artifacts",
        "credential_access" | "authentication_event" => "hash_values",
        "lateral_movement" | "privilege_escalation" | "persistence_mechanism" => "ttps",
        "registry_artifact" | "log_entry" | "user_activity" => "network_host_artifacts",
        _ => "network_host_artifacts",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_evidence tests ──────────────────────────────────────

    #[test]
    fn valid_evidence_passes() {
        let result = validate_evidence("suspicious_ip", "192.168.58.10", "siem");
        assert!(result.valid);
        assert!(result.warnings.is_empty());
        assert_eq!(result.normalized_type, "suspicious_ip");
    }

    #[test]
    fn unknown_evidence_type_fails() {
        let result = validate_evidence("unknown_type", "some_value", "siem");
        assert!(!result.valid);
        assert!(result.warnings[0].contains("Unknown evidence type"));
    }

    #[test]
    fn empty_value_fails() {
        let result = validate_evidence("suspicious_ip", "", "siem");
        assert!(!result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("must not be empty")));
    }

    #[test]
    fn whitespace_only_value_fails() {
        let result = validate_evidence("suspicious_ip", "   ", "siem");
        assert!(!result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("must not be empty")));
    }

    #[test]
    fn empty_source_fails() {
        let result = validate_evidence("log_entry", "event data", "");
        assert!(!result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("source must not be empty")));
    }

    #[test]
    fn value_exceeding_max_length_fails() {
        let long_value = "x".repeat(MAX_VALUE_LENGTH + 1);
        let result = validate_evidence("log_entry", &long_value, "siem");
        assert!(!result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("exceeds maximum length")));
    }

    #[test]
    fn invalid_ip_for_suspicious_ip_warns() {
        let result = validate_evidence("suspicious_ip", "not-an-ip", "firewall");
        // Should still be valid (it is a warning, not a hard failure) -- but
        // ONLY if the type itself is known. suspicious_ip is known, so valid=true
        // with a warning about the IP format.
        assert!(result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("not a valid IP address")));
    }

    #[test]
    fn valid_ipv6_passes_for_suspicious_ip() {
        let result = validate_evidence("suspicious_ip", "::1", "ids");
        assert!(result.valid);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn normalizes_type_to_lowercase() {
        let result = validate_evidence("Suspicious_IP", "192.168.58.10", "siem");
        // Type is normalized but won't match known types in case-sensitive list,
        // however we normalize first, so "suspicious_ip" should match.
        assert!(result.valid);
        assert_eq!(result.normalized_type, "suspicious_ip");
    }

    #[test]
    fn non_ip_evidence_type_skips_ip_validation() {
        let result = validate_evidence("malicious_process", "evil.exe", "edr");
        assert!(result.valid);
        assert!(result.warnings.is_empty());
    }

    // ── validate_technique_id tests ──────────────────────────────────

    #[test]
    fn valid_technique_id_base() {
        let result = validate_technique_id("T1003");
        assert!(result.valid);
        assert_eq!(result.normalized_type, "T1003");
    }

    #[test]
    fn valid_technique_id_with_sub() {
        let result = validate_technique_id("T1003.001");
        assert!(result.valid);
        assert_eq!(result.normalized_type, "T1003.001");
    }

    #[test]
    fn technique_id_normalizes_to_uppercase() {
        let result = validate_technique_id("t1059");
        assert!(result.valid);
        assert_eq!(result.normalized_type, "T1059");
    }

    #[test]
    fn invalid_technique_id_fails() {
        let result = validate_technique_id("X1234");
        assert!(!result.valid);
        assert!(result.warnings[0].contains("Invalid MITRE technique ID"));
    }

    #[test]
    fn technique_id_wrong_digit_count_fails() {
        let result = validate_technique_id("T12");
        assert!(!result.valid);
    }

    #[test]
    fn technique_id_trailing_text_fails() {
        let result = validate_technique_id("T1003abc");
        assert!(!result.valid);
    }

    // ── assign_pyramid_level tests ──────────────────────────────────

    #[test]
    fn pyramid_level_ip() {
        assert_eq!(assign_pyramid_level("suspicious_ip"), "ip_addresses");
    }

    #[test]
    fn pyramid_level_tools() {
        assert_eq!(assign_pyramid_level("malicious_process"), "tools");
        assert_eq!(assign_pyramid_level("file_artifact"), "tools");
    }

    #[test]
    fn pyramid_level_ttps() {
        assert_eq!(assign_pyramid_level("lateral_movement"), "ttps");
        assert_eq!(assign_pyramid_level("privilege_escalation"), "ttps");
        assert_eq!(assign_pyramid_level("persistence_mechanism"), "ttps");
    }

    #[test]
    fn pyramid_level_hash_values() {
        assert_eq!(assign_pyramid_level("credential_access"), "hash_values");
        assert_eq!(assign_pyramid_level("authentication_event"), "hash_values");
    }

    #[test]
    fn pyramid_level_network_host() {
        assert_eq!(
            assign_pyramid_level("c2_communication"),
            "network_host_artifacts"
        );
        assert_eq!(
            assign_pyramid_level("network_artifact"),
            "network_host_artifacts"
        );
        assert_eq!(
            assign_pyramid_level("registry_artifact"),
            "network_host_artifacts"
        );
        assert_eq!(assign_pyramid_level("log_entry"), "network_host_artifacts");
        assert_eq!(
            assign_pyramid_level("user_activity"),
            "network_host_artifacts"
        );
    }

    #[test]
    fn pyramid_level_unknown_defaults() {
        assert_eq!(
            assign_pyramid_level("something_else"),
            "network_host_artifacts"
        );
    }
}
