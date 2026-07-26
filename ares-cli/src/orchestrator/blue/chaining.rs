//! Evidence auto-chaining for blue team investigations.
//!
//! When a task result contains evidence of certain types, this module
//! automatically spawns follow-up investigation tasks.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use serde_json::Value;
use tracing::info;

use ares_core::state::blue_task_queue::BlueTaskResult;
use ares_llm::tool_registry::blue::BlueAgentRole;

// ── Static configuration ───────────────────────────────────────────

/// Follow-up action descriptor produced by evidence chaining.
#[derive(Debug, Clone)]
struct ChainAction {
    /// Task type to dispatch (e.g. `"threat_hunt"`, `"lateral_analysis"`).
    task_type: &'static str,
    /// Worker role that handles this task type.
    role: BlueAgentRole,
    /// Human-readable description embedded in the task params.
    focus: &'static str,
}

/// Evidence type to follow-up actions mapping.
///
/// When a task result contains an evidence type key, the corresponding
/// actions are dispatched as follow-up sub-tasks (subject to dedup).
static EVIDENCE_CHAIN_MAP: LazyLock<HashMap<&'static str, Vec<ChainAction>>> = LazyLock::new(
    || {
        let mut m = HashMap::new();

        m.insert(
            "suspicious_ip",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "IP correlation analysis",
            }],
        );

        m.insert(
            "malicious_process",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "process ancestry and execution chain analysis",
            }],
        );

        m.insert(
            "lateral_movement",
            vec![ChainAction {
                task_type: "lateral_analysis",
                role: BlueAgentRole::LateralAnalyst,
                focus: "lateral movement path reconstruction",
            }],
        );

        m.insert(
            "credential_access",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "credential abuse pattern detection",
            }],
        );

        m.insert(
            "persistence_mechanism",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "persistence indicator sweep",
            }],
        );

        m.insert(
            "c2_communication",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "network IOC and C2 beacon analysis",
            }],
        );

        m.insert(
            "privilege_escalation",
            vec![
                ChainAction {
                    task_type: "lateral_analysis",
                    role: BlueAgentRole::LateralAnalyst,
                    focus: "post-escalation lateral movement assessment",
                },
                ChainAction {
                    task_type: "threat_hunt",
                    role: BlueAgentRole::ThreatHunter,
                    focus: "privilege escalation technique detection",
                },
            ],
        );

        // ── Crown-jewel evidence types (the paths blue historically missed) ──
        // Focus strings are actionable: event IDs to query and fields to check,
        // not English blurbs — the sub-agent gets them verbatim as its focus.

        m.insert(
            "certificate_abuse",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "ADCS ESC1/4/8 chain: run detect_esc1_attack + detect_adcs_exploitation; \
                        correlate 4886 (request) with 4887 (issue); flag requester != SubjectUserName; \
                        4768 PreAuthType=17 (PKINIT cert auth)",
            }],
        );

        m.insert(
            "sid_history",
            vec![ChainAction {
                task_type: "threat_hunt",
                role: BlueAgentRole::ThreatHunter,
                focus: "inter-realm SID history: run detect_cross_realm_tgs + detect_sid_history_extrasid; \
                        4769 ServiceName=krbtgt/<foreign_realm>; child-domain krbtgt principal used against \
                        the parent DC; 4662/4627 with Enterprise/Domain-Admin RIDs (-519/-512) in ExtraSids",
            }],
        );

        m.insert(
            "cross_forest",
            vec![ChainAction {
                task_type: "lateral_analysis",
                role: BlueAgentRole::LateralAnalyst,
                focus: "trust-key material used across a forest boundary: run detect_trust_key_exfil; \
                        DC machine-account (DOMAIN$) auth (4776/4624 type 3) into a foreign domain; \
                        drsuapi/1131f6aa replication of a trust account",
            }],
        );

        m.insert(
            "asrep_roast",
            vec![ChainAction {
                task_type: "user_investigation",
                role: BlueAgentRole::ThreatHunter,
                focus: "preauth-disabled account activity post-crack: run detect_asrep_roasting; \
                        4768 PreAuthType=0 (NOT the 0x17 Kerberoast pattern); then trace the roasted \
                        account's logons/lateral use after the crack window",
            }],
        );

        m
    },
);

/// Users whose appearance in results triggers automatic escalation.
static CRITICAL_USERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut s = HashSet::new();
    s.insert("krbtgt");
    s.insert("administrator");
    s.insert("domain admins");
    s.insert("enterprise admins");
    s.insert("schema admins");
    s
});

// ── Public API ─────────────────────────────────────────────────────

/// A follow-up hunt the chain map wants to run, resolved from evidence.
///
/// The planner returns these; the caller executes them (inline in this
/// deployment, since there is no blue-task worker fleet to consume an
/// enqueued task). Kept `Clone` so callers can log/collect them freely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChain {
    /// Evidence type that triggered this follow-up (for logging / prompts).
    pub evidence_type: String,
    /// Task type label (e.g. `"threat_hunt"`, `"lateral_analysis"`).
    pub task_type: &'static str,
    /// Worker role that should run the follow-up.
    pub role: BlueAgentRole,
    /// Actionable focus string handed to the sub-agent verbatim.
    pub focus: &'static str,
}

/// Escalation hunts fired when a critical user (krbtgt / DA) shows up. These
/// look UPSTREAM for the path that produced the compromise — including the
/// ADCS cert path, which blue historically never checked.
const ESCALATION_HUNTS: &[(&str, BlueAgentRole, &str)] = &[
    (
        "threat_hunt",
        BlueAgentRole::ThreatHunter,
        "DCSync for critical-user activity: run detect_dcsync + detect_dcsync_replication; \
         4662 replication by a user account. Golden ticket (T1558.001) is already decided by \
         the baseline sweep's 4769-without-4768 correlation — do not re-derive it from \
         single-event fields such as a krbtgt ServiceName or a non-DC source IP, which match \
         ordinary Kerberos traffic",
    ),
    (
        "threat_hunt",
        BlueAgentRole::ThreatHunter,
        "UPSTREAM ADCS cert path for the critical user: run detect_esc1_attack + \
         detect_adcs_exploitation; 4886/4887 where requester != SubjectUserName; PKINIT 4768",
    ),
    (
        "threat_hunt",
        BlueAgentRole::ThreatHunter,
        "UPSTREAM cross-realm forge: run detect_cross_realm_tgs + detect_sid_history_extrasid; \
         krbtgt/<foreign_realm> TGS, ExtraSids with -519/-512 RIDs",
    ),
];

/// Resolve the follow-up hunts implied by a result payload, honoring the
/// per-investigation dedup set (`"{evidence_type}:{task_type}"` entries).
///
/// Pure and synchronous — it does not dispatch. The caller runs the returned
/// hunts. `dispatched_chains` is mutated so repeated calls for the same
/// investigation don't re-plan the same follow-up.
pub fn plan_chain_actions(
    payload: &Value,
    dispatched_chains: &mut HashSet<String>,
) -> Vec<PlannedChain> {
    let mut planned = Vec::new();
    for ev_type in extract_evidence_types(payload) {
        if let Some(actions) = EVIDENCE_CHAIN_MAP.get(ev_type.as_str()) {
            for action in actions {
                let dedup_key = format!("{ev_type}:{}", action.task_type);
                if dispatched_chains.insert(dedup_key) {
                    planned.push(PlannedChain {
                        evidence_type: ev_type.clone(),
                        task_type: action.task_type,
                        role: action.role,
                        focus: action.focus,
                    });
                }
            }
        }
    }
    planned
}

/// Plan all follow-up hunts for a completed task result: evidence-driven
/// chains plus critical-user escalation hunts. Returns the deduped set of
/// hunts to run.
pub fn plan_task_result(
    result: &BlueTaskResult,
    dispatched_chains: &mut HashSet<String>,
) -> Vec<PlannedChain> {
    let (true, Some(payload)) = (&result.success, &result.result) else {
        return Vec::new();
    };

    let mut planned = plan_chain_actions(payload, dispatched_chains);

    // Critical-user escalation: look upstream (golden/DCSync + ADCS + cross-realm).
    if let Some(reason) = should_escalate(result) {
        if dispatched_chains.insert("escalation:critical_user".to_string()) {
            info!(
                reason = reason.as_str(),
                "Auto-escalation: planning upstream hunts"
            );
            for &(task_type, role, focus) in ESCALATION_HUNTS {
                let sub_dedup = format!("escalation:{task_type}:{focus}");
                if dispatched_chains.insert(sub_dedup) {
                    planned.push(PlannedChain {
                        evidence_type: "critical_user".to_string(),
                        task_type,
                        role,
                        focus,
                    });
                }
            }
        }
    }

    planned
}

/// Check whether a task result warrants automatic escalation.
///
/// Returns `Some(reason)` if escalation is warranted, `None` otherwise.
pub fn should_escalate(result: &BlueTaskResult) -> Option<String> {
    let payload = result.result.as_ref()?;

    // Check users_investigated array for critical user names.
    if let Some(users) = payload.get("users_investigated").and_then(|v| v.as_array()) {
        for user in users {
            if let Some(name) = user.as_str() {
                let lower = name.to_lowercase();
                let trimmed = lower.trim();
                if CRITICAL_USERS.contains(trimmed) {
                    return Some(format!("Critical user detected: {name}"));
                }
            }
        }
    }

    // Check evidence_highlights for critical user mentions.
    if let Some(highlights) = payload
        .get("evidence_highlights")
        .and_then(|v| v.as_array())
    {
        for highlight in highlights {
            if let Some(text) = highlight.as_str() {
                let lower = text.to_lowercase();
                for &critical in CRITICAL_USERS.iter() {
                    if lower.contains(critical) {
                        return Some(format!("Critical user '{critical}' mentioned in evidence"));
                    }
                }
            }
        }
    }

    // Check for high-severity indicators in the result.
    if let Some(severity) = payload.get("severity").and_then(|v| v.as_str()) {
        let sev_lower = severity.to_lowercase();
        if sev_lower == "critical" || sev_lower == "high" {
            return Some(format!("High severity result: {severity}"));
        }
    }

    // Check findings text for critical user mentions.
    if let Some(findings) = payload.get("findings").and_then(|v| v.as_str()) {
        let lower = findings.to_lowercase();
        for &critical in CRITICAL_USERS.iter() {
            if lower.contains(critical) {
                return Some(format!("Critical user '{critical}' mentioned in findings"));
            }
        }
    }

    None
}

// ── Internals ──────────────────────────────────────────────────────

/// Extract evidence type strings from a result payload.
///
/// Looks for:
///   - `evidence_types`: `["suspicious_ip", ...]`
///   - `evidence`: `[{ "type": "suspicious_ip", ... }, ...]`
///   - `techniques_found`: maps MITRE technique IDs to evidence types
fn extract_evidence_types(payload: &Value) -> Vec<String> {
    let mut types = Vec::new();

    // Direct evidence_types array
    if let Some(arr) = payload.get("evidence_types").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                types.push(s.to_lowercase());
            }
        }
    }

    // Evidence objects with a "type" field
    if let Some(arr) = payload.get("evidence").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(ev_type) = item.get("type").and_then(|v| v.as_str()) {
                types.push(ev_type.to_lowercase());
            }
        }
    }

    // MITRE technique mapping
    if let Some(arr) = payload.get("techniques_found").and_then(|v| v.as_array()) {
        for tech in arr {
            if let Some(tech_str) = tech.as_str() {
                let lower = tech_str.to_lowercase();
                // Specific sub-techniques MUST be matched before their generic
                // parents (e.g. t1558.004 before t1558) so the crown-jewel paths
                // route to their dedicated chains instead of the generic bucket.
                if lower.contains("t1558.004") {
                    // AS-REP Roasting -> asrep_roast (preauth-disabled hunt)
                    types.push("asrep_roast".to_string());
                } else if lower.contains("t1134.005") {
                    // SID-History (inter-realm / child->parent forge) -> sid_history
                    types.push("sid_history".to_string());
                } else if lower.contains("t1649")
                    || lower.contains("adcs")
                    || lower.contains("certipy")
                    || lower.contains("certificate")
                {
                    // ADCS / certificate abuse (ESC1/4/8) -> certificate_abuse
                    types.push("certificate_abuse".to_string());
                } else if lower.contains("t1558") {
                    // Kerberoasting -> credential_access
                    types.push("credential_access".to_string());
                } else if lower.contains("t1003") {
                    // OS Credential Dumping -> credential_access
                    types.push("credential_access".to_string());
                } else if lower.contains("t1550") {
                    // Use Alternate Authentication Material -> lateral_movement
                    types.push("lateral_movement".to_string());
                } else if lower.contains("t1021") {
                    // Remote Services -> lateral_movement
                    types.push("lateral_movement".to_string());
                } else if lower.contains("t1053") || lower.contains("t1547") {
                    // Scheduled Task / Boot Autostart -> persistence_mechanism
                    types.push("persistence_mechanism".to_string());
                } else if lower.contains("t1071") || lower.contains("t1105") {
                    // Application Layer Protocol / Ingress Tool Transfer -> c2
                    types.push("c2_communication".to_string());
                } else if lower.contains("t1068") || lower.contains("t1134") {
                    // Exploitation for Privilege Escalation / Access Token Manipulation
                    types.push("privilege_escalation".to_string());
                }
            }
        }
    }

    // Dedup while preserving order
    let mut seen = HashSet::new();
    types.retain(|t| seen.insert(t.clone()));

    types
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_evidence_types_from_evidence_types_array() {
        let payload = json!({
            "evidence_types": ["suspicious_ip", "lateral_movement"]
        });
        let types = extract_evidence_types(&payload);
        assert_eq!(types, vec!["suspicious_ip", "lateral_movement"]);
    }

    #[test]
    fn extract_evidence_types_from_evidence_objects() {
        let payload = json!({
            "evidence": [
                { "type": "Credential_Access", "value": "hash123" },
                { "type": "c2_communication", "value": "beacon" }
            ]
        });
        let types = extract_evidence_types(&payload);
        assert_eq!(types, vec!["credential_access", "c2_communication"]);
    }

    #[test]
    fn extract_evidence_types_from_techniques() {
        let payload = json!({
            "techniques_found": ["T1558.003", "T1021.002"]
        });
        let types = extract_evidence_types(&payload);
        assert_eq!(types, vec!["credential_access", "lateral_movement"]);
    }

    #[test]
    fn extract_evidence_types_dedup() {
        let payload = json!({
            "evidence_types": ["lateral_movement"],
            "techniques_found": ["T1550.002"]
        });
        let types = extract_evidence_types(&payload);
        // "lateral_movement" appears from both sources but should only be listed once
        assert_eq!(types, vec!["lateral_movement"]);
    }

    #[test]
    fn should_escalate_critical_user_in_users_investigated() {
        let result = BlueTaskResult {
            task_id: "t1".into(),
            investigation_id: "inv1".into(),
            success: true,
            result: Some(json!({
                "users_investigated": ["krbtgt", "normaluser"]
            })),
            error: None,
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        let reason = should_escalate(&result);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("krbtgt"));
    }

    #[test]
    fn should_escalate_critical_user_in_highlights() {
        let result = BlueTaskResult {
            task_id: "t2".into(),
            investigation_id: "inv1".into(),
            success: true,
            result: Some(json!({
                "evidence_highlights": ["Found Administrator logon from unusual host"]
            })),
            error: None,
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        let reason = should_escalate(&result);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("administrator"));
    }

    #[test]
    fn should_escalate_high_severity() {
        let result = BlueTaskResult {
            task_id: "t3".into(),
            investigation_id: "inv1".into(),
            success: true,
            result: Some(json!({
                "severity": "critical",
                "summary": "Active data exfiltration"
            })),
            error: None,
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        let reason = should_escalate(&result);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("critical"));
    }

    #[test]
    fn should_escalate_schema_admins() {
        let result = BlueTaskResult {
            task_id: "t4".into(),
            investigation_id: "inv1".into(),
            success: true,
            result: Some(json!({
                "users_investigated": ["Schema Admins"]
            })),
            error: None,
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        let reason = should_escalate(&result);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Schema Admins"));
    }

    #[test]
    fn should_not_escalate_normal_result() {
        let result = BlueTaskResult {
            task_id: "t5".into(),
            investigation_id: "inv1".into(),
            success: true,
            result: Some(json!({
                "users_investigated": ["svc_backup", "jsmith"],
                "severity": "low"
            })),
            error: None,
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        assert!(should_escalate(&result).is_none());
    }

    #[test]
    fn should_not_escalate_failed_result() {
        let result = BlueTaskResult {
            task_id: "t6".into(),
            investigation_id: "inv1".into(),
            success: false,
            result: None,
            error: Some("timeout".into()),
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        assert!(should_escalate(&result).is_none());
    }

    #[test]
    fn should_escalate_findings_mention() {
        let result = BlueTaskResult {
            task_id: "t7".into(),
            investigation_id: "inv1".into(),
            success: true,
            result: Some(json!({
                "findings": "Enterprise Admins group membership was modified"
            })),
            error: None,
            completed_at: "2026-04-08T00:00:00Z".into(),
            worker_agent: Some("hunter1".into()),
        };
        let reason = should_escalate(&result);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("enterprise admins"));
    }

    #[test]
    fn chain_map_coverage() {
        // Verify all expected evidence types are present in the map
        let expected = [
            "suspicious_ip",
            "malicious_process",
            "lateral_movement",
            "credential_access",
            "persistence_mechanism",
            "c2_communication",
            "privilege_escalation",
        ];
        for ev_type in &expected {
            assert!(
                EVIDENCE_CHAIN_MAP.contains_key(ev_type),
                "Missing evidence type in chain map: {ev_type}"
            );
        }
    }

    #[test]
    fn privilege_escalation_dispatches_two_actions() {
        let actions = EVIDENCE_CHAIN_MAP.get("privilege_escalation").unwrap();
        assert_eq!(actions.len(), 2);
        let task_types: Vec<&str> = actions.iter().map(|a| a.task_type).collect();
        assert!(task_types.contains(&"lateral_analysis"));
        assert!(task_types.contains(&"threat_hunt"));
    }

    #[test]
    fn critical_users_set() {
        assert!(CRITICAL_USERS.contains("krbtgt"));
        assert!(CRITICAL_USERS.contains("administrator"));
        assert!(CRITICAL_USERS.contains("domain admins"));
        assert!(CRITICAL_USERS.contains("enterprise admins"));
        assert!(CRITICAL_USERS.contains("schema admins"));
        assert!(!CRITICAL_USERS.contains("normaluser"));
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    use serde_json::json;

    // --- extract_evidence_types MITRE technique paths ---

    #[test]
    fn technique_t1003_maps_to_credential_access() {
        // T1003.* — OS Credential Dumping
        let payload = json!({ "techniques_found": ["T1003.001"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"credential_access".to_string()),
            "T1003 should map to credential_access"
        );
    }

    #[test]
    fn technique_t1053_maps_to_persistence_mechanism() {
        // T1053 — Scheduled Task/Job
        let payload = json!({ "techniques_found": ["T1053.005"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"persistence_mechanism".to_string()),
            "T1053 should map to persistence_mechanism"
        );
    }

    #[test]
    fn technique_t1547_maps_to_persistence_mechanism() {
        // T1547 — Boot or Logon Autostart Execution
        let payload = json!({ "techniques_found": ["T1547.001"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"persistence_mechanism".to_string()),
            "T1547 should map to persistence_mechanism"
        );
    }

    #[test]
    fn technique_t1071_maps_to_c2_communication() {
        // T1071 — Application Layer Protocol (C2)
        let payload = json!({ "techniques_found": ["T1071.001"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"c2_communication".to_string()),
            "T1071 should map to c2_communication"
        );
    }

    #[test]
    fn technique_t1105_maps_to_c2_communication() {
        // T1105 — Ingress Tool Transfer (C2-adjacent)
        let payload = json!({ "techniques_found": ["T1105"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"c2_communication".to_string()),
            "T1105 should map to c2_communication"
        );
    }

    #[test]
    fn technique_t1068_maps_to_privilege_escalation() {
        // T1068 — Exploitation for Privilege Escalation
        let payload = json!({ "techniques_found": ["T1068"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"privilege_escalation".to_string()),
            "T1068 should map to privilege_escalation"
        );
    }

    #[test]
    fn technique_t1134_maps_to_privilege_escalation() {
        // T1134 — Access Token Manipulation
        let payload = json!({ "techniques_found": ["T1134.001"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.contains(&"privilege_escalation".to_string()),
            "T1134 should map to privilege_escalation"
        );
    }

    #[test]
    fn technique_unknown_produces_no_types() {
        // An unknown technique ID should not produce any evidence type.
        let payload = json!({ "techniques_found": ["T9999"] });
        let types = extract_evidence_types(&payload);
        assert!(
            types.is_empty(),
            "Unknown technique should not produce evidence types, got {types:?}"
        );
    }

    #[test]
    fn empty_techniques_found_array_produces_no_types() {
        let payload = json!({ "techniques_found": [] });
        let types = extract_evidence_types(&payload);
        assert!(types.is_empty());
    }

    #[test]
    fn missing_all_evidence_fields_produces_no_types() {
        let payload = json!({ "summary": "nothing here" });
        let types = extract_evidence_types(&payload);
        assert!(types.is_empty());
    }

    #[test]
    fn evidence_object_without_type_field_is_skipped() {
        let payload = json!({
            "evidence": [
                { "value": "192.168.58.10" },
            ]
        });
        let types = extract_evidence_types(&payload);
        assert!(types.is_empty());
    }
}

#[cfg(test)]
mod crown_jewel_tests {
    use super::*;
    use serde_json::json;

    fn result_with(payload: serde_json::Value) -> BlueTaskResult {
        BlueTaskResult {
            task_id: "t".into(),
            investigation_id: "inv".into(),
            success: true,
            result: Some(payload),
            error: None,
            completed_at: "2026-07-07T00:00:00Z".into(),
            worker_agent: Some("hunter".into()),
        }
    }

    // --- extract_evidence_types: crown-jewel technique routing ---

    #[test]
    fn t1649_maps_to_certificate_abuse() {
        let types = extract_evidence_types(&json!({ "techniques_found": ["T1649"] }));
        assert_eq!(types, vec!["certificate_abuse"]);
    }

    #[test]
    fn adcs_keyword_maps_to_certificate_abuse() {
        let types = extract_evidence_types(&json!({ "techniques_found": ["ADCS ESC1 abuse"] }));
        assert_eq!(types, vec!["certificate_abuse"]);
    }

    #[test]
    fn t1134_005_maps_to_sid_history_not_priv_esc() {
        // The specific sub-technique must beat the generic t1134 parent.
        let types = extract_evidence_types(&json!({ "techniques_found": ["T1134.005"] }));
        assert_eq!(types, vec!["sid_history"]);
    }

    #[test]
    fn generic_t1134_still_maps_to_privilege_escalation() {
        let types = extract_evidence_types(&json!({ "techniques_found": ["T1134.001"] }));
        assert_eq!(types, vec!["privilege_escalation"]);
    }

    #[test]
    fn t1558_004_maps_to_asrep_roast_not_credential_access() {
        let types = extract_evidence_types(&json!({ "techniques_found": ["T1558.004"] }));
        assert_eq!(types, vec!["asrep_roast"]);
    }

    #[test]
    fn generic_t1558_still_maps_to_credential_access() {
        let types = extract_evidence_types(&json!({ "techniques_found": ["T1558.003"] }));
        assert_eq!(types, vec!["credential_access"]);
    }

    // --- chain map has the crown-jewel entries ---

    #[test]
    fn chain_map_has_crown_jewel_entries() {
        for ev in [
            "certificate_abuse",
            "sid_history",
            "cross_forest",
            "asrep_roast",
        ] {
            assert!(
                EVIDENCE_CHAIN_MAP.contains_key(ev),
                "chain map missing crown-jewel evidence type: {ev}"
            );
        }
    }

    // --- plan_chain_actions / plan_task_result ---

    #[test]
    fn plan_chain_actions_for_certificate_abuse() {
        let mut seen = HashSet::new();
        let planned = plan_chain_actions(&json!({ "techniques_found": ["T1649"] }), &mut seen);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].evidence_type, "certificate_abuse");
        assert_eq!(planned[0].role, BlueAgentRole::ThreatHunter);
        assert!(planned[0].focus.contains("detect_esc1_attack"));
    }

    #[test]
    fn plan_chain_actions_cross_forest_direct_evidence_type() {
        let mut seen = HashSet::new();
        let planned = plan_chain_actions(&json!({ "evidence_types": ["cross_forest"] }), &mut seen);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].role, BlueAgentRole::LateralAnalyst);
    }

    #[test]
    fn plan_chain_actions_dedups_across_calls() {
        let mut seen = HashSet::new();
        let p1 = plan_chain_actions(&json!({ "techniques_found": ["T1134.005"] }), &mut seen);
        assert_eq!(p1.len(), 1, "first call plans sid_history hunt");
        let p2 = plan_chain_actions(&json!({ "techniques_found": ["T1134.005"] }), &mut seen);
        assert!(p2.is_empty(), "second call is deduped by dispatched_chains");
    }

    #[test]
    fn plan_task_result_escalation_includes_adcs_upstream() {
        let mut seen = HashSet::new();
        let result = result_with(json!({ "users_investigated": ["krbtgt"] }));
        let planned = plan_task_result(&result, &mut seen);
        // Escalation must fire an upstream ADCS hunt, not only golden/DCSync.
        assert!(
            planned
                .iter()
                .any(|p| p.focus.contains("ADCS") && p.focus.contains("detect_esc1_attack")),
            "escalation should plan an upstream ADCS hunt, got: {:?}",
            planned.iter().map(|p| p.focus).collect::<Vec<_>>()
        );
        // And a cross-realm forge hunt.
        assert!(
            planned
                .iter()
                .any(|p| p.focus.contains("detect_cross_realm_tgs")),
            "escalation should plan a cross-realm hunt"
        );
    }

    #[test]
    fn plan_task_result_ignores_failed_result() {
        let mut seen = HashSet::new();
        let result = BlueTaskResult {
            task_id: "t".into(),
            investigation_id: "inv".into(),
            success: false,
            result: None,
            error: Some("boom".into()),
            completed_at: "2026-07-07T00:00:00Z".into(),
            worker_agent: None,
        };
        assert!(plan_task_result(&result, &mut seen).is_empty());
    }
}
