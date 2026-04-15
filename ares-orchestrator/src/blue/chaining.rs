//! Evidence auto-chaining for blue team investigations.
//!
//! When a task result contains evidence of certain types, this module
//! automatically spawns follow-up investigation tasks. This mirrors
//! the Python `EVIDENCE_CHAIN_MAP` / `_process_result_chains` logic
//! in `result_processing.py`.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use tracing::{debug, info};

use ares_core::state::blue_task_queue::{BlueTaskMessage, BlueTaskQueue, BlueTaskResult};
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
static EVIDENCE_CHAIN_MAP: LazyLock<HashMap<&'static str, Vec<ChainAction>>> =
    LazyLock::new(|| {
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

        m
    });

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

/// Process a completed task result and dispatch any follow-up tasks
/// dictated by the evidence chain map.
///
/// Returns the list of newly dispatched task IDs (may be empty).
///
/// `dispatched_chains` is the per-investigation dedup set: each entry
/// is `"{evidence_type}:{task_type}"`. The caller must persist this
/// set across calls for the same investigation.
pub async fn process_task_result(
    result: &BlueTaskResult,
    task_queue: &mut BlueTaskQueue,
    investigation_id: &str,
    dispatched_chains: &mut HashSet<String>,
) -> Result<Vec<String>> {
    let payload = match (&result.success, &result.result) {
        (true, Some(val)) => val,
        _ => return Ok(Vec::new()),
    };

    let mut new_task_ids = Vec::new();

    // 1. Extract evidence types from the result payload.
    let evidence_types = extract_evidence_types(payload);

    for ev_type in &evidence_types {
        if let Some(actions) = EVIDENCE_CHAIN_MAP.get(ev_type.as_str()) {
            for action in actions {
                let dedup_key = format!("{ev_type}:{}", action.task_type);
                if dispatched_chains.contains(&dedup_key) {
                    debug!(
                        investigation_id,
                        evidence_type = ev_type.as_str(),
                        task_type = action.task_type,
                        "Skipping duplicate chain dispatch"
                    );
                    continue;
                }

                let task_id =
                    dispatch_chain_task(task_queue, investigation_id, action, ev_type).await?;

                dispatched_chains.insert(dedup_key);
                new_task_ids.push(task_id);
            }
        }
    }

    // 2. Check for critical user escalation.
    if let Some(reason) = should_escalate(result) {
        let escalation_dedup = "escalation:critical_user".to_string();
        if !dispatched_chains.contains(&escalation_dedup) {
            info!(
                investigation_id,
                reason = reason.as_str(),
                "Auto-escalating: critical user detected"
            );

            // Dispatch both golden ticket detection and DCSync detection.
            for (task_type, focus) in [
                (
                    "threat_hunt",
                    "golden ticket detection for critical user activity",
                ),
                ("threat_hunt", "DCSync detection for critical user activity"),
            ] {
                let sub_dedup = format!("escalation:{task_type}:{focus}");
                if dispatched_chains.contains(&sub_dedup) {
                    continue;
                }

                let action = ChainAction {
                    task_type,
                    role: BlueAgentRole::ThreatHunter,
                    focus,
                };
                let task_id =
                    dispatch_chain_task(task_queue, investigation_id, &action, "critical_user")
                        .await?;
                dispatched_chains.insert(sub_dedup);
                new_task_ids.push(task_id);
            }

            dispatched_chains.insert(escalation_dedup);
        }
    }

    if !new_task_ids.is_empty() {
        info!(
            investigation_id,
            count = new_task_ids.len(),
            task_ids = ?new_task_ids,
            "Auto-chained follow-up tasks"
        );
    }

    Ok(new_task_ids)
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

    // MITRE technique mapping (mirrors Python _process_result_chains)
    if let Some(arr) = payload.get("techniques_found").and_then(|v| v.as_array()) {
        for tech in arr {
            if let Some(tech_str) = tech.as_str() {
                let lower = tech_str.to_lowercase();
                if lower.contains("t1558") {
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

/// Dispatch a single chained follow-up task to the blue task queue.
async fn dispatch_chain_task(
    task_queue: &mut BlueTaskQueue,
    investigation_id: &str,
    action: &ChainAction,
    evidence_type: &str,
) -> Result<String> {
    let task_id = format!(
        "chain_{}_{}_{}_{}",
        action.task_type,
        evidence_type,
        &investigation_id.chars().take(8).collect::<String>(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );

    let params = serde_json::json!({
        "chained_from_evidence": evidence_type,
        "focus": action.focus,
        "auto_chained": true,
    });

    let task = BlueTaskMessage {
        task_id: task_id.clone(),
        investigation_id: investigation_id.to_string(),
        task_type: action.task_type.to_string(),
        role: action.role.as_str().to_string(),
        params,
        created_at: Utc::now().to_rfc3339(),
    };

    task_queue.submit_task(&task).await?;

    info!(
        task_id = %task_id,
        task_type = action.task_type,
        evidence_type,
        focus = action.focus,
        investigation_id,
        "Dispatched chained follow-up task"
    );

    Ok(task_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_evidence_types_from_evidence_types_array() {
        let payload = json!({
            "evidence_types": ["suspicious_ip", "lateral_movement"]
        });
        let types = extract_evidence_types(&payload);
        assert_eq!(types, vec!["suspicious_ip", "lateral_movement"]);
    }

    #[test]
    fn test_extract_evidence_types_from_evidence_objects() {
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
    fn test_extract_evidence_types_from_techniques() {
        let payload = json!({
            "techniques_found": ["T1558.003", "T1021.002"]
        });
        let types = extract_evidence_types(&payload);
        assert_eq!(types, vec!["credential_access", "lateral_movement"]);
    }

    #[test]
    fn test_extract_evidence_types_dedup() {
        let payload = json!({
            "evidence_types": ["lateral_movement"],
            "techniques_found": ["T1550.002"]
        });
        let types = extract_evidence_types(&payload);
        // "lateral_movement" appears from both sources but should only be listed once
        assert_eq!(types, vec!["lateral_movement"]);
    }

    #[test]
    fn test_should_escalate_critical_user_in_users_investigated() {
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
    fn test_should_escalate_critical_user_in_highlights() {
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
    fn test_should_escalate_high_severity() {
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
    fn test_should_escalate_schema_admins() {
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
    fn test_should_not_escalate_normal_result() {
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
    fn test_should_not_escalate_failed_result() {
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
    fn test_should_escalate_findings_mention() {
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
    fn test_chain_map_coverage() {
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
    fn test_privilege_escalation_dispatches_two_actions() {
        let actions = EVIDENCE_CHAIN_MAP.get("privilege_escalation").unwrap();
        assert_eq!(actions.len(), 2);
        let task_types: Vec<&str> = actions.iter().map(|a| a.task_type).collect();
        assert!(task_types.contains(&"lateral_analysis"));
        assert!(task_types.contains(&"threat_hunt"));
    }

    #[test]
    fn test_critical_users_set() {
        assert!(CRITICAL_USERS.contains("krbtgt"));
        assert!(CRITICAL_USERS.contains("administrator"));
        assert!(CRITICAL_USERS.contains("domain admins"));
        assert!(CRITICAL_USERS.contains("enterprise admins"));
        assert!(CRITICAL_USERS.contains("schema admins"));
        assert!(!CRITICAL_USERS.contains("normaluser"));
    }
}
