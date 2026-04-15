//! `BlueTeamReportGenerator::generate_from_states` — build a report from raw investigation states.

use std::collections::{HashMap, HashSet};

use chrono::Utc;

use crate::models::SharedBlueTeamState;

use super::super::types::BlueTeamReportInput;
use super::BlueTeamReportGenerator;

impl BlueTeamReportGenerator {
    /// Generate a comprehensive blue team report from one or more `SharedBlueTeamState` objects.
    ///
    /// This is the Rust equivalent of `BlueTeamReportGenerator.generate()` in Python,
    /// converting investigation states into the report input format automatically.
    pub fn generate_from_states(
        &self,
        operation_id: &str,
        states: &[SharedBlueTeamState],
        queries_by_inv: &HashMap<String, Vec<serde_json::Value>>,
    ) -> Result<String, tera::Error> {
        if states.is_empty() {
            let input = BlueTeamReportInput {
                operation_id: operation_id.to_string(),
                ..Default::default()
            };
            return self.generate(&input);
        }

        // Compute time bounds
        let started_at = states
            .iter()
            .filter_map(|s| chrono::DateTime::parse_from_rfc3339(&s.started_at).ok())
            .min()
            .map(|dt| {
                dt.with_timezone(&Utc)
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string()
            })
            .unwrap_or_default();
        let now = Utc::now();
        let completed_at = now.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        // Duration from earliest start to now
        let earliest = states
            .iter()
            .filter_map(|s| chrono::DateTime::parse_from_rfc3339(&s.started_at).ok())
            .min();
        let duration = earliest
            .map(|start| {
                let secs = (now - start.with_timezone(&Utc)).num_seconds().max(0) as u64;
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                format!("{h}:{m:02}:{s:02}")
            })
            .unwrap_or_else(|| "0:00:00".to_string());

        // Aggregate across all investigations
        let mut all_evidence: Vec<&crate::models::Evidence> = Vec::new();
        let mut seen_evidence_ids: HashSet<&str> = HashSet::new();
        let mut all_techniques: HashSet<String> = HashSet::new();
        let mut all_tactics: HashSet<String> = HashSet::new();
        let mut all_hosts: HashSet<String> = HashSet::new();
        let mut all_users: HashSet<String> = HashSet::new();
        let mut all_recommendations: Vec<String> = Vec::new();
        let mut seen_recs: HashSet<String> = HashSet::new();
        let mut technique_names: HashMap<String, String> = HashMap::new();
        let mut attack_synopses: Vec<String> = Vec::new();
        let mut escalation_count: usize = 0;
        let mut alert_count: usize = 0;

        for state in states {
            for ev in &state.evidence {
                if seen_evidence_ids.insert(&ev.id) {
                    all_evidence.push(ev);
                }
            }
            all_techniques.extend(state.identified_techniques.iter().cloned());
            all_tactics.extend(state.identified_tactics.iter().cloned());
            all_hosts.extend(state.queried_hosts.iter().cloned());
            all_users.extend(state.queried_users.iter().cloned());
            technique_names.extend(
                state
                    .technique_names
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            );
            for rec in &state.recommendations {
                if seen_recs.insert(rec.clone()) {
                    all_recommendations.push(rec.clone());
                }
            }
            if let Some(ref synopsis) = state.attack_synopsis {
                attack_synopses.push(synopsis.clone());
            }
            if state.escalated {
                escalation_count += 1;
            }
            if !state.alert.is_null() {
                alert_count += 1;
            }
        }

        // Pyramid distribution
        let mut pyramid_distribution: HashMap<i32, i32> = HashMap::new();
        for ev in &all_evidence {
            *pyramid_distribution.entry(ev.pyramid_level).or_insert(0) += 1;
        }

        let highest_pyramid_level = all_evidence
            .iter()
            .map(|e| e.pyramid_level)
            .max()
            .unwrap_or(0);
        let ttp_count = all_evidence.iter().filter(|e| e.pyramid_level == 6).count();

        // Build evidence_by_level
        let mut evidence_by_level: HashMap<i32, Vec<serde_json::Value>> = HashMap::new();
        for ev in &all_evidence {
            let val = ev.value.clone();
            let truncated = if val.len() > 80 {
                let mut end = 80;
                while !val.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &val[..end])
            } else {
                val
            };
            let techniques: Vec<String> = ev.mitre_techniques.iter().take(3).cloned().collect();
            evidence_by_level
                .entry(ev.pyramid_level)
                .or_default()
                .push(serde_json::json!({
                    "id": ev.id,
                    "type": ev.evidence_type,
                    "value": truncated,
                    "source": ev.source,
                    "techniques": techniques,
                    "confidence": ev.confidence,
                }));
        }

        // Build alert summaries
        let alert_summaries: Vec<serde_json::Value> = states
            .iter()
            .map(|inv| {
                let alert = if inv.alert.is_object() {
                    &inv.alert
                } else {
                    &serde_json::Value::Null
                };
                let labels = alert.get("labels").unwrap_or(&serde_json::Value::Null);
                let highest = inv
                    .evidence
                    .iter()
                    .map(|e| e.pyramid_level)
                    .max()
                    .unwrap_or(0);
                serde_json::json!({
                    "investigation_id": inv.investigation_id,
                    "alert_name": labels.get("alertname").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    "severity": labels.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "escalated": inv.escalated,
                    "evidence_count": inv.evidence.len(),
                    "highest_pyramid_level": highest,
                    "techniques": inv.identified_techniques,
                })
            })
            .collect();

        // Build timeline from all investigations
        let mut all_timeline: Vec<&crate::models::TimelineEvent> = Vec::new();
        for state in states {
            all_timeline.extend(state.timeline.iter());
        }
        all_timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let timeline: Vec<serde_json::Value> = all_timeline
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "description": e.description,
                    "mitre_techniques": e.mitre_techniques,
                    "confidence": e.confidence,
                })
            })
            .collect();

        // Build techniques list
        let mut sorted_techniques: Vec<String> = all_techniques.iter().cloned().collect();
        sorted_techniques.sort();
        let techniques: Vec<serde_json::Value> = sorted_techniques
            .iter()
            .map(|tech_id| {
                serde_json::json!({
                    "id": tech_id,
                    "name": technique_names.get(tech_id).unwrap_or(tech_id),
                    "tactic": "Unknown",
                })
            })
            .collect();

        let mut sorted_tactics: Vec<String> = all_tactics.into_iter().collect();
        sorted_tactics.sort();
        let mut sorted_hosts: Vec<String> = all_hosts.into_iter().collect();
        sorted_hosts.sort();
        let mut sorted_users: Vec<String> = all_users.into_iter().collect();
        sorted_users.sort();

        // Build investigation details
        let investigation_details: Vec<serde_json::Value> = states
            .iter()
            .map(|inv| {
                let alert = if inv.alert.is_object() {
                    &inv.alert
                } else {
                    &serde_json::Value::Null
                };
                let labels = alert.get("labels").unwrap_or(&serde_json::Value::Null);
                let queries = queries_by_inv
                    .get(&inv.investigation_id)
                    .cloned()
                    .unwrap_or_default();
                let alert_payload = if alert.is_object() {
                    serde_json::to_string_pretty(alert).unwrap_or_default()
                } else {
                    String::new()
                };
                serde_json::json!({
                    "investigation_id": inv.investigation_id,
                    "alert_name": labels.get("alertname").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    "severity": labels.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "status": if inv.escalated { "ESCALATED" } else { "Completed" },
                    "evidence_count": inv.evidence.len(),
                    "techniques": inv.identified_techniques,
                    "alert_payload": alert_payload,
                    "queries": queries,
                })
            })
            .collect();

        let input = BlueTeamReportInput {
            operation_id: operation_id.to_string(),
            started_at,
            completed_at,
            duration,
            investigation_count: states.len(),
            alert_count,
            evidence_count: all_evidence.len(),
            technique_count: sorted_techniques.len(),
            tactic_count: sorted_tactics.len(),
            host_count: sorted_hosts.len(),
            user_count: sorted_users.len(),
            highest_pyramid_level,
            ttp_count,
            escalation_count,
            attack_synopses,
            alert_summaries,
            evidence_by_level,
            timeline,
            techniques,
            tactics: sorted_tactics,
            hosts: sorted_hosts,
            users: sorted_users,
            recommendations: all_recommendations,
            investigation_details,
            pyramid_distribution,
        };

        self.generate(&input)
    }
}
