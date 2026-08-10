//! `BlueTeamReportGenerator::generate_from_states` — build a report from raw investigation states.

use std::collections::{HashMap, HashSet};

use chrono::Utc;

use crate::models::{SharedBlueTeamState, SharedRedTeamState};

use super::super::coverage::RedTeamCoverage;
use super::super::provenance::EvidenceProvenance;
use super::super::types::BlueTeamReportInput;
use super::BlueTeamReportGenerator;

impl BlueTeamReportGenerator {
    /// Generate a comprehensive blue team report from one or more `SharedBlueTeamState` objects.
    ///
    /// Investigation states are converted into the report input format automatically.
    ///
    /// `red_state` is the red team operation this investigation covered. When
    /// supplied, the report reports blue's detections as a fraction of what red
    /// actually did; when `None`, it says coverage was not measured rather than
    /// presenting blue's own findings as if they were coverage.
    pub fn generate_from_states(
        &self,
        operation_id: &str,
        states: &[SharedBlueTeamState],
        queries_by_inv: &HashMap<String, Vec<serde_json::Value>>,
        red_state: Option<&SharedRedTeamState>,
    ) -> Result<String, tera::Error> {
        let coverage = red_state.map(|red| RedTeamCoverage::compute(red, states));

        if states.is_empty() {
            let input = BlueTeamReportInput {
                operation_id: operation_id.to_string(),
                coverage,
                ..Default::default()
            };
            return self.generate(&input);
        }

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
                // Aggregate techniques from evidence items (not just state-level)
                all_techniques.extend(ev.mitre_techniques.iter().cloned());
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

        let provenance = EvidenceProvenance::from_evidence(all_evidence.iter().copied());

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

        let alert_summaries: Vec<serde_json::Value> = states
            .iter()
            .map(|inv| {
                let alert = if inv.alert.is_object() {
                    &inv.alert
                } else {
                    &serde_json::Value::Null
                };
                let labels = alert.get("labels").unwrap_or(&serde_json::Value::Null);
                let split = EvidenceProvenance::from_evidence(&inv.evidence);
                serde_json::json!({
                    "investigation_id": inv.investigation_id,
                    "alert_name": labels.get("alertname").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    "severity": labels.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "escalated": inv.escalated,
                    "evidence_count": inv.evidence.len(),
                    "highest_pyramid_level": split.highest_level,
                    "highest_analyst_pyramid_level": split.highest_analyst_level,
                    "techniques": inv.identified_techniques,
                })
            })
            .collect();

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

        let mut sorted_techniques: Vec<String> = all_techniques.iter().cloned().collect();
        sorted_techniques.sort();
        let techniques: Vec<serde_json::Value> = sorted_techniques
            .iter()
            .map(|tech_id| {
                serde_json::json!({
                    "id": tech_id,
                    "name": technique_names
                        .get(tech_id)
                        .map(String::as_str)
                        .or_else(|| crate::reports::get_technique_name(tech_id))
                        .unwrap_or(tech_id),
                    "tactic": crate::reports::get_technique_tactic(tech_id),
                })
            })
            .collect();

        // Blue agents rarely record tactics explicitly, which left the report
        // claiming zero tactics alongside a full technique table. Derive them
        // from the techniques so lifecycle coverage reflects what was found.
        all_tactics.extend(
            sorted_techniques
                .iter()
                .map(|t| crate::reports::get_technique_tactic(t))
                .filter(|t| *t != "Unknown")
                .map(String::from),
        );
        let mut sorted_tactics: Vec<String> = all_tactics.into_iter().collect();
        sorted_tactics.sort();
        let mut sorted_hosts: Vec<String> = all_hosts.into_iter().collect();
        sorted_hosts.sort();
        let mut sorted_users: Vec<String> = all_users.into_iter().collect();
        sorted_users.sort();

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
            highest_pyramid_level: provenance.highest_level,
            highest_analyst_pyramid_level: provenance.highest_analyst_level,
            analyst_evidence_count: provenance.analyst_count,
            ttp_count: provenance.ttp_count,
            analyst_ttp_count: provenance.analyst_ttp_count,
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
            pyramid_distribution: provenance.distribution,
            analyst_pyramid_distribution: provenance.analyst_distribution,
            coverage,
        };

        self.generate(&input)
    }
}
