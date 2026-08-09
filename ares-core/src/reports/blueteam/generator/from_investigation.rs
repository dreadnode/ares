//! `BlueTeamReportGenerator::generate_investigation` — render a per-investigation report.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use tera::Context;

use crate::models::SharedBlueTeamState;
use crate::reports::context::TimelineEventCtx;

use super::super::provenance::EvidenceProvenance;
use super::super::types::{
    BlueTeamEvidenceItem, BlueTeamEvidenceLevel, BlueTeamTechnique, PyramidEntry,
};
use super::BlueTeamReportGenerator;

impl BlueTeamReportGenerator {
    /// Generate a single investigation report from `SharedBlueTeamState`.
    pub fn generate_investigation(
        &self,
        state: &SharedBlueTeamState,
        queries: &[serde_json::Value],
    ) -> Result<String, tera::Error> {
        let level_names: HashMap<i32, &str> = [
            (6, "TTPs"),
            (5, "Tools"),
            (4, "Network/Host Artifacts"),
            (3, "Domain Names"),
            (2, "IP Addresses"),
            (1, "Hash Values"),
        ]
        .into_iter()
        .collect();

        let level_pain: HashMap<i32, &str> = [
            (6, "Tough!"),
            (5, "Challenging"),
            (4, "Annoying"),
            (3, "Simple"),
            (2, "Easy"),
            (1, "Trivial"),
        ]
        .into_iter()
        .collect();

        let alert = if state.alert.is_object() {
            &state.alert
        } else {
            &serde_json::Value::Null
        };
        let labels = alert.get("labels").unwrap_or(&serde_json::Value::Null);
        let alert_name = labels
            .get("alertname")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let severity = labels
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let started_at = &state.started_at;
        let now = Utc::now();
        let duration = chrono::DateTime::parse_from_rfc3339(started_at)
            .ok()
            .map(|start| {
                let secs = (now - start.with_timezone(&Utc)).num_seconds().max(0) as u64;
                let m = secs / 60;
                let s = secs % 60;
                format!("{m}m {s}s")
            })
            .unwrap_or_else(|| "0m 0s".to_string());

        let status_display = if state.escalated {
            "ESCALATED".to_string()
        } else {
            "COMPLETED".to_string()
        };

        let mut all_techniques: HashSet<String> =
            state.identified_techniques.iter().cloned().collect();
        for ev in &state.evidence {
            all_techniques.extend(ev.mitre_techniques.iter().cloned());
        }
        let mut sorted_techniques: Vec<String> = all_techniques.into_iter().collect();
        sorted_techniques.sort();
        let technique_count = sorted_techniques.len();
        let evidence_count = state.evidence.len();
        let provenance = EvidenceProvenance::from_evidence(&state.evidence);
        let ttp_count = provenance.ttp_count;
        let highest_pyramid_level = provenance.highest_level;

        let assessment = if state.escalated {
            "**ESCALATED** - Human analyst review required".to_string()
        } else if provenance.analyst_ttp_count > 0 {
            "Investigation reached TTP level - actionable intelligence produced".to_string()
        } else if ttp_count > 0 {
            format!(
                "All {ttp_count} TTP-level items came from the deterministic detection sweep - \
                 the analyst loop did not elevate past level {}",
                provenance.highest_analyst_level
            )
        } else if technique_count > 0 {
            "Techniques identified but TTP elevation recommended".to_string()
        } else {
            "Limited findings - may require additional investigation".to_string()
        };

        let mut key_findings = Vec::new();
        if !sorted_techniques.is_empty() {
            let tech_list: Vec<&str> = sorted_techniques
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect();
            key_findings.push(format!("**MITRE Techniques:** {}", tech_list.join(", ")));
        }
        if !state.queried_hosts.is_empty() {
            let hosts: Vec<&str> = state
                .queried_hosts
                .iter()
                .take(3)
                .map(|s| s.as_str())
                .collect();
            key_findings.push(format!("**Hosts Investigated:** {}", hosts.join(", ")));
        }
        if !state.queried_users.is_empty() {
            let users: Vec<&str> = state
                .queried_users
                .iter()
                .take(3)
                .map(|s| s.as_str())
                .collect();
            key_findings.push(format!("**Users Investigated:** {}", users.join(", ")));
        }
        let high_level = provenance.at_or_above(5);
        if high_level > 0 {
            key_findings.push(format!(
                "**High-Value Indicators:** {high_level} tools/TTPs identified ({} from analyst investigation)",
                provenance.analyst_at_or_above(5)
            ));
        }

        let pyramid_entries: Vec<PyramidEntry> = (1..=6)
            .rev()
            .map(|level| {
                let count = *provenance.distribution.get(&level).unwrap_or(&0);
                let analyst_count = *provenance.analyst_distribution.get(&level).unwrap_or(&0);
                PyramidEntry {
                    level,
                    category: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                    count,
                    analyst_count,
                    sweep_count: count.saturating_sub(analyst_count),
                    pain: level_pain.get(&level).unwrap_or(&"Unknown").to_string(),
                }
            })
            .collect();

        let elevation_score = format!("{:.1}%", provenance.elevation_score() * 100.0);
        let analyst_elevation_score =
            format!("{:.1}%", provenance.analyst_elevation_score() * 100.0);

        let pyramid_assessment = if provenance.total_count == 0 {
            "**No evidence collected.**".to_string()
        } else if provenance.analyst_count == 0 {
            "**Every evidence item came from the deterministic detection sweep.** The level above reflects detection-catalog coverage, not analyst investigation.".to_string()
        } else {
            let analyst = match provenance.highest_analyst_level {
                6 => "**Investigation successfully elevated to TTP level.** Actionable intelligence produced.",
                5 => "**Analyst evidence reached tool level.** Consider further elevation to TTPs.",
                3 | 4 => "**Analyst evidence reached artifact level.** Consider elevation to tools and TTPs.",
                _ => "**Analyst evidence is limited to trivial indicators.** Deeper analysis recommended.",
            };
            if provenance.sweep_ttp_count() > 0 && provenance.analyst_ttp_count == 0 {
                format!(
                    "{analyst} The TTP rows above are baseline-sweep detections, not analyst findings."
                )
            } else {
                analyst.to_string()
            }
        };

        let evidence_levels: Vec<BlueTeamEvidenceLevel> = (1..=6)
            .rev()
            .map(|level| {
                let evidence: Vec<BlueTeamEvidenceItem> = state
                    .evidence
                    .iter()
                    .filter(|e| e.pyramid_level == level)
                    .map(|ev| {
                        let id_short = if ev.id.len() > 12 {
                            ev.id[..12].to_string()
                        } else {
                            ev.id.clone()
                        };
                        let techniques = if ev.mitre_techniques.is_empty() {
                            "-".to_string()
                        } else {
                            ev.mitre_techniques
                                .iter()
                                .take(2)
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        let value = if ev.value.len() > 40 {
                            let mut end = 40;
                            while !ev.value.is_char_boundary(end) {
                                end -= 1;
                            }
                            format!("{}...", &ev.value[..end])
                        } else {
                            ev.value.clone()
                        };
                        BlueTeamEvidenceItem {
                            id_short,
                            ev_type: ev.evidence_type.clone(),
                            value,
                            techniques_display: techniques,
                            confidence_display: format!("{:.0}%", ev.confidence * 100.0),
                        }
                    })
                    .collect();
                BlueTeamEvidenceLevel {
                    level,
                    name: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                    evidence,
                }
            })
            .collect();

        let mut sorted_timeline: Vec<&crate::models::TimelineEvent> =
            state.timeline.iter().collect();
        sorted_timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let timeline: Vec<TimelineEventCtx> = sorted_timeline
            .iter()
            .map(|e| {
                let desc = &e.description;
                TimelineEventCtx {
                    timestamp: e.timestamp.clone(),
                    description: desc.clone(),
                    description_short: if desc.len() > 60 {
                        let mut end = 60;
                        while !desc.is_char_boundary(end) {
                            end -= 1;
                        }
                        format!("{}...", &desc[..end])
                    } else {
                        desc.clone()
                    },
                    mitre_display: if e.mitre_techniques.is_empty() {
                        "-".to_string()
                    } else {
                        e.mitre_techniques.join(", ")
                    },
                    mitre_techniques: e.mitre_techniques.clone(),
                    confidence_display: format!("{:.0}%", e.confidence * 100.0),
                }
            })
            .collect();

        let techniques: Vec<BlueTeamTechnique> = sorted_techniques
            .iter()
            .map(|tech_id| {
                let name = state
                    .technique_names
                    .get(tech_id.as_str())
                    .cloned()
                    .unwrap_or_else(|| tech_id.to_string());
                BlueTeamTechnique {
                    id: tech_id.to_string(),
                    name,
                    tactic: "Unknown".to_string(),
                }
            })
            .collect();

        let detection_techniques: Vec<String> = Vec::new();

        let queries_display: Vec<&serde_json::Value> = queries.iter().take(20).collect();
        let extra_query_count = if queries.len() > 20 {
            queries.len() - 20
        } else {
            0
        };

        let mut ctx = Context::new();
        ctx.insert("investigation_id", &state.investigation_id);
        ctx.insert("alert_name", alert_name);
        ctx.insert("severity", severity);
        ctx.insert("status_display", &status_display);
        ctx.insert("started_at", started_at);
        ctx.insert("duration", &duration);
        ctx.insert("assessment", &assessment);
        ctx.insert("evidence_count", &evidence_count);
        ctx.insert("technique_count", &technique_count);
        ctx.insert("tactic_count", &state.identified_tactics.len());
        ctx.insert("ttp_count", &ttp_count);
        ctx.insert("analyst_ttp_count", &provenance.analyst_ttp_count);
        ctx.insert("sweep_ttp_count", &provenance.sweep_ttp_count());
        ctx.insert("analyst_evidence_count", &provenance.analyst_count);
        ctx.insert("sweep_evidence_count", &provenance.sweep_count());
        ctx.insert("highest_pyramid_level", &highest_pyramid_level);
        ctx.insert(
            "highest_analyst_pyramid_level",
            &provenance.highest_analyst_level,
        );
        ctx.insert("key_findings", &key_findings);
        ctx.insert("attack_synopsis", &state.attack_synopsis);
        ctx.insert("timeline", &timeline);
        ctx.insert("timeline_count", &state.timeline.len());
        ctx.insert("techniques", &techniques);
        ctx.insert("detection_techniques", &detection_techniques);
        ctx.insert("pyramid_entries", &pyramid_entries);
        ctx.insert("elevation_score", &elevation_score);
        ctx.insert("analyst_elevation_score", &analyst_elevation_score);
        ctx.insert("pyramid_assessment", &pyramid_assessment);
        ctx.insert("evidence_levels", &evidence_levels);
        ctx.insert("hosts", &state.queried_hosts);
        ctx.insert("host_count", &state.queried_hosts.len());
        ctx.insert("users", &state.queried_users);
        ctx.insert("user_count", &state.queried_users.len());
        ctx.insert("escalated", &state.escalated);
        ctx.insert(
            "escalation_reason",
            &state
                .escalation_reason
                .as_deref()
                .unwrap_or("Not specified"),
        );
        ctx.insert("recommendations", &state.recommendations);
        ctx.insert("queries", queries);
        ctx.insert("queries_display", &queries_display);
        ctx.insert("extra_query_count", &extra_query_count);
        ctx.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        self.tera.render("investigation_report", &ctx)
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{Evidence, SharedBlueTeamState};

    use super::BlueTeamReportGenerator;

    fn evidence(level: i32, source: &str) -> Evidence {
        serde_json::from_value(serde_json::json!({
            "id": format!("ev-{level}-{source}"),
            "type": "credential_access",
            "value": "T1003",
            "source": source,
            "pyramid_level": level,
            "mitre_techniques": ["T1003"],
        }))
        .expect("evidence deserializes")
    }

    fn render(evidence: Vec<Evidence>) -> String {
        let mut state = SharedBlueTeamState::new("inv-20260728-000000".to_string());
        state.evidence = evidence;

        BlueTeamReportGenerator::new()
            .expect("templates load")
            .generate_investigation(&state, &[])
            .expect("report renders")
    }

    #[test]
    fn sweep_only_investigation_is_not_reported_as_reaching_ttps() {
        let report = render(vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(6, "detection_sweep:detect_kerberoast"),
        ]);

        assert!(
            report.contains("All 2 TTP-level items came from the deterministic detection sweep"),
            "executive summary credited the analyst: {report}"
        );
        assert!(
            report.contains("Every evidence item came from the deterministic detection sweep"),
            "pyramid assessment credited the analyst: {report}"
        );
        assert!(
            report.contains("**Highest Pyramid Level:** 0/6 analyst, 6/6 including baseline sweep"),
            "summary reported a single conflated level: {report}"
        );
        assert!(
            !report.contains("Investigation reached TTP level"),
            "claimed TTP level with no analyst evidence: {report}"
        );
    }

    #[test]
    fn analyst_ttp_evidence_still_reaches_ttps() {
        let report = render(vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(6, "grafana_loki_query"),
        ]);

        assert!(
            report.contains("Investigation reached TTP level"),
            "analyst TTP evidence went uncredited: {report}"
        );
        assert!(
            report.contains("**Highest Pyramid Level:** 6/6 analyst, 6/6 including baseline sweep"),
            "analyst level was not reported: {report}"
        );
    }

    #[test]
    fn elevation_score_separates_analyst_evidence_from_the_sweep() {
        let report = render(vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(3, "grafana_loki_query"),
        ]);

        assert!(
            report.contains("**Elevation Score:** 50.0% analyst, 75.0% including baseline sweep"),
            "elevation score conflated the two sources: {report}"
        );
    }
}
