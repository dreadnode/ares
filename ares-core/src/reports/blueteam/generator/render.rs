//! `BlueTeamReportGenerator::generate` — render pre-processed input into markdown.

use std::collections::HashMap;

use chrono::Utc;
use tera::Context;

use crate::reports::context::TimelineEventCtx;

use super::super::types::{
    BlueTeamAlertSummary, BlueTeamEvidenceItem, BlueTeamEvidenceLevel, BlueTeamInvestigationDetail,
    BlueTeamReportInput, BlueTeamTechnique, PyramidEntry,
};
use super::BlueTeamReportGenerator;

impl BlueTeamReportGenerator {
    /// Generate a comprehensive blue team report from pre-processed input data.
    pub fn generate(&self, input: &BlueTeamReportInput) -> Result<String, tera::Error> {
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

        let pyramid_entries: Vec<PyramidEntry> = (1..=6)
            .rev()
            .map(|level| {
                let count = *input.pyramid_distribution.get(&level).unwrap_or(&0);
                let analyst_count = *input.analyst_pyramid_distribution.get(&level).unwrap_or(&0);
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

        let evidence_levels: Vec<BlueTeamEvidenceLevel> = (1..=6)
            .rev()
            .map(|level| {
                let evidence = input
                    .evidence_by_level
                    .get(&level)
                    .map(|items| {
                        items
                            .iter()
                            .map(|ev| {
                                let id = ev.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                let id_short: String = if id.chars().count() > 12 {
                                    id.chars().take(12).collect()
                                } else {
                                    id.to_string()
                                };
                                let techniques = ev
                                    .get("techniques")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    })
                                    .unwrap_or_else(|| "-".to_string());
                                let confidence =
                                    ev.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);

                                BlueTeamEvidenceItem {
                                    id_short,
                                    ev_type: ev
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    value: {
                                        let val =
                                            ev.get("value").and_then(|v| v.as_str()).unwrap_or("");
                                        if val.len() > 80 {
                                            let mut end = 80;
                                            while !val.is_char_boundary(end) {
                                                end -= 1;
                                            }
                                            format!("{}...", &val[..end])
                                        } else {
                                            val.to_string()
                                        }
                                    },
                                    techniques_display: techniques,
                                    confidence_display: format!("{:.0}%", confidence * 100.0),
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                BlueTeamEvidenceLevel {
                    level,
                    name: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                    evidence,
                }
            })
            .collect();

        let alert_summaries: Vec<BlueTeamAlertSummary> = input
            .alert_summaries
            .iter()
            .map(|a| {
                let inv_id = a
                    .get("investigation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let id_short = if inv_id.len() > 16 {
                    &inv_id[..16]
                } else {
                    inv_id
                };
                let escalated = a
                    .get("escalated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                BlueTeamAlertSummary {
                    investigation_id_short: id_short.to_string(),
                    alert_name: a
                        .get("alert_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    severity: a
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    evidence_count: a
                        .get("evidence_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    highest_pyramid_level: a
                        .get("highest_pyramid_level")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as i32,
                    highest_analyst_pyramid_level: a
                        .get("highest_analyst_pyramid_level")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as i32,
                    status_display: if escalated {
                        "ESCALATED".to_string()
                    } else {
                        "Completed".to_string()
                    },
                    techniques: a
                        .get("techniques")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            })
            .collect();

        let timeline: Vec<TimelineEventCtx> = input
            .timeline
            .iter()
            .map(|e| {
                let desc = e.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let mitre_arr = e
                    .get("mitre_techniques")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let confidence = e.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);

                TimelineEventCtx {
                    timestamp: e
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    description: desc.to_string(),
                    description_short: if desc.len() > 60 {
                        let mut end = 60;
                        while !desc.is_char_boundary(end) {
                            end -= 1;
                        }
                        format!("{}...", &desc[..end])
                    } else {
                        desc.to_string()
                    },
                    mitre_display: if mitre_arr.is_empty() {
                        "-".to_string()
                    } else {
                        mitre_arr.join(", ")
                    },
                    mitre_techniques: mitre_arr,
                    confidence_display: format!("{:.0}%", confidence * 100.0),
                }
            })
            .collect();

        let techniques: Vec<BlueTeamTechnique> = input
            .techniques
            .iter()
            .map(|t| BlueTeamTechnique {
                id: t
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                tactic: t
                    .get("tactic")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
            })
            .collect();

        let detection_techniques: Vec<String> = input
            .coverage
            .as_ref()
            .map(|c| {
                c.missed
                    .iter()
                    .map(|m| {
                        format!(
                            "{} — {} red action{} unmatched ({})",
                            m.id,
                            m.executions,
                            if m.executions == 1 { "" } else { "s" },
                            m.reason
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let investigation_details: Vec<BlueTeamInvestigationDetail> = input
            .investigation_details
            .iter()
            .map(|inv| {
                let techniques_arr = inv
                    .get("techniques")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let queries = inv
                    .get("queries")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let queries_display: Vec<serde_json::Value> =
                    queries.iter().take(10).cloned().collect();
                let extra_query_count = if queries.len() > 10 {
                    queries.len() - 10
                } else {
                    0
                };

                BlueTeamInvestigationDetail {
                    investigation_id: inv
                        .get("investigation_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    alert_name: inv
                        .get("alert_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    severity: inv
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    status: inv
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Completed")
                        .to_string(),
                    evidence_count: inv
                        .get("evidence_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    techniques_display: if techniques_arr.is_empty() {
                        "None".to_string()
                    } else {
                        techniques_arr.join(", ")
                    },
                    alert_payload: inv
                        .get("alert_payload")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    queries,
                    queries_display,
                    extra_query_count,
                }
            })
            .collect();

        let mut ctx = Context::new();
        ctx.insert("operation_id", &input.operation_id);
        ctx.insert("started_at", &input.started_at);
        ctx.insert("completed_at", &input.completed_at);
        ctx.insert("duration", &input.duration);
        ctx.insert("investigation_count", &input.investigation_count);
        ctx.insert("alert_count", &input.alert_count);
        ctx.insert("evidence_count", &input.evidence_count);
        ctx.insert("technique_count", &input.technique_count);
        ctx.insert("tactic_count", &input.tactic_count);
        ctx.insert("host_count", &input.host_count);
        ctx.insert("user_count", &input.user_count);
        ctx.insert("highest_pyramid_level", &input.highest_pyramid_level);
        ctx.insert(
            "highest_analyst_pyramid_level",
            &input.highest_analyst_pyramid_level,
        );
        ctx.insert("analyst_evidence_count", &input.analyst_evidence_count);
        ctx.insert(
            "sweep_evidence_count",
            &input
                .evidence_count
                .saturating_sub(input.analyst_evidence_count),
        );
        ctx.insert("ttp_count", &input.ttp_count);
        ctx.insert("analyst_ttp_count", &input.analyst_ttp_count);
        ctx.insert(
            "sweep_ttp_count",
            &input.ttp_count.saturating_sub(input.analyst_ttp_count),
        );
        ctx.insert("escalation_count", &input.escalation_count);
        ctx.insert("attack_synopses", &input.attack_synopses);
        ctx.insert("alert_summaries", &alert_summaries);
        ctx.insert("evidence_levels", &evidence_levels);
        ctx.insert("timeline", &timeline);
        ctx.insert("techniques", &techniques);
        ctx.insert("detection_techniques", &detection_techniques);
        ctx.insert("tactics", &input.tactics);
        ctx.insert("hosts", &input.hosts);
        ctx.insert("users", &input.users);
        ctx.insert("recommendations", &input.recommendations);
        ctx.insert("investigation_details", &investigation_details);
        ctx.insert("pyramid_entries", &pyramid_entries);
        ctx.insert("coverage", &input.coverage);
        ctx.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        self.tera.render("comprehensive_report", &ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::super::coverage::{CoverageEntry, MissedEntry, RedTeamCoverage};
    use super::super::BlueTeamReportGenerator;
    use crate::reports::blueteam::types::BlueTeamReportInput;

    fn detected_t1003() -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "id": "T1003",
            "name": "Credential Dumping",
            "tactic": "Credential Access",
        })]
    }

    fn improvements(report: &str) -> String {
        report
            .split("### Detection Improvements")
            .nth(1)
            .expect("report has a Detection Improvements section")
            .split("---")
            .next()
            .unwrap()
            .to_string()
    }

    fn pyramid(report: &str) -> String {
        report
            .split("## Pyramid of Pain Assessment")
            .nth(1)
            .expect("report has a Pyramid of Pain section")
            .split("\n---")
            .next()
            .unwrap()
            .to_string()
    }

    fn sweep_only_ttps() -> BlueTeamReportInput {
        BlueTeamReportInput {
            evidence_count: 8,
            analyst_evidence_count: 0,
            ttp_count: 8,
            analyst_ttp_count: 0,
            highest_pyramid_level: 6,
            highest_analyst_pyramid_level: 0,
            pyramid_distribution: HashMap::from([(6, 8)]),
            analyst_pyramid_distribution: HashMap::new(),
            ..Default::default()
        }
    }

    fn render(input: &BlueTeamReportInput) -> String {
        BlueTeamReportGenerator::new()
            .expect("templates load")
            .generate(input)
            .expect("report renders")
    }

    #[test]
    fn improvements_list_red_techniques_blue_missed() {
        let input = BlueTeamReportInput {
            techniques: detected_t1003(),
            coverage: Some(RedTeamCoverage {
                missed: vec![
                    MissedEntry {
                        id: "T1210".into(),
                        executions: 12,
                        reason: "no matching blue detection".into(),
                    },
                    MissedEntry {
                        id: "T1552".into(),
                        executions: 1,
                        reason: "no matching blue detection".into(),
                    },
                ],
                detected: vec![CoverageEntry {
                    id: "T1003".into(),
                    matched_by: "T1003".into(),
                    executions: 4,
                    detected_executions: 4,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let section = improvements(&render(&input));

        assert!(section.contains("T1210"), "missing gap T1210: {section}");
        assert!(section.contains("T1552"), "missing gap T1552: {section}");
        assert!(
            !section.contains("T1003"),
            "recommended a technique blue already detected: {section}"
        );
    }

    #[test]
    fn improvements_report_no_gaps_when_coverage_is_complete() {
        let input = BlueTeamReportInput {
            techniques: detected_t1003(),
            coverage: Some(RedTeamCoverage::default()),
            ..Default::default()
        };

        assert!(improvements(&render(&input)).contains("No gaps"));
    }

    #[test]
    fn improvements_report_unmeasured_without_red_ground_truth() {
        let input = BlueTeamReportInput {
            techniques: detected_t1003(),
            coverage: None,
            ..Default::default()
        };

        assert!(improvements(&render(&input)).contains("Not measured"));
    }

    #[test]
    fn pyramid_does_not_credit_the_analyst_for_sweep_detections() {
        let section = pyramid(&render(&sweep_only_ttps()));

        assert!(
            section.contains("| 6 | TTPs | 0 | 8 | 8 |"),
            "level 6 row did not attribute all 8 items to the sweep: {section}"
        );
        assert!(
            section.contains("Every evidence item came from the deterministic sweep"),
            "sweep-only op did not say so: {section}"
        );
        assert!(
            !section.contains("reached TTP level"),
            "claimed TTP level on an op where the analyst found nothing: {section}"
        );
    }

    #[test]
    fn summary_reports_analyst_and_sweep_levels_separately() {
        let report = render(&sweep_only_ttps());

        assert!(
            report.contains("| Highest Pyramid Level (analyst) | 0/6 |"),
            "summary hid the analyst level: {report}"
        );
        assert!(
            report.contains("| Highest Pyramid Level (incl. baseline sweep) | 6/6 |"),
            "summary hid the sweep level: {report}"
        );
        assert!(
            report.contains("| TTPs Identified | 8 (0 analyst, 8 baseline sweep) |"),
            "TTP count was not split by provenance: {report}"
        );
    }

    #[test]
    fn pyramid_credits_the_analyst_when_analyst_evidence_reaches_ttps() {
        let input = BlueTeamReportInput {
            evidence_count: 4,
            analyst_evidence_count: 1,
            ttp_count: 4,
            analyst_ttp_count: 1,
            highest_pyramid_level: 6,
            highest_analyst_pyramid_level: 6,
            pyramid_distribution: HashMap::from([(6, 4)]),
            analyst_pyramid_distribution: HashMap::from([(6, 1)]),
            ..Default::default()
        };

        let section = pyramid(&render(&input));

        assert!(
            section.contains("| 6 | TTPs | 1 | 3 | 4 |"),
            "level 6 row did not split analyst from sweep: {section}"
        );
        assert!(
            section.contains("independently reached TTP level"),
            "analyst TTP evidence went uncredited: {section}"
        );
    }

    #[test]
    fn pyramid_omits_the_sweep_note_when_no_sweep_ran() {
        let input = BlueTeamReportInput {
            evidence_count: 2,
            analyst_evidence_count: 2,
            highest_pyramid_level: 4,
            highest_analyst_pyramid_level: 4,
            pyramid_distribution: HashMap::from([(4, 2)]),
            analyst_pyramid_distribution: HashMap::from([(4, 2)]),
            ..Default::default()
        };

        let section = pyramid(&render(&input));

        assert!(
            !section.contains("deterministic detection sweep"),
            "explained a sweep that never ran: {section}"
        );
    }
}
