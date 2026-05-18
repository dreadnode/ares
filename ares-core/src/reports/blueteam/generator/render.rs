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

        // Build pyramid entries (6 down to 1)
        let pyramid_entries: Vec<PyramidEntry> = (1..=6)
            .rev()
            .map(|level| PyramidEntry {
                level,
                category: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                count: *input.pyramid_distribution.get(&level).unwrap_or(&0),
                pain: level_pain.get(&level).unwrap_or(&"Unknown").to_string(),
            })
            .collect();

        // Build evidence levels
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

        // Build alert summaries for template
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

        // Build timeline for template
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

        // Build techniques for template
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

        // Detection techniques (first 10)
        let detection_techniques: Vec<&BlueTeamTechnique> = techniques.iter().take(10).collect();

        // Build investigation details
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
        ctx.insert("ttp_count", &input.ttp_count);
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
        ctx.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        self.tera.render("comprehensive_report", &ctx)
    }
}
