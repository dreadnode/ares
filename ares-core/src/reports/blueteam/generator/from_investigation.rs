//! `BlueTeamReportGenerator::generate_investigation` — render a per-investigation report.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use tera::Context;

use crate::models::SharedBlueTeamState;
use crate::reports::context::TimelineEventCtx;

use super::super::types::{
    BlueTeamEvidenceItem, BlueTeamEvidenceLevel, BlueTeamTechnique, PyramidEntry,
};
use super::BlueTeamReportGenerator;

impl BlueTeamReportGenerator {
    /// Generate a single investigation report from `SharedBlueTeamState`.
    ///
    /// This is the Rust equivalent of `MarkdownReportGenerator._build_report()` in Python,
    /// producing a detailed per-investigation report.
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

        // Extract alert metadata
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

        // Duration
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

        // Merge state-level and evidence-level techniques
        let mut all_techniques: HashSet<String> =
            state.identified_techniques.iter().cloned().collect();
        for ev in &state.evidence {
            all_techniques.extend(ev.mitre_techniques.iter().cloned());
        }
        let mut sorted_techniques: Vec<String> = all_techniques.into_iter().collect();
        sorted_techniques.sort();
        let technique_count = sorted_techniques.len();
        let evidence_count = state.evidence.len();
        let ttp_count = state
            .evidence
            .iter()
            .filter(|e| e.pyramid_level == 6)
            .count();
        let highest_pyramid_level = state
            .evidence
            .iter()
            .map(|e| e.pyramid_level)
            .max()
            .unwrap_or(0);

        // Assessment
        let assessment = if state.escalated {
            "**ESCALATED** - Human analyst review required".to_string()
        } else if ttp_count > 0 {
            "Investigation reached TTP level - actionable intelligence produced".to_string()
        } else if technique_count > 0 {
            "Techniques identified but TTP elevation recommended".to_string()
        } else {
            "Limited findings - may require additional investigation".to_string()
        };

        // Key findings
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
        let high_level = state
            .evidence
            .iter()
            .filter(|e| e.pyramid_level >= 5)
            .count();
        if high_level > 0 {
            key_findings.push(format!(
                "**High-Value Indicators:** {high_level} tools/TTPs identified"
            ));
        }

        // Pyramid distribution
        let mut pyramid_distribution: HashMap<i32, i32> = HashMap::new();
        for ev in &state.evidence {
            *pyramid_distribution.entry(ev.pyramid_level).or_insert(0) += 1;
        }

        let pyramid_entries: Vec<PyramidEntry> = (1..=6)
            .rev()
            .map(|level| PyramidEntry {
                level,
                category: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                count: *pyramid_distribution.get(&level).unwrap_or(&0),
                pain: level_pain.get(&level).unwrap_or(&"Unknown").to_string(),
            })
            .collect();

        // Elevation score
        let total = evidence_count.max(1) as f64;
        let weighted_sum: f64 = state.evidence.iter().map(|e| e.pyramid_level as f64).sum();
        let elevation_score = format!("{:.1}%", (weighted_sum / (total * 6.0)) * 100.0);

        // Pyramid assessment text
        let pyramid_assessment = if *pyramid_distribution.get(&6).unwrap_or(&0) > 0 {
            "**Investigation successfully elevated to TTP level.** Actionable intelligence produced."
        } else if *pyramid_distribution.get(&5).unwrap_or(&0) > 0 {
            "**Tool-level indicators identified.** Consider further elevation to TTPs."
        } else if (*pyramid_distribution.get(&1).unwrap_or(&0)
            + *pyramid_distribution.get(&2).unwrap_or(&0))
            > *pyramid_distribution.get(&5).unwrap_or(&0)
        {
            "**Heavy on trivial indicators.** Investigation may benefit from deeper analysis to identify tools and TTPs."
        } else {
            "**Limited evidence.** More investigation may be needed."
        };

        // Evidence levels
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

        // Timeline
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

        // Techniques table (merged state-level + evidence-level)
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

        let detection_techniques: Vec<&BlueTeamTechnique> = techniques.iter().take(5).collect();

        // Queries
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
        ctx.insert("highest_pyramid_level", &highest_pyramid_level);
        ctx.insert("key_findings", &key_findings);
        ctx.insert("attack_synopsis", &state.attack_synopsis);
        ctx.insert("timeline", &timeline);
        ctx.insert("timeline_count", &state.timeline.len());
        ctx.insert("techniques", &techniques);
        ctx.insert("detection_techniques", &detection_techniques);
        ctx.insert("pyramid_entries", &pyramid_entries);
        ctx.insert("elevation_score", &elevation_score);
        ctx.insert("pyramid_assessment", pyramid_assessment);
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
