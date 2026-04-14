//! Blue team report generator.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::Serialize;
use tera::{Context, Tera};

use crate::models::SharedBlueTeamState;

use super::context::TimelineEventCtx;
use super::templates::{BLUETEAM_COMPREHENSIVE_TEMPLATE, BLUETEAM_INVESTIGATION_TEMPLATE};

/// Template context structures for blue team reports.
#[derive(Serialize)]
pub struct BlueTeamAlertSummary {
    pub investigation_id_short: String,
    pub alert_name: String,
    pub severity: String,
    pub evidence_count: usize,
    pub highest_pyramid_level: i32,
    pub status_display: String,
    pub techniques: Vec<String>,
}

#[derive(Serialize)]
pub struct BlueTeamTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Serialize)]
pub struct PyramidEntry {
    pub level: i32,
    pub category: String,
    pub count: i32,
    pub pain: String,
}

#[derive(Serialize)]
pub struct BlueTeamEvidenceItem {
    pub id_short: String,
    #[serde(rename = "type")]
    pub ev_type: String,
    pub value: String,
    pub techniques_display: String,
    pub confidence_display: String,
}

#[derive(Serialize)]
pub struct BlueTeamEvidenceLevel {
    pub level: i32,
    pub name: String,
    pub evidence: Vec<BlueTeamEvidenceItem>,
}

#[derive(Serialize)]
pub struct BlueTeamInvestigationDetail {
    pub investigation_id: String,
    pub alert_name: String,
    pub severity: String,
    pub status: String,
    pub evidence_count: usize,
    pub techniques_display: String,
    pub alert_payload: String,
    pub queries: Vec<serde_json::Value>,
    pub queries_display: Vec<serde_json::Value>,
    pub extra_query_count: usize,
}

/// Input data for blue team report generation.
///
/// Since we don't have full blue team state models in Rust yet, this struct
/// provides a data-transfer object that the CLI can populate from Redis.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BlueTeamReportInput {
    pub operation_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration: String,
    pub investigation_count: usize,
    pub alert_count: usize,
    pub evidence_count: usize,
    pub technique_count: usize,
    pub tactic_count: usize,
    pub host_count: usize,
    pub user_count: usize,
    pub highest_pyramid_level: i32,
    pub ttp_count: usize,
    pub escalation_count: usize,
    pub attack_synopses: Vec<String>,
    pub alert_summaries: Vec<serde_json::Value>,
    pub evidence_by_level: HashMap<i32, Vec<serde_json::Value>>,
    pub timeline: Vec<serde_json::Value>,
    pub techniques: Vec<serde_json::Value>,
    pub tactics: Vec<String>,
    pub hosts: Vec<String>,
    pub users: Vec<String>,
    pub recommendations: Vec<String>,
    pub investigation_details: Vec<serde_json::Value>,
    pub pyramid_distribution: HashMap<i32, i32>,
}

/// Generates markdown reports from blue team operation data using Tera templates.
pub struct BlueTeamReportGenerator {
    tera: Tera,
}

impl BlueTeamReportGenerator {
    /// Create a new blue team report generator with embedded templates.
    pub fn new() -> Result<Self, tera::Error> {
        let mut tera = Tera::default();
        tera.add_raw_template("comprehensive_report", BLUETEAM_COMPREHENSIVE_TEMPLATE)?;
        tera.add_raw_template("investigation_report", BLUETEAM_INVESTIGATION_TEMPLATE)?;
        Ok(Self { tera })
    }

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
                                    id_short: id_short.to_string(),
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

        let technique_count = state.identified_techniques.len();
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
        if !state.identified_techniques.is_empty() {
            let tech_list: Vec<&str> = state
                .identified_techniques
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

        // Techniques table
        let mut sorted_techniques: Vec<&String> = state.identified_techniques.iter().collect();
        sorted_techniques.sort();
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

impl Default for BlueTeamReportGenerator {
    fn default() -> Self {
        Self::new().expect("Failed to initialize blue team report templates")
    }
}
