//! Red-Blue Correlation Engine.
//!
//! Correlates red team attack activities with blue team detections
//! to measure detection coverage and identify gaps.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

/// A single red team activity/action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamActivity {
    pub timestamp: DateTime<Utc>,
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
    pub action: String,
    pub target_ip: Option<String>,
    pub target_host: Option<String>,
    pub credential_used: Option<String>,
    pub success: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl RedTeamActivity {
    /// Unique correlation key for this activity.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.timestamp.to_rfc3339(),
            self.technique_id.as_deref().unwrap_or("none"),
            self.target_ip.as_deref().unwrap_or("none"),
        )
    }
}

/// A blue team detection/alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueTeamDetection {
    pub timestamp: DateTime<Utc>,
    pub alert_name: String,
    pub technique_id: Option<String>,
    pub severity: String,
    pub target_ip: Option<String>,
    pub target_host: Option<String>,
    pub investigation_id: Option<String>,
    /// completed, escalated, timeout
    pub status: String,
    pub evidence_count: u32,
    pub highest_pyramid_level: u32,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl BlueTeamDetection {
    /// Unique correlation key for this detection.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.timestamp.to_rfc3339(),
            self.technique_id.as_deref().unwrap_or("none"),
            self.alert_name,
        )
    }
}

/// A match between red team activity and blue team detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatch {
    pub red_activity: RedTeamActivity,
    pub blue_detection: BlueTeamDetection,
    pub time_delta_seconds: f64,
    pub technique_match: bool,
    pub target_match: bool,
    pub confidence: f64,
}

impl CorrelationMatch {
    /// Assess the quality of this match.
    pub fn match_quality(&self) -> &'static str {
        let abs_delta = self.time_delta_seconds.abs();
        if self.technique_match && self.target_match && abs_delta < 300.0 {
            "STRONG"
        } else if self.technique_match && abs_delta < 600.0 {
            "GOOD"
        } else if self.technique_match || (self.target_match && abs_delta < 300.0) {
            "WEAK"
        } else {
            "TENUOUS"
        }
    }
}

/// An undetected red team activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionGap {
    pub red_activity: RedTeamActivity,
    pub reason: String,
    pub recommended_detection: Option<String>,
    #[serde(default)]
    pub mitre_data_sources: Vec<String>,
}

/// Full correlation analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    pub analysis_timestamp: DateTime<Utc>,
    pub red_operation_id: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,

    // Counts
    pub total_red_activities: usize,
    pub total_blue_detections: usize,
    pub matched_activities: usize,
    pub undetected_activities: usize,
    pub false_positive_detections: usize,

    // Details
    pub matches: Vec<CorrelationMatch>,
    pub gaps: Vec<DetectionGap>,
    pub false_positives: Vec<BlueTeamDetection>,

    // Metrics
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    /// Mean time to detect in seconds, if any detections occurred.
    pub mean_time_to_detect: Option<f64>,

    // By technique
    pub technique_coverage: HashMap<String, TechniqueCoverage>,
}

/// Coverage stats for a single technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    pub total: usize,
    pub detected: usize,
    pub missed: usize,
    pub detection_rate: f64,
}

impl CorrelationReport {
    /// Convert to a JSON-serializable value.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "analysis_timestamp": self.analysis_timestamp.to_rfc3339(),
            "red_operation_id": self.red_operation_id,
            "time_window": {
                "start": self.time_window_start.to_rfc3339(),
                "end": self.time_window_end.to_rfc3339(),
            },
            "summary": {
                "total_red_activities": self.total_red_activities,
                "total_blue_detections": self.total_blue_detections,
                "matched_activities": self.matched_activities,
                "undetected_activities": self.undetected_activities,
                "false_positive_detections": self.false_positive_detections,
                "detection_rate": format!("{:.1}%", self.detection_rate * 100.0),
                "false_positive_rate": format!("{:.1}%", self.false_positive_rate * 100.0),
                "mean_time_to_detect": self.mean_time_to_detect
                    .map(|t| format!("{t:.1}s"))
                    .unwrap_or_else(|| "N/A".to_string()),
            },
            "technique_coverage": self.technique_coverage,
            "matches": self.matches.iter().map(|m| serde_json::json!({
                "red_technique": m.red_activity.technique_id,
                "red_action": &m.red_activity.action[..m.red_activity.action.len().min(100)],
                "blue_alert": m.blue_detection.alert_name,
                "time_delta_seconds": m.time_delta_seconds,
                "match_quality": m.match_quality(),
                "confidence": m.confidence,
            })).collect::<Vec<_>>(),
            "gaps": self.gaps.iter().map(|g| serde_json::json!({
                "technique": g.red_activity.technique_id,
                "action": &g.red_activity.action[..g.red_activity.action.len().min(100)],
                "timestamp": g.red_activity.timestamp.to_rfc3339(),
                "reason": g.reason,
                "recommended_detection": g.recommended_detection,
            })).collect::<Vec<_>>(),
            "false_positives": self.false_positives.iter().map(|fp| serde_json::json!({
                "alert_name": fp.alert_name,
                "technique": fp.technique_id,
                "timestamp": fp.timestamp.to_rfc3339(),
            })).collect::<Vec<_>>(),
        })
    }
}

/// Correlates red team activities with blue team detections.
///
/// This engine:
/// 1. Parses red team operation reports
/// 2. Parses blue team investigation reports
/// 3. Matches activities based on time, technique, and target
/// 4. Identifies detection gaps
/// 5. Calculates coverage metrics
pub struct RedBlueCorrelator {
    pub reports_dir: PathBuf,
    pub time_window: Duration,
}

impl RedBlueCorrelator {
    /// Default time window for matching: 30 minutes.
    pub const DEFAULT_TIME_WINDOW_MINUTES: i64 = 30;

    pub fn new(reports_dir: impl Into<PathBuf>, time_window_minutes: Option<i64>) -> Self {
        Self {
            reports_dir: reports_dir.into(),
            time_window: Duration::minutes(
                time_window_minutes.unwrap_or(Self::DEFAULT_TIME_WINDOW_MINUTES),
            ),
        }
    }

    /// Check if MITRE techniques match, supporting hierarchical matching.
    ///
    /// Supports:
    /// - Exact match: T1003 == T1003
    /// - Parent matches child: T1003 matches T1003.006
    /// - Child matches parent: T1003.006 matches T1003
    pub fn techniques_match(red: Option<&str>, blue: Option<&str>) -> bool {
        let (Some(red), Some(blue)) = (red, blue) else {
            return false;
        };

        let red = red.to_uppercase();
        let blue = blue.to_uppercase();

        if red == blue {
            return true;
        }

        let red_parent = red.split('.').next().unwrap_or(&red);
        let blue_parent = blue.split('.').next().unwrap_or(&blue);

        red_parent == blue_parent
    }

    /// Load and parse a red team report file.
    pub fn load_red_team_report(
        &self,
        report_path: &Path,
    ) -> anyhow::Result<(String, Vec<RedTeamActivity>)> {
        let content = std::fs::read_to_string(report_path)?;
        let mut activities = Vec::new();

        // Extract operation ID
        let op_id_re = Regex::new(r"\*\*Operation ID\*\*:\s*(\S+)")?;
        let operation_id = op_id_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract target IP
        let target_ip_re = Regex::new(r"\*\*Target\*\*:\s*(\d+\.\d+\.\d+\.\d+)")?;
        let target_ip = target_ip_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        // Extract start time
        let started_re = Regex::new(r"\*\*Started\*\*:\s*(.+?)(?:\n|$)")?;
        let started_at = started_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .and_then(|m| {
                chrono::NaiveDateTime::parse_from_str(m.as_str().trim(), "%Y-%m-%d %H:%M:%S UTC")
                    .ok()
            })
            .map(|dt| dt.and_utc())
            .unwrap_or_else(Utc::now);

        // Parse hosts section
        let hosts_re = Regex::new(r"### Hosts \((\d+)\)([\s\S]*?)(?:###|\z)")?;
        if let Some(hosts_cap) = hosts_re.captures(&content) {
            if let Ok(host_count) = hosts_cap[1].parse::<u32>() {
                if host_count > 0 {
                    activities.push(RedTeamActivity {
                        timestamp: started_at,
                        technique_id: Some("T1046".to_string()),
                        technique_name: Some("Network Service Discovery".to_string()),
                        action: format!("Discovered {host_count} host(s) via network scanning"),
                        target_ip: target_ip.clone(),
                        target_host: None,
                        credential_used: None,
                        success: true,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        // Parse credentials section
        let creds_re = Regex::new(r"### Credentials \(\d+\)([\s\S]*?)(?:###|\z)")?;
        if let Some(creds_cap) = creds_re.captures(&content) {
            let creds_content = &creds_cap[1];
            let cred_re = Regex::new(r"\*\*(\S+)\*\*\s*\n.*?Source:\s*(.+?)(?:\n|$)")?;
            for cap in cred_re.captures_iter(creds_content) {
                let username = &cap[1];
                let source = &cap[2];
                let technique_id = if source.to_lowercase().contains("guessing") {
                    "T1110"
                } else {
                    "T1003"
                };
                let technique_name = if source.to_lowercase().contains("guessing") {
                    "Credential Guessing"
                } else {
                    "Credential Dumping"
                };
                activities.push(RedTeamActivity {
                    timestamp: started_at + Duration::minutes(1),
                    technique_id: Some(technique_id.to_string()),
                    technique_name: Some(technique_name.to_string()),
                    action: format!("Obtained credential for {username} via {source}"),
                    target_ip: target_ip.clone(),
                    target_host: None,
                    credential_used: None,
                    success: true,
                    metadata: HashMap::from([
                        ("username".to_string(), username.to_string()),
                        ("source".to_string(), source.to_string()),
                    ]),
                });
            }
        }

        // Parse timeline section
        let timeline_re = Regex::new(r"### Timeline of Key Events([\s\S]*?)(?:---|\z)")?;
        if let Some(timeline_cap) = timeline_re.captures(&content) {
            let timeline_content = &timeline_cap[1];
            let event_re =
                Regex::new(r"\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*(T\d{4}(?:\.\d{3})?)\s*\|")?;
            for cap in event_re.captures_iter(timeline_content) {
                let timestamp_str = cap[1].trim();
                let description = cap[2].trim();
                let technique_id = cap[3].trim();
                let event_time =
                    DateTime::parse_from_rfc3339(&timestamp_str.replace('Z', "+00:00"))
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or(started_at);

                activities.push(RedTeamActivity {
                    timestamp: event_time,
                    technique_id: Some(technique_id.to_string()),
                    technique_name: None,
                    action: description.to_string(),
                    target_ip: target_ip.clone(),
                    target_host: None,
                    credential_used: None,
                    success: true,
                    metadata: HashMap::new(),
                });
            }
        }

        // Domain Admin access
        if content.contains("Domain Admin Access**: ✓")
            || content.to_lowercase().contains("has_domain_admin: true")
        {
            activities.push(RedTeamActivity {
                timestamp: started_at + Duration::minutes(5),
                technique_id: Some("T1078.002".to_string()),
                technique_name: Some("Valid Accounts: Domain Accounts".to_string()),
                action: "Achieved Domain Admin access".to_string(),
                target_ip: target_ip.clone(),
                target_host: None,
                credential_used: None,
                success: true,
                metadata: HashMap::new(),
            });
        }

        // Golden Ticket
        if content.contains("Golden Ticket**: ✓")
            || content.to_lowercase().contains("has_golden_ticket: true")
        {
            activities.push(RedTeamActivity {
                timestamp: started_at + Duration::minutes(6),
                technique_id: Some("T1558.001".to_string()),
                technique_name: Some("Golden Ticket".to_string()),
                action: "Generated Golden Ticket for persistence".to_string(),
                target_ip: target_ip.clone(),
                target_host: None,
                credential_used: None,
                success: true,
                metadata: HashMap::new(),
            });
        }

        info!(
            operation_id = %operation_id,
            activities = activities.len(),
            "Loaded red team report"
        );
        Ok((operation_id, activities))
    }

    /// Load and parse a blue team investigation report.
    pub fn load_investigation_report(
        &self,
        report_path: &Path,
    ) -> anyhow::Result<Option<BlueTeamDetection>> {
        let content = std::fs::read_to_string(report_path)?;

        // Skip DatasourceNoData reports
        if report_path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("DatasourceNoData"))
        {
            return Ok(None);
        }

        let inv_id_re = Regex::new(r"\*\*Investigation ID:\*\*\s*`?(\S+?)`?(?:\n|$)")?;
        let investigation_id = inv_id_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let alert_re = Regex::new(r"\|\s*Alert Name\s*\|\s*(.+?)\s*\|")?;
        let alert_name = alert_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let severity_re = Regex::new(r"\|\s*Severity\s*\|\s*(\w+)\s*\|")?;
        let severity = severity_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Parse timestamp from startsAt or filename
        let starts_at_re = Regex::new(r#""startsAt":\s*"([^"]+)""#)?;
        let timestamp = if let Some(ts_cap) = starts_at_re.captures(&content) {
            DateTime::parse_from_rfc3339(&ts_cap[1].replace('Z', "+00:00"))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now())
        } else {
            let date_re = Regex::new(r"(\d{8}_\d{6})")?;
            report_path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|name| date_re.captures(name))
                .and_then(|c| chrono::NaiveDateTime::parse_from_str(&c[1], "%Y%m%d_%H%M%S").ok())
                .map(|dt| dt.and_utc())
                .unwrap_or_else(Utc::now)
        };

        let technique_re = Regex::new(r"(T\d{4}(?:\.\d{3})?)")?;
        let technique_id = technique_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let status_re = Regex::new(r"\|\s*Status\s*\|\s*(\w+)")?;
        let status = status_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        let evidence_re = Regex::new(r"\*\*Evidence Collected:\*\*\s*(\d+)")?;
        let evidence_count = evidence_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);

        let pyramid_re = Regex::new(r"\*\*Highest Pyramid Level:\*\*\s*(\d+)")?;
        let highest_pyramid_level = pyramid_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);

        let ip_re = Regex::new(r"(\d+\.\d+\.\d+\.\d+)")?;
        let target_ip = ip_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        Ok(Some(BlueTeamDetection {
            timestamp,
            alert_name,
            technique_id,
            severity,
            target_ip,
            target_host: None,
            investigation_id,
            status,
            evidence_count,
            highest_pyramid_level,
            metadata: HashMap::new(),
        }))
    }

    /// Load all reports from the reports directory (recursively).
    ///
    /// Recognises both the new per-operation layout (`{op_id}/red_report.md`,
    /// `{op_id}/blue_investigation_*.md`) and the legacy flat layout
    /// (`redteam-*.md`, `investigation_*.md`).
    #[allow(clippy::type_complexity)]
    pub fn load_all_reports(
        &self,
    ) -> anyhow::Result<(Vec<(String, Vec<RedTeamActivity>)>, Vec<BlueTeamDetection>)> {
        let mut red_team_reports = Vec::new();
        let mut blue_team_detections = Vec::new();

        let md_files = Self::collect_md_files(&self.reports_dir);
        for path in md_files {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // New layout: red_report.md | Legacy: redteam-*.md
            if filename == "red_report.md" || filename.starts_with("redteam-") {
                match self.load_red_team_report(&path) {
                    Ok((op_id, activities)) => red_team_reports.push((op_id, activities)),
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Failed to parse red team report")
                    }
                }
            }
            // New layout: blue_investigation_*.md | Legacy: investigation_*.md
            else if filename.starts_with("blue_investigation_")
                || filename.starts_with("investigation_")
            {
                match self.load_investigation_report(&path) {
                    Ok(Some(detection)) => blue_team_detections.push(detection),
                    Ok(None) => {}
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Failed to parse investigation report")
                    }
                }
            }
        }

        info!(
            red_reports = red_team_reports.len(),
            blue_detections = blue_team_detections.len(),
            "Loaded reports"
        );
        Ok((red_team_reports, blue_team_detections))
    }

    /// Recursively collect all `.md` files under `dir`.
    fn collect_md_files(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    files.extend(Self::collect_md_files(&path));
                } else if path.extension().is_some_and(|ext| ext == "md") {
                    files.push(path);
                }
            }
        }
        files
    }

    /// Correlate red team activities with blue team detections.
    pub fn correlate(
        &self,
        red_activities: &[RedTeamActivity],
        blue_detections: &[BlueTeamDetection],
        operation_id: &str,
    ) -> CorrelationReport {
        let mut matches: Vec<CorrelationMatch> = Vec::new();
        let mut matched_red_keys: HashSet<String> = HashSet::new();
        let mut matched_blue_keys: HashSet<String> = HashSet::new();

        let mut red_sorted: Vec<&RedTeamActivity> = red_activities.iter().collect();
        red_sorted.sort_by_key(|a| a.timestamp);

        let mut blue_sorted: Vec<&BlueTeamDetection> = blue_detections.iter().collect();
        blue_sorted.sort_by_key(|d| d.timestamp);

        let (time_window_start, time_window_end) = if !red_sorted.is_empty() {
            let min_ts = red_sorted.iter().map(|a| a.timestamp).min().unwrap();
            let max_ts = red_sorted.iter().map(|a| a.timestamp).max().unwrap();
            (min_ts - self.time_window, max_ts + self.time_window)
        } else {
            (Utc::now() - Duration::hours(1), Utc::now())
        };

        let time_window_secs = self.time_window.num_seconds() as f64;

        // Match activities to detections
        for red_activity in &red_sorted {
            let mut best_match: Option<CorrelationMatch> = None;
            let mut best_confidence = 0.0_f64;

            for detection in &blue_sorted {
                let time_delta = (detection.timestamp - red_activity.timestamp).num_milliseconds()
                    as f64
                    / 1000.0;

                if time_delta.abs() > time_window_secs {
                    continue;
                }

                let technique_match = Self::techniques_match(
                    red_activity.technique_id.as_deref(),
                    detection.technique_id.as_deref(),
                );

                let target_match = red_activity.target_ip.is_some()
                    && detection.target_ip.is_some()
                    && red_activity.target_ip == detection.target_ip;

                let mut confidence = 0.0;
                if technique_match {
                    confidence += 0.5;
                }
                if target_match {
                    confidence += 0.3;
                }
                // Time proximity bonus
                let time_bonus = (1.0 - time_delta.abs() / time_window_secs).max(0.0) * 0.2;
                confidence += time_bonus;

                if confidence > best_confidence {
                    best_confidence = confidence;
                    best_match = Some(CorrelationMatch {
                        red_activity: (*red_activity).clone(),
                        blue_detection: (*detection).clone(),
                        time_delta_seconds: time_delta,
                        technique_match,
                        target_match,
                        confidence,
                    });
                }
            }

            if let Some(m) = best_match {
                if m.confidence >= 0.3 {
                    matched_red_keys.insert(red_activity.key());
                    matched_blue_keys.insert(m.blue_detection.key());
                    matches.push(m);
                }
            }
        }

        // Identify detection gaps
        let gaps: Vec<DetectionGap> = red_activities
            .iter()
            .filter(|a| !matched_red_keys.contains(&a.key()))
            .map(|activity| DetectionGap {
                red_activity: activity.clone(),
                reason: Self::determine_gap_reason(activity, blue_detections),
                recommended_detection: Self::recommend_detection(activity),
                mitre_data_sources: Vec::new(),
            })
            .collect();

        // Identify false positives
        let false_positives: Vec<BlueTeamDetection> = blue_detections
            .iter()
            .filter(|d| {
                !matched_blue_keys.contains(&d.key())
                    && d.timestamp >= time_window_start
                    && d.timestamp <= time_window_end
            })
            .cloned()
            .collect();

        let total_red = red_activities.len();
        let matched_count = matches.len();
        let detection_rate = if total_red > 0 {
            matched_count as f64 / total_red as f64
        } else {
            0.0
        };

        let detections_in_window = blue_detections
            .iter()
            .filter(|d| d.timestamp >= time_window_start && d.timestamp <= time_window_end)
            .count();
        let false_positive_rate = if detections_in_window > 0 {
            false_positives.len() as f64 / detections_in_window as f64
        } else {
            0.0
        };

        let time_deltas: Vec<f64> = matches
            .iter()
            .filter(|m| m.time_delta_seconds >= 0.0)
            .map(|m| m.time_delta_seconds.abs())
            .collect();
        let mean_ttd = if time_deltas.is_empty() {
            None
        } else {
            Some(time_deltas.iter().sum::<f64>() / time_deltas.len() as f64)
        };

        let technique_coverage =
            Self::calculate_technique_coverage(red_activities, &matches, &gaps);

        CorrelationReport {
            analysis_timestamp: Utc::now(),
            red_operation_id: operation_id.to_string(),
            time_window_start,
            time_window_end,
            total_red_activities: total_red,
            total_blue_detections: blue_detections.len(),
            matched_activities: matched_count,
            undetected_activities: gaps.len(),
            false_positive_detections: false_positives.len(),
            matches,
            gaps,
            false_positives,
            detection_rate,
            false_positive_rate,
            mean_time_to_detect: mean_ttd,
            technique_coverage,
        }
    }

    /// Determine why an activity was not detected.
    fn determine_gap_reason(
        activity: &RedTeamActivity,
        detections: &[BlueTeamDetection],
    ) -> String {
        let Some(ref technique_id) = activity.technique_id else {
            return "Activity has no associated MITRE technique".to_string();
        };

        let has_technique_alert = detections
            .iter()
            .any(|d| Self::techniques_match(Some(technique_id), d.technique_id.as_deref()));

        if !has_technique_alert {
            format!("No alert rules configured for technique {technique_id}")
        } else {
            "Alert exists but did not trigger within time window (possible log ingestion delay or query timeout)".to_string()
        }
    }

    /// Recommend a detection for an undetected activity.
    fn recommend_detection(activity: &RedTeamActivity) -> Option<String> {
        let technique_id = activity.technique_id.as_deref()?;
        let recommendations: HashMap<&str, &str> = HashMap::from([
            (
                "T1046",
                "Add alert for network scanning patterns (nmap, masscan)",
            ),
            (
                "T1110",
                "Add alert for multiple failed authentication attempts",
            ),
            (
                "T1003",
                "Add alert for LSASS access or credential dumping tools",
            ),
            (
                "T1078.002",
                "Add alert for new domain admin group membership",
            ),
            (
                "T1558.001",
                "Add alert for krbtgt service ticket requests with RC4",
            ),
            (
                "T1021.002",
                "Add alert for remote SMB connections from unusual sources",
            ),
        ]);
        recommendations.get(technique_id).map(|s| s.to_string())
    }

    /// Calculate detection coverage per technique.
    fn calculate_technique_coverage(
        activities: &[RedTeamActivity],
        matches: &[CorrelationMatch],
        gaps: &[DetectionGap],
    ) -> HashMap<String, TechniqueCoverage> {
        let mut coverage: HashMap<String, TechniqueCoverage> = HashMap::new();

        for activity in activities {
            if let Some(ref tech) = activity.technique_id {
                coverage
                    .entry(tech.clone())
                    .or_insert_with(|| TechniqueCoverage {
                        total: 0,
                        detected: 0,
                        missed: 0,
                        detection_rate: 0.0,
                    })
                    .total += 1;
            }
        }

        for m in matches {
            if let Some(ref tech) = m.red_activity.technique_id {
                if let Some(cov) = coverage.get_mut(tech) {
                    cov.detected += 1;
                }
            }
        }

        for g in gaps {
            if let Some(ref tech) = g.red_activity.technique_id {
                if let Some(cov) = coverage.get_mut(tech) {
                    cov.missed += 1;
                }
            }
        }

        for cov in coverage.values_mut() {
            if cov.total > 0 {
                cov.detection_rate = cov.detected as f64 / cov.total as f64;
            }
        }

        coverage
    }

    /// Generate a markdown report from correlation results.
    pub fn generate_report_markdown(report: &CorrelationReport) -> String {
        let mut lines = vec![
            "# Red-Blue Correlation Report".to_string(),
            String::new(),
            format!(
                "**Analysis Time:** {}",
                report.analysis_timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            ),
            format!("**Red Team Operation:** {}", report.red_operation_id),
            format!(
                "**Time Window:** {} to {}",
                report.time_window_start.format("%Y-%m-%d %H:%M"),
                report.time_window_end.format("%Y-%m-%d %H:%M"),
            ),
            String::new(),
            "---".to_string(),
            String::new(),
            "## Executive Summary".to_string(),
            String::new(),
            "| Metric | Value |".to_string(),
            "|--------|-------|".to_string(),
            format!("| Red Team Activities | {} |", report.total_red_activities),
            format!(
                "| Blue Team Detections | {} |",
                report.total_blue_detections
            ),
            format!("| Matched (Detected) | {} |", report.matched_activities),
            format!("| Detection Gaps | {} |", report.undetected_activities),
            format!("| False Positives | {} |", report.false_positive_detections),
            format!(
                "| **Detection Rate** | **{:.1}%** |",
                report.detection_rate * 100.0
            ),
            format!(
                "| False Positive Rate | {:.1}% |",
                report.false_positive_rate * 100.0
            ),
            format!(
                "| Mean Time to Detect | {} |",
                report
                    .mean_time_to_detect
                    .map(|t| format!("{t:.0}s"))
                    .unwrap_or_else(|| "N/A".to_string())
            ),
            String::new(),
        ];

        // Assessment
        let assessment = if report.detection_rate >= 0.8 {
            "EXCELLENT - Blue team is detecting most red team activities"
        } else if report.detection_rate >= 0.6 {
            "GOOD - Majority of activities detected, some gaps remain"
        } else if report.detection_rate >= 0.4 {
            "MODERATE - Significant detection gaps exist"
        } else {
            "POOR - Most red team activities went undetected"
        };
        lines.push(format!("### Assessment: {assessment}"));
        lines.push(String::new());
        lines.push("---".to_string());
        lines.push(String::new());

        // Technique coverage
        if !report.technique_coverage.is_empty() {
            lines.push("## Technique Coverage".to_string());
            lines.push(String::new());
            lines.push("| Technique | Total | Detected | Missed | Rate |".to_string());
            lines.push("|-----------|-------|----------|--------|------|".to_string());

            let mut sorted_techs: Vec<_> = report.technique_coverage.iter().collect();
            sorted_techs.sort_by_key(|(k, _)| (*k).clone());

            for (tech_id, data) in sorted_techs {
                let rate_str = format!("{:.0}%", data.detection_rate * 100.0);
                let indicator = if data.detection_rate >= 0.8 {
                    "+"
                } else if data.detection_rate >= 0.5 {
                    "~"
                } else {
                    "-"
                };
                lines.push(format!(
                    "| {} | {} | {} | {} | [{}] {} |",
                    tech_id, data.total, data.detected, data.missed, indicator, rate_str
                ));
            }
            lines.push(String::new());
            lines.push("---".to_string());
            lines.push(String::new());
        }

        // Successful detections
        if !report.matches.is_empty() {
            lines.push("## Successful Detections".to_string());
            lines.push(String::new());
            lines.push("| Red Activity | Blue Alert | Time Delta | Quality |".to_string());
            lines.push("|--------------|------------|------------|---------|".to_string());

            for m in report.matches.iter().take(20) {
                let action = &m.red_activity.action;
                let action_trunc = &action[..action.len().min(40)];
                let alert_trunc =
                    &m.blue_detection.alert_name[..m.blue_detection.alert_name.len().min(30)];
                lines.push(format!(
                    "| {}: {}... | {}... | {:.0}s | {} |",
                    m.red_activity.technique_id.as_deref().unwrap_or("N/A"),
                    action_trunc,
                    alert_trunc,
                    m.time_delta_seconds,
                    m.match_quality(),
                ));
            }
            lines.push(String::new());
            lines.push("---".to_string());
            lines.push(String::new());
        }

        // Detection gaps
        if !report.gaps.is_empty() {
            lines.push("## Detection Gaps (Undetected Activities)".to_string());
            lines.push(String::new());
            lines.push("| Technique | Activity | Reason | Recommendation |".to_string());
            lines.push("|-----------|----------|--------|----------------|".to_string());

            for gap in report.gaps.iter().take(20) {
                let action = &gap.red_activity.action;
                let action_trunc = &action[..action.len().min(40)];
                let reason_trunc = &gap.reason[..gap.reason.len().min(40)];
                lines.push(format!(
                    "| {} | {}... | {}... | {} |",
                    gap.red_activity.technique_id.as_deref().unwrap_or("N/A"),
                    action_trunc,
                    reason_trunc,
                    gap.recommended_detection.as_deref().unwrap_or("N/A"),
                ));
            }
            lines.push(String::new());
            lines.push("---".to_string());
            lines.push(String::new());
        }

        // False positives
        if !report.false_positives.is_empty() {
            lines.push("## False Positives (Detections without Red Activity)".to_string());
            lines.push(String::new());
            lines.push("| Alert | Technique | Time |".to_string());
            lines.push("|-------|-----------|------|".to_string());

            for fp in report.false_positives.iter().take(10) {
                let alert_trunc = &fp.alert_name[..fp.alert_name.len().min(40)];
                lines.push(format!(
                    "| {}... | {} | {} |",
                    alert_trunc,
                    fp.technique_id.as_deref().unwrap_or("N/A"),
                    fp.timestamp.format("%H:%M:%S"),
                ));
            }
            lines.push(String::new());
            lines.push("---".to_string());
            lines.push(String::new());
        }

        // Recommendations
        lines.push("## Recommendations".to_string());
        lines.push(String::new());

        if !report.gaps.is_empty() {
            let mut recommendations: HashMap<String, String> = HashMap::new();
            for gap in &report.gaps {
                if let Some(ref rec) = gap.recommended_detection {
                    let tech = gap
                        .red_activity
                        .technique_id
                        .clone()
                        .unwrap_or_else(|| "General".to_string());
                    recommendations.entry(tech).or_insert_with(|| rec.clone());
                }
            }

            for (i, (tech, rec)) in recommendations.iter().enumerate() {
                lines.push(format!("{}. **{}**: {}", i + 1, tech, rec));
            }
        }

        if report.detection_rate < 0.8 {
            lines.push(String::new());
            lines.push("### General Improvements".to_string());
            lines.push("- Review query timeout issues in Loki/Grafana".to_string());
            lines.push("- Ensure log ingestion latency is < 60 seconds".to_string());
            lines.push("- Add missing detection rules for uncovered techniques".to_string());
            lines.push("- Consider increasing alert rule evaluation frequency".to_string());
        }

        lines.push(String::new());
        lines.push("---".to_string());
        lines.push(String::new());
        lines.push("*Report generated by Ares Red-Blue Correlation Engine*".to_string());

        lines.join("\n")
    }

    /// Run correlation analysis on all reports in the directory.
    pub fn run_full_analysis(&self) -> anyhow::Result<Vec<CorrelationReport>> {
        let (red_reports, blue_detections) = self.load_all_reports()?;
        let mut reports = Vec::new();

        for (operation_id, activities) in &red_reports {
            let report = self.correlate(activities, &blue_detections, operation_id);

            // Save markdown report under {op_id}/ subdirectory
            let markdown = Self::generate_report_markdown(&report);
            let op_dir = self.reports_dir.join(operation_id);
            std::fs::create_dir_all(&op_dir)?;
            let report_path = op_dir.join("correlation.md");
            std::fs::write(&report_path, &markdown)?;
            info!(path = %report_path.display(), "Generated correlation report");

            reports.push(report);
        }

        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 8, hour, min, 0).unwrap()
    }

    fn make_red_activity(technique: &str, ip: &str, time: DateTime<Utc>) -> RedTeamActivity {
        RedTeamActivity {
            timestamp: time,
            technique_id: Some(technique.to_string()),
            technique_name: None,
            action: format!("Test activity for {technique}"),
            target_ip: Some(ip.to_string()),
            target_host: None,
            credential_used: None,
            success: true,
            metadata: HashMap::new(),
        }
    }

    fn make_blue_detection(
        alert: &str,
        technique: &str,
        ip: &str,
        time: DateTime<Utc>,
    ) -> BlueTeamDetection {
        BlueTeamDetection {
            timestamp: time,
            alert_name: alert.to_string(),
            technique_id: Some(technique.to_string()),
            severity: "critical".to_string(),
            target_ip: Some(ip.to_string()),
            target_host: None,
            investigation_id: Some("inv-001".to_string()),
            status: "completed".to_string(),
            evidence_count: 5,
            highest_pyramid_level: 4,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_techniques_match_exact() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003"),
            Some("T1003")
        ));
    }

    #[test]
    fn test_techniques_match_parent_child() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003"),
            Some("T1003.006")
        ));
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003.006"),
            Some("T1003")
        ));
    }

    #[test]
    fn test_techniques_match_different() {
        assert!(!RedBlueCorrelator::techniques_match(
            Some("T1003"),
            Some("T1110")
        ));
    }

    #[test]
    fn test_techniques_match_none() {
        assert!(!RedBlueCorrelator::techniques_match(None, Some("T1003")));
        assert!(!RedBlueCorrelator::techniques_match(Some("T1003"), None));
        assert!(!RedBlueCorrelator::techniques_match(None, None));
    }

    #[test]
    fn test_techniques_match_case_insensitive() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("t1003"),
            Some("T1003")
        ));
    }

    #[test]
    fn test_correlate_perfect_match() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
        let blue = vec![make_blue_detection(
            "Credential Dumping Alert",
            "T1003",
            "192.168.58.10",
            utc(12, 2),
        )];

        let report = correlator.correlate(&red, &blue, "op-test");

        assert_eq!(report.total_red_activities, 1);
        assert_eq!(report.matched_activities, 1);
        assert_eq!(report.undetected_activities, 0);
        assert!(report.detection_rate > 0.99);
        assert_eq!(report.matches[0].match_quality(), "STRONG");
    }

    #[test]
    fn test_correlate_technique_only_match() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
        let blue = vec![make_blue_detection(
            "Credential Dumping Alert",
            "T1003",
            "192.168.58.20", // Different IP
            utc(12, 5),
        )];

        let report = correlator.correlate(&red, &blue, "op-test");
        assert_eq!(report.matched_activities, 1);
        assert_eq!(report.matches[0].match_quality(), "GOOD");
    }

    #[test]
    fn test_correlate_gap_detected() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        // Use different IPs so target matching doesn't cause T1046 to match
        let red = vec![
            make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
            make_red_activity("T1046", "192.168.58.20", utc(12, 5)),
        ];
        let blue = vec![make_blue_detection(
            "Credential Dumping Alert",
            "T1003",
            "192.168.58.10",
            utc(12, 2),
        )];

        let report = correlator.correlate(&red, &blue, "op-test");
        assert_eq!(report.matched_activities, 1);
        assert_eq!(report.undetected_activities, 1);
        assert_eq!(report.gaps.len(), 1);
        assert!(report.gaps[0].reason.contains("No alert rules configured"));
    }

    #[test]
    fn test_correlate_false_positive() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
        let blue = vec![
            make_blue_detection(
                "Credential Dumping Alert",
                "T1003",
                "192.168.58.10",
                utc(12, 2),
            ),
            make_blue_detection("Suspicious Login", "T1078", "192.168.58.20", utc(12, 10)),
        ];

        let report = correlator.correlate(&red, &blue, "op-test");
        assert_eq!(report.false_positive_detections, 1);
        assert_eq!(report.false_positives[0].alert_name, "Suspicious Login");
    }

    #[test]
    fn test_correlate_outside_time_window() {
        let correlator = RedBlueCorrelator::new("/tmp", Some(5)); // 5 minute window

        let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
        let blue = vec![make_blue_detection(
            "Credential Dumping Alert",
            "T1003",
            "192.168.58.10",
            utc(13, 0), // 1 hour later - outside 5 min window
        )];

        let report = correlator.correlate(&red, &blue, "op-test");
        assert_eq!(report.matched_activities, 0);
        assert_eq!(report.undetected_activities, 1);
    }

    #[test]
    fn test_correlate_empty_inputs() {
        let correlator = RedBlueCorrelator::new("/tmp", None);
        let report = correlator.correlate(&[], &[], "op-test");
        assert_eq!(report.total_red_activities, 0);
        assert_eq!(report.detection_rate, 0.0);
    }

    #[test]
    fn test_correlate_technique_coverage() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        // Use different IPs so T1046 doesn't match via target matching
        let red = vec![
            make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
            make_red_activity("T1003", "192.168.58.11", utc(12, 5)),
            make_red_activity("T1046", "192.168.58.20", utc(12, 10)),
        ];
        let blue = vec![make_blue_detection(
            "Credential Dumping",
            "T1003",
            "192.168.58.10",
            utc(12, 2),
        )];

        let report = correlator.correlate(&red, &blue, "op-test");

        assert!(report.technique_coverage.contains_key("T1003"));
        let t1003 = &report.technique_coverage["T1003"];
        assert_eq!(t1003.total, 2);
        assert!(t1003.detected >= 1);

        assert!(report.technique_coverage.contains_key("T1046"));
        let t1046 = &report.technique_coverage["T1046"];
        assert_eq!(t1046.total, 1);
        assert_eq!(t1046.missed, 1);
    }

    #[test]
    fn test_correlate_mean_time_to_detect() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
        let blue = vec![make_blue_detection(
            "Alert",
            "T1003",
            "192.168.58.10",
            utc(12, 5), // 5 minutes later
        )];

        let report = correlator.correlate(&red, &blue, "op-test");
        assert!(report.mean_time_to_detect.is_some());
        let mttd = report.mean_time_to_detect.unwrap();
        assert!(
            (mttd - 300.0).abs() < 1.0,
            "MTTD should be ~300s, got {mttd}"
        );
    }

    #[test]
    fn test_generate_report_markdown() {
        let correlator = RedBlueCorrelator::new("/tmp", None);

        let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
        let blue = vec![make_blue_detection(
            "Credential Dumping Alert",
            "T1003",
            "192.168.58.10",
            utc(12, 2),
        )];

        let report = correlator.correlate(&red, &blue, "op-test");
        let md = RedBlueCorrelator::generate_report_markdown(&report);

        assert!(md.contains("# Red-Blue Correlation Report"));
        assert!(md.contains("op-test"));
        assert!(md.contains("Detection Rate"));
        assert!(md.contains("Successful Detections"));
    }

    #[test]
    fn test_report_to_value() {
        let correlator = RedBlueCorrelator::new("/tmp", None);
        let report = correlator.correlate(&[], &[], "op-test");
        let val = report.to_value();

        assert_eq!(val["red_operation_id"], "op-test");
        assert!(val["summary"]["detection_rate"].is_string());
    }

    #[test]
    fn test_recommend_detection() {
        let activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
        let rec = RedBlueCorrelator::recommend_detection(&activity);
        assert!(rec.is_some());
        assert!(rec.unwrap().contains("LSASS"));

        let unknown = make_red_activity("T9999", "192.168.58.10", utc(12, 0));
        assert!(RedBlueCorrelator::recommend_detection(&unknown).is_none());
    }
}
