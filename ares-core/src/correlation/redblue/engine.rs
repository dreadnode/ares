//! Red-blue correlator engine.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use tracing::{info, warn};

use super::types::{
    BlueTeamDetection, CorrelationMatch, CorrelationReport, DetectionGap, RedTeamActivity,
    TechniqueCoverage,
};

/// Combined red and blue team reports loaded from disk: red activities grouped
/// by operation ID alongside a flat list of blue detections.
pub type LoadedReports = (Vec<(String, Vec<RedTeamActivity>)>, Vec<BlueTeamDetection>);

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
                target_ip,
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
    /// Recognises the current layout (`red/{op_id}.md`,
    /// `blue/investigations/{inv_id}.md`), the intermediate layout
    /// (`{op_id}/red_report.md`, `{op_id}/blue_investigation_*.md`), and the
    /// legacy flat layout (`redteam-*.md`, `investigation_*.md`).
    pub fn load_all_reports(&self) -> anyhow::Result<LoadedReports> {
        let mut red_team_reports = Vec::new();
        let mut blue_team_detections = Vec::new();

        let md_files = Self::collect_md_files(&self.reports_dir);
        for path in md_files {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let parent_name = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Current: red/{op_id}.md | Intermediate: {op_id}/red_report.md | Legacy: redteam-*.md
            let is_red = parent_name == "red"
                || filename == "red_report.md"
                || filename.starts_with("redteam-");

            // Current: blue/investigations/{inv_id}.md | Intermediate: blue_investigation_*.md | Legacy: investigation_*.md
            let is_blue = parent_name == "investigations"
                || filename.starts_with("blue_investigation_")
                || filename.starts_with("investigation_");

            if is_red {
                match self.load_red_team_report(&path) {
                    Ok((op_id, activities)) => red_team_reports.push((op_id, activities)),
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Failed to parse red team report")
                    }
                }
            } else if is_blue {
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
    pub(super) fn determine_gap_reason(
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
    pub(super) fn recommend_detection(activity: &RedTeamActivity) -> Option<String> {
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
    pub(super) fn calculate_technique_coverage(
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
        super::report::generate_report_markdown(report)
    }

    /// Run correlation analysis on all reports in the directory (file I/O).
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

    fn make_red(
        technique_id: Option<&str>,
        target_ip: Option<&str>,
        action: &str,
        timestamp: DateTime<Utc>,
    ) -> RedTeamActivity {
        RedTeamActivity {
            timestamp,
            technique_id: technique_id.map(String::from),
            technique_name: None,
            action: action.to_string(),
            target_ip: target_ip.map(String::from),
            target_host: None,
            credential_used: None,
            success: true,
            metadata: HashMap::new(),
        }
    }

    fn make_blue(
        technique_id: Option<&str>,
        alert_name: &str,
        target_ip: Option<&str>,
        timestamp: DateTime<Utc>,
    ) -> BlueTeamDetection {
        BlueTeamDetection {
            timestamp,
            alert_name: alert_name.to_string(),
            technique_id: technique_id.map(String::from),
            severity: "high".to_string(),
            target_ip: target_ip.map(String::from),
            target_host: None,
            investigation_id: None,
            status: "completed".to_string(),
            evidence_count: 3,
            highest_pyramid_level: 4,
            metadata: HashMap::new(),
        }
    }

    fn base_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap()
    }

    // ── techniques_match ───────────────────────────────────────────

    #[test]
    fn techniques_match_exact() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003"),
            Some("T1003")
        ));
    }

    #[test]
    fn techniques_match_parent_to_child() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003"),
            Some("T1003.006")
        ));
    }

    #[test]
    fn techniques_match_child_to_parent() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003.006"),
            Some("T1003")
        ));
    }

    #[test]
    fn techniques_match_different() {
        assert!(!RedBlueCorrelator::techniques_match(
            Some("T1003"),
            Some("T1046")
        ));
    }

    #[test]
    fn techniques_match_none_red() {
        assert!(!RedBlueCorrelator::techniques_match(None, Some("T1003")));
    }

    #[test]
    fn techniques_match_none_blue() {
        assert!(!RedBlueCorrelator::techniques_match(Some("T1003"), None));
    }

    #[test]
    fn techniques_match_both_none() {
        assert!(!RedBlueCorrelator::techniques_match(None, None));
    }

    #[test]
    fn techniques_match_case_insensitive() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("t1003"),
            Some("T1003")
        ));
    }

    #[test]
    fn techniques_match_different_sub() {
        assert!(RedBlueCorrelator::techniques_match(
            Some("T1003.001"),
            Some("T1003.006")
        ));
    }

    // ── determine_gap_reason ───────────────────────────────────────

    #[test]
    fn gap_reason_no_technique() {
        let activity = make_red(None, Some("192.168.58.1"), "scan", base_time());
        let reason = RedBlueCorrelator::determine_gap_reason(&activity, &[]);
        assert!(reason.contains("no associated MITRE technique"));
    }

    #[test]
    fn gap_reason_no_alert_rules() {
        let activity = make_red(Some("T1003"), Some("192.168.58.1"), "dump", base_time());
        let reason = RedBlueCorrelator::determine_gap_reason(&activity, &[]);
        assert!(reason.contains("No alert rules configured"));
        assert!(reason.contains("T1003"));
    }

    #[test]
    fn gap_reason_alert_exists_but_no_trigger() {
        let activity = make_red(Some("T1003"), Some("192.168.58.1"), "dump", base_time());
        let detections = vec![make_blue(
            Some("T1003"),
            "Cred Dump Alert",
            Some("192.168.58.2"),
            base_time() + Duration::hours(2),
        )];
        let reason = RedBlueCorrelator::determine_gap_reason(&activity, &detections);
        assert!(reason.contains("Alert exists but did not trigger"));
    }

    // ── recommend_detection ────────────────────────────────────────

    #[test]
    fn recommend_detection_t1046() {
        let activity = make_red(Some("T1046"), None, "scan", base_time());
        let rec = RedBlueCorrelator::recommend_detection(&activity);
        assert!(rec.is_some());
        assert!(rec.unwrap().contains("scanning"));
    }

    #[test]
    fn recommend_detection_t1003() {
        let activity = make_red(Some("T1003"), None, "dump", base_time());
        let rec = RedBlueCorrelator::recommend_detection(&activity);
        assert!(rec.is_some());
        assert!(rec.unwrap().contains("LSASS"));
    }

    #[test]
    fn recommend_detection_t1110() {
        let activity = make_red(Some("T1110"), None, "brute", base_time());
        let rec = RedBlueCorrelator::recommend_detection(&activity);
        assert!(rec.is_some());
        assert!(rec.unwrap().contains("authentication"));
    }

    #[test]
    fn recommend_detection_unknown_technique() {
        let activity = make_red(Some("T9999"), None, "unknown", base_time());
        assert!(RedBlueCorrelator::recommend_detection(&activity).is_none());
    }

    #[test]
    fn recommend_detection_no_technique() {
        let activity = make_red(None, None, "stuff", base_time());
        assert!(RedBlueCorrelator::recommend_detection(&activity).is_none());
    }

    // ── calculate_technique_coverage ───────────────────────────────

    #[test]
    fn coverage_empty() {
        let cov = RedBlueCorrelator::calculate_technique_coverage(&[], &[], &[]);
        assert!(cov.is_empty());
    }

    #[test]
    fn coverage_all_detected() {
        let t = base_time();
        let activities = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let matches = vec![CorrelationMatch {
            red_activity: activities[0].clone(),
            blue_detection: make_blue(Some("T1003"), "Alert", Some("192.168.58.1"), t),
            time_delta_seconds: 60.0,
            technique_match: true,
            target_match: true,
            confidence: 0.9,
        }];
        let cov = RedBlueCorrelator::calculate_technique_coverage(&activities, &matches, &[]);
        assert_eq!(cov["T1003"].total, 1);
        assert_eq!(cov["T1003"].detected, 1);
        assert_eq!(cov["T1003"].missed, 0);
        assert!((cov["T1003"].detection_rate - 1.0).abs() < 0.001);
    }

    #[test]
    fn coverage_all_missed() {
        let t = base_time();
        let activities = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let gaps = vec![DetectionGap {
            red_activity: activities[0].clone(),
            reason: "No alert".to_string(),
            recommended_detection: None,
            mitre_data_sources: vec![],
        }];
        let cov = RedBlueCorrelator::calculate_technique_coverage(&activities, &[], &gaps);
        assert_eq!(cov["T1003"].total, 1);
        assert_eq!(cov["T1003"].detected, 0);
        assert_eq!(cov["T1003"].missed, 1);
        assert!((cov["T1003"].detection_rate).abs() < 0.001);
    }

    #[test]
    fn coverage_mixed() {
        let t = base_time();
        let activities = vec![
            make_red(Some("T1003"), Some("192.168.58.1"), "dump1", t),
            make_red(
                Some("T1003"),
                Some("192.168.58.2"),
                "dump2",
                t + Duration::minutes(1),
            ),
        ];
        let matches = vec![CorrelationMatch {
            red_activity: activities[0].clone(),
            blue_detection: make_blue(Some("T1003"), "Alert", Some("192.168.58.1"), t),
            time_delta_seconds: 30.0,
            technique_match: true,
            target_match: true,
            confidence: 0.9,
        }];
        let gaps = vec![DetectionGap {
            red_activity: activities[1].clone(),
            reason: "missed".to_string(),
            recommended_detection: None,
            mitre_data_sources: vec![],
        }];
        let cov = RedBlueCorrelator::calculate_technique_coverage(&activities, &matches, &gaps);
        assert_eq!(cov["T1003"].total, 2);
        assert_eq!(cov["T1003"].detected, 1);
        assert_eq!(cov["T1003"].missed, 1);
        assert!((cov["T1003"].detection_rate - 0.5).abs() < 0.001);
    }

    // ── correlate ──────────────────────────────────────────────────

    #[test]
    fn correlate_empty() {
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&[], &[], "op-1");
        assert_eq!(report.total_red_activities, 0);
        assert_eq!(report.total_blue_detections, 0);
        assert_eq!(report.matched_activities, 0);
        assert!(report.matches.is_empty());
        assert!(report.gaps.is_empty());
        assert!((report.detection_rate).abs() < 0.001);
    }

    #[test]
    fn correlate_exact_match() {
        let t = base_time();
        let red = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let blue = vec![make_blue(
            Some("T1003"),
            "Cred Alert",
            Some("192.168.58.1"),
            t + Duration::minutes(2),
        )];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        assert_eq!(report.matched_activities, 1);
        assert!(report.gaps.is_empty());
        assert!(report.detection_rate > 0.9);
        assert!(report.matches[0].technique_match);
        assert!(report.matches[0].target_match);
    }

    #[test]
    fn correlate_technique_only_match() {
        let t = base_time();
        let red = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let blue = vec![make_blue(
            Some("T1003"),
            "Alert",
            Some("192.168.58.2"),
            t + Duration::minutes(5),
        )];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        assert_eq!(report.matched_activities, 1);
        assert!(report.matches[0].technique_match);
        assert!(!report.matches[0].target_match);
    }

    #[test]
    fn correlate_no_match_outside_window() {
        let t = base_time();
        let red = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let blue = vec![make_blue(
            Some("T1003"),
            "Alert",
            Some("192.168.58.1"),
            t + Duration::hours(2),
        )];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        assert_eq!(report.matched_activities, 0);
        assert_eq!(report.gaps.len(), 1);
    }

    #[test]
    fn correlate_gap_has_recommendation() {
        let t = base_time();
        let red = vec![make_red(Some("T1046"), Some("192.168.58.1"), "scan", t)];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &[], "op-1");
        assert_eq!(report.gaps.len(), 1);
        assert!(report.gaps[0].recommended_detection.is_some());
    }

    #[test]
    fn correlate_false_positives() {
        let t = base_time();
        let red = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let blue = vec![
            make_blue(
                Some("T1003"),
                "Real Alert",
                Some("192.168.58.1"),
                t + Duration::minutes(2),
            ),
            make_blue(
                Some("T1046"),
                "Unrelated Alert",
                Some("192.168.58.5"),
                t + Duration::minutes(10),
            ),
        ];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        assert_eq!(report.matched_activities, 1);
        assert_eq!(report.false_positives.len(), 1);
    }

    #[test]
    fn correlate_detection_rate() {
        let t = base_time();
        let red = vec![
            make_red(Some("T1003"), Some("192.168.58.1"), "dump", t),
            make_red(
                Some("T1046"),
                Some("192.168.58.2"),
                "scan",
                t + Duration::minutes(1),
            ),
        ];
        let blue = vec![make_blue(
            Some("T1003"),
            "Alert",
            Some("192.168.58.1"),
            t + Duration::minutes(2),
        )];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        // One match out of two activities
        assert_eq!(report.matched_activities, 1);
        assert!((report.detection_rate - 0.5).abs() < 0.001);
    }

    #[test]
    fn correlate_mean_time_to_detect() {
        let t = base_time();
        let red = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let blue = vec![make_blue(
            Some("T1003"),
            "Alert",
            Some("192.168.58.1"),
            t + Duration::minutes(5),
        )];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        assert!(report.mean_time_to_detect.is_some());
        let mttd = report.mean_time_to_detect.unwrap();
        assert!((mttd - 300.0).abs() < 1.0);
    }

    #[test]
    fn correlate_no_mttd_when_no_matches() {
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&[], &[], "op-1");
        assert!(report.mean_time_to_detect.is_none());
    }

    #[test]
    fn correlate_custom_time_window() {
        let t = base_time();
        let red = vec![make_red(Some("T1003"), Some("192.168.58.1"), "dump", t)];
        let blue = vec![make_blue(
            Some("T1003"),
            "Alert",
            Some("192.168.58.1"),
            t + Duration::minutes(10),
        )];
        // 5-minute window should miss a 10-minute delta
        let correlator = RedBlueCorrelator::new("/tmp/test", Some(5));
        let report = correlator.correlate(&red, &blue, "op-1");
        assert_eq!(report.matched_activities, 0);
    }

    #[test]
    fn correlate_multiple_techniques() {
        let t = base_time();
        let red = vec![
            make_red(Some("T1003"), Some("192.168.58.1"), "dump", t),
            make_red(
                Some("T1046"),
                Some("192.168.58.2"),
                "scan",
                t + Duration::minutes(1),
            ),
            make_red(
                Some("T1078.002"),
                Some("192.168.58.3"),
                "da",
                t + Duration::minutes(5),
            ),
        ];
        let blue = vec![
            make_blue(
                Some("T1003"),
                "Cred Alert",
                Some("192.168.58.1"),
                t + Duration::minutes(2),
            ),
            make_blue(
                Some("T1046"),
                "Scan Alert",
                Some("192.168.58.2"),
                t + Duration::minutes(3),
            ),
        ];
        let correlator = RedBlueCorrelator::new("/tmp/test", None);
        let report = correlator.correlate(&red, &blue, "op-1");
        // T1003 and T1046 matched, T1078.002 is a gap
        assert_eq!(report.matched_activities, 2);
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.technique_coverage.len(), 3);
    }

    // ── constructor ────────────────────────────────────────────────

    #[test]
    fn new_default_window() {
        let c = RedBlueCorrelator::new("/tmp/test", None);
        assert_eq!(c.time_window.num_minutes(), 30);
    }

    #[test]
    fn new_custom_window() {
        let c = RedBlueCorrelator::new("/tmp/test", Some(60));
        assert_eq!(c.time_window.num_minutes(), 60);
    }
}
