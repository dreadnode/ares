//! Markdown report generation for red-blue correlation.

use std::collections::HashMap;

use super::types::CorrelationReport;

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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;

    use super::super::types::{
        BlueTeamDetection, CorrelationMatch, CorrelationReport, DetectionGap, RedTeamActivity,
        TechniqueCoverage,
    };

    fn make_red(tech: Option<&str>, ip: Option<&str>, action: &str) -> RedTeamActivity {
        RedTeamActivity {
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap(),
            technique_id: tech.map(String::from),
            technique_name: None,
            action: action.to_string(),
            target_ip: ip.map(String::from),
            target_host: None,
            credential_used: None,
            success: true,
            metadata: HashMap::new(),
        }
    }

    fn make_blue(tech: Option<&str>, alert: &str, ip: Option<&str>) -> BlueTeamDetection {
        BlueTeamDetection {
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 10, 2, 0).unwrap(),
            alert_name: alert.to_string(),
            technique_id: tech.map(String::from),
            severity: "high".to_string(),
            target_ip: ip.map(String::from),
            target_host: None,
            investigation_id: None,
            status: "completed".to_string(),
            evidence_count: 3,
            highest_pyramid_level: 4,
            metadata: HashMap::new(),
        }
    }

    fn empty_report(detection_rate: f64) -> CorrelationReport {
        CorrelationReport {
            analysis_timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            red_operation_id: "op-test".to_string(),
            time_window_start: Utc.with_ymd_and_hms(2024, 1, 15, 8, 0, 0).unwrap(),
            time_window_end: Utc.with_ymd_and_hms(2024, 1, 15, 16, 0, 0).unwrap(),
            total_red_activities: 10,
            total_blue_detections: 8,
            matched_activities: 6,
            undetected_activities: 4,
            false_positive_detections: 2,
            matches: vec![],
            gaps: vec![],
            false_positives: vec![],
            detection_rate,
            false_positive_rate: 0.25,
            mean_time_to_detect: Some(45.0),
            technique_coverage: HashMap::new(),
        }
    }

    #[test]
    fn report_contains_header_and_operation_id() {
        let report = empty_report(0.6);
        let md = generate_report_markdown(&report);
        assert!(md.contains("# Red-Blue Correlation Report"));
        assert!(md.contains("op-test"));
    }

    #[test]
    fn report_executive_summary_metrics() {
        let report = empty_report(0.6);
        let md = generate_report_markdown(&report);
        assert!(md.contains("| Red Team Activities | 10 |"));
        assert!(md.contains("| Blue Team Detections | 8 |"));
        assert!(md.contains("| Matched (Detected) | 6 |"));
        assert!(md.contains("| Detection Gaps | 4 |"));
        assert!(md.contains("60.0%"));
    }

    #[test]
    fn report_mttd_none_shows_na() {
        let mut report = empty_report(0.5);
        report.mean_time_to_detect = None;
        let md = generate_report_markdown(&report);
        assert!(md.contains("N/A"));
    }

    #[test]
    fn report_assessment_excellent() {
        let report = empty_report(0.85);
        let md = generate_report_markdown(&report);
        assert!(md.contains("EXCELLENT"));
    }

    #[test]
    fn report_assessment_good() {
        let report = empty_report(0.65);
        let md = generate_report_markdown(&report);
        assert!(md.contains("GOOD"));
    }

    #[test]
    fn report_assessment_moderate() {
        let report = empty_report(0.45);
        let md = generate_report_markdown(&report);
        assert!(md.contains("MODERATE"));
    }

    #[test]
    fn report_assessment_poor() {
        let report = empty_report(0.2);
        let md = generate_report_markdown(&report);
        assert!(md.contains("POOR"));
    }

    #[test]
    fn report_technique_coverage_section() {
        let mut report = empty_report(0.6);
        report.technique_coverage.insert(
            "T1003".to_string(),
            TechniqueCoverage {
                total: 5,
                detected: 4,
                missed: 1,
                detection_rate: 0.8,
            },
        );
        let md = generate_report_markdown(&report);
        assert!(md.contains("## Technique Coverage"));
        assert!(md.contains("T1003"));
        assert!(md.contains("[+] 80%"));
    }

    #[test]
    fn report_technique_coverage_indicators() {
        let mut report = empty_report(0.6);
        report.technique_coverage.insert(
            "T1078".to_string(),
            TechniqueCoverage {
                total: 4,
                detected: 2,
                missed: 2,
                detection_rate: 0.5,
            },
        );
        report.technique_coverage.insert(
            "T1110".to_string(),
            TechniqueCoverage {
                total: 3,
                detected: 0,
                missed: 3,
                detection_rate: 0.0,
            },
        );
        let md = generate_report_markdown(&report);
        assert!(md.contains("[~]")); // 0.5 rate
        assert!(md.contains("[-]")); // 0.0 rate
    }

    #[test]
    fn report_successful_detections_section() {
        let mut report = empty_report(0.6);
        report.matches.push(CorrelationMatch {
            red_activity: make_red(
                Some("T1003"),
                Some("10.0.0.1"),
                "credential dump via secretsdump",
            ),
            blue_detection: make_blue(Some("T1003"), "Credential Dumping Alert", Some("10.0.0.1")),
            time_delta_seconds: 120.0,
            technique_match: true,
            target_match: true,
            confidence: 0.95,
        });
        let md = generate_report_markdown(&report);
        assert!(md.contains("## Successful Detections"));
        assert!(md.contains("T1003"));
        assert!(md.contains("STRONG"));
    }

    #[test]
    fn report_detection_gaps_section() {
        let mut report = empty_report(0.4);
        report.gaps.push(DetectionGap {
            red_activity: make_red(Some("T1558"), Some("10.0.0.5"), "kerberoasting attack"),
            reason: "No detection rule for Kerberoasting".to_string(),
            recommended_detection: Some("Add 4769 monitoring".to_string()),
            mitre_data_sources: vec![],
        });
        let md = generate_report_markdown(&report);
        assert!(md.contains("## Detection Gaps"));
        assert!(md.contains("T1558"));
    }

    #[test]
    fn report_false_positives_section() {
        let mut report = empty_report(0.6);
        report.false_positives.push(make_blue(
            Some("T1110"),
            "Brute Force Alert",
            Some("10.0.0.9"),
        ));
        let md = generate_report_markdown(&report);
        assert!(md.contains("## False Positives"));
        assert!(md.contains("Brute Force Alert"));
    }

    #[test]
    fn report_recommendations_from_gaps() {
        let mut report = empty_report(0.4);
        report.gaps.push(DetectionGap {
            red_activity: make_red(Some("T1003"), None, "secretsdump"),
            reason: "No rule".to_string(),
            recommended_detection: Some("Enable Sysmon Event ID 10".to_string()),
            mitre_data_sources: vec![],
        });
        let md = generate_report_markdown(&report);
        assert!(md.contains("## Recommendations"));
        assert!(md.contains("Enable Sysmon Event ID 10"));
    }

    #[test]
    fn report_general_improvements_when_low_rate() {
        let report = empty_report(0.3);
        let md = generate_report_markdown(&report);
        assert!(md.contains("### General Improvements"));
        assert!(md.contains("log ingestion latency"));
    }

    #[test]
    fn report_no_general_improvements_when_high_rate() {
        let report = empty_report(0.9);
        let md = generate_report_markdown(&report);
        assert!(!md.contains("### General Improvements"));
    }

    #[test]
    fn report_footer_present() {
        let report = empty_report(0.5);
        let md = generate_report_markdown(&report);
        assert!(md.contains("Ares Red-Blue Correlation Engine"));
    }
}
