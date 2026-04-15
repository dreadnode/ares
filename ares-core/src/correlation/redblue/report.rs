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
