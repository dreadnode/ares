//! Core gap analysis logic: gap generation, descriptions, and summary.

use crate::eval::ground_truth::{ExpectedIOC, ExpectedTechnique};
use crate::eval::results::EvaluationResult;

use super::recommendations::{recommend_for_ioc, recommend_for_technique};
use super::types::{DetectionRecommendation, GapAnalysisReport};

/// Analyze an evaluation result and generate a gap analysis report.
pub fn analyze_detection_gaps(result: &EvaluationResult) -> GapAnalysisReport {
    let mut detection_gaps: Vec<String> = Vec::new();
    let mut recommendations: Vec<DetectionRecommendation> = Vec::new();

    // Analyze missed IOCs
    for ioc in &result.missed_iocs {
        detection_gaps.push(describe_ioc_gap(ioc));
        if let Some(rec) = recommend_for_ioc(ioc) {
            recommendations.push(rec);
        }
    }

    // Analyze missed techniques
    for tech in &result.missed_techniques {
        detection_gaps.push(describe_technique_gap(tech));
        if let Some(rec) = recommend_for_technique(tech) {
            recommendations.push(rec);
        }
    }

    // No alert fired
    if !result.alert_fired {
        detection_gaps.push("No alert fired for this attack scenario".to_string());
        recommendations.push(DetectionRecommendation {
            category: "rule".to_string(),
            priority: "critical".to_string(),
            title: "Create detection rules for attack indicators".to_string(),
            description: "The attack did not trigger any alerts. Review the attack \
                timeline and create Grafana/Prometheus alerting rules for \
                the observed indicators."
                .to_string(),
            techniques: Vec::new(),
            implementation_hint: "Create alertmanager rules matching network anomalies, \
                authentication events, and process execution patterns."
                .to_string(),
        });
    }

    // Investigation started but not completed
    if result.investigation_started && !result.investigation_completed {
        detection_gaps.push("Investigation started but did not complete".to_string());
        recommendations.push(DetectionRecommendation {
            category: "training".to_string(),
            priority: "medium".to_string(),
            title: "Improve investigation workflow completion".to_string(),
            description: "The investigation was started but did not complete all stages. \
                This may indicate gaps in tool availability, data access, \
                or investigation methodology."
                .to_string(),
            techniques: Vec::new(),
            implementation_hint: String::new(),
        });
    }

    // Low pyramid level
    if result.highest_pyramid_level < 4 {
        detection_gaps.push(format!(
            "Only reached pyramid level {}/6 (did not reach Network/Host Artifacts)",
            result.highest_pyramid_level,
        ));
        recommendations.push(DetectionRecommendation {
            category: "log_source".to_string(),
            priority: "high".to_string(),
            title: "Enable higher-fidelity log sources".to_string(),
            description: "Investigation evidence stayed at lower pyramid levels. \
                Enable additional log sources to identify tools and TTPs."
                .to_string(),
            techniques: Vec::new(),
            implementation_hint: "Enable Sysmon, PowerShell script block logging, \
                and command-line auditing."
                .to_string(),
        });
    }

    // Generate summary
    let summary = generate_summary(result, &detection_gaps);

    // Sort recommendations by priority
    let priority_order = |p: &str| -> u8 {
        match p {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };
    recommendations.sort_by_key(|r| priority_order(&r.priority));

    GapAnalysisReport {
        evaluation_id: result.evaluation_id.clone(),
        operation_id: result.operation_id.clone(),
        overall_grade: result.grade().to_string(),
        detection_gaps,
        recommendations,
        summary,
    }
}

pub(crate) fn describe_ioc_gap(ioc: &ExpectedIOC) -> String {
    let required_str = if ioc.required { " (required)" } else { "" };
    format!("Missed {} IOC: {}{}", ioc.ioc_type, ioc.value, required_str)
}

pub(crate) fn describe_technique_gap(tech: &ExpectedTechnique) -> String {
    let required_str = if tech.required { " (required)" } else { "" };
    let name = if tech.technique_name.is_empty() {
        String::new()
    } else {
        format!(" - {}", tech.technique_name)
    };
    format!(
        "Missed technique {}{}{}",
        tech.technique_id, name, required_str
    )
}

pub(crate) fn generate_summary(result: &EvaluationResult, gaps: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Overall assessment
    let grade = result.grade();
    if grade == "A" || grade == "B" {
        parts.push(format!(
            "The investigation performed well with a grade of {grade}."
        ));
    } else if grade == "C" {
        parts.push(format!(
            "The investigation achieved a passing grade of {grade} but has room for improvement."
        ));
    } else {
        parts.push(format!(
            "The investigation received a grade of {grade}, indicating \
            significant detection gaps that need to be addressed."
        ));
    }

    // Alert status
    if result.alert_fired {
        parts.push("An alert was successfully triggered for this attack.".to_string());
    } else {
        parts.push(
            "No alert was triggered, indicating a critical gap in detection rules.".to_string(),
        );
    }

    // Detection rates
    parts.push(format!(
        "IOC detection rate was {:.0}% and technique coverage was {:.0}%.",
        result.ioc_detection_rate * 100.0,
        result.technique_coverage * 100.0,
    ));

    // Gap count
    if gaps.is_empty() {
        parts.push("No significant detection gaps were identified.".to_string());
    } else {
        parts.push(format!(
            "A total of {} detection gaps were identified.",
            gaps.len()
        ));
    }

    parts.join(" ")
}
