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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::ground_truth::{ExpectedIOC, ExpectedTechnique};
    use crate::eval::results::EvaluationResult;
    use crate::models::PyramidLevel;

    fn make_ioc(ioc_type: &str, value: &str, required: bool) -> ExpectedIOC {
        ExpectedIOC {
            ioc_type: ioc_type.into(),
            value: value.into(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: vec![],
            required,
            source: String::new(),
        }
    }

    fn make_technique(id: &str, name: &str, required: bool) -> ExpectedTechnique {
        ExpectedTechnique {
            technique_id: id.into(),
            technique_name: name.into(),
            required,
            parent_id: None,
        }
    }

    fn base_result() -> EvaluationResult {
        EvaluationResult {
            evaluation_id: "eval-1".into(),
            operation_id: "op-1".into(),
            overall_score: 0.8,
            ioc_detection_rate: 0.7,
            technique_coverage: 0.6,
            alert_fired: true,
            investigation_started: true,
            investigation_completed: true,
            highest_pyramid_level: 5,
            ..Default::default()
        }
    }

    #[test]
    fn describe_ioc_gap_required() {
        let ioc = make_ioc("ip", "192.168.58.1", true);
        let desc = describe_ioc_gap(&ioc);
        assert!(desc.contains("ip"));
        assert!(desc.contains("192.168.58.1"));
        assert!(desc.contains("(required)"));
    }

    #[test]
    fn describe_ioc_gap_optional() {
        let ioc = make_ioc("hash", "abc123", false);
        let desc = describe_ioc_gap(&ioc);
        assert!(desc.contains("hash"));
        assert!(!desc.contains("(required)"));
    }

    #[test]
    fn describe_technique_gap_with_name() {
        let t = make_technique("T1003", "OS Credential Dumping", true);
        let desc = describe_technique_gap(&t);
        assert!(desc.contains("T1003"));
        assert!(desc.contains("OS Credential Dumping"));
        assert!(desc.contains("(required)"));
    }

    #[test]
    fn describe_technique_gap_no_name() {
        let t = make_technique("T1046", "", false);
        let desc = describe_technique_gap(&t);
        assert!(desc.contains("T1046"));
        assert!(!desc.contains("(required)"));
    }

    #[test]
    fn summary_good_grade_with_alert() {
        let r = base_result();
        let gaps: Vec<String> = vec![];
        let summary = generate_summary(&r, &gaps);
        assert!(summary.contains("grade of B"));
        assert!(summary.contains("alert was successfully"));
        assert!(summary.contains("No significant"));
    }

    #[test]
    fn summary_failing_grade_no_alert() {
        let mut r = base_result();
        r.overall_score = 0.4;
        r.alert_fired = false;
        let gaps = vec!["gap1".into(), "gap2".into()];
        let summary = generate_summary(&r, &gaps);
        assert!(summary.contains("grade of F"));
        assert!(summary.contains("No alert was triggered"));
        assert!(summary.contains("2 detection gaps"));
    }

    #[test]
    fn analyze_no_gaps_clean_result() {
        let r = base_result();
        let report = analyze_detection_gaps(&r);
        assert_eq!(report.evaluation_id, "eval-1");
        assert_eq!(report.overall_grade, "B");
        assert!(report.detection_gaps.is_empty());
    }

    #[test]
    fn analyze_missed_iocs_and_techniques() {
        let mut r = base_result();
        r.missed_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        r.missed_techniques = vec![make_technique("T1003", "OS Credential Dumping", true)];
        let report = analyze_detection_gaps(&r);
        assert!(report.detection_gaps.len() >= 2);
    }

    #[test]
    fn analyze_no_alert_adds_critical_rec() {
        let mut r = base_result();
        r.alert_fired = false;
        let report = analyze_detection_gaps(&r);
        assert!(report
            .detection_gaps
            .iter()
            .any(|g| g.contains("No alert fired")));
        assert!(report
            .recommendations
            .iter()
            .any(|rec| rec.priority == "critical"));
    }

    #[test]
    fn analyze_low_pyramid_adds_rec() {
        let mut r = base_result();
        r.highest_pyramid_level = 2;
        let report = analyze_detection_gaps(&r);
        assert!(report
            .detection_gaps
            .iter()
            .any(|g| g.contains("pyramid level 2/6")));
    }

    #[test]
    fn analyze_incomplete_investigation() {
        let mut r = base_result();
        r.investigation_completed = false;
        let report = analyze_detection_gaps(&r);
        assert!(report
            .detection_gaps
            .iter()
            .any(|g| g.contains("did not complete")));
    }

    #[test]
    fn recommendations_sorted_by_priority() {
        let mut r = base_result();
        r.alert_fired = false;
        r.highest_pyramid_level = 2;
        r.investigation_completed = false;
        let report = analyze_detection_gaps(&r);
        let first = report
            .recommendations
            .first()
            .expect("should have recommendations");
        assert_eq!(first.priority, "critical");
    }
}
