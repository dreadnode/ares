use crate::eval::ground_truth::{ExpectedIOC, ExpectedTechnique};
use crate::models::PyramidLevel;

use super::analysis::{
    analyze_detection_gaps, describe_ioc_gap, describe_technique_gap, generate_summary,
};
use super::recommendations::{recommend_for_ioc, recommend_for_technique};
use crate::eval::results::EvaluationResult;

fn make_result_with_gaps() -> EvaluationResult {
    EvaluationResult {
        evaluation_id: "eval-1".to_string(),
        operation_id: "op-1".to_string(),
        overall_score: 0.45,
        ioc_detection_rate: 0.3,
        technique_coverage: 0.4,
        highest_pyramid_level: 3,
        alert_fired: false,
        investigation_started: true,
        investigation_completed: false,
        missed_iocs: vec![
            ExpectedIOC {
                ioc_type: "ip".to_string(),
                value: "192.168.58.10".to_string(),
                pyramid_level: PyramidLevel::IpAddresses,
                mitre_techniques: vec!["T1046".to_string()],
                required: true,
                source: String::new(),
            },
            ExpectedIOC {
                ioc_type: "user".to_string(),
                value: "admin".to_string(),
                pyramid_level: PyramidLevel::NetworkHostArtifacts,
                mitre_techniques: vec![],
                required: true,
                source: String::new(),
            },
        ],
        missed_techniques: vec![
            ExpectedTechnique {
                technique_id: "T1003".to_string(),
                technique_name: "Credential Dumping".to_string(),
                required: true,
                parent_id: None,
            },
            ExpectedTechnique {
                technique_id: "T1558.003".to_string(),
                technique_name: "Kerberoasting".to_string(),
                required: false,
                parent_id: Some("T1558".to_string()),
            },
        ],
        ..Default::default()
    }
}

#[test]
fn test_analyze_detection_gaps_basic() {
    let result = make_result_with_gaps();
    let report = analyze_detection_gaps(&result);

    assert_eq!(report.evaluation_id, "eval-1");
    assert_eq!(report.operation_id, "op-1");
    assert_eq!(report.overall_grade, "F");

    // 2 missed IOCs + 2 missed techniques + no alert + incomplete investigation + low pyramid
    assert!(
        report.detection_gaps.len() >= 6,
        "Expected >= 6 gaps, got {}",
        report.detection_gaps.len()
    );
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_analyze_no_gaps() {
    let result = EvaluationResult {
        evaluation_id: "eval-2".to_string(),
        operation_id: "op-2".to_string(),
        overall_score: 0.95,
        ioc_detection_rate: 0.9,
        technique_coverage: 0.9,
        highest_pyramid_level: 6,
        alert_fired: true,
        investigation_started: true,
        investigation_completed: true,
        ..Default::default()
    };
    let report = analyze_detection_gaps(&result);
    assert_eq!(report.overall_grade, "A");
    assert!(report.detection_gaps.is_empty());
}

#[test]
fn test_ioc_gap_descriptions() {
    let ioc = ExpectedIOC {
        ioc_type: "ip".to_string(),
        value: "192.168.58.10".to_string(),
        pyramid_level: PyramidLevel::IpAddresses,
        mitre_techniques: vec![],
        required: true,
        source: String::new(),
    };
    let gap = describe_ioc_gap(&ioc);
    assert!(gap.contains("ip IOC"));
    assert!(gap.contains("192.168.58.10"));
    assert!(gap.contains("(required)"));
}

#[test]
fn test_technique_gap_descriptions() {
    let tech = ExpectedTechnique {
        technique_id: "T1003".to_string(),
        technique_name: "Credential Dumping".to_string(),
        required: true,
        parent_id: None,
    };
    let gap = describe_technique_gap(&tech);
    assert!(gap.contains("T1003"));
    assert!(gap.contains("Credential Dumping"));
    assert!(gap.contains("(required)"));
}

#[test]
fn test_recommend_for_known_technique() {
    let tech = ExpectedTechnique {
        technique_id: "T1003".to_string(),
        technique_name: "Credential Dumping".to_string(),
        required: true,
        parent_id: None,
    };
    let rec = recommend_for_technique(&tech).unwrap();
    assert_eq!(rec.priority, "critical");
    assert!(rec.title.contains("credential dumping"));
    assert!(rec.implementation_hint.contains("Sysmon"));
}

#[test]
fn test_recommend_for_subtechnique_falls_back_to_parent() {
    // T1003.001 is not in the map, but T1003 is
    let tech = ExpectedTechnique {
        technique_id: "T1003.001".to_string(),
        technique_name: "LSASS Memory".to_string(),
        required: false,
        parent_id: Some("T1003".to_string()),
    };
    let rec = recommend_for_technique(&tech).unwrap();
    assert!(rec.title.contains("credential dumping"));
    assert_eq!(rec.priority, "high"); // not required → high
}

#[test]
fn test_recommend_for_unknown_technique() {
    let tech = ExpectedTechnique {
        technique_id: "T9999".to_string(),
        technique_name: "Novel Attack".to_string(),
        required: false,
        parent_id: None,
    };
    let rec = recommend_for_technique(&tech).unwrap();
    assert!(rec.title.contains("T9999"));
    assert_eq!(rec.priority, "medium");
    assert!(rec.description.contains("Novel Attack"));
}

#[test]
fn test_recommend_for_ioc_types() {
    let ip_ioc = ExpectedIOC {
        ioc_type: "ip".to_string(),
        value: "192.168.58.10".to_string(),
        pyramid_level: PyramidLevel::IpAddresses,
        mitre_techniques: vec![],
        required: true,
        source: String::new(),
    };
    assert_eq!(recommend_for_ioc(&ip_ioc).unwrap().priority, "high");

    let user_ioc = ExpectedIOC {
        ioc_type: "user".to_string(),
        value: "admin".to_string(),
        pyramid_level: PyramidLevel::NetworkHostArtifacts,
        mitre_techniques: vec![],
        required: true,
        source: String::new(),
    };
    assert_eq!(recommend_for_ioc(&user_ioc).unwrap().priority, "critical");

    let hash_ioc = ExpectedIOC {
        ioc_type: "hash".to_string(),
        value: "abc123def456789012".to_string(),
        pyramid_level: PyramidLevel::HashValues,
        mitre_techniques: vec![],
        required: false,
        source: String::new(),
    };
    assert_eq!(recommend_for_ioc(&hash_ioc).unwrap().priority, "medium");

    let unknown_ioc = ExpectedIOC {
        ioc_type: "process".to_string(),
        value: "cmd.exe".to_string(),
        pyramid_level: PyramidLevel::Tools,
        mitre_techniques: vec![],
        required: false,
        source: String::new(),
    };
    assert!(recommend_for_ioc(&unknown_ioc).is_none());
}

#[test]
fn test_to_markdown() {
    let result = make_result_with_gaps();
    let report = analyze_detection_gaps(&result);
    let md = report.to_markdown();

    assert!(md.contains("# Detection Gap Analysis Report"));
    assert!(md.contains("## Executive Summary"));
    assert!(md.contains("## Detection Gaps"));
    assert!(md.contains("## Recommendations"));
    assert!(md.contains("Critical Priority"));
    assert!(md.contains("eval-1"));
}

#[test]
fn test_recommendations_sorted_by_priority() {
    let result = make_result_with_gaps();
    let report = analyze_detection_gaps(&result);

    let priorities: Vec<&str> = report
        .recommendations
        .iter()
        .map(|r| r.priority.as_str())
        .collect();
    let priority_val = |p: &str| match p {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    for window in priorities.windows(2) {
        assert!(
            priority_val(window[0]) <= priority_val(window[1]),
            "Recommendations not sorted: {:?}",
            priorities,
        );
    }
}

#[test]
fn test_summary_generation() {
    let result = make_result_with_gaps();
    let gaps = vec!["gap 1".to_string(), "gap 2".to_string()];
    let summary = generate_summary(&result, &gaps);

    assert!(summary.contains("grade of F"));
    assert!(summary.contains("No alert was triggered"));
    assert!(summary.contains("2 detection gaps"));
}
