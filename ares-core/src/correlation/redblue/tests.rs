//! Tests for the red-blue correlator engine.

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};

use super::engine::RedBlueCorrelator;
use super::types::{BlueTeamDetection, RedTeamActivity};

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
