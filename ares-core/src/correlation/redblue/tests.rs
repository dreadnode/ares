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
fn techniques_match_exact() {
    assert!(RedBlueCorrelator::techniques_match(
        Some("T1003"),
        Some("T1003")
    ));
}

#[test]
fn techniques_match_parent_child() {
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
fn techniques_match_different() {
    assert!(!RedBlueCorrelator::techniques_match(
        Some("T1003"),
        Some("T1110")
    ));
}

#[test]
fn techniques_match_none() {
    assert!(!RedBlueCorrelator::techniques_match(None, Some("T1003")));
    assert!(!RedBlueCorrelator::techniques_match(Some("T1003"), None));
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
fn correlate_perfect_match() {
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
fn correlate_technique_only_match() {
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
fn correlate_gap_detected() {
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
fn correlate_false_positive() {
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
fn correlate_outside_time_window() {
    let correlator = RedBlueCorrelator::new("/tmp", Some(5)); // 5 minute window

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![make_blue_detection(
        "Credential Dumping Alert",
        "T1003",
        "192.168.58.10",
        utc(13, 0),
    )];

    let report = correlator.correlate(&red, &blue, "op-test");
    assert_eq!(report.matched_activities, 0);
    assert_eq!(report.undetected_activities, 1);
}

#[test]
fn correlate_empty_inputs() {
    let correlator = RedBlueCorrelator::new("/tmp", None);
    let report = correlator.correlate(&[], &[], "op-test");
    assert_eq!(report.total_red_activities, 0);
    assert_eq!(report.detection_rate, 0.0);
}

#[test]
fn correlate_technique_coverage() {
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
fn correlate_mean_time_to_detect() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![make_blue_detection(
        "Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 5),
    )];

    let report = correlator.correlate(&red, &blue, "op-test");
    let mttd = report.mean_time_to_detect.expect("MTTD should be present");
    assert!(
        (mttd - 300.0).abs() < 1.0,
        "MTTD should be ~300s, got {mttd}"
    );
}

#[test]
fn generate_report_markdown() {
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
fn report_to_value() {
    let correlator = RedBlueCorrelator::new("/tmp", None);
    let report = correlator.correlate(&[], &[], "op-test");
    let val = report.to_value();

    assert_eq!(val["red_operation_id"], "op-test");
    assert!(val["summary"]["detection_rate"].is_string());
}

#[test]
fn recommend_detection() {
    let activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity);
    assert!(rec.expect("should have recommendation").contains("LSASS"));

    let unknown = make_red_activity("T9999", "192.168.58.10", utc(12, 0));
    assert!(RedBlueCorrelator::recommend_detection(&unknown).is_none());
}

#[test]
fn recommend_detection_all_known_techniques() {
    let known_techniques = [
        ("T1046", "scanning"),
        ("T1110", "authentication"),
        ("T1078.002", "domain admin"),
        ("T1558.001", "krbtgt"),
        ("T1021.002", "SMB"),
    ];
    for (technique, expected_keyword) in known_techniques {
        let activity = make_red_activity(technique, "192.168.58.10", utc(12, 0));
        let rec = RedBlueCorrelator::recommend_detection(&activity);
        let rec_text = rec
            .unwrap_or_else(|| panic!("Expected recommendation for {technique}"))
            .to_lowercase();
        assert!(
            rec_text.contains(&expected_keyword.to_lowercase()),
            "Recommendation for {technique} should mention '{expected_keyword}', got: {rec_text}"
        );
    }
}

#[test]
fn recommend_detection_no_technique_id() {
    let mut activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    activity.technique_id = None;
    let rec = RedBlueCorrelator::recommend_detection(&activity);
    assert!(rec.is_none());
}

#[test]
fn determine_gap_reason_no_technique() {
    let mut activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    activity.technique_id = None;
    let reason = RedBlueCorrelator::determine_gap_reason(&activity, &[]);
    assert!(reason.contains("no associated MITRE technique"));
}

#[test]
fn determine_gap_reason_no_matching_alert() {
    let activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    let detections = vec![make_blue_detection(
        "Network Scan",
        "T1046",
        "192.168.58.10",
        utc(12, 5),
    )];
    let reason = RedBlueCorrelator::determine_gap_reason(&activity, &detections);
    assert!(reason.contains("No alert rules configured for technique T1003"));
}

#[test]
fn determine_gap_reason_alert_exists_but_no_trigger() {
    let activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    let detections = vec![make_blue_detection(
        "Credential Dumping",
        "T1003",
        "192.168.58.20",
        utc(14, 0), // Way outside time window
    )];
    let reason = RedBlueCorrelator::determine_gap_reason(&activity, &detections);
    assert!(reason.contains("Alert exists but did not trigger"));
}

#[test]
fn determine_gap_reason_hierarchical_technique_match() {
    // T1003 alert should match T1003.006 activity
    let activity = make_red_activity("T1003.006", "192.168.58.10", utc(12, 0));
    let detections = vec![make_blue_detection(
        "Credential Alert",
        "T1003",
        "192.168.58.20",
        utc(14, 0),
    )];
    let reason = RedBlueCorrelator::determine_gap_reason(&activity, &detections);
    // Since T1003 matches T1003.006 hierarchically, reason should mention trigger not time window
    assert!(reason.contains("Alert exists but did not trigger"));
}

#[test]
fn techniques_match_subtechnique_siblings() {
    // T1003.001 and T1003.006 share parent T1003 so they should match
    assert!(RedBlueCorrelator::techniques_match(
        Some("T1003.001"),
        Some("T1003.006")
    ));
}

#[test]
fn techniques_match_mixed_case() {
    assert!(RedBlueCorrelator::techniques_match(
        Some("t1558.001"),
        Some("T1558.003")
    ));
}

#[test]
fn red_team_activity_key() {
    let activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    let key = activity.key();
    assert!(key.contains("T1003"));
    assert!(key.contains("192.168.58.10"));
}

#[test]
fn red_team_activity_key_no_technique_no_ip() {
    let mut activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    activity.technique_id = None;
    activity.target_ip = None;
    let key = activity.key();
    assert!(key.contains("none:none"));
}

#[test]
fn blue_team_detection_key() {
    let detection = make_blue_detection(
        "Credential Dumping Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 2),
    );
    let key = detection.key();
    assert!(key.contains("T1003"));
    assert!(key.contains("Credential Dumping Alert"));
}

#[test]
fn blue_team_detection_key_no_technique() {
    let mut detection = make_blue_detection("Unknown Alert", "T1003", "192.168.58.10", utc(12, 2));
    detection.technique_id = None;
    let key = detection.key();
    assert!(key.contains("none"));
    assert!(key.contains("Unknown Alert"));
}

#[test]
fn match_quality_strong() {
    let m = super::types::CorrelationMatch {
        red_activity: make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        blue_detection: make_blue_detection("Alert", "T1003", "192.168.58.10", utc(12, 2)),
        time_delta_seconds: 120.0,
        technique_match: true,
        target_match: true,
        confidence: 0.9,
    };
    assert_eq!(m.match_quality(), "STRONG");
}

#[test]
fn match_quality_good() {
    let m = super::types::CorrelationMatch {
        red_activity: make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        blue_detection: make_blue_detection("Alert", "T1003", "192.168.58.20", utc(12, 8)),
        time_delta_seconds: 480.0,
        technique_match: true,
        target_match: false,
        confidence: 0.6,
    };
    assert_eq!(m.match_quality(), "GOOD");
}

#[test]
fn match_quality_weak_technique_only() {
    let m = super::types::CorrelationMatch {
        red_activity: make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        blue_detection: make_blue_detection("Alert", "T1003", "192.168.58.20", utc(12, 15)),
        time_delta_seconds: 900.0,
        technique_match: true,
        target_match: false,
        confidence: 0.5,
    };
    assert_eq!(m.match_quality(), "WEAK");
}

#[test]
fn match_quality_weak_target_close() {
    let m = super::types::CorrelationMatch {
        red_activity: make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        blue_detection: make_blue_detection("Alert", "T1046", "192.168.58.10", utc(12, 3)),
        time_delta_seconds: 180.0,
        technique_match: false,
        target_match: true,
        confidence: 0.4,
    };
    assert_eq!(m.match_quality(), "WEAK");
}

#[test]
fn match_quality_tenuous() {
    let m = super::types::CorrelationMatch {
        red_activity: make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        blue_detection: make_blue_detection("Alert", "T1046", "192.168.58.20", utc(12, 10)),
        time_delta_seconds: 600.0,
        technique_match: false,
        target_match: false,
        confidence: 0.2,
    };
    assert_eq!(m.match_quality(), "TENUOUS");
}

#[test]
fn correlate_multiple_red_activities_matched() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![
        make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        make_red_activity("T1046", "192.168.58.10", utc(12, 5)),
        make_red_activity("T1110", "192.168.58.10", utc(12, 10)),
    ];
    let blue = vec![
        make_blue_detection("Cred Alert", "T1003", "192.168.58.10", utc(12, 1)),
        make_blue_detection("Scan Alert", "T1046", "192.168.58.10", utc(12, 6)),
        make_blue_detection("Brute Alert", "T1110", "192.168.58.10", utc(12, 11)),
    ];

    let report = correlator.correlate(&red, &blue, "op-multi");
    assert_eq!(report.total_red_activities, 3);
    assert_eq!(report.matched_activities, 3);
    assert_eq!(report.undetected_activities, 0);
    assert!(report.detection_rate > 0.99);
    assert_eq!(report.false_positive_detections, 0);
}

#[test]
fn correlate_hierarchical_technique_matching() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    // Red uses subtechnique T1003.006, blue detects parent T1003
    let red = vec![make_red_activity("T1003.006", "192.168.58.10", utc(12, 0))];
    let blue = vec![make_blue_detection(
        "Credential Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 3),
    )];

    let report = correlator.correlate(&red, &blue, "op-hier");
    assert_eq!(report.matched_activities, 1);
    assert!(report.matches[0].technique_match);
}

#[test]
fn correlate_no_red_activities() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let blue = vec![make_blue_detection(
        "Spurious Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 0),
    )];

    let report = correlator.correlate(&[], &blue, "op-empty");
    assert_eq!(report.total_red_activities, 0);
    assert_eq!(report.total_blue_detections, 1);
    assert_eq!(report.matched_activities, 0);
    assert_eq!(report.detection_rate, 0.0);
}

#[test]
fn correlate_no_blue_detections() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![
        make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        make_red_activity("T1046", "192.168.58.20", utc(12, 5)),
    ];

    let report = correlator.correlate(&red, &[], "op-noalerts");
    assert_eq!(report.total_red_activities, 2);
    assert_eq!(report.matched_activities, 0);
    assert_eq!(report.undetected_activities, 2);
    assert_eq!(report.detection_rate, 0.0);
    assert_eq!(report.gaps.len(), 2);
}

#[test]
fn correlate_confidence_threshold() {
    // Matches below 0.3 confidence should not be included
    let correlator = RedBlueCorrelator::new("/tmp", Some(30));

    // Different technique, different IP, but within time window
    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![make_blue_detection(
        "Unrelated Alert",
        "T1046",
        "192.168.58.20",
        utc(12, 1),
    )];

    let report = correlator.correlate(&red, &blue, "op-lowconf");
    // No technique or target match, only time bonus (~0.2), below 0.3 threshold
    assert_eq!(report.matched_activities, 0);
    assert_eq!(report.undetected_activities, 1);
}

#[test]
fn correlate_detection_rate_partial() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![
        make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        make_red_activity("T1046", "192.168.58.20", utc(12, 5)),
        make_red_activity("T1110", "192.168.58.30", utc(12, 10)),
        make_red_activity("T1558.001", "192.168.58.40", utc(12, 15)),
    ];
    let blue = vec![
        make_blue_detection("Cred Alert", "T1003", "192.168.58.10", utc(12, 1)),
        make_blue_detection("Brute Alert", "T1110", "192.168.58.30", utc(12, 11)),
    ];

    let report = correlator.correlate(&red, &blue, "op-partial");
    assert_eq!(report.matched_activities, 2);
    assert_eq!(report.undetected_activities, 2);
    assert!((report.detection_rate - 0.5).abs() < 0.01);
}

#[test]
fn correlate_mean_time_to_detect_none_when_no_matches() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let report = correlator.correlate(&red, &[], "op-nomttd");
    assert!(report.mean_time_to_detect.is_none());
}

#[test]
fn correlate_technique_coverage_multiple_techniques() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![
        make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        make_red_activity("T1003", "192.168.58.11", utc(12, 2)),
        make_red_activity("T1003", "192.168.58.12", utc(12, 4)),
        make_red_activity("T1046", "192.168.58.20", utc(12, 10)),
    ];
    let blue = vec![
        make_blue_detection("Cred Alert", "T1003", "192.168.58.10", utc(12, 1)),
        make_blue_detection("Cred Alert 2", "T1003", "192.168.58.11", utc(12, 3)),
    ];

    let report = correlator.correlate(&red, &blue, "op-techcov");

    let t1003 = &report.technique_coverage["T1003"];
    assert_eq!(t1003.total, 3);
    assert!(t1003.detected >= 2);

    let t1046 = &report.technique_coverage["T1046"];
    assert_eq!(t1046.total, 1);
    assert_eq!(t1046.missed, 1);
    assert_eq!(t1046.detection_rate, 0.0);
}

#[test]
fn correlate_false_positive_rate() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![
        make_blue_detection("Cred Alert", "T1003", "192.168.58.10", utc(12, 1)),
        make_blue_detection("FP Alert 1", "T1078", "192.168.58.20", utc(12, 5)),
        make_blue_detection("FP Alert 2", "T1046", "192.168.58.30", utc(12, 10)),
    ];

    let report = correlator.correlate(&red, &blue, "op-fprate");
    assert_eq!(report.false_positive_detections, 2);
    // 2 false positives out of 3 detections in window
    assert!(report.false_positive_rate > 0.6);
}

#[test]
fn report_to_value_full_structure() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![
        make_red_activity("T1003", "192.168.58.10", utc(12, 0)),
        make_red_activity("T1046", "192.168.58.20", utc(12, 5)),
    ];
    let blue = vec![make_blue_detection(
        "Cred Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 1),
    )];

    let report = correlator.correlate(&red, &blue, "op-val");
    let val = report.to_value();

    // Check structure
    assert_eq!(val["red_operation_id"], "op-val");
    assert!(val["time_window"]["start"].is_string());
    assert!(val["time_window"]["end"].is_string());
    assert_eq!(val["summary"]["total_red_activities"], 2);
    assert_eq!(val["summary"]["total_blue_detections"], 1);

    // Check matches array
    let matches = val["matches"].as_array().unwrap();
    assert!(!matches.is_empty());
    assert!(matches[0]["red_technique"].is_string());
    assert!(matches[0]["red_action"].is_string());
    assert!(matches[0]["blue_alert"].is_string());
    assert!(matches[0]["match_quality"].is_string());
    assert!(matches[0]["confidence"].is_f64());

    // Check gaps array
    let gaps = val["gaps"].as_array().unwrap();
    assert!(!gaps.is_empty());
    assert!(gaps[0]["technique"].is_string());
    assert!(gaps[0]["reason"].is_string());
}

#[test]
fn correlate_best_match_selection() {
    // When multiple detections could match, engine should pick best confidence
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![
        // Weak match: different technique, same IP
        make_blue_detection("Generic Alert", "T1046", "192.168.58.10", utc(12, 1)),
        // Strong match: same technique, same IP, close time
        make_blue_detection("Cred Alert", "T1003", "192.168.58.10", utc(12, 1)),
    ];

    let report = correlator.correlate(&red, &blue, "op-best");
    assert_eq!(report.matched_activities, 1);
    assert!(report.matches[0].technique_match);
    assert!(report.matches[0].target_match);
    assert!(report.matches[0].confidence >= 0.8);
}

#[test]
fn correlate_time_window_custom() {
    // Custom time window of 2 minutes
    let correlator = RedBlueCorrelator::new("/tmp", Some(2));

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    // 3 minutes later should be outside 2-minute window
    let blue = vec![make_blue_detection(
        "Cred Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 3),
    )];

    let report = correlator.correlate(&red, &blue, "op-tw");
    assert_eq!(report.matched_activities, 0);
}

#[test]
fn correlate_detection_before_activity() {
    // Blue detection 2 minutes BEFORE red activity (should still match within window)
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 5))];
    let blue = vec![make_blue_detection(
        "Early Alert",
        "T1003",
        "192.168.58.10",
        utc(12, 3), // 2 minutes before
    )];

    let report = correlator.correlate(&red, &blue, "op-before");
    assert_eq!(report.matched_activities, 1);
    // time_delta should be negative (detection before activity)
    assert!(report.matches[0].time_delta_seconds < 0.0);
}

#[test]
fn new_default_time_window() {
    let correlator = RedBlueCorrelator::new("/tmp/reports", None);
    assert_eq!(
        correlator.time_window.num_minutes(),
        RedBlueCorrelator::DEFAULT_TIME_WINDOW_MINUTES
    );
}

#[test]
fn new_custom_time_window() {
    let correlator = RedBlueCorrelator::new("/tmp/reports", Some(60));
    assert_eq!(correlator.time_window.num_minutes(), 60);
}

// -----------------------------------------------------------------------
// recommend_detection — exhaustive per-technique checks
// -----------------------------------------------------------------------

#[test]
fn recommend_detection_t1046_mentions_scanning() {
    let activity = make_red_activity("T1046", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity).unwrap();
    assert!(rec.to_lowercase().contains("scanning"));
}

#[test]
fn recommend_detection_t1110_mentions_authentication() {
    let activity = make_red_activity("T1110", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity).unwrap();
    assert!(rec.to_lowercase().contains("authentication"));
}

#[test]
fn recommend_detection_t1003_mentions_lsass() {
    let activity = make_red_activity("T1003", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity).unwrap();
    assert!(rec.contains("LSASS"));
}

#[test]
fn recommend_detection_t1078_002_mentions_domain_admin() {
    let activity = make_red_activity("T1078.002", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity).unwrap();
    assert!(rec.to_lowercase().contains("domain admin"));
}

#[test]
fn recommend_detection_t1558_001_mentions_krbtgt() {
    let activity = make_red_activity("T1558.001", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity).unwrap();
    assert!(rec.to_lowercase().contains("krbtgt"));
}

#[test]
fn recommend_detection_t1021_002_mentions_smb() {
    let activity = make_red_activity("T1021.002", "192.168.58.10", utc(12, 0));
    let rec = RedBlueCorrelator::recommend_detection(&activity).unwrap();
    assert!(rec.to_lowercase().contains("smb"));
}

#[test]
fn recommend_detection_unknown_technique_returns_none() {
    let activity = make_red_activity("T9999", "192.168.58.10", utc(12, 0));
    assert!(RedBlueCorrelator::recommend_detection(&activity).is_none());
}

// -----------------------------------------------------------------------
// determine_gap_reason — additional edge cases
// -----------------------------------------------------------------------

#[test]
fn determine_gap_reason_empty_detections_list() {
    let activity = make_red_activity("T1046", "192.168.58.10", utc(12, 0));
    let reason = RedBlueCorrelator::determine_gap_reason(&activity, &[]);
    assert!(reason.contains("No alert rules configured for technique T1046"));
}

#[test]
fn determine_gap_reason_technique_matches_via_parent() {
    // Activity uses subtechnique, detection has parent -- should recognize as matching
    let activity = make_red_activity("T1078.002", "192.168.58.10", utc(12, 0));
    let detections = vec![make_blue_detection(
        "Valid Accounts Alert",
        "T1078",
        "192.168.58.20",
        utc(14, 0),
    )];
    let reason = RedBlueCorrelator::determine_gap_reason(&activity, &detections);
    assert!(reason.contains("Alert exists but did not trigger"));
}

// -----------------------------------------------------------------------
// correlate — additional edge cases
// -----------------------------------------------------------------------

#[test]
fn correlate_false_positive_rate_zero_when_no_detections_in_window() {
    let correlator = RedBlueCorrelator::new("/tmp", Some(5));

    // Red activity at 12:00, blue detection way outside the time window
    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![make_blue_detection(
        "Late Alert",
        "T1046",
        "192.168.58.20",
        utc(15, 0), // 3 hours later, well outside window
    )];

    let report = correlator.correlate(&red, &blue, "op-fpzero");
    // Detection is outside the time window, so false_positive_rate should be 0.0
    assert_eq!(report.false_positive_rate, 0.0);
}

#[test]
fn correlate_same_technique_different_ips_matches_by_technique() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    // Same technique but different IPs -- should still match via technique
    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![make_blue_detection(
        "Cred Alert",
        "T1003",
        "192.168.58.1", // Completely different IP
        utc(12, 1),
    )];

    let report = correlator.correlate(&red, &blue, "op-diffip");
    assert_eq!(report.matched_activities, 1);
    assert!(report.matches[0].technique_match);
    assert!(!report.matches[0].target_match);
}

#[test]
fn correlate_prefers_higher_confidence_match() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    let red = vec![make_red_activity("T1003", "192.168.58.10", utc(12, 0))];
    let blue = vec![
        // Weak match: only time proximity, no technique or IP match
        make_blue_detection("Unrelated", "T1046", "192.168.58.1", utc(12, 0)),
        // Strong match: technique + IP + close time
        make_blue_detection("Cred Alert", "T1003", "192.168.58.10", utc(12, 0)),
    ];

    let report = correlator.correlate(&red, &blue, "op-prefer");
    assert_eq!(report.matched_activities, 1);
    assert_eq!(report.matches[0].blue_detection.alert_name, "Cred Alert");
    assert!(report.matches[0].confidence >= 0.8);
}

#[test]
fn correlate_gaps_include_recommended_detection() {
    let correlator = RedBlueCorrelator::new("/tmp", None);

    // T1046 with no matching detections should produce a gap with a recommendation
    let red = vec![make_red_activity("T1046", "192.168.58.20", utc(12, 0))];

    let report = correlator.correlate(&red, &[], "op-gaprec");
    assert_eq!(report.gaps.len(), 1);
    let rec = report.gaps[0].recommended_detection.as_ref().unwrap();
    assert!(rec.to_lowercase().contains("scanning"));
}

#[test]
fn correlate_red_operation_id_propagated() {
    let correlator = RedBlueCorrelator::new("/tmp", None);
    let report = correlator.correlate(&[], &[], "my-custom-op-id");
    assert_eq!(report.red_operation_id, "my-custom-op-id");
}
