use chrono::Utc;

use super::builders::build_technique_detections;
use super::names::{get_technique_name, pyramid_level_name};
use ares_core::models::SharedRedTeamState;

#[test]
fn test_get_technique_name_known() {
    assert_eq!(get_technique_name("T1046"), "Network Service Discovery");
    assert_eq!(get_technique_name("T1003"), "OS Credential Dumping");
    assert_eq!(get_technique_name("T1003.006"), "DCSync");
    assert_eq!(get_technique_name("T1558.003"), "Kerberoasting");
    assert_eq!(get_technique_name("T1558.004"), "AS-REP Roasting");
    assert_eq!(get_technique_name("T1021.002"), "SMB/Windows Admin Shares");
    assert_eq!(get_technique_name("T1649"), "ADCS Certificate Theft");
    assert_eq!(get_technique_name("T1550.002"), "Pass the Hash");
}

#[test]
fn test_get_technique_name_unknown() {
    assert_eq!(get_technique_name("T9999"), "");
    assert_eq!(get_technique_name(""), "");
}

#[test]
fn test_pyramid_level_name_all_levels() {
    assert_eq!(pyramid_level_name(1), "Hash Values (L1)");
    assert_eq!(pyramid_level_name(2), "IP Addresses (L2)");
    assert_eq!(pyramid_level_name(3), "Domain Names (L3)");
    assert_eq!(pyramid_level_name(4), "Network/Host Artifacts (L4)");
    assert_eq!(pyramid_level_name(5), "Tools (L5)");
    assert_eq!(pyramid_level_name(6), "TTPs (L6)");
}

#[test]
fn test_pyramid_level_name_unknown() {
    assert_eq!(pyramid_level_name(0), "Unknown");
    assert_eq!(pyramid_level_name(7), "Unknown");
    assert_eq!(pyramid_level_name(255), "Unknown");
}

#[test]
fn test_build_technique_detections_known_techniques() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1046".to_string(), "T1003".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 2);
    assert!(detections.contains_key("T1046"));
    assert!(detections.contains_key("T1003"));
    assert_eq!(
        detections["T1046"].technique_name,
        "Network Service Discovery"
    );
    assert!(!detections["T1046"].detection_queries.is_empty());
}

#[test]
fn test_build_technique_detections_sub_technique() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1003.006".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections["T1003.006"].technique_name, "DCSync");
}

#[test]
fn test_build_technique_detections_empty() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now();
    let end = Utc::now();
    let detections = build_technique_detections(&state, &[], &start, &end);
    assert!(detections.is_empty());
}

#[test]
fn test_technique_detection_has_event_ids() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1558.003".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    let det = &detections["T1558.003"];
    assert!(!det.windows_event_ids.is_empty());
    assert!(!det.log_sources.is_empty());
}
