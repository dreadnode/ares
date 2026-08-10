use std::collections::HashSet;

use crate::eval::ground_truth::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};
use crate::models::PyramidLevel;

use super::evaluate::{
    evaluate, get_found_iocs, get_found_techniques, get_missed_iocs, get_missed_techniques,
};
use super::scoring::{
    build_found_values, ioc_matches, score_investigation_overall, score_ioc_detection,
    score_technique_coverage, timeline_event_matches,
};
use super::types::{EvidenceItem, InvestigationSnapshot};

fn make_gt() -> EvaluationGroundTruth {
    EvaluationGroundTruth {
        operation_id: "op-1".to_string(),
        host_aliases: vec![],
        target_ip: "192.168.58.10".to_string(),
        expected_iocs: vec![
            ExpectedIOC {
                ioc_type: "ip".to_string(),
                value: "192.168.58.10".to_string(),
                pyramid_level: PyramidLevel::IpAddresses,
                mitre_techniques: vec!["T1046".to_string()],
                required: true,
                source: "".to_string(),
            },
            ExpectedIOC {
                ioc_type: "user".to_string(),
                value: "admin".to_string(),
                pyramid_level: PyramidLevel::NetworkHostArtifacts,
                mitre_techniques: vec![],
                required: true,
                source: "".to_string(),
            },
            ExpectedIOC {
                ioc_type: "hash".to_string(),
                value: "abc123".to_string(),
                pyramid_level: PyramidLevel::HashValues,
                mitre_techniques: vec![],
                required: false,
                source: "".to_string(),
            },
        ],
        expected_techniques: vec![
            ExpectedTechnique {
                technique_id: "T1003".to_string(),
                technique_name: "Credential Dumping".to_string(),
                required: true,
                parent_id: None,
            },
            ExpectedTechnique {
                technique_id: "T1046".to_string(),
                technique_name: "Network Service Discovery".to_string(),
                required: false,
                parent_id: None,
            },
        ],
        expected_timeline: vec![],
        expected_shares: vec![],
        expected_vulnerabilities: vec![],
        min_pyramid_level: 4,
        target_pyramid_level: 6,
        min_technique_coverage: 0.6,
        min_ioc_detection_rate: 0.5,
    }
}

fn make_snapshot() -> InvestigationSnapshot {
    InvestigationSnapshot {
        stage: Some("lateral".to_string()),
        evidence_values: vec![
            EvidenceItem {
                evidence_type: "ip".to_string(),
                value: "192.168.58.10".to_string(),
                pyramid_level: 2,
                confidence: 0.9,
                validated: true,
                mitre_techniques: vec![],
            },
            EvidenceItem {
                evidence_type: "user".to_string(),
                value: "admin".to_string(),
                pyramid_level: 4,
                confidence: 0.8,
                validated: true,
                mitre_techniques: vec![],
            },
            EvidenceItem {
                evidence_type: "tool".to_string(),
                value: "mimikatz".to_string(),
                pyramid_level: 6,
                confidence: 0.7,
                validated: false,
                mitre_techniques: vec![],
            },
        ],
        queried_hosts: HashSet::new(),
        queried_users: HashSet::new(),
        identified_techniques: HashSet::from(["T1003".to_string(), "T1046".to_string()]),
        timeline: vec![],
        highest_pyramid_level: 6,
    }
}

#[test]
fn ioc_detection_all_found() {
    let snap = make_snapshot();
    let mut gt = make_gt();
    // Remove hash IOC since snapshot doesn't have it
    gt.expected_iocs.retain(|i| i.ioc_type != "hash");

    let score = score_ioc_detection(&snap, &gt);
    assert!(
        score > 0.9,
        "All required IOCs found, expected >0.9 got {score}"
    );
}

#[test]
fn ioc_detection_none_found() {
    let snap = InvestigationSnapshot::default();
    let gt = make_gt();
    let score = score_ioc_detection(&snap, &gt);
    assert!(score < 0.5, "No IOCs found, expected <0.5 got {score}");
}

#[test]
fn ioc_user_domain_prefix() {
    let snap = InvestigationSnapshot {
        evidence_values: vec![EvidenceItem {
            evidence_type: "user".to_string(),
            value: "admin".to_string(),
            pyramid_level: 4,
            confidence: 0.9,
            validated: true,
            mitre_techniques: vec![],
        }],
        ..Default::default()
    };

    let ioc = ExpectedIOC {
        ioc_type: "user".to_string(),
        value: "CONTOSO\\admin".to_string(),
        pyramid_level: PyramidLevel::NetworkHostArtifacts,
        mitre_techniques: vec![],
        required: true,
        source: "".to_string(),
    };

    let found = build_found_values(&snap);
    assert!(ioc_matches(&ioc, &found));
}

#[test]
fn technique_coverage_all() {
    let snap = make_snapshot();
    let gt = make_gt();
    let score = score_technique_coverage(&snap, &gt);
    assert!(
        (score - 1.0).abs() < f64::EPSILON,
        "All techniques found, expected 1.0 got {score}"
    );
}

#[test]
fn technique_coverage_partial() {
    let mut snap = make_snapshot();
    snap.identified_techniques = HashSet::from(["T1003".to_string()]);
    let gt = make_gt();
    let score = score_technique_coverage(&snap, &gt);
    // Required T1003 found (1/1) = 1.0 × 0.6 = 0.6
    // Optional T1046 not found (0/1) = 0.0 × 0.4 = 0.0
    assert!(
        (score - 0.6).abs() < 0.01,
        "Partial coverage, expected ~0.6 got {score}"
    );
}

#[test]
fn overall_score() {
    let snap = make_snapshot();
    let gt = make_gt();
    let score = score_investigation_overall(&snap, &gt);
    assert!(score > 0.5, "Good investigation, expected >0.5 got {score}");
}

#[test]
fn timeline_event_matches_substring() {
    let descriptions = vec!["credential dumping via lsass access".to_string()];
    assert!(timeline_event_matches("lsass access", &descriptions));
    assert!(!timeline_event_matches("rdp brute force", &descriptions));
}

#[test]
fn timeline_event_matches_keyword() {
    let descriptions = vec!["detected credential dumping using mimikatz tool".to_string()];
    assert!(timeline_event_matches(
        "credential dumping mimikatz",
        &descriptions
    ));
}

#[test]
fn evaluate_builds_result() {
    let snap = make_snapshot();
    let gt = make_gt();
    let result = evaluate("eval-1", &snap, &gt, true, "claude-opus-4-6", 120.0);

    assert_eq!(result.evaluation_id, "eval-1");
    assert_eq!(result.operation_id, "op-1");
    assert!(result.overall_score > 0.0);
    assert!(result.alert_fired);
    assert!(result.investigation_started);
    assert!(!result.investigation_completed); // stage=lateral, not synthesis
    assert!(
        matches!(result.grade(), "B" | "C"),
        "Expected B or C, got {}",
        result.grade()
    );
}

#[test]
fn missed_and_found_iocs() {
    let snap = make_snapshot();
    let gt = make_gt();
    let missed = get_missed_iocs(&snap, &gt);
    let found = get_found_iocs(&snap, &gt);

    // IP and user are found, hash is not
    assert_eq!(found.len(), 2);
    assert_eq!(missed.len(), 1);
    assert_eq!(missed[0].ioc_type, "hash");
}

#[test]
fn missed_and_found_techniques() {
    let snap = make_snapshot();
    let gt = make_gt();
    let missed = get_missed_techniques(&snap, &gt);
    let found = get_found_techniques(&snap, &gt);

    assert_eq!(found.len(), 2);
    assert_eq!(missed.len(), 0);
}
