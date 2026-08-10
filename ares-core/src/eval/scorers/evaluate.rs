//! Top-level evaluation entry point and IOC/technique query helpers.

use chrono::Utc;

use crate::eval::ground_truth::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};
use crate::eval::results::EvaluationResult;

use super::scoring::{
    build_found_values, ioc_matches, score_evidence_quality, score_investigation_overall,
    score_ioc_detection, score_phase_coverage, score_pyramid_elevation, score_technique_coverage,
    score_timeline_accuracy, technique_matches,
};
use super::types::InvestigationSnapshot;

/// Get IOCs that were not detected.
pub fn get_missed_iocs<'a>(
    snap: &InvestigationSnapshot,
    gt: &'a EvaluationGroundTruth,
) -> Vec<&'a ExpectedIOC> {
    let found = build_found_values(snap);
    gt.expected_iocs
        .iter()
        .filter(|ioc| !ioc_matches(ioc, &found))
        .collect()
}

/// Get IOCs that were successfully detected.
pub fn get_found_iocs<'a>(
    snap: &InvestigationSnapshot,
    gt: &'a EvaluationGroundTruth,
) -> Vec<&'a ExpectedIOC> {
    let found = build_found_values(snap);
    gt.expected_iocs
        .iter()
        .filter(|ioc| ioc_matches(ioc, &found))
        .collect()
}

/// Get techniques that were not identified.
pub fn get_missed_techniques<'a>(
    snap: &InvestigationSnapshot,
    gt: &'a EvaluationGroundTruth,
) -> Vec<&'a ExpectedTechnique> {
    gt.expected_techniques
        .iter()
        .filter(|t| !technique_matches(t, &snap.identified_techniques))
        .collect()
}

/// Get techniques that were successfully identified.
pub fn get_found_techniques<'a>(
    snap: &InvestigationSnapshot,
    gt: &'a EvaluationGroundTruth,
) -> Vec<&'a ExpectedTechnique> {
    gt.expected_techniques
        .iter()
        .filter(|t| technique_matches(t, &snap.identified_techniques))
        .collect()
}

/// Build a full `EvaluationResult` from a snapshot and ground truth.
pub fn evaluate(
    evaluation_id: &str,
    snap: &InvestigationSnapshot,
    gt: &EvaluationGroundTruth,
    alert_fired: bool,
    model: &str,
    duration_seconds: f64,
) -> EvaluationResult {
    let ioc_score = score_ioc_detection(snap, gt);
    let tech_score = score_technique_coverage(snap, gt);
    let pyramid_score = score_pyramid_elevation(snap, gt);
    let evidence_score = score_evidence_quality(snap, gt);
    let phase_score = score_phase_coverage(snap, gt);
    let timeline_score = score_timeline_accuracy(snap, gt);
    let overall = score_investigation_overall(snap, gt);

    let detection_score = (ioc_score + tech_score) / 2.0;
    let quality_score = (pyramid_score + evidence_score) / 2.0;
    // Timeline is a vacuous 1.0 when there's no expected_timeline; don't let it
    // inflate completeness in that case.
    let completeness_score = if gt.expected_timeline.is_empty() {
        phase_score
    } else {
        (phase_score + timeline_score) / 2.0
    };

    let missed_iocs: Vec<ExpectedIOC> = get_missed_iocs(snap, gt).into_iter().cloned().collect();
    let found_iocs: Vec<ExpectedIOC> = get_found_iocs(snap, gt).into_iter().cloned().collect();
    let missed_techniques: Vec<ExpectedTechnique> = get_missed_techniques(snap, gt)
        .into_iter()
        .cloned()
        .collect();
    let found_techniques: Vec<ExpectedTechnique> = get_found_techniques(snap, gt)
        .into_iter()
        .cloned()
        .collect();

    let ttp_count = snap
        .evidence_values
        .iter()
        .filter(|e| e.pyramid_level == 6)
        .count();

    let investigation_started = snap.stage.is_some();
    let investigation_completed = snap.stage.as_deref() == Some("synthesis");

    EvaluationResult {
        evaluation_id: evaluation_id.to_string(),
        operation_id: gt.operation_id.clone(),
        evaluated_at: Utc::now(),
        overall_score: overall,
        detection_score,
        quality_score,
        completeness_score,
        // Populated with kill-chain phase coverage (renamed field in results.rs).
        phase_coverage: phase_score,
        ioc_detection_rate: ioc_score,
        technique_coverage: tech_score,
        pyramid_elevation_score: pyramid_score,
        timeline_accuracy: timeline_score,
        evidence_quality_score: evidence_score,
        final_stage: snap.stage.clone(),
        stages_completed: Vec::new(),
        missed_iocs,
        missed_techniques,
        found_iocs,
        found_techniques,
        evidence_count: snap.evidence_values.len(),
        highest_pyramid_level: snap.highest_pyramid_level,
        ttp_count,
        alert_fired,
        investigation_started,
        investigation_completed,
        model: model.to_string(),
        duration_seconds,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::ground_truth::{ExpectedIOC, ExpectedTechnique};
    use crate::eval::scorers::types::{EvidenceItem, InvestigationSnapshot};
    use crate::models::PyramidLevel;

    fn empty_snap() -> InvestigationSnapshot {
        InvestigationSnapshot::default()
    }

    fn empty_gt() -> EvaluationGroundTruth {
        EvaluationGroundTruth {
            operation_id: "op-1".into(),
            host_aliases: vec![],
            target_ip: "192.168.58.1".into(),
            expected_iocs: vec![],
            expected_techniques: vec![],
            expected_timeline: vec![],
            expected_shares: vec![],
            expected_vulnerabilities: vec![],
            min_pyramid_level: 4,
            target_pyramid_level: 6,
            min_technique_coverage: 0.6,
            min_ioc_detection_rate: 0.5,
        }
    }

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

    fn make_technique(id: &str, required: bool) -> ExpectedTechnique {
        ExpectedTechnique {
            technique_id: id.into(),
            technique_name: String::new(),
            required,
            parent_id: None,
        }
    }

    fn make_evidence(etype: &str, value: &str, pyramid: u32) -> EvidenceItem {
        EvidenceItem {
            evidence_type: etype.into(),
            value: value.into(),
            pyramid_level: pyramid,
            confidence: 0.9,
            validated: true,
            mitre_techniques: Vec::new(),
        }
    }

    #[test]
    fn missed_iocs_all_missed() {
        let snap = empty_snap();
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        let missed = get_missed_iocs(&snap, &gt);
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0].value, "192.168.58.1");
    }

    #[test]
    fn missed_iocs_none_missed() {
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 1));
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        assert!(get_missed_iocs(&snap, &gt).is_empty());
    }

    #[test]
    fn missed_iocs_empty_gt() {
        let snap = empty_snap();
        let gt = empty_gt();
        assert!(get_missed_iocs(&snap, &gt).is_empty());
    }

    #[test]
    fn found_iocs_all_found() {
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 1));
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        let found = get_found_iocs(&snap, &gt);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn found_iocs_none_found() {
        let snap = empty_snap();
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        assert!(get_found_iocs(&snap, &gt).is_empty());
    }

    #[test]
    fn found_iocs_partial() {
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 1));
        let mut gt = empty_gt();
        gt.expected_iocs = vec![
            make_ioc("ip", "192.168.58.1", true),
            make_ioc("ip", "192.168.58.2", true),
        ];
        assert_eq!(get_found_iocs(&snap, &gt).len(), 1);
    }

    #[test]
    fn missed_techniques_all_missed() {
        let snap = empty_snap();
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        let missed = get_missed_techniques(&snap, &gt);
        assert_eq!(missed.len(), 1);
    }

    #[test]
    fn missed_techniques_none_missed() {
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1003".into());
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        assert!(get_missed_techniques(&snap, &gt).is_empty());
    }

    #[test]
    fn found_techniques_all_found() {
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1003".into());
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        assert_eq!(get_found_techniques(&snap, &gt).len(), 1);
    }

    #[test]
    fn found_techniques_parent_matches_sub() {
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1003.001".into());
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        assert_eq!(get_found_techniques(&snap, &gt).len(), 1);
    }

    #[test]
    fn evaluate_empty_returns_valid_result() {
        let snap = empty_snap();
        let gt = empty_gt();
        let result = evaluate("eval-1", &snap, &gt, false, "gpt-4o", 60.0);
        assert_eq!(result.evaluation_id, "eval-1");
        assert_eq!(result.operation_id, "op-1");
        assert!(!result.alert_fired);
        assert_eq!(result.model, "gpt-4o");
        assert!((0.0..=1.0).contains(&result.overall_score));
    }

    #[test]
    fn evaluate_with_findings() {
        let mut snap = empty_snap();
        snap.stage = Some("synthesis".to_string());
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 2));
        snap.identified_techniques.insert("T1003".into());
        snap.highest_pyramid_level = 5;

        let mut gt = empty_gt();
        gt.expected_iocs = vec![
            make_ioc("ip", "192.168.58.1", true),
            make_ioc("ip", "192.168.58.2", true),
        ];
        gt.expected_techniques = vec![make_technique("T1003", true)];

        let result = evaluate("eval-2", &snap, &gt, true, "claude", 120.0);
        assert!(result.investigation_started);
        assert!(result.investigation_completed);
        assert!(result.alert_fired);
        assert_eq!(result.found_iocs.len(), 1);
        assert_eq!(result.missed_iocs.len(), 1);
        assert_eq!(result.found_techniques.len(), 1);
        assert!(result.missed_techniques.is_empty());
        assert_eq!(result.evidence_count, 1);
    }

    #[test]
    fn evaluate_ttp_count() {
        let mut snap = empty_snap();
        snap.evidence_values.push(make_evidence("ttp", "T1003", 6));
        snap.evidence_values.push(make_evidence("ttp", "T1046", 6));
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 2));
        snap.highest_pyramid_level = 6;

        let gt = empty_gt();
        let result = evaluate("eval-3", &snap, &gt, false, "test", 30.0);
        assert_eq!(result.ttp_count, 2);
        assert_eq!(result.evidence_count, 3);
    }

    #[test]
    fn evaluate_not_started() {
        let snap = empty_snap();
        let gt = empty_gt();
        let result = evaluate("eval-4", &snap, &gt, false, "test", 0.0);
        assert!(!result.investigation_started);
        assert!(!result.investigation_completed);
    }

    #[test]
    fn evaluate_scores_bounded() {
        let mut snap = empty_snap();
        snap.stage = Some("triage".to_string());
        let gt = empty_gt();
        let result = evaluate("eval-5", &snap, &gt, false, "test", 10.0);
        assert!((0.0..=1.0).contains(&result.detection_score));
        assert!((0.0..=1.0).contains(&result.quality_score));
        assert!((0.0..=1.0).contains(&result.completeness_score));
        assert!((0.0..=1.0).contains(&result.overall_score));
    }
}
