//! Top-level evaluation entry point and IOC/technique query helpers.

use chrono::Utc;

use crate::eval::ground_truth::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};
use crate::eval::results::EvaluationResult;

use super::scoring::{
    build_found_values, ioc_matches, score_evidence_quality, score_investigation_overall,
    score_ioc_detection, score_pyramid_elevation, score_stage_progress, score_technique_coverage,
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
    let pyramid_score = score_pyramid_elevation(snap);
    let evidence_score = score_evidence_quality(snap);
    let stage_score = score_stage_progress(snap);
    let timeline_score = score_timeline_accuracy(snap, gt);
    let overall = score_investigation_overall(snap, gt);

    let detection_score = (ioc_score + tech_score) / 2.0;
    let quality_score = (pyramid_score + evidence_score) / 2.0;
    let completeness_score = (stage_score + timeline_score) / 2.0;

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
        stage_score,
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
