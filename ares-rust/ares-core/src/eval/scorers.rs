//! Scoring functions for blue team evaluation.
//!
//! Each scorer evaluates investigation state against ground truth and returns
//! a float score between 0.0 and 1.0. Replaces the Dreadnode `@dn.scorer`
//! decorated Python functions with plain Rust functions.

use std::collections::HashSet;

use chrono::Utc;
use regex::Regex;

use super::ground_truth::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};
use super::results::EvaluationResult;

/// Input for scoring functions: investigation evidence data extracted from state.
#[derive(Debug, Clone, Default)]
pub struct InvestigationSnapshot {
    /// Current stage: triage, causation, lateral, synthesis
    pub stage: Option<String>,
    /// Evidence values (lowercase).
    pub evidence_values: Vec<EvidenceItem>,
    /// Queried hosts (lowercase).
    pub queried_hosts: HashSet<String>,
    /// Queried users (lowercase).
    pub queried_users: HashSet<String>,
    /// Identified MITRE technique IDs.
    pub identified_techniques: HashSet<String>,
    /// Timeline event descriptions.
    pub timeline: Vec<TimelineEvent>,
    /// Highest pyramid level reached (1–6).
    pub highest_pyramid_level: u32,
}

/// A piece of evidence from the investigation.
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub evidence_type: String,
    pub value: String,
    pub pyramid_level: u32,
    pub confidence: f64,
    pub validated: bool,
}

/// A timeline event.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub description: String,
    pub mitre_techniques: HashSet<String>,
}

// ---------------------------------------------------------------------------
// Scorer 1: Stage Progress (0.0–1.0)
// ---------------------------------------------------------------------------

/// Score investigation stage progress.
///
/// - TRIAGE: 0.25, CAUSATION: 0.50, LATERAL: 0.75, SYNTHESIS: 1.0
pub fn score_stage_progress(snap: &InvestigationSnapshot) -> f64 {
    match snap.stage.as_deref() {
        Some("triage") => 0.25,
        Some("causation") => 0.50,
        Some("lateral") => 0.75,
        Some("synthesis") => 1.0,
        _ => 0.0,
    }
}

// ---------------------------------------------------------------------------
// Scorer 2: IOC Detection Rate (0.0–1.0)
// ---------------------------------------------------------------------------

/// Score IOC detection rate.
///
/// Compares evidence found against expected IOCs with fuzzy matching.
/// Weighting: 60% required IOCs, 40% optional IOCs.
pub fn score_ioc_detection(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    if gt.expected_iocs.is_empty() {
        return 1.0;
    }

    let found_values = build_found_values(snap);

    let required = gt.required_iocs();
    let optional = gt.optional_iocs();

    let required_found = required
        .iter()
        .filter(|ioc| ioc_matches(ioc, &found_values))
        .count();
    let optional_found = optional
        .iter()
        .filter(|ioc| ioc_matches(ioc, &found_values))
        .count();

    let required_score = if required.is_empty() {
        1.0
    } else {
        required_found as f64 / required.len() as f64
    };
    let optional_score = if optional.is_empty() {
        1.0
    } else {
        optional_found as f64 / optional.len() as f64
    };

    (required_score * 0.6) + (optional_score * 0.4)
}

/// Build set of lowercase found values from evidence and queries.
fn build_found_values(snap: &InvestigationSnapshot) -> HashSet<String> {
    let mut found: HashSet<String> = HashSet::new();

    for item in &snap.evidence_values {
        let val = item.value.to_lowercase();
        // Also add partial hostname matches
        if item.evidence_type == "hostname" || item.evidence_type == "domain" {
            if let Some(first) = val.split('.').next() {
                found.insert(first.to_string());
            }
        }
        found.insert(val);
    }

    for host in &snap.queried_hosts {
        found.insert(host.to_lowercase());
    }
    for user in &snap.queried_users {
        found.insert(user.to_lowercase());
    }

    found
}

/// Check if an expected IOC matches any found value.
fn ioc_matches(ioc: &ExpectedIOC, found: &HashSet<String>) -> bool {
    let val = ioc.value.to_lowercase();

    // Exact match
    if found.contains(&val) {
        return true;
    }

    // Hostname/domain: partial match
    if ioc.ioc_type == "hostname" || ioc.ioc_type == "domain" {
        for f in found {
            if val.contains(f.as_str()) || f.contains(val.as_str()) {
                return true;
            }
        }
        if let Some(first) = val.split('.').next() {
            if found.contains(first) {
                return true;
            }
        }
    }

    // User: handle domain\user and user@domain
    if ioc.ioc_type == "user" {
        if val.contains('\\') {
            if let Some(username) = val.split('\\').next_back() {
                if found.contains(username) {
                    return true;
                }
            }
        }
        if val.contains('@') {
            if let Some(username) = val.split('@').next() {
                if found.contains(username) {
                    return true;
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Scorer 3: Technique Coverage (0.0–1.0)
// ---------------------------------------------------------------------------

/// Score MITRE technique coverage.
///
/// Supports parent/sub-technique matching. Weighting: 60% required, 40% optional.
pub fn score_technique_coverage(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    if gt.expected_techniques.is_empty() {
        return 1.0;
    }

    let required = gt.required_techniques();
    let optional = gt.optional_techniques();

    let required_found = required
        .iter()
        .filter(|t| technique_matches(t, &snap.identified_techniques))
        .count();
    let optional_found = optional
        .iter()
        .filter(|t| technique_matches(t, &snap.identified_techniques))
        .count();

    let required_score = if required.is_empty() {
        1.0
    } else {
        required_found as f64 / required.len() as f64
    };
    let optional_score = if optional.is_empty() {
        1.0
    } else {
        optional_found as f64 / optional.len() as f64
    };

    (required_score * 0.6) + (optional_score * 0.4)
}

fn technique_matches(expected: &ExpectedTechnique, found: &HashSet<String>) -> bool {
    found.iter().any(|f| expected.matches(f))
}

// ---------------------------------------------------------------------------
// Scorer 4: Pyramid Elevation (0.0–1.0)
// ---------------------------------------------------------------------------

/// Score Pyramid of Pain elevation.
///
/// 70% weight: highest_level/6, 30% weight: ratio of evidence at level 5–6.
pub fn score_pyramid_elevation(snap: &InvestigationSnapshot) -> f64 {
    if snap.evidence_values.is_empty() {
        return 0.0;
    }

    let highest_score = snap.highest_pyramid_level as f64 / 6.0;

    let high_level = snap
        .evidence_values
        .iter()
        .filter(|e| e.pyramid_level >= 5)
        .count();
    let high_ratio = high_level as f64 / snap.evidence_values.len() as f64;

    (highest_score * 0.7) + (high_ratio * 0.3)
}

// ---------------------------------------------------------------------------
// Scorer 5: Timeline Accuracy (0.0–1.0)
// ---------------------------------------------------------------------------

/// Score timeline accuracy.
///
/// 60% event matching, 40% technique association in timeline.
pub fn score_timeline_accuracy(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    if gt.expected_timeline.is_empty() {
        return 1.0;
    }
    if snap.timeline.is_empty() {
        return 0.0;
    }

    let descriptions: Vec<String> = snap
        .timeline
        .iter()
        .map(|e| e.description.to_lowercase())
        .collect();

    let mut found_techniques: HashSet<String> = HashSet::new();
    for event in &snap.timeline {
        found_techniques.extend(event.mitre_techniques.iter().cloned());
    }

    // Event matching
    let matched = gt
        .expected_timeline
        .iter()
        .filter(|e| timeline_event_matches(&e.description_pattern, &descriptions))
        .count();
    let event_score = matched as f64 / gt.expected_timeline.len() as f64;

    // Technique coverage in timeline
    let expected_techs: HashSet<String> = gt
        .expected_timeline
        .iter()
        .flat_map(|e| e.mitre_techniques.iter().cloned())
        .collect();

    let technique_score = if expected_techs.is_empty() {
        1.0
    } else {
        let overlap = expected_techs.intersection(&found_techniques).count();
        overlap as f64 / expected_techs.len() as f64
    };

    (event_score * 0.6) + (technique_score * 0.4)
}

/// Match a pattern against any description using multiple strategies.
fn timeline_event_matches(pattern: &str, descriptions: &[String]) -> bool {
    use std::sync::LazyLock;
    static WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\w+").unwrap());

    let pattern_lower = pattern.to_lowercase();

    for desc in descriptions {
        // Strategy 1: regex match if pattern contains regex metacharacters
        if pattern.contains(|c: char| ".*+?[](){}^$|\\".contains(c)) {
            if let Ok(re) = Regex::new(&pattern_lower) {
                if re.is_match(desc) {
                    return true;
                }
            }
        }

        // Strategy 2: substring match
        if pattern_lower.contains(desc.as_str()) || desc.contains(pattern_lower.as_str()) {
            return true;
        }

        // Strategy 3: keyword overlap (>50% of significant words)
        static STOP_WORDS: &[&str] = &[
            "the", "and", "for", "was", "were", "with", "from", "that", "this", "have", "has",
            "been", "which", "into", "user",
        ];

        let extract_words = |text: &str| -> HashSet<String> {
            WORD_RE
                .find_iter(text)
                .map(|m| m.as_str().to_lowercase())
                .filter(|w| w.len() > 3 && !STOP_WORDS.contains(&w.as_str()))
                .collect()
        };

        let pattern_words = extract_words(&pattern_lower);
        let desc_words = extract_words(desc);

        if !pattern_words.is_empty() && !desc_words.is_empty() {
            let overlap = pattern_words.intersection(&desc_words).count();
            if overlap as f64 >= pattern_words.len() as f64 * 0.5 {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Scorer 6: Evidence Quality (0.0–1.0)
// ---------------------------------------------------------------------------

/// Score evidence quality.
///
/// 40% average confidence, 30% validation rate, 30% TTP ratio.
pub fn score_evidence_quality(snap: &InvestigationSnapshot) -> f64 {
    if snap.evidence_values.is_empty() {
        return 0.0;
    }

    let n = snap.evidence_values.len() as f64;

    let avg_confidence: f64 = snap
        .evidence_values
        .iter()
        .map(|e| e.confidence)
        .sum::<f64>()
        / n;

    let validated = snap.evidence_values.iter().filter(|e| e.validated).count() as f64;
    let validation_rate = validated / n;

    let ttp = snap
        .evidence_values
        .iter()
        .filter(|e| e.pyramid_level == 6) // TTPs
        .count() as f64;
    let ttp_ratio = ttp / n;

    (avg_confidence * 0.4) + (validation_rate * 0.3) + (ttp_ratio * 0.3)
}

// ---------------------------------------------------------------------------
// Composite scorer
// ---------------------------------------------------------------------------

/// Compute the overall investigation quality score.
///
/// Weights: IOC 17.5%, Technique 17.5%, Pyramid 15%, Evidence 15%, Stage 17.5%, Timeline 17.5%.
pub fn score_investigation_overall(
    snap: &InvestigationSnapshot,
    gt: &EvaluationGroundTruth,
) -> f64 {
    let scores = [
        (score_ioc_detection(snap, gt), 3.5),
        (score_technique_coverage(snap, gt), 3.5),
        (score_pyramid_elevation(snap), 3.0),
        (score_evidence_quality(snap), 3.0),
        (score_stage_progress(snap), 3.5),
        (score_timeline_accuracy(snap, gt), 3.5),
    ];

    let total_weight: f64 = scores.iter().map(|(_, w)| w).sum();
    let weighted_sum: f64 = scores.iter().map(|(s, w)| s * w).sum();

    weighted_sum / total_weight
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PyramidLevel;

    fn make_gt() -> EvaluationGroundTruth {
        EvaluationGroundTruth {
            operation_id: "op-1".to_string(),
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
                },
                EvidenceItem {
                    evidence_type: "user".to_string(),
                    value: "admin".to_string(),
                    pyramid_level: 4,
                    confidence: 0.8,
                    validated: true,
                },
                EvidenceItem {
                    evidence_type: "tool".to_string(),
                    value: "mimikatz".to_string(),
                    pyramid_level: 6,
                    confidence: 0.7,
                    validated: false,
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
    fn test_stage_progress() {
        let mut snap = InvestigationSnapshot::default();
        assert_eq!(score_stage_progress(&snap), 0.0);

        snap.stage = Some("triage".to_string());
        assert_eq!(score_stage_progress(&snap), 0.25);

        snap.stage = Some("synthesis".to_string());
        assert_eq!(score_stage_progress(&snap), 1.0);
    }

    #[test]
    fn test_ioc_detection_all_found() {
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
    fn test_ioc_detection_none_found() {
        let snap = InvestigationSnapshot::default();
        let gt = make_gt();
        let score = score_ioc_detection(&snap, &gt);
        assert!(score < 0.5, "No IOCs found, expected <0.5 got {score}");
    }

    #[test]
    fn test_ioc_user_domain_prefix() {
        let snap = InvestigationSnapshot {
            evidence_values: vec![EvidenceItem {
                evidence_type: "user".to_string(),
                value: "admin".to_string(),
                pyramid_level: 4,
                confidence: 0.9,
                validated: true,
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
    fn test_technique_coverage_all() {
        let snap = make_snapshot();
        let gt = make_gt();
        let score = score_technique_coverage(&snap, &gt);
        assert!(
            (score - 1.0).abs() < f64::EPSILON,
            "All techniques found, expected 1.0 got {score}"
        );
    }

    #[test]
    fn test_technique_coverage_partial() {
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
    fn test_pyramid_elevation() {
        let snap = make_snapshot();
        let score = score_pyramid_elevation(&snap);
        // highest_level=6/6 * 0.7 = 0.7
        // 1 TTP out of 3 evidence = 0.333 * 0.3 = 0.1
        // Total ≈ 0.8
        assert!(score > 0.7, "High pyramid, expected >0.7 got {score}");
    }

    #[test]
    fn test_evidence_quality() {
        let snap = make_snapshot();
        let score = score_evidence_quality(&snap);
        // avg_confidence = (0.9+0.8+0.7)/3 = 0.8 * 0.4 = 0.32
        // validated = 2/3 = 0.667 * 0.3 = 0.2
        // ttp = 1/3 = 0.333 * 0.3 = 0.1
        // Total ≈ 0.62
        assert!(score > 0.5, "Good quality, expected >0.5 got {score}");
    }

    #[test]
    fn test_overall_score() {
        let snap = make_snapshot();
        let gt = make_gt();
        let score = score_investigation_overall(&snap, &gt);
        assert!(score > 0.5, "Good investigation, expected >0.5 got {score}");
    }

    #[test]
    fn test_timeline_event_matches_substring() {
        let descriptions = vec!["credential dumping via lsass access".to_string()];
        assert!(timeline_event_matches("lsass access", &descriptions));
        assert!(!timeline_event_matches("rdp brute force", &descriptions));
    }

    #[test]
    fn test_timeline_event_matches_keyword() {
        let descriptions = vec!["detected credential dumping using mimikatz tool".to_string()];
        assert!(timeline_event_matches(
            "credential dumping mimikatz",
            &descriptions
        ));
    }

    #[test]
    fn test_evaluate_builds_result() {
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
    fn test_missed_and_found_iocs() {
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
    fn test_missed_and_found_techniques() {
        let snap = make_snapshot();
        let gt = make_gt();
        let missed = get_missed_techniques(&snap, &gt);
        let found = get_found_techniques(&snap, &gt);

        assert_eq!(found.len(), 2);
        assert_eq!(missed.len(), 0);
    }
}
