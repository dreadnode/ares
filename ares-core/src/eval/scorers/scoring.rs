//! Scoring functions for investigation quality metrics.

use std::collections::HashSet;

use regex::Regex;

use crate::eval::ground_truth::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};

use super::types::InvestigationSnapshot;

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
pub(crate) fn build_found_values(snap: &InvestigationSnapshot) -> HashSet<String> {
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
pub(crate) fn ioc_matches(ioc: &ExpectedIOC, found: &HashSet<String>) -> bool {
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

pub(crate) fn technique_matches(expected: &ExpectedTechnique, found: &HashSet<String>) -> bool {
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
pub(crate) fn timeline_event_matches(pattern: &str, descriptions: &[String]) -> bool {
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
