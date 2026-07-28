//! Coverage of red team activity, measured against red team ground truth.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::correlation::redblue::RedBlueCorrelator;
use crate::models::{SharedBlueTeamState, SharedRedTeamState};

/// Whether a blue technique counts as a detection of a red technique.
///
/// Exact matches count, and so does a parent/child pair in either direction:
/// detecting T1003.006 evidences red's generic T1003, and a blue T1003 covers
/// red's T1003.006. Sibling sub-techniques do not count — see
/// [`RedBlueCorrelator::techniques_match`], which this shares so the report and
/// `ares ops correlate` cannot disagree about what counts as a detection.
fn covers(red: &str, blue: &str) -> bool {
    RedBlueCorrelator::techniques_match(Some(red), Some(blue))
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageEntry {
    pub id: String,
    pub matched_by: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RedTeamCoverage {
    pub red_technique_count: usize,
    pub detected_count: usize,
    pub missed_count: usize,
    pub detection_rate_display: String,
    pub detected: Vec<CoverageEntry>,
    pub missed: Vec<String>,
    pub blue_only: Vec<String>,
}

fn normalize(raw: &str) -> Option<String> {
    let t = raw.trim().to_uppercase();
    (!t.is_empty()).then_some(t)
}

fn techniques_from_events(events: &[serde_json::Value]) -> impl Iterator<Item = String> + '_ {
    events
        .iter()
        .filter_map(|ev| ev.get("mitre_techniques").and_then(|v| v.as_array()))
        .flatten()
        .filter_map(|v| v.as_str())
        .filter_map(normalize)
}

pub fn red_techniques(red: &SharedRedTeamState) -> BTreeSet<String> {
    red.all_techniques
        .iter()
        .filter_map(|t| normalize(t))
        .chain(techniques_from_events(&red.all_timeline_events))
        .collect()
}

pub fn blue_techniques(blue: &[SharedBlueTeamState]) -> BTreeSet<String> {
    blue.iter()
        .flat_map(|s| {
            s.identified_techniques
                .iter()
                .filter_map(|t| normalize(t))
                .chain(
                    s.evidence
                        .iter()
                        .flat_map(|e| e.mitre_techniques.iter())
                        .filter_map(|t| normalize(t)),
                )
        })
        .collect()
}

impl RedTeamCoverage {
    pub fn compute(red: &SharedRedTeamState, blue: &[SharedBlueTeamState]) -> Self {
        let red_set = red_techniques(red);
        let blue_set = blue_techniques(blue);

        let mut detected = Vec::new();
        let mut missed = Vec::new();
        for r in &red_set {
            let matches: Vec<&String> = blue_set.iter().filter(|b| covers(r, b)).collect();
            if matches.is_empty() {
                missed.push(r.clone());
            } else {
                detected.push(CoverageEntry {
                    id: r.clone(),
                    matched_by: matches
                        .iter()
                        .map(|b| b.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
        }

        let blue_only: Vec<String> = blue_set
            .iter()
            .filter(|b| !red_set.iter().any(|r| covers(r, b)))
            .cloned()
            .collect();

        let red_technique_count = red_set.len();
        let detected_count = detected.len();
        let detection_rate_display = if red_technique_count == 0 {
            "n/a".to_string()
        } else {
            format!(
                "{:.0}% ({}/{})",
                (detected_count as f64 / red_technique_count as f64) * 100.0,
                detected_count,
                red_technique_count
            )
        };

        Self {
            red_technique_count,
            detected_count,
            missed_count: missed.len(),
            detection_rate_display,
            detected,
            missed,
            blue_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red_with(techniques: &[&str]) -> SharedRedTeamState {
        let mut s = SharedRedTeamState::new("op-20260728-000334".to_string());
        s.all_techniques = techniques.iter().map(|t| t.to_string()).collect();
        s
    }

    fn blue_with(techniques: &[&str]) -> Vec<SharedBlueTeamState> {
        let mut s = SharedBlueTeamState::new("inv-20260728-000547".to_string());
        s.identified_techniques = techniques.iter().map(|t| t.to_string()).collect();
        vec![s]
    }

    #[test]
    fn missed_techniques_are_counted_against_coverage() {
        // op-20260728-000334: red ran these, blue's report claimed success.
        let red = red_with(&["T1003.006", "T1078.002", "T1210", "T1558.003"]);
        let blue = blue_with(&["T1003.006", "T1078.002"]);
        let c = RedTeamCoverage::compute(&red, &blue);

        assert_eq!(c.red_technique_count, 4);
        assert_eq!(c.detected_count, 2);
        assert_eq!(c.missed, vec!["T1210", "T1558.003"]);
        assert_eq!(c.detection_rate_display, "50% (2/4)");
    }

    #[test]
    fn sub_technique_detection_covers_the_parent() {
        let red = red_with(&["T1558"]);
        let blue = blue_with(&["T1558.001"]);
        let c = RedTeamCoverage::compute(&red, &blue);

        assert_eq!(c.detected_count, 1);
        assert_eq!(c.detected[0].matched_by, "T1558.001");
        assert!(c.missed.is_empty());
        assert!(c.blue_only.is_empty());
    }

    #[test]
    fn sibling_sub_techniques_are_not_a_detection() {
        // Golden Ticket is not Kerberoasting. Matching on shared parent alone
        // credited blue for T1558.003 on op-20260728-000334 when it had only
        // detected T1558.001.
        let red = red_with(&["T1558.003"]);
        let blue = blue_with(&["T1558.001", "T1558.004"]);
        let c = RedTeamCoverage::compute(&red, &blue);

        assert_eq!(c.detected_count, 0);
        assert_eq!(c.missed, vec!["T1558.003"]);
        assert_eq!(c.detection_rate_display, "0% (0/1)");
    }

    #[test]
    fn parent_technique_detection_covers_the_child() {
        let red = red_with(&["T1003.006"]);
        let c = RedTeamCoverage::compute(&red, &blue_with(&["T1003"]));
        assert_eq!(c.detected_count, 1);
    }

    #[test]
    fn blue_detections_red_never_ran_are_reported_separately() {
        let red = red_with(&["T1003.006"]);
        let blue = blue_with(&["T1003.006", "T1615"]);
        let c = RedTeamCoverage::compute(&red, &blue);

        assert_eq!(c.blue_only, vec!["T1615"]);
        assert_eq!(c.detection_rate_display, "100% (1/1)");
    }

    #[test]
    fn evidence_techniques_count_as_blue_coverage() {
        let red = red_with(&["T1649"]);
        let mut states = blue_with(&[]);
        states[0].evidence.push(crate::models::Evidence {
            id: "e-1".into(),
            evidence_type: "log_entry".into(),
            value: "T1649".into(),
            source: "detection_sweep:detect_certipy_enumeration".into(),
            timestamp: None,
            pyramid_level: 6,
            mitre_techniques: vec!["T1649".into()],
            confidence: 0.6,
            metadata: std::collections::HashMap::new(),
            source_query_id: None,
            validated: true,
        });
        let c = RedTeamCoverage::compute(&red, &states);

        assert_eq!(c.detected_count, 1);
    }

    #[test]
    fn empty_red_ground_truth_does_not_divide_by_zero() {
        let c = RedTeamCoverage::compute(&red_with(&[]), &blue_with(&["T1649"]));
        assert_eq!(c.detection_rate_display, "n/a");
        assert_eq!(c.blue_only, vec!["T1649"]);
    }

    #[test]
    fn whitespace_and_case_do_not_create_phantom_techniques() {
        let red = red_with(&["  t1003.006 ", "", "T1003.006"]);
        let c = RedTeamCoverage::compute(&red, &blue_with(&["T1003.006"]));
        assert_eq!(c.red_technique_count, 1);
        assert_eq!(c.detected_count, 1);
    }
}
