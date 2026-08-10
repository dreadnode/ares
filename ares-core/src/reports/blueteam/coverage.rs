//! Coverage of red team activity, measured against red team ground truth.
//!
//! The headline number is weighted by what red actually did and bounded in
//! time: every red timeline event is one action, and an action counts as
//! detected only when a matching blue detection observed telemetry around the
//! moment it happened.
//!
//! The set join this replaced — distinct red technique IDs blue named anywhere,
//! over distinct red technique IDs — is kept as a secondary line because it is
//! what earlier reports printed, but it cannot be the headline. It scores a set
//! of size ~16 for an operation of ~200 actions, so missing a technique red ran
//! 109 times costs exactly as much as missing one red ran twice, and it ticks a
//! box for all time: an operation where blue went silent 10 minutes before red
//! stopped still reported 88% coverage, with 54% of red's actions landing after
//! blue's last detection.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
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

/// How far outside the telemetry a detection matched a red action may sit and
/// still count as covered by it.
///
/// A detection records the span of log events it matched, not the moment the
/// sweep noticed, so this absorbs ingestion lag and lab clock skew rather than
/// detection latency. It matches the `STRONG` threshold in
/// [`crate::correlation::redblue::CorrelationMatch::match_quality`], so a red
/// action credited here is one that correlator would also call a strong match.
pub const DETECTION_TOLERANCE_SECS: i64 = 300;

/// One red technique, with how often red ran it and how much of that blue saw.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageEntry {
    pub id: String,
    pub matched_by: String,
    /// Red timeline events carrying this technique.
    pub executions: usize,
    /// Those with a matching blue detection observing telemetry around them.
    pub detected_executions: usize,
}

/// One red technique blue never detected while red was running it.
#[derive(Debug, Clone, Serialize)]
pub struct MissedEntry {
    pub id: String,
    pub executions: usize,
    /// Why it scored zero: blue never named the technique at all, or named it
    /// outside every window in which red was executing it.
    pub reason: String,
}

const REASON_UNNAMED: &str = "no matching blue detection";
const REASON_OUT_OF_WINDOW: &str = "blue named it, but not while red was running it";
const REASON_UNTIMED: &str = "blue named it, but recorded nothing timestamped behind it";

#[derive(Debug, Clone, Default, Serialize)]
pub struct RedTeamCoverage {
    /// Red timeline events carrying at least one technique, plus one synthetic
    /// action for each technique red recorded without a timeline event.
    pub action_count: usize,
    pub detected_action_count: usize,
    /// Weighted, time-bounded rate — the headline.
    pub detection_rate_display: String,
    /// Actions red took after blue's last detection stopped observing anything.
    pub actions_after_last_detection: usize,
    /// Actions with no usable timestamp, matched on technique alone.
    pub untimed_action_count: usize,
    /// Timeline events carrying no technique at all. Excluded from both sides
    /// of the rate: an action with no technique cannot be scored either way.
    pub unattributed_action_count: usize,
    pub blue_last_detection_display: String,
    pub red_last_action_display: String,

    pub red_technique_count: usize,
    pub detected_count: usize,
    pub missed_count: usize,
    /// The unweighted, untimed set join, reported for continuity.
    pub technique_rate_display: String,

    pub detected: Vec<CoverageEntry>,
    pub missed: Vec<MissedEntry>,
    pub blue_only: Vec<String>,
    /// Techniques blue named with no timestamped evidence behind them. They
    /// cannot cover a timed red action, so they are listed rather than scored.
    pub untimed_technique_claims: Vec<String>,
}

fn normalize(raw: &str) -> Option<String> {
    let t = raw.trim().to_uppercase();
    (!t.is_empty()).then_some(t)
}

/// Parse a timestamp written by any of the paths that feed these states.
///
/// The sweep writes RFC3339, but timeline events also arrive from the blue
/// agent, which formats them loosely. An unparsed timestamp downgrades an
/// action to technique-only matching, so accepting the common shapes keeps the
/// time bound from quietly falling off.
fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
        return Some(t.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f UTC",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
    ] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(t.and_utc());
        }
    }
    None
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

/// One thing red did, at the time it did it.
struct RedAction {
    at: Option<DateTime<Utc>>,
    techniques: Vec<String>,
}

/// One blue detection, over the span of telemetry it matched.
///
/// `from`/`to` are log event times, not the moment the sweep ran: every hit in
/// one sweep shares a recording time, so recording time cannot establish that a
/// detection observed the activity it describes. A detection that recorded no
/// span collapses to a point at its single timestamp.
struct BlueDetection {
    technique: String,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}

impl BlueDetection {
    fn observed(&self, at: DateTime<Utc>) -> bool {
        let tolerance = Duration::seconds(DETECTION_TOLERANCE_SECS);
        at >= self.from - tolerance && at <= self.to + tolerance
    }
}

fn event_techniques(ev: &serde_json::Value) -> Vec<String> {
    let mut techniques: Vec<String> = ev
        .get("mitre_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(normalize)
                .collect()
        })
        .unwrap_or_default();
    techniques.sort();
    techniques.dedup();
    techniques
}

fn red_actions(red: &SharedRedTeamState) -> (Vec<RedAction>, usize) {
    let mut actions = Vec::new();
    let mut unattributed = 0;
    let mut on_timeline: BTreeSet<String> = BTreeSet::new();

    for ev in &red.all_timeline_events {
        let techniques = event_techniques(ev);
        if techniques.is_empty() {
            unattributed += 1;
            continue;
        }
        on_timeline.extend(techniques.iter().cloned());
        actions.push(RedAction {
            at: ev
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(parse_time),
            techniques,
        });
    }

    let recorded: BTreeSet<String> = red
        .all_techniques
        .iter()
        .filter_map(|t| normalize(t))
        .collect();
    for technique in recorded {
        if !on_timeline.contains(&technique) {
            actions.push(RedAction {
                at: None,
                techniques: vec![technique],
            });
        }
    }

    (actions, unattributed)
}

/// The span of matched log events a sweep recorded alongside a detection.
fn observed_span(extra_data_json: Option<&String>) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let parsed: serde_json::Value = serde_json::from_str(extra_data_json?).ok()?;
    let first = parsed
        .get("first_event_at")
        .and_then(|v| v.as_str())
        .and_then(parse_time)?;
    let last = parsed
        .get("last_event_at")
        .and_then(|v| v.as_str())
        .and_then(parse_time)
        .unwrap_or(first);
    Some((first, last.max(first)))
}

fn blue_detections(blue: &[SharedBlueTeamState]) -> (Vec<BlueDetection>, BTreeSet<String>) {
    let mut timed: Vec<BlueDetection> = Vec::new();
    let mut untimed: BTreeSet<String> = BTreeSet::new();

    for state in blue {
        for ev in &state.evidence {
            let at = ev.timestamp.as_deref().and_then(parse_time);
            for technique in ev.mitre_techniques.iter().filter_map(|t| normalize(t)) {
                match at {
                    Some(at) => timed.push(BlueDetection {
                        technique,
                        from: at,
                        to: at,
                    }),
                    None => {
                        untimed.insert(technique);
                    }
                }
            }
        }

        for entry in &state.timeline {
            let span = observed_span(entry.extra_data_json.as_ref())
                .or_else(|| parse_time(&entry.timestamp).map(|at| (at, at)));
            for technique in entry.mitre_techniques.iter().filter_map(|t| normalize(t)) {
                match span {
                    Some((from, to)) => timed.push(BlueDetection {
                        technique,
                        from,
                        to,
                    }),
                    None => {
                        untimed.insert(technique);
                    }
                }
            }
        }

        untimed.extend(
            state
                .identified_techniques
                .iter()
                .filter_map(|t| normalize(t)),
        );
    }

    let with_times: BTreeSet<&str> = timed.iter().map(|d| d.technique.as_str()).collect();
    untimed.retain(|t| !with_times.contains(t.as_str()));

    (timed, untimed)
}

fn rate_display(hit: usize, total: usize) -> String {
    if total == 0 {
        return "n/a".to_string();
    }
    format!(
        "{:.0}% ({hit}/{total})",
        (hit as f64 / total as f64) * 100.0
    )
}

fn time_display(at: Option<DateTime<Utc>>) -> String {
    at.map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".to_string())
}

impl RedTeamCoverage {
    pub fn compute(red: &SharedRedTeamState, blue: &[SharedBlueTeamState]) -> Self {
        let red_set = red_techniques(red);
        let blue_set = blue_techniques(blue);
        let (actions, unattributed_action_count) = red_actions(red);
        let (detections, untimed_claims) = blue_detections(blue);

        let mut executions: BTreeMap<String, usize> = BTreeMap::new();
        let mut detected_executions: BTreeMap<String, usize> = BTreeMap::new();
        let mut matched_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut detected_action_count = 0;
        let mut untimed_action_count = 0;

        for action in &actions {
            if action.at.is_none() {
                untimed_action_count += 1;
            }
            let mut action_detected = false;

            for technique in &action.techniques {
                *executions.entry(technique.clone()).or_default() += 1;

                let hits: BTreeSet<String> = match action.at {
                    Some(at) => detections
                        .iter()
                        .filter(|d| covers(technique, &d.technique) && d.observed(at))
                        .map(|d| d.technique.clone())
                        .collect(),
                    None => detections
                        .iter()
                        .map(|d| &d.technique)
                        .chain(untimed_claims.iter())
                        .filter(|b| covers(technique, b))
                        .cloned()
                        .collect(),
                };

                if !hits.is_empty() {
                    *detected_executions.entry(technique.clone()).or_default() += 1;
                    matched_by
                        .entry(technique.clone())
                        .or_default()
                        .extend(hits);
                    action_detected = true;
                }
            }

            if action_detected {
                detected_action_count += 1;
            }
        }

        let mut detected = Vec::new();
        let mut missed = Vec::new();
        for (id, count) in &executions {
            let hit = detected_executions.get(id).copied().unwrap_or(0);
            if hit > 0 {
                detected.push(CoverageEntry {
                    id: id.clone(),
                    matched_by: matched_by
                        .get(id)
                        .map(|b| b.iter().cloned().collect::<Vec<_>>().join(", "))
                        .unwrap_or_default(),
                    executions: *count,
                    detected_executions: hit,
                });
            } else {
                let reason = if detections.iter().any(|d| covers(id, &d.technique)) {
                    REASON_OUT_OF_WINDOW
                } else if untimed_claims.iter().any(|b| covers(id, b)) {
                    REASON_UNTIMED
                } else {
                    REASON_UNNAMED
                };
                missed.push(MissedEntry {
                    id: id.clone(),
                    executions: *count,
                    reason: reason.to_string(),
                });
            }
        }
        detected.sort_by(|a, b| b.executions.cmp(&a.executions).then(a.id.cmp(&b.id)));
        missed.sort_by(|a, b| b.executions.cmp(&a.executions).then(a.id.cmp(&b.id)));

        let blue_only: Vec<String> = blue_set
            .iter()
            .filter(|b| !red_set.iter().any(|r| covers(r, b)))
            .cloned()
            .collect();

        let last_detection = detections.iter().map(|d| d.to).max();
        let last_action = actions.iter().filter_map(|a| a.at).max();
        let tolerance = Duration::seconds(DETECTION_TOLERANCE_SECS);
        let actions_after_last_detection = actions
            .iter()
            .filter_map(|a| a.at)
            .filter(|at| match last_detection {
                Some(end) => *at > end + tolerance,
                None => true,
            })
            .count();

        let set_join_detected = red_set
            .iter()
            .filter(|r| blue_set.iter().any(|b| covers(r, b)))
            .count();

        Self {
            action_count: actions.len(),
            detected_action_count,
            detection_rate_display: rate_display(detected_action_count, actions.len()),
            actions_after_last_detection,
            untimed_action_count,
            unattributed_action_count,
            blue_last_detection_display: time_display(last_detection),
            red_last_action_display: time_display(last_action),
            red_technique_count: red_set.len(),
            detected_count: detected.len(),
            missed_count: missed.len(),
            technique_rate_display: rate_display(set_join_detected, red_set.len()),
            detected,
            missed,
            blue_only,
            untimed_technique_claims: untimed_claims.into_iter().collect(),
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

    fn at(offset_secs: i64) -> String {
        (DateTime::parse_from_rfc3339("2026-07-28T21:28:00Z")
            .unwrap()
            .with_timezone(&Utc)
            + Duration::seconds(offset_secs))
        .to_rfc3339()
    }

    fn red_event(technique: &str, offset_secs: i64) -> serde_json::Value {
        serde_json::json!({
            "id": format!("evt-{technique}-{offset_secs}"),
            "timestamp": at(offset_secs),
            "source": "test",
            "description": format!("red ran {technique}"),
            "mitre_techniques": [technique],
        })
    }

    fn red_timeline(events: Vec<serde_json::Value>) -> SharedRedTeamState {
        let mut s = SharedRedTeamState::new("op-20260728-000334".to_string());
        s.all_timeline_events = events;
        s
    }

    fn evidence(technique: &str, timestamp: Option<String>) -> crate::models::Evidence {
        crate::models::Evidence {
            id: format!("e-{technique}-{}", timestamp.as_deref().unwrap_or("none")),
            evidence_type: "log_entry".into(),
            value: technique.into(),
            source: "detection_sweep:test".into(),
            timestamp,
            pyramid_level: 6,
            mitre_techniques: vec![technique.into()],
            confidence: 0.8,
            metadata: std::collections::HashMap::new(),
            source_query_id: None,
            validated: true,
        }
    }

    fn blue_detecting(items: Vec<crate::models::Evidence>) -> Vec<SharedBlueTeamState> {
        let mut s = SharedBlueTeamState::new("inv-20260728-000547".to_string());
        s.evidence = items;
        vec![s]
    }

    #[test]
    fn missed_techniques_are_counted_against_coverage() {
        let red = red_with(&["T1003.006", "T1078.002", "T1210", "T1558.003"]);
        let blue = blue_with(&["T1003.006", "T1078.002"]);
        let c = RedTeamCoverage::compute(&red, &blue);

        assert_eq!(c.red_technique_count, 4);
        assert_eq!(c.detected_count, 2);
        assert_eq!(
            c.missed.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["T1210", "T1558.003"]
        );
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
        let red = red_with(&["T1558.003"]);
        let blue = blue_with(&["T1558.001", "T1558.004"]);
        let c = RedTeamCoverage::compute(&red, &blue);

        assert_eq!(c.detected_count, 0);
        assert_eq!(c.missed[0].id, "T1558.003");
        assert_eq!(c.missed[0].reason, REASON_UNNAMED);
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
        let c = RedTeamCoverage::compute(&red, &blue_detecting(vec![evidence("T1649", None)]));

        assert_eq!(c.detected_count, 1);
    }

    #[test]
    fn empty_red_ground_truth_does_not_divide_by_zero() {
        let c = RedTeamCoverage::compute(&red_with(&[]), &blue_with(&["T1649"]));
        assert_eq!(c.detection_rate_display, "n/a");
        assert_eq!(c.technique_rate_display, "n/a");
        assert_eq!(c.blue_only, vec!["T1649"]);
    }

    #[test]
    fn whitespace_and_case_do_not_create_phantom_techniques() {
        let red = red_with(&["  t1003.006 ", "", "T1003.006"]);
        let c = RedTeamCoverage::compute(&red, &blue_with(&["T1003.006"]));
        assert_eq!(c.red_technique_count, 1);
        assert_eq!(c.detected_count, 1);
    }

    #[test]
    fn the_rate_is_weighted_by_how_often_red_ran_each_technique() {
        let red = red_timeline(vec![
            red_event("T1046", 0),
            red_event("T1046", 30),
            red_event("T1046", 60),
            red_event("T1003.006", 90),
        ]);
        let c = RedTeamCoverage::compute(
            &red,
            &blue_detecting(vec![evidence("T1003.006", Some(at(90)))]),
        );

        assert_eq!(c.action_count, 4);
        assert_eq!(c.detected_action_count, 1);
        assert_eq!(c.detection_rate_display, "25% (1/4)");
        assert_eq!(c.technique_rate_display, "50% (1/2)");
        assert_eq!(c.missed[0].id, "T1046");
        assert_eq!(c.missed[0].executions, 3);
    }

    #[test]
    fn actions_after_blue_goes_silent_are_not_covered() {
        let red = red_timeline(vec![
            red_event("T1003.006", 0),
            red_event("T1003.006", 909),
            red_event("T1003.006", 1514),
        ]);
        let c = RedTeamCoverage::compute(
            &red,
            &blue_detecting(vec![
                evidence("T1003.006", Some(at(0))),
                evidence("T1003.006", Some(at(909))),
            ]),
        );

        assert_eq!(c.detected_action_count, 2);
        assert_eq!(c.detection_rate_display, "67% (2/3)");
        assert_eq!(c.actions_after_last_detection, 1);
        assert_eq!(c.technique_rate_display, "100% (1/1)");
    }

    #[test]
    fn a_detection_that_precedes_red_does_not_detect_it() {
        let red = red_timeline(vec![red_event("T1558.001", 3600)]);
        let c = RedTeamCoverage::compute(
            &red,
            &blue_detecting(vec![evidence("T1558.001", Some(at(20)))]),
        );

        assert_eq!(c.detected_action_count, 0);
        assert_eq!(c.detection_rate_display, "0% (0/1)");
        assert_eq!(c.missed[0].reason, REASON_OUT_OF_WINDOW);
        assert_eq!(c.technique_rate_display, "100% (1/1)");
    }

    #[test]
    fn a_detection_covers_every_action_inside_the_telemetry_it_matched() {
        let red = red_timeline(vec![
            red_event("T1046", 0),
            red_event("T1046", 1200),
            red_event("T1046", 2400),
        ]);
        let mut state = SharedBlueTeamState::new("inv-20260728-000547".to_string());
        state.timeline.push(crate::models::TimelineEvent {
            id: "t-1".into(),
            timestamp: at(0),
            description: "Baseline detection fired".into(),
            evidence_ids: Vec::new(),
            mitre_techniques: vec!["T1046".into()],
            confidence: 0.8,
            source: "detection_sweep".into(),
            extra_data_json: Some(
                serde_json::json!({
                    "first_event_at": at(0),
                    "last_event_at": at(1200),
                    "event_count": 44,
                })
                .to_string(),
            ),
        });

        let c = RedTeamCoverage::compute(&red, &[state]);

        assert_eq!(c.detected_action_count, 2);
        assert_eq!(c.detection_rate_display, "67% (2/3)");
        assert_eq!(c.actions_after_last_detection, 1);
    }

    #[test]
    fn the_span_survives_the_shape_the_sweep_persists() {
        // Exactly what record_timeline_event stores in Redis. The span is only
        // worth writing if it deserializes back into the state the report reads.
        let stored = serde_json::json!({
            "id": "3f1c",
            "timestamp": at(0),
            "description": "Baseline detection detect_port_scan fired: Port Scan (44 event(s))",
            "evidence_ids": [],
            "mitre_techniques": ["T1046"],
            "confidence": 0.8,
            "source": "detection_sweep",
            "extra_data_json": serde_json::json!({
                "first_event_at": at(0),
                "last_event_at": at(1200),
                "event_count": 44,
            }).to_string(),
        });
        let entry: crate::models::TimelineEvent =
            serde_json::from_value(stored).expect("timeline event round-trips");

        let mut state = SharedBlueTeamState::new("inv-20260728-000547".to_string());
        state.timeline.push(entry);
        let red = red_timeline(vec![red_event("T1046", 1200)]);

        assert_eq!(
            RedTeamCoverage::compute(&red, &[state]).detection_rate_display,
            "100% (1/1)"
        );
    }

    #[test]
    fn an_untimed_claim_cannot_cover_a_timed_action() {
        let red = red_timeline(vec![red_event("T1558.003", 0)]);
        let c = RedTeamCoverage::compute(&red, &blue_with(&["T1558.003"]));

        assert_eq!(c.detection_rate_display, "0% (0/1)");
        assert_eq!(c.untimed_technique_claims, vec!["T1558.003"]);
        assert_eq!(c.missed[0].reason, REASON_UNTIMED);
    }

    #[test]
    fn timeline_events_without_a_technique_are_scored_on_neither_side() {
        let mut red = red_timeline(vec![red_event("T1046", 0)]);
        red.all_timeline_events.push(serde_json::json!({
            "id": "evt-untagged",
            "timestamp": at(30),
            "description": "host discovered",
        }));
        let c =
            RedTeamCoverage::compute(&red, &blue_detecting(vec![evidence("T1046", Some(at(0)))]));

        assert_eq!(c.action_count, 1);
        assert_eq!(c.unattributed_action_count, 1);
        assert_eq!(c.detection_rate_display, "100% (1/1)");
    }

    #[test]
    fn the_timing_summary_names_both_ends_of_the_gap() {
        let red = red_timeline(vec![red_event("T1046", 0), red_event("T1046", 1514)]);
        let c =
            RedTeamCoverage::compute(&red, &blue_detecting(vec![evidence("T1046", Some(at(0)))]));

        assert_eq!(c.blue_last_detection_display, "2026-07-28 21:28:00 UTC");
        assert_eq!(c.red_last_action_display, "2026-07-28 21:53:14 UTC");
    }
}
