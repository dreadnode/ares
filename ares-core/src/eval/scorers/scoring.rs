//! Scoring functions for investigation quality metrics.

use std::collections::HashSet;

use regex::Regex;

use crate::eval::ground_truth::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};

use super::types::{EvidenceItem, InvestigationSnapshot, TimelineEvent};

/// Kill-chain phases of an Active Directory attack, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillChainPhase {
    /// Enumerating the domain: hosts, users, groups, shares, and trusts.
    Discovery,
    /// Obtaining credentials, e.g. dumping, kerberoasting, or brute force.
    CredentialAccess,
    /// Moving between hosts using stolen credentials or tickets.
    LateralMovement,
    /// Gaining higher privileges on a host or within the domain.
    PrivilegeEscalation,
    /// Full domain control, e.g. DCSync or golden-ticket forgery.
    DomainDominance,
}

/// Best-effort map from a MITRE technique id to its kill-chain phase.
///
/// Matches by base id, so a sub-technique resolves like its parent, except
/// select domain-dominance sub-techniques (DCSync, Golden Ticket) that
/// outrank their base tactic. Returns [`None`] for an unrecognized id.
pub(crate) fn technique_phase(technique_id: &str) -> Option<KillChainPhase> {
    use KillChainPhase::*;
    if technique_id.starts_with("T1003.006") // DCSync
        || technique_id.starts_with("T1558.001") // Golden Ticket
        || technique_id.starts_with("T1078.002")
    // Domain Accounts
    {
        return Some(DomainDominance);
    }
    let base = technique_id.split('.').next().unwrap_or(technique_id);
    Some(match base {
        "T1046" | "T1018" | "T1087" | "T1069" | "T1482" | "T1016" | "T1135" | "T1201" => Discovery,
        "T1003" | "T1558" | "T1552" | "T1110" | "T1555" | "T1212" | "T1649" | "T1187" => {
            CredentialAccess
        }
        "T1021" | "T1210" | "T1550" | "T1570" | "T1534" => LateralMovement,
        "T1484" | "T1222" | "T1098" | "T1068" | "T1548" | "T1134" => PrivilegeEscalation,
        "T1078" => DomainDominance,
        _ => return None,
    })
}

/// Base MITRE id without the sub-technique suffix (`T1003.006` -> `T1003`).
fn technique_base(id: &str) -> &str {
    id.split('.').next().unwrap_or(id)
}

/// Score kill-chain phase coverage: of the attack phases present in the ground
/// truth, how many the agent reached via CORRECTLY-identified techniques.
///
/// Replaces the old self-reported stage lookup — it can't be advanced by
/// marching the workflow to "synthesis"; you have to actually identify the
/// techniques that define each phase.
pub fn score_phase_coverage(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    // Ground-truth techniques come from two independent sources: the explicit
    // `expected_techniques` list and the per-event MITRE tags on the expected
    // timeline (populated by the benchmark capture). BOTH the expected
    // (denominator) and the covered (numerator) sets must draw on both — if the
    // numerator only credits `expected_techniques`, a phase contributed solely
    // by a timeline technique inflates the denominator but can never be covered,
    // so a perfect investigation caps below 1.0.
    let expected: HashSet<KillChainPhase> = gt
        .expected_techniques
        .iter()
        .map(|t| t.technique_id.as_str())
        .chain(
            gt.expected_timeline
                .iter()
                .flat_map(|e| e.mitre_techniques.iter().map(String::as_str)),
        )
        .filter_map(technique_phase)
        .collect();
    if expected.is_empty() {
        return 0.0;
    }

    // A phase is credited only for an identified technique that is actually part
    // of the ground truth — matched by base id so a sub-technique (T1003.006)
    // and its parent (T1003) are interchangeable — from either GT source. An
    // agent can't reach a phase by naming a technique the attack never used.
    let gt_technique_bases: HashSet<&str> = gt
        .expected_techniques
        .iter()
        .map(|t| technique_base(&t.technique_id))
        .chain(
            gt.expected_timeline
                .iter()
                .flat_map(|e| e.mitre_techniques.iter().map(|t| technique_base(t))),
        )
        .collect();

    let covered: HashSet<KillChainPhase> = snap
        .identified_techniques
        .iter()
        .filter(|t| gt_technique_bases.contains(technique_base(t.as_str())))
        .filter_map(|t| technique_phase(t))
        // Only credit phases that are actually in the ground truth. Base-id
        // grounding lets an agent technique (e.g. base T1003 -> CredentialAccess)
        // pass the filter against a GT sub-technique (T1003.006 -> DomainDominance)
        // whose phase differs; without this bound `covered` can include phases
        // outside `expected`, pushing the ratio above 1.0.
        .filter(|phase| expected.contains(phase))
        .collect();
    covered.len() as f64 / expected.len() as f64
}

/// Score IOC detection rate.
///
/// Compares evidence found against expected IOCs with fuzzy matching.
/// Weighting: 60% required IOCs, 40% optional IOCs.
pub fn score_ioc_detection(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    if gt.expected_iocs.is_empty() {
        return 1.0;
    }

    let mut found_values = build_found_values(snap);
    expand_aliases(&mut found_values, gt);

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

/// Build the set of lowercase values grounded in actual evidence, excluding
/// merely-queried hosts/users. Metrics that must reward *substantiated*
/// findings — the pyramid tier — use this so an agent can't climb the pyramid
/// by enumerating hosts it never concluded anything about.
pub(crate) fn build_evidence_values(snap: &InvestigationSnapshot) -> HashSet<String> {
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
    found
}

/// Build set of lowercase found values from evidence and queries. Used by IOC
/// detection, where surfacing an IOC in an observed query counts as detecting
/// it (unlike the pyramid, which requires substantiated evidence).
pub(crate) fn build_found_values(snap: &InvestigationSnapshot) -> HashSet<String> {
    let mut found = build_evidence_values(snap);
    for host in &snap.queried_hosts {
        found.insert(host.to_lowercase());
    }
    for user in &snap.queried_users {
        found.insert(user.to_lowercase());
    }
    found
}

/// Expand a found-value set with host aliases: if the agent found any member
/// of an alias group (e.g. a hostname), add the whole group so an IP-typed IOC
/// also matches a hostname finding (and vice versa).
fn expand_aliases(found: &mut HashSet<String>, gt: &EvaluationGroundTruth) {
    let base: Vec<String> = found.iter().cloned().collect();
    for group in &gt.host_aliases {
        if group.iter().any(|a| base.contains(&a.to_lowercase())) {
            for a in group {
                found.insert(a.to_lowercase());
            }
        }
    }
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

/// Score Pyramid of Pain elevation — grounded against the ground truth.
///
/// The tier is taken from the ground-truth entity each correctly-identified
/// finding maps to (an IOC's tier, or 6 for a correctly-identified technique),
/// NOT the agent's self-assigned pyramid label. Rewards climbing to TTPs.
pub fn score_pyramid_elevation(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    grounded_pyramid_tier(snap, gt) as f64 / 6.0
}

/// Highest pyramid tier (1-6) among the ground-truth entities the agent
/// correctly identified.
fn grounded_pyramid_tier(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> u32 {
    // Evidence only — a merely-queried host must not elevate the pyramid.
    let mut found = build_evidence_values(snap);
    expand_aliases(&mut found, gt);
    let mut best = 0u32;
    for ioc in &gt.expected_iocs {
        if ioc_matches(ioc, &found) {
            best = best.max(ioc.pyramid_level as u32);
        }
    }
    // A correctly-identified expected technique is a TTP (tier 6).
    if gt
        .expected_techniques
        .iter()
        .any(|t| technique_matches(t, &snap.identified_techniques))
    {
        best = best.max(6);
    }
    best
}

/// Whether an evidence item corresponds to a real ground-truth entity
/// (a known IOC value or technique) — the basis for precision.
fn evidence_is_grounded(ev: &EvidenceItem, gt: &EvaluationGroundTruth) -> bool {
    let mut single = HashSet::new();
    single.insert(ev.value.to_lowercase());
    expand_aliases(&mut single, gt);
    if gt.expected_iocs.iter().any(|ioc| ioc_matches(ioc, &single)) {
        return true;
    }
    // Behavioral evidence: credit when the evidence's value OR its MITRE
    // technique tag matches an expected technique (e.g. a "4769 RC4 tickets"
    // observation tagged T1558.003 with no discrete IOC value).
    gt.expected_techniques
        .iter()
        .any(|t| t.matches(&ev.value) || ev.mitre_techniques.iter().any(|m| t.matches(m)))
}

/// Whether a timeline event is corroborated by something the investigation
/// actually observed — the timeline analogue of [`evidence_is_grounded`].
///
/// Timeline descriptions are agent-authored prose, and event matching is a
/// fuzzy word-overlap against the expected pattern. Ungated, that pays a
/// verbose model for writing more words: describe every phase in enough detail
/// and the overlap threshold is met with no additional grounding, while
/// `score_evidence_quality` — the same scorer's other half — filters through
/// `evidence_is_grounded`. This closes that asymmetry on the scoring side
/// rather than on the write path, because the timeline is the deliberate
/// channel for *derived* identities that appear verbatim in no log line.
///
/// An event counts when it is machine-produced, when it carries a MITRE tag
/// that grounded evidence also carries, or when its prose names a value from
/// grounded evidence.
fn timeline_event_is_grounded(
    ev: &TimelineEvent,
    grounded_values: &HashSet<String>,
    grounded_techniques: &HashSet<String>,
) -> bool {
    if ev.machine_generated {
        return true;
    }
    if ev
        .mitre_techniques
        .iter()
        .any(|t| grounded_techniques.contains(&t.to_uppercase()))
    {
        return true;
    }
    let description = ev.description.to_lowercase();
    grounded_values
        .iter()
        .any(|v| !v.is_empty() && description.contains(v.as_str()))
}

/// Score timeline accuracy.
///
/// 60% event matching, 40% technique association in timeline. Only grounded
/// events are scored — see [`timeline_event_is_grounded`].
pub fn score_timeline_accuracy(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    if gt.expected_timeline.is_empty() {
        return 1.0;
    }
    if snap.timeline.is_empty() {
        return 0.0;
    }

    let mut grounded_values: HashSet<String> = HashSet::new();
    let mut grounded_techniques: HashSet<String> = HashSet::new();
    for ev in snap
        .evidence_values
        .iter()
        .filter(|ev| evidence_is_grounded(ev, gt))
    {
        grounded_values.insert(ev.value.to_lowercase());
        grounded_techniques.extend(ev.mitre_techniques.iter().map(|t| t.to_uppercase()));
    }
    expand_aliases(&mut grounded_values, gt);

    let grounded: Vec<&TimelineEvent> = snap
        .timeline
        .iter()
        .filter(|e| timeline_event_is_grounded(e, &grounded_values, &grounded_techniques))
        .collect();
    if grounded.is_empty() {
        return 0.0;
    }

    let descriptions: Vec<String> = grounded
        .iter()
        .map(|e| e.description.to_lowercase())
        .collect();

    let mut found_techniques: HashSet<String> = HashSet::new();
    for event in &grounded {
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

    let pattern_lower = pattern.trim().to_lowercase();
    // An empty pattern must not match everything: `"".contains(x)` and
    // `x.contains("")` are vacuously true, so a blank expected description
    // (possible now that patterns come from captured red-event text) would
    // otherwise score every event as matched.
    if pattern_lower.is_empty() {
        return false;
    }

    // Compile the pattern regex once, not once per description. Only patterns
    // that look like a deliberate regex are compiled; untrusted red-event text
    // that fails to compile falls through to the substring/keyword strategies.
    let pattern_re = if pattern.contains(|c: char| ".*+?[](){}^$|\\".contains(c)) {
        Regex::new(&pattern_lower).ok()
    } else {
        None
    };

    for desc in descriptions {
        // Skip empty descriptions for the same vacuous-substring-match reason.
        if desc.is_empty() {
            continue;
        }

        // Strategy 1: regex match when the pattern is a deliberate regex.
        if let Some(re) = &pattern_re {
            if re.is_match(desc) {
                return true;
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

/// Score evidence quality as PRECISION against ground truth: the fraction of
/// the agent's evidence that corresponds to a real (observable) attack
/// indicator. Penalizes fabricated or irrelevant evidence — the key
/// anti-gaming property. Self-assigned confidence no longer certifies truth.
pub fn score_evidence_quality(snap: &InvestigationSnapshot, gt: &EvaluationGroundTruth) -> f64 {
    if snap.evidence_values.is_empty() {
        return 0.0;
    }
    let correct = snap
        .evidence_values
        .iter()
        .filter(|ev| evidence_is_grounded(ev, gt))
        .count();
    correct as f64 / snap.evidence_values.len() as f64
}

/// Compute the overall investigation quality score.
///
/// Weights: IOC 17.5%, Technique 17.5%, Pyramid 15%, Evidence 15%, Phase 17.5%,
/// Timeline 17.5%. Timeline is dropped (and the remaining weights renormalize)
/// when there is no `expected_timeline`, so it never scores a vacuous 1.0.
pub fn score_investigation_overall(
    snap: &InvestigationSnapshot,
    gt: &EvaluationGroundTruth,
) -> f64 {
    let mut scores = vec![
        (score_ioc_detection(snap, gt), 3.5),
        (score_technique_coverage(snap, gt), 3.5),
        (score_pyramid_elevation(snap, gt), 3.0),
        (score_evidence_quality(snap, gt), 3.0),
        (score_phase_coverage(snap, gt), 3.5),
    ];
    // Only score the timeline when there's a timeline to score against. With no
    // expected_timeline, score_timeline_accuracy returns a vacuous 1.0 that
    // would otherwise inflate the overall by its full 17.5% weight.
    if !gt.expected_timeline.is_empty() {
        scores.push((score_timeline_accuracy(snap, gt), 3.5));
    }

    let total_weight: f64 = scores.iter().map(|(_, w)| w).sum();
    let weighted_sum: f64 = scores.iter().map(|(s, w)| s * w).sum();

    weighted_sum / total_weight
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_abs_diff_eq;
    use std::collections::HashSet;

    use crate::eval::ground_truth::{
        EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique, ExpectedTimelineEvent,
    };
    use crate::eval::scorers::types::{EvidenceItem, InvestigationSnapshot, TimelineEvent};
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

    fn make_evidence(
        etype: &str,
        value: &str,
        pyramid: u32,
        confidence: f64,
        validated: bool,
    ) -> EvidenceItem {
        EvidenceItem {
            evidence_type: etype.into(),
            value: value.into(),
            pyramid_level: pyramid,
            confidence,
            validated,
            mitre_techniques: Vec::new(),
        }
    }

    #[test]
    fn phase_coverage_empty_gt() {
        assert_abs_diff_eq!(
            score_phase_coverage(&empty_snap(), &empty_gt()),
            0.0,
            epsilon = 0.001
        );
    }

    #[test]
    fn phase_coverage_partial() {
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1558".into()); // credential access
        let mut gt = empty_gt();
        gt.expected_techniques = vec![
            make_technique("T1558", true), // credential access
            make_technique("T1021", true), // lateral movement
        ];
        // 1 of 2 attack phases covered.
        assert_abs_diff_eq!(score_phase_coverage(&snap, &gt), 0.5, epsilon = 0.001);
    }

    #[test]
    fn ioc_detection_empty_gt_returns_one() {
        let snap = empty_snap();
        let gt = empty_gt();
        assert_abs_diff_eq!(score_ioc_detection(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn ioc_detection_all_found() {
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 1, 0.9, true));
        snap.evidence_values
            .push(make_evidence("user", "admin", 2, 0.8, true));

        let mut gt = empty_gt();
        gt.expected_iocs = vec![
            make_ioc("ip", "192.168.58.1", true),
            make_ioc("user", "admin", false),
        ];

        assert_abs_diff_eq!(score_ioc_detection(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn ioc_detection_none_found() {
        let snap = empty_snap();
        let mut gt = empty_gt();
        gt.expected_iocs = vec![
            make_ioc("ip", "192.168.58.1", true),
            make_ioc("user", "admin", false),
        ];

        assert_abs_diff_eq!(score_ioc_detection(&snap, &gt), 0.0, epsilon = 0.001);
    }

    #[test]
    fn ioc_detection_partial_required_only() {
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 1, 0.9, true));

        let mut gt = empty_gt();
        gt.expected_iocs = vec![
            make_ioc("ip", "192.168.58.1", true),
            make_ioc("ip", "192.168.58.2", true),
        ];

        // 1/2 required = 0.5, no optional => 1.0
        // 0.5*0.6 + 1.0*0.4 = 0.7
        assert_abs_diff_eq!(score_ioc_detection(&snap, &gt), 0.7, epsilon = 0.001);
    }

    #[test]
    fn ioc_matches_exact() {
        let ioc = make_ioc("ip", "192.168.58.1", true);
        let found: HashSet<String> = ["192.168.58.1".into()].into_iter().collect();
        assert!(ioc_matches(&ioc, &found));
    }

    #[test]
    fn ioc_matches_case_insensitive() {
        let ioc = make_ioc("ip", "DC01.CONTOSO.LOCAL", true);
        let found: HashSet<String> = ["dc01.contoso.local".into()].into_iter().collect();
        assert!(ioc_matches(&ioc, &found));
    }

    #[test]
    fn ioc_matches_hostname_partial() {
        let ioc = make_ioc("hostname", "dc01.contoso.local", true);
        let found: HashSet<String> = ["dc01".into()].into_iter().collect();
        assert!(ioc_matches(&ioc, &found));
    }

    #[test]
    fn ioc_matches_user_backslash() {
        let ioc = make_ioc("user", "CONTOSO\\admin", true);
        let found: HashSet<String> = ["admin".into()].into_iter().collect();
        assert!(ioc_matches(&ioc, &found));
    }

    #[test]
    fn ioc_matches_user_at_sign() {
        let ioc = make_ioc("user", "admin@contoso.local", true);
        let found: HashSet<String> = ["admin".into()].into_iter().collect();
        assert!(ioc_matches(&ioc, &found));
    }

    #[test]
    fn ioc_no_match_unrelated() {
        let ioc = make_ioc("ip", "192.168.58.1", true);
        let found: HashSet<String> = ["192.168.58.99".into()].into_iter().collect();
        assert!(!ioc_matches(&ioc, &found));
    }

    #[test]
    fn build_found_values_includes_evidence_and_queries() {
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 1, 0.9, true));
        snap.queried_hosts.insert("DC01".into());
        snap.queried_users.insert("Admin".into());

        let found = build_found_values(&snap);
        assert!(found.contains("192.168.58.1"));
        assert!(found.contains("dc01"));
        assert!(found.contains("admin"));
    }

    #[test]
    fn build_found_values_hostname_splits() {
        let mut snap = empty_snap();
        snap.evidence_values.push(make_evidence(
            "hostname",
            "dc01.contoso.local",
            2,
            0.8,
            true,
        ));
        let found = build_found_values(&snap);
        assert!(found.contains("dc01.contoso.local"));
        assert!(found.contains("dc01"));
    }

    #[test]
    fn technique_coverage_empty_gt_returns_one() {
        let snap = empty_snap();
        let gt = empty_gt();
        assert_abs_diff_eq!(score_technique_coverage(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn technique_coverage_all_found() {
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1003".into());
        snap.identified_techniques.insert("T1046".into());

        let mut gt = empty_gt();
        gt.expected_techniques = vec![
            make_technique("T1003", true),
            make_technique("T1046", false),
        ];

        assert_abs_diff_eq!(score_technique_coverage(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn technique_coverage_none_found() {
        let snap = empty_snap();
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        // 0 required found => required_rate=0, no optional => 1.0
        // 0.0*0.6 + 1.0*0.4 = 0.4
        assert_abs_diff_eq!(score_technique_coverage(&snap, &gt), 0.4, epsilon = 0.01);
    }

    #[test]
    fn pyramid_elevation_empty() {
        assert_abs_diff_eq!(
            score_pyramid_elevation(&empty_snap(), &empty_gt()),
            0.0,
            epsilon = 0.001
        );
    }

    #[test]
    fn pyramid_elevation_grounded_ttp() {
        // Correctly identifying an expected technique is a TTP => tier 6 => 1.0.
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1003".into());
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        assert_abs_diff_eq!(score_pyramid_elevation(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn pyramid_elevation_ignores_self_labels() {
        // Agent self-labels an IP as tier 6, but the grounded tier is the
        // matched IOC's (IpAddresses = 2) => 2/6, NOT 1.0. Anti-gaming.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 6, 1.0, true));
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        assert_abs_diff_eq!(
            score_pyramid_elevation(&snap, &gt),
            2.0 / 6.0,
            epsilon = 0.001
        );
    }

    #[test]
    fn evidence_quality_empty() {
        assert_abs_diff_eq!(
            score_evidence_quality(&empty_snap(), &empty_gt()),
            0.0,
            epsilon = 0.001
        );
    }

    #[test]
    fn evidence_precision_penalizes_fabrication() {
        // One evidence matches a real IOC; the other is fabricated (not in GT)
        // yet self-labeled high confidence + tier 6. Precision = 1/2.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 2, 1.0, true));
        snap.evidence_values
            .push(make_evidence("ip", "8.8.8.8", 6, 1.0, true));
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        assert_abs_diff_eq!(score_evidence_quality(&snap, &gt), 0.5, epsilon = 0.001);
    }

    #[test]
    fn evidence_precision_technique_typed() {
        // Technique-typed evidence matching an expected technique is grounded.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("technique", "T1003", 6, 0.5, false));
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        assert_abs_diff_eq!(score_evidence_quality(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn evidence_grounded_by_technique_tag() {
        // Behavioral evidence: the value is not an IOC, but its MITRE tag
        // matches an expected technique (parent T1558 matches sub T1558.003).
        let mut snap = empty_snap();
        let mut ev = make_evidence("credential_access", "4769 rc4 ticket burst", 6, 0.9, true);
        ev.mitre_techniques = vec!["T1558.003".into()];
        snap.evidence_values.push(ev);
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1558", true)];
        assert_abs_diff_eq!(score_evidence_quality(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn timeline_accuracy_empty_gt_returns_one() {
        let snap = empty_snap();
        let gt = empty_gt();
        assert_abs_diff_eq!(score_timeline_accuracy(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn timeline_accuracy_empty_snap_returns_zero() {
        let snap = empty_snap();
        let mut gt = empty_gt();
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec![],
            timestamp_range: None,
            required: true,
        }];
        assert_abs_diff_eq!(score_timeline_accuracy(&snap, &gt), 0.0, epsilon = 0.001);
    }

    #[test]
    fn timeline_accuracy_matching_event() {
        let mut snap = empty_snap();
        snap.timeline.push(TimelineEvent {
            description: "credential dump via secretsdump".into(),
            mitre_techniques: HashSet::new(),
            machine_generated: true,
        });

        let mut gt = empty_gt();
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec![],
            timestamp_range: None,
            required: true,
        }];

        assert_abs_diff_eq!(score_timeline_accuracy(&snap, &gt), 1.0, epsilon = 0.001);
    }

    /// Prose alone earns nothing. Event matching is a fuzzy word overlap, so an
    /// ungated timeline pays a model for describing the attack it was told to
    /// look for — with no evidence, no technique tag, and nothing observed.
    #[test]
    fn timeline_accuracy_ignores_ungrounded_agent_prose() {
        let mut snap = empty_snap();
        snap.timeline.push(TimelineEvent {
            description: "credential dump via secretsdump".into(),
            mitre_techniques: HashSet::new(),
            machine_generated: false,
        });

        let mut gt = empty_gt();
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec![],
            timestamp_range: None,
            required: true,
        }];

        assert_abs_diff_eq!(score_timeline_accuracy(&snap, &gt), 0.0, epsilon = 0.001);
    }

    /// The same prose counts once the investigation holds grounded evidence
    /// carrying the event's technique — the corroboration
    /// `score_evidence_quality` already demands of its own half of the scorer.
    #[test]
    fn timeline_accuracy_credits_prose_backed_by_grounded_evidence() {
        let mut snap = empty_snap();
        let mut ev = make_evidence("technique", "T1003", 6, 0.9, true);
        ev.mitre_techniques = vec!["T1003".into()];
        snap.evidence_values.push(ev);
        snap.timeline.push(TimelineEvent {
            description: "credential dump via secretsdump".into(),
            mitre_techniques: HashSet::from(["T1003".to_string()]),
            machine_generated: false,
        });

        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec![],
            timestamp_range: None,
            required: true,
        }];

        assert_abs_diff_eq!(score_timeline_accuracy(&snap, &gt), 1.0, epsilon = 0.001);
    }

    /// A technique tag ground truth does not recognise is not grounding: the
    /// evidence carrying it fails `evidence_is_grounded`, so the timeline event
    /// it would have corroborated stays uncounted.
    #[test]
    fn timeline_accuracy_rejects_corroboration_from_ungrounded_evidence() {
        let mut snap = empty_snap();
        let mut ev = make_evidence("technique", "T1590", 6, 0.9, true);
        ev.mitre_techniques = vec!["T1590".into()];
        snap.evidence_values.push(ev);
        snap.timeline.push(TimelineEvent {
            description: "credential dump via secretsdump".into(),
            mitre_techniques: HashSet::from(["T1590".to_string()]),
            machine_generated: false,
        });

        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003", true)];
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec![],
            timestamp_range: None,
            required: true,
        }];

        assert_abs_diff_eq!(score_timeline_accuracy(&snap, &gt), 0.0, epsilon = 0.001);
    }

    #[test]
    fn timeline_event_matches_substring() {
        let descs = vec!["credential dump via secretsdump".into()];
        assert!(timeline_event_matches("credential dump", &descs));
    }

    #[test]
    fn timeline_event_matches_no_match() {
        let descs = vec!["port scan completed".into()];
        assert!(!timeline_event_matches("credential dump", &descs));
    }

    #[test]
    fn timeline_event_matches_regex() {
        let descs = vec!["lateral movement to dc01".into()];
        assert!(timeline_event_matches("lateral.*dc\\d+", &descs));
    }

    #[test]
    fn technique_matches_exact() {
        let t = make_technique("T1003", true);
        let found: HashSet<String> = ["T1003".into()].into_iter().collect();
        assert!(technique_matches(&t, &found));
    }

    #[test]
    fn technique_matches_parent_to_sub() {
        let t = make_technique("T1003", true);
        let found: HashSet<String> = ["T1003.001".into()].into_iter().collect();
        assert!(technique_matches(&t, &found));
    }

    #[test]
    fn technique_no_match() {
        let t = make_technique("T1003", true);
        let found: HashSet<String> = ["T1046".into()].into_iter().collect();
        assert!(!technique_matches(&t, &found));
    }

    #[test]
    fn overall_score_empty_is_bounded() {
        let snap = empty_snap();
        let gt = empty_gt();
        let score = score_investigation_overall(&snap, &gt);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn phase_coverage_credits_timeline_only_technique() {
        // A phase contributed solely by a timeline technique (T1021 lateral
        // movement, absent from expected_techniques) must be coverable when the
        // agent identifies it — otherwise the max score is unreachable.
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1558".into()); // credential access
        snap.identified_techniques.insert("T1021".into()); // lateral movement
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1558", true)];
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "lateral movement".into(),
            mitre_techniques: vec!["T1021".into()],
            timestamp_range: None,
            required: true,
        }];
        // Phases {CredentialAccess, LateralMovement}; both grounded => 1.0.
        assert_abs_diff_eq!(score_phase_coverage(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn phase_coverage_rejects_ungrounded_technique() {
        // Identifying a technique the attack never used earns no phase credit.
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1021".into()); // not in ground truth
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1558", true)];
        assert_abs_diff_eq!(score_phase_coverage(&snap, &gt), 0.0, epsilon = 0.001);
    }

    #[test]
    fn phase_coverage_stays_bounded_on_base_sub_divergence() {
        // GT wants only the DCSync sub-technique (DomainDominance). Base-id
        // grounding lets the agent's base T1003 (CredentialAccess) pass the
        // ground filter too, so covered spans two phases while expected has one.
        // The score must not exceed 1.0.
        let mut snap = empty_snap();
        snap.identified_techniques.insert("T1003".into()); // CredentialAccess
        snap.identified_techniques.insert("T1003.006".into()); // DomainDominance
        let mut gt = empty_gt();
        gt.expected_techniques = vec![make_technique("T1003.006", true)];
        assert_abs_diff_eq!(score_phase_coverage(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn pyramid_elevation_ignores_queried_only_host() {
        // Merely querying a host that matches an expected IOC must NOT elevate
        // the pyramid — only substantiated evidence counts.
        let mut snap = empty_snap();
        snap.queried_hosts.insert("192.168.58.1".into());
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        assert_abs_diff_eq!(score_pyramid_elevation(&snap, &gt), 0.0, epsilon = 0.001);
    }

    #[test]
    fn timeline_event_matches_empty_pattern_no_match() {
        let descs = vec!["kerberoasted svc_sql".to_string()];
        assert!(!timeline_event_matches("", &descs));
        assert!(!timeline_event_matches("   ", &descs));
    }

    #[test]
    fn timeline_event_matches_empty_description_skipped() {
        let descs = vec![String::new()];
        assert!(!timeline_event_matches("credential dump", &descs));
    }

    // technique_phase / KillChainPhase mapping

    #[track_caller]
    fn assert_phase(id: &str, expected: KillChainPhase) {
        assert_eq!(technique_phase(id), Some(expected), "technique {id}");
    }

    #[test]
    fn technique_phase_maps_each_kill_chain_phase() {
        use KillChainPhase::*;
        assert_phase("T1046", Discovery);
        assert_phase("T1003", CredentialAccess);
        assert_phase("T1021", LateralMovement);
        assert_phase("T1484", PrivilegeEscalation);
        assert_phase("T1078", DomainDominance);
    }

    #[test]
    fn technique_phase_dominance_subtechniques_outrank_base() {
        use KillChainPhase::*;
        // DCSync, Golden Ticket, and Domain Accounts sub-techniques resolve to
        // DomainDominance even though their base tactic differs.
        assert_phase("T1003.006", DomainDominance); // base T1003 = CredentialAccess
        assert_phase("T1558.001", DomainDominance); // base T1558 = CredentialAccess
        assert_phase("T1078.002", DomainDominance);
    }

    #[test]
    fn technique_phase_subtechnique_resolves_like_parent() {
        use KillChainPhase::*;
        // A non-dominance sub-technique resolves like its base id.
        assert_phase("T1046.001", Discovery);
        assert_phase("T1021.002", LateralMovement);
    }

    #[test]
    fn technique_phase_unknown_is_none() {
        assert_eq!(technique_phase("T9999"), None);
        assert_eq!(technique_phase(""), None);
    }

    #[test]
    fn phase_coverage_all_five_phases_covered() {
        // One grounded technique per kill-chain phase => full coverage.
        let mut snap = empty_snap();
        for id in ["T1046", "T1003", "T1021", "T1484", "T1078"] {
            snap.identified_techniques.insert(id.into());
        }
        let mut gt = empty_gt();
        gt.expected_techniques = vec![
            make_technique("T1046", false),
            make_technique("T1003", true),
            make_technique("T1021", true),
            make_technique("T1484", false),
            make_technique("T1078", true),
        ];
        assert_abs_diff_eq!(score_phase_coverage(&snap, &gt), 1.0, epsilon = 0.001);
    }

    #[test]
    fn build_evidence_values_domain_splits_short_name() {
        // A "domain" evidence value contributes both the full value and its
        // first label, mirroring the hostname split.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("domain", "contoso.local", 3, 0.9, true));
        let found = build_evidence_values(&snap);
        assert!(found.contains("contoso.local"));
        assert!(found.contains("contoso"));
    }

    #[test]
    fn build_evidence_values_excludes_queried_hosts() {
        // Unlike build_found_values, a merely-queried host is NOT included.
        let mut snap = empty_snap();
        snap.queried_hosts.insert("dc01".into());
        let found = build_evidence_values(&snap);
        assert!(!found.contains("dc01"));
    }

    #[test]
    fn expand_aliases_adds_whole_group_from_one_member() {
        // Finding one host identifier pulls in the rest of its alias group.
        let mut found: HashSet<String> = HashSet::new();
        found.insert("dc01".into());
        let mut gt = empty_gt();
        gt.host_aliases = vec![vec![
            "192.168.58.10".into(),
            "dc01.contoso.local".into(),
            "dc01".into(),
        ]];
        expand_aliases(&mut found, &gt);
        assert!(found.contains("192.168.58.10"));
        assert!(found.contains("dc01.contoso.local"));
        assert!(found.contains("dc01"));
    }

    #[test]
    fn expand_aliases_leaves_unmatched_group_untouched() {
        let mut found: HashSet<String> = HashSet::new();
        found.insert("web01".into());
        let mut gt = empty_gt();
        gt.host_aliases = vec![vec!["192.168.58.10".into(), "dc01.contoso.local".into()]];
        expand_aliases(&mut found, &gt);
        assert!(!found.contains("192.168.58.10"));
        assert!(!found.contains("dc01.contoso.local"));
    }

    #[test]
    fn ioc_detection_alias_credit_hostname_finding_matches_ip_ioc() {
        // The agent produced only a hostname finding; the expected IOC is the
        // host's IP. host_aliases links them, so the IP IOC is credited => 1.0.
        let mut snap = empty_snap();
        snap.evidence_values.push(make_evidence(
            "hostname",
            "dc01.contoso.local",
            3,
            0.9,
            true,
        ));
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.10", true)];
        gt.host_aliases = vec![vec![
            "192.168.58.10".into(),
            "dc01.contoso.local".into(),
            "dc01".into(),
        ]];
        assert_abs_diff_eq!(score_ioc_detection(&snap, &gt), 1.0, epsilon = 0.001);
    }

    // score_investigation_overall weight renormalization / bounds

    #[test]
    fn overall_renormalizes_when_timeline_absent() {
        // With no expected_timeline the overall is the weighted mean of the five
        // remaining dimensions (IOC 3.5, technique 3.5, pyramid 3.0, evidence
        // 3.0, phase 3.5) with the 3.5 timeline weight fully removed.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 2, 0.9, true));
        snap.identified_techniques.insert("T1003".into());
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        gt.expected_techniques = vec![make_technique("T1003", true)];
        assert!(gt.expected_timeline.is_empty());

        let ioc = score_ioc_detection(&snap, &gt);
        let tech = score_technique_coverage(&snap, &gt);
        let pyramid = score_pyramid_elevation(&snap, &gt);
        let evidence = score_evidence_quality(&snap, &gt);
        let phase = score_phase_coverage(&snap, &gt);
        let expected = (ioc * 3.5 + tech * 3.5 + pyramid * 3.0 + evidence * 3.0 + phase * 3.5)
            / (3.5 + 3.5 + 3.0 + 3.0 + 3.5);

        assert_abs_diff_eq!(
            score_investigation_overall(&snap, &gt),
            expected,
            epsilon = 0.0001
        );
    }

    #[test]
    fn overall_includes_timeline_dimension_when_present() {
        // When expected_timeline is non-empty the timeline dimension is added
        // back with its 3.5 weight, so the denominator is the full 20.0.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 2, 0.9, true));
        snap.identified_techniques.insert("T1003".into());
        snap.timeline.push(TimelineEvent {
            description: "credential dump via secretsdump".into(),
            mitre_techniques: HashSet::new(),
            machine_generated: true,
        });
        let mut gt = empty_gt();
        gt.expected_iocs = vec![make_ioc("ip", "192.168.58.1", true)];
        gt.expected_techniques = vec![make_technique("T1003", true)];
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec![],
            timestamp_range: None,
            required: true,
        }];

        let ioc = score_ioc_detection(&snap, &gt);
        let tech = score_technique_coverage(&snap, &gt);
        let pyramid = score_pyramid_elevation(&snap, &gt);
        let evidence = score_evidence_quality(&snap, &gt);
        let phase = score_phase_coverage(&snap, &gt);
        let timeline = score_timeline_accuracy(&snap, &gt);
        let expected = (ioc * 3.5
            + tech * 3.5
            + pyramid * 3.0
            + evidence * 3.0
            + phase * 3.5
            + timeline * 3.5)
            / (3.5 + 3.5 + 3.0 + 3.0 + 3.5 + 3.5);

        assert_abs_diff_eq!(
            score_investigation_overall(&snap, &gt),
            expected,
            epsilon = 0.0001
        );
    }

    #[test]
    fn overall_perfect_investigation_is_one_and_bounded() {
        // Every dimension maxed out => overall is exactly 1.0 and within bounds.
        let mut snap = empty_snap();
        snap.evidence_values
            .push(make_evidence("ip", "192.168.58.1", 2, 0.9, true));
        snap.evidence_values
            .push(make_evidence("user", "admin", 3, 0.9, true));
        snap.evidence_values
            .push(make_evidence("technique", "T1003", 6, 0.9, true));
        snap.identified_techniques.insert("T1003".into());
        snap.identified_techniques.insert("T1046".into());
        snap.timeline.push(TimelineEvent {
            description: "credential dump via secretsdump".into(),
            mitre_techniques: HashSet::from(["T1003".to_string()]),
            machine_generated: true,
        });
        let mut gt = empty_gt();
        gt.expected_iocs = vec![
            make_ioc("ip", "192.168.58.1", true),
            make_ioc("user", "admin", false),
        ];
        gt.expected_techniques = vec![
            make_technique("T1003", true),
            make_technique("T1046", false),
        ];
        gt.expected_timeline = vec![ExpectedTimelineEvent {
            description_pattern: "credential dump".into(),
            mitre_techniques: vec!["T1003".into()],
            timestamp_range: None,
            required: true,
        }];
        let score = score_investigation_overall(&snap, &gt);
        assert_abs_diff_eq!(score, 1.0, epsilon = 0.0001);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn timeline_event_matches_low_keyword_overlap_no_match() {
        // Under 50% of significant pattern words appear in the description, and
        // neither substring nor regex matches, so keyword overlap fails.
        let descs = vec!["kerberoasting against svc_sql service".to_string()];
        assert!(!timeline_event_matches(
            "credential dumping secretsdump lsass memory",
            &descs
        ));
    }
}
