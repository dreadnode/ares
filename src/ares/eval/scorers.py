"""
Scorers for blue team evaluation.

Each scorer follows the Dreadnode Scorer pattern for Eval integration.
Scorers evaluate investigation state against ground truth and return
a float score between 0.0 and 1.0.
"""

from __future__ import annotations

import dreadnode as dn

from ares.core.models import InvestigationStage, InvestigationState, PyramidLevel
from ares.eval.ground_truth import EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique


@dn.scorer(name="Stage Progress")
def score_stage_progress(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Score investigation stage progress.

    Measures how far through the investigation stages the agent progressed:
    - TRIAGE: 0.25
    - CAUSATION: 0.50
    - LATERAL: 0.75
    - SYNTHESIS: 1.0

    Returns 0.0 if investigation didn't start.
    """
    state, _ground_truth = output

    if state is None:
        return 0.0

    stage_scores = {
        InvestigationStage.TRIAGE: 0.25,
        InvestigationStage.CAUSATION: 0.50,
        InvestigationStage.LATERAL: 0.75,
        InvestigationStage.SYNTHESIS: 1.0,
    }

    return stage_scores.get(state.stage, 0.0)


@dn.scorer(name="IOC Detection Rate")
def score_ioc_detection(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Score IOC detection rate.

    Compares evidence found in investigation against expected IOCs.
    Uses fuzzy matching for hostnames (case-insensitive, partial match).
    Uses exact matching for IPs and hashes.

    Weighting:
    - Required IOCs: 60% of score
    - Optional IOCs: 40% of score

    Returns 0.0 if investigation didn't start or no IOCs expected.
    """
    state, ground_truth = output

    if state is None:
        return 0.0

    if not ground_truth.expected_iocs:
        return 1.0  # No IOCs expected = perfect score

    # Build set of found values from evidence
    found_values: set[str] = set()
    for evidence in state.evidence:
        found_values.add(evidence.value.lower())
        # Also add partial matches for hostnames
        if evidence.type in ("hostname", "domain"):
            # Add without domain suffix
            parts = evidence.value.lower().split(".")
            if parts:
                found_values.add(parts[0])

    # Also check queried hosts and users
    for host in state.queried_hosts:
        found_values.add(host.lower())
    for user in state.queried_users:
        found_values.add(user.lower())

    # Score required IOCs
    required_found = 0
    required_total = len(ground_truth.required_iocs)

    for ioc in ground_truth.required_iocs:
        if _ioc_matches(ioc, found_values):
            required_found += 1

    # Score optional IOCs
    optional_found = 0
    optional_total = len(ground_truth.optional_iocs)

    for ioc in ground_truth.optional_iocs:
        if _ioc_matches(ioc, found_values):
            optional_found += 1

    # Calculate weighted score
    required_score = required_found / required_total if required_total > 0 else 1.0
    optional_score = optional_found / optional_total if optional_total > 0 else 1.0

    # Weight: 60% required, 40% optional
    return (required_score * 0.6) + (optional_score * 0.4)


def _ioc_matches(ioc: ExpectedIOC, found_values: set[str]) -> bool:
    """Check if an expected IOC matches any found value."""
    ioc_value = ioc.value.lower()

    # Exact match
    if ioc_value in found_values:
        return True

    # For hostnames/domains, check partial match
    if ioc.ioc_type in ("hostname", "domain"):
        # Check if any found value contains this hostname
        for found in found_values:
            if ioc_value in found or found in ioc_value:
                return True
        # Check first part of hostname
        parts = ioc_value.split(".")
        if parts and parts[0] in found_values:
            return True

    # For users, check without domain prefix
    if ioc.ioc_type == "user":
        # Handle domain\user format
        if "\\" in ioc_value:
            username = ioc_value.split("\\")[-1]
            if username in found_values:
                return True
        # Handle user@domain format
        if "@" in ioc_value:
            username = ioc_value.split("@")[0]
            if username in found_values:
                return True

    return False


@dn.scorer(name="Technique Coverage")
def score_technique_coverage(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Score MITRE technique coverage.

    Compares identified techniques against expected techniques.
    Supports parent/sub-technique matching:
    - T1003 matches T1003.001 (parent matches child)
    - T1003.001 matches T1003 (child matches parent)

    Weighting:
    - Required techniques: 60% of score
    - Optional techniques: 40% of score

    Returns 0.0 if investigation didn't start or no techniques expected.
    """
    state, ground_truth = output

    if state is None:
        return 0.0

    if not ground_truth.expected_techniques:
        return 1.0  # No techniques expected = perfect score

    found_techniques = state.identified_techniques

    # Score required techniques
    required_found = 0
    required_total = len(ground_truth.required_techniques)

    for expected in ground_truth.required_techniques:
        if _technique_matches(expected, found_techniques):
            required_found += 1

    # Score optional techniques
    optional_found = 0
    optional_total = len(ground_truth.optional_techniques)

    for expected in ground_truth.optional_techniques:
        if _technique_matches(expected, found_techniques):
            optional_found += 1

    # Calculate weighted score
    required_score = required_found / required_total if required_total > 0 else 1.0
    optional_score = optional_found / optional_total if optional_total > 0 else 1.0

    # Weight: 60% required, 40% optional
    return (required_score * 0.6) + (optional_score * 0.4)


def _technique_matches(expected: ExpectedTechnique, found_techniques: set[str]) -> bool:
    """Check if an expected technique matches any found technique."""
    for found in found_techniques:
        if expected.matches(found):
            return True
    return False


@dn.scorer(name="Pyramid Elevation")
def score_pyramid_elevation(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Score Pyramid of Pain elevation.

    Measures how high up the Pyramid of Pain the investigation climbed.

    Scoring:
    - 70% weight: highest_level / 6 (normalized)
    - 30% weight: high_level_ratio (% of evidence at level 5-6)

    Returns 0.0 if investigation didn't start.
    """
    state, _ground_truth = output

    if state is None:
        return 0.0

    if not state.evidence:
        return 0.0

    # Calculate highest level score (70% weight)
    highest_level = state.highest_pyramid_level
    highest_score = highest_level / 6.0

    # Calculate high-level ratio (30% weight)
    high_level_evidence = sum(
        1
        for e in state.evidence
        if e.pyramid_level in (PyramidLevel.TOOLS, PyramidLevel.TTPS)
    )
    high_level_ratio = high_level_evidence / len(state.evidence) if state.evidence else 0.0

    return (highest_score * 0.7) + (high_level_ratio * 0.3)


@dn.scorer(name="Timeline Accuracy")
def score_timeline_accuracy(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Score timeline accuracy.

    Measures how well the investigation timeline matches expected events.

    Scoring based on:
    - Event matching (description pattern match)
    - Technique association (correct MITRE techniques linked)
    - Chronological ordering

    Returns 0.0 if investigation didn't start or no timeline expected.
    """
    state, ground_truth = output

    if state is None:
        return 0.0

    if not ground_truth.expected_timeline:
        return 1.0  # No timeline expected = perfect score

    if not state.timeline:
        return 0.0  # No timeline generated = zero score

    # Build set of timeline descriptions and techniques
    found_descriptions: set[str] = set()
    found_techniques_in_timeline: set[str] = set()

    for event in state.timeline:
        found_descriptions.add(event.description.lower())
        found_techniques_in_timeline.update(event.mitre_techniques)

    # Score event matching
    events_matched = 0
    for expected_event in ground_truth.expected_timeline:
        pattern = expected_event.description_pattern.lower()
        # Check if any found description contains the pattern
        for desc in found_descriptions:
            if pattern in desc or desc in pattern:
                events_matched += 1
                break

    event_score = events_matched / len(ground_truth.expected_timeline)

    # Score technique coverage in timeline
    expected_timeline_techniques: set[str] = set()
    for event in ground_truth.expected_timeline:
        expected_timeline_techniques.update(event.mitre_techniques)

    if expected_timeline_techniques:
        technique_matches = len(
            expected_timeline_techniques & found_techniques_in_timeline
        )
        technique_score = technique_matches / len(expected_timeline_techniques)
    else:
        technique_score = 1.0

    # Combine scores: 60% event matching, 40% technique association
    return (event_score * 0.6) + (technique_score * 0.4)


@dn.scorer(name="Evidence Quality")
def score_evidence_quality(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Score evidence quality.

    Measures the quality of evidence collected:
    - Average confidence score
    - Validation rate (% of validated evidence)
    - TTP ratio (% of evidence at TTP level)

    Returns 0.0 if investigation didn't start or no evidence collected.
    """
    state, _ground_truth = output

    if state is None:
        return 0.0

    if not state.evidence:
        return 0.0

    # Calculate average confidence (40% weight)
    avg_confidence = sum(e.confidence for e in state.evidence) / len(state.evidence)

    # Calculate validation rate (30% weight)
    validated_count = sum(1 for e in state.evidence if e.validated)
    validation_rate = validated_count / len(state.evidence)

    # Calculate TTP ratio (30% weight)
    ttp_count = sum(1 for e in state.evidence if e.pyramid_level == PyramidLevel.TTPS)
    ttp_ratio = ttp_count / len(state.evidence)

    return (avg_confidence * 0.4) + (validation_rate * 0.3) + (ttp_ratio * 0.3)


@dn.scorer(name="Investigation Quality")
def score_investigation_overall(
    output: tuple[InvestigationState | None, EvaluationGroundTruth],
) -> float:
    """Composite scorer for overall investigation quality.

    Combines all component scores with weights:
    - Detection (IOC + Technique): 35%
    - Quality (Pyramid + Evidence): 30%
    - Completeness (Stage + Timeline): 20%
    - Efficiency (stage progress alone): 15%

    Returns 0.0 if investigation didn't start.
    """
    state, ground_truth = output

    if state is None:
        return 0.0

    # Get component scores
    ioc_score = score_ioc_detection(output)
    technique_score = score_technique_coverage(output)
    pyramid_score = score_pyramid_elevation(output)
    evidence_score = score_evidence_quality(output)
    stage_score = score_stage_progress(output)
    timeline_score = score_timeline_accuracy(output)

    # Calculate category scores
    detection_score = (ioc_score + technique_score) / 2
    quality_score = (pyramid_score + evidence_score) / 2
    completeness_score = (stage_score + timeline_score) / 2

    # Weighted composite
    return (
        (detection_score * 0.35)
        + (quality_score * 0.30)
        + (completeness_score * 0.20)
        + (stage_score * 0.15)
    )


# Helper functions for external use


def get_missed_iocs(
    state: InvestigationState | None,
    ground_truth: EvaluationGroundTruth,
) -> list[ExpectedIOC]:
    """Get list of IOCs that were not detected."""
    if state is None:
        return ground_truth.expected_iocs.copy()

    # Build set of found values
    found_values: set[str] = set()
    for evidence in state.evidence:
        found_values.add(evidence.value.lower())
        if evidence.type in ("hostname", "domain"):
            parts = evidence.value.lower().split(".")
            if parts:
                found_values.add(parts[0])

    for host in state.queried_hosts:
        found_values.add(host.lower())
    for user in state.queried_users:
        found_values.add(user.lower())

    missed = []
    for ioc in ground_truth.expected_iocs:
        if not _ioc_matches(ioc, found_values):
            missed.append(ioc)

    return missed


def get_found_iocs(
    state: InvestigationState | None,
    ground_truth: EvaluationGroundTruth,
) -> list[ExpectedIOC]:
    """Get list of IOCs that were successfully detected."""
    if state is None:
        return []

    # Build set of found values
    found_values: set[str] = set()
    for evidence in state.evidence:
        found_values.add(evidence.value.lower())
        if evidence.type in ("hostname", "domain"):
            parts = evidence.value.lower().split(".")
            if parts:
                found_values.add(parts[0])

    for host in state.queried_hosts:
        found_values.add(host.lower())
    for user in state.queried_users:
        found_values.add(user.lower())

    found = []
    for ioc in ground_truth.expected_iocs:
        if _ioc_matches(ioc, found_values):
            found.append(ioc)

    return found


def get_missed_techniques(
    state: InvestigationState | None,
    ground_truth: EvaluationGroundTruth,
) -> list[ExpectedTechnique]:
    """Get list of techniques that were not identified."""
    if state is None:
        return ground_truth.expected_techniques.copy()

    missed = []
    for expected in ground_truth.expected_techniques:
        if not _technique_matches(expected, state.identified_techniques):
            missed.append(expected)

    return missed


def get_found_techniques(
    state: InvestigationState | None,
    ground_truth: EvaluationGroundTruth,
) -> list[ExpectedTechnique]:
    """Get list of techniques that were successfully identified."""
    if state is None:
        return []

    found = []
    for expected in ground_truth.expected_techniques:
        if _technique_matches(expected, state.identified_techniques):
            found.append(expected)

    return found
