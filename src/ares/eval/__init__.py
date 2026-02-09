"""
Blue Team Evaluation Framework.

Provides evaluation infrastructure for measuring blue team SOC investigation
effectiveness using red team operation state as ground truth.

Example:
    >>> from ares.eval import EvaluationRunner, EvaluationDataset
    >>>
    >>> runner = EvaluationRunner(
    ...     model="claude-sonnet-4-20250514",
    ...     grafana_url="https://grafana.dev.plundr.ai",
    ...     grafana_api_key="...",
    ... )
    >>>
    >>> dataset = EvaluationDataset.from_directory("./red_team_states/")
    >>> results = await runner.evaluate_dataset(dataset)
    >>> print(results.to_summary())
"""

from ares.eval.gap_analysis import (
    DetectionRecommendation,
    GapAnalysisReport,
    analyze_detection_gaps,
)
from ares.eval.ground_truth import (
    EvaluationGroundTruth,
    ExpectedIOC,
    ExpectedShare,
    ExpectedTechnique,
    ExpectedTimelineEvent,
    ExpectedVulnerability,
    create_ground_truth_from_red_state,
)
from ares.eval.results import (
    DatasetEvaluationResult,
    EvaluationResult,
)
from ares.eval.scorers import (
    get_found_iocs,
    get_found_techniques,
    get_missed_iocs,
    get_missed_techniques,
    score_evidence_quality,
    score_investigation_overall,
    score_ioc_detection,
    score_pyramid_elevation,
    score_stage_progress,
    score_technique_coverage,
    score_timeline_accuracy,
)
from ares.eval.workflow import (
    AlertMatchingRules,
    EvaluationDataset,
    EvaluationRunner,
    EvaluationScenario,
    build_evaluation_result,
    evaluate_investigation,
)

__all__ = [
    # Workflow
    "AlertMatchingRules",
    # Results
    "DatasetEvaluationResult",
    "DetectionRecommendation",
    "EvaluationDataset",
    "EvaluationGroundTruth",
    "EvaluationResult",
    "EvaluationRunner",
    "EvaluationScenario",
    "ExpectedIOC",
    "ExpectedShare",
    "ExpectedTechnique",
    "ExpectedTimelineEvent",
    "ExpectedVulnerability",
    "GapAnalysisReport",
    # Gap analysis
    "analyze_detection_gaps",
    "build_evaluation_result",
    # Ground truth
    "create_ground_truth_from_red_state",
    "evaluate_investigation",
    # Scorers
    "get_found_iocs",
    "get_found_techniques",
    "get_missed_iocs",
    "get_missed_techniques",
    "score_evidence_quality",
    "score_investigation_overall",
    "score_ioc_detection",
    "score_pyramid_elevation",
    "score_stage_progress",
    "score_technique_coverage",
    "score_timeline_accuracy",
]
