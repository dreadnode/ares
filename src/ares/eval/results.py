"""
Evaluation result schema for blue team evaluation.

Defines the structure for storing and reporting evaluation results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ares.core.models import InvestigationStage
from ares.eval.ground_truth import ExpectedIOC, ExpectedTechnique


@dataclass
class EvaluationResult:
    """Complete evaluation result for a blue team investigation.

    Attributes:
        evaluation_id: Unique identifier for this evaluation.
        operation_id: Red team operation ID used as ground truth.
        investigation_id: Blue team investigation ID (if investigation ran).
        evaluated_at: When this evaluation was performed.

        # Overall scores (0.0 - 1.0)
        overall_score: Composite weighted score.
        detection_score: Combined IOC + technique detection score.
        quality_score: Combined pyramid + evidence quality score.
        completeness_score: Combined stage + timeline score.

        # Component scores (0.0 - 1.0)
        stage_score: Investigation stage progress score.
        ioc_detection_rate: Percentage of expected IOCs found.
        technique_coverage: Percentage of expected techniques identified.
        pyramid_elevation_score: How high up Pyramid of Pain.
        timeline_accuracy: Timeline event matching score.
        evidence_quality_score: Evidence confidence and validation score.

        # Stage information
        final_stage: Final investigation stage reached.
        stages_completed: List of stages completed.

        # Gap analysis
        missed_iocs: IOCs that were not detected.
        missed_techniques: Techniques that were not identified.
        found_iocs: IOCs that were successfully detected.
        found_techniques: Techniques that were successfully identified.

        # Investigation stats
        evidence_count: Total evidence items collected.
        highest_pyramid_level: Highest pyramid level reached.
        ttp_count: Number of TTP-level evidence items.

        # Alert/detection status
        alert_fired: Whether a Grafana alert actually fired.
        investigation_started: Whether the blue team investigation ran.
        investigation_completed: Whether investigation reached synthesis.

        # Metadata
        model: LLM model used for investigation.
        duration_seconds: Investigation duration.
        error: Error message if evaluation failed.
    """

    evaluation_id: str
    operation_id: str
    investigation_id: str | None = None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Overall scores
    overall_score: float = 0.0
    detection_score: float = 0.0
    quality_score: float = 0.0
    completeness_score: float = 0.0

    # Component scores
    stage_score: float = 0.0
    ioc_detection_rate: float = 0.0
    technique_coverage: float = 0.0
    pyramid_elevation_score: float = 0.0
    timeline_accuracy: float = 0.0
    evidence_quality_score: float = 0.0

    # Stage information
    final_stage: InvestigationStage | None = None
    stages_completed: list[str] = field(default_factory=list)

    # Gap analysis
    missed_iocs: list[ExpectedIOC] = field(default_factory=list)
    missed_techniques: list[ExpectedTechnique] = field(default_factory=list)
    found_iocs: list[ExpectedIOC] = field(default_factory=list)
    found_techniques: list[ExpectedTechnique] = field(default_factory=list)

    # Investigation stats
    evidence_count: int = 0
    highest_pyramid_level: int = 0
    ttp_count: int = 0

    # Alert/detection status
    alert_fired: bool = False
    investigation_started: bool = False
    investigation_completed: bool = False

    # Timing metrics (response time analysis)
    time_to_first_evidence: float | None = None
    time_to_technique_identification: float | None = None
    time_to_ttp_elevation: float | None = None

    # Cost tracking
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_cost_usd: float = 0.0

    # Metadata
    model: str = ""
    duration_seconds: float = 0.0
    error: str | None = None

    @property
    def passed(self) -> bool:
        """Whether the evaluation passed minimum thresholds."""
        return (
            self.overall_score >= 0.5
            and self.ioc_detection_rate >= 0.5
            and self.technique_coverage >= 0.5
        )

    @property
    def grade(self) -> str:
        """Letter grade for the evaluation."""
        if self.overall_score >= 0.9:
            return "A"
        if self.overall_score >= 0.8:
            return "B"
        if self.overall_score >= 0.7:
            return "C"
        if self.overall_score >= 0.6:
            return "D"
        return "F"

    @property
    def _investigation_status(self) -> str:
        """Human-readable investigation status."""
        if self.investigation_completed:
            return "Completed"
        if self.investigation_started:
            return "Started"
        return "Not Started"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "evaluation_id": self.evaluation_id,
            "operation_id": self.operation_id,
            "investigation_id": self.investigation_id,
            "evaluated_at": self.evaluated_at.isoformat(),
            "scores": {
                "overall": self.overall_score,
                "detection": self.detection_score,
                "quality": self.quality_score,
                "completeness": self.completeness_score,
                "stage": self.stage_score,
                "ioc_detection_rate": self.ioc_detection_rate,
                "technique_coverage": self.technique_coverage,
                "pyramid_elevation": self.pyramid_elevation_score,
                "timeline_accuracy": self.timeline_accuracy,
                "evidence_quality": self.evidence_quality_score,
            },
            "stage_info": {
                "final_stage": self.final_stage.value if self.final_stage else None,
                "stages_completed": self.stages_completed,
            },
            "gaps": {
                "missed_iocs": [
                    {"type": ioc.ioc_type, "value": ioc.value, "required": ioc.required}
                    for ioc in self.missed_iocs
                ],
                "missed_techniques": [
                    {"id": t.technique_id, "name": t.technique_name, "required": t.required}
                    for t in self.missed_techniques
                ],
                "found_iocs_count": len(self.found_iocs),
                "found_techniques_count": len(self.found_techniques),
            },
            "stats": {
                "evidence_count": self.evidence_count,
                "highest_pyramid_level": self.highest_pyramid_level,
                "ttp_count": self.ttp_count,
            },
            "status": {
                "alert_fired": self.alert_fired,
                "investigation_started": self.investigation_started,
                "investigation_completed": self.investigation_completed,
                "passed": self.passed,
                "grade": self.grade,
            },
            "timing": {
                "duration_seconds": self.duration_seconds,
                "time_to_first_evidence": self.time_to_first_evidence,
                "time_to_technique_identification": self.time_to_technique_identification,
                "time_to_ttp_elevation": self.time_to_ttp_elevation,
            },
            "cost": {
                "total_tokens": self.total_tokens,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "estimated_cost_usd": self.estimated_cost_usd,
            },
            "metadata": {
                "model": self.model,
                "error": self.error,
            },
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            f"Evaluation: {self.evaluation_id}",
            f"Operation: {self.operation_id}",
            f"Grade: {self.grade} ({self.overall_score:.1%})",
            "",
            "Scores:",
            f"  Detection: {self.detection_score:.1%}",
            f"  Quality: {self.quality_score:.1%}",
            f"  Completeness: {self.completeness_score:.1%}",
            "",
            (
                f"IOC Detection: {self.ioc_detection_rate:.1%} "
                f"({len(self.found_iocs)}/{len(self.found_iocs) + len(self.missed_iocs)})"
            ),
            (
                f"Technique Coverage: {self.technique_coverage:.1%} "
                f"({len(self.found_techniques)}/"
                f"{len(self.found_techniques) + len(self.missed_techniques)})"
            ),
            f"Pyramid Level: {self.highest_pyramid_level}/6",
            "",
            f"Alert Fired: {'Yes' if self.alert_fired else 'No'}",
            f"Investigation: {self._investigation_status}",
        ]

        # Timing metrics
        if self.time_to_first_evidence is not None or self.duration_seconds > 0:
            lines.append("")
            lines.append("Timing:")
            lines.append(f"  Duration: {self.duration_seconds:.1f}s")
            if self.time_to_first_evidence is not None:
                lines.append(f"  Time to First Evidence: {self.time_to_first_evidence:.1f}s")
            if self.time_to_technique_identification is not None:
                ttid = self.time_to_technique_identification
                lines.append(f"  Time to Technique ID: {ttid:.1f}s")
            if self.time_to_ttp_elevation is not None:
                lines.append(f"  Time to TTP Elevation: {self.time_to_ttp_elevation:.1f}s")

        # Cost metrics
        if self.total_tokens > 0:
            lines.append("")
            lines.append("Cost:")
            lines.append(
                f"  Tokens: {self.total_tokens:,} "
                f"(prompt: {self.prompt_tokens:,}, completion: {self.completion_tokens:,})"
            )
            lines.append(f"  Estimated Cost: ${self.estimated_cost_usd:.4f}")

        if self.missed_techniques:
            lines.append("")
            lines.append("Missed Techniques:")
            for t in self.missed_techniques[:5]:
                lines.append(f"  - {t.technique_id}: {t.technique_name}")
            if len(self.missed_techniques) > 5:
                lines.append(f"  ... and {len(self.missed_techniques) - 5} more")

        if self.error:
            lines.append("")
            lines.append(f"Error: {self.error}")

        return "\n".join(lines)


@dataclass
class DatasetEvaluationResult:
    """Aggregated results for evaluating a dataset of scenarios.

    Attributes:
        dataset_name: Name of the evaluated dataset.
        evaluated_at: When evaluation was performed.
        results: Individual evaluation results.
        aggregate_scores: Averaged scores across all evaluations.
    """

    dataset_name: str
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    results: list[EvaluationResult] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Number of evaluations in dataset."""
        return len(self.results)

    @property
    def pass_rate(self) -> float:
        """Percentage of evaluations that passed."""
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.passed) / len(self.results)

    @property
    def avg_overall_score(self) -> float:
        """Average overall score."""
        if not self.results:
            return 0.0
        return sum(r.overall_score for r in self.results) / len(self.results)

    @property
    def avg_ioc_detection_rate(self) -> float:
        """Average IOC detection rate."""
        if not self.results:
            return 0.0
        return sum(r.ioc_detection_rate for r in self.results) / len(self.results)

    @property
    def avg_technique_coverage(self) -> float:
        """Average technique coverage."""
        if not self.results:
            return 0.0
        return sum(r.technique_coverage for r in self.results) / len(self.results)

    @property
    def alert_fire_rate(self) -> float:
        """Percentage of scenarios where alert fired."""
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.alert_fired) / len(self.results)

    @property
    def investigation_completion_rate(self) -> float:
        """Percentage of investigations that completed."""
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.investigation_completed) / len(self.results)

    @property
    def total_cost_usd(self) -> float:
        """Total estimated cost across all evaluations."""
        return sum(r.estimated_cost_usd for r in self.results)

    @property
    def total_tokens(self) -> int:
        """Total tokens used across all evaluations."""
        return sum(r.total_tokens for r in self.results)

    @property
    def avg_duration_seconds(self) -> float:
        """Average investigation duration."""
        if not self.results:
            return 0.0
        return sum(r.duration_seconds for r in self.results) / len(self.results)

    @property
    def avg_time_to_first_evidence(self) -> float | None:
        """Average time to first evidence (excluding None values)."""
        times = [
            r.time_to_first_evidence
            for r in self.results
            if r.time_to_first_evidence is not None
        ]
        if not times:
            return None
        return sum(times) / len(times)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "dataset_name": self.dataset_name,
            "evaluated_at": self.evaluated_at.isoformat(),
            "summary": {
                "count": self.count,
                "pass_rate": self.pass_rate,
                "avg_overall_score": self.avg_overall_score,
                "avg_ioc_detection_rate": self.avg_ioc_detection_rate,
                "avg_technique_coverage": self.avg_technique_coverage,
                "alert_fire_rate": self.alert_fire_rate,
                "investigation_completion_rate": self.investigation_completion_rate,
                "total_cost_usd": self.total_cost_usd,
                "total_tokens": self.total_tokens,
                "avg_duration_seconds": self.avg_duration_seconds,
                "avg_time_to_first_evidence": self.avg_time_to_first_evidence,
            },
            "results": [r.to_dict() for r in self.results],
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            f"Dataset Evaluation: {self.dataset_name}",
            f"Evaluated: {self.evaluated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Scenarios: {self.count}",
            "",
            "Aggregate Scores:",
            f"  Pass Rate: {self.pass_rate:.1%}",
            f"  Avg Overall: {self.avg_overall_score:.1%}",
            f"  Avg IOC Detection: {self.avg_ioc_detection_rate:.1%}",
            f"  Avg Technique Coverage: {self.avg_technique_coverage:.1%}",
            "",
            "Detection Metrics:",
            f"  Alert Fire Rate: {self.alert_fire_rate:.1%}",
            f"  Investigation Completion: {self.investigation_completion_rate:.1%}",
            "",
            "Cost & Performance:",
            f"  Total Cost: ${self.total_cost_usd:.4f}",
            f"  Total Tokens: {self.total_tokens:,}",
            f"  Avg Duration: {self.avg_duration_seconds:.1f}s",
        ]

        if self.avg_time_to_first_evidence is not None:
            lines.append(f"  Avg Time to First Evidence: {self.avg_time_to_first_evidence:.1f}s")

        # Grade distribution
        grade_counts: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for result in self.results:
            grade_counts[result.grade] += 1

        lines.append("")
        lines.append("Grade Distribution:")
        for grade in ["A", "B", "C", "D", "F"]:
            count = grade_counts[grade]
            pct = count / self.count * 100 if self.count > 0 else 0
            bar = "#" * int(pct / 5)
            lines.append(f"  {grade}: {count:3d} ({pct:5.1f}%) {bar}")

        return "\n".join(lines)
