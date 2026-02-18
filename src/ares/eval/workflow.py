"""
Evaluation workflow for blue team evaluation.

Provides the EvaluationRunner class and @dn.task decorated evaluation
function for running evaluations against real Grafana alerts.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import dreadnode as dn
from loguru import logger

from ares.core.models import (
    InvestigationState,
    SharedRedTeamState,
)
from ares.eval.ground_truth import (
    EvaluationGroundTruth,
    create_ground_truth_from_red_state,
)
from ares.eval.results import DatasetEvaluationResult, EvaluationResult
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

if TYPE_CHECKING:
    from ares.integrations.mitre import MITREAttackClient


@dn.task(  # type: ignore[arg-type]  # dreadnode SDK generic typing limitation
    scorers=[
        score_stage_progress,
        score_ioc_detection,
        score_technique_coverage,
        score_pyramid_elevation,
        score_timeline_accuracy,
        score_evidence_quality,
        score_investigation_overall,
    ],
    name="blue-team-evaluation",
    log_inputs=True,
    log_output=True,
)
async def evaluate_investigation(
    state: InvestigationState | None,
    ground_truth: EvaluationGroundTruth,
) -> tuple[InvestigationState | None, EvaluationGroundTruth]:
    """Evaluate a blue team investigation against ground truth.

    This task is decorated with @dn.task to integrate with Dreadnode
    for metrics tracking and scoring.

    Args:
        state: Investigation state from blue team agent (None if no investigation ran).
        ground_truth: Expected findings from red team operation.

    Returns:
        Tuple of (state, ground_truth) for scorers to evaluate.
    """
    # Log evaluation context
    dn.log_param("operation_id", ground_truth.operation_id)
    dn.log_param("target_ip", ground_truth.target_ip)
    dn.log_param("expected_iocs", len(ground_truth.expected_iocs))
    dn.log_param("expected_techniques", len(ground_truth.expected_techniques))

    if state is not None:
        dn.log_param("investigation_id", state.investigation_id)
        dn.log_metric("evidence_count", state.evidence_count)
        dn.log_metric("highest_pyramid_level", state.highest_pyramid_level)
        dn.log_metric("techniques_identified", len(state.identified_techniques))

    return state, ground_truth


def build_evaluation_result(
    evaluation_id: str,
    state: InvestigationState | None,
    ground_truth: EvaluationGroundTruth,
    alert_fired: bool,
    model: str = "",
    duration_seconds: float = 0.0,
    error: str | None = None,
    # New timing metrics
    time_to_first_evidence: float | None = None,
    time_to_technique_identification: float | None = None,
    time_to_ttp_elevation: float | None = None,
    # Cost metrics
    total_tokens: int = 0,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    estimated_cost_usd: float = 0.0,
) -> EvaluationResult:
    """Build a complete EvaluationResult from investigation state and ground truth.

    Args:
        evaluation_id: Unique evaluation identifier.
        state: Investigation state (None if no investigation ran).
        ground_truth: Ground truth for comparison.
        alert_fired: Whether a Grafana alert fired for this operation.
        model: LLM model used for investigation.
        duration_seconds: Investigation duration.
        error: Error message if evaluation failed.
        time_to_first_evidence: Seconds until first evidence was found.
        time_to_technique_identification: Seconds until first technique identified.
        time_to_ttp_elevation: Seconds until TTP-level evidence found.
        total_tokens: Total tokens used.
        prompt_tokens: Prompt tokens used.
        completion_tokens: Completion tokens used.
        estimated_cost_usd: Estimated cost in USD.

    Returns:
        Complete EvaluationResult with all scores and gaps.
    """
    output = (state, ground_truth)

    # Calculate all scores using .func to call the raw scoring functions
    # directly, bypassing the async @dn.scorer wrapper (which returns Metric).
    # The @dn.task scorers list handles platform logging separately.
    stage_score = score_stage_progress.func(output)
    ioc_score = score_ioc_detection.func(output)
    technique_score = score_technique_coverage.func(output)
    pyramid_score = score_pyramid_elevation.func(output)
    timeline_score = score_timeline_accuracy.func(output)
    evidence_score = score_evidence_quality.func(output)

    # Compute overall as weighted average matching score_investigation_overall weights:
    # Detection 35% (17.5% each), Quality 30% (15% each), Completeness 35% (17.5% each).
    total_weight = 3.5 + 3.5 + 3.0 + 3.0 + 3.5 + 3.5  # 20.0
    overall_score = (
        ioc_score * 3.5
        + technique_score * 3.5
        + pyramid_score * 3.0
        + evidence_score * 3.0
        + stage_score * 3.5
        + timeline_score * 3.5
    ) / total_weight

    # Calculate category scores
    detection_score = (ioc_score + technique_score) / 2
    quality_score = (pyramid_score + evidence_score) / 2
    completeness_score = (stage_score + timeline_score) / 2

    # Get gap analysis
    missed_iocs = get_missed_iocs(state, ground_truth)
    missed_techniques = get_missed_techniques(state, ground_truth)
    found_iocs = get_found_iocs(state, ground_truth)
    found_techniques = get_found_techniques(state, ground_truth)

    # Determine stages completed
    stages_completed = []
    if state is not None:
        from ares.core.models import InvestigationStage

        stage_order = [
            InvestigationStage.TRIAGE,
            InvestigationStage.CAUSATION,
            InvestigationStage.LATERAL,
            InvestigationStage.SYNTHESIS,
        ]
        current_idx = stage_order.index(state.stage) if state.stage in stage_order else -1
        stages_completed = [s.value for s in stage_order[: current_idx + 1]]

    return EvaluationResult(
        evaluation_id=evaluation_id,
        operation_id=ground_truth.operation_id,
        investigation_id=state.investigation_id if state else None,
        evaluated_at=datetime.now(timezone.utc),
        # Overall scores
        overall_score=overall_score,
        detection_score=detection_score,
        quality_score=quality_score,
        completeness_score=completeness_score,
        # Component scores
        stage_score=stage_score,
        ioc_detection_rate=ioc_score,
        technique_coverage=technique_score,
        pyramid_elevation_score=pyramid_score,
        timeline_accuracy=timeline_score,
        evidence_quality_score=evidence_score,
        # Stage info
        final_stage=state.stage if state else None,
        stages_completed=stages_completed,
        # Gap analysis
        missed_iocs=missed_iocs,
        missed_techniques=missed_techniques,
        found_iocs=found_iocs,
        found_techniques=found_techniques,
        # Stats
        evidence_count=state.evidence_count if state else 0,
        highest_pyramid_level=state.highest_pyramid_level if state else 0,
        ttp_count=state.ttp_count if state else 0,
        # Status
        alert_fired=alert_fired,
        investigation_started=state is not None,
        investigation_completed=state.stage.value == "synthesis" if state else False,
        # Metadata
        model=model,
        duration_seconds=duration_seconds,
        error=error,
        # Timing metrics
        time_to_first_evidence=time_to_first_evidence,
        time_to_technique_identification=time_to_technique_identification,
        time_to_ttp_elevation=time_to_ttp_elevation,
        # Cost metrics
        total_tokens=total_tokens,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        estimated_cost_usd=estimated_cost_usd,
    )


@dataclass
class AlertMatchingRules:
    """Configurable rules for matching alerts to red team operations.

    Attributes:
        match_by_exact_ip: Match if instance label equals target IP.
        match_by_subnet: Match if instance IP is in same /24 subnet.
        match_by_hostname_pattern: Regex patterns for hostname matching.
        match_by_time_window: Match alerts within this window of operation start.
        match_by_mitre_technique: Match if alert has matching MITRE technique.
        match_by_operation_id: Match if operation ID appears in alert.
    """

    match_by_exact_ip: bool = True
    match_by_subnet: bool = True
    match_by_hostname_pattern: list[str] = field(default_factory=list)
    match_by_time_window: timedelta | None = None
    match_by_mitre_technique: bool = True
    match_by_operation_id: bool = True


@dataclass
class EvaluationScenario:
    """A single evaluation scenario.

    Attributes:
        red_state: Red team operation state (or path to serialized state).
        ground_truth: Pre-computed ground truth (optional, generated if not provided).
        name: Human-readable scenario name.
        tags: Tags for filtering/grouping scenarios.
        alert_matching_rules: Custom alert matching rules for this scenario.
    """

    red_state: SharedRedTeamState | Path | str
    ground_truth: EvaluationGroundTruth | None = None
    name: str = ""
    tags: list[str] = field(default_factory=list)
    alert_matching_rules: AlertMatchingRules | None = None

    def get_ground_truth(self) -> EvaluationGroundTruth:
        """Get or generate ground truth for this scenario."""
        if self.ground_truth is not None:
            return self.ground_truth

        state = self.get_red_state()
        return create_ground_truth_from_red_state(state)

    def get_red_state(self) -> SharedRedTeamState:
        """Get red team state, loading from file if necessary."""
        if isinstance(self.red_state, SharedRedTeamState):
            return self.red_state

        # Load from file
        path = Path(self.red_state)
        if not path.exists():
            raise FileNotFoundError(f"Red team state file not found: {path}")

        data = json.loads(path.read_text())
        return _deserialize_red_state(data)


@dataclass
class EvaluationDataset:
    """A dataset of evaluation scenarios.

    Attributes:
        name: Dataset name.
        scenarios: List of evaluation scenarios.
        description: Optional dataset description.
    """

    name: str
    scenarios: list[EvaluationScenario] = field(default_factory=list)
    description: str = ""

    def __iter__(self):
        return iter(self.scenarios)

    def __len__(self):
        return len(self.scenarios)

    @classmethod
    def from_directory(cls, dir_path: Path | str, name: str = "") -> EvaluationDataset:
        """Load dataset from a directory of red team state files.

        Args:
            dir_path: Directory containing JSON state files.
            name: Dataset name (defaults to directory name).

        Returns:
            EvaluationDataset with scenarios for each state file.
        """
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        scenarios = []
        for state_file in sorted(dir_path.glob("*.json")):
            scenarios.append(
                EvaluationScenario(
                    red_state=state_file,
                    name=state_file.stem,
                )
            )

        return cls(
            name=name or dir_path.name,
            scenarios=scenarios,
        )

    @classmethod
    def from_json(cls, json_path: Path | str) -> EvaluationDataset:
        """Load dataset from a JSON file.

        Expected format:
        {
            "name": "dataset-name",
            "description": "optional description",
            "scenarios": [
                {"state_file": "path/to/state.json", "name": "scenario-1", "tags": ["tag1"]},
                ...
            ]
        }
        """
        json_path = Path(json_path)
        data = json.loads(json_path.read_text())

        scenarios = []
        base_dir = json_path.parent

        for scenario_data in data.get("scenarios", []):
            state_path = scenario_data.get("state_file", "")
            if not Path(state_path).is_absolute():
                state_path = base_dir / state_path

            scenarios.append(
                EvaluationScenario(
                    red_state=state_path,
                    name=scenario_data.get("name", ""),
                    tags=scenario_data.get("tags", []),
                )
            )

        return cls(
            name=data.get("name", json_path.stem),
            scenarios=scenarios,
            description=data.get("description", ""),
        )


# Cost estimates per 1M tokens (as of 2024)
MODEL_COSTS: dict[str, dict[str, float]] = {
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-opus-4-20250514": {"input": 15.0, "output": 75.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4-turbo": {"input": 10.0, "output": 30.0},
}


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate cost in USD for token usage."""
    costs = MODEL_COSTS.get(model, {"input": 5.0, "output": 15.0})
    return (prompt_tokens * costs["input"] + completion_tokens * costs["output"]) / 1_000_000


class EvaluationRunner:
    """Runner for blue team evaluations.

    Coordinates evaluation of blue team investigations against red team
    ground truth, with Dreadnode integration for metrics tracking.

    Attributes:
        model: LLM model to use for investigations.
        grafana_url: Grafana URL for alert polling.
        grafana_api_key: Grafana API key.
        max_steps: Maximum agent steps per investigation.
        output_dir: Directory for evaluation results.
        inject_synthetic_alerts: If True, create synthetic alerts instead of polling.
        default_matching_rules: Default alert matching rules.
    """

    def __init__(
        self,
        model: str,
        grafana_url: str,
        grafana_api_key: str,
        max_steps: int = 150,
        output_dir: Path | str = "./eval_results",
        inject_synthetic_alerts: bool = False,
        default_matching_rules: AlertMatchingRules | None = None,
    ):
        self.model = model
        self.grafana_url = grafana_url
        self.grafana_api_key = grafana_api_key
        self.max_steps = max_steps
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.inject_synthetic_alerts = inject_synthetic_alerts
        self.default_matching_rules = default_matching_rules or AlertMatchingRules()

        # Cached MITRE client
        self._mitre_client: MITREAttackClient | None = None

    async def _get_mitre_client(self):
        """Get or create cached MITRE client."""
        if self._mitre_client is None:
            from ares.integrations.mitre import MITREAttackClient

            self._mitre_client = MITREAttackClient()
            await self._mitre_client.load()
            logger.info("MITRE ATT&CK client loaded and cached")
        return self._mitre_client

    async def evaluate_scenario(
        self,
        scenario: EvaluationScenario,
        poll_timeout_seconds: int = 60,
        inject_synthetic: bool | None = None,
    ) -> EvaluationResult:
        """Evaluate a single scenario.

        Args:
            scenario: Evaluation scenario with red team state.
            poll_timeout_seconds: How long to wait for an alert to fire.
            inject_synthetic: Override for synthetic alert injection.

        Returns:
            EvaluationResult with scores and gaps.
        """
        evaluation_id = f"eval-{uuid.uuid4().hex[:8]}"
        ground_truth = scenario.get_ground_truth()
        red_state = scenario.get_red_state()

        logger.info(f"Starting evaluation {evaluation_id}")
        logger.info(f"  Operation: {ground_truth.operation_id}")
        logger.info(f"  Target: {ground_truth.target_ip}")
        logger.info(f"  Expected IOCs: {len(ground_truth.expected_iocs)}")
        logger.info(f"  Expected Techniques: {len(ground_truth.expected_techniques)}")

        start_time = time.time()
        state: InvestigationState | None = None
        alert_fired = False
        error: str | None = None
        orchestrator = None

        # Timing metrics
        time_to_first_evidence: float | None = None
        time_to_technique_identification: float | None = None
        time_to_ttp_elevation: float | None = None

        # Cost metrics
        total_tokens = 0
        prompt_tokens = 0
        completion_tokens = 0

        # Determine if we should inject synthetic alerts
        if inject_synthetic is not None:
            use_synthetic = inject_synthetic
        else:
            use_synthetic = self.inject_synthetic_alerts

        try:
            # Get or inject alert
            alert: dict[str, Any] | None = None
            if use_synthetic:
                alert = self._create_synthetic_alert(ground_truth, red_state)
                alert_fired = True
                logger.info("Using synthetic alert for evaluation")
            else:
                # Poll for alert related to this operation
                matching_rules = scenario.alert_matching_rules or self.default_matching_rules
                alert = await self._poll_for_alert(
                    ground_truth=ground_truth,
                    red_state=red_state,
                    timeout_seconds=poll_timeout_seconds,
                    matching_rules=matching_rules,
                )
                if alert is not None:
                    alert_fired = True
                    alert_name = alert.get("labels", {}).get("alertname", "unknown")
                    logger.info(f"Alert found: {alert_name}")

            if alert is not None:
                # Run investigation
                state, orchestrator = await self._run_investigation(alert)

                # Calculate timing metrics from state timeline
                if state and state.timeline:
                    for event in state.timeline:
                        delta = (event.timestamp - state.started_at).total_seconds()
                        event_offset = max(0.0, delta)

                        # First evidence
                        if time_to_first_evidence is None and event.evidence_ids:
                            time_to_first_evidence = event_offset

                        # First technique identification
                        if time_to_technique_identification is None and event.mitre_techniques:
                            time_to_technique_identification = event_offset

                        # TTP elevation (check evidence pyramid level)
                        if time_to_ttp_elevation is None:
                            for eid in event.evidence_ids:
                                evidence = state.get_evidence_by_id(eid)
                                if evidence and evidence.pyramid_level.value >= 5:
                                    time_to_ttp_elevation = event_offset
                                    break

                # TODO(martin): Extract token counts from Dreadnode metrics if available
                # For now, estimate based on steps
                estimated_tokens_per_step = 2000
                if state:
                    total_tokens = len(state.executed_queries) * estimated_tokens_per_step
                    prompt_tokens = int(total_tokens * 0.7)
                    completion_tokens = int(total_tokens * 0.3)

            else:
                logger.warning("No alert fired - this is a detection gap")

            # Run the evaluation task (for Dreadnode metrics)
            await evaluate_investigation(state, ground_truth)

        except Exception as e:
            logger.error(f"Evaluation error: {e}")
            error = str(e)

        finally:
            # Graceful cleanup
            if orchestrator is not None:
                try:
                    await orchestrator._shutdown_mcp()
                except Exception as cleanup_error:
                    logger.warning(f"Cleanup error: {cleanup_error}")

        duration = time.time() - start_time
        estimated_cost = estimate_cost(self.model, prompt_tokens, completion_tokens)

        # Build result
        result = build_evaluation_result(
            evaluation_id=evaluation_id,
            state=state,
            ground_truth=ground_truth,
            alert_fired=alert_fired,
            model=self.model,
            duration_seconds=duration,
            error=error,
            time_to_first_evidence=time_to_first_evidence,
            time_to_technique_identification=time_to_technique_identification,
            time_to_ttp_elevation=time_to_ttp_elevation,
            total_tokens=total_tokens,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            estimated_cost_usd=estimated_cost,
        )

        # Log summary
        logger.info(f"Evaluation complete: {result.grade} ({result.overall_score:.1%})")
        if not alert_fired:
            logger.warning("  Alert did not fire - detection gap identified")

        # Save individual result
        self._save_evaluation_result(result)

        return result

    async def evaluate_dataset(
        self,
        dataset: EvaluationDataset,
        poll_timeout_seconds: int = 60,
        max_concurrent: int = 1,
        inject_synthetic: bool | None = None,
    ) -> DatasetEvaluationResult:
        """Evaluate an entire dataset of scenarios.

        Args:
            dataset: Dataset of evaluation scenarios.
            poll_timeout_seconds: How long to wait for alerts per scenario.
            max_concurrent: Maximum concurrent evaluations (1 = sequential).
            inject_synthetic: Override for synthetic alert injection.

        Returns:
            DatasetEvaluationResult with aggregated metrics.
        """
        logger.info(f"Starting dataset evaluation: {dataset.name}")
        logger.info(f"  Scenarios: {len(dataset)}")
        logger.info(f"  Concurrency: {max_concurrent}")

        results: list[EvaluationResult] = []

        with dn.run(tags=["dataset-evaluation", dataset.name]):
            dn.log_param("dataset_name", dataset.name)
            dn.log_param("scenario_count", len(dataset))
            dn.log_param("model", self.model)
            dn.log_param("max_concurrent", max_concurrent)

            if max_concurrent == 1:
                # Sequential evaluation
                for i, scenario in enumerate(dataset, 1):
                    logger.info(f"\n[{i}/{len(dataset)}] Evaluating: {scenario.name or 'unnamed'}")
                    result = await self._evaluate_scenario_safe(
                        scenario, poll_timeout_seconds, inject_synthetic
                    )
                    results.append(result)
                    dn.log_metric(f"scenario_{i}_overall", result.overall_score)
            else:
                # Parallel evaluation with semaphore
                semaphore = asyncio.Semaphore(max_concurrent)

                async def eval_with_semaphore(
                    idx: int, scenario: EvaluationScenario
                ) -> EvaluationResult:
                    async with semaphore:
                        name = scenario.name or "unnamed"
                        logger.info(f"[{idx}/{len(dataset)}] Evaluating: {name}")
                        return await self._evaluate_scenario_safe(
                            scenario, poll_timeout_seconds, inject_synthetic
                        )

                tasks = [eval_with_semaphore(i, scenario) for i, scenario in enumerate(dataset, 1)]
                results = await asyncio.gather(*tasks)

                # Log metrics after parallel completion
                for i, result in enumerate(results, 1):
                    dn.log_metric(f"scenario_{i}_overall", result.overall_score)

            # Build dataset result
            dataset_result = DatasetEvaluationResult(
                dataset_name=dataset.name,
                results=list(results),
            )

            # Log aggregate metrics
            dn.log_metric("pass_rate", dataset_result.pass_rate)
            dn.log_metric("avg_overall_score", dataset_result.avg_overall_score)
            dn.log_metric("avg_ioc_detection", dataset_result.avg_ioc_detection_rate)
            dn.log_metric("avg_technique_coverage", dataset_result.avg_technique_coverage)
            dn.log_metric("alert_fire_rate", dataset_result.alert_fire_rate)

            # Save results
            self._save_dataset_results(dataset_result)

        logger.info("\nDataset evaluation complete")
        logger.info(dataset_result.to_summary())

        return dataset_result

    async def _evaluate_scenario_safe(
        self,
        scenario: EvaluationScenario,
        poll_timeout_seconds: int,
        inject_synthetic: bool | None,
    ) -> EvaluationResult:
        """Evaluate scenario with error handling."""
        try:
            return await self.evaluate_scenario(
                scenario,
                poll_timeout_seconds=poll_timeout_seconds,
                inject_synthetic=inject_synthetic,
            )
        except Exception as e:
            logger.error(f"Scenario failed: {e}")
            ground_truth = scenario.get_ground_truth()
            return build_evaluation_result(
                evaluation_id=f"eval-failed-{uuid.uuid4().hex[:8]}",
                state=None,
                ground_truth=ground_truth,
                alert_fired=False,
                model=self.model,
                error=str(e),
            )

    def _create_synthetic_alert(
        self,
        ground_truth: EvaluationGroundTruth,
        red_state: SharedRedTeamState,
    ) -> dict[str, Any]:
        """Create a synthetic alert from ground truth for testing.

        Generates a realistic-looking alert based on red team activities.
        """
        # Determine alert type based on techniques
        alert_name = "SuspiciousActivity"
        severity = "warning"
        mitre_technique = None

        techniques = list(ground_truth.expected_techniques)
        if techniques:
            # Pick the most significant technique for the alert
            for tech in techniques:
                if tech.technique_id.startswith("T1003"):
                    alert_name = "CredentialDumpingDetected"
                    severity = "critical"
                    mitre_technique = tech.technique_id
                    break
                if tech.technique_id.startswith("T1558"):
                    alert_name = "KerberosAttackDetected"
                    severity = "critical"
                    mitre_technique = tech.technique_id
                    break
                if tech.technique_id.startswith("T1021"):
                    alert_name = "LateralMovementDetected"
                    severity = "high"
                    mitre_technique = tech.technique_id
                    break
            if mitre_technique is None and techniques:
                mitre_technique = techniques[0].technique_id

        # Get operation timestamp if available
        if isinstance(red_state, SharedRedTeamState) or hasattr(red_state, "started_at"):
            starts_at = red_state.started_at.isoformat()
        else:
            starts_at = datetime.now(timezone.utc).isoformat()

        labels: dict[str, str] = {
            "alertname": alert_name,
            "instance": ground_truth.target_ip,
            "severity": severity,
            "job": "windows-security",
            "source": "synthetic-evaluation",
        }
        if mitre_technique:
            labels["mitre_technique"] = mitre_technique

        # Build description from ground truth
        ioc_summary = f"{len(ground_truth.expected_iocs)} IOCs"
        technique_summary = f"{len(ground_truth.expected_techniques)} techniques"

        return {
            "labels": labels,
            "annotations": {
                "summary": f"Synthetic alert for evaluation: {alert_name}",
                "description": (
                    f"Red team operation {ground_truth.operation_id} targeting "
                    f"{ground_truth.target_ip}. Expected: {ioc_summary}, {technique_summary}."
                ),
            },
            "startsAt": starts_at,
            "fingerprint": f"synthetic-{ground_truth.operation_id}",
        }

    async def _poll_for_alert(
        self,
        ground_truth: EvaluationGroundTruth,
        red_state: SharedRedTeamState,
        timeout_seconds: int = 60,
        matching_rules: AlertMatchingRules | None = None,
    ) -> dict[str, Any] | None:
        """Poll Grafana for an alert related to the red team operation.

        Uses configurable matching rules for flexible alert correlation.

        Args:
            ground_truth: Ground truth with target info.
            red_state: Red team state for context.
            timeout_seconds: How long to wait.
            matching_rules: Rules for matching alerts.

        Returns:
            Alert dict if found, None otherwise.
        """
        from ares.tools.blue import GrafanaTools

        rules = matching_rules or self.default_matching_rules

        grafana = GrafanaTools(
            base_url=self.grafana_url,
            api_key=self.grafana_api_key,
        )

        target_ip = ground_truth.target_ip
        operation_id = ground_truth.operation_id

        # Parse target IP for subnet matching
        try:
            target_network = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        except ValueError:
            target_network = None

        # Get expected techniques for matching
        expected_techniques = {t.technique_id for t in ground_truth.expected_techniques}
        # Also include parent techniques
        for tech in ground_truth.expected_techniques:
            if "." in tech.technique_id:
                expected_techniques.add(tech.technique_id.split(".")[0])

        # Get operation start time for time window matching
        if isinstance(red_state, SharedRedTeamState) or hasattr(red_state, "started_at"):
            operation_start = red_state.started_at
        else:
            operation_start = None

        start_time = time.time()
        poll_interval = 5  # seconds

        while time.time() - start_time < timeout_seconds:
            try:
                alerts = await grafana.get_firing_alerts()

                for alert in alerts:
                    if self._alert_matches(
                        alert=alert,
                        target_ip=target_ip,
                        target_network=target_network,
                        operation_id=operation_id,
                        expected_techniques=expected_techniques,
                        operation_start=operation_start,
                        rules=rules,
                    ):
                        return alert

            except Exception as e:
                logger.warning(f"Alert poll error: {e}")

            await asyncio.sleep(poll_interval)

        return None

    def _alert_matches(
        self,
        alert: dict[str, Any],
        target_ip: str,
        target_network: ipaddress.IPv4Network | ipaddress.IPv6Network | None,
        operation_id: str,
        expected_techniques: set[str],
        operation_start: datetime | None,
        rules: AlertMatchingRules,
    ) -> bool:
        """Check if an alert matches the evaluation criteria."""
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})
        instance = labels.get("instance", "")

        # Match by exact IP
        if rules.match_by_exact_ip:
            if instance == target_ip:
                return True
            if target_ip in str(annotations):
                return True

        # Match by subnet
        if rules.match_by_subnet and target_network:
            try:
                # Extract IP from instance (may include port)
                instance_ip = instance.split(":")[0] if ":" in instance else instance
                if ipaddress.ip_address(instance_ip) in target_network:
                    return True
            except ValueError:
                pass

        # Match by hostname patterns
        if rules.match_by_hostname_pattern:
            for pattern in rules.match_by_hostname_pattern:
                if re.search(pattern, instance, re.IGNORECASE):
                    return True

        # Match by MITRE technique
        if rules.match_by_mitre_technique:
            alert_technique = labels.get("mitre_technique") or annotations.get("mitre_technique")
            if alert_technique and alert_technique in expected_techniques:
                return True

        # Match by operation ID
        if rules.match_by_operation_id:
            alert_str = str(labels) + str(annotations)
            if operation_id in alert_str:
                return True

        # Match by time window
        if rules.match_by_time_window and operation_start:
            alert_time_str = alert.get("startsAt", "")
            if alert_time_str:
                try:
                    alert_time = datetime.fromisoformat(alert_time_str.replace("Z", "+00:00"))
                    time_delta = abs((alert_time - operation_start).total_seconds())
                    if time_delta <= rules.match_by_time_window.total_seconds():
                        return True
                except ValueError:
                    pass

        return False

    async def _run_investigation(self, alert: dict[str, Any]) -> tuple[InvestigationState, Any]:
        """Run a blue team investigation for an alert.

        Args:
            alert: Grafana alert dictionary.

        Returns:
            Tuple of (InvestigationState, orchestrator) for cleanup.
        """
        from ares.agents.blue import InvestigationOrchestrator

        # Use cached MITRE client
        mitre_client = await self._get_mitre_client()

        # Create orchestrator
        orchestrator = InvestigationOrchestrator(
            model=self.model,
            grafana_url=self.grafana_url,
            grafana_api_key=self.grafana_api_key,
            mitre_client=mitre_client,
            report_dir=self.output_dir / "reports",
            max_steps=self.max_steps,
        )

        # Run investigation
        result = await orchestrator.investigate(alert)

        # Get state from result dict (added for evaluation framework support)
        state = result.get("state")
        if state is None:
            raise RuntimeError(
                "Investigation result missing 'state' key - "
                "ensure InvestigationOrchestrator.investigate() returns state"
            )

        return state, orchestrator

    def _save_evaluation_result(self, result: EvaluationResult) -> Path:
        """Save individual evaluation result to JSON file."""
        filename = f"eval_{result.evaluation_id}_{result.operation_id}.json"
        filepath = self.output_dir / filename

        filepath.write_text(json.dumps(result.to_dict(), indent=2, default=str))
        logger.debug(f"Result saved: {filepath}")

        return filepath

    def _save_dataset_results(self, result: DatasetEvaluationResult) -> Path:
        """Save dataset evaluation results to JSON file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"dataset_{result.dataset_name}_{timestamp}.json"
        filepath = self.output_dir / filename

        filepath.write_text(json.dumps(result.to_dict(), indent=2, default=str))
        logger.info(f"Results saved: {filepath}")

        return filepath


def _deserialize_red_state(data: dict[str, Any]) -> SharedRedTeamState:
    """Deserialize red team state from JSON data.

    Creates a SharedRedTeamState from a dict, handling only the fields
    needed for evaluation (credentials, hashes, hosts, etc).
    """
    from ares.core.models import Credential, Hash, Host, User

    state = SharedRedTeamState(operation_id=data.get("operation_id", "unknown"))

    # Load credentials
    for cred_data in data.get("all_credentials", []):
        cred = Credential(
            username=cred_data.get("username", ""),
            password=cred_data.get("password", ""),
            domain=cred_data.get("domain", ""),
            source=cred_data.get("source", ""),
        )
        state.all_credentials.append(cred)

    # Load hashes
    for hash_data in data.get("all_hashes", []):
        h = Hash(
            username=hash_data.get("username", ""),
            hash_type=hash_data.get("hash_type", ""),
            hash_value=hash_data.get("hash_value", ""),
            domain=hash_data.get("domain", ""),
            source=hash_data.get("source", ""),
        )
        state.all_hashes.append(h)

    # Load hosts
    for host_data in data.get("all_hosts", []):
        host = Host(
            ip=host_data.get("ip", ""),
            hostname=host_data.get("hostname", ""),
            os=host_data.get("os", ""),
            roles=host_data.get("roles", []),
            services=host_data.get("services", []),
        )
        state.all_hosts.append(host)

    # Load users
    for user_data in data.get("all_users", []):
        user = User(
            username=user_data.get("username", ""),
            domain=user_data.get("domain", ""),
            source=user_data.get("source", ""),
        )
        state.all_users.append(user)

    # Load simple fields
    state.all_domains = data.get("all_domains", [])
    state.has_domain_admin = data.get("has_domain_admin", False)
    state.has_golden_ticket = data.get("has_golden_ticket", False)
    state.domain_admin_path = data.get("domain_admin_path")

    return state
