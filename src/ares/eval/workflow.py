"""
Evaluation workflow for blue team evaluation.

Provides the EvaluationRunner class and @dn.task decorated evaluation
function for running evaluations against real Grafana alerts.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dreadnode as dn
from loguru import logger

from ares.core.models import (
    InvestigationState,
    RedTeamState,
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


@dn.task(
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

    Returns:
        Complete EvaluationResult with all scores and gaps.
    """
    output = (state, ground_truth)

    # Calculate all scores
    stage_score = score_stage_progress(output)
    ioc_score = score_ioc_detection(output)
    technique_score = score_technique_coverage(output)
    pyramid_score = score_pyramid_elevation(output)
    timeline_score = score_timeline_accuracy(output)
    evidence_score = score_evidence_quality(output)
    overall_score = score_investigation_overall(output)

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
    )


@dataclass
class EvaluationScenario:
    """A single evaluation scenario.

    Attributes:
        red_state: Red team operation state (or path to serialized state).
        ground_truth: Pre-computed ground truth (optional, generated if not provided).
        name: Human-readable scenario name.
        tags: Tags for filtering/grouping scenarios.
    """

    red_state: RedTeamState | SharedRedTeamState | Path | str
    ground_truth: EvaluationGroundTruth | None = None
    name: str = ""
    tags: list[str] = field(default_factory=list)

    def get_ground_truth(self) -> EvaluationGroundTruth:
        """Get or generate ground truth for this scenario."""
        if self.ground_truth is not None:
            return self.ground_truth

        state = self.get_red_state()
        return create_ground_truth_from_red_state(state)

    def get_red_state(self) -> RedTeamState | SharedRedTeamState:
        """Get red team state, loading from file if necessary."""
        if isinstance(self.red_state, (RedTeamState, SharedRedTeamState)):
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
    """

    def __init__(
        self,
        model: str,
        grafana_url: str,
        grafana_api_key: str,
        max_steps: int = 150,
        output_dir: Path | str = "./eval_results",
    ):
        self.model = model
        self.grafana_url = grafana_url
        self.grafana_api_key = grafana_api_key
        self.max_steps = max_steps
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def evaluate_scenario(
        self,
        scenario: EvaluationScenario,
        poll_timeout_seconds: int = 60,
    ) -> EvaluationResult:
        """Evaluate a single scenario.

        Args:
            scenario: Evaluation scenario with red team state.
            poll_timeout_seconds: How long to wait for an alert to fire.

        Returns:
            EvaluationResult with scores and gaps.
        """
        evaluation_id = f"eval-{uuid.uuid4().hex[:8]}"
        ground_truth = scenario.get_ground_truth()

        logger.info(f"Starting evaluation {evaluation_id}")
        logger.info(f"  Operation: {ground_truth.operation_id}")
        logger.info(f"  Target: {ground_truth.target_ip}")
        logger.info(f"  Expected IOCs: {len(ground_truth.expected_iocs)}")
        logger.info(f"  Expected Techniques: {len(ground_truth.expected_techniques)}")

        start_time = time.time()
        state: InvestigationState | None = None
        alert_fired = False
        error: str | None = None

        try:
            # Poll for alert related to this operation
            alert = await self._poll_for_alert(
                ground_truth.target_ip,
                ground_truth.operation_id,
                timeout_seconds=poll_timeout_seconds,
            )

            if alert is not None:
                alert_fired = True
                logger.info(f"Alert found: {alert.get('labels', {}).get('alertname', 'unknown')}")

                # Run investigation
                state = await self._run_investigation(alert)
            else:
                logger.warning("No alert fired - this is a detection gap")

            # Run the evaluation task (for Dreadnode metrics)
            await evaluate_investigation(state, ground_truth)

        except Exception as e:
            logger.error(f"Evaluation error: {e}")
            error = str(e)

        duration = time.time() - start_time

        # Build result
        result = build_evaluation_result(
            evaluation_id=evaluation_id,
            state=state,
            ground_truth=ground_truth,
            alert_fired=alert_fired,
            model=self.model,
            duration_seconds=duration,
            error=error,
        )

        # Log summary
        logger.info(f"Evaluation complete: {result.grade} ({result.overall_score:.1%})")
        if not alert_fired:
            logger.warning("  Alert did not fire - detection gap identified")

        return result

    async def evaluate_dataset(
        self,
        dataset: EvaluationDataset,
        poll_timeout_seconds: int = 60,
    ) -> DatasetEvaluationResult:
        """Evaluate an entire dataset of scenarios.

        Args:
            dataset: Dataset of evaluation scenarios.
            poll_timeout_seconds: How long to wait for alerts per scenario.

        Returns:
            DatasetEvaluationResult with aggregated metrics.
        """
        logger.info(f"Starting dataset evaluation: {dataset.name}")
        logger.info(f"  Scenarios: {len(dataset)}")

        results: list[EvaluationResult] = []

        with dn.run(tags=["dataset-evaluation", dataset.name]):
            dn.log_param("dataset_name", dataset.name)
            dn.log_param("scenario_count", len(dataset))
            dn.log_param("model", self.model)

            for i, scenario in enumerate(dataset, 1):
                logger.info(f"\n[{i}/{len(dataset)}] Evaluating: {scenario.name or 'unnamed'}")

                try:
                    result = await self.evaluate_scenario(
                        scenario,
                        poll_timeout_seconds=poll_timeout_seconds,
                    )
                    results.append(result)

                    # Log progress metrics
                    dn.log_metric(f"scenario_{i}_overall", result.overall_score)
                    dn.log_metric(f"scenario_{i}_detection", result.detection_score)

                except Exception as e:
                    logger.error(f"Scenario failed: {e}")
                    # Create failed result
                    ground_truth = scenario.get_ground_truth()
                    results.append(
                        build_evaluation_result(
                            evaluation_id=f"eval-failed-{uuid.uuid4().hex[:8]}",
                            state=None,
                            ground_truth=ground_truth,
                            alert_fired=False,
                            model=self.model,
                            error=str(e),
                        )
                    )

            # Build dataset result
            dataset_result = DatasetEvaluationResult(
                dataset_name=dataset.name,
                results=results,
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

    async def _poll_for_alert(
        self,
        target_ip: str,
        operation_id: str,
        timeout_seconds: int = 60,
    ) -> dict[str, Any] | None:
        """Poll Grafana for an alert related to the red team operation.

        Args:
            target_ip: Target IP to look for in alerts.
            operation_id: Operation ID to match.
            timeout_seconds: How long to wait.

        Returns:
            Alert dict if found, None otherwise.
        """
        from ares.tools.blue import GrafanaTools

        grafana = GrafanaTools(
            base_url=self.grafana_url,
            api_key=self.grafana_api_key,
        )

        start_time = time.time()
        poll_interval = 5  # seconds

        while time.time() - start_time < timeout_seconds:
            try:
                alerts = await grafana.get_firing_alerts()

                for alert in alerts:
                    # Check if alert matches our target
                    labels = alert.get("labels", {})
                    annotations = alert.get("annotations", {})

                    # Match by target IP
                    if labels.get("instance") == target_ip:
                        return alert
                    if target_ip in str(annotations):
                        return alert

                    # Match by operation ID (if included in alert)
                    if operation_id in str(labels) or operation_id in str(annotations):
                        return alert

            except Exception as e:
                logger.warning(f"Alert poll error: {e}")

            await _async_sleep(poll_interval)

        return None

    async def _run_investigation(self, alert: dict[str, Any]) -> InvestigationState:
        """Run a blue team investigation for an alert.

        Args:
            alert: Grafana alert dictionary.

        Returns:
            InvestigationState after investigation completes.
        """
        from ares.agents.blue import InvestigationOrchestrator
        from ares.integrations.mitre import MITREAttackClient

        # Load MITRE data
        mitre_client = MITREAttackClient()
        await mitre_client.load()

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

        return state

    def _save_dataset_results(self, result: DatasetEvaluationResult) -> Path:
        """Save dataset evaluation results to JSON file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"dataset_{result.dataset_name}_{timestamp}.json"
        filepath = self.output_dir / filename

        filepath.write_text(json.dumps(result.to_dict(), indent=2, default=str))
        logger.info(f"Results saved: {filepath}")

        return filepath


def _deserialize_red_state(data: dict[str, Any]) -> RedTeamState | SharedRedTeamState:
    """Deserialize red team state from JSON data.

    Uses SharedRedTeamState.from_bytes() for multi-agent state (preferred),
    falls back to manual construction for single-agent RedTeamState.
    """
    from ares.core.models import (
        Credential,
        Hash,
        Host,
        Target,
        User,
    )

    # Check if it's SharedRedTeamState or RedTeamState
    if "all_credentials" in data:
        # SharedRedTeamState - use the proper from_bytes() method
        # which handles all fields including newer ones
        return SharedRedTeamState.from_bytes(json.dumps(data).encode("utf-8"))

    # RedTeamState - manual construction (no from_bytes method)
    target = Target.model_validate(data.get("target", {"ip": ""}))

    return RedTeamState(
        operation_id=data.get("operation_id", ""),
        target=target,
        hosts=[Host.model_validate(h) for h in data.get("hosts", [])],
        users=[User.model_validate(u) for u in data.get("users", [])],
        credentials=[Credential.model_validate(c) for c in data.get("credentials", [])],
        hashes=[Hash.model_validate(h) for h in data.get("hashes", [])],
        has_domain_admin=data.get("has_domain_admin", False),
        has_golden_ticket=data.get("has_golden_ticket", False),
        identified_techniques=set(data.get("identified_techniques", [])),
    )


async def _async_sleep(seconds: float) -> None:
    """Async sleep helper."""
    import asyncio

    await asyncio.sleep(seconds)
