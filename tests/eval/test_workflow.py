"""Tests for evaluation workflow with multi-agent support."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.eval.workflow import EvaluationRunner


class TestEvaluationRunnerInit:
    """Tests for EvaluationRunner initialization."""

    def test_default_values(self, tmp_path: Path):
        """Test EvaluationRunner has correct default values."""
        runner = EvaluationRunner(
            model="test-model",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            output_dir=tmp_path,
        )
        assert runner.model == "test-model"
        assert runner.grafana_url == "http://grafana:3000"
        assert runner.grafana_api_key == "test-key"  # pragma: allowlist secret
        assert runner.max_steps == 150
        assert runner.inject_synthetic_alerts is False
        # Multi-agent defaults
        assert runner.multi_agent is False
        assert runner.redis_url == ""

    def test_multi_agent_configuration(self, tmp_path: Path):
        """Test EvaluationRunner accepts multi-agent configuration."""
        runner = EvaluationRunner(
            model="test-model",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            output_dir=tmp_path,
            multi_agent=True,
            redis_url="redis://localhost:6379",
        )
        assert runner.multi_agent is True
        assert runner.redis_url == "redis://localhost:6379"

    def test_creates_output_directory(self, tmp_path: Path):
        """Test EvaluationRunner creates output directory if needed."""
        output_dir = tmp_path / "nested" / "output"
        runner = EvaluationRunner(
            model="test-model",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            output_dir=output_dir,
        )
        assert output_dir.exists()
        assert runner.output_dir == output_dir


class TestEvaluationRunnerMultiAgent:
    """Tests for multi-agent investigation execution."""

    @pytest.mark.asyncio
    async def test_run_investigation_monolithic(self, tmp_path: Path):
        """Test _run_investigation uses monolithic orchestrator by default."""
        runner = EvaluationRunner(
            model="test-model",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            output_dir=tmp_path,
            multi_agent=False,
        )

        with (
            patch("ares.eval.workflow.EvaluationRunner._get_mitre_client") as mock_get_mitre,
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_orch_class,
        ):
            mock_mitre = MagicMock()
            mock_get_mitre.return_value = mock_mitre

            mock_state = MagicMock()
            mock_orchestrator = MagicMock()
            mock_orchestrator.investigate = AsyncMock(return_value={"state": mock_state})
            mock_orch_class.return_value = mock_orchestrator

            alert = {"labels": {"alertname": "TestAlert"}}
            state, _orch = await runner._run_investigation(alert)

            # Verify monolithic orchestrator was used
            mock_orch_class.assert_called_once()
            assert state == mock_state

    @pytest.mark.asyncio
    async def test_run_investigation_multi_agent(self, tmp_path: Path):
        """Test _run_investigation uses multi-agent orchestrator when configured."""
        runner = EvaluationRunner(
            model="test-model",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            output_dir=tmp_path,
            multi_agent=True,
            redis_url="redis://localhost:6379",
        )

        with (
            patch("ares.eval.workflow.EvaluationRunner._get_mitre_client") as mock_get_mitre,
            patch(
                "ares.agents.blue.multi_agent_orchestrator.BlueTeamOrchestrator"
            ) as mock_orch_class,
        ):
            mock_mitre = MagicMock()
            mock_get_mitre.return_value = mock_mitre

            mock_state = MagicMock()
            mock_orchestrator = MagicMock()
            mock_orchestrator.investigate = AsyncMock(return_value={"state": mock_state})
            mock_orch_class.return_value = mock_orchestrator

            alert = {"labels": {"alertname": "TestAlert"}}
            state, _orch = await runner._run_investigation(alert)

            # Verify multi-agent orchestrator was used
            mock_orch_class.assert_called_once()
            # Verify redis_url was passed
            call_kwargs = mock_orch_class.call_args[1]
            assert call_kwargs["redis_url"] == "redis://localhost:6379"
            assert state == mock_state

    @pytest.mark.asyncio
    async def test_run_investigation_multi_agent_requires_redis(self, tmp_path: Path):
        """Test _run_investigation raises error when multi-agent lacks redis_url."""
        runner = EvaluationRunner(
            model="test-model",
            grafana_url="http://grafana:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            output_dir=tmp_path,
            multi_agent=True,
            redis_url="",  # Missing redis_url
        )

        with patch("ares.eval.workflow.EvaluationRunner._get_mitre_client") as mock_get_mitre:
            mock_mitre = MagicMock()
            mock_get_mitre.return_value = mock_mitre

            alert = {"labels": {"alertname": "TestAlert"}}

            with pytest.raises(RuntimeError, match="Multi-agent mode requires redis_url"):
                await runner._run_investigation(alert)


class TestEvaluationRunnerHighSeverityLevels:
    """Tests for HIGH_SEVERITY_LEVELS constant in EvaluationRunner."""

    def test_high_severity_levels_exists(self, tmp_path: Path):
        """Test EvaluationRunner has HIGH_SEVERITY_LEVELS class attribute."""
        assert hasattr(EvaluationRunner, "HIGH_SEVERITY_LEVELS")
        assert "critical" in EvaluationRunner.HIGH_SEVERITY_LEVELS
        assert "high" in EvaluationRunner.HIGH_SEVERITY_LEVELS
        assert "medium" not in EvaluationRunner.HIGH_SEVERITY_LEVELS
