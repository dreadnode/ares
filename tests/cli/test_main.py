"""Tests for main.py entry point module."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.main import (
    HIGH_SEVERITY_LEVELS,
    Args,
    DreadnodeArgs,
    EvalArgs,
    _resolve_model,
    app,
    investigate_alert,
    main,
    should_use_multi_agent,
    version,
)


class TestArgsDataclass:
    """Tests for Args dataclass."""

    def test_default_values(self):
        """Test Args has correct default values."""
        args = Args()
        assert args.model == ""
        assert args.grafana_url == "https://grafana.dev.plundr.ai"
        assert args.grafana_api_key == ""
        assert args.poll_interval == 30
        assert args.max_steps == 150
        assert args.report_dir == "./reports"
        assert args.once is False

    def test_custom_values(self):
        """Test Args accepts custom values."""
        args = Args(
            model="custom-model",
            grafana_url="http://localhost:3000",
            grafana_api_key="test-key",  # pragma: allowlist secret
            poll_interval=60,
            max_steps=50,
            report_dir="/tmp/reports",
            once=True,
        )
        assert args.model == "custom-model"
        assert args.grafana_url == "http://localhost:3000"
        assert args.grafana_api_key == "test-key"  # pragma: allowlist secret
        assert args.poll_interval == 60
        assert args.max_steps == 50
        assert args.report_dir == "/tmp/reports"
        assert args.once is True


class TestDreadnodeArgsDataclass:
    """Tests for DreadnodeArgs dataclass."""

    def test_default_values(self):
        """Test DreadnodeArgs has correct default values."""
        dn_args = DreadnodeArgs()
        assert dn_args.server == "https://platform.dev.plundr.ai/"
        assert dn_args.token == ""
        assert dn_args.organization == "ares"
        assert dn_args.workspace == "ares-protocol"
        assert dn_args.project == "ares-soc"
        assert dn_args.console is True

    def test_custom_values(self):
        """Test DreadnodeArgs accepts custom values."""
        dn_args = DreadnodeArgs(
            server="https://custom.server.com/",
            token="custom-token",
            organization="custom-org",
            workspace="custom-workspace",
            project="custom-project",
            console=False,
        )
        assert dn_args.server == "https://custom.server.com/"
        assert dn_args.token == "custom-token"
        assert dn_args.organization == "custom-org"
        assert dn_args.workspace == "custom-workspace"
        assert dn_args.project == "custom-project"
        assert dn_args.console is False


class TestVersionCommand:
    """Tests for version command."""

    def test_version_returns_none(self):
        """Test version command runs without error."""
        # version() is empty but should not raise
        result = version()
        assert result is None


class TestResolveModel:
    """Tests for model resolution helper."""

    def test_prefers_cli_model(self):
        """CLI model should override environment defaults."""
        with patch.dict("os.environ", {"ARES_MODEL": "env-model"}):
            assert _resolve_model("cli-model") == "cli-model"

    def test_uses_ares_model_by_default(self):
        """ARES_MODEL should be used when CLI model is empty."""
        with patch.dict("os.environ", {"ARES_MODEL": "env-model"}):
            assert _resolve_model("") == "env-model"

    def test_prefers_orchestrator_model_when_requested(self):
        """ARES_ORCHESTRATOR_MODEL should win when prefer_orchestrator=True."""
        with patch.dict(
            "os.environ",
            {"ARES_ORCHESTRATOR_MODEL": "orch-model", "ARES_MODEL": "env-model"},
        ):
            assert _resolve_model("", prefer_orchestrator=True) == "orch-model"

    def test_falls_back_to_ares_model_for_orchestrator(self):
        """Orchestrator model should fall back to ARES_MODEL."""
        with patch.dict("os.environ", {"ARES_MODEL": "env-model"}):
            assert _resolve_model("", prefer_orchestrator=True) == "env-model"


class TestMainFunction:
    """Tests for main() function."""

    @pytest.mark.asyncio
    async def test_main_once_mode_no_alerts(self, tmp_path: Path):
        """Test main in --once mode with no alerts."""
        with (
            patch("ares.main.dn.configure"),
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_orchestrator_class,
            patch("ares.tools.blue.GrafanaTools") as mock_grafana_class,
            patch("ares.integrations.mitre.MITREAttackClient") as mock_mitre_class,
            patch("ares.core.alert_correlation.AlertCorrelator") as mock_correlator_class,
        ):
            # Setup mocks
            mock_mitre = MagicMock()
            mock_mitre.load = AsyncMock()
            mock_mitre._techniques = {}
            mock_mitre._tactics = {}
            mock_mitre_class.return_value = mock_mitre

            mock_grafana = MagicMock()
            mock_grafana.get_firing_alerts = AsyncMock(return_value=[])
            mock_grafana_class.return_value = mock_grafana

            mock_orchestrator = MagicMock()
            mock_orchestrator._shutdown_mcp = AsyncMock()
            mock_orchestrator_class.return_value = mock_orchestrator

            mock_correlator = MagicMock()
            mock_correlator_class.return_value = mock_correlator

            args = Args(
                model="test-model",
                once=True,
                report_dir=str(tmp_path),
            )

            await main(args=args)

            # Verify MITRE client was loaded
            mock_mitre.load.assert_called_once()

            # Verify cleanup was called
            mock_orchestrator._shutdown_mcp.assert_called_once()

    @pytest.mark.asyncio
    async def test_main_processes_alerts(self, tmp_path: Path):
        """Test main processes alerts in --once mode with monolithic orchestrator."""
        with (
            patch("ares.main.dn.configure"),
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_orchestrator_class,
            patch("ares.tools.blue.GrafanaTools") as mock_grafana_class,
            patch("ares.integrations.mitre.MITREAttackClient") as mock_mitre_class,
            patch("ares.core.alert_correlation.AlertCorrelator") as mock_correlator_class,
        ):
            # Setup mocks
            mock_mitre = MagicMock()
            mock_mitre.load = AsyncMock()
            mock_mitre._techniques = {}
            mock_mitre._tactics = {}
            mock_mitre_class.return_value = mock_mitre

            test_alert = {
                "fingerprint": "test-fp-001",
                "labels": {"alertname": "TestAlert", "severity": "critical"},
            }
            mock_grafana = MagicMock()
            mock_grafana.get_firing_alerts = AsyncMock(return_value=[test_alert])
            mock_grafana_class.return_value = mock_grafana

            mock_orchestrator = MagicMock()
            mock_orchestrator._shutdown_mcp = AsyncMock()
            mock_orchestrator.investigate = AsyncMock(
                return_value={
                    "status": "completed",
                    "evidence_count": 5,
                    "techniques_identified": ["T1003"],
                    "highest_pyramid_level": 4,
                }
            )
            mock_orchestrator_class.return_value = mock_orchestrator

            mock_cluster = MagicMock()
            mock_cluster.cluster_id = "cluster-001"
            mock_correlator = MagicMock()
            mock_correlator.add_alert.return_value = mock_cluster
            mock_correlator.get_cluster_context.return_value = {"related_alerts": 0}
            mock_correlator_class.return_value = mock_correlator

            # Disable auto_route to test monolithic path
            args = Args(
                model="test-model",
                once=True,
                report_dir=str(tmp_path),
                auto_route=False,
            )

            await main(args=args)

            # Verify investigation was called
            mock_orchestrator.investigate.assert_called_once()

    @pytest.mark.asyncio
    async def test_main_skips_infrastructure_alerts(self, tmp_path: Path):
        """Test main skips infrastructure alerts like DatasourceNoData."""
        with (
            patch("ares.main.dn.configure"),
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_orchestrator_class,
            patch("ares.tools.blue.GrafanaTools") as mock_grafana_class,
            patch("ares.integrations.mitre.MITREAttackClient") as mock_mitre_class,
            patch("ares.core.alert_correlation.AlertCorrelator") as mock_correlator_class,
        ):
            mock_mitre = MagicMock()
            mock_mitre.load = AsyncMock()
            mock_mitre._techniques = {}
            mock_mitre._tactics = {}
            mock_mitre_class.return_value = mock_mitre

            # Infrastructure alert that should be skipped
            infra_alert = {
                "fingerprint": "infra-fp-001",
                "labels": {"alertname": "DatasourceNoData", "severity": "high"},
            }
            mock_grafana = MagicMock()
            mock_grafana.get_firing_alerts = AsyncMock(return_value=[infra_alert])
            mock_grafana_class.return_value = mock_grafana

            mock_orchestrator = MagicMock()
            mock_orchestrator._shutdown_mcp = AsyncMock()
            mock_orchestrator.investigate = AsyncMock()
            mock_orchestrator_class.return_value = mock_orchestrator

            mock_correlator = MagicMock()
            mock_correlator_class.return_value = mock_correlator

            args = Args(
                model="test-model",
                once=True,
                report_dir=str(tmp_path),
            )

            await main(args=args)

            # Verify investigation was NOT called for infrastructure alert
            mock_orchestrator.investigate.assert_not_called()


class TestInvestigateAlertCommand:
    """Tests for investigate_alert command."""

    @pytest.mark.asyncio
    async def test_investigate_alert_json_string(self, tmp_path: Path):
        """Test investigate_alert with JSON string input."""
        with (
            patch("ares.main.dn.configure"),
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_orchestrator_class,
            patch("ares.integrations.mitre.MITREAttackClient") as mock_mitre_class,
        ):
            mock_mitre = MagicMock()
            mock_mitre.load = AsyncMock()
            mock_mitre_class.return_value = mock_mitre

            mock_orchestrator = MagicMock()
            mock_orchestrator.investigate = AsyncMock(
                return_value={
                    "status": "completed",
                    "evidence_count": 5,
                    "techniques_identified": ["T1003"],
                    "highest_pyramid_level": 4,
                }
            )
            mock_orchestrator_class.return_value = mock_orchestrator

            alert_json = json.dumps({"labels": {"alertname": "TestAlert"}})
            args = Args(model="test-model", report_dir=str(tmp_path))

            await investigate_alert(alert_json, args=args)

            mock_orchestrator.investigate.assert_called_once()

    @pytest.mark.asyncio
    async def test_investigate_alert_file_path(self, tmp_path: Path):
        """Test investigate_alert with file path input."""
        # Create alert file
        alert_file = tmp_path / "alert.json"
        alert_data = {"labels": {"alertname": "FileAlert"}}
        alert_file.write_text(json.dumps(alert_data))

        with (
            patch("ares.main.dn.configure"),
            patch("ares.agents.blue.InvestigationOrchestrator") as mock_orchestrator_class,
            patch("ares.integrations.mitre.MITREAttackClient") as mock_mitre_class,
        ):
            mock_mitre = MagicMock()
            mock_mitre.load = AsyncMock()
            mock_mitre_class.return_value = mock_mitre

            mock_orchestrator = MagicMock()
            mock_orchestrator.investigate = AsyncMock(
                return_value={
                    "status": "completed",
                    "evidence_count": 5,
                    "techniques_identified": ["T1003"],
                    "highest_pyramid_level": 4,
                }
            )
            mock_orchestrator_class.return_value = mock_orchestrator

            args = Args(model="test-model", report_dir=str(tmp_path))

            await investigate_alert(str(alert_file), args=args)

            mock_orchestrator.investigate.assert_called_once()


class TestAppObject:
    """Tests for the cyclopts app object."""

    def test_app_name(self):
        """Test app has correct name."""
        # cyclopts App name is stored as a tuple
        assert "ares" in app.name

    def test_app_help_text(self):
        """Test app has help text."""
        assert "Autonomous SOC Investigation Agent" in app.help


class TestEvalArgsDataclass:
    """Tests for EvalArgs dataclass with multi-agent support."""

    def test_default_values(self):
        """Test EvalArgs has correct default values."""
        eval_args = EvalArgs()
        assert eval_args.output_dir == "./eval_results"
        assert eval_args.poll_timeout == 60
        assert eval_args.ci is False
        assert eval_args.synthetic is False
        assert eval_args.min_score == 0.5
        assert eval_args.min_ioc_rate == 0.5
        assert eval_args.min_technique_rate == 0.5
        assert eval_args.parallel == 1
        # New multi-agent fields
        assert eval_args.multi_agent is False
        assert eval_args.redis_url == ""

    def test_multi_agent_values(self):
        """Test EvalArgs accepts multi-agent configuration."""
        eval_args = EvalArgs(
            multi_agent=True,
            redis_url="redis://localhost:6379",
        )
        assert eval_args.multi_agent is True
        assert eval_args.redis_url == "redis://localhost:6379"


class TestShouldUseMultiAgent:
    """Tests for severity-based multi-agent routing."""

    def test_critical_severity_uses_multi_agent(self):
        """Critical severity should use multi-agent."""
        assert should_use_multi_agent("critical") is True
        assert should_use_multi_agent("CRITICAL") is True
        assert should_use_multi_agent("Critical") is True

    def test_high_severity_uses_multi_agent(self):
        """High severity should use multi-agent."""
        assert should_use_multi_agent("high") is True
        assert should_use_multi_agent("HIGH") is True
        assert should_use_multi_agent("High") is True

    def test_medium_severity_uses_monolithic(self):
        """Medium severity should use monolithic."""
        assert should_use_multi_agent("medium") is False
        assert should_use_multi_agent("MEDIUM") is False

    def test_low_severity_uses_monolithic(self):
        """Low severity should use monolithic."""
        assert should_use_multi_agent("low") is False
        assert should_use_multi_agent("LOW") is False

    def test_unknown_severity_uses_monolithic(self):
        """Unknown severity should use monolithic."""
        assert should_use_multi_agent("warning") is False
        assert should_use_multi_agent("info") is False
        assert should_use_multi_agent("") is False

    def test_force_multi_agent_overrides_severity(self):
        """force_multi_agent=True should always use multi-agent."""
        assert should_use_multi_agent("low", force_multi_agent=True) is True
        assert should_use_multi_agent("medium", force_multi_agent=True) is True
        assert should_use_multi_agent("high", force_multi_agent=True) is True
        assert should_use_multi_agent("critical", force_multi_agent=True) is True


class TestHighSeverityLevels:
    """Tests for HIGH_SEVERITY_LEVELS constant."""

    def test_contains_critical(self):
        """HIGH_SEVERITY_LEVELS should contain 'critical'."""
        assert "critical" in HIGH_SEVERITY_LEVELS

    def test_contains_high(self):
        """HIGH_SEVERITY_LEVELS should contain 'high'."""
        assert "high" in HIGH_SEVERITY_LEVELS

    def test_does_not_contain_medium(self):
        """HIGH_SEVERITY_LEVELS should not contain 'medium'."""
        assert "medium" not in HIGH_SEVERITY_LEVELS

    def test_does_not_contain_low(self):
        """HIGH_SEVERITY_LEVELS should not contain 'low'."""
        assert "low" not in HIGH_SEVERITY_LEVELS

    def test_is_frozenset(self):
        """HIGH_SEVERITY_LEVELS should be a frozenset for immutability."""
        assert isinstance(HIGH_SEVERITY_LEVELS, frozenset)
