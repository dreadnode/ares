"""Tests for main.py entry point module."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.main import (
    HIGH_SEVERITY_LEVELS,
    Args,
    BlueWorkerArgs,
    DreadnodeArgs,
    EvalArgs,
    MultiAgentArgs,
    WorkerArgs,
    _resolve_model,
    app,
    blue_worker,
    discover_recent_completed_operation,
    discover_running_operation,
    get_operation_time_window,
    investigate_alert,
    main,
    merge_alerts,
    multi_agent,
    should_use_multi_agent,
    version,
    worker,
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


class TestAdditionalDataclasses:
    """Tests for other command dataclasses."""

    def test_worker_args_defaults(self):
        """Test WorkerArgs exposes expected default values."""
        worker_args = WorkerArgs()

        assert worker_args.role == ""
        assert worker_args.operation_id == ""
        assert worker_args.redis_url == ""
        assert worker_args.max_steps == 0

    def test_blue_worker_args_defaults(self):
        """Test BlueWorkerArgs exposes expected default values."""
        worker_args = BlueWorkerArgs()

        assert worker_args.role == ""
        assert worker_args.investigation_id == ""
        assert worker_args.grafana_url == ""

    def test_multi_agent_args_defaults(self):
        """Test MultiAgentArgs exposes expected default values."""
        multi_args = MultiAgentArgs()

        assert multi_args.target_domain == ""
        assert multi_args.target_ips == ""
        assert multi_args.initial_user == ""
        assert multi_args.namespace == ""


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


class TestRedisDiscoveryHelpers:
    """Tests for Redis-backed operation discovery helpers."""

    @pytest.mark.asyncio
    async def test_discover_running_operation_returns_first_operation_id(self):
        """Test running operation discovery returns the first parsed lock id."""
        client = AsyncMock()
        client.keys.return_value = ["ares:lock:op-123"]

        with patch(
            "ares.core.redis_client.create_verified_redis_client", AsyncMock(return_value=client)
        ):
            operation_id = await discover_running_operation("redis://example")

        assert operation_id == "op-123"
        client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_discover_running_operation_returns_none_on_client_error(self):
        """Test running operation discovery swallows Redis client failures."""
        with patch(
            "ares.core.redis_client.create_verified_redis_client",
            AsyncMock(side_effect=RuntimeError("redis down")),
        ):
            operation_id = await discover_running_operation("redis://example")

        assert operation_id is None

    @pytest.mark.asyncio
    async def test_discover_recent_completed_operation_prefers_latest_non_running_candidate(self):
        """Test recent completed operation discovery prefers newest eligible operation."""
        client = AsyncMock()
        client.keys.side_effect = [[], ["ares:op:old:meta", "ares:op:new:meta"]]
        client.hgetall.side_effect = [
            {"started_at": "2024-01-01T10:00:00+00:00"},
            {"started_at": "2024-01-01T12:00:00+00:00"},
        ]

        fake_now = datetime(2024, 1, 1, 13, 0, tzinfo=timezone.utc)

        with (
            patch(
                "ares.core.redis_client.create_verified_redis_client",
                AsyncMock(return_value=client),
            ),
            patch("ares.main.datetime") as mock_datetime,
        ):
            mock_datetime.now.return_value = fake_now
            mock_datetime.fromisoformat.side_effect = datetime.fromisoformat
            operation_id = await discover_recent_completed_operation(
                "redis://example", max_age_hours=24
            )

        assert operation_id == "new"
        client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_operation_time_window_returns_running_window(self):
        """Test operation time window uses now as end time for running operations."""
        client = AsyncMock()
        client.exists.return_value = 1
        client.hgetall.return_value = {"started_at": "2024-01-01T10:00:00+00:00"}
        fake_now = datetime(2024, 1, 1, 13, 0, tzinfo=timezone.utc)

        with (
            patch(
                "ares.core.redis_client.create_verified_redis_client",
                AsyncMock(return_value=client),
            ),
            patch("ares.main.datetime") as mock_datetime,
        ):
            mock_datetime.now.return_value = fake_now
            mock_datetime.fromisoformat.side_effect = datetime.fromisoformat
            window = await get_operation_time_window("redis://example", "op-123")

        assert window == (datetime.fromisoformat("2024-01-01T10:00:00+00:00"), fake_now, True)
        client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_operation_time_window_returns_none_for_invalid_start_time(self):
        """Test operation time window returns None for malformed metadata."""
        client = AsyncMock()
        client.exists.return_value = 0
        client.hgetall.return_value = {
            "started_at": "not-a-date",
            "completed_at": "2024-01-01T11:00:00+00:00",
        }

        with patch(
            "ares.core.redis_client.create_verified_redis_client", AsyncMock(return_value=client)
        ):
            window = await get_operation_time_window("redis://example", "op-123")

        assert window is None


class TestMainFunction:
    """Tests for main() function."""

    @pytest.mark.asyncio
    async def test_main_returns_early_when_model_missing(self, tmp_path: Path):
        """Test main exits before expensive setup when no model is configured."""
        with patch("ares.main.logger") as mock_logger:
            await main(args=Args(model="", once=True, report_dir=str(tmp_path)))

        mock_logger.error.assert_called_once()

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

            args = Args(model="test-model", once=True, report_dir=str(tmp_path))

            await main(args=args)

            mock_mitre.load.assert_called_once()
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

            args = Args(model="test-model", once=True, report_dir=str(tmp_path), auto_route=False)

            await main(args=args)

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

            args = Args(model="test-model", once=True, report_dir=str(tmp_path))

            await main(args=args)

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

    @pytest.mark.asyncio
    async def test_investigate_alert_requires_redis_for_forced_multi_agent(self, tmp_path: Path):
        """Test investigate_alert exits early when multi-agent is forced without Redis."""
        alert_json = json.dumps({"labels": {"alertname": "TestAlert", "severity": "critical"}})

        with (
            patch("ares.main.dn.configure"),
            patch("ares.integrations.mitre.MITREAttackClient") as mock_mitre_class,
            patch("ares.main.logger") as mock_logger,
            patch("ares.core.config.get_redis_url", return_value=""),
        ):
            mock_mitre = MagicMock()
            mock_mitre.load = AsyncMock()
            mock_mitre_class.return_value = mock_mitre

            await investigate_alert(
                alert_json,
                args=Args(model="test-model", report_dir=str(tmp_path), multi_agent=True),
            )

        mock_logger.error.assert_called()


class TestWorkerCommands:
    """Tests for worker command entry points."""

    @pytest.mark.asyncio
    async def test_worker_rejects_invalid_role(self):
        """Test worker returns early for invalid roles."""
        with patch("ares.main.logger") as mock_logger:
            await worker("bad-role")

        mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_worker_runs_with_discovered_defaults(self):
        """Test worker delegates to run_worker with mapped AgentRole."""
        config = MagicMock(redis_url="redis://example")
        agent_config = MagicMock(model="cfg-model", max_steps=42)
        run_worker_mock = AsyncMock()

        with (
            patch("ares.main.dn.configure"),
            patch("ares.core.config.load_config", return_value=config),
            patch("ares.core.config.get_agent_config", return_value=agent_config),
            patch("ares.core.worker.run_worker", run_worker_mock),
        ):
            await worker("recon", operation_id="op-1")

        run_worker_mock.assert_awaited_once()
        assert run_worker_mock.await_args.kwargs["operation_id"] == "op-1"

    @pytest.mark.asyncio
    async def test_blue_worker_normalizes_hyphenated_role(self):
        """Test blue_worker normalizes hyphenated role names before dispatch."""
        config = MagicMock(redis_url="redis://example")
        run_blue_worker_mock = AsyncMock()

        with (
            patch("ares.main.dn.configure"),
            patch("ares.core.config.load_config", return_value=config),
            patch("ares.core.blue_worker.run_blue_worker", run_blue_worker_mock),
            patch("ares.core.blue_worker.run_blue_global_worker", AsyncMock()),
        ):
            await blue_worker("threat-hunter", investigation_id="inv-1")

        run_blue_worker_mock.assert_awaited_once()
        assert run_blue_worker_mock.await_args.kwargs["investigation_id"] == "inv-1"

    @pytest.mark.asyncio
    async def test_blue_worker_uses_global_pool_when_enabled(self):
        """Test blue_worker calls global worker entry point when env flag is set."""
        config = MagicMock(redis_url="redis://example")
        run_global_mock = AsyncMock()

        with (
            patch.dict("os.environ", {"ARES_BLUE_GLOBAL_POOL": "true"}, clear=False),
            patch("ares.main.dn.configure"),
            patch("ares.core.config.load_config", return_value=config),
            patch("ares.core.blue_worker.run_blue_global_worker", run_global_mock),
            patch("ares.core.blue_worker.run_blue_worker", AsyncMock()),
        ):
            await blue_worker("triage", investigation_id="inv-1")

        run_global_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_multi_agent_returns_when_no_target_ips_present(self, tmp_path: Path):
        """Test multi_agent exits before orchestration if target IP list is empty."""
        config = MagicMock(redis_url="redis://example", namespace="default")

        with (
            patch("ares.main.dn.configure"),
            patch("ares.core.config.load_config", return_value=config),
            patch("ares.main.logger") as mock_logger,
        ):
            await multi_agent(
                "contoso.local",
                " , ",
                args=Args(model="test-model", report_dir=str(tmp_path)),
            )

        mock_logger.error.assert_called_once()


class TestAppObject:
    """Tests for the cyclopts app object."""

    def test_app_name(self):
        """Test app has correct name."""
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
        assert eval_args.multi_agent is False
        assert eval_args.redis_url == ""

    def test_multi_agent_values(self):
        """Test EvalArgs accepts multi-agent configuration."""
        eval_args = EvalArgs(multi_agent=True, redis_url="redis://localhost:6379")
        assert eval_args.multi_agent is True
        assert eval_args.redis_url == "redis://localhost:6379"


class TestShouldUseMultiAgent:
    """Tests for severity-based multi-agent routing."""

    @pytest.mark.parametrize(
        "severity",
        [
            pytest.param("critical", id="critical-lower"),
            pytest.param("CRITICAL", id="critical-upper"),
            pytest.param("Critical", id="critical-title"),
            pytest.param("high", id="high-lower"),
            pytest.param("HIGH", id="high-upper"),
            pytest.param("High", id="high-title"),
        ],
    )
    def test_high_severities_use_multi_agent(self, severity: str):
        """High and critical severities should route to multi-agent."""
        assert should_use_multi_agent(severity) is True

    @pytest.mark.parametrize(
        "severity",
        [
            pytest.param("medium", id="medium"),
            pytest.param("MEDIUM", id="medium-upper"),
            pytest.param("low", id="low"),
            pytest.param("LOW", id="low-upper"),
            pytest.param("warning", id="warning"),
            pytest.param("info", id="info"),
            pytest.param("", id="empty"),
        ],
    )
    def test_other_severities_use_monolithic(self, severity: str):
        """Non-high severities should stay on the single-agent path."""
        assert should_use_multi_agent(severity) is False

    @pytest.mark.parametrize(
        "severity",
        [
            pytest.param("low", id="low"),
            pytest.param("medium", id="medium"),
            pytest.param("high", id="high"),
            pytest.param("critical", id="critical"),
        ],
    )
    def test_force_multi_agent_overrides_severity(self, severity: str):
        """force_multi_agent=True should always use multi-agent."""
        assert should_use_multi_agent(severity, force_multi_agent=True) is True


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


class TestMergeAlerts:
    """Tests for merge_alerts function."""

    def test_merge_empty_lists(self):
        """Test merging two empty lists."""
        result = merge_alerts([], [])
        assert result == []

    def test_merge_firing_only(self):
        """Test with only firing alerts."""
        firing = [
            {"fingerprint": "fp-1", "labels": {"alertname": "Alert1"}},
            {"fingerprint": "fp-2", "labels": {"alertname": "Alert2"}},
        ]
        result = merge_alerts(firing, [])
        assert len(result) == 2
        assert result[0]["fingerprint"] == "fp-1"
        assert result[1]["fingerprint"] == "fp-2"

    def test_merge_historical_only(self):
        """Test with only historical alerts."""
        historical = [
            {"fingerprint": "fp-3", "labels": {"alertname": "Alert3"}},
            {"fingerprint": "fp-4", "labels": {"alertname": "Alert4"}},
        ]
        result = merge_alerts([], historical)
        assert len(result) == 2

    def test_merge_deduplicates_by_fingerprint(self):
        """Test that alerts with same fingerprint are deduplicated."""
        firing = [{"fingerprint": "fp-1", "labels": {"alertname": "Alert1-Firing"}}]
        historical = [
            {"fingerprint": "fp-1", "labels": {"alertname": "Alert1-Historical"}},
            {"fingerprint": "fp-2", "labels": {"alertname": "Alert2"}},
        ]
        result = merge_alerts(firing, historical)
        assert len(result) == 2
        assert result[0]["labels"]["alertname"] == "Alert1-Firing"
        assert result[1]["fingerprint"] == "fp-2"

    def test_merge_preserves_order(self):
        """Test that firing alerts appear before historical."""
        firing = [{"fingerprint": "fp-1", "labels": {"alertname": "Firing1"}}]
        historical = [{"fingerprint": "fp-2", "labels": {"alertname": "Historical1"}}]
        result = merge_alerts(firing, historical)
        assert result[0]["fingerprint"] == "fp-1"
        assert result[1]["fingerprint"] == "fp-2"

    def test_merge_skips_empty_fingerprints(self):
        """Test that alerts with empty fingerprints are skipped."""
        firing = [
            {"fingerprint": "", "labels": {"alertname": "NoFP"}},
            {"fingerprint": "fp-1", "labels": {"alertname": "WithFP"}},
        ]
        result = merge_alerts(firing, [])
        assert len(result) == 1
        assert result[0]["fingerprint"] == "fp-1"
