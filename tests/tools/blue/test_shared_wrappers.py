"""Tests for shared investigation wrapper tools."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.models import PyramidLevel
from ares.tools.blue.shared_wrappers import SharedInvestigationTools


@pytest.fixture
def shared_tools() -> SharedInvestigationTools:
    """Create shared investigation tools instance."""
    return SharedInvestigationTools()


@pytest.fixture
def backend() -> AsyncMock:
    """Create async backend mock."""
    return AsyncMock()


class TestSharedInvestigationToolsRecordEvidence:
    """Tests for shared evidence recording helpers."""

    @pytest.mark.asyncio
    async def test_record_evidence_requires_backend(
        self, shared_tools: SharedInvestigationTools
    ) -> None:
        """record_evidence reports a configuration error when no backend is set."""
        result = await shared_tools.record_evidence(
            evidence_type="ip",
            value="10.0.0.5",
            source="query",
            timestamp=None,
            pyramid_level=2,
        )

        assert result == "ERROR: No backend configured"

    @pytest.mark.asyncio
    async def test_record_evidence_returns_dedup_message_for_existing_evidence(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """Duplicate evidence returns the informational dedup response."""
        shared_tools.set_backend(backend)
        backend.add_evidence.return_value = False

        with (
            patch(
                "ares.tools.blue.shared_wrappers.validate_evidence_value",
                autospec=True,
                return_value=(True, "query-1"),
            ),
            patch(
                "ares.tools.blue.shared_wrappers.adjust_confidence_for_validation",
                autospec=True,
                return_value=0.8,
            ),
            patch("ares.tools.blue.shared_wrappers.dn.log_metric", autospec=True),
        ):
            result = await shared_tools.record_evidence(
                evidence_type="domain",
                value="example.com",
                source="hunt",
                timestamp="2024-01-01T00:00:00Z",
                pyramid_level=3,
            )

        assert result.endswith("Evidence already recorded (dedup): domain=example.com")
        backend.add_evidence.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_record_evidence_tracks_techniques_and_formats_success_response(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """New evidence records tactics and includes techniques in the success response."""
        shared_tools.set_backend(backend)
        shared_tools.set_mitre_client(
            SimpleNamespace(
                get_technique=lambda _technique_id: SimpleNamespace(
                    name="Command and Scripting Interpreter",
                    tactic="execution",
                )
            )
        )
        backend.add_evidence.return_value = True

        with (
            patch(
                "ares.tools.blue.shared_wrappers.validate_evidence_value",
                autospec=True,
                return_value=(False, "query-99"),
            ),
            patch(
                "ares.tools.blue.shared_wrappers.adjust_confidence_for_validation",
                autospec=True,
                return_value=0.25,
            ),
            patch("ares.tools.blue.shared_wrappers.dn.log_metric", autospec=True) as metric_mock,
        ):
            result = await shared_tools.record_evidence(
                evidence_type="tool",
                value="mimikatz.exe",
                source="endpoint",
                timestamp="invalid",
                pyramid_level=10,
                mitre_techniques=["T1059"],
                confidence=0.6,
            )

        stored_payload = backend.add_evidence.await_args.args[0]
        assert stored_payload["type"] == "tool"
        assert stored_payload["value"] == "mimikatz.exe"
        assert stored_payload["pyramid_level"] == PyramidLevel.TTPS.value
        assert stored_payload["validated"] is False
        assert stored_payload["source_query_id"] == "query-99"
        backend.add_tactic.assert_awaited_once_with("execution")
        backend.add_technique.assert_awaited_once_with("T1059", "Command and Scripting Interpreter")
        assert metric_mock.call_count == 2
        assert "Recorded evidence: ev-0001" in result
        assert "Techniques: T1059" in result
        assert "UNVALIDATED - confidence reduced" in result


class TestSharedInvestigationToolsTimelineAndTracking:
    """Tests for timeline and entity tracking methods."""

    @pytest.mark.asyncio
    async def test_add_timeline_event_uses_fallback_timestamp_on_invalid_input(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """Invalid timeline timestamps fall back to current UTC time."""
        shared_tools.set_backend(backend)

        with (
            patch("ares.tools.blue.shared_wrappers.dn.log_metric", autospec=True),
            patch("ares.tools.blue.shared_wrappers.logger.info", autospec=True),
        ):
            event_id = await shared_tools.add_timeline_event(
                timestamp="not-a-timestamp",
                description="Observed suspicious process tree",
                evidence_ids=["ev-1"],
            )

        stored_event = backend.add_timeline_event.await_args.args[0]
        assert event_id == "tl-0001"
        assert stored_event["id"] == "tl-0001"
        assert stored_event["description"] == "Observed suspicious process tree"
        assert stored_event["evidence_ids"] == ["ev-1"]
        assert stored_event["timestamp"].endswith("Z")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("method_name", "input_value", "expected_call", "expected_message"),
        [
            pytest.param(
                "track_host_investigation",
                " HOST01 ",
                "host01",
                "Tracking host:  HOST01 ",
                id="host",
            ),
            pytest.param(
                "track_user_investigation",
                " Alice ",
                "alice",
                "Tracking user:  Alice ",
                id="user",
            ),
        ],
    )
    async def test_tracking_methods_normalize_values(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
        method_name: str,
        input_value: str,
        expected_call: str,
        expected_message: str,
    ) -> None:
        """Tracking methods lower-case and trim identifiers before storing them."""
        shared_tools.set_backend(backend)

        result = await getattr(shared_tools, method_name)(input_value)

        track_mock = (
            backend.track_host if method_name == "track_host_investigation" else backend.track_user
        )
        track_mock.assert_awaited_once_with(expected_call)
        assert expected_message in result

    @pytest.mark.asyncio
    async def test_record_lateral_connection_requires_backend(
        self,
        shared_tools: SharedInvestigationTools,
    ) -> None:
        """record_lateral_connection reports configuration issues without a backend."""
        result = await shared_tools.record_lateral_connection("src", "dst", "smb")

        assert result == "ERROR: No backend configured"

    @pytest.mark.asyncio
    async def test_record_lateral_connection_tracks_both_hosts(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """Lateral connections are stored and both endpoints are tracked in normalized form."""
        shared_tools.set_backend(backend)

        with patch("ares.tools.blue.shared_wrappers.logger.info", autospec=True):
            result = await shared_tools.record_lateral_connection(
                source=" SRC01 ",
                destination="Dst02 ",
                connection_type="wmi",
                user="alice",
                mitre_technique="T1047",
            )

        backend.add_lateral_connection.assert_awaited_once_with(
            {
                "source": "src01",
                "destination": "dst02",
                "connection_type": "wmi",
                "user": "alice",
                "mitre_technique": "T1047",
            }
        )
        assert backend.track_host.await_args_list[0].args == ("src01",)
        assert backend.track_host.await_args_list[1].args == ("dst02",)
        assert "Recorded lateral connection:" in result


class TestSharedInvestigationToolsReadHelpers:
    """Tests for shared read/query helper methods."""

    @pytest.mark.asyncio
    async def test_read_helpers_require_backend(
        self, shared_tools: SharedInvestigationTools
    ) -> None:
        """Read helper methods return error payloads when backend is missing."""
        summary = await shared_tools.get_investigation_summary()
        queued = await shared_tools.get_queued_queries()
        correlated = await shared_tools.get_correlated_alerts()

        assert summary == {"error": "No backend configured"}
        assert queued == {"error": "No backend configured"}
        assert correlated == {"error": "No backend configured"}

    @pytest.mark.asyncio
    async def test_get_investigation_summary_and_queue_views_use_snapshot(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """Snapshot-backed read helpers expose investigation and queue summaries."""
        shared_tools.set_backend(backend)
        backend.snapshot.return_value = {
            "investigation_id": "inv-77",
            "meta": {"stage": "causation"},
            "evidence": [{"pyramid_level": 2}, {"pyramid_level": 5}],
            "timeline": [{"id": "tl-1"}],
            "techniques": {"T1078"},
            "hosts": {"host1"},
            "users": {"user1"},
            "pending_tasks": {"a": {}},
            "completed_tasks": {"b": {}, "c": {}},
            "pivot_queue": [1, 2],
            "chain_queue": [3],
        }

        summary = await shared_tools.get_investigation_summary()
        queued = await shared_tools.get_queued_queries()

        assert summary == {
            "investigation_id": "inv-77",
            "stage": "causation",
            "evidence_count": 2,
            "timeline_events": 1,
            "techniques_identified": ["T1078"],
            "highest_pyramid_level": 5,
            "hosts_investigated": ["host1"],
            "users_investigated": ["user1"],
            "pending_tasks": 1,
            "completed_tasks": 2,
        }
        assert queued == {
            "queued_pivot_queries": [1, 2],
            "queued_chain_queries": [3],
            "total_queued": 3,
        }

    @pytest.mark.asyncio
    async def test_get_correlated_alerts_prefers_meta_but_has_default_message(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """Correlation helper returns backend metadata when present and a default message otherwise."""
        shared_tools.set_backend(backend)
        backend.get_meta.side_effect = [{"related_alerts": 4}, None]

        first = await shared_tools.get_correlated_alerts()
        second = await shared_tools.get_correlated_alerts()

        assert first == {"related_alerts": 4}
        assert second == {"related_alerts": 0, "message": "No correlation context available"}

    @pytest.mark.asyncio
    async def test_transition_stage_validates_stage_name(
        self,
        shared_tools: SharedInvestigationTools,
        backend: AsyncMock,
    ) -> None:
        """Stage transitions reject unknown stages and persist valid transitions."""
        shared_tools.set_backend(backend)

        invalid = await shared_tools.transition_stage("bogus")

        with patch("ares.tools.blue.shared_wrappers.logger.info", autospec=True):
            valid = await shared_tools.transition_stage("lateral")

        assert invalid.startswith("ERROR: Invalid stage 'bogus'. Must be one of:")
        backend.set_meta.assert_awaited_once_with("stage", "lateral")
        assert "Transitioned to stage: lateral" in valid
