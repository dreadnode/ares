"""Tests for blue dispatcher publishing mixin."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from ares.core.blue_dispatcher.publishing import BluePublishingMixin


class PublishingHarness(BluePublishingMixin):
    """Concrete harness for BluePublishingMixin tests."""

    def __init__(self, backend: AsyncMock) -> None:
        self._backend = backend


@pytest.mark.asyncio
async def test_publish_evidence_adds_source_and_logs_when_new() -> None:
    """Publishing evidence stores the source agent and emits a debug log for new evidence."""
    backend = AsyncMock()
    backend.add_evidence.return_value = True
    harness = PublishingHarness(backend)
    evidence = {"type": "ip", "value": "10.0.0.5"}

    with patch("ares.core.blue_dispatcher.publishing.logger.debug", autospec=True) as debug_mock:
        result = await harness.publish_evidence(evidence, source_agent="triage-agent")

    assert result is True
    assert evidence["source_agent"] == "triage-agent"
    backend.add_evidence.assert_awaited_once_with(evidence)
    debug_mock.assert_called_once()
    assert "Published evidence: ip=10.0.0.5" in debug_mock.call_args.args[0]


@pytest.mark.asyncio
async def test_publish_evidence_skips_source_update_and_logging_for_duplicates() -> None:
    """Duplicate evidence returns false and does not log a publish message."""
    backend = AsyncMock()
    backend.add_evidence.return_value = False
    harness = PublishingHarness(backend)
    evidence = {"type": "domain", "value": "example.com"}

    with patch("ares.core.blue_dispatcher.publishing.logger.debug", autospec=True) as debug_mock:
        result = await harness.publish_evidence(evidence)

    assert result is False
    assert "source_agent" not in evidence
    backend.add_evidence.assert_awaited_once_with(evidence)
    debug_mock.assert_not_called()


@pytest.mark.asyncio
async def test_publish_timeline_event_sets_source_agent_and_truncates_description() -> None:
    """Timeline publishing annotates the source agent and logs a shortened description."""
    backend = AsyncMock()
    harness = PublishingHarness(backend)
    event = {"description": "A" * 70}

    with patch("ares.core.blue_dispatcher.publishing.logger.debug", autospec=True) as debug_mock:
        await harness.publish_timeline_event(event, source_agent="hunter")

    assert event["source_agent"] == "hunter"
    backend.add_timeline_event.assert_awaited_once_with(event)
    debug_message = debug_mock.call_args.args[0]
    assert debug_message.startswith("Published timeline event: ")
    assert len(debug_message.split(": ", 1)[1]) == 50


@pytest.mark.asyncio
async def test_publish_technique_adds_tactic_only_when_present() -> None:
    """Technique publishing stores the tactic conditionally and always logs the technique."""
    backend = AsyncMock()
    harness = PublishingHarness(backend)

    with patch("ares.core.blue_dispatcher.publishing.logger.debug", autospec=True) as debug_mock:
        await harness.publish_technique("T1059", name="Command and Scripting Interpreter")
        await harness.publish_technique("T1078", name="Valid Accounts", tactic="initial-access")

    assert backend.add_technique.await_args_list[0].args == (
        "T1059",
        "Command and Scripting Interpreter",
    )
    assert backend.add_technique.await_args_list[1].args == ("T1078", "Valid Accounts")
    backend.add_tactic.assert_awaited_once_with("initial-access")
    assert debug_mock.call_count == 2


@pytest.mark.asyncio
async def test_publish_lateral_connection_tracks_normalized_hosts() -> None:
    """Lateral connection publishing stores connection details and normalizes tracked host names."""
    backend = AsyncMock()
    harness = PublishingHarness(backend)

    with patch("ares.core.blue_dispatcher.publishing.logger.debug", autospec=True) as debug_mock:
        await harness.publish_lateral_connection(
            source=" SRC01 ",
            destination="Dst02 ",
            connection_type="rdp",
            user="alice",
            mitre_technique="T1021",
        )

    backend.add_lateral_connection.assert_awaited_once_with(
        {
            "source": "src01",
            "destination": "dst02",
            "connection_type": "rdp",
            "user": "alice",
            "mitre_technique": "T1021",
        }
    )
    assert backend.track_host.await_args_list[0].args == ("src01",)
    assert backend.track_host.await_args_list[1].args == ("dst02",)
    debug_mock.assert_called_once()
