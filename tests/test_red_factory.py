"""Tests for red team agent factory module."""

import time
from unittest.mock import MagicMock

import pytest

from ares.core.factories.red_factory import (
    _should_log_event,
    _track_discovery,
    _track_exploitation,
    reset_event_tracking,
)


class TestEventTracking:
    """Tests for event tracking functions."""

    def setup_method(self):
        """Reset event tracking before each test."""
        reset_event_tracking()

    def test_reset_event_tracking(self):
        """Test resetting event tracking state."""
        # Trigger an event to set state
        assert _should_log_event("test_event") is True

        # Reset and verify it allows logging again
        reset_event_tracking()
        assert _should_log_event("test_event") is True

    def test_should_log_event_first_call(self):
        """Test that first event always logs."""
        assert _should_log_event("new_event") is True

    def test_should_log_event_debounce(self):
        """Test that rapid duplicate events are debounced."""
        # First call should pass
        assert _should_log_event("rapid_event") is True

        # Second call within debounce window should be blocked
        assert _should_log_event("rapid_event") is False

    def test_should_log_event_different_types(self):
        """Test that different event types are tracked independently."""
        assert _should_log_event("event_a") is True
        assert _should_log_event("event_b") is True

    def test_should_log_event_after_debounce_window(self):
        """Test that events log again after debounce window."""
        # First call
        assert _should_log_event("timed_event") is True

        # Simulate passage of time by manipulating the internal state
        # This is a bit hacky but tests the time-based logic
        from ares.core.factories import red_factory

        red_factory._last_event_times["timed_event"] = time.time() - 1.0

        # After debounce window, should log again
        assert _should_log_event("timed_event") is True


class TestVulnerabilityTracking:
    """Tests for vulnerability tracking functions."""

    def setup_method(self):
        """Reset tracking state before each test."""
        reset_event_tracking()

    def test_track_discovery_new_vuln(self):
        """Test tracking a new vulnerability."""
        from ares.core.factories import red_factory

        _track_discovery("test_vuln", "Test Vulnerability", "test_tool", 5)

        assert "test_vuln" in red_factory._discovered_vulnerabilities
        assert red_factory._discovered_vulnerabilities["test_vuln"]["type"] == "Test Vulnerability"
        assert red_factory._discovered_vulnerabilities["test_vuln"]["tool"] == "test_tool"
        assert red_factory._discovered_vulnerabilities["test_vuln"]["step"] == 5

    def test_track_discovery_duplicate_ignored(self):
        """Test that duplicate discoveries are ignored."""
        from ares.core.factories import red_factory

        _track_discovery("dupe_vuln", "First Type", "first_tool", 1)
        _track_discovery("dupe_vuln", "Second Type", "second_tool", 10)

        # Should keep the first discovery
        assert red_factory._discovered_vulnerabilities["dupe_vuln"]["type"] == "First Type"
        assert red_factory._discovered_vulnerabilities["dupe_vuln"]["step"] == 1

    def test_track_exploitation_known_tool(self):
        """Test tracking exploitation with a known tool."""
        from ares.core.factories import red_factory

        _track_exploitation("certipy_req_esc1")

        assert "esc1_adcs" in red_factory._exploited_vulnerabilities

    def test_track_exploitation_unknown_tool(self):
        """Test that unknown tools don't track anything."""
        from ares.core.factories import red_factory

        _track_exploitation("unknown_tool")

        assert len(red_factory._exploited_vulnerabilities) == 0

    def test_track_exploitation_duplicate_ignored(self):
        """Test that duplicate exploitations are idempotent."""
        from ares.core.factories import red_factory

        _track_exploitation("pywhisker")
        _track_exploitation("bloodyad_set_password")  # Same vuln type

        # Both map to acl_abuse, should only be added once
        assert "acl_abuse" in red_factory._exploited_vulnerabilities
        assert len(red_factory._exploited_vulnerabilities) == 1


class TestTrackVulnerabilityDiscoveries:
    """Tests for track_vulnerability_discoveries hook."""

    def setup_method(self):
        """Reset tracking state before each test."""
        reset_event_tracking()

    @pytest.mark.asyncio
    async def test_tracks_esc1_vulnerability(self):
        """Test ESC1 ADCS vulnerability is tracked."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = "ESC1 vulnerable template found - exploitable"
        event.tool_call = MagicMock()
        event.tool_call.name = "certipy_find"

        await track_vulnerability_discoveries(event)

        assert "esc1_adcs" in red_factory._discovered_vulnerabilities

    @pytest.mark.asyncio
    async def test_tracks_acl_abuse(self):
        """Test ACL abuse path is tracked."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = "GenericAll permission found on target"
        event.tool_call = MagicMock()
        event.tool_call.name = "run_bloodhound"

        await track_vulnerability_discoveries(event)

        assert "acl_abuse" in red_factory._discovered_vulnerabilities

    @pytest.mark.asyncio
    async def test_tracks_unconstrained_delegation(self):
        """Test unconstrained delegation is tracked."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = "Found unconstrained delegation on SERVER01"
        event.tool_call = MagicMock()
        event.tool_call.name = "find_delegation"

        await track_vulnerability_discoveries(event)

        assert "unconstrained_delegation" in red_factory._discovered_vulnerabilities

    @pytest.mark.asyncio
    async def test_tracks_mssql_impersonation(self):
        """Test MSSQL impersonation is tracked."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = "Can impersonate sa user"
        event.tool_call = MagicMock()
        event.tool_call.name = "mssql_login"

        await track_vulnerability_discoveries(event)

        assert "mssql_impersonation" in red_factory._discovered_vulnerabilities

    @pytest.mark.asyncio
    async def test_tracks_krbtgt_hash(self):
        """Test krbtgt hash discovery is tracked."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = "krbtgt:::aad3b435b51404ee"
        event.tool_call = MagicMock()
        event.tool_call.name = "secretsdump"

        await track_vulnerability_discoveries(event)

        assert "krbtgt_hash" in red_factory._discovered_vulnerabilities

    @pytest.mark.asyncio
    async def test_tracks_exploitation_attempt(self):
        """Test exploitation attempts are tracked."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = "Shadow credentials added"
        event.tool_call = MagicMock()
        event.tool_call.name = "pywhisker"

        await track_vulnerability_discoveries(event)

        assert "acl_abuse" in red_factory._exploited_vulnerabilities

    @pytest.mark.asyncio
    async def test_ignores_empty_result(self):
        """Test that empty results are ignored."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import track_vulnerability_discoveries

        event = MagicMock()
        event.result = None

        await track_vulnerability_discoveries(event)

        assert len(red_factory._discovered_vulnerabilities) == 0


class TestPeriodicPriorityCheck:
    """Tests for periodic_priority_check hook."""

    def setup_method(self):
        """Reset tracking state before each test."""
        reset_event_tracking()

    @pytest.mark.asyncio
    async def test_returns_none_before_interval(self):
        """Test no reminder before check interval."""
        from ares.core.factories.red_factory import periodic_priority_check

        event = MagicMock()
        event.step_number = 5

        result = await periodic_priority_check(event)

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_discoveries(self):
        """Test no reminder when nothing discovered."""
        from ares.core.factories.red_factory import periodic_priority_check

        event = MagicMock()
        event.step_number = 15  # Past interval

        result = await periodic_priority_check(event)

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_reminder_for_unexploited(self):
        """Test reminder is returned for unexploited vulnerabilities."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import periodic_priority_check

        # Add a discovery without exploitation
        red_factory._discovered_vulnerabilities["test_vuln"] = {
            "type": "Test Vulnerability",
            "tool": "test_tool",
            "step": 1,
        }

        event = MagicMock()
        event.step_number = 15

        result = await periodic_priority_check(event)

        assert result is not None
        assert "UNEXPLOITED" in result
        assert "Test Vulnerability" in result

    @pytest.mark.asyncio
    async def test_no_reminder_for_exploited(self):
        """Test no reminder when all vulnerabilities are exploited."""
        from ares.core.factories import red_factory
        from ares.core.factories.red_factory import periodic_priority_check

        # Add a discovery and mark it exploited
        red_factory._discovered_vulnerabilities["test_vuln"] = {
            "type": "Test Vulnerability",
            "tool": "test_tool",
            "step": 1,
        }
        red_factory._exploited_vulnerabilities.add("test_vuln")

        event = MagicMock()
        event.step_number = 15

        result = await periodic_priority_check(event)

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_no_step_number(self):
        """Test returns None when step_number is missing."""
        from ares.core.factories.red_factory import periodic_priority_check

        event = MagicMock()
        event.step_number = None

        result = await periodic_priority_check(event)

        assert result is None
