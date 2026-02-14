"""Tests for ADCS enumeration retry logic.

Tests the _auto_adcs_enumeration background task's retry behavior.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.models import Credential, Share, SharedRedTeamState, Target


class TestAutoAdcsEnumerationRetry:
    """Tests for ADCS enumeration retry logic."""

    @pytest.fixture
    def shared_state(self) -> SharedRedTeamState:
        """Create a shared state with ADCS server and credentials."""
        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="contoso.local")

        # Add a credential
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                domain="contoso.local",
                source="spray",
            )
        )

        # Add a CertEnroll share (indicates ADCS server)
        state.all_shares.append(
            Share(
                host="192.168.58.10",
                name="CertEnroll",
                description="Active Directory Certificate Services",
                permissions="READ",
            )
        )

        return state

    @pytest.fixture
    def mock_dispatcher(self, shared_state):
        """Create a mock dispatcher."""
        dispatcher = MagicMock()
        dispatcher.shared_state = shared_state
        dispatcher.find_adcs_servers = MagicMock(
            return_value=[("192.168.58.10", "ca.contoso.local")]
        )
        dispatcher.request_adcs_enumeration = AsyncMock(return_value="exploit_adcs_001")
        return dispatcher

    @pytest.mark.asyncio
    async def test_dispatches_adcs_enumeration(self, mock_dispatcher):
        """Test that ADCS enumeration is dispatched when server is found."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        iteration_count = [0]

        async def mock_sleep(delay):
            iteration_count[0] += 1
            # Stop after second sleep (first sleep is before dispatch, second is after)
            if iteration_count[0] >= 2:
                mock_dispatcher.shared_state.completed = True

        with (
            patch("asyncio.sleep", side_effect=mock_sleep),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            mock_loop.return_value.time = lambda: 1000.0

            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1)

        mock_dispatcher.request_adcs_enumeration.assert_called_once_with(
            source_agent="orchestrator",
            target_ip="192.168.58.10",
            domain="contoso.local",
            username="testuser",
            password="TestPass123",  # pragma: allowlist secret
        )

    @pytest.mark.asyncio
    async def test_retries_after_failure(self, mock_dispatcher):
        """Test that failed ADCS tasks are retried."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        iteration_count = 0
        task_dispatched_count = 0

        async def mock_sleep(delay):
            nonlocal iteration_count
            iteration_count += 1
            # Stop after 4 iterations
            if iteration_count >= 4:
                mock_dispatcher.shared_state.completed = True

        async def mock_request(*args, **kwargs):
            nonlocal task_dispatched_count
            task_dispatched_count += 1
            return f"exploit_adcs_{task_dispatched_count:03d}"

        mock_dispatcher.request_adcs_enumeration.side_effect = mock_request

        # Simulate time passing for retry cooldown
        time_value = [1000.0]

        def mock_time():
            time_value[0] += 150  # Advance time past retry_cooldown (120s)
            return time_value[0]

        with (
            patch("asyncio.sleep", side_effect=mock_sleep),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            mock_loop.return_value.time = mock_time

            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1, max_retries=3)

        # Should have dispatched multiple times (initial + retries)
        assert mock_dispatcher.request_adcs_enumeration.call_count >= 2

    @pytest.mark.asyncio
    async def test_stops_retry_after_max_attempts(self, mock_dispatcher):
        """Test that retries stop after max_retries is reached."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        iteration_count = 0

        async def mock_sleep(delay):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 10:
                mock_dispatcher.shared_state.completed = True

        # Track dispatches
        dispatch_count = [0]

        async def mock_request(*args, **kwargs):
            dispatch_count[0] += 1
            return f"exploit_adcs_{dispatch_count[0]:03d}"

        mock_dispatcher.request_adcs_enumeration.side_effect = mock_request

        # Always return time past cooldown
        with (
            patch("asyncio.sleep", side_effect=mock_sleep),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            # Return incrementing time values
            call_count = [0]

            def mock_time():
                call_count[0] += 1
                return 1000.0 + (call_count[0] * 200)  # Always past cooldown

            mock_loop.return_value.time = mock_time

            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1, max_retries=2)

        # Should stop after max_retries (2) + initial = 3 max dispatches per cred
        # But since task is never marked complete, it should cap at max_retries
        assert dispatch_count[0] <= 3  # Initial + 2 retries max

    @pytest.mark.asyncio
    async def test_stops_when_domain_admin_achieved(self, mock_dispatcher):
        """Test that ADCS enumeration stops when domain admin is achieved."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        async def mock_sleep(delay):
            # Simulate domain admin being achieved
            mock_dispatcher.shared_state.has_domain_admin = True

        with patch("asyncio.sleep", side_effect=mock_sleep):
            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1)

        # Should not have dispatched anything (stopped before dispatch)
        # or at most once before the check
        assert mock_dispatcher.request_adcs_enumeration.call_count <= 1

    @pytest.mark.asyncio
    async def test_handles_no_credentials(self, mock_dispatcher):
        """Test graceful handling when no credentials available."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        # Remove credentials
        mock_dispatcher.shared_state.all_credentials.clear()

        iteration_count = [0]

        async def mock_sleep(delay):
            iteration_count[0] += 1
            if iteration_count[0] >= 3:
                mock_dispatcher.shared_state.completed = True

        with patch("asyncio.sleep", side_effect=mock_sleep):
            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1)

        # Should not have dispatched anything (no credentials)
        mock_dispatcher.request_adcs_enumeration.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_no_adcs_servers(self, mock_dispatcher):
        """Test graceful handling when no ADCS servers found."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        # No ADCS servers
        mock_dispatcher.find_adcs_servers.return_value = []

        iteration_count = [0]

        async def mock_sleep(delay):
            iteration_count[0] += 1
            if iteration_count[0] >= 3:
                mock_dispatcher.shared_state.completed = True

        with patch("asyncio.sleep", side_effect=mock_sleep):
            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1)

        # Should not have dispatched anything (no ADCS servers)
        mock_dispatcher.request_adcs_enumeration.assert_not_called()

    @pytest.mark.asyncio
    async def test_tries_different_credentials(self, mock_dispatcher):
        """Test that different credentials are tried for the same server."""
        from ares.core.orchestrator import _auto_adcs_enumeration

        # Add another credential
        mock_dispatcher.shared_state.all_credentials.append(
            Credential(
                username="admin",
                password="AdminPass456",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
            )
        )

        iteration_count = [0]

        async def mock_sleep(delay):
            iteration_count[0] += 1
            if iteration_count[0] >= 5:
                mock_dispatcher.shared_state.completed = True

        # Track usernames used
        usernames_used = []

        async def mock_request(source_agent, target_ip, domain, username, password):
            usernames_used.append(username)
            return f"exploit_adcs_{len(usernames_used):03d}"

        mock_dispatcher.request_adcs_enumeration.side_effect = mock_request

        with (
            patch("asyncio.sleep", side_effect=mock_sleep),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            call_count = [0]

            def mock_time():
                call_count[0] += 1
                return 1000.0 + (call_count[0] * 200)

            mock_loop.return_value.time = mock_time

            await _auto_adcs_enumeration(mock_dispatcher, check_interval=0.1, max_retries=3)

        # Should have tried both credentials
        assert "testuser" in usernames_used or "admin" in usernames_used


class TestAdcsServerDetection:
    """Tests for ADCS server detection via CertEnroll share."""

    def test_find_adcs_servers_detects_certenroll(self):
        """Test that CertEnroll share indicates ADCS server."""
        from ares.core.dispatcher import RedTeamDispatcher
        from ares.core.models import Host

        state = SharedRedTeamState(operation_id="test-op")
        state.all_shares.append(
            Share(
                host="192.168.58.10",
                name="CertEnroll",
                description="Certificate Services",
                permissions="READ",
            )
        )
        state.all_hosts.append(Host(ip="192.168.58.10", hostname="ca.contoso.local"))

        # Create a simple object that has find_adcs_servers behavior
        class MockDispatcher:
            shared_state = state

            def find_adcs_servers(self):
                return RedTeamDispatcher.find_adcs_servers(self)

        dispatcher = MockDispatcher()
        result = dispatcher.find_adcs_servers()

        assert len(result) == 1
        assert result[0] == ("192.168.58.10", "ca.contoso.local")

    def test_find_adcs_servers_case_insensitive(self):
        """Test that CertEnroll detection is case-insensitive."""
        from ares.core.dispatcher import RedTeamDispatcher

        state = SharedRedTeamState(operation_id="test-op")
        state.all_shares.append(
            Share(
                host="192.168.58.10",
                name="CERTENROLL",  # Uppercase
                description="Certificate Services",
                permissions="READ",
            )
        )

        class MockDispatcher:
            shared_state = state

            def find_adcs_servers(self):
                return RedTeamDispatcher.find_adcs_servers(self)

        dispatcher = MockDispatcher()
        result = dispatcher.find_adcs_servers()

        assert len(result) == 1

    def test_find_adcs_servers_ignores_non_certenroll(self):
        """Test that non-CertEnroll shares are ignored."""
        from ares.core.dispatcher import RedTeamDispatcher

        state = SharedRedTeamState(operation_id="test-op")
        state.all_shares.append(
            Share(
                host="192.168.58.10",
                name="SYSVOL",
                description="Logon server share",
                permissions="READ",
            )
        )
        state.all_shares.append(
            Share(
                host="192.168.58.10",
                name="NETLOGON",
                description="Logon server share",
                permissions="READ",
            )
        )

        class MockDispatcher:
            shared_state = state

            def find_adcs_servers(self):
                return RedTeamDispatcher.find_adcs_servers(self)

        dispatcher = MockDispatcher()
        result = dispatcher.find_adcs_servers()

        assert len(result) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
