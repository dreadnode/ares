"""Unit tests for announcement behavior - specifically completed_at handling."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import SharedRedTeamState


@pytest.fixture
def dispatcher():
    """Create a dispatcher with mocked checkpoint."""
    d = RedTeamDispatcher()
    d._shared_state = SharedRedTeamState(operation_id="op-test-announce")
    d._checkpoint = AsyncMock()
    return d


class TestAnnounceDomainAdmin:
    """Tests for announce_domain_admin completed_at behavior."""

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.get_stop_on_domain_admin", return_value=False)
    async def test_does_not_set_completed_at_when_stop_disabled(self, mock_stop_on_da, dispatcher):
        """When stop_on_domain_admin=False, completed_at should NOT be set."""
        await dispatcher.announce_domain_admin(
            username="Administrator",
            domain="contoso.local",
            attack_path="secretsdump -> krbtgt",
            credential_type="hash",
            source_agent="orchestrator",
        )

        assert dispatcher.shared_state.has_domain_admin is True
        assert dispatcher.shared_state.domain_admin_path == "secretsdump -> krbtgt"
        assert dispatcher.shared_state.completed_at is None
        assert dispatcher.shared_state.completed is False

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.get_stop_on_domain_admin", return_value=True)
    async def test_sets_completed_at_when_stop_enabled(self, mock_stop_on_da, dispatcher):
        """When stop_on_domain_admin=True, completed_at SHOULD be set."""
        await dispatcher.announce_domain_admin(
            username="Administrator",
            domain="contoso.local",
            attack_path="secretsdump -> krbtgt",
            credential_type="hash",
            source_agent="orchestrator",
        )

        assert dispatcher.shared_state.has_domain_admin is True
        assert dispatcher.shared_state.completed_at is not None
        assert dispatcher.shared_state.completed is True

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.get_stop_on_domain_admin", return_value=True)
    async def test_completed_at_is_idempotent(self, mock_stop_on_da, dispatcher):
        """Multiple calls should not overwrite completed_at."""
        # First announcement
        await dispatcher.announce_domain_admin(
            username="Administrator",
            domain="contoso.local",
            attack_path="first path",
            credential_type="hash",
            source_agent="orchestrator",
        )
        first_completed_at = dispatcher.shared_state.completed_at

        # Second announcement (e.g., from child domain)
        await dispatcher.announce_domain_admin(
            username="krbtgt",
            domain="child.contoso.local",
            attack_path="second path",
            credential_type="hash",
            source_agent="orchestrator",
        )

        # completed_at should not change
        assert dispatcher.shared_state.completed_at == first_completed_at


class TestAnnounceGoldenTicket:
    """Tests for announce_golden_ticket completed_at behavior."""

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.get_stop_on_golden_ticket", return_value=False)
    async def test_does_not_set_completed_at_when_stop_disabled(self, mock_stop_on_gt, dispatcher):
        """When stop_on_golden_ticket=False, completed_at should NOT be set."""
        await dispatcher.announce_golden_ticket(
            domain="contoso.local",
            krbtgt_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            ticket_path="/tmp/admin.ccache",
            source_agent="kerberos-agent",
            target_domain="fabrikam.local",
        )

        assert dispatcher.shared_state.has_golden_ticket is True
        assert dispatcher.shared_state.completed_at is None
        assert dispatcher.shared_state.completed is False

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.get_stop_on_golden_ticket", return_value=True)
    async def test_sets_completed_at_when_stop_enabled(self, mock_stop_on_gt, dispatcher):
        """When stop_on_golden_ticket=True, completed_at SHOULD be set."""
        await dispatcher.announce_golden_ticket(
            domain="contoso.local",
            krbtgt_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            ticket_path="/tmp/admin.ccache",
            source_agent="kerberos-agent",
            target_domain="fabrikam.local",
        )

        assert dispatcher.shared_state.has_golden_ticket is True
        assert dispatcher.shared_state.completed_at is not None
        assert dispatcher.shared_state.completed is True


class TestStopConditionInteraction:
    """Tests for interaction between stop conditions."""

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.get_stop_on_domain_admin", return_value=False)
    @patch("ares.core.dispatcher.announcements.get_stop_on_golden_ticket", return_value=True)
    async def test_da_then_gt_only_sets_completed_at_on_gt(
        self, mock_stop_on_gt, mock_stop_on_da, dispatcher
    ):
        """When stop_on_golden_ticket=True, DA should not set completed_at but GT should."""
        # DA achieved - should not set completed_at
        await dispatcher.announce_domain_admin(
            username="Administrator",
            domain="contoso.local",
            attack_path="secretsdump -> krbtgt",
            credential_type="hash",
            source_agent="orchestrator",
        )

        assert dispatcher.shared_state.has_domain_admin is True
        assert dispatcher.shared_state.completed_at is None
        assert dispatcher.shared_state.completed is False

        # GT forged - should set completed_at
        await dispatcher.announce_golden_ticket(
            domain="contoso.local",
            krbtgt_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            ticket_path="/tmp/admin.ccache",
            source_agent="kerberos-agent",
        )

        assert dispatcher.shared_state.has_golden_ticket is True
        assert dispatcher.shared_state.completed_at is not None
        assert dispatcher.shared_state.completed is True


class TestAnnouncementTracing:
    """Tests for OTel tracing of announcements."""

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.trace_discovery")
    @patch("ares.core.dispatcher.announcements.get_stop_on_domain_admin", return_value=False)
    async def test_domain_admin_emits_trace_discovery(
        self, mock_stop_on_da, mock_trace_discovery, dispatcher
    ):
        """announce_domain_admin should call trace_discovery with correct attributes."""
        await dispatcher.announce_domain_admin(
            username="testuser",
            domain="child.contoso.local",
            attack_path="privesc → krbtgt (NTLM)",
            credential_type="hash",
            source_agent="privesc",
        )

        mock_trace_discovery.assert_called_once()
        call_kwargs = mock_trace_discovery.call_args.kwargs

        assert call_kwargs["discovery_type"] == "domain_admin"
        assert call_kwargs["source_agent"] == "privesc"
        assert call_kwargs["operation_id"] == "op-test-announce"
        assert call_kwargs["target_user"] == "testuser"
        assert call_kwargs["target_domain"] == "child.contoso.local"
        assert call_kwargs["additional_attrs"]["attack_path"] == "privesc → krbtgt (NTLM)"
        assert call_kwargs["additional_attrs"]["credential_type"] == "hash"
        assert call_kwargs["additional_attrs"]["mitre.technique.id"] == "T1003.006"

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.trace_discovery")
    @patch("ares.core.dispatcher.announcements.get_stop_on_golden_ticket", return_value=False)
    async def test_golden_ticket_emits_trace_discovery(
        self, mock_stop_on_gt, mock_trace_discovery, dispatcher
    ):
        """announce_golden_ticket should call trace_discovery with correct attributes."""
        await dispatcher.announce_golden_ticket(
            domain="contoso.local",
            krbtgt_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            ticket_path="/tmp/admin.ccache",
            source_agent="kerberos-agent",
            target_domain=None,
        )

        mock_trace_discovery.assert_called_once()
        call_kwargs = mock_trace_discovery.call_args.kwargs

        assert call_kwargs["discovery_type"] == "golden_ticket"
        assert call_kwargs["source_agent"] == "kerberos-agent"
        assert call_kwargs["operation_id"] == "op-test-announce"
        assert call_kwargs["target_domain"] == "contoso.local"
        assert call_kwargs["additional_attrs"]["source_domain"] == "contoso.local"
        assert call_kwargs["additional_attrs"]["ticket_path"] == "/tmp/admin.ccache"
        assert call_kwargs["additional_attrs"]["is_forest_escalation"] is False
        assert call_kwargs["additional_attrs"]["mitre.technique.id"] == "T1558.001"

    @pytest.mark.asyncio
    @patch("ares.core.dispatcher.announcements.trace_discovery")
    @patch("ares.core.dispatcher.announcements.get_stop_on_golden_ticket", return_value=False)
    async def test_golden_ticket_forest_escalation_traced(
        self, mock_stop_on_gt, mock_trace_discovery, dispatcher
    ):
        """Golden ticket with target_domain should trace is_forest_escalation=True."""
        await dispatcher.announce_golden_ticket(
            domain="child.contoso.local",
            krbtgt_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            ticket_path="/tmp/admin.ccache",
            source_agent="kerberos-agent",
            target_domain="contoso.local",
        )

        mock_trace_discovery.assert_called_once()
        call_kwargs = mock_trace_discovery.call_args.kwargs

        assert call_kwargs["target_domain"] == "contoso.local"
        assert call_kwargs["additional_attrs"]["source_domain"] == "child.contoso.local"
        assert call_kwargs["additional_attrs"]["is_forest_escalation"] is True
