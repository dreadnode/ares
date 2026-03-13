"""Tests for EscalationTriageTools."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.models import (
    Evidence,
    InvestigationStage,
    PyramidLevel,
    SharedBlueTeamState,
)
from ares.tools.blue.triage_tools import EscalationTriageTools


@pytest.fixture
def triage_tools():
    """Create a fresh EscalationTriageTools instance."""
    return EscalationTriageTools()


@pytest.fixture
def mock_backend():
    """Create a mock BlueStateBackend."""
    backend = MagicMock()
    backend.set_triage_decision = AsyncMock()
    backend.add_triage_record = AsyncMock()
    backend.get_reinvestigation_cycle = AsyncMock(return_value=0)
    return backend


@pytest.fixture
def mock_shared_state():
    """Create a mock SharedBlueTeamState."""
    state = SharedBlueTeamState(
        investigation_id="inv-test123",
        alert={
            "labels": {"alertname": "Test Alert", "severity": "high"},
            "annotations": {"description": "Test alert description"},
        },
        stage=InvestigationStage.SYNTHESIS,
        escalated=True,
        escalation_reason="High severity alert with credential access",
    )
    # Add some evidence
    state.evidence = [
        Evidence(
            id="ev-001",
            type="ip",
            value="192.168.58.10",
            source="test",
            timestamp=datetime.now(timezone.utc),
            pyramid_level=PyramidLevel.IP_ADDRESSES,
        ),
        Evidence(
            id="ev-002",
            type="technique",
            value="T1003.001 LSASS Memory",
            source="test",
            timestamp=datetime.now(timezone.utc),
            pyramid_level=PyramidLevel.TTPS,
        ),
    ]
    state.identified_techniques = {"T1003.001", "T1078"}
    state.technique_names = {"T1003.001": "LSASS Memory", "T1078": "Valid Accounts"}
    state.queried_hosts = {"dc01.contoso.local", "ws01.contoso.local"}
    state.queried_users = {"admin@contoso.local"}
    state.attack_synopsis = "Credential theft attack targeting domain admin"
    state.recommendations = ["Reset affected passwords", "Enable MFA"]
    return state


class TestEscalationTriageToolsInit:
    """Tests for EscalationTriageTools initialization."""

    def test_initializes_with_empty_result(self, triage_tools):
        assert triage_tools._result_data == {}
        assert triage_tools._backend is None
        assert triage_tools._shared_state is None
        assert triage_tools._completion_event is None

    def test_set_backend(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        assert triage_tools._backend is mock_backend

    def test_set_shared_state(self, triage_tools, mock_shared_state):
        triage_tools.set_shared_state(mock_shared_state)
        assert triage_tools._shared_state is mock_shared_state

    def test_set_completion_event(self, triage_tools):
        event = asyncio.Event()
        triage_tools.set_completion_event(event)
        assert triage_tools._completion_event is event
        assert triage_tools._result_data == {}


class TestGetImpliedCapabilities:
    """Tests for _get_implied_capabilities method."""

    def test_empty_techniques_returns_empty(self, triage_tools):
        result = triage_tools._get_implied_capabilities(set())
        assert result == []

    def test_dcsync_implies_golden_ticket_and_da(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1003.006"})

        assert len(result) == 2
        assert any("GOLDEN TICKET CAPABILITY" in r for r in result)
        assert any("DOMAIN ADMIN ACHIEVED" in r for r in result)
        # Verify it explains why logs won't show golden ticket
        golden_ticket_msg = next(r for r in result if "GOLDEN TICKET" in r)
        assert "NO log evidence" in golden_ticket_msg

    def test_lsass_dump_implies_golden_ticket(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1003.001"})

        assert len(result) == 1
        assert "GOLDEN TICKET CAPABILITY" in result[0]

    def test_ntds_dump_implies_golden_ticket(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1003.003"})

        assert len(result) == 1
        assert "GOLDEN TICKET CAPABILITY" in result[0]

    def test_generic_credential_dump_implies_golden_ticket(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1003"})

        assert len(result) == 1
        assert "GOLDEN TICKET CAPABILITY" in result[0]

    def test_constrained_delegation_implies_privesc(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1550.003"})

        assert len(result) >= 1
        assert any("PRIVILEGE ESCALATION CAPABILITY" in r for r in result)
        assert any("impersonate ANY user" in r for r in result)

    def test_kerberoasting_implies_offline_cracking(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1558.003"})

        assert len(result) == 1
        assert "CREDENTIAL COMPROMISE RISK" in result[0]
        assert "offline cracking" in result[0].lower()

    def test_asrep_roasting_implies_offline_cracking(self, triage_tools):
        result = triage_tools._get_implied_capabilities({"T1558.004"})

        assert len(result) == 1
        assert "CREDENTIAL COMPROMISE RISK" in result[0]
        assert "pre-auth disabled" in result[0].lower()

    def test_multiple_techniques_combine_implications(self, triage_tools):
        # Simulate a full attack chain: DCSync + Kerberoasting
        result = triage_tools._get_implied_capabilities({"T1003.006", "T1558.003"})

        # Should have: golden ticket, DA achieved, kerberoasting
        assert len(result) == 3
        assert any("GOLDEN TICKET" in r for r in result)
        assert any("DOMAIN ADMIN ACHIEVED" in r for r in result)
        assert any("Kerberoasting" in r for r in result)

    def test_unrelated_technique_returns_empty(self, triage_tools):
        # T1087 is account discovery - no implied capabilities
        result = triage_tools._get_implied_capabilities({"T1087.002"})
        assert result == []


class TestGetInvestigationContext:
    """Tests for get_investigation_context tool."""

    def test_returns_error_without_state(self, triage_tools):
        result = triage_tools.get_investigation_context()
        assert "ERROR" in result

    def test_returns_formatted_context(self, triage_tools, mock_shared_state):
        triage_tools.set_shared_state(mock_shared_state)
        result = triage_tools.get_investigation_context()

        assert "inv-test123" in result
        assert "ESCALATED" in result
        assert "Test Alert" in result
        assert "T1003.001" in result
        assert "dc01.contoso.local" in result
        assert "Credential theft" in result

    def test_includes_evidence_summary(self, triage_tools, mock_shared_state):
        triage_tools.set_shared_state(mock_shared_state)
        result = triage_tools.get_investigation_context()

        assert "Total evidence items: 2" in result
        assert "Level 6" in result  # TTPs
        assert "Level 2" in result  # IP Addresses

    def test_includes_attack_chain_implications(self, triage_tools, mock_shared_state):
        # mock_shared_state has T1003.001 which should trigger golden ticket implication
        triage_tools.set_shared_state(mock_shared_state)
        result = triage_tools.get_investigation_context()

        assert "ATTACK CHAIN IMPLICATIONS" in result
        assert "GOLDEN TICKET CAPABILITY" in result

    def test_shows_no_implications_when_none(self, triage_tools, mock_shared_state):
        # Set techniques that don't have implications
        mock_shared_state.identified_techniques = {"T1087.002"}  # Account discovery only
        triage_tools.set_shared_state(mock_shared_state)
        result = triage_tools.get_investigation_context()

        assert "ATTACK CHAIN IMPLICATIONS" in result
        assert "No additional implied capabilities" in result

    def test_dcsync_shows_both_implications(self, triage_tools, mock_shared_state):
        mock_shared_state.identified_techniques = {"T1003.006"}
        triage_tools.set_shared_state(mock_shared_state)
        result = triage_tools.get_investigation_context()

        assert "GOLDEN TICKET CAPABILITY" in result
        assert "DOMAIN ADMIN ACHIEVED" in result


class TestConfirmEscalation:
    """Tests for confirm_escalation tool."""

    @pytest.mark.asyncio
    async def test_returns_error_without_backend(self, triage_tools):
        result = await triage_tools.confirm_escalation(
            reasoning="Test reasoning",
            severity="high",
            confidence=0.9,
        )
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_sets_triage_decision(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        result = await triage_tools.confirm_escalation(
            reasoning="Active attack in progress",
            severity="critical",
            confidence=0.95,
        )

        assert "CONFIRMED" in result
        assert "critical" in result
        mock_backend.set_triage_decision.assert_called_once()
        call_args = mock_backend.set_triage_decision.call_args
        assert call_args.kwargs["decision"] == "confirmed"
        assert call_args.kwargs["confidence"] == 0.95

    @pytest.mark.asyncio
    async def test_signals_completion(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        await triage_tools.confirm_escalation(
            reasoning="Test",
            severity="high",
            confidence=0.8,
        )

        assert event.is_set()
        assert triage_tools._result_data["decision"] == "confirmed"


class TestDowngradeEscalation:
    """Tests for downgrade_escalation tool."""

    @pytest.mark.asyncio
    async def test_returns_error_without_backend(self, triage_tools):
        result = await triage_tools.downgrade_escalation(
            reasoning="False positive",
            is_false_positive=True,
        )
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_sets_downgrade_decision(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        result = await triage_tools.downgrade_escalation(
            reasoning="Benign admin activity",
            is_false_positive=True,
            confidence=0.85,
        )

        assert "DOWNGRADED" in result
        assert "FALSE POSITIVE" in result
        mock_backend.set_triage_decision.assert_called_once()
        call_args = mock_backend.set_triage_decision.call_args
        assert call_args.kwargs["decision"] == "downgraded"

    @pytest.mark.asyncio
    async def test_low_priority_label(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        result = await triage_tools.downgrade_escalation(
            reasoning="Low priority issue",
            is_false_positive=False,
            confidence=0.7,
        )

        assert "LOW PRIORITY" in result


class TestRequestReinvestigation:
    """Tests for request_reinvestigation tool."""

    @pytest.mark.asyncio
    async def test_returns_error_without_backend(self, triage_tools):
        result = await triage_tools.request_reinvestigation(
            reasoning="Need more data",
            focus_areas=["Check host ws01"],
        )
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_sets_reinvestigation_decision(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        result = await triage_tools.request_reinvestigation(
            reasoning="Missing log data",
            focus_areas=["Check host ws01", "Verify user activity"],
            confidence=0.6,
        )

        assert "REINVESTIGATION requested" in result
        assert "cycle 1/2" in result
        mock_backend.set_triage_decision.assert_called_once()
        call_args = mock_backend.set_triage_decision.call_args
        assert call_args.kwargs["decision"] == "reinvestigate"
        assert call_args.kwargs["reinvestigation_cycle"] == 1

    @pytest.mark.asyncio
    async def test_auto_confirms_after_max_cycles(self, triage_tools, mock_backend):
        mock_backend.get_reinvestigation_cycle = AsyncMock(return_value=2)
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        result = await triage_tools.request_reinvestigation(
            reasoning="Still need more data",
            focus_areas=["More investigation needed"],
        )

        # Should auto-confirm instead of reinvestigating
        assert "CONFIRMED" in result
        # The decision should be confirmed, not reinvestigate
        call_args = mock_backend.set_triage_decision.call_args
        assert call_args.kwargs["decision"] == "confirmed"


class TestRouteToTeam:
    """Tests for route_to_team tool."""

    @pytest.mark.asyncio
    async def test_returns_error_without_backend(self, triage_tools):
        result = await triage_tools.route_to_team(
            reasoning="Needs IR team",
            team="incident_response",
            action="Isolate host",
        )
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_routes_to_valid_team(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)
        event = asyncio.Event()
        triage_tools.set_completion_event(event)

        result = await triage_tools.route_to_team(
            reasoning="APT indicators found",
            team="threat_intel",
            action="Analyze malware sample",
            confidence=0.9,
        )

        assert "ROUTED" in result
        assert "threat_intel" in result
        mock_backend.set_triage_decision.assert_called_once()
        call_args = mock_backend.set_triage_decision.call_args
        assert call_args.kwargs["decision"] == "routed"
        assert call_args.kwargs["routed_to"] == "threat_intel:Analyze malware sample"

    @pytest.mark.asyncio
    async def test_rejects_invalid_team(self, triage_tools, mock_backend):
        triage_tools.set_backend(mock_backend)

        result = await triage_tools.route_to_team(
            reasoning="Test",
            team="invalid_team",
            action="Test action",
        )

        assert "ERROR" in result
        assert "Invalid team" in result
        mock_backend.set_triage_decision.assert_not_called()

    @pytest.mark.asyncio
    async def test_all_valid_teams(self, triage_tools, mock_backend):
        valid_teams = ["incident_response", "threat_intel", "forensics", "legal", "infrastructure"]

        for team in valid_teams:
            mock_backend.reset_mock()
            triage_tools.set_backend(mock_backend)
            event = asyncio.Event()
            triage_tools.set_completion_event(event)

            result = await triage_tools.route_to_team(
                reasoning=f"Route to {team}",
                team=team,
                action="Test action",
            )

            assert "ROUTED" in result, f"Failed for team: {team}"
            assert team in result
