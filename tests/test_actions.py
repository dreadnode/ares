"""Tests for investigation completion and escalation actions."""

from datetime import datetime, timezone

import pytest

from ares.core.lateral_analyzer import HostConnection, LateralGraph
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
    TimelineEvent,
)
from ares.tools.blue.actions import CompletionTools, escalate_investigation


class TestCompletionTools:
    """Tests for CompletionTools class."""

    @pytest.fixture
    def completion_tools(self) -> CompletionTools:
        """Create CompletionTools instance."""
        return CompletionTools()

    @pytest.fixture
    def state_with_evidence(self, sample_alert: dict) -> InvestigationState:
        """Create state with evidence."""
        return InvestigationState(
            investigation_id="test-001",
            alert=sample_alert,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.LATERAL,
            evidence=[
                Evidence(
                    id="ev-1",
                    type="ip_address",
                    value="192.168.56.100",
                    source="Query",
                    timestamp=datetime.now(timezone.utc),
                    pyramid_level=PyramidLevel.IP_ADDRESSES,
                    mitre_techniques=["T1071"],
                    confidence=0.8,
                    validated=True,
                ),
            ],
            timeline=[
                TimelineEvent(
                    id="te-test-001",
                    timestamp=datetime.now(timezone.utc),
                    description="Test event",
                    mitre_techniques=["T1071"],
                    confidence=0.9,
                    source="Test",
                ),
            ],
            questions=[],
            identified_techniques={"T1071"},
            identified_tactics={"TA0011"},
            technique_names={"T1071": "Application Layer Protocol"},
            technique_to_tactic={"T1071": "command-and-control"},
            queried_hosts={"app-srv01.contoso.com"},
            queried_users={"danj"},
            executed_queries=[],
            escalated=False,
            escalation_reason=None,
            attack_synopsis=None,
            recommendations=[],
            lateral_graph=LateralGraph(),
        )

    def test_set_state(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test setting investigation state."""
        completion_tools.set_state(investigation_state)
        assert completion_tools.state == investigation_state

    @pytest.mark.asyncio
    async def test_complete_investigation_no_state(self, completion_tools: CompletionTools):
        """Test completing investigation without state set."""
        result = await completion_tools.complete_investigation(
            summary="Test summary",
            attack_synopsis="Test synopsis",
            recommendations=["Action 1"],
        )
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_complete_investigation_basic(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test basic investigation completion."""
        completion_tools.set_state(investigation_state)
        result = await completion_tools.complete_investigation(
            summary="Investigation completed successfully",
            attack_synopsis="No malicious activity found",
            recommendations=["Continue monitoring"],
        )
        assert "completed" in result.lower()

    @pytest.mark.asyncio
    async def test_complete_investigation_stores_synopsis(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test that synopsis is stored in state."""
        completion_tools.set_state(investigation_state)
        synopsis = "At 14:30, attacker began reconnaissance"
        await completion_tools.complete_investigation(
            summary="Test",
            attack_synopsis=synopsis,
            recommendations=[],
        )
        assert investigation_state.attack_synopsis == synopsis

    @pytest.mark.asyncio
    async def test_complete_investigation_stores_recommendations(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test that recommendations are stored."""
        completion_tools.set_state(investigation_state)
        recommendations = ["Block IP", "Reset passwords"]
        await completion_tools.complete_investigation(
            summary="Test",
            attack_synopsis="Test",
            recommendations=recommendations,
        )
        assert "Block IP" in investigation_state.recommendations
        assert "Reset passwords" in investigation_state.recommendations

    @pytest.mark.asyncio
    async def test_complete_investigation_extracts_recommendations_from_alert(
        self, completion_tools: CompletionTools, sample_alert: dict
    ):
        """Test auto-extraction of recommendations from alert annotations."""
        state = InvestigationState(
            investigation_id="test-002",
            alert=sample_alert,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.TRIAGE,
            evidence=[],
            timeline=[],
            questions=[],
            identified_techniques=set(),
            identified_tactics=set(),
            technique_names={},
            technique_to_tactic={},
            queried_hosts=set(),
            queried_users=set(),
            executed_queries=[],
            escalated=False,
            escalation_reason=None,
            attack_synopsis=None,
            recommendations=[],
            lateral_graph=LateralGraph(),
        )
        completion_tools.set_state(state)
        await completion_tools.complete_investigation(
            summary="Test",
            attack_synopsis="Test",
            recommendations=None,
        )
        # Should have extracted from alert annotations
        assert len(state.recommendations) > 0

    @pytest.mark.asyncio
    async def test_complete_investigation_generates_fallback_synopsis(
        self, completion_tools: CompletionTools, state_with_evidence: InvestigationState
    ):
        """Test fallback synopsis generation when none provided."""
        completion_tools.set_state(state_with_evidence)
        await completion_tools.complete_investigation(
            summary="Test",
            attack_synopsis=None,
            recommendations=["Test"],
        )
        # Should have generated a fallback synopsis from evidence
        assert state_with_evidence.attack_synopsis is not None


class TestGenerateFallbackSynopsis:
    """Tests for _generate_fallback_synopsis method."""

    @pytest.fixture
    def completion_tools(self) -> CompletionTools:
        return CompletionTools()

    def test_fallback_synopsis_no_state(self, completion_tools: CompletionTools):
        """Test fallback with no state."""
        completion_tools._generate_fallback_synopsis()
        # Should not raise

    def test_fallback_synopsis_includes_alert_info(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test fallback includes alert information."""
        completion_tools.set_state(investigation_state)
        investigation_state.evidence.append(
            Evidence(
                id="ev-test",
                type="ip",
                value="192.168.56.1",
                source="test",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=[],
                confidence=0.8,
                validated=True,
            )
        )
        completion_tools._generate_fallback_synopsis()
        assert investigation_state.attack_synopsis is not None
        assert "Alert" in investigation_state.attack_synopsis

    def test_fallback_synopsis_includes_techniques(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes MITRE techniques."""
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert (
            "T1003.006" in populated_investigation_state.attack_synopsis
            or "MITRE" in populated_investigation_state.attack_synopsis
        )

    def test_fallback_synopsis_includes_hosts(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes investigated hosts."""
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert "Hosts" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_includes_users(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes investigated users."""
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert "Users" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_includes_evidence_summary(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes evidence summary."""
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert "Evidence" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_with_lateral_graph(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes lateral movement info."""
        populated_investigation_state.lateral_graph = LateralGraph(
            connections=[
                HostConnection(
                    source_host="host1",
                    destination_host="host2",
                    connection_type="rdp",
                    timestamp=datetime.now(timezone.utc),
                    user="admin",
                )
            ],
            investigated_hosts={"host1"},
            pending_hosts={"host2"},
        )
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert "Lateral" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_timeline_summary(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes timeline summary."""
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert "Timeline" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_confidence_assessment(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback includes confidence assessment."""
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        assert "Confidence" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_technique_without_name(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback handles technique without name in technique_names."""
        populated_investigation_state.attack_synopsis = ""  # Clear to trigger generation
        populated_investigation_state.identified_techniques.add("T9999")  # Unknown technique
        # Don't add T9999 to technique_names so it falls back to just the ID
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        # Should include the technique ID without name
        assert "T9999" in populated_investigation_state.attack_synopsis

    def test_fallback_synopsis_many_hosts(
        self, completion_tools: CompletionTools, populated_investigation_state: InvestigationState
    ):
        """Test fallback handles more than 5 hosts."""
        populated_investigation_state.attack_synopsis = ""  # Clear to trigger generation
        # Add many hosts (more than 5)
        populated_investigation_state.queried_hosts = {
            "host1.domain.local",
            "host2.domain.local",
            "host3.domain.local",
            "host4.domain.local",
            "host5.domain.local",
            "host6.domain.local",
            "host7.domain.local",
        }
        completion_tools.set_state(populated_investigation_state)
        completion_tools._generate_fallback_synopsis()
        # Should include "and X more" text
        assert "and 2 more" in populated_investigation_state.attack_synopsis


class TestEscalateInvestigation:
    """Tests for escalate_investigation function."""

    @pytest.mark.asyncio
    async def test_escalate_basic(self):
        """Test basic escalation."""
        result = await escalate_investigation(
            reason="Active attack in progress",
            severity="critical",
            current_findings="Attacker has domain admin access",
            immediate_actions=["Isolate network", "Reset passwords"],
        )
        assert "escalated" in result.lower()
        assert "critical" in result.lower()

    @pytest.mark.asyncio
    async def test_escalate_high_severity(self):
        """Test high severity escalation."""
        result = await escalate_investigation(
            reason="Suspicious activity detected",
            severity="high",
            current_findings="Multiple failed login attempts",
            immediate_actions=["Monitor closely"],
        )
        assert "escalated" in result.lower()
        assert "high" in result.lower()

    @pytest.mark.asyncio
    async def test_escalate_medium_severity(self):
        """Test medium severity escalation."""
        result = await escalate_investigation(
            reason="Needs human review",
            severity="medium",
            current_findings="Uncertain about scope",
            immediate_actions=["Review logs"],
        )
        assert "escalated" in result.lower()
        assert "medium" in result.lower()

    @pytest.mark.asyncio
    async def test_escalate_with_empty_actions(self):
        """Test escalation with empty actions list."""
        result = await escalate_investigation(
            reason="Need help",
            severity="high",
            current_findings="Complex situation",
            immediate_actions=[],
        )
        assert "escalated" in result.lower()


class TestCompletionToolsEdgeCases:
    """Edge case tests for CompletionTools."""

    @pytest.fixture
    def completion_tools(self) -> CompletionTools:
        return CompletionTools()

    @pytest.mark.asyncio
    async def test_complete_early_stage(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test completing at early stage."""
        investigation_state.stage = InvestigationStage.TRIAGE
        completion_tools.set_state(investigation_state)
        result = await completion_tools.complete_investigation(
            summary="Early completion",
            attack_synopsis="Quick resolution",
            recommendations=["Done"],
        )
        assert "completed" in result.lower()

    @pytest.mark.asyncio
    async def test_complete_synthesis_stage(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test completing at synthesis stage."""
        investigation_state.stage = InvestigationStage.SYNTHESIS
        completion_tools.set_state(investigation_state)
        result = await completion_tools.complete_investigation(
            summary="Full investigation complete",
            attack_synopsis="Comprehensive analysis done",
            recommendations=["All actions identified"],
        )
        assert "completed" in result.lower()

    @pytest.mark.asyncio
    async def test_complete_with_none_synopsis(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test completing with None synopsis."""
        completion_tools.set_state(investigation_state)
        result = await completion_tools.complete_investigation(
            summary="Test",
            attack_synopsis=None,
            recommendations=None,
        )
        assert "completed" in result.lower()

    @pytest.mark.asyncio
    async def test_complete_with_long_synopsis(
        self, completion_tools: CompletionTools, investigation_state: InvestigationState
    ):
        """Test completing with very long synopsis."""
        completion_tools.set_state(investigation_state)
        long_synopsis = "A" * 10000  # Very long synopsis
        result = await completion_tools.complete_investigation(
            summary="Test",
            attack_synopsis=long_synopsis,
            recommendations=["Action"],
        )
        assert "completed" in result.lower()
        assert investigation_state.attack_synopsis == long_synopsis
