"""Tests for the blue team consolidated report generator."""

from datetime import datetime, timedelta, timezone

import pytest

from ares.core.lateral_analyzer import LateralGraph
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
    TimelineEvent,
)
from ares.reports.blueteam import (
    BlueTeamOperation,
    BlueTeamReportGenerator,
    create_operation_from_investigations,
    generate_operation_report,
)


@pytest.fixture
def sample_alert() -> dict:
    """Create a sample alert for testing."""
    return {
        "labels": {
            "alertname": "DCSync_Attack_Detected",
            "severity": "critical",
            "instance": "dc01.contoso.local:9100",
        },
        "annotations": {
            "summary": "Potential DCSync attack detected",
        },
        "startsAt": "2026-02-18T10:00:00Z",
    }


@pytest.fixture
def sample_investigation_state(sample_alert: dict) -> InvestigationState:
    """Create a sample investigation state."""
    return InvestigationState(
        investigation_id="inv-test-001",
        alert=sample_alert,
        started_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        stage=InvestigationStage.SYNTHESIS,
        evidence=[
            Evidence(
                id="ev-001",
                type="ip",
                value="192.168.58.10",
                source="loki_query",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=["T1003.006"],
                confidence=0.9,
            ),
            Evidence(
                id="ev-002",
                type="tool",
                value="mimikatz.exe",
                source="process_analysis",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.TOOLS,
                mitre_techniques=["T1003"],
                confidence=0.95,
            ),
        ],
        timeline=[
            TimelineEvent(
                id="evt-001",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=25),
                description="DCSync replication request detected",
                mitre_techniques=["T1003.006"],
                confidence=0.9,
                source="investigation",
            ),
        ],
        questions=[],
        identified_techniques={"T1003.006", "T1003"},
        identified_tactics={"credential-access"},
        technique_names={
            "T1003.006": "DCSync",
            "T1003": "OS Credential Dumping",
        },
        technique_to_tactic={
            "T1003.006": "credential-access",
            "T1003": "credential-access",
        },
        queried_hosts={"dc01.contoso.local", "ws01.contoso.local"},
        queried_users={"admin", "svc_backup"},
        executed_queries=[{"type": "loki", "query": "test query", "result_count": 10}],
        escalated=False,
        escalation_reason=None,
        attack_synopsis="DCSync attack detected targeting domain controller.",
        recommendations=["Reset affected passwords", "Review DC access logs"],
        lateral_graph=LateralGraph(),
    )


@pytest.fixture
def second_investigation_state() -> InvestigationState:
    """Create a second investigation state for multi-investigation tests."""
    return InvestigationState(
        investigation_id="inv-test-002",
        alert={
            "labels": {
                "alertname": "Kerberoasting_Detected",
                "severity": "high",
            },
        },
        started_at=datetime.now(timezone.utc) - timedelta(minutes=15),
        stage=InvestigationStage.SYNTHESIS,
        evidence=[
            Evidence(
                id="ev-003",
                type="hash",
                value="$krb5tgs$23$*svc_sql$CONTOSO.LOCAL*",
                source="kerberos_logs",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.HASH_VALUES,
                mitre_techniques=["T1558.003"],
                confidence=0.85,
            ),
        ],
        timeline=[],
        questions=[],
        identified_techniques={"T1558.003"},
        identified_tactics={"credential-access"},
        technique_names={"T1558.003": "Kerberoasting"},
        technique_to_tactic={"T1558.003": "credential-access"},
        queried_hosts={"sql01.contoso.local"},
        queried_users={"svc_sql"},
        executed_queries=[],
        escalated=True,
        escalation_reason="Multiple service accounts targeted",
        attack_synopsis=None,
        recommendations=["Rotate service account passwords"],
        lateral_graph=LateralGraph(),
    )


class TestBlueTeamOperation:
    """Tests for BlueTeamOperation class."""

    def test_create_empty_operation(self):
        """Test creating an empty operation."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        assert operation.operation_id == "test-op-001"
        assert len(operation.investigations) == 0
        assert len(operation.all_evidence) == 0

    def test_add_investigation(self, sample_investigation_state: InvestigationState):
        """Test adding an investigation to an operation."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)

        assert len(operation.investigations) == 1
        assert len(operation.all_evidence) == 2
        assert "T1003.006" in operation.all_techniques

    def test_all_evidence_deduplication(self, sample_investigation_state: InvestigationState):
        """Test that evidence is deduplicated across investigations."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)
        # Add same investigation again
        operation.add_investigation(sample_investigation_state)

        # Should have same evidence count (deduplicated)
        assert len(operation.all_evidence) == 2

    def test_all_techniques_aggregation(
        self,
        sample_investigation_state: InvestigationState,
        second_investigation_state: InvestigationState,
    ):
        """Test that techniques are aggregated across investigations."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)
        operation.add_investigation(second_investigation_state)

        # Should have techniques from both investigations
        assert "T1003.006" in operation.all_techniques
        assert "T1558.003" in operation.all_techniques

    def test_highest_pyramid_level(self, sample_investigation_state: InvestigationState):
        """Test highest pyramid level calculation."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)

        # Sample has TOOLS level (5) evidence
        assert operation.highest_pyramid_level == 5

    def test_escalation_count(
        self,
        sample_investigation_state: InvestigationState,
        second_investigation_state: InvestigationState,
    ):
        """Test escalation counting."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)  # Not escalated
        operation.add_investigation(second_investigation_state)  # Escalated

        assert operation.escalation_count == 1

    def test_all_recommendations(
        self,
        sample_investigation_state: InvestigationState,
        second_investigation_state: InvestigationState,
    ):
        """Test recommendation aggregation."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)
        operation.add_investigation(second_investigation_state)

        recs = operation.all_recommendations
        assert "Reset affected passwords" in recs
        assert "Rotate service account passwords" in recs

    def test_pyramid_distribution(self, sample_investigation_state: InvestigationState):
        """Test pyramid level distribution."""
        operation = BlueTeamOperation(operation_id="test-op-001")
        operation.add_investigation(sample_investigation_state)

        dist = operation.get_pyramid_distribution()
        assert dist[PyramidLevel.IP_ADDRESSES] == 1
        assert dist[PyramidLevel.TOOLS] == 1


class TestCreateOperationFromInvestigations:
    """Tests for create_operation_from_investigations function."""

    def test_creates_operation(self, sample_investigation_state: InvestigationState):
        """Test operation creation from investigations."""
        operation = create_operation_from_investigations(
            [sample_investigation_state],
            operation_id="custom-op-001",
        )

        assert operation.operation_id == "custom-op-001"
        assert len(operation.investigations) == 1

    def test_auto_generates_operation_id(self, sample_investigation_state: InvestigationState):
        """Test auto-generation of operation ID."""
        operation = create_operation_from_investigations([sample_investigation_state])

        assert operation.operation_id.startswith("blue-op-")

    def test_empty_investigations_raises(self):
        """Test that empty investigations list raises error."""
        with pytest.raises(ValueError, match="At least one investigation"):
            create_operation_from_investigations([])

    def test_sets_time_bounds(self, sample_investigation_state: InvestigationState):
        """Test that time bounds are set correctly."""
        operation = create_operation_from_investigations([sample_investigation_state])

        assert operation.started_at == sample_investigation_state.started_at
        assert operation.completed_at is not None


class TestBlueTeamReportGenerator:
    """Tests for BlueTeamReportGenerator class."""

    def test_generate_report(self, sample_investigation_state: InvestigationState):
        """Test report generation."""
        operation = create_operation_from_investigations([sample_investigation_state])
        generator = BlueTeamReportGenerator()

        report = generator.generate(operation)

        assert "# Blue Team Operation Report" in report
        assert operation.operation_id in report

    def test_report_contains_executive_summary(
        self, sample_investigation_state: InvestigationState
    ):
        """Test that report contains executive summary."""
        operation = create_operation_from_investigations([sample_investigation_state])
        report = generate_operation_report(operation)

        assert "## Executive Summary" in report
        assert "Evidence Collected" in report

    def test_report_contains_mitre_mapping(self, sample_investigation_state: InvestigationState):
        """Test that report contains MITRE mapping."""
        operation = create_operation_from_investigations([sample_investigation_state])
        report = generate_operation_report(operation)

        assert "## MITRE ATT&CK Coverage" in report
        assert "T1003.006" in report

    def test_report_contains_evidence_inventory(
        self, sample_investigation_state: InvestigationState
    ):
        """Test that report contains evidence inventory."""
        operation = create_operation_from_investigations([sample_investigation_state])
        report = generate_operation_report(operation)

        assert "## Evidence Inventory" in report
        assert "192.168.58.10" in report

    def test_report_contains_recommendations(self, sample_investigation_state: InvestigationState):
        """Test that report contains recommendations."""
        operation = create_operation_from_investigations([sample_investigation_state])
        report = generate_operation_report(operation)

        assert "## Recommendations" in report
        assert "Reset affected passwords" in report

    def test_report_contains_attack_synopsis(self, sample_investigation_state: InvestigationState):
        """Test that report contains attack synopsis."""
        operation = create_operation_from_investigations([sample_investigation_state])
        report = generate_operation_report(operation)

        assert "DCSync attack detected" in report

    def test_report_shows_escalations(self, second_investigation_state: InvestigationState):
        """Test that escalations are shown in report."""
        operation = create_operation_from_investigations([second_investigation_state])
        report = generate_operation_report(operation)

        assert "ESCALATIONS REQUIRED" in report or "Escalation" in report

    def test_multi_investigation_report(
        self,
        sample_investigation_state: InvestigationState,
        second_investigation_state: InvestigationState,
    ):
        """Test report with multiple investigations."""
        operation = create_operation_from_investigations(
            [sample_investigation_state, second_investigation_state]
        )
        report = generate_operation_report(operation)

        # Should include data from both investigations
        assert "DCSync_Attack_Detected" in report
        assert "Kerberoasting_Detected" in report
        assert "| Investigations | 2 |" in report


class TestGenerateOperationReport:
    """Tests for generate_operation_report convenience function."""

    def test_generates_valid_markdown(self, sample_investigation_state: InvestigationState):
        """Test that generated report is valid markdown."""
        operation = create_operation_from_investigations([sample_investigation_state])
        report = generate_operation_report(operation)

        # Check markdown structure
        assert report.startswith("# ")
        assert "---" in report  # Section separators
        assert "|" in report  # Tables
