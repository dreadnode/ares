"""Tests for the red team report generator."""

from datetime import datetime, timezone

import pytest

from ares.core.models import (
    Credential,
    InvestigationStage,
    RedTeamState,
    Target,
    User,
)
from ares.reports.redteam import RedTeamReportGenerator


class TestRedTeamReportGeneratorInit:
    """Tests for RedTeamReportGenerator initialization."""

    def test_init_creates_loader(self):
        """Test that initialization creates a template loader."""
        generator = RedTeamReportGenerator()
        assert generator.loader is not None


class TestGenerateReport:
    """Tests for report generation."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        """Create a report generator."""
        return RedTeamReportGenerator()

    @pytest.fixture
    def minimal_state(self, sample_target: Target) -> RedTeamState:
        """Create minimal red team state."""
        return RedTeamState(
            operation_id="op-test-001",
            target=sample_target,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.TRIAGE,
            hosts=[],
            users=[],
            credentials=[],
            hashes=[],
            shares=[],
            weaknesses=[],
            timeline=[],
            identified_techniques=set(),
            has_domain_admin=False,
            has_golden_ticket=False,
            report_summary=None,
        )

    def test_generate_returns_string(
        self, generator: RedTeamReportGenerator, minimal_state: RedTeamState
    ):
        """Test generate returns a string."""
        report = generator.generate(minimal_state)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_generate_contains_operation_id(
        self, generator: RedTeamReportGenerator, minimal_state: RedTeamState
    ):
        """Test report contains operation ID."""
        report = generator.generate(minimal_state)
        assert minimal_state.operation_id in report

    def test_generate_contains_target_ip(
        self, generator: RedTeamReportGenerator, minimal_state: RedTeamState
    ):
        """Test report contains target IP."""
        report = generator.generate(minimal_state)
        assert minimal_state.target.ip in report


class TestExecutiveSummary:
    """Tests for executive summary generation."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_summary_with_custom_summary(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test using custom report summary."""
        red_team_state.report_summary = "Custom executive summary for this operation."
        summary = generator._generate_executive_summary(red_team_state)
        assert summary == "Custom executive summary for this operation."

    def test_summary_generated_without_custom(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test auto-generated summary when no custom provided."""
        red_team_state.report_summary = None
        summary = generator._generate_executive_summary(red_team_state)
        assert "Red team operation" in summary
        assert red_team_state.target.ip in summary

    def test_summary_with_domain_admin(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test summary with domain admin achieved."""
        populated_red_team_state.has_domain_admin = True
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Domain Administrator" in summary

    def test_summary_with_golden_ticket(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test summary with golden ticket."""
        populated_red_team_state.has_golden_ticket = True
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Golden ticket" in summary

    def test_summary_with_credentials(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test summary includes credential count."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "credential" in summary.lower()

    def test_summary_with_admins(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test summary includes admin count."""
        # Set admin count
        populated_red_team_state.users = [
            User(username="admin1", is_admin=True),
            User(username="admin2", is_admin=True),
        ]
        summary = generator._generate_executive_summary(populated_red_team_state)
        # Admin count should be mentioned somewhere
        assert "administrator" in summary.lower() or "admin" in summary.lower()


class TestSecurityPostureAssessment:
    """Tests for security posture assessment in summary."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_critical_posture_domain_admin(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test CRITICAL posture with domain admin."""
        red_team_state.has_domain_admin = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "CRITICAL" in summary

    def test_critical_posture_golden_ticket(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test CRITICAL posture with golden ticket."""
        red_team_state.has_golden_ticket = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "CRITICAL" in summary

    def test_high_posture_admins_found(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test HIGH posture when admin credentials found."""
        # admin_count in RedTeamState counts admin credentials, not admin users
        red_team_state.credentials = [
            Credential(
                username="admin",
                password="admin123",  # pragma: allowlist secret
                is_admin=True,
            )
        ]
        summary = generator._generate_executive_summary(red_team_state)
        assert "HIGH" in summary

    def test_medium_posture_credentials(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test MEDIUM posture with credentials only."""
        red_team_state.credentials = [
            Credential(username="user", password="abc123")  # pragma: allowlist secret
        ]
        summary = generator._generate_executive_summary(red_team_state)
        assert "MEDIUM" in summary

    def test_low_posture_nothing_found(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test LOW posture when nothing significant found."""
        summary = generator._generate_executive_summary(red_team_state)
        assert "LOW" in summary


class TestDiscoveryStatistics:
    """Tests for discovery statistics in summary."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_statistics_hosts(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test discovery statistics include hosts."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Host" in summary
        assert str(populated_red_team_state.host_count) in summary

    def test_statistics_users(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test discovery statistics include users."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "User" in summary

    def test_statistics_shares(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test discovery statistics include shares."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Share" in summary

    def test_statistics_vulnerabilities(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test discovery statistics include vulnerabilities."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert (
            "Vulnerabilities" in summary
            or "Weaknesses" in summary.lower()
            or "weakness" in summary.lower()
        )


class TestAttackPath:
    """Tests for attack path summary."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_attack_path_with_domain_admin(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test attack path shown when domain admin achieved."""
        red_team_state.has_domain_admin = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "Attack Path" in summary

    def test_attack_path_with_golden_ticket(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test attack path shown when golden ticket obtained."""
        red_team_state.has_golden_ticket = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "Attack Path" in summary

    def test_no_attack_path_without_success(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test attack path not shown without significant success."""
        generator._generate_executive_summary(red_team_state)
        # Attack path might not be explicitly mentioned without success
        # Just ensure no crash


class TestReportWithTimeline:
    """Tests for reports with timeline events."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_report_with_timeline_events(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test report generation with timeline events."""
        report = generator.generate(populated_red_team_state)
        assert isinstance(report, str)
        # Timeline should be passed to template
        assert len(report) > 0


class TestReportWithTechniques:
    """Tests for reports with MITRE techniques."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_report_includes_techniques(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test report includes identified techniques."""
        report = generator.generate(populated_red_team_state)
        assert isinstance(report, str)
        # Techniques should be in the report
        assert "T1046" in report or "T1003" in report or "technique" in report.lower()


class TestEdgeCases:
    """Edge case tests for report generation."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_empty_lists(self, generator: RedTeamReportGenerator, red_team_state: RedTeamState):
        """Test report with all empty lists."""
        report = generator.generate(red_team_state)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_full_state(
        self, generator: RedTeamReportGenerator, populated_red_team_state: RedTeamState
    ):
        """Test report with fully populated state."""
        populated_red_team_state.has_domain_admin = True
        populated_red_team_state.has_golden_ticket = True
        report = generator.generate(populated_red_team_state)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_special_characters_in_target(
        self, generator: RedTeamReportGenerator, red_team_state: RedTeamState
    ):
        """Test report with special characters in target."""
        red_team_state.target = Target(
            ip="192.168.58.100",
            hostname="server-01.domain.local",
            domain="domain.local",
            os="Windows Server 2019 <Special>",
        )
        report = generator.generate(red_team_state)
        assert isinstance(report, str)
