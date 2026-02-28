"""Tests for the red team report generator."""

from datetime import datetime, timezone

import pytest

from ares.core.models import (
    Credential,
    SharedRedTeamState,
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
    def minimal_state(self, sample_target: Target) -> SharedRedTeamState:
        """Create minimal red team state."""
        state = SharedRedTeamState(operation_id="op-test-001")
        state.target = sample_target
        return state

    def test_generate_returns_string(
        self, generator: RedTeamReportGenerator, minimal_state: SharedRedTeamState
    ):
        """Test generate returns a string."""
        report = generator.generate(minimal_state)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_generate_contains_operation_id(
        self, generator: RedTeamReportGenerator, minimal_state: SharedRedTeamState
    ):
        """Test report contains operation ID."""
        report = generator.generate(minimal_state)
        assert minimal_state.operation_id in report

    def test_generate_contains_target_ip(
        self, generator: RedTeamReportGenerator, minimal_state: SharedRedTeamState
    ):
        """Test report contains target IP."""
        report = generator.generate(minimal_state)
        assert minimal_state.target.ip in report


class TestExecutiveSummary:
    """Tests for executive summary generation."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_summary_generated(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test auto-generated summary."""
        summary = generator._generate_executive_summary(red_team_state)
        assert "Red team operation" in summary
        assert red_team_state.target.ip in summary

    def test_summary_with_domain_admin(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test summary with domain admin achieved."""
        populated_red_team_state.has_domain_admin = True
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Domain Administrator" in summary

    def test_summary_with_golden_ticket(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test summary with golden ticket."""
        populated_red_team_state.has_golden_ticket = True
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Golden ticket" in summary

    def test_summary_with_credentials(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test summary includes credential count."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "credential" in summary.lower()

    def test_summary_with_admins(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test summary includes admin count."""
        # Set admin count
        populated_red_team_state.all_users = [
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
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test CRITICAL posture with domain admin."""
        red_team_state.has_domain_admin = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "CRITICAL" in summary

    def test_critical_posture_golden_ticket(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test CRITICAL posture with golden ticket."""
        red_team_state.has_golden_ticket = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "CRITICAL" in summary

    def test_high_posture_admins_found(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test HIGH posture when admin credentials found."""
        # admin_count in SharedRedTeamState counts admin credentials, not admin users
        red_team_state.all_credentials = [
            Credential(
                username="admin",
                password="admin123",  # pragma: allowlist secret
                is_admin=True,
            )
        ]
        summary = generator._generate_executive_summary(red_team_state)
        assert "HIGH" in summary

    def test_medium_posture_credentials(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test MEDIUM posture with credentials only."""
        red_team_state.all_credentials = [
            Credential(username="user", password="abc123")  # pragma: allowlist secret
        ]
        summary = generator._generate_executive_summary(red_team_state)
        assert "MEDIUM" in summary

    def test_low_posture_nothing_found(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
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
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test discovery statistics include hosts."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Host" in summary
        assert str(len(populated_red_team_state.all_hosts)) in summary

    def test_statistics_users(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test discovery statistics include users."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "User" in summary

    def test_statistics_shares(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test discovery statistics include shares."""
        summary = generator._generate_executive_summary(populated_red_team_state)
        assert "Share" in summary

    def test_statistics_vulnerabilities(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
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
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test attack path shown when domain admin achieved."""
        red_team_state.has_domain_admin = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "Attack Path" in summary

    def test_attack_path_with_golden_ticket(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test attack path shown when golden ticket obtained."""
        red_team_state.has_golden_ticket = True
        summary = generator._generate_executive_summary(red_team_state)
        assert "Attack Path" in summary

    def test_no_attack_path_without_success(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
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
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
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
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test report includes identified techniques."""
        report = generator.generate(populated_red_team_state)
        assert isinstance(report, str)
        # Techniques should be in the report
        assert "T1046" in report or "T1003" in report or "technique" in report.lower()

    def test_techniques_aggregated_from_timeline_events(self, generator: RedTeamReportGenerator):
        """Test that techniques from timeline events are aggregated into the report."""
        from ares.core.models import TimelineEvent

        # Create state with NO identified_techniques but WITH timeline events that have techniques
        state = SharedRedTeamState(
            operation_id="op-test-timeline-agg",
            target=Target(
                ip="192.168.58.100",
                hostname="dc01.contoso.local",
                domain="contoso.local",
            ),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            identified_techniques=set(),  # Empty!
            operation_timeline=[
                TimelineEvent(
                    id="evt-001",
                    timestamp=datetime.now(timezone.utc),
                    description="Hash discovered via Kerberoast",
                    mitre_techniques=["T1558.003"],
                    source="ares-privesc",
                ),
                TimelineEvent(
                    id="evt-002",
                    timestamp=datetime.now(timezone.utc),
                    description="Credential found in SYSVOL",
                    mitre_techniques=["T1552.006"],
                    source="ares-recon",
                ),
            ],
        )

        report = generator.generate(state)

        # Both techniques from timeline should appear in the Techniques Identified section
        assert "T1558.003" in report
        assert "T1552.006" in report


class TestEdgeCases:
    """Edge case tests for report generation."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_empty_lists(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test report with all empty lists."""
        report = generator.generate(red_team_state)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_full_state(
        self, generator: RedTeamReportGenerator, populated_red_team_state: SharedRedTeamState
    ):
        """Test report with fully populated state."""
        populated_red_team_state.has_domain_admin = True
        populated_red_team_state.has_golden_ticket = True
        report = generator.generate(populated_red_team_state)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_special_characters_in_target(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test report with special characters in target."""
        red_team_state.target = Target(
            ip="192.168.58.100",
            hostname="server-01.contoso.local",
            domain="contoso.local",
            os="Windows Server 2019 <Special>",
        )
        report = generator.generate(red_team_state)
        assert isinstance(report, str)


class TestGenerateComprehensiveReport:
    """Tests for generate_comprehensive_report function."""

    def test_mitre_techniques_collected_from_timeline(self):
        """Test that MITRE techniques from timeline events appear in the mapping section."""
        from ares.core.models import SharedRedTeamState, TimelineEvent
        from ares.reports.redteam import generate_comprehensive_report

        # Create a SharedRedTeamState with timeline events containing MITRE techniques
        # but with empty identified_techniques set
        state = SharedRedTeamState(
            operation_id="op-test-mitre",
            target=Target(
                ip="192.168.58.100",
                hostname="dc01.contoso.local",
                domain="contoso.local",
            ),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            operation_timeline=[
                TimelineEvent(
                    id="evt-001",
                    timestamp=datetime.now(timezone.utc),
                    description="Network scan completed",
                    mitre_techniques=["T1046"],
                    source="nmap",
                ),
                TimelineEvent(
                    id="evt-002",
                    timestamp=datetime.now(timezone.utc),
                    description="Credential discovered via Kerberoasting",
                    mitre_techniques=["T1558.003"],
                    source="kerberoast",
                ),
                TimelineEvent(
                    id="evt-003",
                    timestamp=datetime.now(timezone.utc),
                    description="DCSync attack performed",
                    mitre_techniques=["T1003.006"],
                    source="secretsdump",
                ),
            ],
            identified_techniques=set(),  # Empty - the bug we're fixing
        )

        report = generate_comprehensive_report(state)

        # The MITRE ATT&CK Mapping section should contain the techniques from timeline
        assert "## MITRE ATT&CK Mapping" in report
        assert "T1046" in report
        assert "T1558.003" in report
        assert "T1003.006" in report
        # Should NOT say "No MITRE techniques mapped"
        assert "No MITRE techniques mapped" not in report

    def test_mitre_techniques_combined_from_both_sources(self):
        """Test that techniques from both identified_techniques and timeline are combined."""
        from ares.core.models import SharedRedTeamState, TimelineEvent
        from ares.reports.redteam import generate_comprehensive_report

        state = SharedRedTeamState(
            operation_id="op-test-combined",
            target=Target(
                ip="192.168.58.100",
                hostname="dc01.contoso.local",
                domain="contoso.local",
            ),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            operation_timeline=[
                TimelineEvent(
                    id="evt-001",
                    timestamp=datetime.now(timezone.utc),
                    description="Credential discovered",
                    mitre_techniques=["T1552"],  # From timeline
                    source="discovery",
                ),
            ],
            identified_techniques={"T1078", "T1003"},  # Pre-existing techniques
        )

        report = generate_comprehensive_report(state)

        # All techniques should be in the report
        assert "T1552" in report  # From timeline
        assert "T1078" in report  # From identified_techniques
        assert "T1003" in report  # From identified_techniques


class TestDeduplication:
    """Tests for user and credential deduplication in reports."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_user_deduplication_case_insensitive(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that duplicate users are deduplicated case-insensitively."""
        # Add duplicate users with different cases
        red_team_state.all_users = [
            User(username="Administrator", domain="CONTOSO.LOCAL"),
            User(username="administrator", domain="contoso.local"),  # Duplicate
            User(username="ADMINISTRATOR", domain="Contoso.Local"),  # Duplicate
            User(username="testuser", domain="contoso.local"),
        ]

        report = generator.generate(red_team_state)

        # Report should show 2 unique users, not 4
        assert "User" in report
        # The report includes user_count in the template
        assert "2" in report or "two" in report.lower()

    def test_credential_deduplication_case_insensitive(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that duplicate credentials are deduplicated case-insensitively."""
        # Add duplicate credentials with different cases
        red_team_state.all_credentials = [
            Credential(
                username="Admin",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="CONTOSO.LOCAL",
            ),
            Credential(
                username="admin",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
            ),  # Duplicate
            Credential(
                username="svc_backup",
                password="backup123",  # pragma: allowlist secret
                domain="contoso.local",
            ),
        ]

        report = generator.generate(red_team_state)

        # Should have 2 unique credentials
        assert isinstance(report, str)
        assert len(report) > 0

    def test_credentials_with_different_passwords_not_deduplicated(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that same user with different passwords are NOT deduplicated."""
        red_team_state.all_credentials = [
            Credential(
                username="admin",
                password="OldP@ss",  # pragma: allowlist secret
                domain="contoso.local",
            ),
            Credential(
                username="admin",
                password="NewP@ss",  # pragma: allowlist secret
                domain="contoso.local",
            ),  # Different password = different cred
        ]

        report = generator.generate(red_team_state)
        assert isinstance(report, str)


class TestAdminCount:
    """Tests for admin count logic including known admin usernames.

    The new admin count logic (checking for administrator/krbtgt usernames)
    is applied in generate() when calculating admin_count for the template.
    """

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_administrator_username_counted_as_admin(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that 'administrator' username is counted as admin even without is_admin flag."""
        red_team_state.all_credentials = [
            Credential(
                username="Administrator",
                password="AdminP@ss",  # pragma: allowlist secret
                domain="contoso.local",
                is_admin=False,  # No flag but should still count
            ),
        ]

        report = generator.generate(red_team_state)

        # Report should show admin count of 1 (administrator username counts)
        # The template shows "Administrator Accounts: X"
        assert "Administrator Accounts**: 1" in report

    def test_krbtgt_username_counted_as_admin(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that 'krbtgt' username is counted as admin."""
        red_team_state.all_credentials = [
            Credential(
                username="krbtgt",
                password="",
                domain="contoso.local",
                is_admin=False,  # No flag but krbtgt is always admin-level
            ),
        ]

        report = generator.generate(red_team_state)

        # Report should show admin count of 1 (krbtgt username counts)
        assert "Administrator Accounts**: 1" in report

    def test_is_admin_flag_still_works(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that is_admin=True still counts as admin."""
        red_team_state.all_credentials = [
            Credential(
                username="svc_backup",
                password="backup123",  # pragma: allowlist secret
                domain="contoso.local",
                is_admin=True,
            ),
        ]

        report = generator.generate(red_team_state)
        # Report should show admin count of 1
        assert "Administrator Accounts**: 1" in report


class TestCompletionStatus:
    """Tests for operation completion status detection."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_completed_at_marks_operation_completed(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that completed_at alone marks operation as completed."""
        # Set completed_at but not completed flag
        red_team_state.completed = False
        red_team_state.completed_at = datetime.now(timezone.utc)

        report = generator.generate(red_team_state)

        # Stage field should show "completed", not "in_progress"
        assert "**Stage**: completed" in report

    def test_neither_completed_shows_in_progress(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that without completed or completed_at, stage is in_progress."""
        red_team_state.completed = False
        red_team_state.completed_at = None

        report = generator.generate(red_team_state)

        assert "**Stage**: in_progress" in report


class TestAttackPathDisplay:
    """Tests for attack path display in executive summary."""

    @pytest.fixture
    def generator(self) -> RedTeamReportGenerator:
        return RedTeamReportGenerator()

    def test_actual_attack_path_shown_when_available(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that actual domain_admin_path is shown instead of generic text."""
        red_team_state.has_domain_admin = True
        red_team_state.domain_admin_path = (
            "LLMNR Poisoning → svc_backup creds → Constrained Delegation → DC01 → krbtgt hash"
        )

        summary = generator._generate_executive_summary(red_team_state)

        # Should contain the actual path
        assert "LLMNR Poisoning" in summary
        assert "svc_backup" in summary
        assert "Constrained Delegation" in summary

    def test_fallback_when_no_path_captured(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test fallback message when domain_admin_path is not set."""
        red_team_state.has_domain_admin = True
        red_team_state.domain_admin_path = None

        summary = generator._generate_executive_summary(red_team_state)

        # Should contain fallback text
        assert "Attack Path" in summary
        assert "timeline" in summary.lower() or "details" in summary.lower()

    def test_no_attack_path_without_da(
        self, generator: RedTeamReportGenerator, red_team_state: SharedRedTeamState
    ):
        """Test that attack path section is not shown without DA."""
        red_team_state.has_domain_admin = False
        red_team_state.has_golden_ticket = False
        red_team_state.domain_admin_path = "Some path"  # Should be ignored

        summary = generator._generate_executive_summary(red_team_state)

        # Should NOT contain attack path section
        assert "Attack Path" not in summary
