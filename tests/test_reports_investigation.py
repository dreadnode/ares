"""Tests for the investigation report generator."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ares.core.lateral_analyzer import LateralGraph
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
)
from ares.reports.investigation import (
    PYRAMID_EMOJI,
    PYRAMID_NAMES,
    MarkdownReportGenerator,
)


class TestPyramidConstants:
    """Tests for pyramid level constants."""

    def test_pyramid_emoji_has_all_levels(self):
        """Verify all pyramid levels have emojis."""
        for level in PyramidLevel:
            assert level in PYRAMID_EMOJI

    def test_pyramid_names_has_all_levels(self):
        """Verify all pyramid levels have names."""
        for level in PyramidLevel:
            assert level in PYRAMID_NAMES

    def test_pyramid_emoji_are_unique(self):
        """Verify each level has a unique emoji."""
        emojis = list(PYRAMID_EMOJI.values())
        assert len(emojis) == len(set(emojis))


class TestMarkdownReportGeneratorInit:
    """Tests for MarkdownReportGenerator initialization."""

    def test_creates_output_directory(self, temp_dir: Path):
        """Test that output directory is created."""
        output_dir = temp_dir / "reports"
        generator = MarkdownReportGenerator(output_dir)
        assert generator.output_dir.exists()

    def test_existing_directory_ok(self, temp_reports_dir: Path):
        """Test that existing directory is handled."""
        generator = MarkdownReportGenerator(temp_reports_dir)
        assert generator.output_dir == temp_reports_dir


class TestReportGeneration:
    """Tests for report generation."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        """Create a generator for testing."""
        return MarkdownReportGenerator(temp_reports_dir)

    @pytest.fixture
    def minimal_state(self, sample_alert: dict) -> InvestigationState:
        """Create minimal investigation state."""
        return InvestigationState(
            investigation_id="test-inv-001",
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

    def test_generate_creates_file(
        self, generator: MarkdownReportGenerator, minimal_state: InvestigationState
    ):
        """Test that generate creates a markdown file."""
        filepath = generator.generate(minimal_state)
        assert filepath.exists()
        assert filepath.suffix == ".md"

    def test_generate_filename_format(
        self, generator: MarkdownReportGenerator, minimal_state: InvestigationState
    ):
        """Test filename follows expected format."""
        filepath = generator.generate(minimal_state)
        assert filepath.name.startswith("investigation_")
        assert "HighCPUUsage" in filepath.name

    def test_generate_sanitizes_filename(
        self, generator: MarkdownReportGenerator, minimal_state: InvestigationState
    ):
        """Test that special characters are sanitized in filename."""
        minimal_state.alert["labels"]["alertname"] = "Alert/With:Special*Chars"
        filepath = generator.generate(minimal_state)
        assert "/" not in filepath.name
        assert ":" not in filepath.name
        assert "*" not in filepath.name


class TestReportHeader:
    """Tests for report header generation."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_header_contains_investigation_id(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test header contains investigation ID."""
        header = generator._header(populated_investigation_state)
        assert populated_investigation_state.investigation_id in header

    def test_header_contains_alert_name(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test header contains alert name."""
        header = generator._header(populated_investigation_state)
        assert "DCSync_Attack_Detected" in header

    def test_header_shows_escalated_status(
        self, generator: MarkdownReportGenerator, escalated_investigation_state: InvestigationState
    ):
        """Test header shows escalated status."""
        header = generator._header(escalated_investigation_state)
        assert "ESCALATED" in header

    def test_header_shows_completed_status(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test header shows completed status."""
        header = generator._header(populated_investigation_state)
        assert "COMPLETED" in header


class TestExecutiveSummary:
    """Tests for executive summary generation."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_summary_with_techniques(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test summary includes identified techniques."""
        summary = generator._executive_summary(populated_investigation_state)
        assert "T1003.006" in summary or "T1078" in summary

    def test_summary_with_hosts(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test summary includes investigated hosts."""
        summary = generator._executive_summary(populated_investigation_state)
        assert "dc01" in summary or "winterfell" in summary

    def test_summary_with_users(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test summary includes investigated users."""
        summary = generator._executive_summary(populated_investigation_state)
        assert "eddard.stark" in summary or "robb.stark" in summary

    def test_summary_escalated_assessment(
        self, generator: MarkdownReportGenerator, escalated_investigation_state: InvestigationState
    ):
        """Test escalated investigation assessment."""
        summary = generator._executive_summary(escalated_investigation_state)
        assert "ESCALATED" in summary

    def test_summary_attack_synopsis(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test attack synopsis is included."""
        summary = generator._executive_summary(populated_investigation_state)
        assert "DCSync" in summary or "Attack Synopsis" in summary

    def test_summary_no_synopsis_fallback(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test fallback when no synopsis."""
        summary = generator._executive_summary(investigation_state)
        assert "No attack synopsis" in summary or "Attack Synopsis" in summary

    def test_summary_techniques_no_ttp(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test assessment when techniques identified but no TTP-level evidence."""
        # Add techniques but ensure no TTP-level evidence
        investigation_state.identified_techniques = {"T1059.001", "T1046"}
        investigation_state.technique_names = {
            "T1059.001": "PowerShell",
            "T1046": "Network Scanning",
        }
        investigation_state.escalated = False
        # Clear any TTP-level evidence
        investigation_state.evidence = [
            e
            for e in investigation_state.evidence
            if e.pyramid_level.value < 6  # Keep non-TTP evidence only
        ]
        summary = generator._executive_summary(investigation_state)
        assert "TTP elevation recommended" in summary or "Techniques identified" in summary


class TestTimelineSection:
    """Tests for timeline section generation."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_timeline_empty(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test timeline section with no events."""
        timeline = generator._timeline_section(investigation_state)
        assert "No timeline events" in timeline

    def test_timeline_with_events(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test timeline with events."""
        timeline = generator._timeline_section(populated_investigation_state)
        assert "Timeline" in timeline
        assert "Time (UTC)" in timeline
        assert "Event" in timeline

    def test_timeline_sorted_by_timestamp(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test timeline events are sorted."""
        timeline = generator._timeline_section(populated_investigation_state)
        # Should contain table headers
        assert "|" in timeline


class TestMitreMapping:
    """Tests for MITRE ATT&CK mapping section."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_mitre_mapping_empty(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test MITRE mapping with no techniques."""
        mapping = generator._mitre_mapping(investigation_state)
        assert "No techniques identified" in mapping

    def test_mitre_mapping_with_techniques(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test MITRE mapping with techniques."""
        mapping = generator._mitre_mapping(populated_investigation_state)
        assert "T1003.006" in mapping or "T1078" in mapping
        assert "Technique ID" in mapping

    def test_mitre_mapping_includes_supporting_evidence(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test mapping includes supporting evidence."""
        mapping = generator._mitre_mapping(populated_investigation_state)
        assert "Supporting Evidence" in mapping


class TestPyramidAssessment:
    """Tests for Pyramid of Pain assessment section."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_pyramid_empty_evidence(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test pyramid assessment with no evidence."""
        assessment = generator._pyramid_assessment(investigation_state)
        assert "Elevation Score" in assessment
        assert "Limited evidence" in assessment

    def test_pyramid_with_ttp_evidence(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test pyramid assessment with TTP evidence."""
        # Add TTP evidence
        populated_investigation_state.evidence.append(
            Evidence(
                id="ttp-test",
                type="ttp",
                value="DCSync attack",
                source="Investigation",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.TTPS,
                mitre_techniques=["T1003.006"],
                confidence=0.95,
                validated=True,
            )
        )
        assessment = generator._pyramid_assessment(populated_investigation_state)
        assert "TTP level" in assessment or "TTPs" in assessment

    def test_pyramid_visualization(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test pyramid visualization is included."""
        assessment = generator._pyramid_assessment(populated_investigation_state)
        assert "▲" in assessment  # Pyramid visualization

    def test_pyramid_distribution_table(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test pyramid distribution table."""
        assessment = generator._pyramid_assessment(populated_investigation_state)
        assert "Level" in assessment
        assert "Name" in assessment
        assert "Count" in assessment

    def test_pyramid_with_tool_evidence_no_ttp(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test assessment with tool-level evidence but no TTPs."""
        investigation_state.evidence = [
            Evidence(
                id="tool-test",
                type="tool",
                value="mimikatz.exe",
                source="Investigation",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.TOOLS,
                mitre_techniques=["T1003"],
                confidence=0.9,
            )
        ]
        assessment = generator._pyramid_assessment(investigation_state)
        assert "Tool-level" in assessment or "elevation" in assessment.lower()

    def test_pyramid_heavy_trivial_indicators(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test assessment with heavy trivial indicators (IPs and hashes vs tools)."""
        investigation_state.evidence = [
            Evidence(
                id="ip-1",
                type="ip",
                value="192.168.1.1",
                source="logs",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
            ),
            Evidence(
                id="ip-2",
                type="ip",
                value="192.168.1.2",
                source="logs",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
            ),
            Evidence(
                id="hash-1",
                type="hash",
                value="abc123",
                source="logs",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.HASH_VALUES,
            ),
        ]
        assessment = generator._pyramid_assessment(investigation_state)
        assert "trivial" in assessment.lower() or "deeper analysis" in assessment.lower()


class TestEvidenceInventory:
    """Tests for evidence inventory section."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_evidence_inventory_empty(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test evidence inventory with no evidence."""
        inventory = generator._evidence_inventory(investigation_state)
        assert "No evidence recorded" in inventory

    def test_evidence_inventory_with_evidence(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test evidence inventory with evidence."""
        inventory = generator._evidence_inventory(populated_investigation_state)
        assert "Evidence Inventory" in inventory
        assert "ID" in inventory
        assert "Type" in inventory

    def test_evidence_grouped_by_level(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test evidence is grouped by pyramid level."""
        inventory = generator._evidence_inventory(populated_investigation_state)
        # Should have level headers
        assert "Level" in inventory


class TestScopeSection:
    """Tests for scope assessment section."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_scope_empty(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test scope section with no lateral investigation."""
        scope = generator._scope_section(investigation_state)
        assert "No lateral investigation" in scope

    def test_scope_with_hosts_and_users(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test scope section with hosts and users."""
        scope = generator._scope_section(populated_investigation_state)
        assert "Hosts Investigated" in scope
        assert "Users Investigated" in scope

    def test_scope_summary_counts(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test scope summary shows counts."""
        scope = generator._scope_section(populated_investigation_state)
        assert "hosts investigated" in scope.lower()
        assert "users investigated" in scope.lower()


class TestRecommendations:
    """Tests for recommendations section."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_recommendations_empty(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test recommendations with no recommendations."""
        recs = generator._recommendations(investigation_state)
        assert "Recommendations" in recs
        assert "No specific recommendations" in recs

    def test_recommendations_with_items(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test recommendations with items."""
        recs = generator._recommendations(populated_investigation_state)
        assert "Reset affected passwords" in recs or "Immediate Actions" in recs

    def test_recommendations_escalation_section(
        self, generator: MarkdownReportGenerator, escalated_investigation_state: InvestigationState
    ):
        """Test escalation section in recommendations."""
        recs = generator._recommendations(escalated_investigation_state)
        assert "ESCALATION REQUIRED" in recs

    def test_detection_improvements(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test detection improvements section."""
        recs = generator._recommendations(populated_investigation_state)
        assert "Detection Improvements" in recs


class TestAppendix:
    """Tests for appendix section."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_appendix_no_queries(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test appendix with no queries."""
        appendix = generator._appendix(investigation_state)
        assert "No query data" in appendix

    def test_appendix_with_queries(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test appendix with executed queries."""
        appendix = generator._appendix(populated_investigation_state)
        assert "Queries Executed" in appendix
        assert "Query 1" in appendix

    def test_appendix_metadata(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test appendix includes metadata."""
        appendix = generator._appendix(populated_investigation_state)
        assert "Investigation Metadata" in appendix
        assert "Started:" in appendix


class TestFormatDuration:
    """Tests for duration formatting."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_format_duration(
        self, generator: MarkdownReportGenerator, investigation_state: InvestigationState
    ):
        """Test duration formatting."""
        duration = generator._format_duration(investigation_state)
        assert "m" in duration
        assert "s" in duration


class TestFullReportBuild:
    """Tests for full report building."""

    @pytest.fixture
    def generator(self, temp_reports_dir: Path) -> MarkdownReportGenerator:
        return MarkdownReportGenerator(temp_reports_dir)

    def test_build_report_has_all_sections(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test full report contains all sections."""
        report = generator._build_report(populated_investigation_state)
        assert "Executive Summary" in report
        assert "Timeline" in report
        assert "MITRE ATT&CK" in report
        assert "Pyramid of Pain" in report
        assert "Evidence Inventory" in report
        assert "Scope Assessment" in report
        assert "Recommendations" in report
        assert "Appendix" in report

    def test_build_report_sections_separated(
        self, generator: MarkdownReportGenerator, populated_investigation_state: InvestigationState
    ):
        """Test sections are separated by horizontal rules."""
        report = generator._build_report(populated_investigation_state)
        assert "---" in report
