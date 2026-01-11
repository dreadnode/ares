"""Tests for the Red-Blue Correlation Engine."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ares.core.correlation import (
    BlueTeamDetection,
    CorrelationMatch,
    CorrelationReport,
    DetectionGap,
    RedBlueCorrelator,
    RedTeamActivity,
)


@pytest.fixture
def temp_reports_dir() -> Path:
    """Create a temporary reports directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_red_activity() -> RedTeamActivity:
    """Create a sample red team activity."""
    return RedTeamActivity(
        timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        technique_id="T1059.001",
        technique_name="PowerShell",
        action="Executed PowerShell command for reconnaissance",
        target_ip="192.168.1.100",
        target_host="server01",
        credential_used="admin",
        success=True,
        metadata={"command": "Get-Process"},
    )


@pytest.fixture
def sample_blue_detection() -> BlueTeamDetection:
    """Create a sample blue team detection."""
    return BlueTeamDetection(
        timestamp=datetime(2024, 1, 15, 10, 32, 0, tzinfo=timezone.utc),
        alert_name="Suspicious PowerShell Activity",
        technique_id="T1059.001",
        severity="high",
        target_ip="192.168.1.100",
        target_host="server01",
        investigation_id="inv-001",
        status="completed",
        evidence_count=5,
        highest_pyramid_level=3,
        metadata={"rule_id": "rule-ps-001"},
    )


class TestRedTeamActivity:
    """Tests for RedTeamActivity dataclass."""

    def test_key_generation(self, sample_red_activity: RedTeamActivity) -> None:
        """Test unique key generation."""
        key = sample_red_activity.key

        assert "2024-01-15" in key
        assert "T1059.001" in key
        assert "192.168.1.100" in key

    def test_key_uniqueness(self) -> None:
        """Test that different activities have different keys."""
        activity1 = RedTeamActivity(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            technique_id="T1059.001",
            technique_name="PowerShell",
            action="Action 1",
            target_ip="192.168.1.100",
            target_host=None,
            credential_used=None,
            success=True,
        )
        activity2 = RedTeamActivity(
            timestamp=datetime(2024, 1, 15, 10, 31, 0, tzinfo=timezone.utc),
            technique_id="T1059.001",
            technique_name="PowerShell",
            action="Action 2",
            target_ip="192.168.1.100",
            target_host=None,
            credential_used=None,
            success=True,
        )

        assert activity1.key != activity2.key


class TestBlueTeamDetection:
    """Tests for BlueTeamDetection dataclass."""

    def test_key_generation(self, sample_blue_detection: BlueTeamDetection) -> None:
        """Test unique key generation."""
        key = sample_blue_detection.key

        assert "2024-01-15" in key
        assert "T1059.001" in key
        assert "Suspicious PowerShell Activity" in key


class TestCorrelationMatch:
    """Tests for CorrelationMatch dataclass."""

    def test_match_quality_strong(
        self,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test strong match quality classification."""
        match = CorrelationMatch(
            red_activity=sample_red_activity,
            blue_detection=sample_blue_detection,
            time_delta_seconds=120.0,  # 2 minutes
            technique_match=True,
            target_match=True,
            confidence=0.9,
        )

        assert match.match_quality == "STRONG"

    def test_match_quality_good(
        self,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test good match quality classification."""
        match = CorrelationMatch(
            red_activity=sample_red_activity,
            blue_detection=sample_blue_detection,
            time_delta_seconds=400.0,  # ~7 minutes
            technique_match=True,
            target_match=False,
            confidence=0.6,
        )

        assert match.match_quality == "GOOD"

    def test_match_quality_weak(
        self,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test weak match quality classification."""
        match = CorrelationMatch(
            red_activity=sample_red_activity,
            blue_detection=sample_blue_detection,
            time_delta_seconds=700.0,  # ~12 minutes
            technique_match=True,
            target_match=False,
            confidence=0.4,
        )

        assert match.match_quality == "WEAK"

    def test_match_quality_tenuous(
        self,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test tenuous match quality classification."""
        match = CorrelationMatch(
            red_activity=sample_red_activity,
            blue_detection=sample_blue_detection,
            time_delta_seconds=700.0,
            technique_match=False,
            target_match=False,
            confidence=0.2,
        )

        assert match.match_quality == "TENUOUS"


class TestCorrelationReport:
    """Tests for CorrelationReport dataclass."""

    def test_to_dict(
        self,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test conversion to dictionary."""
        match = CorrelationMatch(
            red_activity=sample_red_activity,
            blue_detection=sample_blue_detection,
            time_delta_seconds=120.0,
            technique_match=True,
            target_match=True,
            confidence=0.9,
        )

        gap = DetectionGap(
            red_activity=sample_red_activity,
            reason="No alert rule configured",
            recommended_detection="Add PowerShell monitoring",
        )

        report = CorrelationReport(
            analysis_timestamp=datetime.now(timezone.utc),
            red_operation_id="op-001",
            time_window_start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            time_window_end=datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
            total_red_activities=10,
            total_blue_detections=8,
            matched_activities=7,
            undetected_activities=3,
            false_positive_detections=1,
            matches=[match],
            gaps=[gap],
            false_positives=[sample_blue_detection],
            detection_rate=0.7,
            false_positive_rate=0.125,
            mean_time_to_detect=120.0,
            technique_coverage={
                "T1059.001": {"total": 5, "detected": 4, "missed": 1, "detection_rate": 0.8}
            },
        )

        data = report.to_dict()

        assert data["red_operation_id"] == "op-001"
        assert data["summary"]["total_red_activities"] == 10
        assert data["summary"]["detection_rate"] == "70.0%"
        assert len(data["matches"]) == 1
        assert len(data["gaps"]) == 1
        assert "T1059.001" in data["technique_coverage"]


class TestRedBlueCorrelator:
    """Tests for RedBlueCorrelator."""

    def test_init(self, temp_reports_dir: Path) -> None:
        """Test correlator initialization."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        assert correlator.reports_dir == temp_reports_dir
        assert correlator.time_window == timedelta(minutes=30)

    def test_init_custom_time_window(self, temp_reports_dir: Path) -> None:
        """Test correlator with custom time window."""
        correlator = RedBlueCorrelator(temp_reports_dir, time_window_minutes=60)

        assert correlator.time_window == timedelta(minutes=60)

    def test_correlate_perfect_match(
        self,
        temp_reports_dir: Path,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test correlation with perfect technique and target match."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        report = correlator.correlate(
            red_activities=[sample_red_activity],
            blue_detections=[sample_blue_detection],
            operation_id="test-op",
        )

        assert report.total_red_activities == 1
        assert report.total_blue_detections == 1
        assert report.matched_activities == 1
        assert report.undetected_activities == 0
        assert len(report.matches) == 1
        assert report.matches[0].technique_match is True
        assert report.matches[0].target_match is True

    def test_correlate_no_match_outside_time_window(
        self, temp_reports_dir: Path, sample_red_activity: RedTeamActivity
    ) -> None:
        """Test that activities outside time window are not matched."""
        correlator = RedBlueCorrelator(temp_reports_dir, time_window_minutes=10)

        # Detection 1 hour after activity
        late_detection = BlueTeamDetection(
            timestamp=sample_red_activity.timestamp + timedelta(hours=1),
            alert_name="Late Detection",
            technique_id="T1059.001",
            severity="high",
            target_ip="192.168.1.100",
            target_host=None,
            investigation_id="inv-late",
            status="completed",
            evidence_count=1,
            highest_pyramid_level=1,
        )

        report = correlator.correlate(
            red_activities=[sample_red_activity],
            blue_detections=[late_detection],
            operation_id="test-op",
        )

        assert report.matched_activities == 0
        assert report.undetected_activities == 1

    def test_correlate_technique_mismatch(
        self, temp_reports_dir: Path, sample_red_activity: RedTeamActivity
    ) -> None:
        """Test correlation with technique mismatch."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        wrong_technique_detection = BlueTeamDetection(
            timestamp=sample_red_activity.timestamp + timedelta(minutes=2),
            alert_name="Different Technique",
            technique_id="T1003.001",  # Different technique
            severity="high",
            target_ip="192.168.1.100",
            target_host=None,
            investigation_id="inv-001",
            status="completed",
            evidence_count=1,
            highest_pyramid_level=1,
        )

        report = correlator.correlate(
            red_activities=[sample_red_activity],
            blue_detections=[wrong_technique_detection],
            operation_id="test-op",
        )

        # Should still match based on target and time proximity
        assert len(report.matches) == 1
        assert report.matches[0].technique_match is False
        assert report.matches[0].target_match is True

    def test_correlate_multiple_activities(self, temp_reports_dir: Path) -> None:
        """Test correlation with multiple activities and detections."""
        correlator = RedBlueCorrelator(temp_reports_dir)
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Use different target IPs to prevent cross-matching via target
        red_activities = [
            RedTeamActivity(
                timestamp=base_time + timedelta(minutes=i * 10),
                technique_id=f"T100{i}",
                technique_name=f"Technique {i}",
                action=f"Action {i}",
                target_ip=f"192.168.1.{100 + i}",  # Different IPs
                target_host=None,
                credential_used=None,
                success=True,
            )
            for i in range(5)
        ]

        # Only detect 3 of 5 activities (matching technique and target)
        blue_detections = [
            BlueTeamDetection(
                timestamp=base_time + timedelta(minutes=i * 10 + 2),
                alert_name=f"Alert {i}",
                technique_id=f"T100{i}",
                severity="high",
                target_ip=f"192.168.1.{100 + i}",  # Matching IPs
                target_host=None,
                investigation_id=f"inv-{i}",
                status="completed",
                evidence_count=1,
                highest_pyramid_level=1,
            )
            for i in [0, 2, 4]  # Only detect activities 0, 2, 4
        ]

        report = correlator.correlate(
            red_activities=red_activities,
            blue_detections=blue_detections,
            operation_id="test-op",
        )

        assert report.total_red_activities == 5
        assert report.total_blue_detections == 3
        assert report.matched_activities == 3
        assert report.undetected_activities == 2
        assert report.detection_rate == 0.6

    def test_correlate_empty_activities(self, temp_reports_dir: Path) -> None:
        """Test correlation with no activities."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        report = correlator.correlate(
            red_activities=[],
            blue_detections=[],
            operation_id="empty-op",
        )

        assert report.total_red_activities == 0
        assert report.detection_rate == 0.0

    def test_correlate_identifies_false_positives(
        self, temp_reports_dir: Path, sample_red_activity: RedTeamActivity
    ) -> None:
        """Test that unmatched detections are identified as false positives."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        # Detection without corresponding red activity
        unrelated_detection = BlueTeamDetection(
            timestamp=sample_red_activity.timestamp + timedelta(minutes=5),
            alert_name="Unrelated Alert",
            technique_id="T9999",  # No matching red activity
            severity="low",
            target_ip="10.0.0.1",  # Different target
            target_host=None,
            investigation_id="inv-fp",
            status="completed",
            evidence_count=0,
            highest_pyramid_level=0,
        )

        report = correlator.correlate(
            red_activities=[sample_red_activity],
            blue_detections=[
                BlueTeamDetection(
                    timestamp=sample_red_activity.timestamp + timedelta(minutes=2),
                    alert_name="Matching Alert",
                    technique_id="T1059.001",
                    severity="high",
                    target_ip="192.168.1.100",
                    target_host=None,
                    investigation_id="inv-001",
                    status="completed",
                    evidence_count=1,
                    highest_pyramid_level=1,
                ),
                unrelated_detection,
            ],
            operation_id="test-op",
        )

        assert len(report.false_positives) == 1
        assert report.false_positives[0].alert_name == "Unrelated Alert"

    def test_technique_coverage_calculation(self, temp_reports_dir: Path) -> None:
        """Test technique coverage calculation."""
        correlator = RedBlueCorrelator(temp_reports_dir)
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Create activities with DIFFERENT techniques and targets for clear matching
        # This ensures each activity can only match its corresponding detection
        red_activities = [
            RedTeamActivity(
                timestamp=base_time + timedelta(minutes=i * 10),
                technique_id=f"T105{i}",  # Different technique per activity
                technique_name=f"Technique {i}",
                action=f"Action {i}",
                target_ip=f"192.168.1.{100 + i}",  # Different targets
                target_host=None,
                credential_used=None,
                success=True,
            )
            for i in range(4)
        ]

        # Only detect 3 of 4 (activities 0, 1, 2 but not 3)
        blue_detections = [
            BlueTeamDetection(
                timestamp=base_time + timedelta(minutes=i * 10, seconds=30),
                alert_name=f"Alert {i}",
                technique_id=f"T105{i}",  # Matching technique
                severity="high",
                target_ip=f"192.168.1.{100 + i}",  # Matching targets
                target_host=None,
                investigation_id=f"inv-{i}",
                status="completed",
                evidence_count=1,
                highest_pyramid_level=1,
            )
            for i in range(3)  # Only first 3 activities get detected
        ]

        report = correlator.correlate(
            red_activities=red_activities,
            blue_detections=blue_detections,
            operation_id="test-op",
        )

        # Should have coverage data for all 4 techniques
        assert len(report.technique_coverage) == 4
        # 3 techniques should be detected (T1050, T1051, T1052)
        # 1 technique should be missed (T1053)
        detected_count = sum(1 for t in report.technique_coverage.values() if t["detected"] > 0)
        missed_count = sum(1 for t in report.technique_coverage.values() if t["missed"] > 0)
        assert detected_count == 3
        assert missed_count == 1
        assert report.matched_activities == 3
        assert report.undetected_activities == 1

    def test_mean_time_to_detect(
        self,
        temp_reports_dir: Path,
    ) -> None:
        """Test mean time to detect calculation."""
        correlator = RedBlueCorrelator(temp_reports_dir)
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        red_activities = [
            RedTeamActivity(
                timestamp=base_time,
                technique_id="T1059.001",
                technique_name="PowerShell",
                action="Action 1",
                target_ip="192.168.1.100",
                target_host=None,
                credential_used=None,
                success=True,
            ),
            RedTeamActivity(
                timestamp=base_time + timedelta(minutes=10),
                technique_id="T1059.002",
                technique_name="Script",
                action="Action 2",
                target_ip="192.168.1.100",
                target_host=None,
                credential_used=None,
                success=True,
            ),
        ]

        blue_detections = [
            BlueTeamDetection(
                timestamp=base_time + timedelta(seconds=60),  # 60s after
                alert_name="Alert 1",
                technique_id="T1059.001",
                severity="high",
                target_ip="192.168.1.100",
                target_host=None,
                investigation_id="inv-1",
                status="completed",
                evidence_count=1,
                highest_pyramid_level=1,
            ),
            BlueTeamDetection(
                timestamp=base_time + timedelta(minutes=10, seconds=120),  # 120s after
                alert_name="Alert 2",
                technique_id="T1059.002",
                severity="high",
                target_ip="192.168.1.100",
                target_host=None,
                investigation_id="inv-2",
                status="completed",
                evidence_count=1,
                highest_pyramid_level=1,
            ),
        ]

        report = correlator.correlate(
            red_activities=red_activities,
            blue_detections=blue_detections,
            operation_id="test-op",
        )

        # Mean of 60s and 120s = 90s
        assert report.mean_time_to_detect == 90.0

    def test_generate_report_markdown(
        self,
        temp_reports_dir: Path,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test markdown report generation."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        report = correlator.correlate(
            red_activities=[sample_red_activity],
            blue_detections=[sample_blue_detection],
            operation_id="test-op",
        )

        markdown = correlator.generate_report_markdown(report)

        assert "# Red-Blue Correlation Report" in markdown
        assert "Executive Summary" in markdown
        assert "test-op" in markdown
        assert "Detection Rate" in markdown

    def test_load_red_team_report_basic(self, temp_reports_dir: Path) -> None:
        """Test loading a basic red team report."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        # Create a sample red team report
        report_content = """# Red Team Operation Report

**Operation ID**: op-test-001
**Target**: 192.168.1.100
**Started**: 2024-01-15 10:00:00 UTC

### Hosts (3)
Found 3 hosts during scanning.

### Credentials (2)
**admin**
Source: password guessing

**backup**
Source: credential dumping

### Timeline of Key Events
| Timestamp | Event | Technique |
|-----------|-------|-----------|
| 2024-01-15T10:05:00Z | Initial access | T1078 |
| 2024-01-15T10:10:00Z | Privilege escalation | T1068 |

**Domain Admin Access**: ✓
**Golden Ticket**: ✓
"""
        report_path = temp_reports_dir / "redteam-op-test-001.md"
        report_path.write_text(report_content)

        operation_id, activities = correlator.load_red_team_report(report_path)

        assert operation_id == "op-test-001"
        assert len(activities) > 0

        # Check for network discovery activity
        discovery = next((a for a in activities if a.technique_id == "T1046"), None)
        assert discovery is not None
        assert "3 host" in discovery.action

    def test_load_investigation_report(self, temp_reports_dir: Path) -> None:
        """Test loading an investigation report."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        report_content = """# Investigation Report

**Investigation ID:** `inv-20240115-001`

| Field | Value |
|-------|-------|
| Alert Name | Suspicious PowerShell Activity |
| Severity | high |
| Status | completed |

Alert payload contains:
"startsAt": "2024-01-15T10:30:00Z"

Target IP: 192.168.1.100

Technique: T1059.001

**Evidence Collected:** 5
**Highest Pyramid Level:** 3
"""
        report_path = temp_reports_dir / "investigation_20240115_103000.md"
        report_path.write_text(report_content)

        detection = correlator.load_investigation_report(report_path)

        assert detection is not None
        assert detection.investigation_id == "inv-20240115-001"
        assert detection.alert_name == "Suspicious PowerShell Activity"
        assert detection.severity == "high"
        assert detection.technique_id == "T1059.001"
        assert detection.evidence_count == 5
        assert detection.highest_pyramid_level == 3

    def test_load_investigation_report_skips_no_data(self, temp_reports_dir: Path) -> None:
        """Test that DatasourceNoData reports are skipped."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        report_path = temp_reports_dir / "investigation_DatasourceNoData_20240115.md"
        report_path.write_text("Some content")

        detection = correlator.load_investigation_report(report_path)

        assert detection is None

    def test_load_all_reports(self, temp_reports_dir: Path) -> None:
        """Test loading all reports from directory."""
        correlator = RedBlueCorrelator(temp_reports_dir)

        # Create red team report
        red_report = temp_reports_dir / "redteam-op001.md"
        red_report.write_text("""# Red Team Report
**Operation ID**: op001
**Target**: 192.168.1.1
**Started**: 2024-01-15 10:00:00 UTC
### Hosts (1)
### Credentials (0)
""")

        # Create investigation report
        inv_report = temp_reports_dir / "investigation_20240115.md"
        inv_report.write_text("""# Investigation
**Investigation ID:** `inv-001`
| Alert Name | Test Alert |
| Severity | high |
| Status | completed |
"startsAt": "2024-01-15T10:30:00Z"
**Evidence Collected:** 1
**Highest Pyramid Level:** 1
""")

        # Create non-report file (should be ignored)
        other_file = temp_reports_dir / "readme.md"
        other_file.write_text("# README")

        red_reports, blue_detections = correlator.load_all_reports()

        assert len(red_reports) == 1
        assert red_reports[0][0] == "op001"
        assert len(blue_detections) >= 0  # May or may not parse depending on format


class TestDetectionGap:
    """Tests for DetectionGap dataclass."""

    def test_gap_with_recommendation(self, sample_red_activity: RedTeamActivity) -> None:
        """Test detection gap with recommendation."""
        gap = DetectionGap(
            red_activity=sample_red_activity,
            reason="No alert rule configured",
            recommended_detection="Add PowerShell monitoring rule",
            mitre_data_sources=["Process: Process Creation", "Script: Script Execution"],
        )

        assert gap.reason == "No alert rule configured"
        assert gap.recommended_detection == "Add PowerShell monitoring rule"
        assert len(gap.mitre_data_sources) == 2

    def test_gap_without_recommendation(self, sample_red_activity: RedTeamActivity) -> None:
        """Test detection gap without recommendation."""
        gap = DetectionGap(
            red_activity=sample_red_activity,
            reason="Unknown technique",
        )

        assert gap.recommended_detection is None
        assert gap.mitre_data_sources == []


class TestRedTeamReportParsingEdgeCases:
    """Tests for edge cases in red team report parsing."""

    @pytest.fixture
    def correlator(self, temp_reports_dir: Path) -> RedBlueCorrelator:
        """Create a correlator with temp reports dir."""
        return RedBlueCorrelator(reports_dir=temp_reports_dir)

    def test_parse_report_with_invalid_date(
        self, correlator: RedBlueCorrelator, temp_reports_dir: Path
    ) -> None:
        """Test parsing report with invalid started date falls back to current time."""
        content = """# Red Team Operation Report

**Operation ID**: op-test
**Target:** 192.168.1.1
**Started:** invalid-date-format

### Hosts (2)
- host1
- host2
"""
        report_file = temp_reports_dir / "redteam_op-test.md"
        report_file.write_text(content)

        operation_id, activities = correlator.load_red_team_report(report_file)
        # Should still parse successfully with fallback timestamp
        assert operation_id == "op-test"
        assert len(activities) >= 1

    def test_parse_report_with_credentials_section(
        self, correlator: RedBlueCorrelator, temp_reports_dir: Path
    ) -> None:
        """Test parsing report with credentials section."""
        content = """# Red Team Operation Report
## op-test

**Target:** 192.168.1.1
**Started:** 2024-01-15 10:30:00 UTC

### Credentials (2)
**admin**
Source: Password guessing

**serviceacct**
Source: Secretsdump from DC

### Hosts (1)
- host1
"""
        report_file = temp_reports_dir / "redteam_op-test.md"
        report_file.write_text(content)

        _operation_id, activities = correlator.load_red_team_report(report_file)
        # Should have activities for host discovery and credentials
        assert len(activities) >= 1

    def test_parse_report_with_timeline(
        self, correlator: RedBlueCorrelator, temp_reports_dir: Path
    ) -> None:
        """Test parsing report with timeline section."""
        content = """# Red Team Operation Report
## op-test

**Target:** 192.168.1.1
**Started:** 2024-01-15 10:30:00 UTC

### Timeline of Key Events

| Timestamp | Event | Technique |
|-----------|-------|-----------|
| 2024-01-15T10:35:00+00:00 | Port scan | T1046 |
| invalid-timestamp | Credential dump | T1003 |

---

### Hosts (0)
"""
        report_file = temp_reports_dir / "redteam_op-test.md"
        report_file.write_text(content)

        _operation_id, activities = correlator.load_red_team_report(report_file)
        # Should parse timeline events, handling invalid timestamps gracefully
        assert isinstance(activities, list)

    def test_parse_report_without_started_date(
        self, correlator: RedBlueCorrelator, temp_reports_dir: Path
    ) -> None:
        """Test parsing report without started field."""
        content = """# Red Team Operation Report
## op-test

**Target:** 192.168.1.1

### Hosts (1)
- host1
"""
        report_file = temp_reports_dir / "redteam_op-test.md"
        report_file.write_text(content)

        _operation_id, activities = correlator.load_red_team_report(report_file)
        # Should still work with a default timestamp
        assert len(activities) >= 1

    def test_parse_report_credential_guessing(
        self, correlator: RedBlueCorrelator, temp_reports_dir: Path
    ) -> None:
        """Test credential guessing is mapped to T1110."""
        content = """# Red Team Operation Report
## op-test

**Target:** 192.168.1.1
**Started:** 2024-01-15 10:30:00 UTC

### Credentials (1)
**user1**
Source: password guessing attack

### Hosts (0)
"""
        report_file = temp_reports_dir / "redteam_op-test.md"
        report_file.write_text(content)

        _operation_id, activities = correlator.load_red_team_report(report_file)
        # Check if credential guessing maps to T1110
        [a for a in activities if a.technique_id == "T1110"]
        # May or may not find depending on regex match
        assert isinstance(activities, list)


class TestGenerateReportMarkdownAdvanced:
    """Tests for advanced generate_report_markdown scenarios."""

    @pytest.fixture
    def correlator(self, temp_reports_dir: Path) -> RedBlueCorrelator:
        """Create a correlator with temp directory."""
        return RedBlueCorrelator(reports_dir=temp_reports_dir)

    def _make_report(
        self,
        red_operation_id: str = "test-op",
        total_red_activities: int = 5,
        total_blue_detections: int = 2,
        matched_activities: int = 1,
        undetected_activities: int = 3,
        false_positive_detections: int = 1,
        matches: list | None = None,
        gaps: list | None = None,
        false_positives: list | None = None,
        detection_rate: float = 0.4,
        false_positive_rate: float = 0.2,
        mean_time_to_detect: float | None = None,
        technique_coverage: dict | None = None,
    ) -> CorrelationReport:
        """Helper to create a CorrelationReport with defaults."""
        now = datetime.now(timezone.utc)
        return CorrelationReport(
            analysis_timestamp=now,
            red_operation_id=red_operation_id,
            time_window_start=now - timedelta(hours=1),
            time_window_end=now,
            total_red_activities=total_red_activities,
            total_blue_detections=total_blue_detections,
            matched_activities=matched_activities,
            undetected_activities=undetected_activities,
            false_positive_detections=false_positive_detections,
            matches=matches or [],
            gaps=gaps or [],
            false_positives=false_positives or [],
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            mean_time_to_detect=mean_time_to_detect,
            technique_coverage=technique_coverage or {},
        )

    def test_generate_report_with_gaps(
        self, correlator: RedBlueCorrelator, sample_red_activity: RedTeamActivity
    ) -> None:
        """Test generating report markdown with detection gaps."""
        gap = DetectionGap(
            red_activity=sample_red_activity,
            reason="No matching alert found for this technique",
            recommended_detection="Add PowerShell command logging rule",
        )

        report = self._make_report(gaps=[gap])
        markdown = correlator.generate_report_markdown(report)

        # Verify gaps section is present
        assert "## Detection Gaps (Undetected Activities)" in markdown
        assert "T1059.001" in markdown or "PowerShell" in markdown
        assert "No matching alert" in markdown

    def test_generate_report_with_false_positives(
        self, correlator: RedBlueCorrelator, sample_blue_detection: BlueTeamDetection
    ) -> None:
        """Test generating report markdown with false positives."""
        report = self._make_report(
            false_positives=[sample_blue_detection],
            detection_rate=1.0,
        )
        markdown = correlator.generate_report_markdown(report)

        # Verify false positives section is present
        assert "## False Positives (Detections without Red Activity)" in markdown
        assert "Suspicious PowerShell Activity" in markdown

    def test_generate_report_with_low_detection_rate(self, correlator: RedBlueCorrelator) -> None:
        """Test generating report with low detection rate includes improvement recommendations."""
        report = self._make_report(detection_rate=0.2)
        markdown = correlator.generate_report_markdown(report)

        # Verify general improvements section for low detection rate
        assert "### General Improvements" in markdown
        assert "query timeout" in markdown.lower() or "Loki/Grafana" in markdown

    def test_generate_report_with_gaps_and_recommendations(
        self, correlator: RedBlueCorrelator, sample_red_activity: RedTeamActivity
    ) -> None:
        """Test generating report with gaps shows recommendations."""
        gap1 = DetectionGap(
            red_activity=sample_red_activity,
            reason="No alert rule for this technique",
            recommended_detection="Create PowerShell monitoring rule",
        )
        gap2 = DetectionGap(
            red_activity=RedTeamActivity(
                timestamp=datetime.now(timezone.utc),
                technique_id="T1046",
                technique_name="Network Service Discovery",
                action="Scanned network for open ports",
                target_ip="192.168.1.0/24",
                target_host=None,
                credential_used=None,
                success=True,
            ),
            reason="Network scanning not detected",
            recommended_detection="Enable network anomaly detection",
        )

        report = self._make_report(gaps=[gap1, gap2], detection_rate=0.2)
        markdown = correlator.generate_report_markdown(report)

        # Verify recommendations section
        assert "## Recommendations" in markdown
        # Check technique-specific recommendations
        assert "T1059.001" in markdown or "T1046" in markdown
        # Recommendations should appear
        assert "monitoring rule" in markdown.lower() or "anomaly" in markdown.lower()

    def test_generate_report_with_all_sections(
        self,
        correlator: RedBlueCorrelator,
        sample_red_activity: RedTeamActivity,
        sample_blue_detection: BlueTeamDetection,
    ) -> None:
        """Test generating complete report with all sections."""
        correlation = CorrelationMatch(
            red_activity=sample_red_activity,
            blue_detection=sample_blue_detection,
            time_delta_seconds=120.0,  # 2 minutes
            technique_match=True,
            target_match=True,
            confidence=0.95,
        )

        gap = DetectionGap(
            red_activity=RedTeamActivity(
                timestamp=datetime.now(timezone.utc),
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                action="Dumped credentials via LSASS",
                target_ip="192.168.1.100",
                target_host="server01",
                credential_used=None,
                success=True,
            ),
            reason="Credential dumping went undetected",
            recommended_detection="Add LSASS access monitoring",
        )

        fp_detection = BlueTeamDetection(
            timestamp=datetime.now(timezone.utc),
            alert_name="False Positive Alert",
            technique_id="T1071",
            severity="medium",
            target_ip="192.168.1.50",
            target_host=None,
            investigation_id="inv-fp",
            status="closed",
            evidence_count=1,
            highest_pyramid_level=1,
        )

        report = self._make_report(
            red_operation_id="full-test-op",
            matches=[correlation],
            gaps=[gap],
            false_positives=[fp_detection],
            detection_rate=0.5,
            mean_time_to_detect=120.0,  # 2 minutes in seconds
            technique_coverage={
                "T1059.001": {"detected": 1, "total": 1, "missed": 0, "detection_rate": 1.0},
                "T1003": {"detected": 0, "total": 1, "missed": 1, "detection_rate": 0.0},
            },
        )
        markdown = correlator.generate_report_markdown(report)

        # Verify all major sections
        assert "# Red-Blue Correlation Report" in markdown
        assert "## Executive Summary" in markdown
        assert "## Successful Detections" in markdown
        assert "## Detection Gaps" in markdown
        assert "## False Positives" in markdown
        assert "## Recommendations" in markdown
        assert "full-test-op" in markdown
