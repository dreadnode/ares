"""Tests for detection playbook generation."""

from datetime import datetime, timedelta, timezone

import pytest

from ares.core.models import (
    Credential,
    Hash,
    Host,
    PyramidLevel,
    Share,
    SharedRedTeamState,
    Target,
    User,
)
from ares.eval.detection_playbook import (
    DetectionTarget,
    PlaybookQuery,
    TechniqueDetection,
    create_detection_playbook,
)


@pytest.fixture
def sample_state() -> SharedRedTeamState:
    """Create a sample red team state for testing."""
    now = datetime.now(timezone.utc)
    return SharedRedTeamState(
        operation_id="op-20260218-test",
        target=Target(ip="192.168.58.10", domain="contoso.local"),
        started_at=now - timedelta(hours=1),
        completed_at=now,
        all_hosts=[
            Host(ip="192.168.58.10", hostname="dc01.contoso.local", roles=["DC"]),
            Host(ip="192.168.58.20", hostname="sql01.contoso.local", services=["MSSQL"]),
            Host(ip="192.168.58.30", hostname="web01.contoso.local", services=["HTTP"]),
        ],
        all_credentials=[
            Credential(
                username="svc_backup",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoasting",
            ),
            Credential(
                username="admin",
                password="Admin123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="secretsdump",
                is_admin=True,
            ),
        ],
        all_hashes=[
            Hash(
                username="Administrator",
                hash_type="NTLM",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                source="secretsdump",
            ),
            Hash(
                username="krbtgt",
                hash_type="NTLM",
                hash_value="aad3b435b51404eeaad3b435b51404ee:b6e60f4c7d6b09e8f6b2b7a9c8e4d1f2",
                source="secretsdump",
            ),
        ],
        all_users=[
            User(username="svc_backup", domain="contoso.local", is_admin=False),
            User(username="admin", domain="contoso.local", is_admin=True),
        ],
        all_shares=[
            Share(host="192.168.58.10", name="SYSVOL", permissions="READ"),
            Share(host="192.168.58.10", name="C$", permissions="READ/WRITE"),
        ],
        identified_techniques={"T1046", "T1003", "T1558.003", "T1078.002", "T1021.002"},
        has_domain_admin=True,
        domain_admin_path="kerberoasting -> svc_backup -> secretsdump -> Administrator",
    )


class TestDetectionPlaybook:
    """Tests for DetectionPlaybook dataclass."""

    def test_to_dict_includes_all_fields(self, sample_state: SharedRedTeamState) -> None:
        """Test that to_dict includes all expected fields."""
        playbook = create_detection_playbook(sample_state)
        result = playbook.to_dict()

        assert "operation_id" in result
        assert "generated_at" in result
        assert "attack_window" in result
        assert "summary" in result
        assert "executive_summary" in result
        assert "technique_detections" in result
        assert "detection_targets" in result
        assert "priority_queries" in result

    def test_to_markdown_generates_valid_markdown(self, sample_state: SharedRedTeamState) -> None:
        """Test that to_markdown generates valid markdown."""
        playbook = create_detection_playbook(sample_state)
        markdown = playbook.to_markdown()

        assert "# Detection Playbook" in markdown
        assert "## Executive Summary" in markdown
        assert "## Priority Detection Queries" in markdown
        assert "## Detection Targets" in markdown
        assert sample_state.operation_id in markdown


class TestCreateDetectionPlaybook:
    """Tests for create_detection_playbook function."""

    def test_extracts_hosts_as_detection_targets(self, sample_state: SharedRedTeamState) -> None:
        """Test that hosts are extracted as IP detection targets."""
        playbook = create_detection_playbook(sample_state)

        ip_targets = [t for t in playbook.detection_targets if t.ioc_type == "ip"]
        assert len(ip_targets) >= 3  # At least our 3 hosts

        # Check that our host IPs are in the targets
        target_ips = {t.value for t in ip_targets}
        assert "192.168.58.10" in target_ips
        assert "192.168.58.20" in target_ips

    def test_extracts_credentials_as_detection_targets(
        self, sample_state: SharedRedTeamState
    ) -> None:
        """Test that credentials are extracted as user detection targets."""
        playbook = create_detection_playbook(sample_state)

        user_targets = [t for t in playbook.detection_targets if t.ioc_type == "user"]
        assert len(user_targets) >= 2

        # Check that our usernames are in the targets
        target_values = {t.value for t in user_targets}
        assert any("svc_backup" in v for v in target_values)
        assert any("admin" in v for v in target_values)

    def test_builds_technique_detections(self, sample_state: SharedRedTeamState) -> None:
        """Test that technique-specific detections are built."""
        playbook = create_detection_playbook(sample_state)

        # Check that we have detections for techniques that were used
        assert "T1003" in playbook.technique_detections or any(
            t.startswith("T1003") for t in playbook.technique_detections
        )
        assert "T1558.003" in playbook.technique_detections

    def test_builds_priority_queries(self, sample_state: SharedRedTeamState) -> None:
        """Test that priority queries are generated and sorted."""
        playbook = create_detection_playbook(sample_state)

        assert len(playbook.priority_queries) > 0

        # Check that queries have required fields
        for query in playbook.priority_queries:
            assert query.technique_id
            assert query.logql
            assert query.priority in ("critical", "high", "medium", "low")

        # Check that critical/high queries come first
        priorities = [q.priority for q in playbook.priority_queries]
        critical_high_first = True
        seen_low = False
        for p in priorities:
            if p in ("critical", "high"):
                if seen_low:
                    critical_high_first = False
            elif p in ("medium", "low"):
                seen_low = True
        assert critical_high_first, "Priority queries should be sorted by priority"

    def test_domain_admin_adds_critical_query(self, sample_state: SharedRedTeamState) -> None:
        """Test that achieving domain admin adds a critical detection query."""
        playbook = create_detection_playbook(sample_state)

        da_queries = [q for q in playbook.priority_queries if q.technique_id == "T1078.002"]
        assert len(da_queries) > 0
        assert da_queries[0].priority == "critical"

    def test_executive_summary_mentions_domain_admin(
        self, sample_state: SharedRedTeamState
    ) -> None:
        """Test that executive summary mentions domain admin achievement."""
        playbook = create_detection_playbook(sample_state)

        assert (
            "Domain Admin" in playbook.executive_summary
            or "domain admin" in playbook.executive_summary.lower()
        )

    def test_attack_window_set_correctly(self, sample_state: SharedRedTeamState) -> None:
        """Test that attack window is set from state timestamps."""
        playbook = create_detection_playbook(sample_state)

        assert playbook.attack_window_start == sample_state.started_at
        assert playbook.attack_window_end == sample_state.completed_at


class TestPlaybookQuery:
    """Tests for PlaybookQuery dataclass."""

    def test_to_dict_includes_time_window(self) -> None:
        """Test that to_dict includes time window."""
        now = datetime.now(timezone.utc)
        query = PlaybookQuery(
            technique_id="T1003",
            technique_name="Credential Dumping",
            description="Detect credential access",
            logql='{job="windows-security"} |= "4624"',
            priority="critical",
            time_window_start=now - timedelta(hours=1),
            time_window_end=now,
        )
        result = query.to_dict()

        assert "time_window" in result
        assert result["time_window"]["start"] is not None
        assert result["time_window"]["end"] is not None


class TestDetectionTarget:
    """Tests for DetectionTarget dataclass."""

    def test_to_dict_includes_pyramid_level_name(self) -> None:
        """Test that to_dict includes human-readable pyramid level."""
        target = DetectionTarget(
            ioc_type="ip",
            value="192.168.58.10",
            pyramid_level=PyramidLevel.IP_ADDRESSES,
            context="Test host",
        )
        result = target.to_dict()

        assert "pyramid_level_name" in result
        assert "IP" in result["pyramid_level_name"]


class TestTechniqueDetection:
    """Tests for TechniqueDetection dataclass."""

    def test_to_dict_serializes_queries(self) -> None:
        """Test that to_dict properly serializes nested queries."""
        detection = TechniqueDetection(
            technique_id="T1003",
            technique_name="Credential Dumping",
            description="Test",
            detection_queries=[
                PlaybookQuery(
                    technique_id="T1003",
                    technique_name="Test",
                    description="Test query",
                    logql='{job="test"}',
                )
            ],
        )
        result = detection.to_dict()

        assert "detection_queries" in result
        assert len(result["detection_queries"]) == 1
        assert "logql" in result["detection_queries"][0]
