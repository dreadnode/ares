"""Tests for rigging Model integration in ares.core.models."""

from datetime import datetime, timezone

import pytest


class TestEvidenceModel:
    """Tests for Evidence rigging Model."""

    def test_evidence_creation(self) -> None:
        """Test creating Evidence with required fields."""
        from ares.core.models import Evidence, PyramidLevel

        evidence = Evidence(
            id="test-001",
            type="ip",
            value="192.168.56.100",
            source="loki_query",
            timestamp=datetime.now(timezone.utc),
            pyramid_level=PyramidLevel.IP_ADDRESSES,
        )

        assert evidence.id == "test-001"
        assert evidence.type == "ip"
        assert evidence.value == "192.168.56.100"
        assert evidence.pyramid_level == PyramidLevel.IP_ADDRESSES
        assert evidence.confidence == 0.5  # default
        assert evidence.validated is False  # default

    def test_evidence_with_optional_fields(self) -> None:
        """Test creating Evidence with optional fields."""
        from ares.core.models import Evidence, PyramidLevel

        evidence = Evidence(
            id="test-002",
            type="domain",
            value="malicious.example.com",
            source="dns_query",
            timestamp=None,
            pyramid_level=PyramidLevel.DOMAIN_NAMES,
            mitre_techniques=["T1071", "T1568"],
            confidence=0.9,
            metadata={"resolver": "8.8.8.8"},
            source_query_id="query-123",
            validated=True,
        )

        assert evidence.mitre_techniques == ["T1071", "T1568"]
        assert evidence.confidence == 0.9
        assert evidence.metadata == {"resolver": "8.8.8.8"}
        assert evidence.validated is True

    def test_evidence_to_dict(self) -> None:
        """Test Evidence to_dict serialization."""
        from ares.core.models import Evidence, PyramidLevel

        ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        evidence = Evidence(
            id="test-003",
            type="hash",
            value="abc123def456",  # pragma: allowlist secret
            source="file_scan",
            timestamp=ts,
            pyramid_level=PyramidLevel.HASH_VALUES,
            mitre_techniques=["T1027"],
        )

        data = evidence.to_dict()

        assert data["id"] == "test-003"
        assert data["type"] == "hash"
        assert data["value"] == "abc123def456"  # pragma: allowlist secret
        assert data["pyramid_level"] == 1  # HASH_VALUES = 1
        assert data["mitre_techniques"] == ["T1027"]
        assert data["timestamp"] == "2024-01-15T10:30:00Z"

    def test_evidence_model_dump(self) -> None:
        """Test Evidence model_dump method."""
        from ares.core.models import Evidence, PyramidLevel

        evidence = Evidence(
            id="test-004",
            type="ip",
            value="192.168.56.1",
            source="firewall",
            timestamp=None,
            pyramid_level=PyramidLevel.IP_ADDRESSES,
        )

        data = evidence.model_dump()

        assert data["id"] == "test-004"
        assert data["pyramid_level"] == PyramidLevel.IP_ADDRESSES
        assert data["timestamp"] is None

    def test_evidence_model_validate(self) -> None:
        """Test creating Evidence from dict using model_validate."""
        from ares.core.models import Evidence, PyramidLevel

        data = {
            "id": "test-005",
            "type": "process",
            "value": "malware.exe",
            "source": "edr",
            "timestamp": None,
            "pyramid_level": 5,  # TOOLS
            "confidence": 0.8,
        }

        evidence = Evidence.model_validate(data)

        assert evidence.id == "test-005"
        assert evidence.pyramid_level == PyramidLevel.TOOLS
        assert evidence.confidence == 0.8


class TestTimelineEventModel:
    """Tests for TimelineEvent rigging Model."""

    def test_timeline_event_creation(self) -> None:
        """Test creating TimelineEvent."""
        from ares.core.models import TimelineEvent

        ts = datetime.now(timezone.utc)
        event = TimelineEvent(
            id="event-001",
            timestamp=ts,
            description="Suspicious outbound connection detected",
        )

        assert event.id == "event-001"
        assert event.timestamp == ts
        assert event.confidence == 0.5  # default
        assert event.source == "investigation"  # default

    def test_timeline_event_to_dict(self) -> None:
        """Test TimelineEvent to_dict serialization."""
        from ares.core.models import TimelineEvent

        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = TimelineEvent(
            id="event-002",
            timestamp=ts,
            description="Lateral movement attempt",
            evidence_ids=["ev-001", "ev-002"],
            mitre_techniques=["T1021"],
            confidence=0.85,
        )

        data = event.to_dict()

        assert data["id"] == "event-002"
        assert data["evidence_ids"] == ["ev-001", "ev-002"]
        assert data["mitre_techniques"] == ["T1021"]
        assert data["confidence"] == 0.85


class TestInvestigativeQuestionModel:
    """Tests for InvestigativeQuestion rigging Model."""

    def test_investigative_question_creation(self) -> None:
        """Test creating InvestigativeQuestion."""
        from ares.core.models import InvestigativeQuestion, QuestionSource

        question = InvestigativeQuestion(
            id="q-001",
            text="What process initiated the connection?",
            source=QuestionSource.MITRE_NAVIGATOR,
            rationale="Need to identify source process for T1071",
            target_insight="Process identification",
        )

        assert question.id == "q-001"
        assert question.source == QuestionSource.MITRE_NAVIGATOR
        assert question.priority_score == 0.0  # all scores default to 0

    def test_investigative_question_priority_score(self) -> None:
        """Test InvestigativeQuestion priority_score computation."""
        from ares.core.models import InvestigativeQuestion, QuestionSource

        question = InvestigativeQuestion(
            id="q-002",
            text="What TTP was used?",
            source=QuestionSource.PYRAMID_CLIMBER,
            rationale="Climb to TTP level",
            target_insight="TTP identification",
            pyramid_elevation_score=0.8,  # 3x weight
            mitre_coverage_score=0.5,  # 2x weight
            confidence_impact_score=0.6,  # 2x weight
            urgency_score=0.4,  # 1x weight
        )

        # Expected: (0.8 * 3) + (0.5 * 2) + (0.6 * 2) + (0.4 * 1) = 2.4 + 1.0 + 1.2 + 0.4 = 5.0
        assert question.priority_score == pytest.approx(5.0)

    def test_investigative_question_to_dict(self) -> None:
        """Test InvestigativeQuestion to_dict serialization."""
        from ares.core.models import InvestigativeQuestion, QuestionSource, QuestionState

        question = InvestigativeQuestion(
            id="q-003",
            text="Which hosts are affected?",
            source=QuestionSource.LATERAL_EXPANSION,
            rationale="Determine scope",
            target_insight="Host enumeration",
            state=QuestionState.PENDING,
        )

        data = question.to_dict()

        assert data["id"] == "q-003"
        assert data["question"] == "Which hosts are affected?"  # Note: 'question' not 'text'
        assert data["source"] == "lateral"
        assert data["state"] == "pending"
        assert "priority_score" in data

    def test_can_parallelize_with(self) -> None:
        """Test question parallelization check."""
        from ares.core.models import InvestigativeQuestion, QuestionSource

        q1 = InvestigativeQuestion(
            id="q-parent",
            text="Parent question",
            source=QuestionSource.INITIAL_TRIAGE,
            rationale="Start",
            target_insight="Initial",
        )

        q2 = InvestigativeQuestion(
            id="q-child",
            text="Child question",
            source=QuestionSource.MITRE_NAVIGATOR,
            rationale="Follow-up",
            target_insight="Detail",
            generated_from_question_id="q-parent",
        )

        q3 = InvestigativeQuestion(
            id="q-independent",
            text="Independent question",
            source=QuestionSource.PYRAMID_CLIMBER,
            rationale="Separate",
            target_insight="Other",
        )

        # Child depends on parent - cannot parallelize
        assert not q2.can_parallelize_with(q1)
        assert not q1.can_parallelize_with(q2)

        # Independent questions can parallelize
        assert q1.can_parallelize_with(q3)
        assert q3.can_parallelize_with(q1)


class TestRedTeamModels:
    """Tests for Red Team rigging Models."""

    def test_target_model(self) -> None:
        """Test Target model."""
        from ares.core.models import Target

        target = Target(ip="192.168.56.50", hostname="dc01", domain="corp.local")

        assert target.ip == "192.168.56.50"
        assert target.hostname == "dc01"
        assert target.domain == "corp.local"

    def test_host_model(self) -> None:
        """Test Host model."""
        from ares.core.models import Host

        host = Host(
            ip="192.168.56.100",
            hostname="web01",
            os="Windows Server 2019",
            roles=["web", "app"],
            services=["http", "https", "rdp"],
        )

        assert host.ip == "192.168.56.100"
        assert host.roles == ["web", "app"]
        assert host.services == ["http", "https", "rdp"]

    def test_credential_model(self) -> None:
        """Test Credential model."""
        from ares.core.models import Credential

        cred = Credential(
            username="admin",
            password="P@ssw0rd",  # pragma: allowlist secret
            domain="CORP",
            source="mimikatz",
            is_admin=True,
        )

        assert cred.username == "admin"
        assert cred.is_admin is True
        assert cred.source == "mimikatz"

    def test_hash_model(self) -> None:
        """Test Hash model."""
        from ares.core.models import Hash

        h = Hash(
            username="svc_account",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="CORP",
        )

        assert h.username == "svc_account"
        assert h.hash_type == "NTLM"


class TestParsingUtilities:
    """Tests for rigging parsing utilities."""

    def test_parsing_imports(self) -> None:
        """Test that parsing utilities are importable from models."""
        from ares.core.models import (
            Model,
            parse,
            parse_set,
            try_parse,
        )

        assert Model is not None
        assert callable(parse)
        assert callable(parse_set)
        assert callable(try_parse)

    def test_try_parse_no_match(self) -> None:
        """Test try_parse returns None when no match found."""
        from ares.core.models import Evidence, try_parse

        result = try_parse("This text has no Evidence XML", Evidence)
        assert result is None

    def test_model_to_xml(self) -> None:
        """Test that models can be serialized to XML."""
        from ares.core.models import Target

        target = Target(ip="192.168.56.1", hostname="test-host")
        xml = target.to_xml()

        # Verify XML structure exists (pydantic-xml may use attributes for simple models)
        assert "<target" in xml
        assert "</target>" in xml or "/>" in xml


class TestModelValidation:
    """Tests for pydantic validation in rigging Models."""

    def test_evidence_validation_error_missing_field(self) -> None:
        """Test that missing required fields raise validation error."""
        from pydantic import ValidationError

        from ares.core.models import Evidence

        with pytest.raises(ValidationError):
            Evidence(
                id="test",
                # missing type, value, source, pyramid_level
            )

    def test_evidence_validation_error_wrong_type(self) -> None:
        """Test that wrong field types raise validation error."""
        from pydantic import ValidationError

        from ares.core.models import Evidence

        with pytest.raises(ValidationError):
            Evidence(
                id="test",
                type="ip",
                value="192.168.56.1",
                source="test",
                timestamp=None,
                pyramid_level="not-an-int",  # should be PyramidLevel
            )

    def test_confidence_accepts_float(self) -> None:
        """Test that confidence accepts float values."""
        from ares.core.models import Evidence, PyramidLevel

        evidence = Evidence(
            id="test",
            type="ip",
            value="1.2.3.4",
            source="test",
            timestamp=None,
            pyramid_level=PyramidLevel.IP_ADDRESSES,
            confidence=0.95,
        )

        assert evidence.confidence == 0.95


class TestInvestigationStateHelpers:
    """Tests for InvestigationState helper methods."""

    def _make_state(self):
        """Helper to create an InvestigationState for testing."""
        from datetime import datetime, timezone

        from ares.core.models import InvestigationStage, InvestigationState

        return InvestigationState(
            investigation_id="test-001",
            alert={"fingerprint": "test", "labels": {"alertname": "Test"}},
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
        )

    def test_get_evidence_by_id_found(self) -> None:
        """Test getting evidence by ID when it exists."""
        from ares.core.models import Evidence, PyramidLevel

        state = self._make_state()

        evidence1 = Evidence(
            id="ev-001",
            type="ip",
            value="192.168.56.1",
            source="test",
            timestamp=None,
            pyramid_level=PyramidLevel.IP_ADDRESSES,
        )
        evidence2 = Evidence(
            id="ev-002",
            type="hash",
            value="abc123",
            source="test",
            timestamp=None,
            pyramid_level=PyramidLevel.HASH_VALUES,
        )
        state.evidence.append(evidence1)
        state.evidence.append(evidence2)

        found = state.get_evidence_by_id("ev-002")
        assert found is not None
        assert found.id == "ev-002"
        assert found.value == "abc123"

    def test_get_evidence_by_id_not_found(self) -> None:
        """Test getting evidence by ID when it doesn't exist."""
        from ares.core.models import Evidence, PyramidLevel

        state = self._make_state()

        evidence = Evidence(
            id="ev-001",
            type="ip",
            value="192.168.56.1",
            source="test",
            timestamp=None,
            pyramid_level=PyramidLevel.IP_ADDRESSES,
        )
        state.evidence.append(evidence)

        found = state.get_evidence_by_id("nonexistent")
        assert found is None

    def test_get_evidence_by_id_empty_state(self) -> None:
        """Test getting evidence by ID from empty state."""
        state = self._make_state()
        found = state.get_evidence_by_id("ev-001")
        assert found is None

    def test_get_evidence_for_pyramid_questions(self) -> None:
        """Test getting evidence formatted for pyramid climber."""
        from ares.core.models import Evidence, PyramidLevel

        state = self._make_state()

        evidence1 = Evidence(
            id="ev-001",
            type="ip",
            value="192.168.56.1",
            source="network logs",
            timestamp=None,
            pyramid_level=PyramidLevel.IP_ADDRESSES,
            mitre_techniques=["T1046"],
        )
        evidence2 = Evidence(
            id="ev-002",
            type="command",
            value="whoami",
            source="process logs",
            timestamp=None,
            pyramid_level=PyramidLevel.TTPS,
            mitre_techniques=["T1059"],
        )
        state.evidence.append(evidence1)
        state.evidence.append(evidence2)

        result = state.get_evidence_for_pyramid_questions()

        assert len(result) == 2
        assert result[0]["id"] == "ev-001"
        assert result[0]["pyramid_level"] == PyramidLevel.IP_ADDRESSES.value
        assert result[1]["id"] == "ev-002"
        assert result[1]["pyramid_level"] == PyramidLevel.TTPS.value

    def test_get_evidence_for_pyramid_questions_empty(self) -> None:
        """Test getting evidence from empty state."""
        state = self._make_state()
        result = state.get_evidence_for_pyramid_questions()
        assert result == []


class TestTaskStatusAndTaskInfo:
    """Tests for TaskStatus enum and TaskInfo dataclass."""

    def test_task_status_retrying_value(self) -> None:
        """Test TaskStatus has RETRYING status."""
        from ares.core.models import TaskStatus

        assert TaskStatus.RETRYING.value == "retrying"
        assert TaskStatus.RETRYING in TaskStatus

    def test_task_status_all_values(self) -> None:
        """Test all TaskStatus enum values exist."""
        from ares.core.models import TaskStatus

        expected_statuses = {
            "pending",
            "in_progress",
            "completed",
            "failed",
            "cancelled",
            "retrying",
        }
        actual_statuses = {status.value for status in TaskStatus}
        assert actual_statuses == expected_statuses

    def test_default_max_retries_exported(self) -> None:
        """Test DEFAULT_MAX_RETRIES is exported and has correct value."""
        from ares.core.models import DEFAULT_MAX_RETRIES

        assert DEFAULT_MAX_RETRIES == 3

    def test_task_info_default_retry_fields(self) -> None:
        """Test TaskInfo has retry fields with correct defaults."""
        from datetime import datetime, timezone

        from ares.core.models import DEFAULT_MAX_RETRIES, TaskInfo, TaskStatus

        task = TaskInfo(
            task_id="test-task-001",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.PENDING,
            created_at=datetime.now(timezone.utc),
        )

        assert task.retry_count == 0
        assert task.max_retries == DEFAULT_MAX_RETRIES

    def test_task_info_custom_retry_fields(self) -> None:
        """Test TaskInfo with custom retry values."""
        from datetime import datetime, timezone

        from ares.core.models import TaskInfo, TaskStatus

        task = TaskInfo(
            task_id="test-task-002",
            task_type="lateral",
            assigned_agent="lateral",
            status=TaskStatus.RETRYING,
            created_at=datetime.now(timezone.utc),
            retry_count=2,
            max_retries=5,
        )

        assert task.retry_count == 2
        assert task.max_retries == 5
        assert task.status == TaskStatus.RETRYING

    def test_task_info_with_error(self) -> None:
        """Test TaskInfo with error message after retry."""
        from datetime import datetime, timezone

        from ares.core.models import TaskInfo, TaskStatus

        task = TaskInfo(
            task_id="test-task-003",
            task_type="enum",
            assigned_agent="enum",
            status=TaskStatus.FAILED,
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            retry_count=3,
            max_retries=3,
            error="Pod restart during execution (max retries 3 exceeded)",
        )

        assert task.status == TaskStatus.FAILED
        assert task.retry_count == task.max_retries
        assert "Pod restart" in task.error


class TestRedTeamStateHelpers:
    """Tests for RedTeamState helper methods."""

    def test_get_credential_key(self) -> None:
        """Test generating credential key."""
        from ares.core.models import RedTeamState, Target

        state = RedTeamState(
            operation_id="test-op",
            target=Target(ip="192.168.56.1"),
        )

        key = state.get_credential_key("Admin", "P@ssword123", "DOMAIN")
        assert key == "domain:admin:p@ssword123"

    def test_get_credential_key_no_domain(self) -> None:
        """Test generating credential key without domain."""
        from ares.core.models import RedTeamState, Target

        state = RedTeamState(
            operation_id="test-op",
            target=Target(ip="192.168.56.1"),
        )

        key = state.get_credential_key("user", "pass")
        assert key == ":user:pass"

    def test_admin_count(self) -> None:
        """Test counting admin credentials."""
        from ares.core.models import Credential, RedTeamState, Target

        state = RedTeamState(
            operation_id="test-op",
            target=Target(ip="192.168.56.1"),
            credentials=[
                Credential(
                    username="admin",
                    password="pass",  # pragma: allowlist secret
                    domain="test",
                    is_admin=True,
                ),
                Credential(
                    username="user",
                    password="pass",  # pragma: allowlist secret
                    domain="test",
                    is_admin=False,
                ),
                Credential(
                    username="root",
                    password="pass",  # pragma: allowlist secret
                    domain="test",
                    is_admin=True,
                ),
            ],
        )

        assert state.admin_count == 2
