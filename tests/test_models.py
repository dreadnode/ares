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
            value="192.168.58.100",
            source="loki_query",
            timestamp=datetime.now(timezone.utc),
            pyramid_level=PyramidLevel.IP_ADDRESSES,
        )

        assert evidence.id == "test-001"
        assert evidence.type == "ip"
        assert evidence.value == "192.168.58.100"
        assert evidence.pyramid_level == PyramidLevel.IP_ADDRESSES
        assert evidence.confidence == 0.5  # default
        assert evidence.validated is False  # default

    def test_evidence_with_optional_fields(self) -> None:
        """Test creating Evidence with optional fields."""
        from ares.core.models import Evidence, PyramidLevel

        evidence = Evidence(
            id="test-002",
            type="domain",
            value="malicious-external.com",
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
            value="192.168.58.1",
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

        target = Target(ip="192.168.58.50", hostname="dc01", domain="contoso.local")

        assert target.ip == "192.168.58.50"
        assert target.hostname == "dc01"
        assert target.domain == "contoso.local"

    def test_host_model(self) -> None:
        """Test Host model."""
        from ares.core.models import Host

        host = Host(
            ip="192.168.58.100",
            hostname="web01",
            os="Windows Server 2019",
            roles=["web", "app"],
            services=["http", "https", "rdp"],
        )

        assert host.ip == "192.168.58.100"
        assert host.roles == ["web", "app"]
        assert host.services == ["http", "https", "rdp"]

    def test_credential_model(self) -> None:
        """Test Credential model."""
        from ares.core.models import Credential

        cred = Credential(
            username="danj",
            password="P@ssw0rd",  # pragma: allowlist secret
            domain="CONTOSO",
            source="mimikatz",
            is_admin=True,
        )

        assert cred.username == "danj"
        assert cred.is_admin is True
        assert cred.source == "mimikatz"

    def test_hash_model(self) -> None:
        """Test Hash model."""
        from ares.core.models import Hash

        h = Hash(
            username="svc-sql",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="CONTOSO",
        )

        assert h.username == "svc-sql"
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

        target = Target(ip="192.168.58.1", hostname="test-host")
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
                value="192.168.58.1",
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
            value="192.168.58.1",
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
            value="192.168.58.1",
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
            value="192.168.58.1",
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
            task_type="recon",
            assigned_agent="recon",
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
            target=Target(ip="192.168.58.1"),
        )

        key = state.get_credential_key("danj", "P@ssword123", "CONTOSO")
        assert key == "contoso:danj:p@ssword123"

    def test_get_credential_key_no_domain(self) -> None:
        """Test generating credential key without domain."""
        from ares.core.models import RedTeamState, Target

        state = RedTeamState(
            operation_id="test-op",
            target=Target(ip="192.168.58.1"),
        )

        key = state.get_credential_key("adamb", "pass")
        assert key == ":adamb:pass"

    def test_admin_count(self) -> None:
        """Test counting admin credentials."""
        from ares.core.models import Credential, RedTeamState, Target

        state = RedTeamState(
            operation_id="test-op",
            target=Target(ip="192.168.58.1"),
            credentials=[
                Credential(
                    username="danj",
                    password="pass",  # pragma: allowlist secret
                    domain="CONTOSO",
                    is_admin=True,
                ),
                Credential(
                    username="adamb",
                    password="pass",  # pragma: allowlist secret
                    domain="CONTOSO",
                    is_admin=False,
                ),
                Credential(
                    username="karimm",
                    password="pass",  # pragma: allowlist secret
                    domain="CONTOSO",
                    is_admin=True,
                ),
            ],
        )

        assert state.admin_count == 2


class TestExtractDomains:
    """Tests for SharedRedTeamState._extract_domains."""

    def test_extracts_domains_from_host_fqdns(self) -> None:
        """Test that domains are extracted from host FQDNs."""
        from ares.core.models import Host, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        state.all_hosts = [
            Host(ip="192.168.58.183", hostname="app-srv01.contoso.local"),
            Host(ip="192.168.58.239", hostname="app-srv01.fabrikam.local"),
            Host(ip="192.168.58.92", hostname="app-srv02.fabrikam.local"),
        ]

        domains = SharedRedTeamState._extract_domains(state)

        assert "contoso.local" in domains
        assert "fabrikam.local" in domains

    def test_extracts_domains_from_nested_fqdns(self) -> None:
        """Test that domains are extracted from nested FQDNs like sub.domain.local."""
        from ares.core.models import Host, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        state.all_hosts = [
            Host(ip="192.168.58.240", hostname="dc01.corp.contoso.local"),
        ]

        domains = SharedRedTeamState._extract_domains(state)

        # Should extract "corp.contoso.local" (everything after first dot)
        assert "corp.contoso.local" in domains

    def test_extracts_domains_from_all_sources(self) -> None:
        """Test that domains are extracted from users, credentials, hashes, and hosts."""
        from ares.core.models import (
            Credential,
            Hash,
            Host,
            SharedRedTeamState,
            Target,
            User,
        )

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", hostname="dc.target.local", domain="target.local")
        state.all_users = [User(username="admin", domain="users.local")]
        state.all_credentials = [
            Credential(
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="creds.local",
            )
        ]
        state.all_hashes = [Hash(username="admin", hash_value="abc", domain="hashes.local")]
        state.all_hosts = [Host(ip="192.168.58.2", hostname="server.hosts.local")]

        domains = SharedRedTeamState._extract_domains(state)

        assert "target.local" in domains  # from target.domain
        assert "users.local" in domains  # from user
        assert "creds.local" in domains  # from credential
        assert "hashes.local" in domains  # from hash
        assert "hosts.local" in domains  # from host FQDN

    def test_extracts_domain_from_target_hostname(self) -> None:
        """Test that domain is extracted from target hostname FQDN."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", hostname="dc01.corp.local")

        domains = SharedRedTeamState._extract_domains(state)

        assert "corp.local" in domains

    def test_handles_hosts_without_fqdn(self) -> None:
        """Test that hosts without dots in hostname don't cause issues."""
        from ares.core.models import Host, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        state.all_hosts = [
            Host(ip="192.168.58.1", hostname="server1"),  # No domain
            Host(ip="192.168.58.2", hostname=""),  # Empty hostname
            Host(ip="192.168.58.3"),  # No hostname at all
        ]

        # Should not raise, should return empty list
        domains = SharedRedTeamState._extract_domains(state)
        assert domains == []


class TestResolveNetBIOSToFQDN:
    """Tests for SharedRedTeamState._resolve_netbios_to_fqdn."""

    def test_resolves_netbios_from_target_domain(self) -> None:
        """Test that NetBIOS name is resolved using target.domain."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="corp.contoso.local")

        # Should resolve "corp" to "corp.contoso.local"
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp.contoso.local"

    def test_resolves_netbios_from_existing_credentials(self) -> None:
        """Test that NetBIOS name is resolved using existing credentials."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        # No target set, but we have a credential with FQDN
        state.all_credentials = [
            Credential(
                username="adamb",
                password="Op3rat0r2024!",  # pragma: allowlist secret
                domain="corp.contoso.local",
            )
        ]

        # Should resolve "corp" to "corp.contoso.local"
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp.contoso.local"

    def test_resolves_netbios_from_known_domains(self) -> None:
        """Test that NetBIOS name is resolved using all_domains."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        state.all_domains = ["corp.contoso.local", "fabrikam.local"]

        # Should resolve "corp" to "corp.contoso.local"
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp.contoso.local"

    def test_returns_original_when_no_match(self) -> None:
        """Test that original NetBIOS name is returned when no FQDN match exists."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="fabrikam.local")

        # "corp" doesn't match "fabrikam.local", so return original
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp"

    def test_case_insensitive_matching(self) -> None:
        """Test that NetBIOS matching is case-insensitive."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="CORP.CONTOSO.LOCAL")

        # Lowercase input should match uppercase domain
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp.contoso.local"

    def test_handles_empty_state(self) -> None:
        """Test that empty state returns original NetBIOS name."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp"

    def test_priority_netbios_mapping_over_target_domain(self) -> None:
        """Test that netbios_to_fqdn mapping takes priority over target.domain."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="contoso.local")
        # Authoritative mapping from AD crossRef objects
        state.netbios_to_fqdn = {"corp": "corp.contoso.local"}

        # Should use netbios_to_fqdn mapping (highest priority)
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp.contoso.local"

    def test_priority_known_domains_over_target(self) -> None:
        """Test that all_domains takes priority over target.domain for more specific matches."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="contoso.local")
        # Known domains includes the child domain
        state.all_domains = ["corp.contoso.local", "contoso.local"]

        # Should prefer the more specific match from all_domains
        result = state._resolve_netbios_to_fqdn("corp")
        assert result == "corp.contoso.local"

    def test_prefers_longest_domain_match(self) -> None:
        """Test that the longest (most specific) domain match is preferred."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        # Multiple domains that could match "corp"
        state.all_domains = [
            "corp.local",  # shorter
            "corp.contoso.local",  # longer, more specific
        ]

        result = state._resolve_netbios_to_fqdn("corp")
        # Should prefer the longest match
        assert result == "corp.contoso.local"


class TestAddNetBIOSMapping:
    """Tests for SharedRedTeamState.add_netbios_mapping."""

    def test_adds_new_mapping(self) -> None:
        """Test adding a new NetBIOS to FQDN mapping."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        result = state.add_netbios_mapping("CORP", "corp.contoso.local")

        assert result is True
        assert state.netbios_to_fqdn["corp"] == "corp.contoso.local"
        # Should also add to all_domains
        assert "corp.contoso.local" in state.all_domains

    def test_normalizes_case(self) -> None:
        """Test that NetBIOS names are normalized to lowercase."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        state.add_netbios_mapping("CORP", "CORP.CONTOSO.LOCAL")

        # Both should be lowercase
        assert "corp" in state.netbios_to_fqdn
        assert state.netbios_to_fqdn["corp"] == "corp.contoso.local"

    def test_returns_false_for_duplicate(self) -> None:
        """Test that adding duplicate mapping returns False."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        result1 = state.add_netbios_mapping("CORP", "corp.contoso.local")
        result2 = state.add_netbios_mapping("corp", "corp.contoso.local")

        assert result1 is True
        assert result2 is False

    def test_retroactively_normalizes_credentials(self) -> None:
        """Test that adding mapping retroactively normalizes existing credentials."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        # Add credential with NetBIOS domain (no FQDN match yet)
        state.all_credentials = [
            Credential(
                username="svc_backup",
                password="BackupPass123",  # pragma: allowlist secret
                domain="corp",
                source="kerberoast",
            )
        ]

        # Now add the authoritative mapping
        state.add_netbios_mapping("CORP", "corp.contoso.local")

        # Credential should be retroactively normalized
        assert state.all_credentials[0].domain == "corp.contoso.local"

    def test_multi_domain_forest_scenario(self) -> None:
        """Test realistic multi-domain forest with parent and child domains."""
        from ares.core.models import Credential, SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Add authoritative mappings (as would come from AD crossRef query)
        state.add_netbios_mapping("CONTOSO", "contoso.local")
        state.add_netbios_mapping("CORP", "corp.contoso.local")
        state.add_netbios_mapping("FABRIKAM", "child.fabrikam.local")

        # Now credentials should resolve correctly
        cred_forest_root = Credential(
            username="admin.user",
            password="AdminPass456",  # pragma: allowlist secret
            domain="CONTOSO",
            source="test",
        )
        cred_child = Credential(
            username="svc_backup",
            password="BackupPass123",  # pragma: allowlist secret
            domain="CORP",
            source="test",
        )

        state.add_credential(cred_forest_root, "test")
        state.add_credential(cred_child, "test")

        # Each should resolve to correct domain
        assert state.all_credentials[0].domain == "contoso.local"
        assert state.all_credentials[1].domain == "corp.contoso.local"


class TestAddCredentialNetBIOSResolution:
    """Tests for add_credential NetBIOS to FQDN resolution."""

    def test_credential_netbios_resolved_to_fqdn(self) -> None:
        """Test that credential with NetBIOS domain is resolved to FQDN."""
        from ares.core.models import Credential, SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="corp.contoso.local")

        cred = Credential(
            username="alans",
            password="D1rect0r2024!",  # pragma: allowlist secret
            domain="CORP",  # NetBIOS name
            source="share_spider",
        )
        result = state.add_credential(cred, "credential_access")

        assert result is True
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "corp.contoso.local"

    def test_credential_fqdn_preserved(self) -> None:
        """Test that credential with FQDN domain is not modified."""
        from ares.core.models import Credential, SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="corp.contoso.local")

        cred = Credential(
            username="adamb",
            password="Op3rat0r2024!",  # pragma: allowlist secret
            domain="corp.contoso.local",  # Already FQDN
            source="kerberoast",
        )
        result = state.add_credential(cred, "credential_access")

        assert result is True
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "corp.contoso.local"

    def test_netbios_deduplication_with_fqdn(self) -> None:
        """Test that NetBIOS credential is deduplicated against FQDN credential."""
        from ares.core.models import Credential, SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="corp.contoso.local")

        cred1 = Credential(
            username="adamb",
            password="Op3rat0r2024!",  # pragma: allowlist secret
            domain="corp.contoso.local",
            source="kerberoast",
        )
        result1 = state.add_credential(cred1, "credential_access")
        assert result1 is True

        cred2 = Credential(
            username="adamb",
            password="Op3rat0r2024!",  # pragma: allowlist secret
            domain="CORP",  # NetBIOS will be resolved to FQDN
            source="share_spider",
        )
        result2 = state.add_credential(cred2, "credential_access")
        assert result2 is False  # Duplicate

        assert len(state.all_credentials) == 1


class TestAddHashNetBIOSResolution:
    """Tests for add_hash NetBIOS to FQDN resolution."""

    def test_hash_netbios_resolved_to_fqdn(self) -> None:
        """Test that hash with NetBIOS domain is resolved to FQDN."""
        from ares.core.models import Hash, SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="corp.contoso.local")

        hash_obj = Hash(
            username="alans",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="CORP",  # NetBIOS name
        )
        result = state.add_hash(hash_obj, "secretsdump")

        assert result is True
        assert len(state.all_hashes) == 1
        assert state.all_hashes[0].domain == "corp.contoso.local"


class TestAddUserNetBIOSResolution:
    """Tests for add_user NetBIOS to FQDN resolution."""

    def test_user_netbios_resolved_to_fqdn(self) -> None:
        """Test that user with NetBIOS domain is resolved to FQDN."""
        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(operation_id="test-op")
        state.target = Target(ip="192.168.58.1", domain="corp.contoso.local")

        result = state.add_user("alans", "CORP")

        assert result is True
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "corp.contoso.local"


class TestRetroactiveDomainNormalization:
    """Tests for retroactive domain normalization when FQDN is discovered."""

    def test_add_domain_retroactively_normalizes_credentials(self) -> None:
        """Test that adding FQDN updates existing credentials with matching NetBIOS domain."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        cred = Credential(
            username="testuser",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso",  # NetBIOS name
            source="kerberoast",
        )
        state.add_credential(cred, "credential_access")

        assert state.all_credentials[0].domain == "contoso"

        result = state.add_domain("contoso.local")

        assert result is True
        assert state.all_credentials[0].domain == "contoso.local"

    def test_add_domain_retroactively_normalizes_users(self) -> None:
        """Test that adding FQDN updates existing users with matching NetBIOS domain."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        state.add_user("jsmith", "contoso")

        assert state.all_users[0].domain == "contoso"

        state.add_domain("contoso.local")

        assert state.all_users[0].domain == "contoso.local"

    def test_add_domain_retroactively_normalizes_hashes(self) -> None:
        """Test that adding FQDN updates existing hashes with matching NetBIOS domain."""
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        hash_obj = Hash(
            username="jsmith",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso",
        )
        state.add_hash(hash_obj, "secretsdump")

        assert state.all_hashes[0].domain == "contoso"

        state.add_domain("contoso.local")

        assert state.all_hashes[0].domain == "contoso.local"

    def test_add_domain_normalizes_multiple_items(self) -> None:
        """Test that FQDN normalizes multiple credentials/users/hashes."""
        from ares.core.models import Credential, Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # Add multiple items with NetBIOS domain
        state.add_user("user1", "contoso")
        state.add_user("user2", "contoso")

        cred1 = Credential(
            username="cred1",
            password="pass1",  # pragma: allowlist secret
            domain="contoso",
            source="test",
        )
        cred2 = Credential(
            username="cred2",
            password="pass2",  # pragma: allowlist secret
            domain="contoso",
            source="test",
        )
        state.add_credential(cred1, "test")
        state.add_credential(cred2, "test")

        hash1 = Hash(username="hash1", hash_value="abc123", domain="contoso")
        hash2 = Hash(username="hash2", hash_value="def456", domain="contoso")
        state.add_hash(hash1, "test")
        state.add_hash(hash2, "test")

        # Add FQDN - should normalize all
        state.add_domain("contoso.local")

        # Verify all normalized
        assert all(u.domain == "contoso.local" for u in state.all_users)
        assert all(c.domain == "contoso.local" for c in state.all_credentials)
        assert all(h.domain == "contoso.local" for h in state.all_hashes)

    def test_add_domain_deduplicates_after_normalization(self) -> None:
        """Test that adding FQDN retroactively normalizes and deduplicates credentials."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # Add two credentials with NetBIOS domain that will become duplicates after normalization
        cred1 = Credential(
            username="testuser",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso",  # NetBIOS
            source="source1",
        )
        cred2 = Credential(
            username="testuser",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso",  # Same NetBIOS (would be duplicate, but same source)
            source="source2",
        )
        state.add_credential(cred1, "test")
        # cred2 will be merged into cred1 since they're the same credential
        state.add_credential(cred2, "test")

        # Should have 1 credential (merged sources)
        assert len(state.all_credentials) == 1

        # Add FQDN domain - should trigger retroactive normalization
        state.add_domain("contoso.local")

        # After normalization, credential should have FQDN domain
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "contoso.local"

    def test_add_domain_ignores_non_matching_netbios(self) -> None:
        """Test that FQDN only normalizes matching NetBIOS domains."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # Add credentials with different NetBIOS domains
        cred1 = Credential(
            username="user1",
            password="pass1",  # pragma: allowlist secret
            domain="contoso",
            source="test",
        )
        cred2 = Credential(
            username="user2",
            password="pass2",  # pragma: allowlist secret
            domain="fabrikam",  # Different NetBIOS
            source="test",
        )
        state.add_credential(cred1, "test")
        state.add_credential(cred2, "test")

        # Add FQDN for "contoso" only
        state.add_domain("contoso.local")

        # Only "contoso" should be normalized
        assert state.all_credentials[0].domain == "contoso.local"
        assert state.all_credentials[1].domain == "fabrikam"  # Unchanged

    def test_add_domain_case_insensitive_matching(self) -> None:
        """Test that NetBIOS matching is case-insensitive."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # Add credential with uppercase NetBIOS
        cred = Credential(
            username="testuser",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="CONTOSO",  # Uppercase
            source="test",
        )
        state.add_credential(cred, "test")

        # Add lowercase FQDN - should still match
        state.add_domain("contoso.local")

        # Domain should be normalized (lowercase FQDN)
        assert state.all_credentials[0].domain == "contoso.local"

    def test_add_domain_non_fqdn_does_not_trigger_normalization(self) -> None:
        """Test that adding a non-FQDN domain (no dots) does not trigger normalization."""
        from ares.core.models import Credential, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # Add credential with NetBIOS domain
        cred = Credential(
            username="testuser",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso",
            source="test",
        )
        state.add_credential(cred, "test")

        # Add another NetBIOS name (no dot) - should not trigger normalization
        state.add_domain("fabrikam")

        # Credential domain should remain unchanged
        assert state.all_credentials[0].domain == "contoso"


class TestDomainAdminAutoDetection:
    """Tests for automatic domain admin detection via hash analysis.

    CRITICAL: Only krbtgt NTLM hash should trigger DA auto-detection.
    Administrator hash does NOT trigger DA because it could be a local admin.
    """

    def test_krbtgt_hash_triggers_domain_admin(self) -> None:
        """Test that krbtgt NTLM hash correctly triggers domain admin flag."""
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        assert state.has_domain_admin is False

        hash_obj = Hash(
            username="krbtgt",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
        )
        state.add_hash(hash_obj, "secretsdump")

        assert state.has_domain_admin is True
        assert state.domain_admin_path is not None
        assert len(state.weaknesses) > 0

    def test_administrator_hash_does_not_trigger_domain_admin(self) -> None:
        """Test that Administrator NTLM hash does NOT trigger domain admin.

        This is critical: "Administrator" could be a LOCAL admin on a workstation,
        not the domain Administrator. Getting 7 hashes instead of thousands from
        ntds.dit = NOT domain admin.
        """
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")
        assert state.has_domain_admin is False

        hash_obj = Hash(
            username="Administrator",
            hash_value="aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889",
            hash_type="NTLM",
            domain="contoso.local",
        )
        state.add_hash(hash_obj, "secretsdump")

        # Administrator hash should NOT set domain admin
        assert state.has_domain_admin is False
        assert state.domain_admin_path is None

    def test_administrator_lowercase_does_not_trigger_domain_admin(self) -> None:
        """Test that administrator (lowercase) also doesn't trigger DA."""
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        hash_obj = Hash(
            username="administrator",
            hash_value="aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889",
            hash_type="NTLM",
            domain="contoso.local",
        )
        state.add_hash(hash_obj, "lsass_dump")

        assert state.has_domain_admin is False

    def test_local_admin_does_not_trigger_domain_admin(self) -> None:
        """Test that local Administrator from workstation doesn't trigger DA."""
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # This is what happens when you dump LSASS on a workstation
        hash_obj = Hash(
            username="Administrator",
            hash_value="aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889",
            hash_type="NTLM",
            domain="WS01",  # Workstation name, not domain
        )
        state.add_hash(hash_obj, "mimikatz")

        assert state.has_domain_admin is False

    def test_non_ntlm_krbtgt_does_not_trigger_domain_admin(self) -> None:
        """Test that non-NTLM krbtgt hash doesn't trigger DA."""
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        # Kerberos TGT is not the same as NTLM hash
        hash_obj = Hash(
            username="krbtgt",
            hash_value="$krb5tgs$23$*krbtgt$CONTOSO.LOCAL$...",
            hash_type="kerberos",
            domain="contoso.local",
        )
        state.add_hash(hash_obj, "kerberoast")

        assert state.has_domain_admin is False

    def test_regular_user_hash_does_not_trigger_domain_admin(self) -> None:
        """Test that regular user NTLM hash doesn't trigger DA."""
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-op")

        hash_obj = Hash(
            username="jsmith",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
        )
        state.add_hash(hash_obj, "secretsdump")

        assert state.has_domain_admin is False
