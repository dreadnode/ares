"""Tests for investigation state management and question engine tools."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ares.core.lateral_analyzer import LateralGraph
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
)
from ares.tools.blue.investigation import (
    InvestigationTools,
    QuestionEngineTools,
)


class MockTechnique:
    """Mock MITRE technique with proper attributes."""

    def __init__(self, name: str, tactic: str):
        self.name = name
        self.tactic = tactic


@pytest.fixture
def investigation_state(sample_alert: dict) -> InvestigationState:
    """Create a basic investigation state for testing."""
    return InvestigationState(
        investigation_id="test-001",
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


@pytest.fixture
def investigation_state_with_evidence(sample_alert: dict) -> InvestigationState:
    """Create investigation state with pre-existing evidence."""
    return InvestigationState(
        investigation_id="test-002",
        alert=sample_alert,
        started_at=datetime.now(timezone.utc),
        stage=InvestigationStage.CAUSATION,
        evidence=[
            Evidence(
                id="ev-0000",
                type="ip_address",
                value="192.168.58.100",
                source="Query",
                timestamp=datetime.now(timezone.utc),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=["T1003"],
                confidence=0.8,
                validated=True,
            ),
        ],
        timeline=[],
        questions=[],
        identified_techniques={"T1003"},
        identified_tactics={"credential-access"},
        technique_names={"T1003": "OS Credential Dumping"},
        technique_to_tactic={"T1003": "credential-access"},
        queried_hosts={"server01"},
        queried_users={"admin"},
        executed_queries=[],
        escalated=False,
        escalation_reason=None,
        attack_synopsis=None,
        recommendations=[],
        lateral_graph=LateralGraph(),
    )


@pytest.fixture
def mock_mitre_client():
    """Create a mock MITRE client."""
    client = MagicMock()
    client.get_technique.return_value = MockTechnique("OS Credential Dumping", "credential-access")
    return client


class TestInvestigationToolsInit:
    """Tests for InvestigationTools initialization."""

    def test_init_defaults(self):
        """Test initialization with defaults."""
        tools = InvestigationTools()
        assert tools.state is None
        assert tools.mitre_client is None

    def test_set_state(self, investigation_state):
        """Test setting investigation state."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)
        assert tools.state == investigation_state

    def test_set_mitre_client(self, mock_mitre_client):
        """Test setting MITRE client."""
        tools = InvestigationTools()
        tools.set_mitre_client(mock_mitre_client)
        assert tools.mitre_client == mock_mitre_client


class TestRecordEvidence:
    """Tests for InvestigationTools.record_evidence method."""

    def test_record_evidence_no_state(self):
        """Test record_evidence with no state."""
        tools = InvestigationTools()
        result = tools.record_evidence(
            evidence_type="ip",
            value="192.168.58.100",
            source="test",
            timestamp=None,
            pyramid_level=2,
        )
        assert "ERROR" in result

    def test_record_evidence_success(self, investigation_state):
        """Test successful evidence recording."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        with patch("ares.tools.blue.investigation.validate_evidence_value") as mock_validate:
            mock_validate.return_value = (True, "q-0001")
            with patch(
                "ares.tools.blue.investigation.adjust_confidence_for_validation"
            ) as mock_adjust:
                mock_adjust.return_value = 0.8
                result = tools.record_evidence(
                    evidence_type="ip",
                    value="192.168.58.100",
                    source="Loki query",
                    timestamp="2024-01-15T14:30:00Z",
                    pyramid_level=2,
                    confidence=0.8,
                )

        assert "ev-0000" in result
        assert "validated" in result.lower()
        assert len(investigation_state.evidence) == 1

    def test_record_evidence_without_timestamp(self, investigation_state):
        """Test evidence recording without timestamp."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        with patch("ares.tools.blue.investigation.validate_evidence_value") as mock_validate:
            mock_validate.return_value = (False, None)
            with patch(
                "ares.tools.blue.investigation.adjust_confidence_for_validation"
            ) as mock_adjust:
                mock_adjust.return_value = 0.3
                result = tools.record_evidence(
                    evidence_type="hash",
                    value="a1b2c3d4e5f6",  # pragma: allowlist secret
                    source="File scan",
                    timestamp=None,
                    pyramid_level=1,
                    confidence=0.6,
                )

        assert "ev-0000" in result
        assert "UNVALIDATED" in result
        assert investigation_state.evidence[0].timestamp is None

    def test_record_evidence_with_mitre_techniques(self, investigation_state, mock_mitre_client):
        """Test evidence recording with MITRE techniques."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)
        tools.set_mitre_client(mock_mitre_client)

        with patch("ares.tools.blue.investigation.validate_evidence_value") as mock_validate:
            mock_validate.return_value = (True, "q-0001")
            with patch(
                "ares.tools.blue.investigation.adjust_confidence_for_validation"
            ) as mock_adjust:
                mock_adjust.return_value = 0.9
                tools.record_evidence(
                    evidence_type="technique",
                    value="T1003",
                    source="Detection rule",
                    timestamp="2024-01-15T14:30:00Z",
                    pyramid_level=6,
                    mitre_techniques=["T1003"],
                    confidence=0.9,
                )

        assert "T1003" in investigation_state.identified_techniques
        mock_mitre_client.get_technique.assert_called()

    def test_record_evidence_clamps_pyramid_level(self, investigation_state):
        """Test pyramid level is clamped to valid range."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        with patch("ares.tools.blue.investigation.validate_evidence_value") as mock_validate:
            mock_validate.return_value = (True, None)
            with patch(
                "ares.tools.blue.investigation.adjust_confidence_for_validation"
            ) as mock_adjust:
                mock_adjust.return_value = 0.5

                # Test level below minimum
                tools.record_evidence(
                    evidence_type="ip",
                    value="1.1.1.1",
                    source="test",
                    timestamp=None,
                    pyramid_level=0,
                )
                assert investigation_state.evidence[0].pyramid_level == PyramidLevel.HASH_VALUES

                # Test level above maximum
                tools.record_evidence(
                    evidence_type="ttp",
                    value="T1059",
                    source="test",
                    timestamp=None,
                    pyramid_level=10,
                )
                assert investigation_state.evidence[1].pyramid_level == PyramidLevel.TTPS


class TestResolveMetadata:
    """Tests for InvestigationTools._resolve_technique_metadata method."""

    def test_resolve_no_state(self):
        """Test resolve with no state."""
        tools = InvestigationTools()
        # Should not raise
        tools._resolve_technique_metadata(["T1003"])

    def test_resolve_no_client(self, investigation_state):
        """Test resolve with no MITRE client."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)
        # Should not raise
        tools._resolve_technique_metadata(["T1003"])

    def test_resolve_success(self, investigation_state, mock_mitre_client):
        """Test successful technique resolution."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)
        tools.set_mitre_client(mock_mitre_client)

        tools._resolve_technique_metadata(["T1003"])

        assert "T1003" in investigation_state.technique_names
        assert investigation_state.technique_names["T1003"] == "OS Credential Dumping"
        assert "credential-access" in investigation_state.identified_tactics

    def test_resolve_skips_already_resolved(
        self, investigation_state_with_evidence, mock_mitre_client
    ):
        """Test resolve skips already resolved techniques."""
        tools = InvestigationTools()
        tools.set_state(investigation_state_with_evidence)
        tools.set_mitre_client(mock_mitre_client)

        # T1003 is already in technique_names
        tools._resolve_technique_metadata(["T1003"])

        # Should not have called get_technique since already resolved
        mock_mitre_client.get_technique.assert_not_called()


class TestAddTimelineEvent:
    """Tests for InvestigationTools.add_timeline_event method."""

    def test_add_timeline_no_state(self):
        """Test add_timeline_event with no state."""
        tools = InvestigationTools()
        result = tools.add_timeline_event(
            timestamp="2024-01-15T14:30:00Z",
            description="Test event",
            evidence_ids=["ev-0001"],
        )
        assert "ERROR" in result

    def test_add_timeline_success(self, investigation_state):
        """Test successful timeline event addition."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.add_timeline_event(
            timestamp="2024-01-15T14:30:00Z",
            description="Suspicious PowerShell execution",
            evidence_ids=["ev-0001", "ev-0002"],
            mitre_techniques=["T1059.001"],
            confidence=0.9,
        )

        assert "tl-0000" in result
        assert len(investigation_state.timeline) == 1
        assert investigation_state.timeline[0].description == "Suspicious PowerShell execution"

    def test_add_timeline_invalid_timestamp(self, investigation_state):
        """Test timeline event with invalid timestamp uses current time."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.add_timeline_event(
            timestamp="invalid-timestamp",
            description="Test event",
            evidence_ids=[],
        )

        assert "tl-0000" in result
        # Should use current time, not fail
        assert investigation_state.timeline[0].timestamp is not None

    def test_add_timeline_sorts_by_timestamp(self, investigation_state):
        """Test timeline events are sorted by timestamp."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        # Add events out of order
        tools.add_timeline_event(
            timestamp="2024-01-15T16:00:00Z",
            description="Later event",
            evidence_ids=[],
        )
        tools.add_timeline_event(
            timestamp="2024-01-15T14:00:00Z",
            description="Earlier event",
            evidence_ids=[],
        )

        assert investigation_state.timeline[0].description == "Earlier event"
        assert investigation_state.timeline[1].description == "Later event"


class TestTransitionStage:
    """Tests for InvestigationTools.transition_stage method."""

    def test_transition_no_state(self):
        """Test transition_stage with no state."""
        tools = InvestigationTools()
        result = tools.transition_stage("causation")
        assert "ERROR" in result

    def test_transition_success(self, investigation_state):
        """Test successful stage transition."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.transition_stage("causation")

        assert "triage" in result.lower()
        assert "causation" in result.lower()
        assert investigation_state.stage == InvestigationStage.CAUSATION


class TestGetInvestigationSummary:
    """Tests for InvestigationTools.get_investigation_summary method."""

    def test_summary_no_state(self):
        """Test summary with no state."""
        tools = InvestigationTools()
        result = tools.get_investigation_summary()
        assert "error" in result

    def test_summary_success(self, investigation_state_with_evidence):
        """Test successful summary retrieval."""
        tools = InvestigationTools()
        tools.set_state(investigation_state_with_evidence)

        result = tools.get_investigation_summary()

        assert isinstance(result, dict)
        # Should contain standard summary fields from to_summary()


class TestTrackHostInvestigation:
    """Tests for InvestigationTools.track_host_investigation method."""

    def test_track_host_no_state(self):
        """Test track_host with no state."""
        tools = InvestigationTools()
        result = tools.track_host_investigation("server01")
        assert "ERROR" in result

    def test_track_host_success(self, investigation_state):
        """Test successful host tracking."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.track_host_investigation("dc01.contoso.local")

        assert "dc01.contoso.local" in investigation_state.queried_hosts
        assert isinstance(result, str)  # Returns rendered template


class TestTrackUserInvestigation:
    """Tests for InvestigationTools.track_user_investigation method."""

    def test_track_user_no_state(self):
        """Test track_user with no state."""
        tools = InvestigationTools()
        result = tools.track_user_investigation("admin")
        assert "ERROR" in result

    def test_track_user_success(self, investigation_state):
        """Test successful user tracking."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.track_user_investigation("admin@contoso.local")

        assert "admin@contoso.local" in investigation_state.queried_users
        assert isinstance(result, str)  # Returns rendered template


class TestGetSuggestedEvidence:
    """Tests for InvestigationTools.get_suggested_evidence method."""

    def test_get_suggested_empty(self):
        """Test get_suggested_evidence with no IOCs."""
        tools = InvestigationTools()

        with patch("ares.tools.blue.investigation.get_suggested_iocs") as mock_get:
            mock_get.return_value = []
            result = tools.get_suggested_evidence()

        assert len(result) == 1
        assert "message" in result[0]

    def test_get_suggested_with_iocs(self):
        """Test get_suggested_evidence with IOCs."""
        tools = InvestigationTools()

        with patch("ares.tools.blue.investigation.get_suggested_iocs") as mock_get:
            mock_get.return_value = [
                {"type": "ip", "value": "192.168.58.100", "source_query_id": "q-0001"},
                {"type": "hostname", "value": "dc01.contoso.local", "source_query_id": "q-0001"},
            ]
            result = tools.get_suggested_evidence()

        assert len(result) == 2
        assert result[0]["type"] == "ip"


class TestAnalyzeLateralMovement:
    """Tests for InvestigationTools.analyze_lateral_movement method."""

    def test_analyze_no_state(self):
        """Test analyze with no state."""
        tools = InvestigationTools()
        result = tools.analyze_lateral_movement()
        assert "error" in result

    def test_analyze_success(self, investigation_state):
        """Test successful lateral movement analysis."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.analyze_lateral_movement()

        assert "graph_summary" in result
        assert "pivot_suggestions" in result
        assert "attack_path" in result

    def test_analyze_with_focus_host(self, investigation_state):
        """Test analysis with focus host."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        # Add a connection first
        investigation_state.lateral_graph.add_connection(
            source="ws01", destination="dc01", conn_type="smb"
        )

        result = tools.analyze_lateral_movement(focus_host="ws01")

        assert "host_connections" in result


class TestRecordLateralConnection:
    """Tests for InvestigationTools.record_lateral_connection method."""

    def test_record_connection_no_state(self):
        """Test record_connection with no state."""
        tools = InvestigationTools()
        result = tools.record_lateral_connection(
            source_host="ws01", destination_host="dc01", connection_type="smb"
        )
        assert "ERROR" in result

    def test_record_connection_success(self, investigation_state):
        """Test successful connection recording."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.record_lateral_connection(
            source_host="ws01.contoso.local",
            destination_host="dc01.contoso.local",
            connection_type="smb",
            user="admin",
            mitre_technique="T1021.002",
        )

        assert "SMB" in result
        assert "ws01.contoso.local" in result
        assert "dc01.contoso.local" in result
        assert len(investigation_state.lateral_graph.connections) == 1

    def test_record_connection_same_host(self, investigation_state):
        """Test connection with same source and destination."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.record_lateral_connection(
            source_host="server01",
            destination_host="server01",
            connection_type="local",
        )

        assert "not recorded" in result.lower()


class TestGetCorrelatedAlerts:
    """Tests for InvestigationTools.get_correlated_alerts method."""

    def test_correlated_no_state(self):
        """Test correlated alerts with no state."""
        tools = InvestigationTools()
        result = tools.get_correlated_alerts()
        assert "error" in result

    def test_correlated_no_context(self, investigation_state):
        """Test correlated alerts with no correlation context."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.get_correlated_alerts()

        assert "message" in result
        assert "first alert" in result["message"]

    def test_correlated_with_context(self, investigation_state):
        """Test correlated alerts with correlation context."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        investigation_state.correlation_context = {
            "cluster_id": "cluster-0001",
            "related_alerts": 3,
            "common_hosts": ["dc01.contoso.local"],
            "common_users": ["admin"],
            "common_ips": ["192.168.58.100"],
            "techniques_in_cluster": ["T1558.003"],
            "time_range": "2024-01-15T14:00:00Z to 2024-01-15T16:00:00Z",
        }

        result = tools.get_correlated_alerts()

        assert result["cluster_id"] == "cluster-0001"
        assert result["related_alert_count"] == 3
        assert "recommendation" in result


class TestQuestionEngineToolsInit:
    """Tests for QuestionEngineTools initialization."""

    def test_init_defaults(self):
        """Test initialization with defaults."""
        tools = QuestionEngineTools()
        assert tools.mitre_navigator is None
        assert tools.pyramid_climber is None
        assert tools.state is None

    def test_set_engines(self, mock_mitre_client, investigation_state):
        """Test setting engines."""
        tools = QuestionEngineTools()
        tools.set_engines(mock_mitre_client, investigation_state)

        assert tools.mitre_navigator is not None
        assert tools.pyramid_climber is not None
        assert tools.state == investigation_state


class TestGenerateMITREQuestions:
    """Tests for QuestionEngineTools.generate_mitre_questions method."""

    def test_generate_no_engines(self):
        """Test generate with no engines."""
        tools = QuestionEngineTools()
        result = tools.generate_mitre_questions()
        assert result[0].get("error") is not None

    def test_generate_success(self, mock_mitre_client, investigation_state):
        """Test successful question generation."""
        tools = QuestionEngineTools()
        tools.set_engines(mock_mitre_client, investigation_state)

        result = tools.generate_mitre_questions()

        assert isinstance(result, list)


class TestGeneratePyramidQuestions:
    """Tests for QuestionEngineTools.generate_pyramid_questions method."""

    def test_generate_no_engines(self):
        """Test generate with no engines."""
        tools = QuestionEngineTools()
        result = tools.generate_pyramid_questions()
        assert result[0].get("error") is not None

    def test_generate_success(self, mock_mitre_client, investigation_state):
        """Test successful question generation."""
        tools = QuestionEngineTools()
        tools.set_engines(mock_mitre_client, investigation_state)

        result = tools.generate_pyramid_questions()

        assert isinstance(result, list)


class TestAssessPyramidState:
    """Tests for QuestionEngineTools.assess_pyramid_state method."""

    def test_assess_no_engines(self):
        """Test assess with no engines."""
        tools = QuestionEngineTools()
        result = tools.assess_pyramid_state()
        assert "error" in result

    def test_assess_success(self, mock_mitre_client, investigation_state):
        """Test successful pyramid assessment."""
        tools = QuestionEngineTools()
        tools.set_engines(mock_mitre_client, investigation_state)

        result = tools.assess_pyramid_state()

        assert isinstance(result, dict)


class TestGetCombinedQuestions:
    """Tests for QuestionEngineTools.get_combined_questions method."""

    def test_combined_no_engines(self):
        """Test combined with no engines."""
        tools = QuestionEngineTools()
        result = tools.get_combined_questions()
        assert result[0].get("error") is not None

    def test_combined_success(self, mock_mitre_client, investigation_state):
        """Test successful combined question generation."""
        tools = QuestionEngineTools()
        tools.set_engines(mock_mitre_client, investigation_state)

        result = tools.get_combined_questions(max_questions=5)

        assert isinstance(result, list)
        assert len(result) <= 5


class TestGetAttackChainPrecursors:
    """Tests for QuestionEngineTools.get_attack_chain_precursors method."""

    def test_precursors_not_found(self):
        """Test precursors for unknown technique."""
        tools = QuestionEngineTools()
        result = tools.get_attack_chain_precursors("T9999")

        assert result["technique"] == "T9999"
        assert "message" in result or "precursors" in result

    def test_precursors_found(self):
        """Test precursors for known technique."""
        tools = QuestionEngineTools()

        with patch("ares.tools.blue.investigation._load_attack_chains") as mock_load:
            mock_load.return_value = {
                "T1003.006": {
                    "name": "DCSync",
                    "description": "DCSync attack",
                    "precursors": [{"technique": "T1087", "name": "Account Discovery"}],
                    "windows_events": [{"event_id": 4625}],
                    "log_patterns": [],
                    "investigation_questions": [],
                }
            }
            result = tools.get_attack_chain_precursors("T1003.006")

        assert result["technique"] == "T1003.006"
        assert result["name"] == "DCSync"
        assert len(result["precursors"]) == 1


class TestGetDetectionRecipe:
    """Tests for QuestionEngineTools.get_detection_recipe method."""

    def test_recipe_not_found(self):
        """Test recipe not found."""
        tools = QuestionEngineTools()

        with patch("ares.tools.blue.investigation._load_detection_recipes") as mock_load:
            mock_load.return_value = {"password_spray": {}}
            result = tools.get_detection_recipe("unknown_recipe")

        assert "error" in result
        assert "available_recipes" in result

    def test_recipe_found(self):
        """Test recipe found."""
        tools = QuestionEngineTools()

        with patch("ares.tools.blue.investigation._load_detection_recipes") as mock_load:
            mock_load.return_value = {
                "password_spray": {
                    "name": "Password Spray Detection",
                    "description": "Detect password spray attacks",
                    "mitre_technique": "T1110.003",
                    "indicators": ["multiple failed logins"],
                    "windows_events": {"4625": "Failed Logon"},
                    "logql_queries": ["{job='auth'} |= 'failed'"],
                    "investigation_steps": {"step1": "Check logs"},
                    "detection_patterns": {},
                }
            }
            result = tools.get_detection_recipe("password_spray")

        assert result["name"] == "Password Spray Detection"
        assert result["mitre_technique"] == "T1110.003"


class TestListDetectionRecipes:
    """Tests for QuestionEngineTools.list_detection_recipes method."""

    def test_list_recipes(self):
        """Test listing detection recipes."""
        tools = QuestionEngineTools()

        with patch("ares.tools.blue.investigation._load_detection_recipes") as mock_load:
            mock_load.return_value = {
                "password_spray": {
                    "name": "Password Spray",
                    "mitre_technique": "T1110.003",
                    "description": "Detect password spray attacks",
                },
                "kerberoasting": {
                    "name": "Kerberoasting",
                    "mitre_technique": "T1558.003",
                    "description": "Detect Kerberoasting attacks",
                },
                "query_templates": {"some": "template"},  # Should be skipped
            }
            result = tools.list_detection_recipes()

        assert len(result) == 2
        assert any(r["recipe_name"] == "password_spray" for r in result)
        assert any(r["recipe_name"] == "kerberoasting" for r in result)


class TestGetQueuedQueries:
    """Tests for InvestigationTools.get_queued_queries method."""

    def test_get_queued_queries_no_state(self):
        """Test get_queued_queries with no state."""
        tools = InvestigationTools()
        result = tools.get_queued_queries()
        assert "error" in result

    def test_get_queued_queries_empty_queues(self, investigation_state):
        """Test get_queued_queries with empty queues."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.get_queued_queries()

        assert result["pivot_queries"] == []
        assert result["chain_queries"] == []
        assert result["total_queued"] == 0
        assert "recommendation" in result

    def test_get_queued_queries_with_pivot_queries(self, investigation_state):
        """Test get_queued_queries with pivot queries."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        # Add pivot queries
        investigation_state.queued_pivot_queries = [
            {"type": "pivot", "host": "dc01.contoso.local", "reason": "Lateral movement"},
            {"type": "pivot", "host": "ws01.contoso.local", "reason": "Lateral movement"},
        ]

        result = tools.get_queued_queries()

        assert len(result["pivot_queries"]) == 2
        assert result["total_queued"] == 2

    def test_get_queued_queries_with_chain_queries(self, investigation_state):
        """Test get_queued_queries with chain queries."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        # Add chain queries
        investigation_state.queued_chain_queries = [
            "detect_golden_ticket",
            "detect_lateral_movement",
        ]

        result = tools.get_queued_queries()

        assert len(result["chain_queries"]) == 2
        assert result["total_queued"] == 2

    def test_get_queued_queries_limits_to_top_3(self, investigation_state):
        """Test get_queued_queries limits results to top 3."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        # Add more than 3 pivot queries
        investigation_state.queued_pivot_queries = [
            {"type": "pivot", "host": f"host{i}.contoso.local"} for i in range(5)
        ]
        investigation_state.queued_chain_queries = [f"detect_method_{i}" for i in range(5)]

        result = tools.get_queued_queries()

        assert len(result["pivot_queries"]) == 3
        assert len(result["chain_queries"]) == 3
        # But total reflects all queued
        assert result["total_queued"] == 10


class TestPopQueuedPivot:
    """Tests for InvestigationTools.pop_queued_pivot method."""

    def test_pop_queued_pivot_no_state(self):
        """Test pop_queued_pivot with no state."""
        tools = InvestigationTools()
        result = tools.pop_queued_pivot()
        assert result is None

    def test_pop_queued_pivot_empty_queue(self, investigation_state):
        """Test pop_queued_pivot with empty queue."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.pop_queued_pivot()
        assert result is None

    def test_pop_queued_pivot_returns_first(self, investigation_state):
        """Test pop_queued_pivot returns and removes first item."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        investigation_state.queued_pivot_queries = [
            {"type": "pivot", "host": "first.contoso.local"},
            {"type": "pivot", "host": "second.contoso.local"},
        ]

        result = tools.pop_queued_pivot()

        assert result["host"] == "first.contoso.local"
        assert len(investigation_state.queued_pivot_queries) == 1
        assert investigation_state.queued_pivot_queries[0]["host"] == "second.contoso.local"


class TestPopQueuedChain:
    """Tests for InvestigationTools.pop_queued_chain method."""

    def test_pop_queued_chain_no_state(self):
        """Test pop_queued_chain with no state."""
        tools = InvestigationTools()
        result = tools.pop_queued_chain()
        assert result is None

    def test_pop_queued_chain_empty_queue(self, investigation_state):
        """Test pop_queued_chain with empty queue."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        result = tools.pop_queued_chain()
        assert result is None

    def test_pop_queued_chain_returns_first(self, investigation_state):
        """Test pop_queued_chain returns and removes first item."""
        tools = InvestigationTools()
        tools.set_state(investigation_state)

        investigation_state.queued_chain_queries = [
            "detect_golden_ticket",
            "detect_lateral_movement",
        ]

        result = tools.pop_queued_chain()

        assert result == "detect_golden_ticket"
        assert len(investigation_state.queued_chain_queries) == 1
        assert investigation_state.queued_chain_queries[0] == "detect_lateral_movement"
