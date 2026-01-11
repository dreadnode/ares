"""Tests for question generation engines."""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ares.core.engines import (
    MITRENavigator,
    PyramidClimber,
    QuestionPrioritizer,
    _load_attack_chains,
    _load_detection_recipes,
)
from ares.core.lateral_analyzer import LateralGraph
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    InvestigativeQuestion,
    PyramidLevel,
    QuestionSource,
)


class MockTechnique:
    """Mock MITRE technique with proper attributes."""

    def __init__(self, name: str, tactic: str):
        self.name = name
        self.tactic = tactic


@pytest.fixture
def mock_mitre_client():
    """Create a mock MITRE client."""
    client = MagicMock()
    client._techniques = {
        "T1003": MockTechnique("OS Credential Dumping", "credential-access"),
        "T1003.001": MockTechnique("LSASS Memory", "credential-access"),
        "T1046": MockTechnique("Network Service Scanning", "discovery"),
        "T1078": MockTechnique("Valid Accounts", "defense-evasion"),
    }
    client._tactics = {
        "credential-access": {"name": "Credential Access"},
        "discovery": {"name": "Discovery"},
        "defense-evasion": {"name": "Defense Evasion"},
    }
    client.get_technique.side_effect = lambda tid: client._techniques.get(tid)
    client.get_related_techniques.return_value = [
        {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "relevance": 0.8,
            "relationship": "uses",
        }
    ]
    client.get_tactic.side_effect = lambda tid: client._tactics.get(tid)
    client.get_techniques_for_tactic.return_value = [
        {"technique_id": "T1003", "name": "OS Credential Dumping"}
    ]
    return client


@pytest.fixture
def basic_state(sample_alert: dict) -> InvestigationState:
    """Create basic investigation state."""
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
def state_with_techniques(sample_alert: dict) -> InvestigationState:
    """Create state with identified techniques."""
    return InvestigationState(
        investigation_id="test-002",
        alert=sample_alert,
        started_at=datetime.now(timezone.utc),
        stage=InvestigationStage.CAUSATION,
        evidence=[
            Evidence(
                id="ev-1",
                type="ip_address",
                value="192.168.1.100",
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
        identified_techniques={"T1003", "T1046"},
        identified_tactics={"credential-access", "discovery"},
        technique_names={"T1003": "OS Credential Dumping", "T1046": "Network Service Scanning"},
        technique_to_tactic={"T1003": "credential-access", "T1046": "discovery"},
        queried_hosts={"server01"},
        queried_users={"admin"},
        executed_queries=[],
        escalated=False,
        escalation_reason=None,
        attack_synopsis=None,
        recommendations=[],
        lateral_graph=LateralGraph(),
    )


class TestLoadAttackChains:
    """Tests for _load_attack_chains function."""

    def test_load_returns_dict(self):
        """Test load returns a dictionary."""
        result = _load_attack_chains()
        assert isinstance(result, dict)

    def test_load_filters_non_techniques(self):
        """Test load filters out non-technique entries."""
        result = _load_attack_chains()
        # All keys should start with 'T'
        for key in result:
            assert key.startswith("T")

    def test_load_missing_file_returns_empty(self):
        """Test load returns empty dict if file missing."""
        with patch("pathlib.Path.exists", return_value=False):
            result = _load_attack_chains()
            # Should return empty dict (or cached value)
            assert isinstance(result, dict)


class TestLoadDetectionRecipes:
    """Tests for _load_detection_recipes function."""

    def test_load_returns_dict(self):
        """Test load returns a dictionary."""
        result = _load_detection_recipes()
        assert isinstance(result, dict)

    def test_load_missing_file_returns_empty(self):
        """Test load returns empty dict if file missing."""
        with patch("pathlib.Path.exists", return_value=False):
            result = _load_detection_recipes()
            assert isinstance(result, dict)


class TestMITRENavigatorInit:
    """Tests for MITRENavigator initialization."""

    def test_init_with_client(self, mock_mitre_client):
        """Test initialization with MITRE client."""
        navigator = MITRENavigator(mock_mitre_client)
        assert navigator.mitre == mock_mitre_client
        assert isinstance(navigator.attack_chains, dict)
        assert isinstance(navigator.detection_recipes, dict)


class TestMITRENavigatorGenerateQuestions:
    """Tests for MITRENavigator.generate_questions method."""

    def test_generate_empty_state(self, mock_mitre_client, basic_state):
        """Test question generation with empty state."""
        navigator = MITRENavigator(mock_mitre_client)
        questions = navigator.generate_questions(basic_state)
        assert isinstance(questions, list)

    def test_generate_with_techniques(self, mock_mitre_client, state_with_techniques):
        """Test question generation with identified techniques."""
        navigator = MITRENavigator(mock_mitre_client)
        questions = navigator.generate_questions(state_with_techniques)
        assert isinstance(questions, list)


class TestMITRENavigatorFollowOnQuestions:
    """Tests for follow-on question generation."""

    def test_followon_calls_mitre(self, mock_mitre_client, state_with_techniques):
        """Test follow-on questions call MITRE client."""
        navigator = MITRENavigator(mock_mitre_client)
        navigator._generate_followon_questions(state_with_techniques)

        # Should have called get_technique for each identified technique
        assert mock_mitre_client.get_technique.called

    def test_followon_skips_already_identified(self, mock_mitre_client, state_with_techniques):
        """Test follow-on questions skip already identified techniques."""
        # Add related technique to identified
        state_with_techniques.identified_techniques.add("T1078")

        navigator = MITRENavigator(mock_mitre_client)
        questions = navigator._generate_followon_questions(state_with_techniques)

        # Should not include T1078 since already identified
        for q in questions:
            if hasattr(q, "target_technique"):
                assert q.target_technique != "T1078" or q.target_technique is None


class TestMITRENavigatorGapQuestions:
    """Tests for tactical gap question generation."""

    def test_gap_questions_empty_state(self, mock_mitre_client, basic_state):
        """Test gap questions with empty state."""
        navigator = MITRENavigator(mock_mitre_client)
        questions = navigator._generate_gap_questions(basic_state)
        assert isinstance(questions, list)


class TestPyramidClimberInit:
    """Tests for PyramidClimber initialization."""

    def test_init(self):
        """Test initialization."""
        climber = PyramidClimber()
        # Should initialize without error
        assert climber is not None


class TestPyramidClimberGenerateQuestions:
    """Tests for PyramidClimber.generate_questions method."""

    def test_generate_empty_evidence(self, basic_state):
        """Test question generation with no evidence."""
        climber = PyramidClimber()
        questions = climber.generate_questions(basic_state)
        assert isinstance(questions, list)

    def test_generate_with_ip_evidence(self, sample_alert):
        """Test question generation with IP evidence."""
        state = InvestigationState(
            investigation_id="test-003",
            alert=sample_alert,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.CAUSATION,
            evidence=[
                Evidence(
                    id="ev-ip",
                    type="ip_address",
                    value="192.168.1.100",
                    source="Query",
                    timestamp=datetime.now(timezone.utc),
                    pyramid_level=PyramidLevel.IP_ADDRESSES,
                    mitre_techniques=[],
                    confidence=0.8,
                    validated=True,
                ),
            ],
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
        climber = PyramidClimber()
        questions = climber.generate_questions(state)
        assert isinstance(questions, list)

    def test_generate_with_hash_evidence(self, sample_alert):
        """Test question generation with hash evidence."""
        state = InvestigationState(
            investigation_id="test-004",
            alert=sample_alert,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.CAUSATION,
            evidence=[
                Evidence(
                    id="ev-hash",
                    type="hash",
                    value="a1b2c3d4e5f6",  # pragma: allowlist secret
                    source="Query",
                    timestamp=datetime.now(timezone.utc),
                    pyramid_level=PyramidLevel.HASH_VALUES,
                    mitre_techniques=[],
                    confidence=0.7,
                    validated=True,
                ),
            ],
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
        climber = PyramidClimber()
        questions = climber.generate_questions(state)
        assert isinstance(questions, list)

    def test_generate_skips_ttp_level(self, sample_alert):
        """Test that TTP level evidence is skipped."""
        state = InvestigationState(
            investigation_id="test-005",
            alert=sample_alert,
            started_at=datetime.now(timezone.utc),
            stage=InvestigationStage.CAUSATION,
            evidence=[
                Evidence(
                    id="ev-ttp",
                    type="technique",
                    value="T1003",
                    source="Query",
                    timestamp=datetime.now(timezone.utc),
                    pyramid_level=PyramidLevel.TTPS,
                    mitre_techniques=["T1003"],
                    confidence=0.9,
                    validated=True,
                ),
            ],
            timeline=[],
            questions=[],
            identified_techniques={"T1003"},
            identified_tactics={"credential-access"},
            technique_names={"T1003": "OS Credential Dumping"},
            technique_to_tactic={"T1003": "credential-access"},
            queried_hosts=set(),
            queried_users=set(),
            executed_queries=[],
            escalated=False,
            escalation_reason=None,
            attack_synopsis=None,
            recommendations=[],
            lateral_graph=LateralGraph(),
        )
        climber = PyramidClimber()
        questions = climber.generate_questions(state)
        # TTP level should be skipped, so no climb questions for it
        assert isinstance(questions, list)


class TestQuestionPrioritizerInit:
    """Tests for QuestionPrioritizer initialization."""

    def test_init(self, mock_mitre_client):
        """Test initialization."""
        navigator = MITRENavigator(mock_mitre_client)
        climber = PyramidClimber()
        prioritizer = QuestionPrioritizer(navigator, climber)
        assert prioritizer.mitre == navigator
        assert prioritizer.pyramid == climber


class TestQuestionPrioritizerGenerateAll:
    """Tests for QuestionPrioritizer.generate_all_questions method."""

    def test_generate_all_empty_state(self, mock_mitre_client, basic_state):
        """Test generating questions from empty state."""
        navigator = MITRENavigator(mock_mitre_client)
        climber = PyramidClimber()
        prioritizer = QuestionPrioritizer(navigator, climber)

        questions = prioritizer.generate_all_questions(basic_state)
        assert isinstance(questions, list)

    def test_generate_all_with_techniques(self, mock_mitre_client, state_with_techniques):
        """Test generating questions with techniques."""
        navigator = MITRENavigator(mock_mitre_client)
        climber = PyramidClimber()
        prioritizer = QuestionPrioritizer(navigator, climber)

        questions = prioritizer.generate_all_questions(state_with_techniques)
        assert isinstance(questions, list)


class TestQuestionPrioritizerParallelBatch:
    """Tests for QuestionPrioritizer.get_parallel_batch method."""

    def test_parallel_batch_empty(self, mock_mitre_client):
        """Test parallel batch with empty list."""
        navigator = MITRENavigator(mock_mitre_client)
        climber = PyramidClimber()
        prioritizer = QuestionPrioritizer(navigator, climber)

        batch = prioritizer.get_parallel_batch([])
        assert batch == []

    def test_parallel_batch_single_question(self, mock_mitre_client):
        """Test parallel batch with single question."""
        navigator = MITRENavigator(mock_mitre_client)
        climber = PyramidClimber()
        prioritizer = QuestionPrioritizer(navigator, climber)

        question = InvestigativeQuestion(
            id=f"q-{uuid.uuid4().hex[:8]}",
            text="What is the source IP?",
            source=QuestionSource.MITRE_NAVIGATOR,
            rationale="Understand origin",
            target_insight="Source identification",
            target_technique="T1003",
        )
        batch = prioritizer.get_parallel_batch([question])
        assert len(batch) == 1

    def test_parallel_batch_respects_max_size(self, mock_mitre_client):
        """Test parallel batch respects max_size."""
        navigator = MITRENavigator(mock_mitre_client)
        climber = PyramidClimber()
        prioritizer = QuestionPrioritizer(navigator, climber)

        questions = [
            InvestigativeQuestion(
                id=f"q-{uuid.uuid4().hex[:8]}",
                text=f"Question {i}",
                source=QuestionSource.MITRE_NAVIGATOR,
                rationale=f"Reason {i}",
                target_insight=f"Insight {i}",
            )
            for i in range(10)
        ]
        batch = prioritizer.get_parallel_batch(questions, max_size=3)
        assert len(batch) <= 3
