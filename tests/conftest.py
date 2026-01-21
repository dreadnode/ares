"""Common test fixtures for Ares test suite."""

import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.lateral_analyzer import LateralGraph
from ares.core.models import (
    Credential,
    Evidence,
    Hash,
    Host,
    InvestigationStage,
    InvestigationState,
    InvestigativeQuestion,
    PyramidLevel,
    QuestionSource,
    RedTeamState,
    Share,
    Target,
    TimelineEvent,
    User,
)
from ares.integrations.mitre import MITREAttackClient, Tactic, Technique

# ============================================================================
# Alert Fixtures
# ============================================================================


@pytest.fixture
def sample_alert() -> dict[str, Any]:
    """Create a sample Grafana alert for testing."""
    return {
        "fingerprint": "abc123",
        "status": "firing",
        "startsAt": "2024-01-15T10:30:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "labels": {
            "alertname": "HighCPUUsage",
            "severity": "warning",
            "instance": "server01.example.com:9090",
            "job": "node_exporter",
        },
        "annotations": {
            "summary": "High CPU usage detected on server01",
            "description": "CPU usage has been above 90% for more than 5 minutes",
            "response": "1. Check running processes 2. Identify resource hogs 3. Scale if needed",
        },
        "generatorURL": "http://grafana:3000/alerting/grafana/abc123/view",
    }


@pytest.fixture
def critical_alert() -> dict[str, Any]:
    """Create a critical severity alert."""
    return {
        "fingerprint": "crit456",
        "status": "firing",
        "startsAt": "2024-01-15T11:00:00Z",
        "labels": {
            "alertname": "DCSync_Attack_Detected",
            "severity": "critical",
            "instance": "dc01.child.example.local",
            "job": "windows_events",
        },
        "annotations": {
            "summary": "Potential DCSync attack detected",
            "description": "Event 4662 detected with replication permissions",
            "response": "1. Isolate affected DC 2. Reset compromised accounts 3. Audit replication logs",
            "mitre_technique": "T1003.006",
        },
    }


@pytest.fixture
def kerberoasting_alert() -> dict[str, Any]:
    """Create a Kerberoasting alert for testing."""
    return {
        "fingerprint": "kerb789",
        "status": "firing",
        "startsAt": "2024-01-15T14:30:00Z",
        "labels": {
            "alertname": "Kerberoasting_Detected",
            "severity": "high",
            "instance": "dc01.child.example.local",
            "job": "windows_events",
            "event_id": "4769",
        },
        "annotations": {
            "summary": "Multiple TGS requests with RC4 encryption detected",
            "description": "User dave.lee requested 12 TGS tickets in 5 minutes",
            "mitre_technique": "T1558.003",
        },
    }


# ============================================================================
# Evidence Fixtures
# ============================================================================


@pytest.fixture
def sample_evidence() -> Evidence:
    """Create a sample evidence item."""
    return Evidence(
        id="ev-001",
        type="ip_address",
        value="192.168.56.100",
        source="Loki query: {job='firewall'}",
        timestamp=datetime.now(timezone.utc),
        pyramid_level=PyramidLevel.IP_ADDRESSES,
        mitre_techniques=["T1071"],
        confidence=0.85,
        validated=True,
    )


@pytest.fixture
def ttp_evidence() -> Evidence:
    """Create a TTP-level evidence item."""
    return Evidence(
        id="ev-002",
        type="ttp",
        value="DCSync replication attack using mimikatz",
        source="Windows Event 4662 with replication rights",
        timestamp=datetime.now(timezone.utc),
        pyramid_level=PyramidLevel.TTPS,
        mitre_techniques=["T1003.006"],
        confidence=0.95,
        validated=True,
    )


@pytest.fixture
def tool_evidence() -> Evidence:
    """Create a tool-level evidence item."""
    return Evidence(
        id="ev-003",
        type="tool",
        value="mimikatz.exe",
        source="Process creation event",
        timestamp=datetime.now(timezone.utc),
        pyramid_level=PyramidLevel.TOOLS,
        mitre_techniques=["T1003"],
        confidence=0.90,
        validated=True,
    )


@pytest.fixture
def hash_evidence() -> Evidence:
    """Create a hash-level evidence item."""
    return Evidence(
        id="ev-004",
        type="file_hash",
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # pragma: allowlist secret
        source="VirusTotal lookup",
        timestamp=datetime.now(timezone.utc),
        pyramid_level=PyramidLevel.HASH_VALUES,
        mitre_techniques=["T1059"],
        confidence=0.70,
        validated=False,
    )


@pytest.fixture
def evidence_list(
    sample_evidence: Evidence, ttp_evidence: Evidence, tool_evidence: Evidence
) -> list[Evidence]:
    """Create a list of evidence items."""
    return [sample_evidence, ttp_evidence, tool_evidence]


# ============================================================================
# Investigation State Fixtures
# ============================================================================


@pytest.fixture
def investigation_state(sample_alert: dict[str, Any]) -> InvestigationState:
    """Create a sample investigation state."""
    return InvestigationState(
        investigation_id=f"inv-{uuid.uuid4().hex[:8]}",
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
def populated_investigation_state(
    critical_alert: dict[str, Any], evidence_list: list[Evidence]
) -> InvestigationState:
    """Create a fully populated investigation state."""
    return InvestigationState(
        investigation_id=f"inv-{uuid.uuid4().hex[:8]}",
        alert=critical_alert,
        started_at=datetime.now(timezone.utc),
        stage=InvestigationStage.LATERAL,
        evidence=evidence_list,
        timeline=[
            TimelineEvent(
                id=f"te-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                description="Initial alert triggered",
                mitre_techniques=["T1003.006"],
                confidence=0.9,
                source="Grafana",
            ),
            TimelineEvent(
                id=f"te-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                description="DCSync replication detected",
                mitre_techniques=["T1003.006"],
                confidence=0.95,
                source="Windows Event Log",
            ),
        ],
        questions=[
            InvestigativeQuestion(
                id=f"q-{uuid.uuid4().hex[:8]}",
                text="What accounts were targeted?",
                source=QuestionSource.MITRE_NAVIGATOR,
                rationale="Identify compromised accounts",
                target_insight="Understand scope of credential compromise",
                target_technique="T1003.006",
            ),
        ],
        identified_techniques={"T1003.006", "T1078"},
        identified_tactics={"TA0006", "TA0003"},
        technique_names={"T1003.006": "DCSync", "T1078": "Valid Accounts"},
        technique_to_tactic={"T1003.006": "credential-access", "T1078": "persistence"},
        queried_hosts={"dc01.child.example.local"},
        queried_users={"alice.smith", "bob.jones"},
        executed_queries=[
            {"type": "loki", "query": '{job="windows"} |= "4662"', "result_count": 5}
        ],
        escalated=False,
        escalation_reason=None,
        attack_synopsis="DCSync attack detected targeting domain controllers",
        recommendations=["Reset affected passwords", "Audit replication permissions"],
        lateral_graph=LateralGraph(),
    )


@pytest.fixture
def escalated_investigation_state(
    populated_investigation_state: InvestigationState,
) -> InvestigationState:
    """Create an escalated investigation state."""
    populated_investigation_state.escalated = True
    populated_investigation_state.escalation_reason = (
        "Active lateral movement detected - human review required"
    )
    return populated_investigation_state


# ============================================================================
# Red Team State Fixtures
# ============================================================================


@pytest.fixture
def sample_target() -> Target:
    """Create a sample target."""
    return Target(
        ip="192.168.56.100",
        hostname="dc01.child.example.local",
        domain="child.example.local",
        os="Windows Server 2019",
    )


@pytest.fixture
def red_team_state(sample_target: Target) -> RedTeamState:
    """Create a sample red team state."""
    return RedTeamState(
        operation_id=f"op-{uuid.uuid4().hex[:8]}",
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


@pytest.fixture
def populated_red_team_state(sample_target: Target) -> RedTeamState:
    """Create a fully populated red team state."""
    return RedTeamState(
        operation_id=f"op-{uuid.uuid4().hex[:8]}",
        target=sample_target,
        started_at=datetime.now(timezone.utc),
        stage=InvestigationStage.CAUSATION,
        hosts=[
            Host(ip="192.168.56.100", hostname="dc01", os="Windows Server 2019"),
            Host(ip="192.168.56.101", hostname="dc01", os="Windows 10"),
        ],
        users=[
            User(username="alice.smith", domain="north", is_admin=True),
            User(username="bob.jones", domain="north", is_admin=False),
        ],
        credentials=[
            Credential(
                username="alice.smith",
                password="",
                domain="north",
                source="mimikatz",
                is_admin=True,
            ),
        ],
        hashes=[
            Hash(
                username="alice.smith",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="NTLM",
                domain="north",
            ),
        ],
        shares=[
            Share(host="dc01", name="SYSVOL", permissions="READ"),
            Share(host="dc01", name="C$", permissions=""),
        ],
        weaknesses=[
            "SMB Signing Disabled",
            "Kerberoastable Accounts",
        ],
        timeline=[
            TimelineEvent(
                id=f"te-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc),
                description="Initial enumeration started",
                mitre_techniques=["T1046"],
                confidence=1.0,
                source="nmap",
            ),
        ],
        identified_techniques={"T1046", "T1003", "T1558.003"},
        has_domain_admin=False,
        has_golden_ticket=False,
        report_summary=None,
    )


# ============================================================================
# MITRE ATT&CK Fixtures
# ============================================================================


@pytest.fixture
def mock_mitre_client() -> MagicMock:
    """Create a mock MITRE client."""
    client = MagicMock(spec=MITREAttackClient)
    client._loaded = True
    client._techniques = {}
    client._tactics = {}

    # Add sample techniques
    technique = Technique(
        id="T1003.006",
        name="DCSync",
        description="Adversaries may attempt to access credentials stored in AD",
        tactic="credential-access",
        tactic_id="TA0006",
        platforms=["Windows"],
        data_sources=["Active Directory", "Windows Event Logs"],
        detection="Monitor for Event ID 4662",
        is_subtechnique=True,
        parent_technique="T1003",
    )
    client._techniques["T1003.006"] = technique
    client.get_technique.return_value = technique

    # Add sample tactics
    tactic = Tactic(
        id="TA0006",
        name="Credential Access",
        shortname="credential-access",
        description="The adversary is trying to steal credentials",
    )
    client._tactics["TA0006"] = tactic
    client.get_tactic.return_value = tactic

    client.get_techniques_for_tactic.return_value = [technique]
    client.get_subtechniques.return_value = []
    client.get_all_tactics.return_value = [tactic]
    client.get_uncovered_tactics.return_value = []
    client.get_related_techniques.return_value = []
    client.search_by_keyword.return_value = [technique]

    return client


@pytest.fixture
async def real_mitre_client() -> MITREAttackClient:
    """Create a real MITRE client (requires network - use sparingly)."""
    return MITREAttackClient()
    # Don't actually load - tests should mock the data


# ============================================================================
# Temporary Directory Fixtures
# ============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_reports_dir(temp_dir: Path) -> Path:
    """Create a temporary reports directory."""
    reports_dir = temp_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


@pytest.fixture
def temp_db(temp_dir: Path) -> Path:
    """Create a temporary database file path."""
    return temp_dir / "test_investigations.db"


# ============================================================================
# Mock External Services
# ============================================================================


@pytest.fixture
def mock_grafana_response() -> dict[str, Any]:
    """Mock Grafana API response."""
    return {
        "status": "success",
        "data": {
            "result": [
                {
                    "stream": {
                        "job": "windows",
                        "computer": "dc01.child.example.local",
                    },
                    "values": [
                        ["1704105000000000000", "Event 4662: Directory Service Access"],
                        ["1704105001000000000", "Event 4624: Account Logon"],
                    ],
                }
            ]
        },
    }


@pytest.fixture
def mock_loki_logs() -> list[dict[str, Any]]:
    """Mock Loki log entries."""
    return [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "line": '{"event_id": 4662, "computer": "dc01", "user": "alice.smith"}',
            "labels": {"job": "windows", "level": "info"},
        },
        {
            "timestamp": "2024-01-15T10:30:01Z",
            "line": '{"event_id": 4624, "computer": "dc01", "user": "bob.jones"}',
            "labels": {"job": "windows", "level": "info"},
        },
    ]


@pytest.fixture
def mock_httpx_client():
    """Create a mock httpx async client."""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_response.raise_for_status = MagicMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response
    return mock_client


# ============================================================================
# Dreadnode Mock Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def mock_dreadnode(monkeypatch):
    """Mock dreadnode functions to avoid external calls during tests."""
    import dreadnode as dn

    monkeypatch.setattr(dn, "configure", lambda **_kwargs: None)
    monkeypatch.setattr(dn, "log_metric", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(dn, "log_output", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(dn, "tag", lambda *_args, **_kwargs: None)


# ============================================================================
# Query Result Fixtures
# ============================================================================


@pytest.fixture
def loki_query_result() -> dict[str, Any]:
    """Sample Loki query result."""
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {
                        "job": "windows",
                        "computer": "dc01.child.example.local",
                        "event_id": "4662",
                    },
                    "values": [
                        [
                            "1704105000000000000",
                            '{"event_id": 4662, "event_data": {"SubjectUserName": "alice.smith"}}',
                        ],
                    ],
                }
            ],
        },
    }


@pytest.fixture
def prometheus_query_result() -> dict[str, Any]:
    """Sample Prometheus query result."""
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"instance": "server01:9090", "job": "node_exporter"},
                    "value": [1704105000, "0.95"],
                },
            ],
        },
    }


# ============================================================================
# Correlation Fixtures
# ============================================================================


@pytest.fixture
def correlation_context() -> dict[str, Any]:
    """Sample correlation context for investigations."""
    return {
        "cluster_id": "cluster-123",
        "related_alerts": 3,
        "shared_indicators": ["192.168.56.100", "alice.smith"],
        "common_techniques": ["T1003.006"],
        "time_window_minutes": 30,
    }
