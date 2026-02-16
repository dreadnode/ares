"""Data models for Ares SOC Investigation Agent.

This module provides structured data models for SOC investigations and red team operations,
built on rigging's Model class for automatic serialization and LLM output parsing.

Example usage for LLM output parsing:
    >>> from ares.core.models import Evidence, parse, parse_set
    >>> # Parse a single Evidence from LLM response text
    >>> evidence, _ = parse(llm_response, Evidence)
    >>> # Parse multiple Evidence items
    >>> items = [e for e, _ in parse_set(llm_response, Evidence)]

"""

from __future__ import annotations

import json
import types
import uuid
from dataclasses import dataclass, field, is_dataclass
from dataclasses import fields as dc_fields
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Union, get_args, get_origin, get_type_hints

from loguru import logger
from pydantic import BaseModel, Field, computed_field
from rigging import Model
from rigging.model import element, wrapped

# Re-export rigging parsing utilities for convenient access
from rigging.parsing import (
    parse,
    parse_many,
    parse_set,
    try_parse,
    try_parse_many,
    try_parse_set,
)

from ares.core.config import get_default_max_retries

# Default retry count for tasks - exported for test compatibility
DEFAULT_MAX_RETRIES = 3

__all__ = [
    # Constants
    "DEFAULT_MAX_RETRIES",
    # Multi-Agent Models
    "AgentInfo",
    "AgentLocalState",
    "AgentRole",
    # Core Models
    "Credential",
    "Evidence",
    "Hash",
    "Host",
    "InvestigationStage",
    "InvestigationState",
    "InvestigativeQuestion",
    "Model",
    "PyramidLevel",
    "QuestionSource",
    "QuestionState",
    "RedTeamState",
    "Share",
    "SharedRedTeamState",
    "Target",
    "TaskInfo",
    "TaskResult",
    "TaskStatus",
    "TimelineEvent",
    "User",
    "VulnerabilityInfo",
    # Parsing utilities
    "parse",
    "parse_many",
    "parse_set",
    "try_parse",
    "try_parse_many",
    "try_parse_set",
]


class PyramidLevel(IntEnum):
    """Levels of the Pyramid of Pain.

    Higher levels are harder for adversaries to change.
    The goal is always to climb toward TTPs.

    Attributes:
        HASH_VALUES: Level 1 - Trivial to change.
        IP_ADDRESSES: Level 2 - Easy to change.
        DOMAIN_NAMES: Level 3 - Simple to change.
        NETWORK_HOST_ARTIFACTS: Level 4 - Annoying to change.
        TOOLS: Level 5 - Challenging to change.
        TTPS: Level 6 - Tough to change (the goal).
    """

    HASH_VALUES = 1
    IP_ADDRESSES = 2
    DOMAIN_NAMES = 3
    NETWORK_HOST_ARTIFACTS = 4
    TOOLS = 5
    TTPS = 6


class QuestionSource(Enum):
    """Source engine that generated a question."""

    MITRE_NAVIGATOR = "mitre"
    PYRAMID_CLIMBER = "pyramid"
    LATERAL_EXPANSION = "lateral"
    INITIAL_TRIAGE = "triage"


class QuestionState(Enum):
    """State of an investigative question."""

    PENDING = "pending"
    EXECUTING = "executing"
    ANSWERED = "answered"
    UNANSWERABLE = "unanswerable"
    SUPERSEDED = "superseded"


class InvestigationStage(Enum):
    """Stages of the investigation workflow."""

    TRIAGE = "triage"  # WHAT is happening
    CAUSATION = "causation"  # WHY it happened
    LATERAL = "lateral"  # What is the SCOPE
    SYNTHESIS = "synthesis"  # Generate report


class Evidence(Model):
    """A piece of evidence discovered during investigation.

    Attributes:
        id: Unique identifier for this evidence.
        type: Type of evidence - one of: ip, domain, hash, process, user,
            file, artifact, tool, technique.
        value: The actual evidence value.
        source: Query or tool that found this evidence.
        timestamp: When this evidence was observed (optional).
        pyramid_level: Classification on Pyramid of Pain scale (1-6).
        mitre_techniques: Associated MITRE ATT&CK technique IDs.
        confidence: Confidence score between 0.0 and 1.0.
        metadata: Additional context about this evidence.
        source_query_id: ID of the query that produced this evidence (for provenance).
        validated: Whether this evidence was validated against query results.
    """

    id: str
    type: str
    value: str
    source: str
    timestamp: datetime | None
    pyramid_level: PyramidLevel
    mitre_techniques: list[str] = wrapped("mitre-techniques", element(tag="technique", default=[]))
    confidence: float = 0.5
    metadata: dict[str, str] = Field(default_factory=dict)
    source_query_id: str | None = None
    validated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return self.model_dump(mode="json")


class TimelineEvent(Model):
    """An event in the investigation timeline.

    Attributes:
        id: Unique identifier for this timeline event.
        timestamp: When this event occurred.
        description: Human-readable description of the event.
        evidence_ids: List of evidence IDs supporting this event.
        mitre_techniques: MITRE ATT&CK technique IDs associated with this event.
        confidence: Confidence score between 0.0 and 1.0.
        source: Source of this event (e.g., "investigation", "alert").
    """

    id: str
    timestamp: datetime
    description: str
    evidence_ids: list[str] = wrapped("evidence-ids", element(tag="evidence-id", default=[]))
    mitre_techniques: list[str] = wrapped("mitre-techniques", element(tag="technique", default=[]))
    confidence: float = 0.5
    source: str = "investigation"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return self.model_dump(mode="json")


class InvestigativeQuestion(Model):
    """A question that drives the investigation forward.

    Generated by the MITRE Navigator and Pyramid Climber engines.

    Attributes:
        id: Unique identifier for this question.
        text: The question text.
        source: Which engine generated this question.
        rationale: Why this question matters.
        target_insight: What we hope to learn from answering this.
        target_technique: MITRE technique this question targets (MITRE-specific).
        technique_chain_from: Technique this follows from (MITRE-specific).
        current_pyramid_level: Starting pyramid level (Pyramid-specific).
        target_pyramid_level: Target pyramid level (Pyramid-specific).
        pyramid_elevation_score: Score 0-1 for elevation potential.
        mitre_coverage_score: Score 0-1 for MITRE coverage value.
        confidence_impact_score: Score 0-1 for confidence improvement potential.
        urgency_score: Score 0-1 for time sensitivity.
        state: Current state of this question.
        created_at: When this question was generated.
        answered_at: When this question was answered.
        generated_from_evidence_ids: Evidence that prompted this question.
        generated_from_question_id: Parent question if part of a chain.
        answer_evidence_ids: Evidence collected while answering.
        answer_summary: Summary of the answer.
    """

    id: str
    text: str
    source: QuestionSource
    rationale: str
    target_insight: str

    target_technique: str | None = None
    technique_chain_from: str | None = None

    current_pyramid_level: int | None = None
    target_pyramid_level: int | None = None

    pyramid_elevation_score: float = 0.0
    mitre_coverage_score: float = 0.0
    confidence_impact_score: float = 0.0
    urgency_score: float = 0.0

    state: QuestionState = QuestionState.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    answered_at: datetime | None = None

    generated_from_evidence_ids: list[str] = wrapped(
        "generated-from-evidence-ids", element(tag="evidence-id", default=[])
    )
    generated_from_question_id: str | None = None

    answer_evidence_ids: list[str] = wrapped(
        "answer-evidence-ids", element(tag="evidence-id", default=[])
    )
    answer_summary: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def priority_score(self) -> float:
        """Composite priority score.

        Weights:
        - Pyramid elevation: 3x (we want TTPs, not IOCs)
        - MITRE coverage: 2x (tactical completeness)
        - Confidence impact: 2x (certainty is valuable)
        - Urgency: 1x (time sensitivity)
        """
        return (
            (self.pyramid_elevation_score * 3.0)
            + (self.mitre_coverage_score * 2.0)
            + (self.confidence_impact_score * 2.0)
            + (self.urgency_score * 1.0)
        )

    def can_parallelize_with(self, other: InvestigativeQuestion) -> bool:
        """Check if this question can run in parallel with another."""
        # Questions in a reasoning chain should be sequential
        if self.generated_from_question_id == other.id:
            return False
        return other.generated_from_question_id != self.id

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        # Use custom format to match original API
        return {
            "id": self.id,
            "question": self.text,
            "source": self.source.value,
            "rationale": self.rationale,
            "target_insight": self.target_insight,
            "target_technique": self.target_technique,
            "current_pyramid_level": self.current_pyramid_level,
            "target_pyramid_level": self.target_pyramid_level,
            "priority_score": self.priority_score,
            "state": self.state.value,
        }


@dataclass
class InvestigationState:
    """Mutable state for an investigation.

    This is the central state object that tracks everything
    discovered during the investigation.

    Attributes:
        investigation_id: Unique identifier for this investigation.
        alert: The original alert dictionary that triggered investigation.
        stage: Current investigation stage (triage, causation, lateral, synthesis).
        started_at: When the investigation began.
        evidence: List of all evidence collected.
        timeline: List of timeline events in chronological order.
        questions: List of all investigative questions generated.
        executed_queries: Log of all queries executed.
        identified_techniques: Set of MITRE ATT&CK technique IDs found.
        identified_tactics: Set of MITRE ATT&CK tactic IDs found.
        queried_hosts: Set of hosts that have been investigated.
        queried_users: Set of users that have been investigated.
        queried_data_sources: Set of data sources queried.
        technique_names: Cached mapping of technique IDs to names.
        technique_to_tactic: Cached mapping of techniques to their tactics.
        escalated: Whether investigation was escalated to human analyst.
        escalation_reason: Reason for escalation if applicable.
        attack_synopsis: Summary of the attack for the report.
        recommendations: List of recommended actions.
        lateral_graph: Graph tracking lateral movement between hosts.
        correlation_context: Context from alert correlation (related alerts, common IOCs).
        queued_pivot_queries: Auto-generated pivot queries for hosts discovered via lateral movement.
        queued_chain_queries: Auto-generated follow-up detection methods based on evidence type.
        executed_query_types: Set of query method names already executed to avoid duplicates.
    """

    investigation_id: str
    alert: dict[str, Any]
    stage: InvestigationStage = InvestigationStage.TRIAGE
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    evidence: list[Evidence] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)

    questions: list[InvestigativeQuestion] = field(default_factory=list)

    executed_queries: list[dict] = field(default_factory=list)

    identified_techniques: set[str] = field(default_factory=set)
    identified_tactics: set[str] = field(default_factory=set)
    queried_hosts: set[str] = field(default_factory=set)
    queried_users: set[str] = field(default_factory=set)
    queried_data_sources: set[str] = field(default_factory=set)

    technique_names: dict[str, str] = field(default_factory=dict)
    technique_to_tactic: dict[str, str] = field(default_factory=dict)

    escalated: bool = False
    escalation_reason: str | None = None
    attack_synopsis: str | None = None
    recommendations: list[str] = field(default_factory=list)

    # Lateral movement tracking
    lateral_graph: Any = field(
        default=None
    )  # LateralGraph - imported lazily to avoid circular imports

    # Alert correlation context
    correlation_context: dict[str, Any] | None = None

    # Auto-pivot and detection chaining queues
    queued_pivot_queries: list[dict] = field(default_factory=list)
    queued_chain_queries: list[str] = field(default_factory=list)
    executed_query_types: set[str] = field(default_factory=set)

    def __post_init__(self):
        """Initialize lateral graph if not provided."""
        if self.lateral_graph is None:
            from ares.core.lateral_analyzer import LateralGraph

            self.lateral_graph = LateralGraph()

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def highest_pyramid_level(self) -> int:
        if not self.evidence:
            return 0
        return max(e.pyramid_level.value for e in self.evidence)

    @property
    def ttp_count(self) -> int:
        return len([e for e in self.evidence if e.pyramid_level == PyramidLevel.TTPS])

    def get_evidence_by_id(self, evidence_id: str) -> Evidence | None:
        for e in self.evidence:
            if e.id == evidence_id:
                return e
        return None

    def get_pending_questions(self) -> list[InvestigativeQuestion]:
        return [q for q in self.questions if q.state == QuestionState.PENDING]

    def get_evidence_for_pyramid_questions(self) -> list[dict]:
        """Get evidence formatted for pyramid climber."""
        return [
            {
                "id": e.id,
                "type": e.type,
                "value": e.value,
                "pyramid_level": e.pyramid_level.value,
            }
            for e in self.evidence
        ]

    def to_summary(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "stage": self.stage.value,
            "evidence_count": self.evidence_count,
            "timeline_events": len(self.timeline),
            "questions_pending": len(self.get_pending_questions()),
            "questions_total": len(self.questions),
            "techniques_identified": list(self.identified_techniques),
            "highest_pyramid_level": self.highest_pyramid_level,
            "ttp_count": self.ttp_count,
            "hosts_investigated": list(self.queried_hosts),
            "users_investigated": list(self.queried_users),
        }


# Red Team Models
class Target(Model):
    """Primary target information."""

    ip: str
    hostname: str = ""
    domain: str = ""


class Host(Model):
    """Discovered host information."""

    ip: str
    hostname: str = ""
    os: str = ""
    roles: list[str] = wrapped("roles", element(tag="role", default=[]))
    services: list[str] = wrapped("services", element(tag="service", default=[]))
    is_dc: bool = False
    owned: bool = False

    def detect_dc(self) -> bool:
        """Detect if this host is a domain controller based on services/hostname/roles.

        Returns True if host appears to be a DC based on:
        - "dc" in hostname
        - "domain controller" in roles
        - Kerberos (88/tcp) or LDAP (389/tcp) services
        """
        hostname_lower = (self.hostname or "").lower()
        roles_lower = " ".join(self.roles).lower() if self.roles else ""
        if "dc" in hostname_lower or "domain controller" in roles_lower:
            return True
        dc_port_prefixes = ("88/tcp", "389/tcp")
        dc_service_names = ("kerberos", "ldap")
        for svc in self.services:
            svc_lower = svc.lower()
            if any(svc_lower.startswith(port) for port in dc_port_prefixes):
                return True
            if any(name in svc_lower for name in dc_service_names):
                return True
        return False

    def update_dc_status(self) -> None:
        """Update is_dc flag based on current services/hostname/roles."""
        self.is_dc = self.detect_dc()


class User(Model):
    """Discovered user account.

    Attributes:
        username: The username.
        domain: The domain.
        description: User description from LDAP.
        is_admin: Whether this is an admin user.
        source: Tool/method that discovered this user.
    """

    username: str
    domain: str = ""
    description: str = ""
    is_admin: bool = False
    source: str = ""


class Credential(Model):
    """Discovered credential.

    Attributes:
        id: Unique identifier for chain tracking.
        username: The username.
        password: The password.
        domain: The domain.
        source: Tool/method that discovered this credential.
        is_admin: Whether this is an admin credential.
        parent_id: ID of the credential/hash that enabled this discovery (for attack chain).
        attack_step: Position in the attack chain (0 = initial access).
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password: str
    domain: str = ""
    source: str = ""  # where it was found
    is_admin: bool = False
    parent_id: str | None = None  # ID of credential/hash that enabled this discovery
    attack_step: int = 0  # Position in attack chain


class Hash(Model):
    """Discovered password hash.

    Attributes:
        id: Unique identifier for chain tracking.
        username: The username.
        hash_value: The hash value.
        hash_type: Type of hash (NTLM, etc.).
        domain: The domain.
        cracked_password: Password if cracked.
        source: Tool/method that discovered this hash.
        discovered_at: When the hash was discovered.
        parent_id: ID of the credential/hash that enabled this discovery (for attack chain).
        attack_step: Position in the attack chain (0 = initial access).
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    hash_value: str
    hash_type: str = "NTLM"
    domain: str = ""
    cracked_password: str = ""
    source: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    parent_id: str | None = None  # ID of credential/hash that enabled this discovery
    attack_step: int = 0  # Position in attack chain


class Share(Model):
    """Discovered SMB share."""

    host: str
    name: str
    permissions: str = ""  # READ, WRITE, READ/WRITE
    comment: str = ""


@dataclass
class RedTeamState:
    """Tracks state for red team operations."""

    operation_id: str
    target: Target
    completed: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    stage: InvestigationStage = InvestigationStage.TRIAGE
    report_summary: str = ""

    # Discovery tracking
    hosts: list[Host] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    hashes: list[Hash] = field(default_factory=list)
    shares: list[Share] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)

    # Operation tracking
    queried_hosts: set[str] = field(default_factory=set)
    scanned_targets: set[str] = field(default_factory=set)
    tested_credentials: set[str] = field(default_factory=set)
    timeline: list[TimelineEvent] = field(default_factory=list)
    identified_techniques: set[str] = field(default_factory=set)
    pending_credential_findings: set[str] = field(default_factory=set)

    # Success flags
    has_domain_admin: bool = False
    has_golden_ticket: bool = False

    @property
    def host_count(self) -> int:
        """Count of discovered hosts."""
        return len(self.hosts)

    @property
    def credential_count(self) -> int:
        """Count of discovered credentials."""
        return len(self.credentials)

    @property
    def admin_count(self) -> int:
        """Count of admin credentials."""
        return sum(1 for c in self.credentials if c.is_admin)

    def get_credential_key(self, username: str, password: str, domain: str = "") -> str:
        """Generate unique key for credential tracking."""
        return f"{domain}:{username}:{password}".lower()


# Multi-Agent Shared State Models


class AgentRole(Enum):
    """Specialized roles for multi-agent red team operations."""

    ORCHESTRATOR = "orchestrator"  # Central coordinator, dispatches to workers
    RECON = "recon"  # Network scanning, enumeration, BloodHound
    CREDENTIAL_ACCESS = "credential_access"
    CRACKER = "cracker"
    ACL = "acl"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    COERCION = "coercion"


class TaskStatus(Enum):
    """Status of a dispatched task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"  # Marked for retry after pod restart


@dataclass
class TaskInfo:
    """Information about a dispatched task."""

    task_id: str
    task_type: str
    assigned_agent: str
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    # Last activity time - updated when task shows progress (heartbeat, status change)
    # Used for stale task detection - defaults to created_at if never updated
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    params: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    retry_count: int = 0
    max_retries: int = field(default_factory=get_default_max_retries)


@dataclass
class TaskResult:
    """Result of a completed task."""

    task_id: str
    success: bool
    result: Any = None
    error: str | None = None
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class VulnerabilityInfo:
    """Information about a discovered vulnerability."""

    vuln_id: str
    vuln_type: str  # ADCS_ESC1, UNCONSTRAINED_DELEGATION, ACL_ABUSE, etc.
    target: str
    discovered_by: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)
    recommended_agent: str = ""  # Which agent should exploit this
    priority: int = 5  # 1=highest, 10=lowest


@dataclass
class AgentInfo:
    """Metadata about a registered agent."""

    name: str
    pod_name: str
    role: AgentRole
    capabilities: set[str] = field(default_factory=set)
    status: str = "idle"  # idle, busy, offline
    current_task: str | None = None
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =========================================================================
# JSON serialization helpers for SharedRedTeamState
# =========================================================================

# Fields to exclude from JSON serialization (transient runtime references)
# Fields excluded from JSON serialization (transient state, not persisted)
_EXCLUDED_FIELDS = frozenset({"_dispatcher", "_background_tasks"})


def _to_json(val: Any) -> Any:
    """Recursively convert a value to JSON-safe types."""
    if val is None or isinstance(val, (str, int, float, bool)):
        return val
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, Enum):
        return val.value
    if isinstance(val, set):
        return sorted(_to_json(v) for v in val)
    if isinstance(val, BaseModel):
        return val.model_dump(mode="json")
    if is_dataclass(val) and not isinstance(val, type):
        return {
            f.name: _to_json(getattr(val, f.name))
            for f in dc_fields(val)
            if f.name not in _EXCLUDED_FIELDS
        }
    if isinstance(val, dict):
        return {str(k): _to_json(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_to_json(v) for v in val]
    return str(val)


def _from_json(val: Any, hint: type) -> Any:  # noqa: PLR0912
    """Reconstruct a typed value from JSON using the type annotation."""
    origin = get_origin(hint)
    args = get_args(hint)

    # Handle Optional[X] / X | None  (Union with NoneType)
    if origin is Union or origin is types.UnionType:
        if val is None:
            return None
        non_none = [a for a in args if a is not type(None)]
        if non_none:
            return _from_json(val, non_none[0])
        return val

    # Primitives / Any
    if hint in (str, int, float, bool, type(None)) or hint is Any:
        return val

    # datetime
    if hint is datetime:
        if isinstance(val, str):
            return datetime.fromisoformat(val)
        return val

    # Enum subclasses
    if isinstance(hint, type) and issubclass(hint, Enum):
        return hint(val)

    # Pydantic BaseModel (rigging.Model inherits from this)
    if isinstance(hint, type) and issubclass(hint, BaseModel):
        return hint.model_validate(val)

    # set[T]
    if origin is set:
        elem_type = args[0] if args else Any
        return {_from_json(v, elem_type) for v in val}

    # list[T]
    if origin is list:
        elem_type = args[0] if args else Any
        return [_from_json(v, elem_type) for v in val]

    # dict[K, V]
    if origin is dict:
        val_type = args[1] if len(args) > 1 else Any
        return {k: _from_json(v, val_type) for k, v in val.items()}

    # dataclass
    if is_dataclass(hint):
        hints = get_type_hints(hint)
        kwargs = {}
        for f in dc_fields(hint):
            if f.name in _EXCLUDED_FIELDS:
                continue
            if f.name in val:
                kwargs[f.name] = _from_json(val[f.name], hints[f.name])
        return hint(**kwargs)

    return val


@dataclass
class SharedRedTeamState:
    """
    Cluster-wide state shared across all agents.

    Stored in Redis/etcd for pod crash recovery. This extends the
    single-agent RedTeamState with multi-agent coordination features.

    Attributes:
        operation_id: Unique identifier for this operation.
        target: Primary target information.
        all_credentials: Credentials discovered by any agent.
        all_hashes: Hashes discovered by any agent.
        all_hosts: Hosts discovered by any agent.
        all_users: Users discovered by any agent.
        all_shares: Shares discovered by any agent.
        discovered_vulnerabilities: Vulnerabilities found but not yet exploited.
        exploited_vulnerabilities: Set of vuln_ids that have been exploited.
        pending_tasks: Tasks dispatched but not completed.
        completed_tasks: Results of completed tasks.
        has_domain_admin: Whether domain admin access achieved.
        has_golden_ticket: Whether golden ticket has been forged.
        domain_admin_path: The attack path that led to domain admin.
        registered_agents: Agents registered with the dispatcher.
    """

    operation_id: str
    target: Target | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None  # Set when operation completes

    # Global discoveries (aggregated from all agents)
    all_domains: list[str] = field(default_factory=list)
    # Authoritative NetBIOS to FQDN mapping from AD crossRef objects
    # Key: lowercase NetBIOS name (e.g., "corp"), Value: FQDN (e.g., "corp.contoso.local")
    # Populated by querying CN=Partitions,CN=Configuration via LDAP
    netbios_to_fqdn: dict[str, str] = field(default_factory=dict)

    # Domain controller IP cache - populated when DC hosts are discovered
    # Key: lowercase FQDN (e.g., "contoso.local"), Value: DC IP address
    domain_controllers: dict[str, str] = field(default_factory=dict)

    # Multi-domain tracking for cross-domain/cross-forest attacks
    trusted_domains: list[str] = field(
        default_factory=list
    )  # Trusted domains (from nltest/AD trusts)
    domain_admin_domains: list[str] = field(default_factory=list)  # Domains where we have DA

    all_credentials: list[Credential] = field(default_factory=list)
    all_hashes: list[Hash] = field(default_factory=list)
    all_hosts: list[Host] = field(default_factory=list)
    all_users: list[User] = field(default_factory=list)
    all_shares: list[Share] = field(default_factory=list)
    all_weaknesses: list[str] = field(default_factory=list)

    # Vulnerability registry
    discovered_vulnerabilities: dict[str, VulnerabilityInfo] = field(default_factory=dict)
    exploited_vulnerabilities: set[str] = field(default_factory=set)

    # Task tracking
    pending_tasks: dict[str, TaskInfo] = field(default_factory=dict)
    completed_tasks: dict[str, TaskResult] = field(default_factory=dict)

    # Success flags
    completed: bool = False
    has_domain_admin: bool = False
    has_golden_ticket: bool = False
    domain_admin_path: str | None = None

    # Persistence tracking (CRITICAL: must be in state for pub/sub visibility)
    # Golden tickets: {domain, ticket_path, created_at, krbtgt_hash}
    golden_tickets: list[dict] = field(default_factory=list)
    # Domains where AdminSDHolder backdoor was planted
    adminsd_holder_backdoors: list[str] = field(default_factory=list)

    # ACL chain tracking for multi-hop attacks
    # Serialized chain data: {chain_id, steps, goal, domain, is_complete, progress}
    acl_chains: list[dict] = field(default_factory=list)

    # gMSA account tracking for password retrieval
    # {account, domain, principals_allowed, discovered_by}
    gmsa_accounts: list[dict] = field(default_factory=list)

    # Background task deduplication tracking (CRITICAL for restart recovery)
    # These prevent re-running expensive operations after orchestrator restart
    # Format: "domain:username:password_hash" for creds, "domain:username:hash" for hashes
    processed_cred_expansion: set[str] = field(default_factory=set)  # kerberoast/secretsdump done
    processed_hash_lateral: set[str] = field(default_factory=set)  # lateral movement dispatched
    processed_crack_requests: set[str] = field(default_factory=set)  # hash crack submitted
    processed_asrep_domains: set[str] = field(default_factory=set)  # AS-REP roast done
    processed_username_spray: set[str] = field(default_factory=set)  # username_as_password done
    processed_password_spray: set[str] = field(default_factory=set)  # password_spray done
    processed_secretsdump: set[str] = field(
        default_factory=set
    )  # secretsdump done "host:user:domain"
    dispatched_acl_steps: set[str] = field(default_factory=set)  # ACL steps dispatched "chain:step"
    # Coercion and delegation tracking (prevents duplicate dispatch after restart)
    processed_esc8_servers: set[str] = field(default_factory=set)  # ADCS IPs with ESC8 attempted
    processed_coerced_dcs: set[str] = field(default_factory=set)  # DC IPs that have been coerced
    processed_writable_shares: set[str] = field(default_factory=set)  # "host:share" combos notified
    processed_delegation_creds: set[str] = field(
        default_factory=set
    )  # "domain:username" delegation done
    # Additional automation tracking
    processed_adcs_servers: set[str] = field(default_factory=set)  # ADCS servers enumerated
    processed_bloodhound_domains: set[str] = field(default_factory=set)  # BloodHound run
    processed_spidered_shares: set[str] = field(
        default_factory=set
    )  # "host:share:user:domain" spidered
    processed_expansion_creds: set[str] = field(
        default_factory=set
    )  # "domain:user:pwdhash" - expansion loop triggered

    # Agent registry
    registered_agents: dict[str, AgentInfo] = field(default_factory=dict)

    # Timeline for cross-agent correlation
    operation_timeline: list[TimelineEvent] = field(default_factory=list)
    identified_techniques: set[str] = field(default_factory=set)
    pending_credential_findings: set[str] = field(default_factory=set)

    # Scan tracking: IPs/subnets that have already been nmap-scanned
    # Prevents redundant nmap scans after hosts are discovered
    scanned_targets: set[str] = field(default_factory=set)

    # Shared artifacts storage (base64-encoded file contents)
    # Key format: "category/filename" -> base64 content
    # Example: "sysvol/login.bat" -> "QmF0Y2ggZmlsZSBjb250ZW50..."
    downloaded_artifacts: dict[str, str] = field(default_factory=dict)

    # Transient dispatcher reference for real-time publishing (NOT serialized)
    _dispatcher: Any = field(default=None, init=False, repr=False, compare=False)

    # Background task tracking for proper cleanup (NOT serialized)
    _background_tasks: set = field(default_factory=set, init=False, repr=False, compare=False)

    def set_dispatcher(self, dispatcher) -> None:
        """Set dispatcher for real-time publishing of discoveries."""
        object.__setattr__(self, "_dispatcher", dispatcher)

    def _publish_async(self, coro) -> None:
        """Publish to Redis with proper task tracking.

        Creates a background task and tracks it for proper cleanup.
        This prevents fire-and-forget tasks from being lost on shutdown.

        NOTE: Skipped when called from non-main thread (threaded result consumer)
        because the coroutine uses main-loop-bound Redis client.
        """
        import threading

        if not self._dispatcher:
            # Close coroutine to avoid "was never awaited" warning
            coro.close()
            return

        # Skip when in non-main thread - coroutine uses main loop's Redis client
        if threading.current_thread() is not threading.main_thread():
            # Close coroutine to avoid "was never awaited" warning
            coro.close()
            return

        try:
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(coro)
            # Track task for cleanup
            self._background_tasks.add(task)
            # Remove from tracking when done
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            # No event loop, skip real-time publish
            pass

    async def cleanup_background_tasks(self) -> None:
        """Cancel and await all pending background publish tasks.

        Should be called during graceful shutdown to ensure all
        checkpoint publishes complete or are properly cancelled.
        """
        import asyncio

        if not self._background_tasks:
            return

        logger.debug(f"Cleaning up {len(self._background_tasks)} background tasks")

        # Cancel all pending tasks
        for task in self._background_tasks:
            if not task.done():
                task.cancel()

        # Wait for all tasks to complete (cancelled or otherwise)
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

        self._background_tasks.clear()
        logger.debug("Background tasks cleanup complete")

    def store_artifact(self, key: str, content: bytes | str, source_agent: str = "") -> bool:
        """Store a downloaded artifact in shared state.

        Args:
            key: Artifact key (e.g., "sysvol/login.bat" or "loot/ntds.dit")
            content: File content as bytes or string
            source_agent: Agent that downloaded the artifact

        Returns:
            True if stored, False if duplicate or too large
        """
        import base64

        # Limit artifact size to 10MB (Redis Sentinel provides robust storage)
        max_size = 10 * 1024 * 1024
        if isinstance(content, str):
            content_bytes = content.encode("utf-8", errors="replace")
        else:
            content_bytes = content

        if len(content_bytes) > max_size:
            logger.warning(f"Artifact '{key}' too large ({len(content_bytes)} bytes), skipping")
            return False

        if key in self.downloaded_artifacts:
            logger.debug(f"Artifact '{key}' already exists, skipping")
            return False

        encoded = base64.b64encode(content_bytes).decode("ascii")
        self.downloaded_artifacts[key] = encoded
        logger.info(f"Artifact stored: {key} ({len(content_bytes)} bytes) from {source_agent}")
        return True

    def get_artifact(self, key: str) -> bytes | None:
        """Retrieve a downloaded artifact from shared state.

        Args:
            key: Artifact key

        Returns:
            File content as bytes, or None if not found
        """
        import base64

        encoded = self.downloaded_artifacts.get(key)
        if not encoded:
            return None
        return base64.b64decode(encoded)

    def get_artifact_text(self, key: str, encoding: str = "utf-8") -> str | None:
        """Retrieve a downloaded artifact as text.

        Args:
            key: Artifact key
            encoding: Text encoding (default utf-8)

        Returns:
            File content as string, or None if not found
        """
        content = self.get_artifact(key)
        if content is None:
            return None
        return content.decode(encoding, errors="replace")

    def list_artifacts(self, prefix: str = "") -> list[str]:
        """List all artifact keys, optionally filtered by prefix.

        Args:
            prefix: Optional prefix filter (e.g., "sysvol/")

        Returns:
            List of artifact keys
        """
        if not prefix:
            return list(self.downloaded_artifacts.keys())
        return [k for k in self.downloaded_artifacts if k.startswith(prefix)]

    def _merge_source(self, source_agent: str, existing_source: str) -> str:
        """Merge source_agent with existing source, avoiding duplicate prefixes.

        Handles cases like:
        - source_agent="Task input (x)", existing="x" → "Task input (x)"
        - source_agent="orchestrator", existing="worker:tool" → "orchestrator:worker:tool"
        - source_agent="x", existing="x" → "x" (no duplication)
        """
        if not source_agent:
            return existing_source or ""
        if not existing_source:
            return source_agent

        # Skip concatenation if equal or already prefixed
        if source_agent == existing_source or existing_source.startswith(f"{source_agent}:"):
            return existing_source

        # Skip if one contains the other (task ID pattern overlap)
        if source_agent in existing_source or existing_source in source_agent:
            # Keep the more descriptive one
            return source_agent if len(source_agent) > len(existing_source) else existing_source

        return f"{source_agent}:{existing_source}"

    def _resolve_netbios_to_fqdn(self, netbios_name: str) -> str:
        """Resolve a NetBIOS domain name to its FQDN equivalent.

        When netexec outputs 'CONTOSO\\user:password', we capture 'CONTOSO' as the domain.
        This method resolves it to 'contoso.local' if we know the mapping.

        Resolution order (first match wins):
        1. Authoritative mapping from AD crossRef objects (netbios_to_fqdn dict)
        2. Known domains that start with the NetBIOS name
        3. Existing credentials with matching domain prefix
        4. Target domain if it matches (fallback)

        Args:
            netbios_name: The NetBIOS domain name (e.g., 'CONTOSO')

        Returns:
            The FQDN if found, otherwise the original NetBIOS name
        """
        netbios_lower = netbios_name.lower()

        # 1. Check authoritative mapping from AD crossRef objects (PREFERRED)
        # This is populated by querying CN=Partitions,CN=Configuration via LDAP
        if netbios_lower in self.netbios_to_fqdn:
            return self.netbios_to_fqdn[netbios_lower]

        # 2. Check known domains for a matching FQDN pattern
        # Prefer more specific (longer) matches to avoid parent/child domain confusion
        matching_domains = [
            d.lower() for d in self.all_domains if d.lower().startswith(netbios_lower + ".")
        ]
        if matching_domains:
            # Return the most specific (longest) match
            return max(matching_domains, key=len)

        # 3. Check existing credentials for a matching FQDN pattern
        for cred in self.all_credentials:
            cred_domain = (cred.domain or "").lower()
            if cred_domain.startswith(netbios_lower + "."):
                return cred_domain

        # 4. Check if target.domain starts with the NetBIOS name (least preferred)
        # This can be wrong in multi-domain forests where target is root but cred is from child
        if self.target and self.target.domain:
            target_domain = self.target.domain.lower()
            if target_domain.startswith(netbios_lower + "."):
                return target_domain

        # No FQDN found, return original
        return netbios_lower

    def _validate_hash_domain(self, username: str, domain: str, source_agent: str) -> str:
        """Validate and correct hash domain by cross-referencing with known user domains.

        When a hash is extracted from tool output (e.g., kerberoast, secretsdump), the domain
        may be incorrect due to:
        - Cross-forest trust causing wrong realm in Kerberos tickets
        - Tool running against wrong DC
        - LLM hallucinating domain when parsing output

        This method checks if we've seen this user in a DIFFERENT domain via BloodHound,
        LDAP enumeration, or other recon, and corrects the domain if so.

        Args:
            username: The username from the hash (lowercase)
            domain: The domain extracted from the hash (may be wrong)
            source_agent: For logging purposes

        Returns:
            Corrected domain if user is known to exist elsewhere, otherwise original domain
        """
        if not username or not domain:
            return domain

        username_lower = username.lower()
        domain_lower = domain.lower()

        # Find all domains where this user has been seen
        known_domains: set[str] = set()
        for user in self.all_users:
            if user.username.lower() == username_lower and user.domain:
                known_domains.add(user.domain.lower())

        if not known_domains:
            # User not seen before - accept the domain from hash
            return domain_lower

        if domain_lower in known_domains:
            # Domain matches a known domain for this user - all good
            return domain_lower

        # Domain doesn't match any known domain for this user!
        if len(known_domains) == 1:
            # User exists in exactly one other domain - use that
            correct_domain = next(iter(known_domains))
            logger.warning(
                f"Domain correction: {domain_lower}\\{username_lower} -> "
                f"{correct_domain}\\{username_lower} (user known from prior recon, "
                f"source: {source_agent})"
            )
            return correct_domain

        # User exists in multiple other domains - pick the most likely one
        # Prefer child domains over parent domains (more specific)
        # E.g., prefer child.contoso.local over contoso.local
        sorted_domains = sorted(known_domains, key=len, reverse=True)
        best_match = sorted_domains[0]
        logger.warning(
            f"Domain correction (ambiguous): {domain_lower}\\{username_lower} -> "
            f"{best_match}\\{username_lower} (user known in {known_domains}, "
            f"picked longest FQDN, source: {source_agent})"
        )
        return best_match

    @staticmethod
    def _extract_kerberoast_spn_key(hash_value: str) -> str:
        """Extract a deduplication key from a Kerberoast hash.

        Kerberoast hash format: $krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted

        We extract ETYPE (encryption type) and SPN to create a unique key.
        Same user can have multiple SPNs, and same SPN can have different encryption
        types (RC4=23, AES128=17, AES256=18), so we keep one per SPN+ETYPE combo.

        Args:
            hash_value: The Kerberoast hash string

        Returns:
            A key like "23:http/web01.contoso.local" or empty string if parse fails
        """
        if not hash_value or not hash_value.startswith("$krb5tgs$"):
            return ""

        # Format: $krb5tgs$23$*user$realm$spn*$...
        parts = hash_value.split("$")
        if len(parts) < 4:
            return ""

        etype = parts[2]  # Encryption type (23=RC4, 17=AES128, 18=AES256)

        # Extract SPN from the *user$realm$spn* section
        # Find content between first * and second *
        try:
            first_star = hash_value.index("*")
            second_star = hash_value.index("*", first_star + 1)
            inner = hash_value[first_star + 1 : second_star]
            # inner = "user$realm$spn" - SPN is the last part
            inner_parts = inner.split("$")
            if len(inner_parts) >= 3:
                spn = inner_parts[-1]  # Last part is SPN
                return f"{etype}:{spn.lower()}"
        except (ValueError, IndexError):
            pass

        return ""

    def _resolve_credential_domain_from_users(self, username: str, provided_domain: str) -> str:
        """Resolve credential domain by cross-referencing with discovered users.

        In multi-domain AD forests, a credential might come in with a parent domain
        (e.g., 'contoso.local') when the user actually belongs to a child domain
        (e.g., 'child.contoso.local'). This method cross-references with
        discovered users to return the correct domain.

        Resolution logic:
        1. If user exists in exactly one domain, use that domain
        2. If user exists in a child domain of the provided domain, prefer the child
        3. If user exists in the provided domain, use the provided domain
        4. If user not found, return the provided domain unchanged

        Args:
            username: The username to look up
            provided_domain: The domain from the credential

        Returns:
            The resolved domain (may be the same as provided_domain)
        """
        if not username:
            return provided_domain

        username_lower = username.lower()
        provided_lower = provided_domain.lower()

        # Find all domains where this user exists
        user_domains: list[str] = []
        for user in self.all_users:
            if user.username.lower() == username_lower and user.domain:
                user_domains.append(user.domain.lower())

        if not user_domains:
            # User not in discovered users - accept provided domain
            return provided_domain

        unique_domains = list(set(user_domains))

        # If user exists in exactly one domain, use it
        if len(unique_domains) == 1:
            resolved = unique_domains[0]
            if resolved != provided_lower:
                logger.debug(f"Domain corrected for {username}: {provided_domain} -> {resolved}")
            return resolved

        # User exists in multiple domains - try to find the best match
        # Prefer a child domain of the provided domain (more specific)
        if provided_lower:
            for domain in unique_domains:
                # Check if domain is a child of provided domain
                # e.g., 'child.contoso.local' is child of 'contoso.local'
                if domain.endswith("." + provided_lower):
                    logger.debug(
                        f"Domain corrected for {username}: {provided_domain} -> {domain} (child domain)"
                    )
                    return domain

            # If provided domain is one of the user's domains, use it
            if provided_lower in unique_domains:
                return provided_lower

        # Multiple domains, can't determine - return the most specific (longest)
        resolved = max(unique_domains, key=len)
        if resolved != provided_lower:
            logger.debug(
                f"Domain resolved for {username}: {provided_domain} -> {resolved} (most specific)"
            )
        return resolved

    def add_credential(self, credential: Credential, source_agent: str) -> bool:  # noqa: PLR0912
        """Add credential if not duplicate. Returns True if added."""
        username = credential.username.strip()
        # Normalize domain to lowercase for consistency
        domain = credential.domain.strip().lower()
        # Resolve NetBIOS domain names (e.g., "CONTOSO") to FQDN (e.g., "contoso.local")
        if domain and "." not in domain:
            domain = self._resolve_netbios_to_fqdn(domain)
        # Cross-reference with discovered users to get correct domain
        # This handles cases where credential has parent domain but user is in child domain
        domain = self._resolve_credential_domain_from_users(username, domain)
        password = credential.password.strip()
        # Strip truncation artifacts from LLM extraction (e.g., "Password123..." -> "Password123")
        while password.endswith("..."):
            password = password[:-3].strip()
        while password.endswith("…"):  # Unicode ellipsis
            password = password[:-1].strip()
        if not username or username.lower() in {"(none)", "none", "null", "(null)"}:
            logger.debug(f"Credential rejected: invalid username '{username}' from {source_agent}")
            return False
        # Reject credentials without passwords (use add_hash for hashes)
        if not password:
            logger.debug(
                f"Credential rejected: empty password for '{username}' from {source_agent}"
            )
            return False
        # Guard against file-path artifacts (e.g., /tmp/users.txt) leaking in.
        if "/" in username or "\\" in username or username.endswith(".txt"):
            logger.debug(f"Credential rejected: path artifact '{username}' from {source_agent}")
            return False
        # Filter out attack tool artifacts (e.g., EVIL625686$ created by impacket addcomputer.py for RBCD)
        username_upper = username.upper()
        if username_upper.startswith("EVIL") and username_upper.endswith("$"):
            middle = username_upper[4:-1]  # Extract part between EVIL and $
            if middle.isdigit():
                logger.debug(
                    f"Credential rejected: attack tool artifact '{username}' from {source_agent}"
                )
                return False
        self.add_user(username, domain, source_agent)
        self.add_domain(domain)
        key = f"{domain}:{username}:{password}".lower()
        for existing in self.all_credentials:
            existing_key = f"{existing.domain.strip()}:{existing.username.strip()}:{existing.password.strip()}".lower()
            if key == existing_key:
                pending_key = f"{domain}:{username}".lower()
                self.pending_credential_findings.discard(pending_key)
                logger.debug(
                    f"Credential rejected: duplicate {domain}\\{username} from {source_agent}"
                )
                return False
            # Check for cross-domain duplicates: same username + password but different domain
            # Only reject if user is KNOWN to exist in only ONE domain (hallucination)
            # If user exists in multiple domains, it's legitimate password reuse
            existing_user_pass = f"{existing.username.strip()}:{existing.password.strip()}".lower()
            new_user_pass = f"{username}:{password}".lower()
            if existing_user_pass == new_user_pass and existing.domain.strip().lower() != domain:
                # Check how many domains this user exists in
                user_domains = {
                    u.domain.lower()
                    for u in self.all_users
                    if u.username.lower() == username.lower() and u.domain
                }
                if len(user_domains) == 1 and domain.lower() not in user_domains:
                    # User only exists in one domain, this is likely a hallucination
                    logger.warning(
                        f"Credential rejected: cross-domain duplicate {domain}\\{username} "
                        f"(user only exists in {existing.domain}) from {source_agent}"
                    )
                    return False
                # User exists in multiple domains or we haven't discovered them yet
                # Log password reuse but allow it
                logger.info(
                    f"Password reuse detected: {username} in {domain} and {existing.domain}"
                )
        credential.username = username
        credential.domain = domain
        credential.password = password
        # Set credential source, avoiding duplicate prefixes
        credential.source = self._merge_source(source_agent, credential.source)
        self.all_credentials.append(credential)
        pending_key = f"{domain}:{username}".lower()
        self.pending_credential_findings.discard(pending_key)
        logger.info(f"Credential added: {domain}\\{username} (source: {source_agent})")

        # Real-time checkpoint to Redis (don't call publish_credential - that would re-add)
        if self._dispatcher:
            self._dispatcher.signal_credential_access()
            self._publish_async(self._dispatcher._checkpoint())

        return True

    def add_user(self, username: str, domain: str, source: str = "") -> bool:
        """Add user if not duplicate. Returns True if added.

        If the user already exists in a parent domain and is now being added to
        a child domain, updates the existing entry to use the child domain
        (child domains are more specific/accurate).

        Args:
            username: The username.
            domain: The domain.
            source: Tool/method that discovered this user.
        """
        if not username:
            logger.debug(f"User rejected: empty username for domain {domain}")
            return False
        normalized = username.strip()
        # Normalize domain to lowercase for consistency
        normalized_domain = (domain or "").strip().lower()
        # Resolve NetBIOS domain names to FQDN
        if normalized_domain and "." not in normalized_domain:
            normalized_domain = self._resolve_netbios_to_fqdn(normalized_domain)
        if not normalized or normalized.lower() in {"(none)", "none", "null", "(null)"}:
            logger.debug(
                f"User rejected: invalid username '{normalized}' for domain {normalized_domain}"
            )
            return False
        if "/" in normalized or "\\" in normalized or normalized.endswith(".txt"):
            logger.debug(
                f"User rejected: path artifact '{normalized}' for domain {normalized_domain}"
            )
            return False

        # Check for existing user entries
        target_domain = (self.target.domain or "").lower() if self.target else ""
        for existing in self.all_users:
            existing_domain = (existing.domain or "").lower()
            if existing.username == normalized:
                if existing_domain == normalized_domain:
                    # Exact duplicate
                    logger.debug(f"User rejected: duplicate {normalized_domain}\\{normalized}")
                    return False
                # Check if this is a child->parent or parent->child relationship
                if normalized_domain.endswith("." + existing_domain):
                    # New domain is a child of existing - update to more specific
                    old_domain = existing_domain
                    existing.domain = normalized_domain
                    logger.info(
                        f"User domain upgraded: {normalized} from {old_domain} to {normalized_domain}"
                    )
                    # Also update credentials with the old parent domain
                    self._update_credentials_domain(normalized, old_domain, normalized_domain)
                    self.add_domain(normalized_domain)
                    return True
                if existing_domain.endswith("." + normalized_domain):
                    # Existing domain is more specific (child) - keep it
                    logger.debug(
                        f"User rejected: {normalized} already in more specific domain {existing_domain}"
                    )
                    return False
                # Sibling domain case: domains are unrelated (e.g., contoso.local vs fabrikam.local)
                # If existing domain is the target domain (fallback) but new domain is more specific,
                # update to the new domain (it's likely from actual tool output, not fallback)
                if existing_domain == target_domain and normalized_domain != target_domain:
                    old_domain = existing_domain
                    existing.domain = normalized_domain
                    logger.warning(
                        f"User domain corrected: {normalized} from {old_domain} (target fallback) "
                        f"to {normalized_domain} (specific discovery)"
                    )
                    self._update_credentials_domain(normalized, old_domain, normalized_domain)
                    self.add_domain(normalized_domain)
                    return True
                # If new domain is target fallback but existing has specific domain, reject
                if normalized_domain == target_domain and existing_domain != target_domain:
                    logger.debug(
                        f"User rejected: {normalized} already in {existing_domain}, "
                        f"ignoring target fallback {normalized_domain}"
                    )
                    return False
                # Both domains are non-target siblings - trust the first discovery
                logger.warning(
                    f"User domain conflict: {normalized} in both {existing_domain} and "
                    f"{normalized_domain} (keeping {existing_domain})"
                )
                return False

        self.all_users.append(User(username=normalized, domain=normalized_domain, source=source))
        self.add_domain(normalized_domain)
        logger.debug(
            f"User added: {normalized_domain}\\{normalized} (source: {source or 'unknown'})"
        )
        return True

    def _update_credentials_domain(self, username: str, old_domain: str, new_domain: str) -> None:
        """Update credentials for a user when their domain is corrected."""
        updated = 0
        for cred in self.all_credentials:
            if (
                cred.username.lower() == username.lower()
                and cred.domain.lower() == old_domain.lower()
            ):
                cred.domain = new_domain
                updated += 1
        for hash_obj in self.all_hashes:
            if (
                hash_obj.username.lower() == username.lower()
                and hash_obj.domain.lower() == old_domain.lower()
            ):
                hash_obj.domain = new_domain
                updated += 1
        if updated:
            logger.info(
                f"Updated {updated} credential(s)/hash(es) for {username}: "
                f"{old_domain} -> {new_domain}"
            )
            self.all_credentials = self._dedupe_credentials(self.all_credentials)

    def add_domain(self, domain: str) -> bool:
        """Add domain if not duplicate. Returns True if added.

        When a new FQDN domain is added, retroactively normalizes any existing
        credentials/users/hashes that have a matching NetBIOS domain name.
        """
        normalized = (domain or "").strip().lower()
        if not normalized:
            return False
        if any(existing.lower() == normalized for existing in self.all_domains):
            return False
        self.all_domains.append(normalized)

        # If this is an FQDN (has a dot), retroactively normalize any
        # credentials/users/hashes with matching NetBIOS domain
        if "." in normalized:
            self._retroactive_domain_normalize(normalized)

        return True

    def add_netbios_mapping(self, netbios: str, fqdn: str) -> bool:
        """Add an authoritative NetBIOS to FQDN mapping from AD crossRef objects.

        This mapping is used by _resolve_netbios_to_fqdn to correctly resolve
        NetBIOS domain names (e.g., "CORP") to their FQDN (e.g., "corp.contoso.local").

        Args:
            netbios: The NetBIOS domain name (e.g., "CORP")
            fqdn: The fully qualified domain name (e.g., "corp.contoso.local")

        Returns:
            True if added, False if already exists with same value
        """
        netbios_lower = netbios.strip().lower()
        fqdn_lower = fqdn.strip().lower()

        if not netbios_lower or not fqdn_lower:
            return False

        existing = self.netbios_to_fqdn.get(netbios_lower)
        if existing == fqdn_lower:
            return False

        if existing and existing != fqdn_lower:
            logger.warning(
                f"NetBIOS mapping conflict: '{netbios_lower}' was '{existing}', "
                f"updating to '{fqdn_lower}'"
            )

        self.netbios_to_fqdn[netbios_lower] = fqdn_lower
        logger.info(f"NetBIOS mapping added: {netbios_lower} -> {fqdn_lower}")

        # Also add the FQDN to all_domains if not already present
        self.add_domain(fqdn_lower)

        # Retroactively normalize any credentials/users/hashes with this NetBIOS domain
        self._retroactive_domain_normalize(fqdn_lower)

        return True

    def _retroactive_domain_normalize(self, fqdn: str) -> None:
        """Normalize existing credentials/users/hashes when a new FQDN is discovered.

        For example, if fqdn="corp.contoso.local", this will update any
        credentials with domain="corp" to use the FQDN instead.
        """
        # Extract NetBIOS portion (e.g., "corp" from "corp.contoso.local")
        netbios = fqdn.split(".", maxsplit=1)[0]
        if not netbios:
            return

        updated_creds = 0
        updated_users = 0
        updated_hashes = 0

        # Update credentials with matching NetBIOS domain
        for cred in self.all_credentials:
            cred_domain = (cred.domain or "").strip().lower()
            if cred_domain == netbios:
                cred.domain = fqdn
                updated_creds += 1

        # Update users with matching NetBIOS domain
        for user in self.all_users:
            user_domain = (user.domain or "").strip().lower()
            if user_domain == netbios:
                user.domain = fqdn
                updated_users += 1

        # Update hashes with matching NetBIOS domain
        for hash_obj in self.all_hashes:
            hash_domain = (hash_obj.domain or "").strip().lower()
            if hash_domain == netbios:
                hash_obj.domain = fqdn
                updated_hashes += 1

        if updated_creds or updated_users or updated_hashes:
            logger.info(
                f"Retroactive domain normalize '{netbios}' -> '{fqdn}': "
                f"{updated_creds} creds, {updated_users} users, {updated_hashes} hashes"
            )

        # Remove the NetBIOS name from all_domains since it's now represented by the FQDN
        # e.g., remove "child" after normalizing to "child.contoso.local"
        self.all_domains = [d for d in self.all_domains if d.lower() != netbios]

        # Now deduplicate credentials that may now be duplicates after normalization
        self.all_credentials = self._dedupe_credentials(self.all_credentials)

        # Check if this is a child domain and normalize parent domain credentials
        # e.g., when adding "child.contoso.local", check for credentials with
        # "contoso.local" that should be reassigned to this child domain
        self._normalize_parent_domain_credentials(fqdn)

    def _normalize_parent_domain_credentials(self, child_fqdn: str) -> None:  # noqa: PLR0912
        """Normalize credentials with parent domain when a child domain is discovered.

        In AD forests, tools sometimes report credentials with the parent/root domain
        even when the user only exists in a child domain. For example:
        - contoso.local\\sql_svc when user is actually in child.contoso.local

        This method:
        1. Identifies if child_fqdn is a child domain of any existing domain
        2. Finds credentials/users/hashes with the parent domain
        3. Cross-references with all_users to see if the user ONLY exists in the child domain
        4. If so, reassigns the credential to the child domain

        Args:
            child_fqdn: The child domain FQDN (e.g., "child.contoso.local")
        """
        # Find potential parent domains (e.g., "contoso.local" is parent of "child.contoso.local")
        parts = child_fqdn.split(".")
        if len(parts) < 3:
            # Not a child domain (e.g., "contoso.local" has no parent)
            return

        # Extract parent domain (remove first label)
        # e.g., "child.contoso.local" -> "contoso.local"
        parent_domain = ".".join(parts[1:])

        # Check if parent domain is in our known domains
        if parent_domain not in [d.lower() for d in self.all_domains]:
            return

        updated_creds = 0
        updated_users = 0
        updated_hashes = 0

        # Build a set of usernames that ONLY exist in the child domain
        # These are users that should NOT have credentials with the parent domain
        users_in_child: set[str] = set()
        users_in_parent: set[str] = set()

        for user in self.all_users:
            user_domain = (user.domain or "").lower()
            username_lower = user.username.lower()
            if user_domain == child_fqdn:
                users_in_child.add(username_lower)
            elif user_domain == parent_domain:
                users_in_parent.add(username_lower)

        # Users that are ONLY in child domain (not in parent)
        child_only_users = users_in_child - users_in_parent

        if not child_only_users:
            return

        # Update credentials for users that only exist in the child domain
        for cred in self.all_credentials:
            cred_domain = (cred.domain or "").lower()
            username_lower = cred.username.lower()
            if cred_domain == parent_domain and username_lower in child_only_users:
                cred.domain = child_fqdn
                updated_creds += 1

        # Update users (shouldn't happen often since we checked all_users above)
        for user in self.all_users:
            user_domain = (user.domain or "").lower()
            username_lower = user.username.lower()
            if user_domain == parent_domain and username_lower in child_only_users:
                user.domain = child_fqdn
                updated_users += 1

        # Update hashes
        for hash_obj in self.all_hashes:
            hash_domain = (hash_obj.domain or "").lower()
            username_lower = hash_obj.username.lower()
            if hash_domain == parent_domain and username_lower in child_only_users:
                hash_obj.domain = child_fqdn
                updated_hashes += 1

        if updated_creds or updated_users or updated_hashes:
            logger.info(
                f"Parent->child domain normalize '{parent_domain}' -> '{child_fqdn}': "
                f"{updated_creds} creds, {updated_users} users, {updated_hashes} hashes "
                f"(for {len(child_only_users)} child-only users)"
            )

            # Deduplicate after normalization
            self.all_credentials = self._dedupe_credentials(self.all_credentials)

    def add_hash(self, hash_obj: Hash, source_agent: str) -> bool:  # noqa: PLR0912
        """Add hash if not duplicate. Returns True if added."""
        hash_type = (hash_obj.hash_type or "").strip().lower()
        username = (hash_obj.username or "").strip().lower()
        domain = (hash_obj.domain or "").strip().lower()
        # Resolve NetBIOS domain names to FQDN
        if domain and "." not in domain:
            domain = self._resolve_netbios_to_fqdn(domain)

        # Cross-reference with known user domains to catch mislabeling
        # E.g., if hash says FABRIKAM\svc.backup but we know svc.backup is in CONTOSO
        domain = self._validate_hash_domain(username, domain, source_agent)

        hash_value = hash_obj.hash_value or ""

        # Detect hash type from value if type is unknown/missing
        # AS-REP hashes start with $krb5asrep$
        is_asrep = hash_type in {"as-rep", "asrep", "krb5asrep"} or hash_value.startswith(
            "$krb5asrep$"
        )
        # Kerberoast hashes start with $krb5tgs$
        is_kerberoast = hash_type in {"kerberoast", "krb5tgs", "tgs-rep"} or hash_value.startswith(
            "$krb5tgs$"
        )

        # Normalize hash_type based on detected format
        if is_asrep and hash_type not in {"as-rep", "asrep", "krb5asrep"}:
            hash_obj.hash_type = "AS-REP"
            hash_type = "as-rep"
        elif is_kerberoast and hash_type not in {"kerberoast", "krb5tgs", "tgs-rep"}:
            hash_obj.hash_type = "Kerberoast"
            hash_type = "kerberoast"

        for existing in self.all_hashes:
            if existing.hash_value == hash_value:
                # If incoming hash has cracked_password and existing doesn't, merge it
                if hash_obj.cracked_password and not existing.cracked_password:
                    existing.cracked_password = hash_obj.cracked_password
                    logger.info(
                        f"Hash updated with cracked password: {domain}\\{username} ({hash_type}) "
                        f"from {source_agent}"
                    )
                    # Create a credential from the cracked password, linking to parent hash
                    cracked_cred = Credential(
                        username=username,
                        password=hash_obj.cracked_password,
                        domain=domain,
                        source=f"cracked:{hash_type}",
                        parent_id=existing.id,  # Link to the hash that was cracked
                        attack_step=existing.attack_step + 1,
                    )
                    self.add_credential(cracked_cred, source_agent)
                    # Signal credential access if dispatcher available
                    if self._dispatcher:
                        self._dispatcher.signal_credential_access()
                        self._publish_async(self._dispatcher._checkpoint())
                    return True  # Return True since we updated it
                logger.debug(
                    f"Hash rejected: duplicate hash for {domain}\\{username} ({hash_type}) from {source_agent}"
                )
                return False
            # For AS-REP, dedupe by user since each request generates different hash but same password
            existing_value = existing.hash_value or ""
            existing_is_asrep = (existing.hash_type or "").strip().lower() in {
                "as-rep",
                "asrep",
                "krb5asrep",
            } or existing_value.startswith("$krb5asrep$")

            if is_asrep and existing_is_asrep:
                existing_user = (existing.username or "").strip().lower()
                existing_domain = (existing.domain or "").strip().lower()
                if existing_user == username and existing_domain == domain:
                    logger.debug(
                        f"Hash rejected: duplicate AS-REP user {domain}\\{username} from {source_agent}"
                    )
                    return False

            # For Kerberoast, dedupe by user+SPN+encryption_type
            # Same user can have multiple SPNs, and same SPN can have RC4 vs AES
            # But we don't need multiple copies of the same SPN with same encryption
            # Hash format: $krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted
            existing_is_kerberoast = (existing.hash_type or "").strip().lower() in {
                "kerberoast",
                "krb5tgs",
                "tgs-rep",
                "tgs",
            } or existing_value.startswith("$krb5tgs$")

            if is_kerberoast and existing_is_kerberoast:
                existing_user = (existing.username or "").strip().lower()
                existing_domain = (existing.domain or "").strip().lower()
                if existing_user == username and existing_domain == domain:
                    # Extract SPN and encryption type from both hashes
                    new_spn_key = self._extract_kerberoast_spn_key(hash_value)
                    existing_spn_key = self._extract_kerberoast_spn_key(existing_value)
                    if new_spn_key and existing_spn_key and new_spn_key == existing_spn_key:
                        logger.debug(
                            f"Hash rejected: duplicate Kerberoast {domain}\\{username} "
                            f"(SPN: {new_spn_key}) from {source_agent}"
                        )
                        return False
        # Update hash_obj with normalized values (including resolved domain)
        hash_obj.domain = domain
        hash_obj.username = username
        self.add_domain(domain)
        # Avoid repeated source prefix concatenation (e.g., during state restores/merges)
        # Only prepend source_agent if it's not already in the source chain
        existing_source = getattr(hash_obj, "source", "")
        if source_agent and existing_source:
            if not existing_source.startswith(f"{source_agent}:"):
                hash_obj.source = f"{source_agent}:{existing_source}"
        elif source_agent and not existing_source:
            hash_obj.source = source_agent
        if not getattr(hash_obj, "discovered_at", None):
            hash_obj.discovered_at = datetime.now(timezone.utc)
        self.all_hashes.append(hash_obj)
        logger.info(f"Hash added: {domain}\\{username} ({hash_type}) (source: {source_agent})")

        # Auto-detect Domain Admin: krbtgt NTLM hash = DA achieved
        # NOTE: We ONLY check krbtgt, NOT Administrator, because:
        # - krbtgt only exists on DCs, so its hash proves DC-level access
        # - "Administrator" could be a LOCAL admin on a workstation (not DA!)
        # - Having 7 hashes instead of all ntds.dit hashes = NOT domain admin
        if hash_type == "ntlm" and username == "krbtgt" and not self.has_domain_admin:
            self.has_domain_admin = True
            self.completed_at = datetime.now(timezone.utc)  # Record completion time
            # Build attack path from credential chain instead of hardcoding
            attack_chain = self.format_attack_chain(hash_obj)
            self.domain_admin_path = attack_chain
            logger.success(
                f"🏆 DOMAIN ADMIN AUTO-DETECTED: {domain}\\{username} NTLM hash "
                f"found in state (source: {source_agent})"
            )
            logger.info(f"Attack chain: {attack_chain}")
            self.add_weakness(
                f"### Domain Admin Achieved — krbtgt NTLM hash extracted\n"
                f"**Attack Path:** {attack_chain}\n"
                f"**Vulnerability:** krbtgt hash extracted via DCSync or ntds.dit dump, "
                f"enabling Golden Ticket attacks.\n"
                f"- **Affected Resource:** {domain} domain\n"
                f"- **Discovery Method:** {source_agent}\n"
                f"- **Impact:** Complete domain compromise. Golden Tickets grant indefinite DA access."
            )

        # Real-time checkpoint to Redis (don't call publish_hash - that would re-add)
        if self._dispatcher:
            self._dispatcher.signal_credential_access()
            self._publish_async(self._dispatcher._checkpoint())

        return True

    def find_by_id(self, item_id: str) -> Credential | Hash | None:
        """Find a credential or hash by its ID.

        Args:
            item_id: The unique ID to search for.

        Returns:
            The Credential or Hash if found, None otherwise.
        """
        for cred in self.all_credentials:
            if cred.id == item_id:
                return cred
        for hash_obj in self.all_hashes:
            if hash_obj.id == item_id:
                return hash_obj
        return None

    def build_attack_chain(self, item: Credential | Hash | None = None) -> list[dict[str, str]]:
        """Build the attack chain by walking parent_id backwards.

        Args:
            item: The credential or hash to start from. If None, uses the most
                  recent DA credential (krbtgt or Administrator hash).

        Returns:
            List of chain steps from initial access to final compromise, each with:
            - type: "credential" or "hash"
            - username: The username
            - domain: The domain
            - source: How it was discovered
            - attack_step: Position in chain
        """
        # If no item provided, find the DA credential
        if item is None:
            for hash_obj in reversed(self.all_hashes):
                if hash_obj.hash_type.lower() == "ntlm" and hash_obj.username.lower() in (
                    "krbtgt",
                    "administrator",
                ):
                    item = hash_obj
                    break

        if item is None:
            return []

        # Walk backwards through parent_id chain
        chain: list[dict[str, str]] = []
        visited: set[str] = set()
        current: Credential | Hash | None = item

        while current is not None:
            if current.id in visited:
                logger.warning(f"Cycle detected in attack chain at {current.id}")
                break
            visited.add(current.id)

            step = {
                "type": "hash" if isinstance(current, Hash) else "credential",
                "username": current.username,
                "domain": current.domain,
                "source": current.source,
                "attack_step": str(current.attack_step),
            }
            if isinstance(current, Hash):
                step["hash_type"] = current.hash_type
            chain.append(step)

            # Move to parent
            current = self.find_by_id(current.parent_id) if current.parent_id else None

        # Reverse so chain goes from initial access to final compromise
        chain.reverse()
        return chain

    def format_attack_chain(self, item: Credential | Hash | None = None) -> str:
        """Format the attack chain as a human-readable string.

        Args:
            item: The credential or hash to start from. If None, uses DA credential.

        Returns:
            Formatted string like "password_spray → user1 → kerberoast → svc_sql → ..."
        """
        chain = self.build_attack_chain(item)
        if not chain:
            return "Unknown path"

        parts = []
        for step in chain:
            source = step["source"].split(":")[0] if step["source"] else "unknown"
            username = step["username"]
            domain = step["domain"]
            if step["type"] == "hash":
                hash_type = step.get("hash_type", "NTLM")
                parts.append(f"{source} → {domain}\\{username} ({hash_type})")
            else:
                parts.append(f"{source} → {domain}\\{username}")
        return " → ".join(parts) if parts else "Unknown path"

    def add_host(self, host: Host) -> bool:  # noqa: PLR0912
        """Add host if not duplicate. Returns True if added."""
        if not host.ip or not host.ip.strip():
            logger.debug("Host rejected: empty IP address")
            return False
        host.ip = host.ip.strip()
        host.hostname = host.hostname.strip()

        if host.hostname:
            hostname_lower = host.hostname.lower()
            if hostname_lower.startswith("ip-") and "compute.internal" in hostname_lower:
                host.hostname = ""
        for existing in self.all_hosts:
            if existing.ip == host.ip:
                # Merge stronger hostname/OS details instead of dropping updates.
                existing_hostname = (existing.hostname or "").strip()
                if existing_hostname:
                    existing_lower = existing_hostname.lower()
                    if existing_lower.startswith("ip-") and "compute.internal" in existing_lower:
                        existing_hostname = ""
                        existing.hostname = ""
                new_hostname = (host.hostname or "").strip()
                if new_hostname:
                    existing_lower = existing_hostname.lower()
                    existing_is_short = "." not in existing_hostname
                    new_is_fqdn = "." in new_hostname
                    existing_is_ptr = (
                        existing_lower.startswith("ip-") and "compute.internal" in existing_lower
                    )
                    if (
                        not existing_hostname
                        or existing_is_ptr
                        or (existing_is_short and new_is_fqdn)
                    ):
                        existing.hostname = new_hostname
                        # Extract domain from new FQDN hostname
                        if new_is_fqdn:
                            parts = new_hostname.lower().split(".")
                            if len(parts) > 1:
                                domain = ".".join(parts[1:])
                                self.add_domain(domain)
                if host.os and (not existing.os or existing.os.lower() == "unknown"):
                    existing.os = host.os
                if host.roles:
                    existing.roles = list({*existing.roles, *host.roles})
                if host.services:
                    existing.services = list({*existing.services, *host.services})
                # Update DC status after merge (new services/hostname may reveal it's a DC)
                existing.update_dc_status()
                # Register DC IP if merge reveals it's a domain controller
                if existing.is_dc and existing.hostname and "." in existing.hostname:
                    parts = existing.hostname.lower().split(".")
                    if len(parts) > 1:
                        domain = ".".join(parts[1:])
                        if domain not in self.domain_controllers:
                            self.domain_controllers[domain] = existing.ip
                            logger.info(f"DC registered (merge): {domain} -> {existing.ip}")
                logger.debug(
                    f"Host merged: {host.ip} (existing, updated details, is_dc={existing.is_dc})"
                )
                return False
        # Set DC status before adding
        host.update_dc_status()
        self.all_hosts.append(host)
        logger.debug(
            f"Host added: {host.ip} ({host.hostname or 'no hostname'}, is_dc={host.is_dc})"
        )

        # Extract domain from FQDN hostname and add to all_domains
        # e.g., srv01.corp.contoso.local -> corp.contoso.local
        if host.hostname and "." in host.hostname:
            parts = host.hostname.lower().split(".")
            if len(parts) > 1:
                domain = ".".join(parts[1:])
                self.add_domain(domain)

                # Register DC IP if host is a domain controller
                if host.is_dc and domain not in self.domain_controllers:
                    self.domain_controllers[domain] = host.ip
                    logger.info(f"DC registered: {domain} -> {host.ip} ({host.hostname})")

        # Real-time checkpoint to Redis (don't call publish_host - that would re-add)
        if self._dispatcher:
            self._publish_async(self._dispatcher._checkpoint())

        return True

    def add_share(self, share: Share) -> bool:
        """Add share if not duplicate. Returns True if added."""
        host = (share.host or "").strip().lower()
        name = (share.name or "").strip().lower()
        if not host or not name:
            logger.debug(f"Share rejected: empty host or name (host='{host}', name='{name}')")
            return False
        for existing in self.all_shares:
            if (existing.host or "").strip().lower() == host and (
                existing.name or ""
            ).strip().lower() == name:
                logger.debug(f"Share rejected: duplicate {host}/{name}")
                return False

        # Validate permissions before storing - agents may return comment text
        # (e.g., "Remote" from "Remote Admin") as permissions
        valid_perms = {"read", "write", "read,write", "write,read", "full"}
        if share.permissions:
            perm_lower = share.permissions.strip().lower()
            if perm_lower not in valid_perms:
                # Invalid permission - move to comment if empty, then clear
                if not share.comment:
                    share.comment = share.permissions
                share.permissions = ""

        self.all_shares.append(share)
        logger.debug(f"Share added: {host}/{name}")

        # Real-time checkpoint to Redis
        if self._dispatcher:
            self._publish_async(self._dispatcher._checkpoint())

        return True

    def add_weakness(self, block: str) -> bool:
        """Add weakness if not duplicate. Returns True if added. Triggers pub/sub."""
        if not block or block in self.all_weaknesses:
            return False
        self.all_weaknesses.append(block)
        logger.info(f"Weakness added: {block[:80]}...")

        # Real-time checkpoint to Redis
        if self._dispatcher:
            self._publish_async(self._dispatcher._checkpoint())

        return True

    def add_vulnerability(self, vuln: VulnerabilityInfo) -> bool:
        """Add vulnerability if not duplicate. Returns True if added.

        Deduplicates by both vuln_id AND (vuln_type, target) to prevent
        logical duplicates with different UUIDs.
        """
        if vuln.vuln_id in self.discovered_vulnerabilities:
            return False
        # Also check for same (type, target) combination to prevent logical duplicates
        for existing in self.discovered_vulnerabilities.values():
            if existing.vuln_type == vuln.vuln_type and existing.target == vuln.target:
                return False
        self.discovered_vulnerabilities[vuln.vuln_id] = vuln
        return True

    def mark_exploited(self, vuln_id: str) -> None:
        """Mark a vulnerability as exploited."""
        self.exploited_vulnerabilities.add(vuln_id)

    def get_unexploited_vulnerabilities(self) -> list[VulnerabilityInfo]:
        """Get vulnerabilities that haven't been exploited yet."""
        return [
            v
            for vid, v in self.discovered_vulnerabilities.items()
            if vid not in self.exploited_vulnerabilities
        ]

    def get_agent_credentials(self, agent_name: str) -> list[Credential]:
        """Get credentials discovered by a specific agent."""
        return [c for c in self.all_credentials if c.source.startswith(f"{agent_name}:")]

    # =========================================================================
    # Compatibility aliases for RedTeamState interface
    # These allow tools expecting RedTeamState to work with SharedRedTeamState
    # =========================================================================

    @property
    def hosts(self) -> list[Host]:
        """Alias for all_hosts (RedTeamState compatibility)."""
        return self.all_hosts

    @property
    def users(self) -> list[User]:
        """Alias for all_users (RedTeamState compatibility)."""
        return self.all_users

    @property
    def credentials(self) -> list[Credential]:
        """Alias for all_credentials (RedTeamState compatibility)."""
        return self.all_credentials

    @property
    def hashes(self) -> list[Hash]:
        """Alias for all_hashes (RedTeamState compatibility)."""
        return self.all_hashes

    @property
    def shares(self) -> list[Share]:
        """Alias for all_shares (RedTeamState compatibility)."""
        return self.all_shares

    @property
    def weaknesses(self) -> list[str]:
        """Alias for all_weaknesses (RedTeamState compatibility)."""
        return self.all_weaknesses

    @property
    def queried_hosts(self) -> set[str]:
        """Compatibility property - tracks queried hosts."""
        # SharedRedTeamState tracks this via pending_tasks, but provide empty set for compatibility
        return getattr(self, "_queried_hosts", set())

    @queried_hosts.setter
    def queried_hosts(self, value: set[str]) -> None:
        """Set queried hosts."""
        object.__setattr__(self, "_queried_hosts", value)

    @property
    def tested_credentials(self) -> set[str]:
        """Compatibility property - tracks tested credentials."""
        return getattr(self, "_tested_credentials", set())

    @tested_credentials.setter
    def tested_credentials(self, value: set[str]) -> None:
        """Set tested credentials."""
        object.__setattr__(self, "_tested_credentials", value)

    def get_credential_key(self, username: str, password: str, domain: str = "") -> str:
        """Generate unique key for credential tracking (RedTeamState compatibility)."""
        return f"{domain}:{username}:{password}".lower()

    def to_summary(self) -> dict[str, Any]:
        """Generate summary for reporting."""
        return {
            "operation_id": self.operation_id,
            "domain_count": len(self.all_domains),
            "host_count": len(self.all_hosts),
            "credential_count": len(self.all_credentials),
            "hash_count": len(self.all_hashes),
            "vulnerability_count": len(self.discovered_vulnerabilities),
            "exploited_count": len(self.exploited_vulnerabilities),
            "pending_tasks": len(self.pending_tasks),
            "completed_tasks": len(self.completed_tasks),
            "pending_credential_findings": len(self.pending_credential_findings),
            "has_domain_admin": self.has_domain_admin,
            "has_golden_ticket": self.has_golden_ticket,
            "golden_ticket_count": len(self.golden_tickets),
            "acl_chain_count": len(self.acl_chains),
            "gmsa_account_count": len(self.gmsa_accounts),
            "adminsd_backdoor_count": len(self.adminsd_holder_backdoors),
            "processed_cred_expansion": len(self.processed_cred_expansion),
            "processed_hash_lateral": len(self.processed_hash_lateral),
            "processed_crack_requests": len(self.processed_crack_requests),
            "registered_agents": list(self.registered_agents.keys()),
        }

    def to_bytes(self) -> bytes:
        """Serialize state for Redis storage (JSON format)."""
        for host in self.all_hosts:
            hostname = (host.hostname or "").strip()
            if not hostname:
                continue
            lowered = hostname.lower()
            if lowered.startswith("ip-") and "compute.internal" in lowered:
                host.hostname = ""

        data = _to_json(self)
        # Version 2: parsing bugs fixed, no cleanup needed on load
        data["_v"] = 2
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> SharedRedTeamState:
        """Deserialize state from Redis (JSON)."""
        raw = json.loads(data)
        version = raw.pop("_v", 1)  # Default to v1 for old checkpoints
        state = _from_json(raw, cls)

        state.all_credentials = cls._dedupe_credentials(state.all_credentials)
        if not state.all_domains:
            state.all_domains = cls._extract_domains(state)

        # Version-gated cleanup: only run domain cleanup on old checkpoints (v1)
        if version < 2:
            logger.info(f"Migrating v{version} checkpoint - running domain data cleanup")
            state._cleanup_domain_data()

        # Always sanitize share permissions - agents can still return bad data
        # even with v2, since LLM parsing is non-deterministic
        state._sanitize_share_permissions()

        return state

    def _cleanup_domain_data(self) -> None:  # noqa: PLR0912
        """Clean up domain data to fix historical issues.

        This method fixes:
        1. NetBIOS domains that should be FQDNs (e.g., "child" -> remove if "child.contoso.local" exists)
        2. Users with parent domain when they only exist in child domain
        3. Credentials with parent domain when user only exists in child domain
        """
        # 1. Remove NetBIOS entries when FQDN exists
        fqdns = [d for d in self.all_domains if "." in d]
        netbios_to_remove: set[str] = set()

        for netbios in [d for d in self.all_domains if "." not in d]:
            # Check if any FQDN starts with this NetBIOS name
            for fqdn in fqdns:
                if fqdn.startswith(netbios + "."):
                    netbios_to_remove.add(netbios)
                    break

        if netbios_to_remove:
            self.all_domains = [d for d in self.all_domains if d not in netbios_to_remove]
            logger.info(
                f"Cleaned up {len(netbios_to_remove)} NetBIOS domain(s): {netbios_to_remove}"
            )

        # 2. Build mapping of username -> domains (to find users in multiple domains)
        user_domains: dict[str, set[str]] = {}
        for user in self.all_users:
            username_lower = user.username.lower()
            domain_lower = (user.domain or "").lower()
            if username_lower not in user_domains:
                user_domains[username_lower] = set()
            user_domains[username_lower].add(domain_lower)

        # 3. For users in both parent and child domains, keep only the child domain
        users_to_update: dict[str, str] = {}  # username -> correct child domain
        for username, domains in user_domains.items():
            if len(domains) <= 1:
                continue
            # Find parent-child relationships
            for d1 in domains:
                for d2 in domains:
                    if d1 != d2 and d1.endswith("." + d2):
                        # d1 is child of d2 - user should be in d1
                        users_to_update[username] = d1

        # 4. Update users and credentials
        if users_to_update:
            # Remove duplicate user entries with parent domain
            updated_users: list[User] = []
            seen_users: set[tuple[str, str]] = set()
            for user in self.all_users:
                username_lower = user.username.lower()
                domain_lower = (user.domain or "").lower()
                correct_domain = users_to_update.get(username_lower)

                if correct_domain:
                    # This user should be in the child domain
                    if domain_lower != correct_domain:
                        # Skip this entry (it's the parent domain duplicate)
                        continue
                    domain_lower = correct_domain
                    user.domain = correct_domain

                key = (username_lower, domain_lower)
                if key not in seen_users:
                    seen_users.add(key)
                    updated_users.append(user)

            if len(updated_users) < len(self.all_users):
                logger.info(
                    f"Cleaned up {len(self.all_users) - len(updated_users)} duplicate user(s) "
                    f"with parent domain"
                )
                self.all_users = updated_users

            # Update credentials with parent domain
            creds_updated = 0
            for cred in self.all_credentials:
                username_lower = cred.username.lower()
                correct_domain = users_to_update.get(username_lower)
                if correct_domain and cred.domain.lower() != correct_domain:
                    cred.domain = correct_domain
                    creds_updated += 1

            if creds_updated:
                logger.info(f"Fixed {creds_updated} credential(s) with parent domain")
                self.all_credentials = self._dedupe_credentials(self.all_credentials)

            # Update hashes with parent domain
            hashes_updated = 0
            for hash_obj in self.all_hashes:
                username_lower = hash_obj.username.lower()
                correct_domain = users_to_update.get(username_lower)
                if correct_domain and hash_obj.domain.lower() != correct_domain:
                    hash_obj.domain = correct_domain
                    hashes_updated += 1

            if hashes_updated:
                logger.info(f"Fixed {hashes_updated} hash(es) with parent domain")

        # 5. Deduplicate Kerberoast/AS-REP hashes by user+SPN+etype
        self.all_hashes = self._dedupe_hashes(self.all_hashes)

    def _sanitize_share_permissions(self) -> None:
        """Sanitize share permissions to fix historical parsing bugs.

        Netexec output has columns: Share, Permissions, Remark
        When shares have no permissions, the Remark column was incorrectly
        parsed as permissions (e.g., "Remote" from "Remote Admin").

        This fixes existing bad data by clearing invalid permissions.
        """
        valid_perms = {"read", "write", "read,write", "write,read", "full"}
        fixed_count = 0

        for share in self.all_shares:
            if not share.permissions:
                continue
            perm_lower = share.permissions.strip().lower()
            if perm_lower not in valid_perms:
                # Invalid permission - was probably parsed from comment
                # Move it to comment if comment is empty
                if not share.comment:
                    share.comment = share.permissions
                share.permissions = ""
                fixed_count += 1

        if fixed_count:
            logger.info(f"Fixed {fixed_count} share(s) with invalid permissions")

    def _dedupe_hashes(self, hashes: list[Hash]) -> list[Hash]:
        """Deduplicate hashes.

        - NTLM hashes: dedupe by hash_value
        - AS-REP hashes: dedupe by username+domain (same password)
        - Kerberoast hashes: dedupe by username+domain+SPN+etype
        """
        deduped: list[Hash] = []
        seen_values: set[str] = set()  # For NTLM
        seen_asrep: set[str] = set()  # For AS-REP: domain:username
        seen_kerberoast: set[str] = set()  # For Kerberoast: domain:username:spn_key

        for hash_obj in hashes:
            hash_value = hash_obj.hash_value or ""
            hash_type = (hash_obj.hash_type or "").lower()
            username = (hash_obj.username or "").lower()
            domain = (hash_obj.domain or "").lower()

            is_asrep = hash_type in {"as-rep", "asrep", "krb5asrep"} or hash_value.startswith(
                "$krb5asrep$"
            )
            is_kerberoast = hash_type in {
                "kerberoast",
                "krb5tgs",
                "tgs-rep",
                "tgs",
            } or hash_value.startswith("$krb5tgs$")

            if is_asrep:
                key = f"{domain}:{username}"
                if key in seen_asrep:
                    continue
                seen_asrep.add(key)
            elif is_kerberoast:
                spn_key = self._extract_kerberoast_spn_key(hash_value)
                key = f"{domain}:{username}:{spn_key}"
                if key in seen_kerberoast:
                    continue
                seen_kerberoast.add(key)
            else:
                # NTLM and other hashes - dedupe by exact value
                if hash_value in seen_values:
                    continue
                seen_values.add(hash_value)

            deduped.append(hash_obj)

        removed = len(hashes) - len(deduped)
        if removed > 0:
            logger.info(f"Deduplicated {removed} hash(es)")

        return deduped

    @staticmethod
    def _dedupe_credentials(credentials: list[Credential]) -> list[Credential]:
        """Deduplicate credentials by domain:username:password key."""
        deduped: list[Credential] = []
        seen: set[str] = set()
        for cred in credentials:
            username = (cred.username or "").strip()
            domain = (cred.domain or "").strip()
            password = (cred.password or "").strip()
            key = f"{domain}:{username}:{password}".lower()
            if not username or key in seen:
                continue
            seen.add(key)
            cred.username = username
            cred.domain = domain
            cred.password = password
            deduped.append(cred)
        return deduped

    @staticmethod
    def _extract_domains(state: SharedRedTeamState) -> list[str]:  # noqa: PLR0912
        """Extract all domains from state objects."""
        domains: set[str] = set()
        if state.target and state.target.domain:
            domains.add(state.target.domain.strip().lower())
        # Extract from target hostname (e.g., dc.contoso.local -> contoso.local)
        if state.target and state.target.hostname:
            hostname = state.target.hostname.strip().lower()
            if "." in hostname:
                parts = hostname.split(".")
                if len(parts) > 1:
                    domains.add(".".join(parts[1:]))
        for user in state.all_users:
            if user.domain:
                domains.add(user.domain.strip().lower())
        for cred in state.all_credentials:
            if cred.domain:
                domains.add(cred.domain.strip().lower())
        for h in state.all_hashes:
            if h.domain:
                domains.add(h.domain.strip().lower())
        # Extract domains from host FQDNs (e.g., dc01.contoso.local -> contoso.local)
        for host in state.all_hosts:
            hostname = (host.hostname or "").strip().lower()
            if "." in hostname:
                parts = hostname.split(".")
                if len(parts) > 1:
                    domains.add(".".join(parts[1:]))
        return sorted(domains)


@dataclass
class AgentLocalState:
    """
    Per-agent local state (not shared across cluster).

    Tracks agent-specific progress and context that doesn't need
    to be shared with other agents.
    """

    agent_name: str
    agent_role: AgentRole
    current_task: str | None = None
    tools_executed: list[str] = field(default_factory=list)
    errors_encountered: list[str] = field(default_factory=list)
    last_checkpoint: datetime | None = None

    # Agent-specific discoveries before broadcasting
    local_credentials: list[Credential] = field(default_factory=list)
    local_hashes: list[Hash] = field(default_factory=list)

    def record_tool_execution(self, tool_name: str) -> None:
        """Record a tool execution."""
        self.tools_executed.append(tool_name)

    def record_error(self, error: str) -> None:
        """Record an error."""
        self.errors_encountered.append(error)
