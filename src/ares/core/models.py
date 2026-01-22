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

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any

from pydantic import Field, computed_field
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

__all__ = [
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
        """Convert to dictionary for storage (backward compatible)."""
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
        """Convert to dictionary for storage (backward compatible)."""
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
        """Convert to dictionary for storage (backward compatible)."""
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


class User(Model):
    """Discovered user account."""

    username: str
    domain: str = ""
    description: str = ""
    is_admin: bool = False


class Credential(Model):
    """Discovered credential."""

    username: str
    password: str
    domain: str = ""
    source: str = ""  # where it was found
    is_admin: bool = False


class Hash(Model):
    """Discovered password hash."""

    username: str
    hash_value: str
    hash_type: str = "NTLM"
    domain: str = ""
    cracked_password: str = ""


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
    tested_credentials: set[str] = field(default_factory=set)
    timeline: list[TimelineEvent] = field(default_factory=list)
    identified_techniques: set[str] = field(default_factory=set)

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

    ENUM = "enum"
    CRACKER = "cracker"
    ACL = "acl"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    POISONING = "poisoning"


class TaskStatus(Enum):
    """Status of a dispatched task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"  # Marked for retry after pod restart


# Default max retries for tasks interrupted by pod restarts
DEFAULT_MAX_RETRIES = 3


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
    params: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    retry_count: int = 0
    max_retries: int = DEFAULT_MAX_RETRIES


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

    # Global discoveries (aggregated from all agents)
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

    # Agent registry
    registered_agents: dict[str, AgentInfo] = field(default_factory=dict)

    # Timeline for cross-agent correlation
    operation_timeline: list[TimelineEvent] = field(default_factory=list)
    identified_techniques: set[str] = field(default_factory=set)

    def add_credential(self, credential: Credential, source_agent: str) -> bool:
        """Add credential if not duplicate. Returns True if added."""
        username = credential.username.strip()
        if not username or username.lower() in {"(none)", "none", "null", "(null)"}:
            return False
        key = f"{credential.domain}:{credential.username}:{credential.password}".lower()
        for existing in self.all_credentials:
            existing_key = f"{existing.domain}:{existing.username}:{existing.password}".lower()
            if key == existing_key:
                return False
        credential.source = f"{source_agent}:{credential.source}"
        self.all_credentials.append(credential)
        return True

    def add_hash(self, hash_obj: Hash, source_agent: str) -> bool:
        """Add hash if not duplicate. Returns True if added."""
        for existing in self.all_hashes:
            if existing.hash_value == hash_obj.hash_value:
                return False
        self.all_hashes.append(hash_obj)
        return True

    def add_host(self, host: Host) -> bool:
        """Add host if not duplicate. Returns True if added."""
        for existing in self.all_hosts:
            if existing.ip == host.ip:
                return False
        self.all_hosts.append(host)
        return True

    def add_vulnerability(self, vuln: VulnerabilityInfo) -> bool:
        """Add vulnerability if not duplicate. Returns True if added."""
        if vuln.vuln_id in self.discovered_vulnerabilities:
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
            "host_count": len(self.all_hosts),
            "credential_count": len(self.all_credentials),
            "hash_count": len(self.all_hashes),
            "vulnerability_count": len(self.discovered_vulnerabilities),
            "exploited_count": len(self.exploited_vulnerabilities),
            "pending_tasks": len(self.pending_tasks),
            "completed_tasks": len(self.completed_tasks),
            "has_domain_admin": self.has_domain_admin,
            "has_golden_ticket": self.has_golden_ticket,
            "registered_agents": list(self.registered_agents.keys()),
        }

    def to_bytes(self) -> bytes:
        """Serialize state for Redis storage."""
        import pickle  # nosec B403

        return pickle.dumps(self)  # nosec B301

    @classmethod
    def from_bytes(cls, data: bytes) -> SharedRedTeamState:
        """Deserialize state from Redis."""
        import pickle  # nosec B403

        return pickle.loads(data)  # noqa: S301  # nosec B301


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
