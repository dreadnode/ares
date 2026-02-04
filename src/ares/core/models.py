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

from loguru import logger
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
    is_dc: bool = False

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
    source: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


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
    all_domains: list[str] = field(default_factory=list)
    # Authoritative NetBIOS to FQDN mapping from AD crossRef objects
    # Key: lowercase NetBIOS name (e.g., "corp"), Value: FQDN (e.g., "corp.contoso.local")
    # Populated by querying CN=Partitions,CN=Configuration via LDAP
    netbios_to_fqdn: dict[str, str] = field(default_factory=dict)
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
    pending_credential_findings: set[str] = field(default_factory=set)

    # Shared artifacts storage (base64-encoded file contents)
    # Key format: "category/filename" -> base64 content
    # Example: "sysvol/login.bat" -> "QmF0Y2ggZmlsZSBjb250ZW50..."
    downloaded_artifacts: dict[str, str] = field(default_factory=dict)

    # Transient dispatcher reference for real-time publishing (NOT pickled)
    _dispatcher: Any = field(default=None, init=False, repr=False, compare=False)

    def __getstate__(self):
        """Exclude _dispatcher from pickling."""
        state = self.__dict__.copy()
        state.pop("_dispatcher", None)
        return state

    def __setstate__(self, state):
        """Restore state without dispatcher."""
        self.__dict__.update(state)
        self._dispatcher = None

    def set_dispatcher(self, dispatcher) -> None:
        """Set dispatcher for real-time publishing of discoveries."""
        object.__setattr__(self, "_dispatcher", dispatcher)

    def _publish_async(self, coro) -> None:
        """Fire-and-forget async publish to Redis."""
        if not self._dispatcher:
            return
        try:
            import asyncio

            loop = asyncio.get_running_loop()
            asyncio.ensure_future(coro, loop=loop)  # noqa: RUF006 - fire-and-forget
        except RuntimeError:
            # No event loop, skip real-time publish
            pass

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

    def add_credential(self, credential: Credential, source_agent: str) -> bool:
        """Add credential if not duplicate. Returns True if added."""
        username = credential.username.strip()
        # Normalize domain to lowercase for consistency
        domain = credential.domain.strip().lower()
        # Resolve NetBIOS domain names (e.g., "CONTOSO") to FQDN (e.g., "contoso.local")
        if domain and "." not in domain:
            domain = self._resolve_netbios_to_fqdn(domain)
        password = credential.password.strip()
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
        self.add_user(username, domain)
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
        credential.username = username
        credential.domain = domain
        credential.password = password
        credential.source = f"{source_agent}:{credential.source}"
        self.all_credentials.append(credential)
        pending_key = f"{domain}:{username}".lower()
        self.pending_credential_findings.discard(pending_key)
        logger.info(f"Credential added: {domain}\\{username} (source: {source_agent})")

        # Real-time checkpoint to Redis (don't call publish_credential - that would re-add)
        if self._dispatcher:
            self._dispatcher.signal_credential_access()
            self._publish_async(self._dispatcher._checkpoint())

        return True

    def add_user(self, username: str, domain: str) -> bool:
        """Add user if not duplicate. Returns True if added."""
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
        for existing in self.all_users:
            existing_domain = (existing.domain or "").lower()
            if existing.username == normalized and existing_domain == normalized_domain:
                logger.debug(f"User rejected: duplicate {normalized_domain}\\{normalized}")
                return False
        self.all_users.append(User(username=normalized, domain=normalized_domain))
        self.add_domain(normalized_domain)
        logger.debug(f"User added: {normalized_domain}\\{normalized}")
        return True

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
        netbios = fqdn.split(".")[0]
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

        # Now deduplicate credentials that may now be duplicates after normalization
        self.all_credentials = self._dedupe_credentials(self.all_credentials)

    def add_hash(self, hash_obj: Hash, source_agent: str) -> bool:
        """Add hash if not duplicate. Returns True if added."""
        hash_type = (hash_obj.hash_type or "").strip().lower()
        username = (hash_obj.username or "").strip().lower()
        domain = (hash_obj.domain or "").strip().lower()
        # Resolve NetBIOS domain names to FQDN
        if domain and "." not in domain:
            domain = self._resolve_netbios_to_fqdn(domain)
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
                logger.debug(
                    f"Hash rejected: duplicate hash for {domain}\\{username} ({hash_type}) from {source_agent}"
                )
                return False
            # For AS-REP, dedupe by user since each request generates different hash but same password
            # NOTE: Don't dedupe Kerberoast by user - same user can have multiple SPNs with different
            # encryption types (RC4 vs AES), and we want to keep all of them for cracking flexibility
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
        # Update hash_obj with normalized values (including resolved domain)
        hash_obj.domain = domain
        hash_obj.username = username
        self.add_domain(domain)
        if not getattr(hash_obj, "source", ""):
            hash_obj.source = source_agent
        else:
            hash_obj.source = f"{source_agent}:{hash_obj.source}"
        if not getattr(hash_obj, "discovered_at", None):
            hash_obj.discovered_at = datetime.now(timezone.utc)
        self.all_hashes.append(hash_obj)
        logger.info(f"Hash added: {domain}\\{username} ({hash_type}) (source: {source_agent})")

        # Real-time checkpoint to Redis (don't call publish_hash - that would re-add)
        if self._dispatcher:
            self._dispatcher.signal_credential_access()
            self._publish_async(self._dispatcher._checkpoint())

        return True

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
        self.all_shares.append(share)
        logger.debug(f"Share added: {host}/{name}")

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
            "registered_agents": list(self.registered_agents.keys()),
        }

    def to_bytes(self) -> bytes:
        """Serialize state for Redis storage."""
        import pickle  # nosec B403

        for host in self.all_hosts:
            hostname = (host.hostname or "").strip()
            if not hostname:
                continue
            lowered = hostname.lower()
            if lowered.startswith("ip-") and "compute.internal" in lowered:
                host.hostname = ""

        return pickle.dumps(self)  # nosec B301

    @classmethod
    def from_bytes(cls, data: bytes) -> SharedRedTeamState:
        """Deserialize state from Redis."""
        import pickle  # nosec B403

        state = pickle.loads(data)  # noqa: S301  # nosec B301
        if not hasattr(state, "all_domains"):
            state.all_domains = []
        if not hasattr(state, "pending_credential_findings"):
            state.pending_credential_findings = set()
        if not hasattr(state, "downloaded_artifacts"):
            state.downloaded_artifacts = {}
        for host in state.all_hosts:
            if not hasattr(host, "is_dc"):
                host.update_dc_status()
        state.all_credentials = cls._dedupe_credentials(state.all_credentials)
        if not state.all_domains:
            state.all_domains = cls._extract_domains(state)
        return state

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
        # Extract from target hostname (e.g., dc.example.local -> example.local)
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
