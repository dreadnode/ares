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

import threading
import uuid
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

from ares.core.config import get_default_max_retries


def _get_uuid() -> str:
    """Get a UUID, deterministic if replay context is active."""
    try:
        from ares.core.replay.determinism import get_deterministic_uuid

        return get_deterministic_uuid()
    except ImportError:
        return str(uuid.uuid4())


# Default retry count for tasks - exported for test compatibility
DEFAULT_MAX_RETRIES = 3

__all__ = [
    "DEFAULT_MAX_RETRIES",
    "AgentInfo",
    "AgentLocalState",
    "AgentRole",
    "BlueRole",
    "BlueTaskInfo",
    "BlueTaskType",
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
    "Share",
    "SharedBlueTeamState",
    "SharedRedTeamState",
    "Target",
    "TaskInfo",
    "TaskResult",
    "TaskStatus",
    "TimelineEvent",
    "TriageDecision",
    "TriageRecord",
    "User",
    "VulnerabilityInfo",
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
        discovered_at: When the credential was discovered.
        is_admin: Whether this is an admin credential.
        parent_id: ID of the credential/hash that enabled this discovery (for attack chain).
        attack_step: Position in the attack chain (0 = initial access).
    """

    id: str = Field(default_factory=_get_uuid)
    username: str
    password: str
    domain: str = ""
    source: str = ""  # where it was found
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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

    id: str = Field(default_factory=_get_uuid)
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


# Map in-memory processed set attribute names to Redis set names
# Used by SharedRedTeamState.mark_processed() and is_processed() methods
_PROCESSED_SET_MAP: dict[str, str] = {
    "processed_cred_expansion": "cred_expansion",
    "processed_hash_lateral": "hash_lateral",
    "processed_crack_requests": "crack_requests",
    "processed_asrep_domains": "asrep_domains",
    "processed_username_spray": "username_spray",
    "processed_password_spray": "password_spray",  # nosec B105 # pragma: allowlist secret
    "processed_secretsdump": "secretsdump",  # pragma: allowlist secret
    "processed_esc8_servers": "esc8_servers",
    "processed_coerced_dcs": "coerced_dcs",
    "processed_writable_shares": "writable_shares",
    "processed_delegation_creds": "delegation_creds",
    "processed_adcs_servers": "adcs_servers",
    "processed_bloodhound_domains": "bloodhound_domains",
    "processed_spidered_shares": "spidered_shares",
    "processed_expansion_creds": "expansion_creds",
    "dispatched_acl_steps": "acl_steps",
    "scanned_targets": "scanned_targets",
}


@dataclass
class SharedRedTeamState:
    """
    Cluster-wide state shared across all agents.

    Stored in Redis for pod crash recovery and multi-agent coordination.

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
    target_ips: list[str] = field(default_factory=list)  # All target IPs (for multi-target ops)
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
    da_hash_id: str | None = None  # ID of the krbtgt hash that achieved DA (for attack chain)

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

    # Golden ticket capability tracking
    # Key: "domain:username" (lowercase), Value: list of capability info dicts
    # Each dict: {domain, reason, dc_host, dc_ip}
    # reason: "local_admin_on_dc" (has admin on a DC, can dump NTDS.dit)
    golden_ticket_capable_creds: dict[str, list[dict]] = field(default_factory=dict)

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

    # Report-time fields (set during report generation, NOT serialized)
    vulnerability_count: int | None = field(default=None, init=False, repr=False, compare=False)
    exploited_count: int | None = field(default=None, init=False, repr=False, compare=False)

    # Transient dispatcher reference for real-time publishing (NOT serialized)
    _dispatcher: Any = field(default=None, init=False, repr=False, compare=False)

    # Background task tracking for proper cleanup (NOT serialized)
    _background_tasks: set = field(default_factory=set, init=False, repr=False, compare=False)

    # Tracking sets exposed via properties (NOT serialized)
    _queried_hosts: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _tested_credentials: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )
    # Weakness deduplication keys (normalized title + affected entity)
    _weakness_dedup_keys: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )

    # Redis-native state backend (NOT serialized)
    # When set, all add_* methods persist directly to Redis instead of in-memory lists
    _backend: Any = field(default=None, init=False, repr=False, compare=False)
    # Event loop where backend was created (for cross-loop detection)
    _backend_loop: Any = field(default=None, init=False, repr=False, compare=False)

    def set_dispatcher(self, dispatcher) -> None:
        """Set dispatcher for real-time publishing of discoveries."""
        object.__setattr__(self, "_dispatcher", dispatcher)

    def set_backend(self, backend) -> None:
        """Set Redis-native state backend for direct persistence.

        When a backend is set, all add_* methods will persist changes
        directly to Redis instead of in-memory lists. This eliminates
        the need for periodic checkpointing and merge logic.

        Also captures the current event loop to detect cross-loop calls
        from threaded consumers, which would cause "Future attached to
        a different loop" errors.

        Args:
            backend: RedisStateBackend instance
        """
        import asyncio

        object.__setattr__(self, "_backend", backend)
        # Capture the event loop where backend was created
        try:
            loop = asyncio.get_running_loop()
            object.__setattr__(self, "_backend_loop", loop)
        except RuntimeError:
            # No event loop running, will be set later
            pass

    def _can_persist_to_backend(self) -> bool:
        """Check if we can safely persist to the Redis backend.

        Returns False if:
        - No backend is set
        - No event loop is running
        - Current loop differs from backend loop (threaded consumer case)

        When called from the threaded result consumer, the current loop
        is different from where the backend was created. Attempting to
        use the backend's Redis client from a different loop causes
        "Future attached to a different loop" errors. In this case,
        we skip persistence - the worker already published the data
        via pub/sub, so it's not lost.
        """
        if not self._backend:
            return False

        import asyncio

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            return False

        # If backend loop wasn't captured (shouldn't happen), allow persist
        if self._backend_loop is None:
            return True

        # Only persist if we're in the same loop where backend was created
        return current_loop is self._backend_loop

    def _track_background_task(self, task, description: str = "") -> None:
        """Track a background Redis persist task with proper error handling.

        This ensures Redis persist failures are logged instead of silently ignored.
        The task is tracked in _background_tasks and removed on completion.

        Args:
            task: asyncio.Task to track
            description: Human-readable description for error logging (e.g., "add_credential")
        """

        def done_callback(t):
            self._background_tasks.discard(t)
            if t.cancelled():
                return
            exc = t.exception()
            if exc:
                logger.warning(
                    f"Background Redis persist failed ({description}): {exc!r}. "
                    f"State may diverge - checkpoint will reconcile."
                )

        self._background_tasks.add(task)
        task.add_done_callback(done_callback)

    # =========================================================================
    # Processed Set Helpers (with Redis persistence)
    # =========================================================================

    def mark_processed(self, set_name: str, key: str) -> None:
        """Mark a key as processed in both in-memory set and Redis backend.

        This is a sync wrapper that updates the in-memory set immediately
        and fires off an async task to persist to Redis backend if available.

        Args:
            set_name: Name of the processed set (e.g., "cred_expansion")
            key: The key to mark as processed
        """
        # Get the corresponding in-memory set attribute
        attr_name = f"processed_{set_name}" if not set_name.startswith("processed_") else set_name
        if attr_name not in _PROCESSED_SET_MAP and set_name not in _PROCESSED_SET_MAP.values():
            # Try direct attribute access for non-mapped sets
            if hasattr(self, attr_name):
                getattr(self, attr_name).add(key)
            elif hasattr(self, set_name):
                getattr(self, set_name).add(key)
            return

        # Determine Redis set name and in-memory attribute
        if attr_name in _PROCESSED_SET_MAP:
            redis_set_name = _PROCESSED_SET_MAP[attr_name]
            in_memory_attr: str | None = attr_name
        else:
            # set_name is already the Redis name
            redis_set_name = set_name
            # Find the in-memory attribute
            in_memory_attr = next((k for k, v in _PROCESSED_SET_MAP.items() if v == set_name), None)

        # Update in-memory set
        if in_memory_attr is not None and hasattr(self, in_memory_attr):
            getattr(self, in_memory_attr).add(key)

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.mark_processed(redis_set_name, key))
            self._track_background_task(task, f"mark_processed({redis_set_name})")

    def is_processed(self, set_name: str, key: str) -> bool:
        """Check if a key has been processed.

        This checks the in-memory set for fast sync access.
        For Redis-native mode, in-memory sets are kept in sync via mark_processed().

        Args:
            set_name: Name of the processed set (e.g., "cred_expansion")
            key: The key to check

        Returns:
            True if the key has been processed
        """
        # Get the corresponding in-memory set attribute
        attr_name = f"processed_{set_name}" if not set_name.startswith("processed_") else set_name
        if hasattr(self, attr_name):
            return key in getattr(self, attr_name)
        # Try direct set_name
        if hasattr(self, set_name):
            return key in getattr(self, set_name)
        return False

    async def load_processed_sets_from_backend(self) -> None:
        """Load all processed sets from Redis backend into memory.

        This should be called after recovery to sync the in-memory sets
        with the persisted Redis state. Only needed for Redis-native mode.
        """
        if not self._backend:
            return

        for attr_name, redis_set_name in _PROCESSED_SET_MAP.items():
            if hasattr(self, attr_name):
                try:
                    items = await self._backend.get_processed_set(redis_set_name)
                    # Update in-memory set with items from Redis
                    getattr(self, attr_name).update(items)
                except Exception as e:
                    from loguru import logger

                    logger.warning(f"Failed to load processed set {attr_name}: {e}")

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

    # =========================================================================
    # Persistence Tracking Helpers (with Redis persistence)
    # =========================================================================

    def add_golden_ticket(self, ticket: dict) -> bool:
        """Add a golden ticket to state and persist to Redis.

        Args:
            ticket: Golden ticket dict with domain, ticket_path, status, etc.

        Returns:
            True if added (always succeeds unless Redis persistence fails silently)
        """
        # Check for duplicate by domain (allow updates for same domain, e.g., failed -> success)
        for existing in self.golden_tickets:
            if (
                existing.get("domain", "").lower() == ticket.get("domain", "").lower()
                and existing.get("status") == "success"
                and ticket.get("status") == "success"
            ):
                logger.debug(f"Golden ticket already exists for {ticket.get('domain')}")
                return False

        self.golden_tickets.append(ticket)
        logger.info(f"Golden ticket added for {ticket.get('domain')}: {ticket.get('status')}")

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_golden_ticket(ticket))
            self._track_background_task(task, "add_golden_ticket")

        return True

    def add_adminsd_backdoor(self, backdoor_key: str) -> bool:
        """Add an AdminSD holder backdoor to state and persist to Redis.

        Args:
            backdoor_key: Backdoor identifier string

        Returns:
            True if added, False if duplicate
        """
        if backdoor_key in self.adminsd_holder_backdoors:
            logger.debug(f"AdminSD backdoor already exists: {backdoor_key}")
            return False

        self.adminsd_holder_backdoors.append(backdoor_key)
        logger.info(f"AdminSD backdoor added: {backdoor_key}")

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_adminsd_backdoor(backdoor_key))
            self._track_background_task(task, "add_adminsd_backdoor")

        return True

    def add_acl_chain(self, chain: dict) -> bool:
        """Add an ACL chain to state and persist to Redis.

        Args:
            chain: ACL chain dict with chain_id, steps, goal, domain, etc.

        Returns:
            True if added, False if duplicate chain_id
        """
        chain_id = chain.get("chain_id", "")
        for existing in self.acl_chains:
            if existing.get("chain_id") == chain_id:
                logger.debug(f"ACL chain already exists: {chain_id}")
                return False

        self.acl_chains.append(chain)
        logger.info(f"ACL chain added: {chain_id}")

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_acl_chain(chain))
            self._track_background_task(task, "add_acl_chain")

        return True

    def update_acl_chain(self, chain_id: str, chain: dict) -> bool:
        """Update an existing ACL chain in state and Redis.

        Args:
            chain_id: Chain ID to update
            chain: Updated chain dict

        Returns:
            True if updated, False if not found
        """
        for i, existing in enumerate(self.acl_chains):
            if existing.get("chain_id") == chain_id:
                self.acl_chains[i] = chain
                logger.info(f"ACL chain updated: {chain_id}")

                # Persist to Redis backend if available and in the correct event loop
                if self._can_persist_to_backend():
                    import asyncio

                    loop = asyncio.get_running_loop()
                    task = loop.create_task(self._backend.update_acl_chain(chain_id, chain))
                    self._track_background_task(task, f"update_acl_chain({chain_id})")

                return True

        logger.debug(f"ACL chain not found for update: {chain_id}")
        return False

    def add_gmsa_account(self, gmsa: dict) -> bool:
        """Add a gMSA account to state and persist to Redis.

        Args:
            gmsa: gMSA account dict with account, domain, principals_allowed, etc.

        Returns:
            True if added, False if duplicate
        """
        account = gmsa.get("account", "").lower()
        for existing in self.gmsa_accounts:
            if existing.get("account", "").lower() == account:
                logger.debug(f"gMSA account already exists: {account}")
                return False

        self.gmsa_accounts.append(gmsa)
        logger.info(f"gMSA account added: {gmsa.get('account')}")

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_gmsa_account(gmsa))
            self._track_background_task(task, "add_gmsa_account")

        return True

    async def load_persistence_tracking_from_backend(self) -> None:
        """Load all persistence tracking data from Redis backend into memory.

        This should be called after recovery to sync the in-memory lists
        with the persisted Redis state. Only needed for Redis-native mode.
        """
        if not self._backend:
            return

        try:
            # Load golden tickets
            tickets = await self._backend.get_golden_tickets()
            for ticket in tickets:
                # Add without triggering another Redis write
                if ticket not in self.golden_tickets:
                    self.golden_tickets.append(ticket)

            # Load AdminSD backdoors
            backdoors = await self._backend.get_adminsd_backdoors()
            for backdoor in backdoors:
                if backdoor not in self.adminsd_holder_backdoors:
                    self.adminsd_holder_backdoors.append(backdoor)

            # Load ACL chains
            chains = await self._backend.get_acl_chains()
            existing_chain_ids = {c.get("chain_id") for c in self.acl_chains}
            for chain in chains:
                if chain.get("chain_id") not in existing_chain_ids:
                    self.acl_chains.append(chain)

            # Load gMSA accounts
            gmsas = await self._backend.get_gmsa_accounts()
            existing_accounts = {g.get("account", "").lower() for g in self.gmsa_accounts}
            for gmsa in gmsas:
                if gmsa.get("account", "").lower() not in existing_accounts:
                    self.gmsa_accounts.append(gmsa)

            # Load golden ticket capable credentials
            gt_capable = await self._backend.get_golden_ticket_capable_creds()
            for cred_key, capabilities in gt_capable.items():
                if cred_key not in self.golden_ticket_capable_creds:
                    self.golden_ticket_capable_creds[cred_key] = capabilities
                else:
                    # Merge capabilities
                    existing_keys = {
                        f"{c.get('dc_ip')}:{c.get('reason')}"
                        for c in self.golden_ticket_capable_creds[cred_key]
                    }
                    for cap in capabilities:
                        cap_key = f"{cap.get('dc_ip')}:{cap.get('reason')}"
                        if cap_key not in existing_keys:
                            self.golden_ticket_capable_creds[cred_key].append(cap)

            logger.info(
                f"Loaded persistence tracking from Redis: "
                f"{len(self.golden_tickets)} golden tickets, "
                f"{len(self.adminsd_holder_backdoors)} backdoors, "
                f"{len(self.acl_chains)} ACL chains, "
                f"{len(self.gmsa_accounts)} gMSA accounts, "
                f"{len(self.golden_ticket_capable_creds)} golden ticket capable creds"
            )
        except Exception as e:
            logger.warning(f"Failed to load persistence tracking from backend: {e}")

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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.store_artifact(key, encoded))
            self._track_background_task(task, f"store_artifact({key})")

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
        2. Domain controllers keys (FQDNs discovered early via DC enumeration)
        3. Known domains that start with the NetBIOS name
        4. Existing credentials with matching domain prefix
        5. Target domain if it matches (fallback)

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

        # 2. Check domain_controllers keys (FQDNs discovered early via DC enumeration)
        # e.g., if netbios="north" and we have domain_controllers["north.sevenkingdoms.local"]
        matching_dc_domains = [
            d for d in self.domain_controllers if d.startswith(netbios_lower + ".")
        ]
        if matching_dc_domains:
            # Return the most specific (longest) match
            fqdn = max(matching_dc_domains, key=len)
            # Cache this mapping for future lookups
            self.netbios_to_fqdn[netbios_lower] = fqdn
            logger.debug(f"NetBIOS resolved via DC: {netbios_lower} -> {fqdn}")
            return fqdn

        # 3. Check known domains for a matching FQDN pattern
        # Prefer more specific (longer) matches to avoid parent/child domain confusion
        matching_domains = [
            d.lower() for d in self.all_domains if d.lower().startswith(netbios_lower + ".")
        ]
        if matching_domains:
            # Return the most specific (longest) match
            return max(matching_domains, key=len)

        # 4. Check existing credentials for a matching FQDN pattern
        for cred in self.all_credentials:
            cred_domain = (cred.domain or "").lower()
            if cred_domain.startswith(netbios_lower + "."):
                return cred_domain

        # 5. Check if target.domain starts with the NetBIOS name (least preferred)
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

        IMPORTANT: If the incoming domain is already an FQDN (contains "."), we trust it.
        Domain "correction" is primarily for fixing NetBIOS names, not overriding valid FQDNs.
        For example, krbtgt exists in EVERY domain with the same name but different hashes.
        We should NOT "correct" child.contoso.local to contoso.local just because
        krbtgt was only enumerated from the parent domain.

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

        # CRITICAL: Never correct domain for well-known accounts that exist in EVERY domain.
        # These accounts (krbtgt, Administrator, Guest, etc.) have the same username in every
        # domain but are completely different accounts with different hashes/passwords.
        # "Correcting" their domain based on user lookups is ALWAYS wrong.
        well_known_accounts = {"krbtgt", "administrator", "guest", "defaultaccount"}
        if username_lower in well_known_accounts:
            logger.debug(
                f"Domain kept as-is (well-known account): {domain_lower}\\{username_lower} "
                f"(never correct well-known accounts, source: {source_agent})"
            )
            return domain_lower

        # CRITICAL: If the incoming domain is already an FQDN (contains "."), trust it.
        # Domain correction was designed for fixing NetBIOS names like "CONTOSO" -> "contoso.local",
        # NOT for overriding valid FQDNs like "child.contoso.local" -> "contoso.local".
        #
        # Why this matters: Users like krbtgt exist in EVERY domain with the same name.
        # If we only enumerated krbtgt from the parent domain, we shouldn't "correct" a child
        # domain's krbtgt hash to the parent domain. They're different accounts with different hashes.
        is_incoming_fqdn = "." in domain_lower

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

        # Domain doesn't match any known domain for this user.
        # If incoming domain is an FQDN, do NOT override it - trust the tool's output.
        # The user may exist in multiple domains (e.g., krbtgt, Administrator, Guest).
        if is_incoming_fqdn:
            logger.debug(
                f"Domain kept as-is (FQDN): {domain_lower}\\{username_lower} "
                f"(user also known in {known_domains}, source: {source_agent})"
            )
            return domain_lower

        # Incoming domain is NetBIOS-only - try to correct it
        if len(known_domains) == 1:
            # User exists in exactly one domain - use that
            correct_domain = next(iter(known_domains))
            logger.warning(
                f"Domain correction (NetBIOS -> FQDN): {domain_lower}\\{username_lower} -> "
                f"{correct_domain}\\{username_lower} (user known from prior recon, "
                f"source: {source_agent})"
            )
            return correct_domain

        # User exists in multiple domains - pick the most likely one
        # Prefer child domains over parent domains (more specific)
        # E.g., prefer child.contoso.local over contoso.local
        sorted_domains = sorted(known_domains, key=len, reverse=True)
        best_match = sorted_domains[0]
        logger.warning(
            f"Domain correction (NetBIOS -> FQDN, ambiguous): {domain_lower}\\{username_lower} -> "
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

    def add_credential(self, credential: Credential, source_agent: str) -> bool:
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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_credential(credential))
            self._track_background_task(
                task, f"add_credential({credential.domain}\\{credential.username})"
            )

        return True

    def _handle_existing_user_domain(
        self,
        existing: User,
        normalized: str,
        normalized_domain: str,
        target_domain: str,
    ) -> bool | None:
        """Handle domain comparison for existing user.

        Returns:
            True if user was updated, False if should be rejected, None if not a match.
        """
        existing_domain = (existing.domain or "").lower()
        if existing.username != normalized:
            return None

        if existing_domain == normalized_domain:
            logger.debug(f"User rejected: duplicate {normalized_domain}\\{normalized}")
            return False

        # Check if this is a child->parent or parent->child relationship
        if normalized_domain.endswith("." + existing_domain):
            old_domain = existing_domain
            existing.domain = normalized_domain
            logger.info(
                f"User domain upgraded: {normalized} from {old_domain} to {normalized_domain}"
            )
            self._update_credentials_domain(normalized, old_domain, normalized_domain)
            self.add_domain(normalized_domain)
            return True

        if existing_domain.endswith("." + normalized_domain):
            logger.debug(
                f"User rejected: {normalized} already in more specific domain {existing_domain}"
            )
            return False

        # Sibling domain handling
        return self._handle_sibling_domain_user(
            existing, normalized, normalized_domain, existing_domain, target_domain
        )

    def _handle_sibling_domain_user(
        self,
        existing: User,
        normalized: str,
        normalized_domain: str,
        existing_domain: str,
        target_domain: str,
    ) -> bool:
        """Handle sibling domain case for user deduplication."""
        if existing_domain == target_domain and normalized_domain != target_domain:
            user_in_new_domain = any(
                u.username == normalized and (u.domain or "").lower() == normalized_domain
                for u in self.all_users
            )
            if user_in_new_domain:
                logger.debug(f"User rejected: {normalized} already exists in {normalized_domain}")
                return False
            old_domain = existing_domain
            existing.domain = normalized_domain
            logger.warning(
                f"User domain corrected: {normalized} from {old_domain} (target fallback) "
                f"to {normalized_domain} (specific discovery)"
            )
            self._update_credentials_domain(normalized, old_domain, normalized_domain)
            self.add_domain(normalized_domain)
            return True

        if normalized_domain == target_domain and existing_domain != target_domain:
            logger.debug(
                f"User rejected: {normalized} already in {existing_domain}, "
                f"ignoring target fallback {normalized_domain}"
            )
            return False

        logger.warning(
            f"User domain conflict: {normalized} in both {existing_domain} and "
            f"{normalized_domain} (keeping {existing_domain})"
        )
        return False

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
        normalized_domain = (domain or "").strip().lower()
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
        # Skip machine accounts (ending in $) - these are computer accounts, not users
        if normalized.endswith("$"):
            logger.debug(
                f"User rejected: machine account '{normalized}' for domain {normalized_domain}"
            )
            return False
        # Filter out tool output artifacts that look like usernames but are actually
        # status messages or descriptions (e.g., "gpp_passwords_found" from netexec)
        artifact_patterns = (
            "_found",
            "_failed",
            "_success",
            "_error",
            "_status",
            "passwords_",
            "credentials_",
            "hashes_",
        )
        normalized_lower = normalized.lower()
        if any(pattern in normalized_lower for pattern in artifact_patterns):
            logger.debug(
                f"User rejected: tool artifact '{normalized}' for domain {normalized_domain}"
            )
            return False

        target_domain = (self.target.domain or "").lower() if self.target else ""
        for existing in self.all_users:
            result = self._handle_existing_user_domain(
                existing, normalized, normalized_domain, target_domain
            )
            if result is not None:
                return result

        user = User(username=normalized, domain=normalized_domain, source=source)
        self.all_users.append(user)
        self.add_domain(normalized_domain)
        logger.debug(
            f"User added: {normalized_domain}\\{normalized} (source: {source or 'unknown'})"
        )

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_user(user))
            self._track_background_task(task, f"add_user({user.domain}\\{user.username})")

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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_domain(normalized))
            self._track_background_task(task, f"add_domain({normalized})")

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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.set_netbios_mapping(netbios_lower, fqdn_lower))
            self._track_background_task(task, f"set_netbios_mapping({netbios_lower})")

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

    def _normalize_parent_domain_credentials(self, child_fqdn: str) -> None:
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

    def add_hash(self, hash_obj: Hash, source_agent: str) -> bool:
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
                    # NOTE: Credential creation is handled by publish_hash() in publishing.py,
                    # which calls publish_credential() to trigger immediate dispatch (delegation
                    # checks, secretsdump, etc). We don't create credentials here because:
                    # 1. add_credential() is state-layer only - no immediate dispatch
                    # 2. The caller (publish_hash) will call publish_credential() which has dispatch logic
                    # 3. Creating here + caller creating = duplicate, which skips dispatch entirely
                    #
                    # Signal credential access if dispatcher available so loops wake up
                    if self._dispatcher:
                        if threading.current_thread() is threading.main_thread():
                            self._dispatcher.signal_credential_access()
                        elif hasattr(self._dispatcher, "_credential_access_requested"):
                            # Thread-safe signal - maintenance loop will transfer to asyncio.Event
                            self._dispatcher._credential_access_requested.set()
                    # Request checkpoint from dispatcher's maintenance loop
                    # _checkpoint_requested is a threading.Event, safe from any thread
                    if self._dispatcher and hasattr(self._dispatcher, "_checkpoint_requested"):
                        self._dispatcher._checkpoint_requested.set()
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
            self.da_hash_id = hash_obj.id  # Store the ID for consistent attack chain building
            # NOTE: Do NOT set completed_at here - that's controlled by stop_on_domain_admin
            # or stop_on_golden_ticket config in announcements.py
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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_hash(hash_obj))
            self._track_background_task(task, f"add_hash({domain}\\{username})")
            # Also persist DA status if achieved
            if hash_type == "ntlm" and username == "krbtgt":
                task2 = loop.create_task(
                    self._backend.set_domain_admin(
                        achieved=True, path=self.domain_admin_path, da_hash_id=self.da_hash_id
                    )
                )
                self._track_background_task(task2, "set_domain_admin")

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
            item: The credential or hash to start from. If None, uses the
                  stored DA hash (da_hash_id) or falls back to the most recent
                  krbtgt/Administrator hash.

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
            # CRITICAL: Use the stored da_hash_id if available.
            # This ensures consistency with domain_admin_path which was set when
            # the FIRST krbtgt hash was found. If we just pick the last krbtgt
            # hash, we might get a different attack chain (e.g., from a child domain).
            if self.da_hash_id:
                item = self.find_by_id(self.da_hash_id)
            # Fallback to finding the most recent krbtgt/administrator hash
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

    def add_host(self, host: Host) -> bool:
        """Add host if not duplicate. Returns True if added or meaningfully merged."""
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
                # Track if we're making meaningful changes (for checkpoint triggering)
                data_changed = False

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
                        data_changed = True
                        # Extract domain from new FQDN hostname
                        if new_is_fqdn:
                            parts = new_hostname.lower().split(".")
                            if len(parts) > 1:
                                domain = ".".join(parts[1:])
                                self.add_domain(domain)
                if host.os and (not existing.os or existing.os.lower() == "unknown"):
                    existing.os = host.os
                    data_changed = True
                if host.roles:
                    old_roles_count = len(existing.roles)
                    existing.roles = list({*existing.roles, *host.roles})
                    if len(existing.roles) > old_roles_count:
                        data_changed = True
                if host.services:
                    old_services_count = len(existing.services)
                    existing.services = list({*existing.services, *host.services})
                    if len(existing.services) > old_services_count:
                        data_changed = True
                # Update DC status after merge using OR-logic:
                # - Preserve existing is_dc=True (worker may have detected it)
                # - Accept incoming is_dc=True (worker serialized it)
                # - Re-detect from merged services/hostname
                old_is_dc = existing.is_dc
                existing.update_dc_status()
                # OR-logic: if any source says DC, it's a DC
                if host.is_dc and not existing.is_dc:
                    existing.is_dc = True
                if existing.is_dc and not old_is_dc:
                    data_changed = True
                # Register DC IP if merge reveals it's a domain controller
                if existing.is_dc and existing.hostname and "." in existing.hostname:
                    parts = existing.hostname.lower().split(".")
                    if len(parts) > 1:
                        domain = ".".join(parts[1:])
                        if domain not in self.domain_controllers:
                            self.domain_controllers[domain] = existing.ip
                            logger.info(f"DC registered (merge): {domain} -> {existing.ip}")
                logger.debug(
                    f"Host merged: {host.ip} (existing, updated details, is_dc={existing.is_dc}, "
                    f"data_changed={data_changed})"
                )
                # Persist merged host to Redis backend
                if self._can_persist_to_backend():
                    import asyncio

                    loop = asyncio.get_running_loop()
                    task = loop.create_task(self._backend.update_host(existing.ip, existing))
                    self._track_background_task(task, f"update_host({existing.ip})")
                    # Also persist DC mapping if merge revealed it's a DC
                    if existing.is_dc and existing.hostname and "." in existing.hostname:
                        parts = existing.hostname.lower().split(".")
                        if len(parts) > 1:
                            dc_domain = ".".join(parts[1:])
                            task2 = loop.create_task(self._backend.set_dc(dc_domain, existing.ip))
                            self._track_background_task(task2, f"set_dc({dc_domain})")
                # Return True if data changed so caller can trigger checkpoint
                return data_changed
        # Set DC status before adding (preserve incoming is_dc=True from worker)
        incoming_is_dc = host.is_dc
        host.update_dc_status()
        if incoming_is_dc and not host.is_dc:
            host.is_dc = True
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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_host(host))
            self._track_background_task(task, f"add_host({host.ip})")
            # Also persist DC mapping if this is a DC
            if host.is_dc and host.hostname and "." in host.hostname:
                parts = host.hostname.lower().split(".")
                if len(parts) > 1:
                    dc_domain = ".".join(parts[1:])
                    task2 = loop.create_task(self._backend.set_dc(dc_domain, host.ip))
                    self._track_background_task(task2, f"set_dc({dc_domain})")

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

        # Ensure host has SMB service since share discovery proves 445 is open
        share_host_ip = (share.host or "").strip()
        if share_host_ip:
            for existing_host in self.all_hosts:
                if existing_host.ip == share_host_ip:
                    has_smb = any(
                        "445" in svc or "smb" in svc.lower() or "microsoft-ds" in svc.lower()
                        for svc in existing_host.services
                    )
                    if not has_smb:
                        existing_host.services.append("445/tcp smb")
                    break

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_share(share))
            self._track_background_task(task, f"add_share({share.host}/{share.name})")

        return True

    def _extract_entities_from_weakness(self, block_lower: str) -> list[str]:
        """Extract affected entities from a weakness block in priority order."""
        import re

        # Machine accounts (DC01$, SQL01$) - highest priority
        machine_accounts = [m.group(1) for m in re.finditer(r"\b([a-z0-9_-]+\$)", block_lower)]
        if machine_accounts:
            return machine_accounts

        # IP addresses - high priority
        ips = [m.group(1) for m in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\b", block_lower)]
        if ips:
            return ips

        # User accounts with dots/underscores (svc_backup, admin.user)
        user_accounts = [
            m.group(1)
            for m in re.finditer(r"\b([a-z]+[._][a-z]+)\b", block_lower)
            if m.group(1) not in ("e.g", "i.e", "et.al")
        ]
        if user_accounts:
            return user_accounts

        # Hostnames with digits (dc01, sql01)
        common_words = {
            "the",
            "this",
            "some",
            "multiple",
            "all",
            "any",
            "account",
            "accounts",
            "host",
            "hosts",
            "server",
            "servers",
            "configured",
            "enabled",
            "disabled",
            "on",
            "for",
            "from",
            "to",
            "has",
            "with",
            "domain",
            "controller",
        }
        return [
            m.group(1)
            for m in re.finditer(
                r"(?:on|from|host|server)\s+([a-z][a-z0-9-]+)(?:\s|$|\.|,)", block_lower
            )
            if m.group(1) not in common_words and any(c.isdigit() for c in m.group(1))
        ]

    def _classify_weakness_type(self, block_lower: str) -> str:
        """Classify weakness type from block content."""
        type_patterns = [
            (("unconstrained", "delegation"), "unconstrained_delegation"),
            (("constrained", "delegation"), "constrained_delegation"),
            (("rbcd",), "rbcd"),
            (("resource-based",), "rbcd"),
            (("smb", "signing"), "smb_signing"),
            (("smbv1",), "smbv1"),
            (("llmnr",), "name_poisoning"),
            (("nbt-ns",), "name_poisoning"),
            (("mdns",), "name_poisoning"),
            (("rdp", "exposed"), "rdp_exposed"),
            (("rdp", "3389"), "rdp_exposed"),
            (("sql", "1433"), "mssql_exposed"),
            (("sql", "exposed"), "mssql_exposed"),
            (("kerberoast",), "kerberoastable"),
            (("asrep",), "asrep_roastable"),
            (("as-rep",), "asrep_roastable"),
            (("password", "policy"), "weak_password_policy"),
        ]
        for keywords, wtype in type_patterns:
            if all(kw in block_lower for kw in keywords):
                return wtype
        return "other"

    def _extract_weakness_dedup_key(self, block: str) -> str:
        """Extract a normalized deduplication key from a weakness block.

        The key is derived from weakness TYPE + affected entities.
        This handles LLM rephrasing the same finding with different titles.
        """
        block_lower = block.lower()
        entities = self._extract_entities_from_weakness(block_lower)
        weakness_type = self._classify_weakness_type(block_lower)
        unique_entities = sorted(set(entities))
        if unique_entities:
            return f"{weakness_type}:{','.join(unique_entities[:3])}"
        return weakness_type

    def add_weakness(self, block: str) -> bool:
        """Add weakness if not duplicate. Returns True if added. Triggers pub/sub.

        Deduplication uses normalized keys extracted from the weakness:
        - Title (### header)
        - Affected resource/account (if present)

        This prevents duplicates like "Unconstrained delegation on HOST$" being
        recorded multiple times with slightly different descriptions.
        """
        if not block:
            return False

        # Extract normalized dedup key from the weakness block
        dedup_key = self._extract_weakness_dedup_key(block)
        if dedup_key in self._weakness_dedup_keys:
            logger.debug(f"Weakness rejected (duplicate key): {dedup_key}")
            return False

        # Also check exact match for legacy weaknesses without proper structure
        if block in self.all_weaknesses:
            return False

        self._weakness_dedup_keys.add(dedup_key)
        self.all_weaknesses.append(block)
        logger.info(f"Weakness added [{dedup_key}]: {block[:60]}...")

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            # Pass dedup_key to backend for proper HASH-based deduplication
            task = loop.create_task(self._backend.add_weakness(block, dedup_key))
            self._track_background_task(task, "add_weakness")

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

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.add_vulnerability(vuln))
            self._track_background_task(task, f"add_vulnerability({vuln.vuln_type})")

        return True

    def mark_exploited(self, vuln_id: str) -> None:
        """Mark a vulnerability as exploited."""
        self.exploited_vulnerabilities.add(vuln_id)

        # Persist to Redis backend if available and in the correct event loop
        if self._can_persist_to_backend():
            import asyncio

            loop = asyncio.get_running_loop()
            task = loop.create_task(self._backend.mark_exploited(vuln_id))
            self._track_background_task(task, f"mark_exploited({vuln_id})")

    def get_unexploited_vulnerabilities(self) -> list[VulnerabilityInfo]:
        """Get vulnerabilities that haven't been exploited yet."""
        return [
            v
            for vid, v in self.discovered_vulnerabilities.items()
            if vid not in self.exploited_vulnerabilities
        ]

    # =========================================================================
    # Golden Ticket Capability Detection
    # =========================================================================

    def check_golden_ticket_capability(self, username: str, domain: str) -> list[dict[str, str]]:
        """Check if a credential can obtain krbtgt hash (golden ticket capability).

        A credential can forge a golden ticket if it has local admin access on a
        Domain Controller. This allows dumping NTDS.dit to extract the krbtgt hash.

        ACCURACY NOTE: We ONLY return True for verified conditions:
        1. The credential has a local_admin vulnerability on a host
        2. That host is confirmed as a DC (is_dc=True in all_hosts)
        3. The DC's domain matches the credential's domain (or is resolvable)

        We do NOT assume golden ticket capability based on:
        - Generic "admin" flags without confirmed DC access
        - Membership in groups without verified DC admin rights
        - Untested/unverified access claims

        Args:
            username: The username to check.
            domain: The domain of the credential.

        Returns:
            List of capability dicts, each with:
            - domain: The domain where krbtgt can be obtained
            - reason: "local_admin_on_dc"
            - dc_host: DC hostname
            - dc_ip: DC IP address
        """
        capabilities: list[dict[str, str]] = []
        username_lower = username.lower()
        domain_lower = domain.lower()

        # Build a map of DC hosts: hostname -> Host, ip -> Host
        dc_hosts_by_name: dict[str, Host] = {}
        dc_hosts_by_ip: dict[str, Host] = {}
        for host in self.all_hosts:
            if host.is_dc:
                if host.hostname:
                    # Store by short name and FQDN
                    dc_hosts_by_name[host.hostname.lower()] = host
                    short_name = host.hostname.split(".")[0].lower()
                    dc_hosts_by_name[short_name] = host
                if host.ip:
                    dc_hosts_by_ip[host.ip] = host

        # Check all local_admin vulnerabilities for this user
        for vuln in self.discovered_vulnerabilities.values():
            if vuln.vuln_type != "local_admin":
                continue

            # Get the principal from the vulnerability
            principal = vuln.details.get("username", "").lower()
            principal_domain = vuln.details.get("domain", "").lower()

            # Also check the principal field directly (may include domain)
            vuln_principal = str(vuln.details.get("principal", "")).lower()
            if "@" in vuln_principal:
                parts = vuln_principal.split("@")
                if len(parts) == 2:
                    principal = parts[0]
                    principal_domain = parts[1]
            elif "\\" in vuln_principal:
                parts = vuln_principal.split("\\")
                if len(parts) == 2:
                    principal_domain = parts[0]
                    principal = parts[1]

            # Match username (case-insensitive)
            if principal != username_lower:
                continue

            # Match domain if specified (handle NetBIOS vs FQDN)
            if (
                principal_domain
                and domain_lower
                and not self._domains_match(principal_domain, domain_lower)
            ):
                continue

            # Get the target host from the vulnerability
            target = vuln.target.lower()

            # Check if target is a DC
            dc_host = dc_hosts_by_name.get(target) or dc_hosts_by_ip.get(target)
            if not dc_host:
                # Try matching by partial hostname
                for name, host in dc_hosts_by_name.items():
                    if target in name or name in target:
                        dc_host = host
                        break

            if dc_host:
                # Determine the domain of this DC
                dc_domain = ""
                if dc_host.hostname and "." in dc_host.hostname:
                    # Extract domain from FQDN: winterfell.north.sevenkingdoms.local -> north.sevenkingdoms.local
                    parts = dc_host.hostname.lower().split(".", 1)
                    if len(parts) > 1:
                        dc_domain = parts[1]

                # Also check domain_controllers cache
                for cached_domain, cached_ip in self.domain_controllers.items():
                    if cached_ip == dc_host.ip:
                        dc_domain = cached_domain
                        break

                capabilities.append(
                    {
                        "domain": dc_domain or domain_lower,
                        "reason": "local_admin_on_dc",
                        "dc_host": dc_host.hostname or dc_host.ip,
                        "dc_ip": dc_host.ip,
                    }
                )

        return capabilities

    def _domains_match(self, domain1: str, domain2: str) -> bool:
        """Check if two domain identifiers refer to the same domain.

        Handles NetBIOS name vs FQDN comparison using netbios_to_fqdn mapping.
        """
        d1 = domain1.lower()
        d2 = domain2.lower()

        if d1 == d2:
            return True

        # Check if one is NetBIOS and maps to the other
        d1_fqdn = self.netbios_to_fqdn.get(d1, d1)
        d2_fqdn = self.netbios_to_fqdn.get(d2, d2)

        if d1_fqdn == d2_fqdn:
            return True

        # Check if one is a prefix of the other (north vs north.sevenkingdoms.local)
        return d1_fqdn.startswith(d2 + ".") or d2_fqdn.startswith(d1 + ".")

    def update_golden_ticket_capability(
        self, username: str, domain: str, source_agent: str = ""
    ) -> bool:
        """Update golden ticket capability tracking for a credential.

        Should be called when:
        1. A new credential is published
        2. A new local_admin vulnerability is discovered
        3. A new DC host is identified

        Args:
            username: The username to check.
            domain: The domain of the credential.
            source_agent: Agent that triggered the check.

        Returns:
            True if new capability was detected, False otherwise.
        """
        cred_key = f"{domain.lower()}:{username.lower()}"

        # Check current capabilities
        capabilities = self.check_golden_ticket_capability(username, domain)

        if not capabilities:
            return False

        # Check if this is new capability
        existing = self.golden_ticket_capable_creds.get(cred_key, [])
        existing_keys = {f"{c.get('dc_ip')}:{c.get('reason')}" for c in existing}

        new_capabilities = []
        for cap in capabilities:
            cap_key = f"{cap.get('dc_ip')}:{cap.get('reason')}"
            if cap_key not in existing_keys:
                new_capabilities.append(cap)

        if new_capabilities:
            updated_capabilities = existing + new_capabilities
            self.golden_ticket_capable_creds[cred_key] = updated_capabilities
            logger.info(
                f"🎫 GOLDEN TICKET CAPABILITY: {domain}\\{username} can obtain krbtgt "
                f"via {new_capabilities[0].get('reason')} on {new_capabilities[0].get('dc_host')}"
            )

            # Persist to Redis backend if available
            if self._can_persist_to_backend():
                import asyncio

                loop = asyncio.get_running_loop()
                task = loop.create_task(
                    self._backend.add_golden_ticket_capable_cred(cred_key, updated_capabilities)
                )
                self._track_background_task(task, f"add_golden_ticket_capable_cred({cred_key})")

            return True

        return False

    def get_golden_ticket_capable_credentials(self) -> list[tuple[str, list[dict]]]:
        """Get all credentials with golden ticket capability.

        Returns:
            List of (cred_key, capabilities) tuples where cred_key is "domain:username"
            and capabilities is the list of ways they can obtain krbtgt.
        """
        return list(self.golden_ticket_capable_creds.items())

    def get_agent_credentials(self, agent_name: str) -> list[Credential]:
        """Get credentials discovered by a specific agent."""
        return [c for c in self.all_credentials if c.source.startswith(f"{agent_name}:")]

    # =========================================================================
    # Convenience aliases
    # =========================================================================

    @property
    def hosts(self) -> list[Host]:
        """Alias for all_hosts."""
        return self.all_hosts

    @property
    def users(self) -> list[User]:
        """Alias for all_users."""
        return self.all_users

    @property
    def credentials(self) -> list[Credential]:
        """Alias for all_credentials."""
        return self.all_credentials

    @property
    def hashes(self) -> list[Hash]:
        """Alias for all_hashes."""
        return self.all_hashes

    @property
    def shares(self) -> list[Share]:
        """Alias for all_shares."""
        return self.all_shares

    @property
    def weaknesses(self) -> list[str]:
        """Return combined weaknesses and vulnerability descriptions for reporting."""
        vuln_descriptions = [
            f"{v.vuln_type} on {v.target} ({v.vuln_id})"
            for v in self.discovered_vulnerabilities.values()
        ]
        return self.all_weaknesses + vuln_descriptions

    @property
    def timeline(self) -> list[TimelineEvent]:
        """Alias for operation_timeline."""
        return self.operation_timeline

    @property
    def stage(self) -> InvestigationStage:
        """Return operation stage for reporting."""
        return InvestigationStage.SYNTHESIS

    @property
    def report_summary(self) -> str:
        """Return empty report summary (generated dynamically)."""
        return ""

    @property
    def admin_count(self) -> int:
        """Count of admin credentials."""
        return sum(1 for c in self.all_credentials if c.is_admin)

    @property
    def credential_count(self) -> int:
        """Count of all credentials."""
        return len(self.all_credentials)

    @property
    def host_count(self) -> int:
        """Count of all hosts."""
        return len(self.all_hosts)

    @property
    def queried_hosts(self) -> set[str]:
        """Tracks queried hosts."""
        return getattr(self, "_queried_hosts", set())

    @queried_hosts.setter
    def queried_hosts(self, value: set[str]) -> None:
        """Set queried hosts."""
        object.__setattr__(self, "_queried_hosts", value)

    @property
    def tested_credentials(self) -> set[str]:
        """Tracks tested credentials."""
        return getattr(self, "_tested_credentials", set())

    @tested_credentials.setter
    def tested_credentials(self, value: set[str]) -> None:
        """Set tested credentials."""
        object.__setattr__(self, "_tested_credentials", value)

    def get_credential_key(self, username: str, password: str, domain: str = "") -> str:
        """Generate unique key for credential tracking."""
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
    def _extract_domains(state: SharedRedTeamState) -> list[str]:
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


# =============================================================================
# Blue Team Multi-Agent Models
# =============================================================================


class BlueRole(Enum):
    """Specialized roles for multi-agent blue team operations."""

    ORCHESTRATOR = "orchestrator"
    TRIAGE = "triage"
    THREAT_HUNTER = "threat_hunter"
    LATERAL_ANALYST = "lateral_analyst"


class BlueTaskType(Enum):
    """Types of tasks dispatched to blue team workers."""

    TRIAGE_ALERT = "triage_alert"
    THREAT_HUNT = "threat_hunt"
    LATERAL_ANALYSIS = "lateral_analysis"
    USER_INVESTIGATION = "user_investigation"
    HOST_INVESTIGATION = "host_investigation"


@dataclass
class BlueTaskInfo:
    """Information about a dispatched blue team task."""

    task_id: str
    task_type: BlueTaskType
    investigation_id: str
    status: TaskStatus = TaskStatus.PENDING
    assigned_role: BlueRole = BlueRole.TRIAGE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    params: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    retry_count: int = 0


class TriageDecision(Enum):
    """Triage decisions for escalated investigations.

    When an investigation is escalated, the triage agent evaluates
    whether it truly requires human review or can be handled automatically.

    Attributes:
        PENDING: Triage not yet performed.
        CONFIRMED: Valid escalation, needs human review.
        DOWNGRADED: False positive or low priority, auto-completed.
        REINVESTIGATE: Need more data before deciding.
        ROUTED: Routed to specific team/action.
    """

    PENDING = "pending"
    CONFIRMED = "confirmed"
    DOWNGRADED = "downgraded"
    REINVESTIGATE = "reinvestigate"
    ROUTED = "routed"


@dataclass
class TriageRecord:
    """Record of a triage decision for audit trail.

    Each time the triage agent makes a decision, a record is created
    to track the reasoning and enable post-hoc analysis.

    Attributes:
        triage_id: Unique identifier for this triage record.
        investigation_id: Investigation this triage applies to.
        decision: The triage decision made.
        reasoning: LLM-generated explanation for the decision.
        confidence: Confidence score 0.0-1.0 for the decision.
        routed_to: Team/action if decision is ROUTED.
        focus_areas: Areas to focus on if decision is REINVESTIGATE.
        reinvestigation_cycle: Current reinvestigation cycle (0-2).
        created_at: When this record was created.
    """

    triage_id: str
    investigation_id: str
    decision: TriageDecision
    reasoning: str
    confidence: float
    routed_to: str | None = None
    focus_areas: list[str] = field(default_factory=list)
    reinvestigation_cycle: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for Redis storage."""
        return {
            "triage_id": self.triage_id,
            "investigation_id": self.investigation_id,
            "decision": self.decision.value,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "routed_to": self.routed_to,
            "focus_areas": self.focus_areas,
            "reinvestigation_cycle": self.reinvestigation_cycle,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TriageRecord:
        """Create from dictionary (Redis deserialization)."""
        return cls(
            triage_id=data["triage_id"],
            investigation_id=data["investigation_id"],
            decision=TriageDecision(data["decision"]),
            reasoning=data["reasoning"],
            confidence=data["confidence"],
            routed_to=data.get("routed_to"),
            focus_areas=data.get("focus_areas", []),
            reinvestigation_cycle=data.get("reinvestigation_cycle", 0),
            created_at=datetime.fromisoformat(data["created_at"])
            if isinstance(data.get("created_at"), str)
            else data.get("created_at", datetime.now(timezone.utc)),
        )


@dataclass
class SharedBlueTeamState:
    """Cluster-wide state shared across all blue team agents.

    Stored in Redis for multi-agent coordination. Each field maps to
    a Redis key under ares:blue:inv:{investigation_id}:*.

    Attributes:
        investigation_id: Unique identifier for this investigation.
        alert: The original alert that triggered investigation.
        stage: Current investigation stage.
        started_at: When the investigation began.
        evidence: List of all evidence collected across agents.
        timeline: Timeline events in chronological order.
        identified_techniques: MITRE ATT&CK technique IDs found.
        identified_tactics: MITRE ATT&CK tactic IDs found.
        queried_hosts: Hosts that have been investigated.
        queried_users: Users that have been investigated.
        executed_query_types: Query method names already executed.
        executed_queries: Log of all queries executed.
        technique_names: Mapping of technique IDs to names.
        lateral_connections: Lateral movement connections discovered.
        queued_pivot_queries: Auto-generated pivot queries.
        queued_chain_queries: Auto-generated follow-up detection methods.
        escalated: Whether investigation was escalated.
        escalation_reason: Reason for escalation.
        attack_synopsis: Summary of the attack.
        recommendations: Recommended actions.
        correlation_context: Alert correlation context.
        pending_tasks: Tasks dispatched but not completed.
        completed_tasks: Results of completed tasks.
    """

    investigation_id: str
    alert: dict[str, Any] = field(default_factory=dict)
    stage: InvestigationStage = InvestigationStage.TRIAGE
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Evidence and timeline (aggregated from all agents)
    evidence: list[Evidence] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)

    # MITRE tracking
    identified_techniques: set[str] = field(default_factory=set)
    identified_tactics: set[str] = field(default_factory=set)
    technique_names: dict[str, str] = field(default_factory=dict)

    # Investigation scope
    queried_hosts: set[str] = field(default_factory=set)
    queried_users: set[str] = field(default_factory=set)
    executed_query_types: set[str] = field(default_factory=set)
    executed_queries: list[dict] = field(default_factory=list)

    # Lateral movement
    lateral_connections: list[dict] = field(default_factory=list)

    # Auto-pivot and detection chaining
    queued_pivot_queries: list[dict] = field(default_factory=list)
    queued_chain_queries: list[str] = field(default_factory=list)

    # Completion
    escalated: bool = False
    escalation_reason: str | None = None
    attack_synopsis: str | None = None
    recommendations: list[str] = field(default_factory=list)

    # Alert correlation
    correlation_context: dict[str, Any] | None = None

    # Task tracking
    pending_tasks: dict[str, BlueTaskInfo] = field(default_factory=dict)
    completed_tasks: dict[str, BlueTaskInfo] = field(default_factory=dict)

    # Triage tracking (for escalated investigations)
    triage_decision: TriageDecision = TriageDecision.PENDING
    triage_records: list[TriageRecord] = field(default_factory=list)

    # Evidence dedup keys (in-memory for fast checking)
    _evidence_dedup_keys: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )

    # Backend reference (NOT serialized)
    _backend: Any = field(default=None, init=False, repr=False, compare=False)

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

    def set_backend(self, backend) -> None:
        """Set Redis state backend."""
        object.__setattr__(self, "_backend", backend)

    def to_investigation_state(self) -> InvestigationState:
        """Convert to InvestigationState for report generation and eval scoring.

        This is the backward-compatibility bridge: MarkdownReportGenerator.generate()
        and eval scorers operate on InvestigationState regardless of source.
        """
        from ares.core.lateral_analyzer import LateralGraph

        state = InvestigationState(
            investigation_id=self.investigation_id,
            alert=self.alert,
            stage=self.stage,
            started_at=self.started_at,
            evidence=list(self.evidence),
            timeline=sorted(self.timeline, key=lambda e: e.timestamp),
            executed_queries=list(self.executed_queries),
            identified_techniques=set(self.identified_techniques),
            identified_tactics=set(self.identified_tactics),
            queried_hosts=set(self.queried_hosts),
            queried_users=set(self.queried_users),
            technique_names=dict(self.technique_names),
            escalated=self.escalated,
            escalation_reason=self.escalation_reason,
            attack_synopsis=self.attack_synopsis,
            recommendations=list(self.recommendations),
            correlation_context=self.correlation_context,
            queued_pivot_queries=list(self.queued_pivot_queries),
            queued_chain_queries=list(self.queued_chain_queries),
            executed_query_types=set(self.executed_query_types),
        )

        # Rebuild lateral graph from connections
        graph = LateralGraph()
        for conn in self.lateral_connections:
            graph.add_connection(
                source=conn.get("source", ""),
                destination=conn.get("destination", ""),
                conn_type=conn.get("connection_type", ""),
                user=conn.get("user", ""),
                mitre_technique=conn.get("mitre_technique", ""),
            )
        state.lateral_graph = graph

        return state

    def to_summary(self) -> dict:
        """Return a summary dict of the investigation state."""
        return {
            "investigation_id": self.investigation_id,
            "stage": self.stage.value,
            "evidence_count": self.evidence_count,
            "timeline_events": len(self.timeline),
            "techniques_identified": list(self.identified_techniques),
            "highest_pyramid_level": self.highest_pyramid_level,
            "ttp_count": self.ttp_count,
            "hosts_investigated": list(self.queried_hosts),
            "users_investigated": list(self.queried_users),
            "pending_tasks": len(self.pending_tasks),
            "completed_tasks": len(self.completed_tasks),
        }
