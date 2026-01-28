"""Inter-agent communication protocol for multi-agent red team operations.

This module defines the message types used for communication between
specialized red team agents in a distributed Kubernetes environment.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class MessageType(Enum):
    """Types of messages exchanged between agents."""

    # Discovery broadcasts - notify all agents of new findings
    CREDENTIAL_DISCOVERED = "credential_discovered"
    HASH_DISCOVERED = "hash_discovered"
    HOST_DISCOVERED = "host_discovered"
    USER_DISCOVERED = "user_discovered"
    SHARE_DISCOVERED = "share_discovered"
    VULNERABILITY_FOUND = "vulnerability_found"

    # Task requests - dispatch work to specialized agents
    CRACK_REQUEST = "crack_request"
    LATERAL_REQUEST = "lateral_request"
    EXPLOIT_REQUEST = "exploit_request"
    COERCION_REQUEST = "coercion_request"
    ACL_ANALYSIS_REQUEST = "acl_analysis_request"
    CREDENTIAL_ACCESS_REQUEST = "credential_access_request"
    RECON_REQUEST = "recon_request"

    # Task responses - report results back
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"
    TASK_PROGRESS = "task_progress"

    # Coordination messages
    AGENT_REGISTERED = "agent_registered"
    AGENT_HEARTBEAT = "agent_heartbeat"
    AGENT_OFFLINE = "agent_offline"
    PRIORITY_CHANGE = "priority_change"
    DOMAIN_ADMIN_ACHIEVED = "domain_admin_achieved"
    GOLDEN_TICKET_FORGED = "golden_ticket_forged"
    OPERATION_COMPLETE = "operation_complete"
    OPERATION_ABORT = "operation_abort"


def generate_message_id() -> str:
    """Generate a unique message ID."""
    return f"msg-{uuid.uuid4().hex[:12]}"


def generate_task_id() -> str:
    """Generate a unique task ID."""
    return f"task-{uuid.uuid4().hex[:12]}"


class AgentMessage(BaseModel):
    """Base message for inter-agent communication."""

    id: str = Field(default_factory=generate_message_id)
    type: MessageType
    source_agent: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)
    reply_to: str | None = None  # For request-response patterns
    priority: int = 5  # 1=highest, 10=lowest

    model_config = {"use_enum_values": True}


# Discovery Messages


class CredentialDiscovered(AgentMessage):
    """Broadcast when new credential found."""

    type: MessageType = MessageType.CREDENTIAL_DISCOVERED
    username: str
    password: str | None = None
    hash_value: str | None = None
    domain: str = ""
    is_admin: bool = False
    discovery_method: str = ""


class HashDiscovered(AgentMessage):
    """Broadcast when new hash found."""

    type: MessageType = MessageType.HASH_DISCOVERED
    username: str
    hash_value: str
    hash_type: str = "NTLM"  # NTLM, NetNTLMv2, Kerberos, AS-REP
    domain: str = ""
    priority: int = 5  # krbtgt=1, admin=2, user=5


class HostDiscovered(AgentMessage):
    """Broadcast when new host found."""

    type: MessageType = MessageType.HOST_DISCOVERED
    ip: str
    hostname: str = ""
    os: str = ""
    roles: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


class VulnerabilityFound(AgentMessage):
    """Broadcast when exploitable vulnerability discovered."""

    type: MessageType = MessageType.VULNERABILITY_FOUND
    vuln_type: str  # ADCS_ESC1, UNCONSTRAINED_DELEGATION, ACL_ABUSE, etc.
    vuln_id: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)
    recommended_agent: str  # Which agent should exploit this
    exploit_tools: list[str] = Field(default_factory=list)  # Tools to use


# Task Request Messages


class CrackRequest(AgentMessage):
    """Request to crack a hash."""

    type: MessageType = MessageType.CRACK_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    hash_value: str
    hash_type: str  # NTLM=1000, NetNTLMv2=5600, Kerberos=13100, AS-REP=18200
    username: str = ""
    domain: str = ""
    callback_agent: str = ""
    wordlist: str = "rockyou.txt"
    rules: str | None = None


class LateralMovementRequest(AgentMessage):
    """Request lateral movement to target."""

    type: MessageType = MessageType.LATERAL_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    target_host: str
    username: str
    password: str | None = None
    hash_value: str | None = None
    domain: str = ""
    method: str | None = None  # psexec, winrm, wmi - None for auto
    callback_agent: str = ""


class ExploitRequest(AgentMessage):
    """Request exploitation of a vulnerability."""

    type: MessageType = MessageType.EXPLOIT_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    vuln_type: str  # ADCS_ESC1, DELEGATION_UNCONSTRAINED, etc.
    vuln_id: str
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    callback_agent: str = ""


class ACLAnalysisRequest(AgentMessage):
    """Request ACL analysis for attack paths."""

    type: MessageType = MessageType.ACL_ANALYSIS_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    target_user: str
    domain: str
    find_path_to: str = "Domain Admins"  # Target group/user
    callback_agent: str = ""


class CredentialAccessRequest(AgentMessage):
    """Request credential access actions (AS-REP roast, Kerberoast, secretsdump, LSASS)."""

    type: MessageType = MessageType.CREDENTIAL_ACCESS_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    target_ips: list[str] = Field(default_factory=list)
    domain: str = ""
    dc_ip: str = ""
    username: str = ""
    password: str | None = None
    hash_value: str | None = None
    techniques: list[str] = Field(default_factory=list)
    callback_agent: str = ""


class ReconRequest(AgentMessage):
    """Request reconnaissance actions (nmap, user enumeration, BloodHound)."""

    type: MessageType = MessageType.RECON_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    target_ips: list[str] = Field(default_factory=list)
    domain: str = ""
    dc_ip: str = ""
    username: str = ""
    password: str | None = None
    hash_value: str | None = None
    reason: str | None = None  # e.g., "network_scan", "bloodhound", "user_enum"
    techniques: list[str] = Field(default_factory=list)
    callback_agent: str = ""


class CoercionRequest(AgentMessage):
    """Request network coercion."""

    type: MessageType = MessageType.COERCION_REQUEST
    task_id: str = Field(default_factory=generate_task_id)
    interface: str = "eth0"
    techniques: list[str] = Field(default_factory=lambda: ["LLMNR", "NBT-NS", "mDNS"])
    duration: int = 300  # seconds
    callback_agent: str = ""


# Task Response Messages


class TaskComplete(AgentMessage):
    """Task completed successfully."""

    type: MessageType = MessageType.TASK_COMPLETE
    task_id: str
    success: bool = True
    result: dict[str, Any] = Field(default_factory=dict)
    execution_time: float = 0.0  # seconds


class TaskFailed(AgentMessage):
    """Task failed."""

    type: MessageType = MessageType.TASK_FAILED
    task_id: str
    success: bool = False
    error: str
    error_type: str = "unknown"
    recoverable: bool = False


class TaskProgress(AgentMessage):
    """Progress update for long-running task."""

    type: MessageType = MessageType.TASK_PROGRESS
    task_id: str
    progress: float  # 0.0 to 1.0
    status_message: str = ""


# Coordination Messages


class AgentRegistered(AgentMessage):
    """Agent has registered with dispatcher."""

    type: MessageType = MessageType.AGENT_REGISTERED
    agent_name: str
    agent_role: str
    pod_name: str
    capabilities: list[str] = Field(default_factory=list)


class AgentHeartbeat(AgentMessage):
    """Periodic heartbeat from agent."""

    type: MessageType = MessageType.AGENT_HEARTBEAT
    agent_name: str
    status: str = "idle"  # idle, busy, offline
    current_task: str | None = None
    memory_usage: float = 0.0
    tasks_completed: int = 0


class PriorityChange(AgentMessage):
    """Change priority for a task or vulnerability type."""

    type: MessageType = MessageType.PRIORITY_CHANGE
    target_type: str  # "task" or "vuln_type"
    target_id: str
    new_priority: int  # 1=highest, 10=lowest
    reason: str = ""


class DomainAdminAchieved(AgentMessage):
    """Domain admin access has been achieved."""

    type: MessageType = MessageType.DOMAIN_ADMIN_ACHIEVED
    username: str
    domain: str
    attack_path: str  # Description of how it was achieved
    credential_type: str  # "password", "hash", "ticket"


class GoldenTicketForged(AgentMessage):
    """Golden ticket has been forged."""

    type: MessageType = MessageType.GOLDEN_TICKET_FORGED
    domain: str
    krbtgt_hash: str
    ticket_path: str


class OperationComplete(AgentMessage):
    """Operation has completed."""

    type: MessageType = MessageType.OPERATION_COMPLETE
    operation_id: str
    success: bool
    summary: str
    total_credentials: int = 0
    total_hosts: int = 0
    domain_admin_achieved: bool = False


class OperationAbort(AgentMessage):
    """Abort the operation."""

    type: MessageType = MessageType.OPERATION_ABORT
    operation_id: str
    reason: str
    cleanup_required: bool = False


# Message Factory


def create_message(message_type: MessageType, source_agent: str, **kwargs) -> AgentMessage:
    """Factory function to create appropriate message type."""
    message_classes = {
        MessageType.CREDENTIAL_DISCOVERED: CredentialDiscovered,
        MessageType.HASH_DISCOVERED: HashDiscovered,
        MessageType.HOST_DISCOVERED: HostDiscovered,
        MessageType.VULNERABILITY_FOUND: VulnerabilityFound,
        MessageType.CRACK_REQUEST: CrackRequest,
        MessageType.LATERAL_REQUEST: LateralMovementRequest,
        MessageType.EXPLOIT_REQUEST: ExploitRequest,
        MessageType.ACL_ANALYSIS_REQUEST: ACLAnalysisRequest,
        MessageType.COERCION_REQUEST: CoercionRequest,
        MessageType.TASK_COMPLETE: TaskComplete,
        MessageType.TASK_FAILED: TaskFailed,
        MessageType.TASK_PROGRESS: TaskProgress,
        MessageType.AGENT_REGISTERED: AgentRegistered,
        MessageType.AGENT_HEARTBEAT: AgentHeartbeat,
        MessageType.PRIORITY_CHANGE: PriorityChange,
        MessageType.DOMAIN_ADMIN_ACHIEVED: DomainAdminAchieved,
        MessageType.GOLDEN_TICKET_FORGED: GoldenTicketForged,
        MessageType.OPERATION_COMPLETE: OperationComplete,
        MessageType.OPERATION_ABORT: OperationAbort,
    }

    cls = message_classes.get(message_type, AgentMessage)
    return cls(source_agent=source_agent, **kwargs)


__all__ = [
    "ACLAnalysisRequest",
    "AgentHeartbeat",
    "AgentMessage",
    "AgentRegistered",
    "CoercionRequest",
    "CrackRequest",
    "CredentialDiscovered",
    "DomainAdminAchieved",
    "ExploitRequest",
    "GoldenTicketForged",
    "HashDiscovered",
    "HostDiscovered",
    "LateralMovementRequest",
    "MessageType",
    "OperationAbort",
    "OperationComplete",
    "PriorityChange",
    "TaskComplete",
    "TaskFailed",
    "TaskProgress",
    "VulnerabilityFound",
    "create_message",
    "generate_message_id",
    "generate_task_id",
]
