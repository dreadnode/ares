"""Central dispatcher for multi-agent red team operations.

This module provides the RedTeamDispatcher class which coordinates
communication and task routing between specialized red team agents
running in Kubernetes pods.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from asyncio import PriorityQueue, Queue
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import get_agent_heartbeat_timeout
from ares.core.messages import (
    ACLAnalysisRequest,
    AgentMessage,
    AgentRegistered,
    CoercionRequest,
    CrackRequest,
    CredentialAccessRequest,
    CredentialDiscovered,
    DomainAdminAchieved,
    ExploitRequest,
    GoldenTicketForged,
    HashDiscovered,
    HostDiscovered,
    LateralMovementRequest,
    MessageType,
    OperationComplete,
    ReconRequest,
    TaskComplete,
    TaskFailed,
    VulnerabilityFound,
    generate_task_id,
)
from ares.core.models import (
    AgentInfo,
    AgentRole,
    Credential,
    Hash,
    Host,
    Share,
    SharedRedTeamState,
    TaskInfo,
    TaskResult,
    TaskStatus,
    User,
    VulnerabilityInfo,
)
from ares.core.recovery import _merge_state
from ares.core.redis_client import create_redis_client
from ares.core.task_queue import RedisTaskQueue
from ares.core.task_queue import TaskResult as QueueTaskResult

if TYPE_CHECKING:
    from collections.abc import Callable


class RedTeamDispatcher:
    """
    Central coordinator for multi-agent red team operations.

    Responsibilities:
    - Agent registration and health monitoring
    - Task routing based on agent capabilities
    - Credential/discovery broadcasting
    - State aggregation across agents

    Usage:
        dispatcher = RedTeamDispatcher()
        await dispatcher.start(operation_id)

        # Register agents as they come online
        await dispatcher.register(agent_info)

        # Publish discoveries to all agents
        await dispatcher.publish_credential(credential, "ares-recon")

        # Route tasks to specialized agents
        task_id = await dispatcher.request_crack(hash_data, "orchestrator")
    """

    def __init__(self, redis_url: str | None = None):
        """
        Initialize the dispatcher.

        Args:
            redis_url: Optional Redis URL for state persistence and task queuing.
                       If not provided, uses in-memory state only.
        """
        self._agents: dict[str, AgentInfo] = {}
        self._message_queues: dict[str, Queue[AgentMessage]] = {}
        self._shared_state: SharedRedTeamState | None = None
        self._subscribers: dict[MessageType, set[str]] = {}
        self._task_callbacks: dict[str, Callable] = {}
        self._running = False
        self._redis_url = redis_url
        self._redis_client = None
        self._heartbeat_task: asyncio.Task | None = None
        self._message_processor_task: asyncio.Task | None = None
        self._agent_heartbeat_timeout = get_agent_heartbeat_timeout()
        self._credential_access_event = asyncio.Event()

        # Redis task queue for cross-pod communication
        self._task_queue: RedisTaskQueue | None = None
        if redis_url:
            self._task_queue = RedisTaskQueue(redis_url)

        # Role-based routing
        self._role_queues: dict[AgentRole, str] = {}  # role -> agent_name

        # Priority-based vulnerability queue
        self._vulnerability_queue: PriorityQueue[tuple[int, str, dict[str, Any]]] = PriorityQueue()
        self._vulnerability_priorities: dict[str, int] = {
            "ADCS_ESC1": 1,
            "ADCS_ESC4": 2,
            "ADCS_ESC8": 3,
            "krbtgt_hash": 4,
            "domain_admin_hash": 5,
            "acl_abuse": 6,
            "unconstrained_delegation": 7,
            "constrained_delegation": 8,
            "rbcd": 9,
            "mssql_impersonation": 10,
            "mssql_linked": 11,
            "mssql_linked_server": 11,  # Alias for mssql_linked
            "mssql_xp_cmdshell": 12,
            "gpo_abuse": 13,
            "laps_abuse": 14,
            "dcsync": 15,
            "shadow_credentials": 16,
        }

        # Task completion futures for wait_for_task
        self._task_futures: dict[str, asyncio.Future[dict[str, Any]]] = {}

        # Track task IDs submitted via Redis for result consumption
        self._redis_task_ids: set[str] = set()
        self._result_consumer_task: asyncio.Task | None = None

    async def start(self, operation_id: str) -> None:
        """
        Start the dispatcher for an operation.

        Args:
            operation_id: Unique identifier for this operation.
        """
        self._shared_state = SharedRedTeamState(operation_id=operation_id)
        self._running = True

        # Connect to Redis if URL provided
        if self._redis_url:
            try:
                self._redis_client = await create_redis_client(self._redis_url)
                await self._redis_client.ping()
                logger.info(f"Connected to Redis at {self._redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}, using in-memory state")

        # Connect task queue for cross-pod communication
        if self._task_queue:
            try:
                await self._task_queue.connect()
                logger.info("Task queue connected for cross-pod messaging")
            except Exception as e:
                logger.warning(f"Failed to connect task queue: {e}")

        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())

        # Start result consumer for Redis-based task completion
        if self._task_queue:
            self._result_consumer_task = asyncio.create_task(self._result_consumer())
            logger.info("Result consumer started for Redis task completion")

        logger.info(f"Dispatcher started for operation {operation_id}")

    async def stop(self) -> None:
        """Stop the dispatcher and cleanup resources."""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._result_consumer_task:
            self._result_consumer_task.cancel()
            try:
                await self._result_consumer_task
            except asyncio.CancelledError:
                pass

        # Disconnect task queue
        if self._task_queue:
            try:
                await self._task_queue.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting task queue: {e}")

        if self._redis_client:
            await self._redis_client.close()

        logger.info("Dispatcher stopped")

    @property
    def shared_state(self) -> SharedRedTeamState:
        """Get the shared state object."""
        if self._shared_state is None:
            raise RuntimeError("Dispatcher not started. Call start() first.")
        return self._shared_state

    # Agent Registration

    async def register(self, agent: AgentInfo) -> None:
        """
        Register an agent with the dispatcher.

        Args:
            agent: Agent metadata including name, role, and capabilities.
        """
        self._agents[agent.name] = agent
        self._message_queues[agent.name] = Queue()
        self._role_queues[agent.role] = agent.name
        self.shared_state.registered_agents[agent.name] = agent

        # Subscribe agent to relevant message types based on role
        await self._setup_role_subscriptions(agent)

        # Broadcast registration
        await self._broadcast(
            AgentRegistered(
                source_agent="dispatcher",
                agent_name=agent.name,
                agent_role=agent.role.value,
                pod_name=agent.pod_name,
                capabilities=list(agent.capabilities),
            )
        )

        logger.info(f"Registered agent: {agent.name} (role: {agent.role.value})")

    async def unregister(self, agent_name: str) -> None:
        """Unregister an agent from the dispatcher."""
        if agent_name in self._agents:
            agent = self._agents.pop(agent_name)
            del self._message_queues[agent_name]
            if agent.role in self._role_queues:
                del self._role_queues[agent.role]
            if agent_name in self.shared_state.registered_agents:
                del self.shared_state.registered_agents[agent_name]

            # Remove from subscriptions
            for subscribers in self._subscribers.values():
                subscribers.discard(agent_name)

            logger.info(f"Unregistered agent: {agent_name}")

    def get_agent(self, agent_name: str) -> AgentInfo | None:
        """Get agent info by name."""
        return self._agents.get(agent_name)

    def get_agent_for_role(self, role: AgentRole) -> AgentInfo | None:
        """Get the agent assigned to a specific role."""
        agent_name = self._role_queues.get(role)
        if agent_name:
            return self._agents.get(agent_name)
        return None

    async def _setup_role_subscriptions(self, agent: AgentInfo) -> None:
        """Setup message subscriptions based on agent role."""
        # All agents subscribe to these
        common_subscriptions = {
            MessageType.CREDENTIAL_DISCOVERED,
            MessageType.DOMAIN_ADMIN_ACHIEVED,
            MessageType.OPERATION_COMPLETE,
        }

        # Role-specific subscriptions
        role_subscriptions = {
            AgentRole.ORCHESTRATOR: {
                # Orchestrator receives all task status updates and discoveries
                MessageType.TASK_COMPLETE,
                MessageType.TASK_FAILED,
                MessageType.TASK_PROGRESS,
                MessageType.VULNERABILITY_FOUND,
                MessageType.HASH_DISCOVERED,
                MessageType.HOST_DISCOVERED,
                MessageType.USER_DISCOVERED,
                MessageType.SHARE_DISCOVERED,
                MessageType.GOLDEN_TICKET_FORGED,
            },
            AgentRole.RECON: {
                MessageType.RECON_REQUEST,
                MessageType.TASK_COMPLETE,
                MessageType.TASK_FAILED,
            },
            AgentRole.CRACKER: {
                MessageType.CRACK_REQUEST,
                MessageType.HASH_DISCOVERED,
            },
            AgentRole.ACL: {
                MessageType.ACL_ANALYSIS_REQUEST,
                MessageType.VULNERABILITY_FOUND,
            },
            AgentRole.CREDENTIAL_ACCESS: {
                MessageType.CREDENTIAL_ACCESS_REQUEST,
            },
            AgentRole.PRIVESC: {
                MessageType.EXPLOIT_REQUEST,
                MessageType.VULNERABILITY_FOUND,
            },
            AgentRole.LATERAL: {
                MessageType.LATERAL_REQUEST,
                MessageType.HOST_DISCOVERED,
            },
            AgentRole.COERCION: {
                MessageType.COERCION_REQUEST,
            },
        }

        subscriptions = common_subscriptions | role_subscriptions.get(agent.role, set())

        for msg_type in subscriptions:
            if msg_type not in self._subscribers:
                self._subscribers[msg_type] = set()
            self._subscribers[msg_type].add(agent.name)

    # Message Queue Operations

    async def get_messages(self, agent_name: str, timeout: float = 0.1) -> list[AgentMessage]:
        """
        Get pending messages for an agent.

        Args:
            agent_name: Name of the agent to get messages for.
            timeout: How long to wait for messages (seconds).

        Returns:
            List of pending messages.
        """
        if agent_name not in self._message_queues:
            return []

        messages = []
        queue = self._message_queues[agent_name]

        try:
            # Get all available messages without blocking
            while not queue.empty():
                msg = queue.get_nowait()
                messages.append(msg)
        except asyncio.QueueEmpty:
            pass

        return messages

    async def send_to_agent(self, agent_name: str, message: AgentMessage) -> bool:
        """
        Send a message to a specific agent.

        Args:
            agent_name: Target agent name.
            message: Message to send.

        Returns:
            True if message was queued successfully.
        """
        if agent_name not in self._message_queues:
            logger.warning(f"Cannot send to unknown agent: {agent_name}")
            return False

        await self._message_queues[agent_name].put(message)
        return True

    async def _broadcast(self, message: AgentMessage, exclude: str | None = None) -> None:
        """
        Broadcast a message to all subscribed agents.

        Args:
            message: Message to broadcast.
            exclude: Agent name to exclude from broadcast.
        """
        subscribers = self._subscribers.get(message.type, set())

        for agent_name in subscribers:
            if agent_name != exclude:
                await self._message_queues[agent_name].put(message)

    # Discovery Publishing

    async def publish_credential(
        self,
        credential: Credential,
        source_agent: str,
        is_admin: bool = False,
    ) -> bool:
        """
        Broadcast new credential to all agents.

        Args:
            credential: The discovered credential.
            source_agent: Agent that discovered it.
            is_admin: Whether this is an admin credential.

        Returns:
            True if credential was new and added.
        """
        self._add_user(credential.username, credential.domain)
        added = self.shared_state.add_credential(credential, source_agent)

        if added:
            self.signal_credential_access()
            await self._broadcast(
                CredentialDiscovered(
                    source_agent=source_agent,
                    username=credential.username,
                    password=credential.password,
                    domain=credential.domain,
                    is_admin=is_admin,
                    discovery_method=credential.source,
                ),
                exclude=source_agent,
            )
            await self._checkpoint()
            logger.info(f"Credential published: {credential.domain}\\{credential.username}")
        else:
            logger.debug(
                f"Credential not published (duplicate/invalid): {credential.domain}\\{credential.username}"
            )

        return added

    async def publish_hash(
        self,
        hash_obj: Hash,
        source_agent: str,
        priority: int = 5,
    ) -> bool:
        """
        Broadcast new hash to all agents.

        Args:
            hash_obj: The discovered hash.
            source_agent: Agent that discovered it.
            priority: Priority for cracking (1=krbtgt, 2=admin, 5=normal).

        Returns:
            True if hash was new and added.
        """
        added = self.shared_state.add_hash(hash_obj, source_agent)

        if added:
            self.signal_credential_access()
            await self._broadcast(
                HashDiscovered(
                    source_agent=source_agent,
                    username=hash_obj.username,
                    hash_value=hash_obj.hash_value,
                    hash_type=hash_obj.hash_type,
                    domain=hash_obj.domain,
                    priority=priority,
                ),
                exclude=source_agent,
            )
            await self._checkpoint()
            logger.info(
                f"Hash published: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )
        else:
            logger.debug(
                f"Hash not published (duplicate): {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type})"
            )

        return added

    async def publish_share(self, share: Share, source_agent: str) -> bool:
        """
        Record share discovery in shared state.

        Args:
            share: The discovered share.
            source_agent: Agent that discovered it.

        Returns:
            True if share was new and added.
        """
        added = self.shared_state.add_share(share)
        if added:
            await self._checkpoint()
            logger.info(f"Share recorded: {share.host}/{share.name}")
        else:
            logger.debug(f"Share not published (duplicate/invalid): {share.host}/{share.name}")
        return added

    def signal_credential_access(self) -> None:
        """Wake credential access loop when new credentials or hashes appear."""
        self._credential_access_event.set()

    async def wait_for_credential_access_signal(self, timeout: float) -> None:
        """Wait for new credential activity or a timeout."""
        if self._credential_access_event.is_set():
            self._credential_access_event.clear()
            return
        try:
            await asyncio.wait_for(self._credential_access_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return
        finally:
            self._credential_access_event.clear()

    async def publish_host(self, host: Host, source_agent: str) -> bool:
        """
        Broadcast new host to all agents.

        Args:
            host: The discovered host.
            source_agent: Agent that discovered it.

        Returns:
            True if host was new and added.
        """
        added = self.shared_state.add_host(host)

        if added:
            await self._broadcast(
                HostDiscovered(
                    source_agent=source_agent,
                    ip=host.ip,
                    hostname=host.hostname,
                    os=host.os,
                    roles=list(host.roles) if hasattr(host.roles, "__iter__") else [],
                    services=list(host.services) if hasattr(host.services, "__iter__") else [],
                ),
                exclude=source_agent,
            )
            await self._checkpoint()
            logger.info(f"Host published: {host.ip} ({host.hostname})")

            # Auto-detect MSSQL and queue vulnerability for exploitation
            await self._auto_detect_mssql(host, source_agent)
        else:
            logger.debug(f"Host not published (duplicate/merged): {host.ip} ({host.hostname})")

        return added

    async def _auto_detect_mssql(self, host: Host, source_agent: str) -> None:
        """
        Auto-detect MSSQL service on host and queue vulnerability for exploitation.

        Checks for MSSQL indicators in services list and automatically queues
        an mssql_linked_server vulnerability for the privesc agent to exploit.
        """
        services_lower = [s.lower() for s in host.services]

        # Check for MSSQL indicators
        has_mssql = any(
            indicator in svc
            for svc in services_lower
            for indicator in ("mssql", "1433", "ms-sql", "sqlserver")
        )

        if not has_mssql:
            return

        # Check if we already have an MSSQL vuln queued for this host
        existing_vulns = self.shared_state.discovered_vulnerabilities.values()
        for vuln in existing_vulns:
            if vuln.target == host.ip and vuln.vuln_type.startswith("mssql_"):
                logger.debug(f"MSSQL vulnerability already queued for {host.ip}")
                return

        # Find any SQL-related credentials we have
        sql_creds = self._find_sql_credentials()

        # Queue MSSQL vulnerability for exploitation
        details: dict[str, Any] = {
            "hostname": host.hostname,
            "services": host.services,
            "note": "Auto-detected MSSQL service. Check for linked servers and impersonation.",
        }

        if sql_creds:
            details["available_credentials"] = sql_creds
            details["note"] += f" Found {len(sql_creds)} potential SQL credential(s)."

        await self.queue_vulnerability(
            vuln_type="mssql_linked_server",
            target=host.ip,
            details=details,
            discovered_by=source_agent,
        )
        logger.warning(
            f"Auto-queued MSSQL vulnerability for {host.ip} ({host.hostname}) - "
            f"found {len(sql_creds)} potential SQL creds"
        )

    def _find_sql_credentials(self) -> list[dict[str, str]]:
        """
        Find credentials that might work for MSSQL authentication.

        Returns credentials for:
        - Users with 'sql' in username (e.g., sql_svc)
        - Domain users (can auth to SQL via Windows auth)
        """
        sql_creds: list[dict[str, str]] = []
        seen: set[str] = set()

        for cred in self.shared_state.all_credentials:
            key = f"{cred.domain}\\{cred.username}"
            if key in seen:
                continue
            seen.add(key)

            # Prioritize SQL service accounts
            is_sql_account = "sql" in cred.username.lower()

            sql_creds.append(
                {
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                    "is_sql_account": str(is_sql_account),
                }
            )

        # Sort to prioritize SQL accounts
        sql_creds.sort(key=lambda x: x.get("is_sql_account", "False") != "True")
        return sql_creds[:5]  # Return top 5 candidates

    async def scan_hosts_for_mssql(self) -> int:
        """
        Scan all known hosts for MSSQL services and queue vulnerabilities.

        This method should be called periodically by the orchestrator to catch
        MSSQL hosts discovered by worker agents that didn't go through publish_host.

        Returns:
            Number of new MSSQL vulnerabilities queued.
        """
        queued = 0
        for host in self.shared_state.all_hosts:
            services_lower = [s.lower() for s in host.services]

            # Check for MSSQL indicators
            has_mssql = any(
                indicator in svc
                for svc in services_lower
                for indicator in ("mssql", "1433", "ms-sql", "sqlserver")
            )

            if not has_mssql:
                continue

            # Check if we already have an MSSQL vuln queued for this host
            already_queued = any(
                vuln.target == host.ip and vuln.vuln_type.startswith("mssql_")
                for vuln in self.shared_state.discovered_vulnerabilities.values()
            )

            if already_queued:
                continue

            # Find SQL credentials
            sql_creds = self._find_sql_credentials()

            # Queue MSSQL vulnerability
            details: dict[str, Any] = {
                "hostname": host.hostname,
                "services": host.services,
                "note": "Auto-detected MSSQL service. Check for linked servers and impersonation.",
            }

            if sql_creds:
                details["available_credentials"] = sql_creds
                details["note"] += f" Found {len(sql_creds)} potential SQL credential(s)."

            await self.queue_vulnerability(
                vuln_type="mssql_linked_server",
                target=host.ip,
                details=details,
                discovered_by="mssql_scanner",
            )
            queued += 1
            logger.warning(
                f"Periodic scan: queued MSSQL vulnerability for {host.ip} ({host.hostname})"
            )

        return queued

    async def publish_vulnerability(
        self,
        vuln: VulnerabilityInfo,
        source_agent: str,
    ) -> bool:
        """
        Broadcast new vulnerability to all agents.

        Args:
            vuln: The discovered vulnerability.
            source_agent: Agent that discovered it.

        Returns:
            True if vulnerability was new and added.
        """
        added = self.shared_state.add_vulnerability(vuln)

        if added:
            await self._broadcast(
                VulnerabilityFound(
                    source_agent=source_agent,
                    vuln_type=vuln.vuln_type,
                    vuln_id=vuln.vuln_id,
                    target=vuln.target,
                    details=vuln.details,
                    recommended_agent=vuln.recommended_agent,
                    priority=vuln.priority,
                ),
                exclude=source_agent,
            )
            await self._checkpoint()
            logger.warning(f"Vulnerability published: {vuln.vuln_type} on {vuln.target}")

        return added

    # Task Routing

    async def request_crack(
        self,
        hash_value: str,
        hash_type: str,
        source_agent: str,
        username: str = "",
        domain: str = "",
        priority: int = 5,
        wordlist: str = "rockyou.txt",
    ) -> str:
        """
        Route hash to CrackerAgent for cracking.

        Uses Redis task queue for cross-pod communication when available,
        falls back to in-memory queue for same-process communication.

        Args:
            hash_value: The hash to crack.
            hash_type: Type (NTLM, NetNTLMv2, Kerberos, etc.).
            source_agent: Agent making the request.
            username: Associated username.
            domain: Associated domain.
            priority: 1=urgent (krbtgt), 5=normal, 10=low.
            wordlist: Wordlist to use.

        Returns:
            Task ID for tracking.
        """
        payload = {
            "hash_value": hash_value,
            "hash_type": hash_type,
            "username": username,
            "domain": domain,
            "wordlist": wordlist,
        }

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="crack",
                target_role="cracker",
                payload=payload,
                source_agent=source_agent,
                priority=priority,
            )

            # Track in shared state
            task_info = TaskInfo(
                task_id=task_id,
                task_type="crack",
                assigned_agent="cracker",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Crack task {task_id} submitted to Redis queue")
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        cracker_agent = self._role_queues.get(AgentRole.CRACKER)

        if not cracker_agent:
            logger.warning("No cracker agent registered, cannot route crack request")
            return ""

        # Create task info
        task_info = TaskInfo(
            task_id=task_id,
            task_type="crack",
            assigned_agent=cracker_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        # Send request to cracker via in-memory queue
        await self._message_queues[cracker_agent].put(
            CrackRequest(
                source_agent=source_agent,
                task_id=task_id,
                hash_value=hash_value,
                hash_type=hash_type,
                username=username,
                domain=domain,
                callback_agent=source_agent,
                wordlist=wordlist,
                priority=priority,
            )
        )

        logger.info(f"Crack request {task_id} sent to {cracker_agent}")
        return task_id

    async def request_lateral_movement(
        self,
        target_host: str,
        username: str,
        source_agent: str,
        password: str | None = None,
        hash_value: str | None = None,
        domain: str = "",
        method: str | None = None,
    ) -> str:
        """
        Route lateral movement request to LateralAgent.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            target_host: IP or hostname to move to.
            username: Username to authenticate.
            source_agent: Agent making the request.
            password: Password (if available).
            hash_value: NTLM hash (if available).
            domain: Domain for authentication.
            method: Specific method (psexec, winrm, wmi) or None for auto.

        Returns:
            Task ID for tracking.
        """
        if not target_host or not target_host.strip():
            logger.warning(
                "Skipping lateral movement for %s\\%s: empty target_host",
                domain,
                username,
            )
            return ""

        resolved_password = password
        resolved_hash = hash_value
        resolved_domain = domain

        if not resolved_password and not resolved_hash:
            username_key = username.strip().lower()
            domain_key = domain.strip().lower() if domain else ""

            matching_creds = [
                cred
                for cred in self.shared_state.all_credentials
                if cred.username.strip().lower() == username_key
                and (not domain_key or cred.domain.strip().lower() == domain_key)
            ]

            if matching_creds:
                cred = matching_creds[0]
                resolved_password = cred.password
                if not resolved_domain:
                    resolved_domain = cred.domain
                logger.debug(
                    "Filled lateral auth from credential store for %s\\%s",
                    resolved_domain or domain,
                    username,
                )

            if not resolved_password:
                matching_hashes = [
                    h
                    for h in self.shared_state.all_hashes
                    if h.username.strip().lower() == username_key
                    and (not domain_key or h.domain.strip().lower() == domain_key)
                ]
                if matching_hashes:
                    h = matching_hashes[0]
                    resolved_hash = h.hash_value
                    if h.cracked_password:
                        resolved_password = h.cracked_password
                    if not resolved_domain:
                        resolved_domain = h.domain
                    logger.debug(
                        "Filled lateral auth from hash store for %s\\%s",
                        resolved_domain or domain,
                        username,
                    )

        payload = {
            "target_host": target_host,
            "username": username,
            "password": resolved_password,
            "hash_value": resolved_hash,
            "domain": resolved_domain,
            "method": method,
        }

        if not resolved_password and not resolved_hash:
            logger.warning(
                "Skipping lateral movement for %s\\%s -> %s: missing credentials",
                resolved_domain or domain,
                username,
                target_host,
            )
            return ""

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="lateral",
                target_role="lateral",
                payload=payload,
                source_agent=source_agent,
            )

            task_info = TaskInfo(
                task_id=task_id,
                task_type="lateral_movement",
                assigned_agent="lateral",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Lateral movement task {task_id} submitted to Redis queue")
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        lateral_agent = self._role_queues.get(AgentRole.LATERAL)

        if not lateral_agent:
            logger.warning("No lateral agent registered, cannot route lateral request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="lateral_movement",
            assigned_agent=lateral_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[lateral_agent].put(
            LateralMovementRequest(
                source_agent=source_agent,
                task_id=task_id,
                target_host=target_host,
                username=username,
                password=password,
                hash_value=hash_value,
                domain=domain,
                method=method,
                callback_agent=source_agent,
            )
        )

        logger.info(f"Lateral movement request {task_id} sent to {lateral_agent}")
        return task_id

    def _find_domain_credential(self, domain: str) -> Credential | None:
        """Find a credential for the specified domain."""
        domain_lower = domain.lower() if domain else ""
        credential = None
        for cred in self.shared_state.all_credentials:
            cred_domain = cred.domain.lower() if cred.domain else ""
            if cred_domain == domain_lower or domain_lower in cred_domain:
                if cred.password:  # Prefer credentials with passwords
                    return cred
                if not credential:
                    credential = cred
        return credential

    def _find_domain_controller_ip(self, domain: str) -> str:
        """Find DC IP for the specified domain."""
        domain_lower = domain.lower() if domain else ""
        dc_service_tokens = ("88/tcp", "389/tcp", "53/tcp", "kerberos", "ldap")

        def _has_dc_services(host: Host) -> bool:
            services = " ".join(host.services).lower()
            return any(token in services for token in dc_service_tokens)

        # Check target first
        if self.shared_state.target and self.shared_state.target.ip:
            target_ip = self.shared_state.target.ip
            target_hostname = (self.shared_state.target.hostname or "").lower()
            if target_hostname and target_hostname.endswith(domain_lower):
                return target_ip
            for host in self.shared_state.all_hosts:
                if host.ip == target_ip:
                    hostname = (host.hostname or "").lower()
                    if hostname.endswith(domain_lower) and _has_dc_services(host):
                        return host.ip
        # Search all hosts by explicit DC markers
        for host in self.shared_state.all_hosts:
            if (
                "dc" in (host.hostname or "").lower()
                or "domain controller" in str(host.roles).lower()
            ):
                return host.ip
        # Fallback: infer DC from services on hosts within the domain
        if domain_lower:
            for host in self.shared_state.all_hosts:
                hostname = (host.hostname or "").lower()
                if hostname.endswith(domain_lower) and _has_dc_services(host):
                    return host.ip
        # Last resort: any host advertising DC-like services
        for host in self.shared_state.all_hosts:
            if _has_dc_services(host):
                return host.ip
        return ""

    async def request_acl_analysis(
        self,
        target_user: str,
        domain: str,
        source_agent: str,
        find_path_to: str = "Domain Admins",
    ) -> str:
        """
        Request ACLAgent to analyze attack paths for target.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            target_user: User to find paths to.
            domain: Target domain.
            source_agent: Agent making the request.
            find_path_to: Target group/user for path finding.

        Returns:
            Task ID for tracking.
        """
        # Find credential and DC for this domain
        credential = self._find_domain_credential(domain)
        dc_ip = self._find_domain_controller_ip(domain)

        payload = {
            "target_user": target_user,
            "domain": domain,
            "find_path_to": find_path_to,
            "dc_ip": dc_ip,
        }
        if credential:
            payload["username"] = credential.username
            payload["password"] = credential.password or ""
            if not credential.password:
                # Check for hash
                for h in self.shared_state.all_hashes:
                    if h.username == credential.username:
                        payload["hash"] = h.hash_value
                        break

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="acl_analysis",
                target_role="acl",
                payload=payload,
                source_agent=source_agent,
            )

            task_info = TaskInfo(
                task_id=task_id,
                task_type="acl_analysis",
                assigned_agent="acl",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"ACL analysis task {task_id} submitted to Redis queue")
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        acl_agent = self._role_queues.get(AgentRole.ACL)

        if not acl_agent:
            logger.warning("No ACL agent registered, cannot route ACL request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="acl_analysis",
            assigned_agent=acl_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[acl_agent].put(
            ACLAnalysisRequest(
                source_agent=source_agent,
                task_id=task_id,
                target_user=target_user,
                domain=domain,
                find_path_to=find_path_to,
                callback_agent=source_agent,
            )
        )

        logger.info(f"ACL analysis request {task_id} sent to {acl_agent}")
        return task_id

    async def request_recon(
        self,
        source_agent: str,
        domain: str,
        target_ips: list[str] | None = None,
        username: str = "",
        password: str | None = None,
        hash_value: str | None = None,
        reason: str | None = None,
        techniques: list[str] | None = None,
    ) -> str:
        """
        Request reconnaissance actions (nmap, user enumeration, BloodHound).

        Uses Redis task queue for cross-pod communication when available.

        Args:
            source_agent: Agent making the request.
            domain: Target domain.
            target_ips: Target IPs for scanning/enumeration.
            username: Optional username for authenticated enumeration.
            password: Optional password for authenticated enumeration.
            hash_value: Optional NTLM hash for pass-the-hash.
            reason: Reason for the recon request (e.g., "network_scan", "bloodhound").
            techniques: Optional list of techniques to prioritize.

        Returns:
            Task ID for tracking.
        """
        dc_ip = self._find_domain_controller_ip(domain)
        payload = {
            "domain": domain,
            "target_ips": target_ips or [],
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "reason": reason,
            "techniques": techniques or [],
        }

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="recon",
                target_role="recon",
                payload=payload,
                source_agent=source_agent,
            )

            task_info = TaskInfo(
                task_id=task_id,
                task_type="recon",
                assigned_agent="recon",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            cred_label = username or "unauthenticated"
            if hash_value and not password:
                cred_label = f"{cred_label} (hash)"
            if password:
                cred_label = f"{cred_label} (password)"
            reason_label = f" reason={reason}" if reason else ""
            logger.info(
                "Recon task {} submitted to Redis queue for {}{}",
                task_id,
                cred_label,
                reason_label,
            )
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        recon_agent = self._role_queues.get(AgentRole.RECON)

        if not recon_agent:
            logger.warning("No recon agent registered, cannot route request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="recon",
            assigned_agent=recon_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[recon_agent].put(
            ReconRequest(
                source_agent=source_agent,
                task_id=task_id,
                domain=domain,
                target_ips=payload["target_ips"],
                dc_ip=dc_ip,
                username=username,
                password=password,
                hash_value=hash_value,
                reason=reason,
                techniques=payload["techniques"],
                callback_agent=source_agent,
            )
        )

        logger.info(f"Recon request {task_id} sent to {recon_agent}")
        return task_id

    async def request_credential_access(
        self,
        source_agent: str,
        domain: str,
        target_ips: list[str] | None = None,
        username: str = "",
        password: str | None = None,
        hash_value: str | None = None,
        hash_type: str | None = None,
        credential_source: str | None = None,
        reason: str | None = None,
        techniques: list[str] | None = None,
    ) -> str:
        """
        Request credential access actions (AS-REP roast, Kerberoast, secretsdump, LSASS).

        Uses Redis task queue for cross-pod communication when available.

        Args:
            source_agent: Agent making the request.
            domain: Target domain.
            target_ips: Target IPs for credential access actions.
            username: Optional username for authenticated actions.
            password: Optional password for authenticated actions.
            hash_value: Optional NTLM hash for pass-the-hash actions.
            techniques: Optional list of techniques to prioritize.

        Returns:
            Task ID for tracking.
        """
        dc_ip = self._find_domain_controller_ip(domain)
        payload = {
            "domain": domain,
            "target_ips": target_ips or [],
            "dc_ip": dc_ip,
            "username": username,
            "password": password,
            "hash_value": hash_value,
            "hash_type": hash_type,
            "credential_source": credential_source,
            "reason": reason,
            "techniques": techniques or [],
        }

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="credential_access",
                target_role="credential_access",
                payload=payload,
                source_agent=source_agent,
            )

            task_info = TaskInfo(
                task_id=task_id,
                task_type="credential_access",
                assigned_agent="credential_access",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            cred_label = username or "no-cred"
            if hash_value and not password:
                cred_label = f"{cred_label} (hash)"
            if password:
                cred_label = f"{cred_label} (password)"
            reason_label = f" reason={reason}" if reason else ""
            source_label = f" source={credential_source}" if credential_source else ""
            hash_label = f" hash_type={hash_type}" if hash_type else ""
            logger.info(
                "Credential access task {} submitted to Redis queue for {}{}{}{}",
                task_id,
                cred_label,
                reason_label,
                source_label,
                hash_label,
            )
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        credential_agent = self._role_queues.get(AgentRole.CREDENTIAL_ACCESS)

        if not credential_agent:
            logger.warning("No credential access agent registered, cannot route request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="credential_access",
            assigned_agent=credential_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[credential_agent].put(
            CredentialAccessRequest(
                source_agent=source_agent,
                task_id=task_id,
                domain=domain,
                target_ips=payload["target_ips"],
                dc_ip=dc_ip,
                username=username,
                password=password,
                hash_value=hash_value,
                techniques=payload["techniques"],
                callback_agent=source_agent,
            )
        )

        logger.info(f"Credential access request {task_id} sent to {credential_agent}")
        return task_id

    async def request_exploit(
        self,
        vuln_type: str,
        vuln_id: str,
        target: str,
        source_agent: str,
        params: dict[str, Any] | None = None,
    ) -> str:
        """
        Request PrivEscAgent to exploit vulnerability.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            vuln_type: ADCS_ESC1, DELEGATION_UNCONSTRAINED, etc.
            vuln_id: Vulnerability ID.
            target: Target to exploit.
            source_agent: Agent making the request.
            params: Vulnerability-specific parameters.

        Returns:
            Task ID for tracking.
        """
        payload = {
            "vuln_type": vuln_type,
            "vuln_id": vuln_id,
            "target": target,
            **(params or {}),
        }

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="exploit",
                target_role="privesc",
                payload=payload,
                source_agent=source_agent,
            )

            task_info = TaskInfo(
                task_id=task_id,
                task_type="exploit",
                assigned_agent="privesc",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Exploit task {task_id} for {vuln_type} submitted to Redis queue")
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        privesc_agent = self._role_queues.get(AgentRole.PRIVESC)

        if not privesc_agent:
            logger.warning("No privesc agent registered, cannot route exploit request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="exploit",
            assigned_agent=privesc_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[privesc_agent].put(
            ExploitRequest(
                source_agent=source_agent,
                task_id=task_id,
                vuln_type=vuln_type,
                vuln_id=vuln_id,
                target=target,
                params=params or {},
                callback_agent=source_agent,
            )
        )

        logger.info(f"Exploit request {task_id} for {vuln_type} sent to {privesc_agent}")
        return task_id

    async def request_coercion(
        self,
        source_agent: str,
        interface: str = "eth0",
        techniques: list[str] | None = None,
        duration: int = 300,
    ) -> str:
        """
        Request the coercion agent to start network coercion.

        Uses Redis task queue for cross-pod communication when available.

        Args:
            source_agent: Agent making the request.
            interface: Network interface.
            techniques: Coercion techniques to use.
            duration: How long to run (seconds).

        Returns:
            Task ID for tracking.
        """
        techniques = techniques or ["LLMNR", "NBT-NS", "mDNS"]

        payload = {
            "interface": interface,
            "techniques": techniques,
            "duration": duration,
        }

        # Use Redis task queue if available (Kubernetes multi-pod mode)
        if self._task_queue:
            task_id = await self._task_queue.submit_task(
                task_type="coercion",
                target_role="coercion",
                payload=payload,
                source_agent=source_agent,
            )

            task_info = TaskInfo(
                task_id=task_id,
                task_type="coercion",
                assigned_agent="coercion",
                params=payload,
            )
            self.shared_state.pending_tasks[task_id] = task_info
            self._redis_task_ids.add(task_id)

            logger.info(f"Coercion task {task_id} submitted to Redis queue")
            return task_id

        # Fallback to in-memory queue (single-process mode)
        task_id = generate_task_id()
        coercion_agent = self._role_queues.get(AgentRole.COERCION)

        if not coercion_agent:
            logger.warning("No coercion agent registered, cannot route coercion request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="coercion",
            assigned_agent=coercion_agent,
            params=payload,
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[coercion_agent].put(
            CoercionRequest(
                source_agent=source_agent,
                task_id=task_id,
                interface=interface,
                techniques=techniques,
                duration=duration,
                callback_agent=source_agent,
            )
        )

        logger.info(f"Coercion request {task_id} sent to {coercion_agent}")
        return task_id

    # Task Completion

    async def complete_task(  # noqa: PLR0912
        self,
        task_id: str,
        success: bool,
        result: Any = None,
        error: str | None = None,
        source_agent: str = "",
    ) -> None:
        """
        Mark a task as complete.

        Args:
            task_id: The task ID.
            success: Whether the task succeeded.
            result: Task result (if successful).
            error: Error message (if failed).
            source_agent: Agent completing the task.
        """
        if task_id not in self.shared_state.pending_tasks:
            logger.warning(f"Unknown task: {task_id}")
            return

        task_info = self.shared_state.pending_tasks.pop(task_id)
        was_retry = task_info.status == TaskStatus.RETRYING

        task_info.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        task_info.completed_at = datetime.now(timezone.utc)
        task_info.result = result
        task_info.error = error

        if was_retry:
            logger.info(
                f"Retried task {task_id} completed after {task_info.retry_count} retries: "
                f"success={success}"
            )

        task_result = TaskResult(
            task_id=task_id,
            success=success,
            result=result,
            error=error,
        )
        self.shared_state.completed_tasks[task_id] = task_result

        output = ""

        # Process discoveries from result dict (even if task failed)
        # Workers serialize discoveries and send them regardless of success/failure
        if isinstance(result, dict):
            # Process serialized state discoveries from worker's local state first
            # These should be processed even on failure since workers preserve discoveries
            discovered_hosts = result.get("discovered_hosts")
            if isinstance(discovered_hosts, list) and discovered_hosts:
                logger.info(
                    f"Processing {len(discovered_hosts)} discovered hosts from {source_agent}"
                )
                for h in discovered_hosts:
                    if not isinstance(h, dict):
                        continue
                    host = Host(
                        ip=h.get("ip", ""),
                        hostname=h.get("hostname", ""),
                        os=h.get("os", ""),
                        roles=h.get("roles", []),
                        services=h.get("services", []),
                    )
                    await self.publish_host(host, source_agent)

            discovered_credentials = result.get("discovered_credentials")
            if isinstance(discovered_credentials, list) and discovered_credentials:
                logger.info(
                    f"Processing {len(discovered_credentials)} discovered credentials from {source_agent}"
                )
                for c in discovered_credentials:
                    if not isinstance(c, dict):
                        continue
                    credential = Credential(
                        username=c.get("username", ""),
                        password=c.get("password", ""),
                        domain=c.get("domain", ""),
                        source=c.get("source", f"worker:{source_agent}"),
                        is_admin=c.get("is_admin", False),
                    )
                    await self.publish_credential(credential, source_agent)

            discovered_hashes = result.get("discovered_hashes")
            if isinstance(discovered_hashes, list) and discovered_hashes:
                logger.info(
                    f"Processing {len(discovered_hashes)} discovered hashes from {source_agent}"
                )
                for h in discovered_hashes:
                    if not isinstance(h, dict):
                        continue
                    hash_obj = Hash(
                        username=h.get("username", ""),
                        hash_value=h.get("hash_value", ""),
                        hash_type=h.get("hash_type", "NTLM"),
                        domain=h.get("domain", ""),
                        cracked_password=h.get("cracked_password", ""),
                        source=h.get("source", ""),
                    )
                    await self.publish_hash(hash_obj, source_agent)
                    if hash_obj.cracked_password:
                        cracked_cred = Credential(
                            username=hash_obj.username,
                            password=hash_obj.cracked_password,
                            domain=hash_obj.domain,
                            source=f"cracked:{source_agent}",
                            is_admin=False,
                        )
                        await self.publish_credential(cracked_cred, source_agent)

            discovered_shares = result.get("discovered_shares")
            if isinstance(discovered_shares, list):
                for s in discovered_shares:
                    if not isinstance(s, dict):
                        continue
                    share = Share(
                        host=s.get("host", ""),
                        name=s.get("name", ""),
                        permissions=s.get("permissions", ""),
                        comment=s.get("comment", ""),
                    )
                    await self.publish_share(share, source_agent)

            discovered_users = result.get("discovered_users")
            if isinstance(discovered_users, list):
                for u in discovered_users:
                    if not isinstance(u, dict):
                        continue
                    self._add_user(u.get("username", ""), u.get("domain", ""))

        # Process additional result fields only on success
        if success and isinstance(result, dict):
            cred_data = result.get("credential")
            if isinstance(cred_data, dict):
                self._add_user(cred_data.get("username", ""), cred_data.get("domain", ""))
                credential = Credential(
                    username=cred_data.get("username", ""),
                    password=cred_data.get("password", ""),
                    domain=cred_data.get("domain", ""),
                    source=cred_data.get("source", f"task:{task_id}"),
                    is_admin=cred_data.get("is_admin", False),
                )
                await self.publish_credential(credential, source_agent)
            creds_data = result.get("credentials")
            if isinstance(creds_data, list):
                for cred in creds_data:
                    if not isinstance(cred, dict):
                        continue
                    self._add_user(cred.get("username", ""), cred.get("domain", ""))
                    credential = Credential(
                        username=cred.get("username", ""),
                        password=cred.get("password", ""),
                        domain=cred.get("domain", ""),
                        source=cred.get("source", f"task:{task_id}"),
                        is_admin=cred.get("is_admin", False),
                    )
                    await self.publish_credential(credential, source_agent)

            hash_data = result.get("hash")
            if isinstance(hash_data, dict):
                hash_obj = Hash(
                    username=hash_data.get("username", ""),
                    hash_value=hash_data.get("hash_value", ""),
                    hash_type=hash_data.get("hash_type", "NTLM"),
                    domain=hash_data.get("domain", ""),
                    cracked_password=hash_data.get("cracked_password", ""),
                )
                await self.publish_hash(hash_obj, source_agent)
                if hash_obj.cracked_password:
                    cracked_cred = Credential(
                        username=hash_obj.username,
                        password=hash_obj.cracked_password,
                        domain=hash_obj.domain,
                        source=f"hash:{task_id}",
                        is_admin=False,
                    )
                    await self.publish_credential(cracked_cred, source_agent)
            hashes_data = result.get("hashes")
            if isinstance(hashes_data, list):
                for h in hashes_data:
                    if not isinstance(h, dict):
                        continue
                    hash_obj = Hash(
                        username=h.get("username", ""),
                        hash_value=h.get("hash_value", ""),
                        hash_type=h.get("hash_type", "NTLM"),
                        domain=h.get("domain", ""),
                        cracked_password=h.get("cracked_password", ""),
                    )
                    await self.publish_hash(hash_obj, source_agent)
                    if hash_obj.cracked_password:
                        cracked_cred = Credential(
                            username=hash_obj.username,
                            password=hash_obj.cracked_password,
                            domain=hash_obj.domain,
                            source=f"hash:{task_id}",
                            is_admin=False,
                        )
                        await self.publish_credential(cracked_cred, source_agent)

            share_data = result.get("share")
            if isinstance(share_data, dict):
                share = Share(
                    host=share_data.get("host", share_data.get("host_ip", "")),
                    name=share_data.get("name", share_data.get("share_name", "")),
                    permissions=share_data.get("permissions", ""),
                    comment=share_data.get("comment", share_data.get("description", "")),
                )
                await self.publish_share(share, source_agent)
            shares_data = result.get("shares")
            if isinstance(shares_data, list):
                for s in shares_data:
                    if not isinstance(s, dict):
                        continue
                    share = Share(
                        host=s.get("host", s.get("host_ip", "")),
                        name=s.get("name", s.get("share_name", "")),
                        permissions=s.get("permissions", ""),
                        comment=s.get("comment", s.get("description", "")),
                    )
                    await self.publish_share(share, source_agent)

            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            output_field = result.get("output", "")
            output_parts = []
            for chunk in (stdout, stderr, output_field):
                if isinstance(chunk, str) and chunk.strip():
                    output_parts.append(chunk.strip())
            output = "\n".join(output_parts).strip()
        elif success and isinstance(result, str):
            output = result.strip()

        if output:
            domain = ""
            if self.shared_state.target and self.shared_state.target.domain:
                domain = self.shared_state.target.domain

            for host in self._extract_hosts_from_output(output):
                if hasattr(self.shared_state, "add_host"):
                    self.shared_state.add_host(host)
                elif not any(h.ip == host.ip for h in self.shared_state.all_hosts):
                    self.shared_state.all_hosts.append(host)

            for username in self._extract_users_from_output(output):
                self._add_user(username, domain)

            creds = self._extract_plaintext_passwords_from_output(output)
            if "password :" in output.lower() and not creds and domain:
                self.shared_state.pending_credential_findings.add(f"{domain}:unknown")
            for username, password in creds:
                if domain:
                    self.shared_state.pending_credential_findings.add(
                        f"{domain}:{username}".lower()
                    )
                self._add_user(username, domain)
                credential = Credential(
                    username=username,
                    password=password,
                    domain=domain,
                    source="user_description",
                    is_admin=False,
                )
                await self.publish_credential(credential, source_agent)

            # Extract shares from netexec --shares output
            for share in self._extract_shares_from_output(output):
                await self.publish_share(share, source_agent)

            # Extract hashes (Kerberoast, AS-REP, NTLM) from tool output
            for hash_obj in self._extract_hashes_from_output(output):
                await self.publish_hash(hash_obj, source_agent)

        # Broadcast completion
        if success:
            await self._broadcast(
                TaskComplete(
                    source_agent=source_agent,
                    task_id=task_id,
                    result={"task_type": task_info.task_type, "data": result},
                )
            )
        else:
            await self._broadcast(
                TaskFailed(
                    source_agent=source_agent,
                    task_id=task_id,
                    error=error or "Unknown error",
                )
            )

        # Resolve any waiting futures
        self._resolve_task_future(task_id, success, result, error)

        await self._checkpoint()
        logger.info(f"Task {task_id} completed: success={success}")

    def _add_user(self, username: str, domain: str) -> bool:
        if not username:
            return False
        normalized = username.strip()
        if not normalized or normalized.lower() in {"(none)", "none", "null", "(null)"}:
            return False
        if "/" in normalized or "\\" in normalized or normalized.endswith(".txt"):
            return False
        for existing in self.shared_state.all_users:
            if existing.username == normalized and existing.domain == domain:
                return False
        self.shared_state.all_users.append(User(username=normalized, domain=domain))
        return True

    def _extract_hosts_from_output(self, output: str) -> list[Host]:
        if not output:
            return []
        hosts: list[Host] = []
        seen: set[str] = set()
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            smb_match = re.search(
                r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.-]+)\s+\[\*\]\s+(.+)",
                stripped,
            )
            if not smb_match:
                continue
            ip = smb_match.group(1)
            host_col = smb_match.group(2)
            details = smb_match.group(3)
            name_match = re.search(r"\(name:([^)]+)\)", details)
            domain_match = re.search(r"\(domain:([^)]+)\)", details)
            domain = domain_match.group(1) if domain_match else ""
            hostname = name_match.group(1) if name_match else host_col
            if domain and hostname and not hostname.lower().endswith(domain.lower()):
                hostname = f"{hostname.lower()}.{domain}"
            os_match = re.search(r"^\s*([^(]+?)\s+\(name:", details)
            os_name = os_match.group(1).strip() if os_match else "Unknown"
            if ip in seen:
                continue
            seen.add(ip)
            hosts.append(
                Host(
                    ip=ip,
                    hostname=hostname,
                    os=os_name,
                    roles=[],
                    services=[],
                )
            )
        return hosts

    def _extract_users_from_output(self, output: str) -> list[str]:
        if not output:
            return []
        users: list[str] = []
        seen: set[str] = set()
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            for match in re.findall(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE):
                user = match.strip()
                if user and user not in seen:
                    users.append(user)
                    seen.add(user)
            account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_match:
                user = account_match.group(1).strip()
                if user and user not in seen:
                    users.append(user)
                    seen.add(user)
            sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
            if sam_match:
                user = sam_match.group(1).strip()
                if user and user not in seen:
                    users.append(user)
                    seen.add(user)
            smb_match = re.search(
                r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}",
                stripped,
            )
            if smb_match:
                user = smb_match.group(1).strip()
                if user and user not in seen:
                    users.append(user)
                    seen.add(user)
        return users

    def _extract_plaintext_passwords_from_output(self, output: str) -> list[tuple[str, str]]:  # noqa: PLR0912
        if not output:
            return []
        creds: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        current_user = ""
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            user_match = re.search(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE)
            if user_match:
                current_user = user_match.group(1).strip()
            account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
            if account_match:
                current_user = account_match.group(1).strip()
            sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
            if sam_match:
                current_user = sam_match.group(1).strip()
            if "password" not in stripped.lower():
                continue
            pass_match = re.search(r"Password\s*:\s*([^\s\)]+)", stripped, re.IGNORECASE)
            if not pass_match:
                continue
            password = pass_match.group(1).strip()
            username = ""
            smb_match = re.search(
                r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}.*Password\s*:\s*",
                stripped,
            )
            if smb_match:
                username = smb_match.group(1).strip()
            elif current_user:
                username = current_user
            if not username:
                continue
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue
            if "/" in password or "\\" in password or password.endswith(".txt"):
                continue
            key = (username, password)
            if key in seen:
                continue
            seen.add(key)
            creds.append(key)
        return creds

    def _extract_shares_from_output(  # noqa: PLR0912
        self, output: str, default_host: str = ""
    ) -> list[Share]:
        """Extract shares from netexec --shares output."""
        if not output:
            return []
        shares: list[Share] = []
        seen: set[tuple[str, str]] = set()
        in_table = False
        current_host = default_host

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Parse host from SMB line prefix: "SMB  192.168.1.1  445  HOSTNAME  ..."
            if stripped.startswith("SMB"):
                smb_match = re.match(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+", stripped)
                if smb_match:
                    current_host = smb_match.group(1)
                # Strip SMB prefix to get body
                body = re.sub(r"^SMB\s+\S+\s+\d+\s+\S+\s+", "", stripped).strip()
                if not body:
                    continue
                lower = body.lower()
                # Detect share table header
                if lower.startswith("share") and "permission" in lower:
                    in_table = True
                    continue
                # Skip separator lines
                if in_table and set(body) <= {"-", " "}:
                    continue
                # End of table
                if in_table and (body.startswith("[") or lower.startswith("smb")):
                    in_table = False
                    continue
                if not in_table:
                    continue
                # Parse share row
                parts = body.split(None, 2)
                if not parts:
                    continue
                name = parts[0].strip()
                if not name or name.lower() == "share":
                    continue
                permissions = parts[1].strip() if len(parts) > 1 else ""
                comment = parts[2].strip() if len(parts) > 2 else ""
                key = (current_host.lower(), name.lower())
                if key in seen:
                    continue
                seen.add(key)
                shares.append(
                    Share(
                        host=current_host,
                        name=name,
                        permissions=permissions,
                        comment=comment,
                    )
                )
        return shares

    def _extract_hashes_from_output(self, output: str) -> list[Hash]:
        """Extract Kerberos hashes (TGS, AS-REP) from tool output."""
        if not output:
            return []
        hashes: list[Hash] = []
        seen: set[str] = set()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Match Kerberoast TGS hashes: $krb5tgs$23$*username$domain$...
            tgs_match = re.search(
                r"(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+)",
                stripped,
            )
            if tgs_match:
                hash_value = tgs_match.group(1)
                username = tgs_match.group(2)
                domain = tgs_match.group(3)
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="TGS",
                            domain=domain,
                        )
                    )
                continue

            # Match AS-REP hashes: $krb5asrep$23$username@domain:...
            asrep_match = re.search(
                r"(\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+)",
                stripped,
            )
            if asrep_match:
                hash_value = asrep_match.group(1)
                username = asrep_match.group(2)
                domain = asrep_match.group(3)
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="AS-REP",
                            domain=domain,
                        )
                    )
                continue

            # Match NTLM hashes from secretsdump: domain\user:rid:lmhash:nthash:::
            ntlm_match = re.search(
                r"([^\\:\s]+)\\([^:\\]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
                stripped,
            )
            if ntlm_match:
                domain = ntlm_match.group(1)
                username = ntlm_match.group(2)
                lm_hash = ntlm_match.group(3)
                nt_hash = ntlm_match.group(4)
                # Use NT hash (more useful), include LM if not empty
                hash_value = f"{lm_hash}:{nt_hash}"
                if hash_value not in seen:
                    seen.add(hash_value)
                    hashes.append(
                        Hash(
                            username=username,
                            hash_value=hash_value,
                            hash_type="NTLM",
                            domain=domain,
                        )
                    )

        return hashes

    # Domain Admin Achievement

    async def announce_domain_admin(
        self,
        username: str,
        domain: str,
        attack_path: str,
        credential_type: str,
        source_agent: str,
    ) -> None:
        """
        Announce that domain admin has been achieved.

        This triggers all agents to halt current tasks.

        Args:
            username: The domain admin username.
            domain: The domain.
            attack_path: Description of how it was achieved.
            credential_type: Type of credential (password, hash, ticket).
            source_agent: Agent that achieved it.
        """
        self.shared_state.has_domain_admin = True
        self.shared_state.domain_admin_path = attack_path

        await self._broadcast(
            DomainAdminAchieved(
                source_agent=source_agent,
                username=username,
                domain=domain,
                attack_path=attack_path,
                credential_type=credential_type,
            )
        )

        await self._checkpoint()
        logger.success(f"DOMAIN ADMIN ACHIEVED: {domain}\\{username}")

    async def announce_golden_ticket(
        self,
        domain: str,
        krbtgt_hash: str,
        ticket_path: str,
        source_agent: str,
    ) -> None:
        """
        Announce that golden ticket has been forged.

        Args:
            domain: The domain.
            krbtgt_hash: The krbtgt hash used.
            ticket_path: Path to the ticket file.
            source_agent: Agent that forged it.
        """
        self.shared_state.has_golden_ticket = True

        await self._broadcast(
            GoldenTicketForged(
                source_agent=source_agent,
                domain=domain,
                krbtgt_hash=krbtgt_hash,
                ticket_path=ticket_path,
            )
        )

        await self._checkpoint()
        logger.success(f"GOLDEN TICKET FORGED for {domain}")

    async def announce_operation_complete(
        self,
        source_agent: str,
        success: bool,
        summary: str,
    ) -> None:
        """
        Announce that the operation is complete.

        Args:
            source_agent: Agent making the announcement.
            success: Whether the operation was successful.
            summary: Summary of the operation.
        """
        await self._broadcast(
            OperationComplete(
                source_agent=source_agent,
                operation_id=self.shared_state.operation_id,
                success=success,
                summary=summary,
                total_credentials=len(self.shared_state.all_credentials),
                total_hosts=len(self.shared_state.all_hosts),
                domain_admin_achieved=self.shared_state.has_domain_admin,
            )
        )

        await self._checkpoint()
        logger.info(f"Operation complete: {summary}")

    # Heartbeat and Health Monitoring

    async def heartbeat(
        self, agent_name: str, status: str, current_task: str | None = None
    ) -> None:
        """
        Process heartbeat from an agent.

        Args:
            agent_name: Name of the agent.
            status: Current status (idle, busy, offline).
            current_task: Current task ID if busy.
        """
        if agent_name in self._agents:
            self._agents[agent_name].status = status
            self._agents[agent_name].current_task = current_task
            self._agents[agent_name].last_heartbeat = datetime.now(timezone.utc)

    async def _heartbeat_monitor(self) -> None:
        """Background task to monitor agent heartbeats."""
        while self._running:
            now = datetime.now(timezone.utc)

            # For cross-pod workers, read heartbeats from Redis
            if self._task_queue:
                for agent_name in list(self._agents.keys()):
                    try:
                        heartbeat_data = await self._task_queue.get_heartbeat(agent_name)
                        if heartbeat_data:
                            # Update in-memory state from Redis heartbeat
                            timestamp_str = heartbeat_data.get("timestamp")
                            if timestamp_str:
                                timestamp = datetime.fromisoformat(timestamp_str)
                                self._agents[agent_name].last_heartbeat = timestamp
                                self._agents[agent_name].status = heartbeat_data.get(
                                    "status", "idle"
                                )
                                self._agents[agent_name].current_task = heartbeat_data.get(
                                    "current_task"
                                )
                    except Exception as e:  # noqa: PERF203
                        # Heartbeat failures could indicate auth issues - log at ERROR level
                        logger.error(
                            f"Failed to get heartbeat for {agent_name}: {e}. "
                            "This may indicate authentication failure or misconfiguration.",
                            exc_info=True,
                        )

            # Check for stale heartbeats
            for agent_name, agent_info in list(self._agents.items()):
                elapsed = (now - agent_info.last_heartbeat).total_seconds()
                stale_threshold = max(60, self._agent_heartbeat_timeout)
                if elapsed > stale_threshold and agent_info.status != "offline":
                    logger.warning(
                        f"Agent {agent_name} heartbeat stale ({elapsed:.0f}s) - marking offline"
                    )
                    agent_info.status = "offline"

            await asyncio.sleep(15)

    async def _result_consumer(self) -> None:
        """
        Background task to consume results from Redis for completed tasks.

        This bridges the gap between Redis-based workers (which send results via
        task_queue.send_result()) and the dispatcher's in-memory pending_tasks
        tracking. Without this, tasks complete on workers but the orchestrator
        never knows about it.
        """
        logger.info("Result consumer started")

        try:
            while self._running:
                await self._consume_pending_results()
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            logger.info("Result consumer cancelled")
        except Exception as e:
            logger.error(f"Result consumer fatal error: {e}", exc_info=True)

        logger.info("Result consumer stopped")

    async def _consume_pending_results(self) -> None:
        """Check and consume results for all pending Redis tasks."""
        if not self._task_queue:
            logger.warning("Result consumer has no task queue; skipping result checks")
            return

        task_ids_to_check = list(self._redis_task_ids)

        for task_id in task_ids_to_check:
            try:
                result = await self._task_queue.check_result(task_id)
                if result:
                    # Result found - process it
                    logger.info(
                        f"Result consumer received result for task {task_id}: "
                        f"success={result.success}"
                    )

                    # Remove from tracking set
                    self._redis_task_ids.discard(task_id)

                    # Call complete_task to update dispatcher state
                    await self.complete_task(
                        task_id=task_id,
                        success=result.success,
                        result=result.result,
                        error=result.error,
                        source_agent=result.worker_pod or "unknown",
                    )
            except Exception as e:  # noqa: PERF203
                logger.warning(f"Error checking result for task {task_id}: {e}")

    # State Persistence

    async def _checkpoint(self) -> None:
        """Save state checkpoint to Redis if available.

        IMPORTANT: This method merges with existing Redis state before writing
        to prevent race conditions where multiple workers/orchestrator overwrite
        each other's discoveries. All state is additive (credentials, hosts, etc.)
        so merging is safe and ensures no discoveries are lost.
        """
        if self._redis_client is None:
            return

        try:
            key = f"ares:operation:{self.shared_state.operation_id}:state"

            # Merge with existing state to prevent overwrites from other workers
            existing_data = await self._redis_client.get(key)
            if existing_data:
                try:
                    existing_state = SharedRedTeamState.from_bytes(existing_data)
                    _merge_state(self.shared_state, existing_state)
                except Exception as exc:
                    logger.warning(f"Failed to merge existing checkpoint state: {exc}")

            # Debug: log state counts after merge
            logger.debug(
                f"[Dispatcher checkpoint] hosts={len(self.shared_state.all_hosts)}, "
                f"creds={len(self.shared_state.all_credentials)}, hashes={len(self.shared_state.all_hashes)}"
            )
            await self._redis_client.set(key, self.shared_state.to_bytes())
            await self._redis_client.expire(key, 86400)  # 24 hour TTL

            # Publish state update notification via pub/sub for real-time worker sync
            if self._task_queue:
                await self._task_queue.publish_state_update(self.shared_state.operation_id)
        except Exception as e:
            logger.warning(f"Failed to checkpoint state: {e}")

    async def recover_state(self, operation_id: str) -> SharedRedTeamState | None:
        """
        Recover state from Redis checkpoint.

        Args:
            operation_id: The operation ID to recover.

        Returns:
            Recovered state or None if not found.
        """
        if self._redis_client is None:
            return None

        try:
            key = f"ares:operation:{operation_id}:state"
            data = await self._redis_client.get(key)
            if data:
                state = SharedRedTeamState.from_bytes(data)
                self._shared_state = state
                logger.info(f"Recovered state for operation {operation_id}")
                return state
        except Exception as e:
            logger.error(f"Failed to recover state: {e}")

        return None

    # Query Methods

    def get_pending_tasks(self) -> list[TaskInfo]:
        """Get all pending tasks."""
        return list(self.shared_state.pending_tasks.values())

    def get_agent_status(self) -> dict[str, dict]:
        """Get status of all registered agents."""
        return {
            name: {
                "role": agent.role.value,
                "status": agent.status,
                "current_task": agent.current_task,
                "last_heartbeat": agent.last_heartbeat.isoformat(),
            }
            for name, agent in self._agents.items()
        }

    async def get_exploitation_status(self) -> dict[str, Any]:  # noqa: PLR0912
        """Get status of discovered vs exploited vulnerabilities."""
        discovered: dict[str, VulnerabilityInfo] = dict(
            self.shared_state.discovered_vulnerabilities
        )
        succeeded: set[str] = set(self.shared_state.exploited_vulnerabilities)
        failed: dict[str, dict[str, Any]] = {}

        if self._redis_client is not None:
            try:
                import json

                vuln_prefix = f"ares:operation:{self.shared_state.operation_id}:vulns:"
                async for key in self._redis_client.scan_iter(f"{vuln_prefix}*"):
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    if not key_str.startswith(vuln_prefix):
                        continue
                    raw = await self._redis_client.get(key)
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                    except Exception as e:
                        logger.debug(f"Failed to parse vulnerability data for {key_str}: {e}")
                        continue
                    vuln_id = key_str[len(vuln_prefix) :]
                    if vuln_id in discovered:
                        continue
                    vuln_type = data.get("type", "unknown")
                    target = data.get("target", "unknown")
                    discovered_by = data.get("discovered_by", "unknown")
                    details = data.get("details") or {}
                    priority = self._vulnerability_priorities.get(vuln_type, 99)
                    discovered_at = datetime.now(timezone.utc)
                    queued_at = data.get("queued_at")
                    if queued_at:
                        try:
                            discovered_at = datetime.fromisoformat(str(queued_at))
                        except Exception:
                            pass
                    discovered[vuln_id] = VulnerabilityInfo(
                        vuln_id=vuln_id,
                        vuln_type=vuln_type,
                        target=target,
                        discovered_by=discovered_by,
                        discovered_at=discovered_at,
                        details=details,
                        priority=priority,
                    )

                key_prefix = f"ares:operation:{self.shared_state.operation_id}:exploited:"
                async for key in self._redis_client.scan_iter(f"{key_prefix}*"):
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    if not key_str.startswith(key_prefix):
                        continue
                    raw = await self._redis_client.get(key)
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                    except Exception as e:
                        logger.debug(f"Failed to parse exploit status for {key_str}: {e}")
                        continue
                    vuln_id = key_str[len(key_prefix) :]
                    if data.get("success"):
                        succeeded.add(vuln_id)
                    else:
                        failed[vuln_id] = data
            except Exception as e:
                logger.warning(f"Failed to load exploitation status from Redis: {e}")

        failed_ids = set(failed.keys())

        return {
            "total_discovered": len(discovered),
            "total_succeeded": len(succeeded),
            "total_failed": len(failed),
            "pending": [
                {"id": vid, "type": v.vuln_type, "target": v.target}
                for vid, v in discovered.items()
                if vid not in succeeded and vid not in failed_ids
            ],
            "succeeded": [
                {"id": vid, "type": discovered[vid].vuln_type, "target": discovered[vid].target}
                for vid in discovered
                if vid in succeeded
            ],
            "failed": [
                {
                    "id": vid,
                    "type": discovered[vid].vuln_type if vid in discovered else "unknown",
                    "target": discovered[vid].target if vid in discovered else "unknown",
                    "error": failed.get(vid, {}).get("result", {}).get("error")
                    or failed.get(vid, {}).get("error")
                    or "Unknown error",
                }
                for vid in failed
            ],
        }

    # Priority Vulnerability Queue Methods

    async def queue_vulnerability(
        self,
        vuln_type: str,
        target: str,
        details: dict[str, Any],
        discovered_by: str,
    ) -> str:
        """
        Queue vulnerability for exploitation with priority.

        Args:
            vuln_type: Type of vulnerability (ADCS_ESC1, krbtgt_hash, etc.)
            target: Target to exploit
            details: Vulnerability-specific details
            discovered_by: Agent that discovered this vulnerability

        Returns:
            Vulnerability ID for tracking
        """
        priority = self._vulnerability_priorities.get(vuln_type, 99)
        vuln_id = f"{vuln_type}_{target}_{uuid.uuid4().hex[:8]}"

        vuln_data = {
            "type": vuln_type,
            "target": target,
            "details": details,
            "discovered_by": discovered_by,
            "queued_at": datetime.now(timezone.utc),
        }

        await self._vulnerability_queue.put((priority, vuln_id, vuln_data))

        # Also add to shared state for tracking
        vuln_info = VulnerabilityInfo(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            target=target,
            discovered_by=discovered_by,
            details=details,
            priority=priority,
        )
        self.shared_state.add_vulnerability(vuln_info)

        # Persist to Redis
        await self._save_vulnerability_to_redis(vuln_id, vuln_data)

        logger.info(f"Queued vulnerability {vuln_id} with priority {priority}")
        return vuln_id

    async def get_next_vulnerability(self) -> dict[str, Any] | None:
        """
        Get highest priority unexploited vulnerability.

        Returns:
            Vulnerability data dict or None if queue empty
        """
        while not self._vulnerability_queue.empty():
            try:
                priority, vuln_id, vuln_data = self._vulnerability_queue.get_nowait()

                # Check if already exploited
                if await self._is_vulnerability_exploited(vuln_id):
                    continue  # Skip and get next

                return {"id": vuln_id, "priority": priority, **vuln_data}

            except asyncio.QueueEmpty:
                break

        return None

    async def mark_vulnerability_exploited(
        self,
        vuln_id: str,
        success: bool,
        result: dict[str, Any] | None = None,
    ) -> None:
        """
        Mark vulnerability as exploited.

        Args:
            vuln_id: The vulnerability ID
            success: Whether exploitation was successful
            result: Exploitation result (credentials, hashes, etc.)
        """
        if success:
            self.shared_state.mark_exploited(vuln_id)

        if success and result:
            result_payload = result
            if isinstance(result, dict) and isinstance(result.get("result"), dict):
                result_payload = result["result"]

            # Update state with exploitation results
            if isinstance(result_payload, dict) and "credential" in result_payload:
                cred_data = result_payload["credential"]
                credential = Credential(
                    username=cred_data.get("username", ""),
                    password=cred_data.get("password", ""),
                    domain=cred_data.get("domain", ""),
                    source=f"exploit:{vuln_id}",
                    is_admin=cred_data.get("is_admin", False),
                )
                self.shared_state.add_credential(credential, "exploitation")

            if isinstance(result_payload, dict) and "hash" in result_payload:
                hash_data = result_payload["hash"]
                hash_obj = Hash(
                    username=hash_data.get("username", ""),
                    hash_value=hash_data.get("hash_value", ""),
                    hash_type=hash_data.get("hash_type", "NTLM"),
                    domain=hash_data.get("domain", ""),
                )
                self.shared_state.add_hash(hash_obj, "exploitation")

        # Update Redis
        await self._mark_exploited_in_redis(vuln_id, success, result)
        await self._checkpoint()

        if success:
            logger.info(f"Marked vulnerability {vuln_id} as exploited (success=True)")
        else:
            logger.info(f"Recorded failed exploitation attempt for {vuln_id}")

    async def _save_vulnerability_to_redis(self, vuln_id: str, vuln_data: dict[str, Any]) -> None:
        """Save vulnerability to Redis for persistence."""
        if self._redis_client is None:
            return

        try:
            import json

            key = f"ares:operation:{self.shared_state.operation_id}:vulns:{vuln_id}"
            # Convert datetime to ISO string for JSON serialization
            serializable_data = {
                **vuln_data,
                "queued_at": vuln_data["queued_at"].isoformat()
                if isinstance(vuln_data.get("queued_at"), datetime)
                else vuln_data.get("queued_at"),
            }
            await self._redis_client.set(key, json.dumps(serializable_data))
            await self._redis_client.expire(key, 86400)  # 24 hour TTL
        except Exception as e:
            logger.warning(f"Failed to save vulnerability to Redis: {e}")

    async def _is_vulnerability_exploited(self, vuln_id: str) -> bool:
        """Check if vulnerability has been exploited."""
        # Check in-memory state first
        if vuln_id in self.shared_state.exploited_vulnerabilities:
            return True

        # Check Redis if available
        if self._redis_client is not None:
            try:
                import json

                key = f"ares:operation:{self.shared_state.operation_id}:exploited:{vuln_id}"
                raw = await self._redis_client.get(key)
                if not raw:
                    return False
                try:
                    data = json.loads(raw)
                except Exception:
                    return False
                return bool(data.get("success"))
            except Exception as e:
                logger.warning(f"Failed to check Redis for exploited vuln: {e}")

        return False

    async def _mark_exploited_in_redis(
        self,
        vuln_id: str,
        success: bool,
        result: dict[str, Any] | None,
    ) -> None:
        """Mark vulnerability as exploited in Redis."""
        if self._redis_client is None:
            return

        try:
            import json

            key = f"ares:operation:{self.shared_state.operation_id}:exploited:{vuln_id}"
            data = {
                "success": success,
                "result": result,
                "exploited_at": datetime.now(timezone.utc).isoformat(),
            }
            await self._redis_client.set(key, json.dumps(data))
            await self._redis_client.expire(key, 86400)
        except Exception as e:
            logger.warning(f"Failed to mark exploited in Redis: {e}")

    # Task Completion Waiting

    async def wait_for_task(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """
        Wait for a task to complete.

        Args:
            task_id: The task ID to wait for
            timeout: Maximum time to wait in seconds

        Returns:
            Task result dict with success, result, and error fields

        Raises:
            asyncio.TimeoutError: If task doesn't complete within timeout
        """
        # Check if already completed
        if task_id in self.shared_state.completed_tasks:
            result = self.shared_state.completed_tasks[task_id]
            return {
                "success": result.success,
                "result": result.result,
                "error": result.error,
            }

        # Create future if not exists
        if task_id not in self._task_futures:
            future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
            self._task_futures[task_id] = future

        try:
            return await asyncio.wait_for(self._task_futures[task_id], timeout=timeout)
        finally:
            # Cleanup future
            self._task_futures.pop(task_id, None)

    def _resolve_task_future(
        self,
        task_id: str,
        success: bool,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        """Resolve a task future when task completes."""
        if task_id in self._task_futures:
            future = self._task_futures[task_id]
            if not future.done():
                future.set_result(
                    {
                        "success": success,
                        "result": result,
                        "error": error,
                    }
                )

    # Redis Task Queue Methods

    @property
    def task_queue(self) -> RedisTaskQueue | None:
        """Get the Redis task queue for direct access if needed."""
        return self._task_queue

    async def dispatch_and_wait(
        self,
        task_type: str,
        target_role: str,
        payload: dict[str, Any],
        timeout: float = 300.0,
    ) -> QueueTaskResult | None:
        """
        Submit task and wait for result.

        Convenience method for synchronous-style task dispatch when using
        Redis task queues in Kubernetes multi-pod mode.

        Args:
            task_type: Type of task (crack, lateral, exploit, etc.)
            target_role: Role to handle the task (cracker, lateral, privesc, etc.)
            payload: Task-specific data
            timeout: Maximum wait time in seconds

        Returns:
            QueueTaskResult or None if timeout/not available
        """
        if not self._task_queue:
            logger.error("Task queue not initialized - Redis URL required for dispatch_and_wait")
            return None

        task_id = await self._task_queue.submit_task(
            task_type=task_type,
            target_role=target_role,
            payload=payload,
        )

        return await self._task_queue.wait_for_result(task_id, timeout=timeout)

    async def wait_for_redis_result(
        self,
        task_id: str,
        timeout: float = 300.0,
    ) -> QueueTaskResult | None:
        """
        Wait for a task result via Redis queue.

        Use this when you've submitted a task via Redis and want to wait
        for the worker to complete it.

        Args:
            task_id: Task ID to wait for
            timeout: Maximum wait time in seconds

        Returns:
            QueueTaskResult or None if timeout/not available
        """
        if not self._task_queue:
            logger.error("Task queue not initialized - cannot wait for Redis result")
            return None

        return await self._task_queue.wait_for_result(task_id, timeout=timeout)


__all__ = ["RedTeamDispatcher"]
