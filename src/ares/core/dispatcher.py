"""Central dispatcher for multi-agent red team operations.

This module provides the RedTeamDispatcher class which coordinates
communication and task routing between specialized red team agents
running in Kubernetes pods.
"""

from __future__ import annotations

import asyncio
import uuid
from asyncio import PriorityQueue, Queue
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.messages import (
    ACLAnalysisRequest,
    AgentMessage,
    AgentRegistered,
    CrackRequest,
    CredentialDiscovered,
    DomainAdminAchieved,
    ExploitRequest,
    GoldenTicketForged,
    HashDiscovered,
    HostDiscovered,
    LateralMovementRequest,
    MessageType,
    OperationComplete,
    PoisonRequest,
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
    SharedRedTeamState,
    TaskInfo,
    TaskResult,
    TaskStatus,
    VulnerabilityInfo,
)

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
        await dispatcher.publish_credential(credential, "enum-agent")

        # Route tasks to specialized agents
        task_id = await dispatcher.request_crack(hash_data, "orchestrator")
    """

    def __init__(self, redis_url: str | None = None):
        """
        Initialize the dispatcher.

        Args:
            redis_url: Optional Redis URL for state persistence.
                       If not provided, uses in-memory state.
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
            "gpo_abuse": 12,
            "laps_abuse": 13,
            "dcsync": 14,
            "shadow_credentials": 15,
        }

        # Task completion futures for wait_for_task
        self._task_futures: dict[str, asyncio.Future[dict[str, Any]]] = {}

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
                import redis.asyncio as redis

                self._redis_client = redis.from_url(self._redis_url)
                await self._redis_client.ping()
                logger.info(f"Connected to Redis at {self._redis_url}")
            except ImportError:
                logger.warning("redis package not installed, using in-memory state")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}, using in-memory state")

        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())

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
            AgentRole.ENUM: {
                MessageType.TASK_COMPLETE,
                MessageType.TASK_FAILED,
                MessageType.VULNERABILITY_FOUND,
                MessageType.HASH_DISCOVERED,
                MessageType.HOST_DISCOVERED,
            },
            AgentRole.CRACKER: {
                MessageType.CRACK_REQUEST,
                MessageType.HASH_DISCOVERED,
            },
            AgentRole.ACL: {
                MessageType.ACL_ANALYSIS_REQUEST,
                MessageType.VULNERABILITY_FOUND,
            },
            AgentRole.PRIVESC: {
                MessageType.EXPLOIT_REQUEST,
                MessageType.VULNERABILITY_FOUND,
            },
            AgentRole.LATERAL: {
                MessageType.LATERAL_REQUEST,
                MessageType.HOST_DISCOVERED,
            },
            AgentRole.POISONING: {
                MessageType.POISON_REQUEST,
            },
            AgentRole.ATOMIC: {
                MessageType.ATOMIC_TEST_REQUEST,
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
        added = self.shared_state.add_credential(credential, source_agent)

        if added:
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

        return added

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

        return added

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
            params={
                "hash_value": hash_value,
                "hash_type": hash_type,
                "username": username,
                "domain": domain,
                "wordlist": wordlist,
            },
        )
        self.shared_state.pending_tasks[task_id] = task_info

        # Send request to cracker
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
        task_id = generate_task_id()
        lateral_agent = self._role_queues.get(AgentRole.LATERAL)

        if not lateral_agent:
            logger.warning("No lateral agent registered, cannot route lateral request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="lateral_movement",
            assigned_agent=lateral_agent,
            params={
                "target_host": target_host,
                "username": username,
                "domain": domain,
                "method": method,
            },
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

    async def request_acl_analysis(
        self,
        target_user: str,
        domain: str,
        source_agent: str,
        find_path_to: str = "Domain Admins",
    ) -> str:
        """
        Request ACLAgent to analyze attack paths for target.

        Args:
            target_user: User to find paths to.
            domain: Target domain.
            source_agent: Agent making the request.
            find_path_to: Target group/user for path finding.

        Returns:
            Task ID for tracking.
        """
        task_id = generate_task_id()
        acl_agent = self._role_queues.get(AgentRole.ACL)

        if not acl_agent:
            logger.warning("No ACL agent registered, cannot route ACL request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="acl_analysis",
            assigned_agent=acl_agent,
            params={
                "target_user": target_user,
                "domain": domain,
                "find_path_to": find_path_to,
            },
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

        Args:
            vuln_type: ADCS_ESC1, DELEGATION_UNCONSTRAINED, etc.
            vuln_id: Vulnerability ID.
            target: Target to exploit.
            source_agent: Agent making the request.
            params: Vulnerability-specific parameters.

        Returns:
            Task ID for tracking.
        """
        task_id = generate_task_id()
        privesc_agent = self._role_queues.get(AgentRole.PRIVESC)

        if not privesc_agent:
            logger.warning("No privesc agent registered, cannot route exploit request")
            return ""

        task_info = TaskInfo(
            task_id=task_id,
            task_type="exploit",
            assigned_agent=privesc_agent,
            params={
                "vuln_type": vuln_type,
                "vuln_id": vuln_id,
                "target": target,
                **(params or {}),
            },
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

    async def request_poisoning(
        self,
        source_agent: str,
        interface: str = "eth0",
        techniques: list[str] | None = None,
        duration: int = 300,
    ) -> str:
        """
        Request PoisonAgent to start network poisoning.

        Args:
            source_agent: Agent making the request.
            interface: Network interface.
            techniques: Poisoning techniques to use.
            duration: How long to run (seconds).

        Returns:
            Task ID for tracking.
        """
        task_id = generate_task_id()
        poison_agent = self._role_queues.get(AgentRole.POISONING)

        if not poison_agent:
            logger.warning("No poison agent registered, cannot route poison request")
            return ""

        techniques = techniques or ["LLMNR", "NBT-NS", "mDNS"]

        task_info = TaskInfo(
            task_id=task_id,
            task_type="poisoning",
            assigned_agent=poison_agent,
            params={
                "interface": interface,
                "techniques": techniques,
                "duration": duration,
            },
        )
        self.shared_state.pending_tasks[task_id] = task_info

        await self._message_queues[poison_agent].put(
            PoisonRequest(
                source_agent=source_agent,
                task_id=task_id,
                interface=interface,
                techniques=techniques,
                duration=duration,
                callback_agent=source_agent,
            )
        )

        logger.info(f"Poisoning request {task_id} sent to {poison_agent}")
        return task_id

    # Task Completion

    async def complete_task(
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
        task_info.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        task_info.completed_at = datetime.now(timezone.utc)
        task_info.result = result
        task_info.error = error

        task_result = TaskResult(
            task_id=task_id,
            success=success,
            result=result,
            error=error,
        )
        self.shared_state.completed_tasks[task_id] = task_result

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

            for agent_name, agent_info in list(self._agents.items()):
                # Check if heartbeat is stale (> 60 seconds)
                elapsed = (now - agent_info.last_heartbeat).total_seconds()
                if elapsed > 60 and agent_info.status != "offline":
                    logger.warning(f"Agent {agent_name} heartbeat stale ({elapsed:.0f}s)")
                    agent_info.status = "offline"

            await asyncio.sleep(15)

    # State Persistence

    async def _checkpoint(self) -> None:
        """Save state checkpoint to Redis if available."""
        if self._redis_client is None:
            return

        try:
            key = f"ares:operation:{self.shared_state.operation_id}:state"
            await self._redis_client.set(key, self.shared_state.to_bytes())
            await self._redis_client.expire(key, 86400)  # 24 hour TTL
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

    def get_exploitation_status(self) -> dict[str, Any]:
        """Get status of discovered vs exploited vulnerabilities."""
        discovered = self.shared_state.discovered_vulnerabilities
        exploited = self.shared_state.exploited_vulnerabilities

        return {
            "total_discovered": len(discovered),
            "total_exploited": len(exploited),
            "pending": [
                {"id": vid, "type": v.vuln_type, "target": v.target}
                for vid, v in discovered.items()
                if vid not in exploited
            ],
            "exploited": list(exploited),
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
        self.shared_state.mark_exploited(vuln_id)

        if success and result:
            # Update state with exploitation results
            if "credential" in result:
                cred_data = result["credential"]
                credential = Credential(
                    username=cred_data.get("username", ""),
                    password=cred_data.get("password", ""),
                    domain=cred_data.get("domain", ""),
                    source=f"exploit:{vuln_id}",
                    is_admin=cred_data.get("is_admin", False),
                )
                self.shared_state.add_credential(credential, "exploitation")

            if "hash" in result:
                hash_data = result["hash"]
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

        logger.info(f"Marked vulnerability {vuln_id} as exploited (success={success})")

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
                key = f"ares:operation:{self.shared_state.operation_id}:exploited:{vuln_id}"
                result = await self._redis_client.exists(key)
                return bool(result)
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


__all__ = ["RedTeamDispatcher"]
