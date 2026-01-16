"""Orchestrator tools for multi-agent red team coordination.

This module provides tools for the orchestrator agent to coordinate
and dispatch tasks to specialized worker agents.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import dreadnode as dn
from dreadnode.agent.tools import Toolset
from loguru import logger

if TYPE_CHECKING:
    from ares.core.dispatcher import RedTeamDispatcher
    from ares.core.models import SharedRedTeamState


class OrchestratorTools(Toolset):
    """
    Tools for the orchestrator agent to coordinate other agents.

    These tools allow the orchestrator to:
    - Dispatch tasks to specialized agents
    - Monitor task progress
    - Query shared state
    - Coordinate exploitation workflow
    """

    _dispatcher: RedTeamDispatcher | None = None
    _shared_state: SharedRedTeamState | None = None
    _agent_name: str = "orchestrator"

    def set_dispatcher(self, dispatcher: RedTeamDispatcher) -> None:
        """Set the dispatcher for inter-agent communication."""
        self._dispatcher = dispatcher

    def set_shared_state(self, state: SharedRedTeamState) -> None:
        """Set the shared state reference."""
        self._shared_state = state

    @property
    def dispatcher(self) -> RedTeamDispatcher:
        if self._dispatcher is None:
            raise RuntimeError("Dispatcher not set. Call set_dispatcher() first.")
        return self._dispatcher

    @property
    def shared_state(self) -> SharedRedTeamState:
        if self._shared_state is None:
            raise RuntimeError("Shared state not set. Call set_shared_state() first.")
        return self._shared_state

    @dn.tool_method
    async def dispatch_crack_hash(
        self,
        hash_value: str,
        hash_type: str,
        priority: int = 5,
        username: str = "",
        domain: str = "",
        wordlist: str = "rockyou.txt",
        wait_for_result: bool = False,
        timeout: float = 300.0,
    ) -> str:
        """
        Send hash to CrackerAgent for cracking.

        The cracker agent will use hashcat or john to attempt to crack
        the hash and report results back.

        Args:
            hash_value: The hash to crack
            hash_type: Type - NTLM, NetNTLMv2, Kerberos, AS-REP
            priority: 1=urgent (krbtgt), 2=admin, 5=normal, 10=low
            username: Associated username (helps prioritization)
            domain: Associated domain
            wordlist: Wordlist to use (default: rockyou.txt)
            wait_for_result: If True, wait for cracking to complete
            timeout: Max time to wait if wait_for_result=True (seconds)

        Returns:
            Task ID for tracking, or cracked result if wait_for_result=True

        Example:
            # Crack admin hash with high priority
            >>> dispatch_crack_hash(
            ...     hash_value="aad3b435b51404eeaad3b435b51404ee:...",
            ...     hash_type="NTLM",
            ...     priority=2,
            ...     username="Administrator"
            ... )
        """
        task_id = await self.dispatcher.request_crack(
            hash_value=hash_value,
            hash_type=hash_type,
            source_agent=self._agent_name,
            username=username,
            domain=domain,
            priority=priority,
            wordlist=wordlist,
        )

        if not task_id:
            return "✗ Failed to dispatch crack request - no cracker agent available"

        logger.info(f"Dispatched crack request: {task_id}")

        if not wait_for_result:
            return f"✓ Crack request submitted: {task_id}\nHash type: {hash_type}, Priority: {priority}"

        # Wait for result via Redis queue
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Crack task {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Cracked: {result.result}"
        return f"✗ Cracking failed: {result.error}"

    @dn.tool_method
    async def dispatch_acl_analysis(
        self,
        target_user: str,
        domain: str,
        find_path_to: str = "Domain Admins",
        wait_for_result: bool = False,
        timeout: float = 300.0,
    ) -> str:
        """
        Request ACLAgent to analyze attack paths for target.

        The ACL agent will run BloodHound and find the shortest
        path to privileged groups/users.

        Args:
            target_user: User to find paths FROM (usually current compromised user)
            domain: Target domain
            find_path_to: Target group/user to find paths TO (default: Domain Admins)
            wait_for_result: If True, wait for analysis to complete
            timeout: Max time to wait if wait_for_result=True (seconds)

        Returns:
            Task ID for tracking, or analysis result if wait_for_result=True

        Example:
            >>> dispatch_acl_analysis(
            ...     target_user="svc_backup",
            ...     domain="corp.local",
            ...     find_path_to="Domain Admins"
            ... )
        """
        task_id = await self.dispatcher.request_acl_analysis(
            target_user=target_user,
            domain=domain,
            source_agent=self._agent_name,
            find_path_to=find_path_to,
        )

        if not task_id:
            return "✗ Failed to dispatch ACL analysis - no ACL agent available"

        logger.info(f"Dispatched ACL analysis: {task_id}")

        if not wait_for_result:
            return f"✓ ACL analysis requested: {task_id}\nFinding paths from {target_user} to {find_path_to}"

        # Wait for result via Redis queue
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ ACL analysis {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ ACL analysis complete: {result.result}"
        return f"✗ ACL analysis failed: {result.error}"

    @dn.tool_method
    async def dispatch_lateral_movement(
        self,
        target_host: str,
        username: str,
        password: str = "",
        hash_value: str = "",
        domain: str = "",
        method: str = "",
        wait_for_result: bool = False,
        timeout: float = 300.0,
    ) -> str:
        """
        Request LateralAgent to move to target host.

        The lateral agent will attempt to establish access using
        the provided credentials, then harvest more credentials.

        Args:
            target_host: IP or hostname to move to
            username: Username to authenticate
            password: Password (if available)
            hash_value: NTLM hash for pass-the-hash (if available)
            domain: Domain for authentication
            method: Specific method (psexec/winrm/wmi) or empty for auto
            wait_for_result: If True, wait for movement to complete
            timeout: Max time to wait if wait_for_result=True (seconds)

        Returns:
            Task ID for tracking, or result if wait_for_result=True

        Example:
            # Move to target using hash
            >>> dispatch_lateral_movement(
            ...     target_host="192.168.1.10",
            ...     username="Administrator",
            ...     hash_value="aad3b435b51404ee:...",
            ...     domain="corp.local"
            ... )
        """
        task_id = await self.dispatcher.request_lateral_movement(
            target_host=target_host,
            username=username,
            source_agent=self._agent_name,
            password=password or None,
            hash_value=hash_value or None,
            domain=domain,
            method=method or None,
        )

        if not task_id:
            return "✗ Failed to dispatch lateral movement - no lateral agent available"

        logger.info(f"Dispatched lateral movement: {task_id}")
        auth_method = "password" if password else "hash" if hash_value else "unknown"

        if not wait_for_result:
            return (
                f"✓ Lateral movement requested: {task_id}\n"
                f"Target: {target_host}, User: {domain}\\{username}, Auth: {auth_method}"
            )

        # Wait for result via Redis queue
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Lateral movement {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Lateral movement to {target_host} succeeded: {result.result}"
        return f"✗ Lateral movement to {target_host} failed: {result.error}"

    @dn.tool_method
    async def dispatch_privesc_exploit(
        self,
        vuln_type: str,
        target: str,
        vuln_id: str = "",
        wait_for_result: bool = False,
        timeout: float = 300.0,
        **kwargs,
    ) -> str:
        """
        Request PrivEscAgent to exploit vulnerability.

        The privesc agent specializes in ADCS, delegation, and MSSQL attacks.

        Args:
            vuln_type: Vulnerability type - ADCS_ESC1, ADCS_ESC4, ADCS_ESC8,
                      DELEGATION_UNCONSTRAINED, DELEGATION_CONSTRAINED, MSSQL_IMPERSONATION
            target: Target to exploit (CA name, server, etc.)
            vuln_id: Optional vulnerability ID for tracking
            wait_for_result: If True, wait for exploitation to complete
            timeout: Max time to wait if wait_for_result=True (seconds)
            **kwargs: Vulnerability-specific parameters

        Returns:
            Task ID for tracking, or result if wait_for_result=True

        Example:
            # Exploit ADCS ESC1
            >>> dispatch_privesc_exploit(
            ...     vuln_type="ADCS_ESC1",
            ...     target="corp-CA",
            ...     template="VulnerableTemplate",
            ...     ca="corp.local\\corp-CA"
            ... )
        """
        if not vuln_id:
            vuln_id = f"{vuln_type}_{target}".replace(" ", "_")

        task_id = await self.dispatcher.request_exploit(
            vuln_type=vuln_type,
            vuln_id=vuln_id,
            target=target,
            source_agent=self._agent_name,
            params=kwargs,
        )

        if not task_id:
            return "✗ Failed to dispatch exploitation - no privesc agent available"

        logger.info(f"Dispatched exploitation: {task_id}")

        if not wait_for_result:
            return f"✓ Exploitation requested: {task_id}\nType: {vuln_type}, Target: {target}"

        # Wait for result via Redis queue
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Exploitation {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Exploitation of {vuln_type} on {target} succeeded: {result.result}"
        return f"✗ Exploitation failed: {result.error}"

    @dn.tool_method
    async def start_poisoning(
        self,
        interface: str = "eth0",
        techniques: str = "LLMNR,NBT-NS,mDNS",
        duration: int = 300,
        wait_for_result: bool = False,
        timeout: float = 600.0,
    ) -> str:
        """
        Request PoisonAgent to start network poisoning.

        The poisoner will run responder/mitm6 to capture hashes.

        Args:
            interface: Network interface to use
            techniques: Comma-separated poisoning techniques (LLMNR, NBT-NS, mDNS)
            duration: How long to run in seconds (default: 300)
            wait_for_result: If True, wait for poisoning to complete
            timeout: Max time to wait if wait_for_result=True (seconds)

        Returns:
            Task ID for tracking, or result if wait_for_result=True

        Example:
            >>> start_poisoning(
            ...     interface="eth0",
            ...     techniques="LLMNR,NBT-NS",
            ...     duration=600
            ... )
        """
        tech_list = [t.strip() for t in techniques.split(",")]

        task_id = await self.dispatcher.request_poisoning(
            source_agent=self._agent_name,
            interface=interface,
            techniques=tech_list,
            duration=duration,
        )

        if not task_id:
            return "✗ Failed to start poisoning - no poison agent available"

        logger.info(f"Dispatched poisoning: {task_id}")

        if not wait_for_result:
            return (
                f"✓ Poisoning started: {task_id}\n"
                f"Techniques: {', '.join(tech_list)}, Duration: {duration}s"
            )

        # Wait for result via Redis queue (longer timeout for poisoning)
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Poisoning {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Poisoning complete: {result.result}"
        return f"✗ Poisoning failed: {result.error}"

    @dn.tool_method
    def get_pending_tasks(self) -> str:
        """
        Get status of all pending tasks across agents.

        Returns summary of tasks that have been dispatched but
        not yet completed.

        Returns:
            Formatted list of pending tasks
        """
        pending = self.shared_state.pending_tasks

        if not pending:
            return "No pending tasks"

        lines = ["📋 Pending Tasks:"]
        for task_id, info in pending.items():
            lines.append(
                f"  • {task_id}: {info.task_type} → {info.assigned_agent} [{info.status.value}]"
            )
        return "\n".join(lines)

    @dn.tool_method
    async def cleanup_orphaned_tasks(self, task_ids: list[str] | None = None) -> str:
        """
        Clean up orphaned or stale tasks that are stuck in pending/retrying/in-progress state.

        Orphaned tasks can occur when:
        - Tasks were dispatched but pods restarted before processing
        - Redis queues were cleared but shared_state still tracks them
        - Workers failed to pick up tasks due to connectivity issues

        Args:
            task_ids: Optional list of specific task IDs to clean up.
                     If None, cleans up ALL pending/retrying/in-progress tasks older than 5 minutes.

        Returns:
            Summary of cleaned up tasks

        Example:
            # Clean up specific orphaned tasks
            >>> cleanup_orphaned_tasks(["poison_ab0056ff310a", "exploit_fe7b6d76ce4b"])

            # Clean up all stale tasks
            >>> cleanup_orphaned_tasks()
        """
        from datetime import datetime, timezone

        cleaned = []
        pending = self.shared_state.pending_tasks

        if not pending:
            return "No pending tasks to clean up"

        if task_ids:
            for task_id in task_ids:
                if task_id in pending:
                    task = pending.pop(task_id)
                    cleaned.append(f"{task_id} ({task.task_type})")
                    logger.info(f"Manually cleaned orphaned task: {task_id}")
        else:
            now = datetime.now(timezone.utc)
            stale_threshold = 300  # 5 minutes
            stale_statuses = {"pending", "retrying", "in_progress"}

            for task_id, task in list(pending.items()):
                if task.status.value in stale_statuses:
                    age_seconds = (now - task.created_at).total_seconds()
                    if age_seconds > stale_threshold:
                        pending.pop(task_id)
                        cleaned.append(f"{task_id} ({task.task_type}, age: {int(age_seconds)}s)")
                        logger.info(
                            f"Auto-cleaned stale pending task: {task_id} (age: {int(age_seconds)}s)"
                        )

        if not cleaned:
            return "No orphaned tasks found to clean up"

        lines = ["🧹 Cleaned up orphaned tasks:"]
        for item in cleaned:
            lines.append(f"  • {item}")

        return "\n".join(lines)

    @dn.tool_method
    def get_all_credentials(self) -> str:
        """
        Get all credentials discovered by any agent.

        Returns credentials from the shared state, showing
        which agent discovered each credential.

        Returns:
            Formatted list of discovered credentials
        """
        creds = self.shared_state.all_credentials

        if not creds:
            return "No credentials discovered yet"

        lines = ["🔑 Discovered Credentials:"]
        for cred in creds:
            auth = cred.password if cred.password else "[hash]"
            admin_tag = " ⚡ADMIN" if cred.is_admin else ""
            lines.append(f"  • {cred.domain}\\{cred.username}: {auth[:20]}...{admin_tag}")
            lines.append(f"    Source: {cred.source}")

        return "\n".join(lines)

    @dn.tool_method
    def get_all_hashes(self) -> str:
        """
        Get all hashes discovered by any agent.

        Useful for tracking which hashes need cracking.

        Returns:
            Formatted list of discovered hashes
        """
        hashes = self.shared_state.all_hashes

        if not hashes:
            return "No hashes discovered yet"

        lines = ["#️⃣ Discovered Hashes:"]
        cracked = 0
        uncracked = 0

        for h in hashes:
            status = "✓ CRACKED" if h.cracked_password else "⏳ pending"
            lines.append(f"  • {h.domain}\\{h.username}: {h.hash_type} [{status}]")
            if h.cracked_password:
                cracked += 1
            else:
                uncracked += 1

        lines.append(f"\nSummary: {cracked} cracked, {uncracked} pending")
        return "\n".join(lines)

    @dn.tool_method
    def get_exploitation_status(self) -> str:
        """
        Get status of discovered vs exploited vulnerabilities.

        Critical for tracking attack surface coverage.

        Returns:
            Formatted vulnerability status
        """
        discovered = self.shared_state.discovered_vulnerabilities
        exploited = self.shared_state.exploited_vulnerabilities

        lines = ["🎯 Vulnerability Status:"]

        if not discovered:
            lines.append("  No vulnerabilities discovered")
            return "\n".join(lines)

        pending = []
        done = []

        for vuln_id, info in discovered.items():
            if vuln_id in exploited:
                done.append(f"  ✓ [EXPLOITED] {info.vuln_type}: {info.target}")
            else:
                pending.append(
                    f"  ⚠️ [PENDING] {info.vuln_type}: {info.target} (priority: {info.priority})"
                )

        if pending:
            lines.append("\n⚠️ UNEXPLOITED (high priority):")
            lines.extend(sorted(pending, key=lambda x: "priority" in x))

        if done:
            lines.append("\n✓ EXPLOITED:")
            lines.extend(done)

        lines.append(f"\nTotal: {len(done)} exploited / {len(discovered)} discovered")

        return "\n".join(lines)

    @dn.tool_method
    def get_agent_status(self) -> str:
        """
        Get status of all registered agents.

        Shows which agents are online, busy, or offline.

        Returns:
            Formatted agent status
        """
        agent_status = self.dispatcher.get_agent_status()

        if not agent_status:
            return "No agents registered"

        lines = ["🤖 Agent Status:"]

        for name, status in agent_status.items():
            icon = {"idle": "⚪", "busy": "🟢", "offline": "🔴"}.get(status["status"], "⚪")
            task_info = f" → {status['current_task']}" if status["current_task"] else ""
            lines.append(f"  {icon} {name} ({status['role']}): {status['status']}{task_info}")

        return "\n".join(lines)

    @dn.tool_method
    def get_operation_summary(self) -> str:
        """
        Get comprehensive operation summary.

        Aggregates all key metrics and achievements.

        Returns:
            Formatted operation summary
        """
        state = self.shared_state
        summary = state.to_summary()

        lines = [
            "📊 OPERATION SUMMARY",
            "=" * 40,
            f"Operation ID: {summary['operation_id']}",
            "",
            "📈 Discovery Metrics:",
            f"  • Hosts discovered: {summary['host_count']}",
            f"  • Credentials found: {summary['credential_count']}",
            f"  • Hashes captured: {summary['hash_count']}",
            "",
            "🎯 Exploitation Progress:",
            f"  • Vulnerabilities found: {summary['vulnerability_count']}",
            f"  • Vulnerabilities exploited: {summary['exploited_count']}",
            "",
            "📋 Task Status:",
            f"  • Pending tasks: {summary['pending_tasks']}",
            f"  • Completed tasks: {summary['completed_tasks']}",
            "",
            "🏆 Achievements:",
        ]

        if summary["has_domain_admin"]:
            lines.append("  ✅ DOMAIN ADMIN ACHIEVED")
        else:
            lines.append("  ⏳ Domain admin: not yet")

        if summary["has_golden_ticket"]:
            lines.append("  ✅ GOLDEN TICKET FORGED")

        lines.extend(
            [
                "",
                "🤖 Active Agents:",
                f"  {', '.join(summary['registered_agents']) or 'None'}",
            ]
        )

        return "\n".join(lines)

    @dn.tool_method
    async def broadcast_credential(
        self,
        username: str,
        password: str = "",
        hash_value: str = "",
        domain: str = "",
        is_admin: bool = False,
        source: str = "",
    ) -> str:
        """
        Broadcast a discovered credential to all agents.

        Use this when you discover credentials that other agents
        should know about.

        Args:
            username: The username
            password: Password if known
            hash_value: Hash if password not known
            domain: Domain
            is_admin: Whether this is an admin credential
            source: How/where the credential was discovered

        Returns:
            Confirmation message
        """
        from ares.core.models import Credential

        cred = Credential(
            username=username,
            password=password or hash_value,  # Store hash in password field if no password
            domain=domain,
            source=source,
            is_admin=is_admin,
        )

        added = await self.dispatcher.publish_credential(
            cred,
            source_agent=self._agent_name,
            is_admin=is_admin,
        )

        if added:
            return f"✓ Credential broadcast to all agents: {domain}\\{username}"
        return f"[i] Credential already known: {domain}\\{username}"

    @dn.tool_method
    async def announce_domain_admin(
        self,
        username: str,
        domain: str,
        attack_path: str,
        credential_type: str = "password",
    ) -> str:
        """
        Announce domain admin achievement to all agents.

        This is a critical milestone - triggers celebration and
        next phase actions.

        Args:
            username: The domain admin username
            domain: The domain
            attack_path: Description of how DA was achieved
            credential_type: Type of credential (password/hash/ticket)

        Returns:
            Confirmation message
        """
        await self.dispatcher.announce_domain_admin(
            username=username,
            domain=domain,
            attack_path=attack_path,
            credential_type=credential_type,
            source_agent=self._agent_name,
        )

        return f"🎉 DOMAIN ADMIN ANNOUNCED!\nUser: {domain}\\{username}\nPath: {attack_path}"

    @dn.tool_method
    async def trigger_credential_expansion(self, max_iterations: int = 10) -> str:
        """
        Automatically test all credentials against all hosts.

        This initiates a recursive workflow:
        1. Test each credential against each host
        2. Successful access -> run secretsdump
        3. New credentials -> repeat process

        Use after discovering new credentials to maximize access.

        Args:
            max_iterations: Maximum expansion iterations (default: 10)

        Returns:
            Summary of expansion results
        """
        from ares.core.workflows import credential_expansion_loop

        tracker = await credential_expansion_loop(
            self.dispatcher,
            max_iterations=max_iterations,
        )

        stats = tracker.get_stats()

        # Get updated state
        state = self.shared_state

        return (
            f"Credential expansion complete!\n"
            f"→ Tested {stats['total_tested']} credential/host combinations\n"
            f"→ Successful: {stats['successful']}\n"
            f"→ Failed: {stats['failed']}\n"
            f"→ Current access: {len(state.all_hosts)} hosts\n"
            f"→ Total credentials: {len(state.all_credentials)}\n"
            f"→ Check get_all_credentials() for details"
        )

    @dn.tool_method
    async def queue_vulnerability_for_exploitation(
        self,
        vuln_type: str,
        target: str,
        details: str = "{}",
    ) -> str:
        """
        Queue a discovered vulnerability for priority-based exploitation.

        Vulnerabilities are automatically prioritized (ADCS > krbtgt > delegation > etc.)
        and processed by the exploitation workflow.

        Args:
            vuln_type: Type of vulnerability (ADCS_ESC1, ADCS_ESC4, ADCS_ESC8,
                      krbtgt_hash, domain_admin_hash, acl_abuse,
                      unconstrained_delegation, constrained_delegation, etc.)
            target: Target to exploit (CA name, server, user, etc.)
            details: JSON string with vulnerability-specific details

        Returns:
            Confirmation with vulnerability ID and priority
        """
        import json

        try:
            details_dict = json.loads(details) if details else {}
        except json.JSONDecodeError:
            details_dict = {"raw": details}

        vuln_id = await self.dispatcher.queue_vulnerability(
            vuln_type=vuln_type,
            target=target,
            details=details_dict,
            discovered_by=self._agent_name,
        )

        # Get the priority for reporting
        priority = self.dispatcher._vulnerability_priorities.get(vuln_type, 99)

        return (
            f"✓ Vulnerability queued for exploitation\n"
            f"→ ID: {vuln_id}\n"
            f"→ Type: {vuln_type}\n"
            f"→ Target: {target}\n"
            f"→ Priority: {priority} (lower = higher priority)"
        )

    @dn.tool_method
    async def get_vulnerability_queue_status(self) -> str:
        """
        Get status of the vulnerability exploitation queue.

        Shows queued, in-progress, and completed vulnerability exploitations.

        Returns:
            Formatted queue status
        """
        status = self.dispatcher.get_exploitation_status()

        lines = ["🎯 Vulnerability Queue Status:"]
        lines.append(f"  Total discovered: {status['total_discovered']}")
        lines.append(f"  Total exploited: {status['total_exploited']}")

        if status["pending"]:
            lines.append("\n⏳ Pending exploitation:")
            for vuln in status["pending"]:
                lines.append(f"  • [{vuln['type']}] {vuln['target']} (ID: {vuln['id']})")
        else:
            lines.append("\n✓ No vulnerabilities pending exploitation")

        if status["exploited"]:
            lines.append(f"\n✓ Exploited: {len(status['exploited'])} vulnerabilities")

        return "\n".join(lines)

    @dn.tool_method
    async def register_discovered_host(
        self,
        ip: str,
        hostname: str = "",
        os: str = "",
        roles: list[str] | None = None,
        services: list[str] | None = None,
    ) -> str:
        """
        Register a newly discovered host with all agents.

        Use this when network enumeration discovers new systems.

        Args:
            ip: IP address of the host
            hostname: Hostname if known
            os: Operating system detected (Windows Server 2019, Ubuntu 20.04, etc.)
            roles: Server roles (["DC", "SQL"], ["Exchange"], etc.)
            services: Running services detected (["SMB", "RDP", "WinRM"], etc.)

        Returns:
            Confirmation message

        Example:
            >>> register_discovered_host(
            ...     ip="192.168.1.10",
            ...     hostname="DC01",
            ...     os="Windows Server 2019",
            ...     roles=["DC"],
            ...     services=["SMB", "LDAP", "Kerberos"]
            ... )
        """
        from ares.core.models import Host

        host = Host(
            ip=ip,
            hostname=hostname,
            os=os,
            roles=roles or [],
            services=services or [],
        )

        added = await self.dispatcher.publish_host(host, self._agent_name)

        if added:
            return f"✓ Host registered: {hostname or ip} ({os})"
        return f"[i] Host already known: {hostname or ip}"


class CrackerCallbackTools(Toolset):
    """Callback tools for the cracker agent to report results."""

    _dispatcher: RedTeamDispatcher | None = None
    _agent_name: str = "cracker"

    def set_dispatcher(self, dispatcher: RedTeamDispatcher) -> None:
        self._dispatcher = dispatcher

    @property
    def dispatcher(self) -> RedTeamDispatcher:
        if self._dispatcher is None:
            raise RuntimeError("Dispatcher not set")
        return self._dispatcher

    @dn.tool_method
    async def report_cracked_credential(
        self,
        task_id: str,
        username: str,
        password: str,
        original_hash: str,
        domain: str = "",
        method: str = "hashcat",
    ) -> str:
        """
        Report a successfully cracked credential.

        Broadcasts the credential to all agents and completes the task.

        Args:
            task_id: The original crack request task ID
            username: Username
            password: Cracked password
            original_hash: The hash that was cracked
            domain: Domain
            method: Cracking method used (hashcat/john)

        Returns:
            Confirmation message
        """
        from ares.core.models import Credential

        cred = Credential(
            username=username,
            password=password,
            domain=domain,
            source=f"cracked:{method}",
        )

        await self.dispatcher.publish_credential(cred, self._agent_name)

        await self.dispatcher.complete_task(
            task_id=task_id,
            success=True,
            result={"username": username, "password": password, "method": method},
            source_agent=self._agent_name,
        )

        logger.success(f"Cracked: {domain}\\{username}")
        return f"✓ Credential broadcast: {domain}\\{username}"

    @dn.tool_method
    async def report_crack_failed(
        self,
        task_id: str,
        hash_value: str,
        reason: str = "exhausted wordlist",
    ) -> str:
        """
        Report that cracking failed.

        Args:
            task_id: The original crack request task ID
            hash_value: The hash that couldn't be cracked
            reason: Why cracking failed

        Returns:
            Confirmation message
        """
        await self.dispatcher.complete_task(
            task_id=task_id,
            success=False,
            error=reason,
            source_agent=self._agent_name,
        )

        return f"✗ Cracking failed: {reason}"


class LateralCallbackTools(Toolset):
    """Callback tools for the lateral agent to report results."""

    _dispatcher: RedTeamDispatcher | None = None
    _agent_name: str = "lateral"

    def set_dispatcher(self, dispatcher: RedTeamDispatcher) -> None:
        self._dispatcher = dispatcher

    @property
    def dispatcher(self) -> RedTeamDispatcher:
        if self._dispatcher is None:
            raise RuntimeError("Dispatcher not set")
        return self._dispatcher

    @dn.tool_method
    async def report_lateral_success(
        self,
        task_id: str,
        target_host: str,
        method: str,
        new_credentials: str = "",
    ) -> str:
        """
        Report successful lateral movement.

        Args:
            task_id: The original lateral movement task ID
            target_host: Host that was accessed
            method: Method used (psexec/winrm/etc)
            new_credentials: Any new credentials found (JSON format)

        Returns:
            Confirmation message
        """
        import json

        result = {
            "target_host": target_host,
            "method": method,
            "success": True,
        }

        # Parse and broadcast new credentials
        if new_credentials:
            try:
                creds = json.loads(new_credentials)
                result["new_credentials_count"] = len(creds) if isinstance(creds, list) else 1
            except json.JSONDecodeError:
                pass

        await self.dispatcher.complete_task(
            task_id=task_id,
            success=True,
            result=result,
            source_agent=self._agent_name,
        )

        return f"✓ Lateral movement to {target_host} reported"

    @dn.tool_method
    async def report_lateral_failed(
        self,
        task_id: str,
        target_host: str,
        reason: str,
    ) -> str:
        """
        Report failed lateral movement.

        Args:
            task_id: The original lateral movement task ID
            target_host: Host that was targeted
            reason: Why it failed

        Returns:
            Confirmation message
        """
        await self.dispatcher.complete_task(
            task_id=task_id,
            success=False,
            error=f"Lateral to {target_host} failed: {reason}",
            source_agent=self._agent_name,
        )

        return f"✗ Lateral movement failed: {reason}"


__all__ = [
    "CrackerCallbackTools",
    "LateralCallbackTools",
    "OrchestratorTools",
]
