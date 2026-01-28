"""Orchestrator tools for multi-agent red team coordination.

This module provides tools for the orchestrator agent to coordinate
and dispatch tasks to specialized worker agents.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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
    def complete_operation(self, summary: str) -> str:
        """
        Mark the multi-agent red team operation as complete.

        Use this tool when you have:
        - Achieved domain admin access OR exhausted all attack paths
        - Coordinated with all specialized agents
        - Collected all available credentials and hashes
        - Generated golden ticket (if krbtgt hash was found)

        Args:
            summary: Executive summary of the operation including:
                - All domain administrators compromised
                - Attack paths used
                - Total credentials obtained
                - Hosts compromised
                - Key vulnerabilities exploited

        Returns:
            Confirmation message
        """
        self.shared_state.completed = True
        logger.success(f"🎯 Multi-agent operation completed: {summary}")
        return f"✓ Operation marked as complete. Summary: {summary}"

    @dn.tool_method
    async def dispatch_recon(
        self,
        task_type: str,
        targets: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
        hash_value: str = "",
        details: str = "{}",
        wait_for_result: bool = False,
        timeout: float = 600.0,
    ) -> str:
        """
        Dispatch reconnaissance tasks to the RECON agent.

        The RECON agent specializes in network scanning, enumeration, and
        attack path discovery. Use this to delegate:
        - Network scanning (nmap)
        - User and share enumeration
        - Domain information gathering
        - BloodHound collection and analysis

        Args:
            task_type: Type of reconnaissance task:
                - "network_scan": Run nmap to discover live hosts and services
                - "user_enumeration": Enumerate domain users
                - "share_enumeration": Enumerate network shares
                - "domain_info": Gather domain controller and trust information
                - "bloodhound": Run BloodHound collection and analysis (requires creds)
            targets: Comma-separated target IPs, hostnames, or CIDR ranges (e.g., "10.0.0.0/24,10.0.1.5")
            domain: Target domain (e.g., "corp.local")
            username: Username for authenticated enumeration (optional)
            password: Password for authenticated enumeration (optional)
            hash_value: NTLM hash for pass-the-hash (optional)
            details: JSON string with additional parameters (e.g., '{"ports": "80,443,445"}')
            wait_for_result: If True, wait for task completion
            timeout: Max time to wait if wait_for_result=True (seconds, default 600 for long scans)

        Returns:
            Task ID for tracking, or result if wait_for_result=True

        Example:
            # Initial network scan
            >>> dispatch_recon(
            ...     task_type="network_scan",
            ...     targets="10.0.0.0/24",
            ...     details='{"ports": "top-1000"}'
            ... )

            # User enumeration (unauthenticated)
            >>> dispatch_recon(
            ...     task_type="user_enumeration",
            ...     targets="10.0.0.1",
            ...     domain="corp.local"
            ... )

            # BloodHound with credentials
            >>> dispatch_recon(
            ...     task_type="bloodhound",
            ...     targets="10.0.0.1",
            ...     domain="corp.local",
            ...     username="user1",
            ...     password="P@ssw0rd"  # pragma: allowlist secret
            ... )
        """
        # Parse targets into list
        target_ips = [t.strip() for t in targets.split(",") if t.strip()] if targets else []

        # Map task_type to techniques
        technique_map = {
            "network_scan": ["nmap_scan"],
            "user_enumeration": ["enumerate_users"],
            "share_enumeration": ["enumerate_shares"],
            "domain_info": ["get_domain_info"],
            "bloodhound": ["run_bloodhound"],
        }

        techniques = technique_map.get(task_type, [task_type])

        # Get domain from shared state if not provided
        if not domain and self.shared_state.domains:
            domain = next(iter(self.shared_state.domains))

        task_id = await self.dispatcher.request_recon(
            source_agent=self._agent_name,
            domain=domain,
            target_ips=target_ips or None,
            username=username or "",
            password=password or None,
            hash_value=hash_value or None,
            reason=task_type,
            techniques=techniques,
        )

        if not task_id:
            return "✗ Failed to dispatch recon - no recon agent available"

        logger.info(f"Dispatched recon ({task_type}): {task_id}")

        if not wait_for_result:
            target_info = f", Targets: {targets}" if targets else ""
            cred_info = f", User: {username}" if username else ""
            return (
                f"✓ Recon task dispatched: {task_id}\n"
                f"Type: {task_type}{target_info}{cred_info}\n"
                f"Techniques: {', '.join(techniques)}"
            )

        # Wait for result via Redis queue
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Recon task {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Recon complete: {result.result}"
        return f"✗ Recon failed: {result.error}"

    @dn.tool_method
    async def dispatch_credential_access(
        self,
        task_type: str,
        targets: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
        hash_value: str = "",
        details: str = "{}",
        wait_for_result: bool = False,
        timeout: float = 300.0,
    ) -> str:
        """
        Dispatch credential access tasks to the CREDENTIAL_ACCESS agent.

        The credential access agent specializes in password attacks, hash
        extraction, and credential discovery. Use this to delegate:
        - Low-hanging fruit attacks (username=password, password spray, LDAP descriptions)
        - Hash extraction (secretsdump, kerberoast, asrep_roast)
        - Share pilfering (GPP passwords, SYSVOL scripts)

        Args:
            task_type: Type of credential access task:
                - "low_hanging_fruit": Run username_as_password, password_spray,
                  ldap_search_descriptions, sysvol_script_search, gpp_password_finder
                - "secretsdump": Extract hashes from target (requires admin creds)
                - "kerberoast": Find and roast service accounts with SPNs
                - "asrep_roast": Find accounts without pre-auth required
                - "lsassy": Dump LSASS memory (requires admin access)
                - "share_spider": Search accessible shares for credentials
            targets: Comma-separated target IPs or hostnames (e.g., "10.0.0.1,10.0.0.2")
            domain: Target domain (e.g., "corp.local")
            username: Username for authenticated actions (optional)
            password: Password for authenticated actions (optional)
            hash_value: NTLM hash for pass-the-hash (optional)
            details: JSON string with additional parameters (e.g., '{"users_file": "/tmp/users.txt"}')
            wait_for_result: If True, wait for task completion
            timeout: Max time to wait if wait_for_result=True (seconds)

        Returns:
            Task ID for tracking, or result if wait_for_result=True

        Example:
            # Low-hanging fruit after user enumeration
            >>> dispatch_credential_access(
            ...     task_type="low_hanging_fruit",
            ...     targets="10.0.0.1",
            ...     domain="corp.local",
            ...     details='{"users_file": "/tmp/users.txt"}'
            ... )

            # Secretsdump with credentials
            >>> dispatch_credential_access(
            ...     task_type="secretsdump",
            ...     targets="10.0.0.1,10.0.0.2",
            ...     domain="corp.local",
            ...     username="admin",
            ...     password="P@ssw0rd"  # pragma: allowlist secret
            ... )

            # Kerberoast to find service accounts
            >>> dispatch_credential_access(
            ...     task_type="kerberoast",
            ...     domain="corp.local",
            ...     username="user1",
            ...     password="password123"  # pragma: allowlist secret
            ... )
        """
        # Parse targets into list
        target_ips = [t.strip() for t in targets.split(",") if t.strip()] if targets else []

        # Map task_type to techniques
        technique_map = {
            "low_hanging_fruit": [
                "username_as_password",
                "password_spray",
                "ldap_search_descriptions",
                "sysvol_script_search",
                "gpp_password_finder",
            ],
            "secretsdump": ["secretsdump"],
            "kerberoast": ["kerberoast"],
            "asrep_roast": ["asrep_roast"],
            "lsassy": ["lsassy"],
            "share_spider": ["share_spider"],
        }

        techniques = technique_map.get(task_type, [task_type])

        # Get domain from shared state if not provided
        if not domain and self.shared_state.domains:
            domain = next(iter(self.shared_state.domains))

        task_id = await self.dispatcher.request_credential_access(
            source_agent=self._agent_name,
            domain=domain,
            target_ips=target_ips or None,
            username=username or "",
            password=password or None,
            hash_value=hash_value or None,
            reason=task_type,
            techniques=techniques,
        )

        if not task_id:
            return "✗ Failed to dispatch credential access - no credential_access agent available"

        logger.info(f"Dispatched credential access ({task_type}): {task_id}")

        if not wait_for_result:
            target_info = f", Targets: {targets}" if targets else ""
            cred_info = f", User: {username}" if username else ""
            return (
                f"✓ Credential access task dispatched: {task_id}\n"
                f"Type: {task_type}{target_info}{cred_info}\n"
                f"Techniques: {', '.join(techniques)}"
            )

        # Wait for result via Redis queue
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Credential access task {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Credential access complete: {result.result}"
        return f"✗ Credential access failed: {result.error}"

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

        The ACL agent focuses on exploiting ACL abuse paths. Ensure
        BloodHound analysis is run by recon/orchestrator when needed.

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
        # Validate username is not empty
        if not username or not username.strip():
            return (
                "✗ Invalid lateral movement request: username cannot be empty. "
                "Please provide a valid username (e.g., 'Administrator', 'user1')."
            )

        # Detect common mistake: domain contains "domain\username" format
        if domain and "\\" in domain:
            return (
                f"✗ Invalid lateral movement request: domain field contains backslash ('{domain}'). "
                "The domain and username must be separate parameters. "
                f"Please use domain='{domain.split(chr(92))[0]}' and username='{domain.split(chr(92))[1]}' separately."
            )

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

        if vuln_type == "ADCS_ESC8":
            kwargs = dict(kwargs)
            if not kwargs.get("coerce_target"):
                kwargs["coerce_target"] = kwargs.get("dc_host") or kwargs.get("ca_host") or target

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
    async def start_coercion(
        self,
        interface: str = "eth0",
        techniques: str = "LLMNR,NBT-NS,mDNS",
        duration: int = 300,
        wait_for_result: bool = False,
        timeout: float = 600.0,
    ) -> str:
        """
        Request the coercion agent to start network coercion.

        The coercion agent will run responder/mitm6 to capture hashes.

        Args:
            interface: Network interface to use
            techniques: Comma-separated coercion techniques (LLMNR, NBT-NS, mDNS)
            duration: How long to run in seconds (default: 300)
            wait_for_result: If True, wait for coercion to complete
            timeout: Max time to wait if wait_for_result=True (seconds)

        Returns:
            Task ID for tracking, or result if wait_for_result=True

        Example:
            >>> start_coercion(
            ...     interface="eth0",
            ...     techniques="LLMNR,NBT-NS",
            ...     duration=600
            ... )
        """
        tech_list = [t.strip() for t in techniques.split(",")]

        task_id = await self.dispatcher.request_coercion(
            source_agent=self._agent_name,
            interface=interface,
            techniques=tech_list,
            duration=duration,
        )

        if not task_id:
            return "✗ Failed to start coercion - no coercion agent available"

        logger.info(f"Dispatched coercion: {task_id}")

        if not wait_for_result:
            return (
                f"✓ Coercion started: {task_id}\n"
                f"Techniques: {', '.join(tech_list)}, Duration: {duration}s"
            )

        # Wait for result via Redis queue (longer timeout for coercion)
        result = await self.dispatcher.wait_for_redis_result(task_id, timeout=timeout)

        if result is None:
            return f"⏳ Coercion {task_id} timed out after {timeout}s"

        if result.success:
            return f"✓ Coercion complete: {result.result}"
        return f"✗ Coercion failed: {result.error}"

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
    async def cleanup_orphaned_tasks(  # noqa: PLR0912
        self,
        task_ids: list[str] | None = None,
        force: bool = False,
    ) -> str:
        """
        Clean up orphaned or stale tasks that are stuck in pending/retrying/in-progress state.

        Orphaned tasks can occur when:
        - Tasks were dispatched but pods restarted before processing
        - Redis queues were cleared but shared_state still tracks them
        - Workers failed to pick up tasks due to connectivity issues

        Args:
            task_ids: Optional list of specific task IDs to clean up.
                     If None, cleans up ALL pending/retrying/in-progress tasks older than 5 minutes.
            force: If True, remove specified task_ids immediately regardless of age/status.

        Returns:
            Summary of cleaned up tasks

        Example:
            # Clean up specific orphaned tasks
            >>> cleanup_orphaned_tasks(["coercion_ab0056ff310a", "exploit_fe7b6d76ce4b"])

            # Clean up all stale tasks
            >>> cleanup_orphaned_tasks()
        """
        from datetime import datetime, timezone

        cleaned = []
        skipped = []
        pending = self.shared_state.pending_tasks

        if not pending:
            return "No pending tasks to clean up"

        now = datetime.now(timezone.utc)
        stale_threshold = 300  # 5 minutes
        stale_statuses = {"pending", "retrying", "in_progress"}

        if task_ids:
            for task_id in task_ids:
                if task_id in pending:
                    task = pending[task_id]
                    age_seconds = (now - task.created_at).total_seconds()
                    if force:
                        pending.pop(task_id)
                        cleaned.append(f"{task_id} ({task.task_type})")
                        logger.info(f"Manually cleaned orphaned task (force): {task_id}")
                    elif task.status.value in {"failed", "cancelled", "completed"}:
                        pending.pop(task_id)
                        cleaned.append(f"{task_id} ({task.task_type})")
                        logger.info(f"Manually cleaned terminal task: {task_id}")
                    elif task.status.value in stale_statuses and age_seconds > stale_threshold:
                        pending.pop(task_id)
                        cleaned.append(f"{task_id} ({task.task_type}, age: {int(age_seconds)}s)")
                        logger.info(
                            f"Manually cleaned stale pending task: {task_id} "
                            f"(age: {int(age_seconds)}s)"
                        )
                    else:
                        skipped.append(
                            f"{task_id} ({task.task_type}, age: {int(age_seconds)}s, "
                            f"status: {task.status.value})"
                        )
        else:
            for task_id, task in list(pending.items()):
                if task.status.value in stale_statuses:
                    age_seconds = (now - task.created_at).total_seconds()
                    if age_seconds > stale_threshold:
                        pending.pop(task_id)
                        cleaned.append(f"{task_id} ({task.task_type}, age: {int(age_seconds)}s)")
                        logger.info(
                            f"Auto-cleaned stale pending task: {task_id} (age: {int(age_seconds)}s)"
                        )

        if not cleaned and not skipped:
            return "No orphaned tasks found to clean up"

        lines = ["🧹 Cleaned up orphaned tasks:"]
        for item in cleaned:
            lines.append(f"  • {item}")
        if skipped:
            lines.append("\n⏭️ Skipped tasks (not stale):")
            for item in skipped:
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
            username = cred.username.strip()
            if not username or username.lower() in {"(none)", "none", "null", "(null)"}:
                continue
            auth = cred.password if cred.password else "[hash]"
            admin_tag = " ⚡ADMIN" if cred.is_admin else ""
            lines.append(f"  • {cred.domain}\\{cred.username}: {auth[:20]}...{admin_tag}")
            lines.append(f"    Source: {cred.source}")

        return "\n".join(lines) if len(lines) > 1 else "No credentials discovered yet"

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
    async def get_exploitation_status(self) -> str:
        """
        Get status of discovered vs exploited vulnerabilities.

        Critical for tracking attack surface coverage.

        Returns:
            Formatted vulnerability status
        """
        discovered = self.shared_state.discovered_vulnerabilities
        status = await self.dispatcher.get_exploitation_status()

        lines = ["🎯 Vulnerability Status:"]

        if not discovered:
            lines.append("  No vulnerabilities discovered")
            return "\n".join(lines)

        pending = []
        succeeded = []
        failed = []

        for vuln in status.get("pending", []):
            info = discovered.get(vuln["id"])
            priority = info.priority if info else "unknown"
            pending.append(f"  ⚠️ [PENDING] {vuln['type']}: {vuln['target']} (priority: {priority})")

        for vuln in status.get("succeeded", []):
            succeeded.append(f"  ✓ [SUCCEEDED] {vuln['type']}: {vuln['target']}")

        for vuln in status.get("failed", []):
            failed.append(f"  ✗ [FAILED] {vuln['type']}: {vuln['target']} (error: {vuln['error']})")

        if pending:
            lines.append("\n⚠️ UNEXPLOITED (high priority):")
            lines.extend(sorted(pending, key=lambda x: "priority" in x))

        if failed:
            lines.append("\n✗ FAILED:")
            lines.extend(failed)

        if succeeded:
            lines.append("\n✓ SUCCEEDED:")
            lines.extend(succeeded)

        lines.append(
            f"\nTotal: {status.get('total_succeeded', 0)} succeeded / "
            f"{status.get('total_failed', 0)} failed / {len(discovered)} discovered"
        )

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
    async def get_operation_summary(self) -> str:
        """
        Get comprehensive operation summary.

        Aggregates all key metrics and achievements.

        Returns:
            Formatted operation summary
        """
        state = self.shared_state
        summary = state.to_summary()
        status = await self.dispatcher.get_exploitation_status()

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
            f"  • Vulnerabilities found: {status.get('total_discovered', summary['vulnerability_count'])}",
            f"  • Vulnerabilities exploited: {status.get('total_succeeded', summary['exploited_count'])}",
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
        username = username.strip()
        if not username or username.lower() in {"(none)", "none", "null", "(null)"}:
            return "[!] Invalid username; credential not broadcast"
        if not (password or hash_value):
            return "[!] Missing password/hash; credential not broadcast"
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
        status = await self.dispatcher.get_exploitation_status()

        lines = ["🎯 Vulnerability Queue Status:"]
        lines.append(f"  Total discovered: {status['total_discovered']}")
        lines.append(f"  Total succeeded: {status.get('total_succeeded', 0)}")
        lines.append(f"  Total failed: {status.get('total_failed', 0)}")

        if status["pending"]:
            lines.append("\n⏳ Pending exploitation:")
            for vuln in status["pending"]:
                lines.append(f"  • [{vuln['type']}] {vuln['target']} (ID: {vuln['id']})")
        else:
            lines.append("\n✓ No vulnerabilities pending exploitation")

        if status.get("failed"):
            lines.append("\n✗ Failed exploitation:")
            for vuln in status["failed"]:
                lines.append(
                    f"  • [{vuln['type']}] {vuln['target']} (ID: {vuln['id']}) - {vuln['error']}"
                )

        if status.get("succeeded"):
            lines.append(f"\n✓ Succeeded: {len(status['succeeded'])} vulnerabilities")

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

        Use this when network recon discovers new systems.

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
            result={
                "credential": {
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "source": f"cracked:{method}",
                },
                "original_hash": original_hash,
                "method": method,
            },
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

    async def _send_via_task_queue(
        self,
        task_id: str,
        *,
        success: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> bool:
        task_queue = self.dispatcher.task_queue
        if not task_queue:
            return False
        if task_id in self.dispatcher.shared_state.pending_tasks:
            return False
        await task_queue.send_result(
            task_id=task_id,
            success=success,
            result=result,
            error=error,
            worker_pod=self._agent_name,
        )
        return True

    @dn.tool_method
    async def report_lateral_success(
        self,
        task_id: str,
        target_host: str,
        method: str,
        new_credentials: str = "",
        new_hashes: str = "",
    ) -> str:
        """
        Report successful lateral movement.

        Args:
            task_id: The original lateral movement task ID
            target_host: Host that was accessed
            method: Method used (psexec/winrm/etc)
            new_credentials: Any new credentials found (JSON format, list of dicts with
                username, password, domain, source fields)
            new_hashes: Any new hashes found (JSON format, list of dicts with
                username, hash_value, hash_type, domain fields)

        Returns:
            Confirmation message
        """
        import json

        result: dict[str, Any] = {
            "target_host": target_host,
            "method": method,
            "success": True,
        }

        # Parse credentials and include in result for complete_task to publish
        if new_credentials:
            try:
                creds = json.loads(new_credentials)
                if isinstance(creds, list):
                    result["credentials"] = creds
                elif isinstance(creds, dict):
                    result["credential"] = creds
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse new_credentials JSON: {new_credentials[:200]}")

        # Parse hashes and include in result for complete_task to publish
        if new_hashes:
            try:
                hashes = json.loads(new_hashes)
                if isinstance(hashes, list):
                    result["hashes"] = hashes
                elif isinstance(hashes, dict):
                    result["hash"] = hashes
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse new_hashes JSON: {new_hashes[:200]}")

        # Calculate extra message for reporting
        cred_count = len(result.get("credentials", [])) or (1 if "credential" in result else 0)
        hash_count = len(result.get("hashes", [])) or (1 if "hash" in result else 0)
        extras = []
        if cred_count:
            extras.append(f"{cred_count} credential(s)")
        if hash_count:
            extras.append(f"{hash_count} hash(es)")
        extra_msg = f" with {', '.join(extras)}" if extras else ""

        if await self._send_via_task_queue(
            task_id,
            success=True,
            result=result,
        ):
            return f"✓ Lateral movement to {target_host} reported{extra_msg}"

        await self.dispatcher.complete_task(
            task_id=task_id,
            success=True,
            result=result,
            source_agent=self._agent_name,
        )

        return f"✓ Lateral movement to {target_host} reported{extra_msg}"

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
        error = f"Lateral to {target_host} failed: {reason}"
        if await self._send_via_task_queue(
            task_id,
            success=False,
            error=error,
        ):
            return f"✗ Lateral movement failed: {reason}"

        await self.dispatcher.complete_task(
            task_id=task_id,
            success=False,
            error=error,
            source_agent=self._agent_name,
        )

        return f"✗ Lateral movement failed: {reason}"


__all__ = [
    "CrackerCallbackTools",
    "LateralCallbackTools",
    "OrchestratorTools",
]
