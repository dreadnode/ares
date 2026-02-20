"""Pre-built query templates for detecting red team attack patterns.

Provides ready-to-use LogQL queries mapped to MITRE ATT&CK techniques,
specifically designed to detect attacks performed by the Ares red team agent.
"""

from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import dreadnode as dn
import httpx
from dreadnode.agent.tools.base import Toolset
from loguru import logger

# Type alias for MCP query function signature:
# (datasource_uid, logql, start_time, end_time, limit) -> result
MCPQueryFn = Callable[[str, str, str, str, int], Awaitable[Any]]


class QueryTemplateTools(Toolset):  # type: ignore[misc]
    """Pre-built query templates for detecting red team attack patterns.

    These templates encode detection logic for Active Directory attacks,
    specifically aligned with the techniques used by the Ares red team agent:
    - Network recon (nmap, user/share recon)
    - Credential access (secretsdump, kerberoasting, AS-REP roasting)
    - Lateral movement (pass-the-hash, psexec, wmi)
    - Privilege escalation (ADCS, delegation, golden ticket)

    Query Optimization (per Grafana Loki best practices):
    - Label selectors are the most important filter - narrow them first
    - Use |= (contains) before |~ (regex) - contains is faster
    - Put most selective filters (event IDs) first
    - Avoid {job=~".+"} - use specific labels when possible

    Attributes:
        loki_url: Base URL of the Loki instance (fallback for direct HTTP queries).
        timeout: HTTP request timeout in seconds.
        default_label_selector: Base label selector for queries. Defaults to
            '{job="windows-security"}' for Windows Security event logs. Override for other log
            types (e.g., '{job="windows-system"}', '{job="windows-application"}').
            NEVER use broad patterns like '{job=~".+"}' - they scan all streams and timeout.
        default_hours_back: Default time range for queries. Shorter ranges are faster.
        mcp_query_fn: Optional MCP query function for authenticated Loki queries.
            If provided, uses MCP instead of direct HTTP calls to avoid auth issues.
        datasource_uid: Loki datasource UID for MCP queries (default: "loki").
    """

    loki_url: str
    timeout: int = 30
    default_label_selector: str = '{job="windows-security"}'
    default_hours_back: int = 1  # Reduced from 4 hours for faster queries
    mcp_query_fn: MCPQueryFn | None = None
    datasource_uid: str = "loki"

    def _build_selector(
        self,
        hostname: str | None = None,
        extra_labels: dict[str, str] | None = None,
    ) -> str:
        """Build an optimized label selector.

        Args:
            hostname: Optional hostname to filter by (uses regex match).
            extra_labels: Additional label key-value pairs.

        Returns:
            LogQL label selector string like '{job="x", hostname=~"dc.*"}'
        """
        # Start with base selector, strip outer braces to add more labels
        base = self.default_label_selector.strip("{}")

        parts = [base] if base else []

        if hostname:
            # Use regex without leading .* for better performance
            # Loki optimizes hostname=~"dc" better than hostname=~".*dc.*"
            parts.append(f'hostname=~"{hostname}"')

        if extra_labels:
            for key, value in extra_labels.items():
                # Use exact match for known values, regex for patterns
                if "*" in value or "." in value:
                    parts.append(f'{key}=~"{value}"')
                else:
                    parts.append(f'{key}="{value}"')

        return "{" + ", ".join(parts) + "}"

    def _build_event_filter(self, event_ids: list[str]) -> str:
        """Build an optimized filter for Windows Event IDs.

        Uses |= (contains) instead of regex since event IDs are exact strings.
        Per Grafana docs: "Loki evaluates contains faster than regex."

        Args:
            event_ids: List of Windows Event IDs like ["4624", "4625"]

        Returns:
            LogQL filter string like '|= "4624" or |= "4625"'
        """
        if not event_ids:
            return ""
        if len(event_ids) == 1:
            return f'|= "{event_ids[0]}"'
        # For multiple IDs, use regex alternation (Loki optimizes simple alternations)
        return '|~ "(' + "|".join(event_ids) + ')"'

    def _build_pattern_filter(self, patterns: list[str], case_insensitive: bool = True) -> str:
        """Build a regex filter for tool/attack patterns.

        Args:
            patterns: List of patterns to match.
            case_insensitive: Whether to use case-insensitive matching.

        Returns:
            LogQL filter string.
        """
        if not patterns:
            return ""
        prefix = "(?i)" if case_insensitive else ""
        return f'|~ "{prefix}({"|".join(patterns)})"'

    async def _query_loki(
        self,
        logql: str,
        start_time: str,
        end_time: str,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Execute a LogQL query against Loki.

        Uses MCP query function if available (preferred, handles authentication).
        Falls back to direct HTTP calls if MCP is not configured.
        """
        if '=~".*"' in logql or "=~'.*'" in logql:
            return {
                "status": "error",
                "error": "Query contains empty-compatible regex '.*'. Use '.+' instead.",
            }

        # Prefer MCP-based query if available (handles auth correctly)
        if self.mcp_query_fn is not None:
            try:
                logger.debug(f"Using MCP query_loki_logs for: {logql[:100]}...")
                result = await self.mcp_query_fn(
                    self.datasource_uid,
                    logql,
                    start_time,
                    end_time,
                    min(limit, 100),  # MCP tool has max 100 limit
                )
                # MCP returns list of results, wrap in standard format
                if isinstance(result, list):
                    return {
                        "status": "success",
                        "data": {"result": result},
                    }
                return result
            except Exception as e:
                logger.error(f"MCP Loki query failed: {e}")
                return {"status": "error", "error": str(e), "data": {"result": []}}

        # Fallback to direct HTTP (may fail with 302 redirect if auth required)
        logger.warning(
            "Using direct HTTP for Loki query - this may fail with auth errors. "
            "Consider passing mcp_query_fn for authenticated queries."
        )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.loki_url}/loki/api/v1/query_range",
                    params={
                        "query": logql,
                        "start": start_time,
                        "end": end_time,
                        "limit": limit,
                    },
                )
                # Check for redirect (common auth issue)
                if response.status_code == 302:
                    logger.error(
                        "Loki returned 302 redirect - authentication required. "
                        "Use MCP-based queries (mcp_query_fn) for authenticated access."
                    )
                    return {
                        "status": "error",
                        "error": "Authentication required (302 redirect). Use MCP query tools.",
                        "data": {"result": []},
                    }
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Loki query failed: {e}")
            return {"status": "error", "error": str(e), "data": {"result": []}}

    def _get_time_range(self, hours_back: int | None = None) -> tuple[str, str]:
        """Get ISO8601 time range for queries.

        Args:
            hours_back: Hours to look back. Defaults to self.default_hours_back (1 hour).

        Returns:
            Tuple of (start_time, end_time) in ISO8601 format.
        """
        if hours_back is None:
            hours_back = self.default_hours_back
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)
        return start.isoformat(), now.isoformat()

    def _count_results(self, result: dict) -> int:
        """Count total log entries in result."""
        streams = result.get("data", {}).get("result", [])
        return sum(len(s.get("values", [])) for s in streams)

    # =========================================================================
    # UNIFIED DETECTION QUERY DISPATCHER
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def run_detection_query(
        self,
        query_name: str,
        target_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Run a pre-built detection query by name.

        Use list_query_templates() first to see available queries.
        Each query targets a specific MITRE ATT&CK technique.

        Args:
            query_name: Name of the detection query (e.g. "detect_dcsync",
                "detect_pass_the_hash", "detect_kerberoasting").
                Use list_query_templates() to see all available names.
            target_host: Optional hostname/IP to focus detection on.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with detection indicators and MITRE mappings.
        """
        method = getattr(self, query_name, None)
        if method is None or not query_name.startswith("detect_"):
            available = [
                t["name"] for t in self.list_query_templates() if t["name"].startswith("detect_")
            ]
            return {
                "status": "error",
                "error": f"Unknown query: '{query_name}'. Available: {available}",
            }

        # All detect_* methods accept (target_host_or_ip, hours_back) as first two args
        try:
            return await method(target_host, hours_back)
        except TypeError:
            # Some methods use different param names, try without target
            return await method(hours_back=hours_back)

    # =========================================================================
    # RECONNAISSANCE & DISCOVERY (TA0007)
    # Maps to: nmap_scan, enumerate_users, enumerate_shares
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_port_scanning(
        self,
        target_ip: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect network port scanning activity (nmap, masscan).

        Detects reconnaissance performed by red team's nmap_scan tool.
        Looks for rapid connection attempts to multiple ports.

        MITRE ATT&CK: T1046 (Network Service Discovery)

        Args:
            target_ip: Optional IP to focus detection on.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with port scanning indicators.
        """
        dn.log_metric("query_template_port_scan", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector()
        # Use simple contains for common tool names, regex only for complex patterns
        tool_filter = self._build_pattern_filter(
            ["nmap", "masscan", "syn.scan", "port.scan", "connection.refused"]
        )

        logql = f"{selector} {tool_filter}"

        if target_ip:
            logql += f' |= "{target_ip}"'  # Use contains for IP (faster than regex)

        logger.info(f"Port scanning detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "port_scanning"
        result["_mitre_technique"] = "T1046"
        result["_red_team_tool"] = "nmap_scan"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_user_enumeration(
        self,
        domain_controller: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect Active Directory user recon.

        Detects reconnaissance performed by red team's enumerate_users tool (netexec --users).
        Looks for LDAP queries, net user commands, and SMB-based recon.

        MITRE ATT&CK: T1087.002 (Account Discovery: Domain Account)

        Args:
            domain_controller: Optional DC hostname to focus on.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with user recon indicators.
        """
        dn.log_metric("query_template_user_enum", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=domain_controller)

        # Event IDs first (most selective), then tool patterns
        # Event 4662: Object access (LDAP queries)
        # Event 4798: User's group membership enumerated
        # Event 4799: Security-enabled group membership enumerated
        event_filter = self._build_event_filter(["4662", "4798", "4799"])
        tool_filter = self._build_pattern_filter(
            [
                "samr",
                "lsarpc",
                "ldap",
                "net.user",
                "net.group",
                "enumerate",
                "crackmapexec",
                "netexec",
                "ldapsearch",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"User recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "user_enumeration"
        result["_mitre_technique"] = "T1087.002"
        result["_red_team_tool"] = "enumerate_users"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_share_enumeration(
        self,
        target_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect SMB share recon.

        Detects reconnaissance performed by red team's enumerate_shares tool (netexec --shares).
        Looks for share listing, access attempts, and smbclient activity.

        MITRE ATT&CK: T1135 (Network Share Discovery)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with share recon indicators.
        """
        dn.log_metric("query_template_share_enum", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=target_host)

        # Event IDs first (most selective)
        # Event 5140: Network share accessed
        # Event 5145: Detailed file share access
        event_filter = self._build_event_filter(["5140", "5145"])
        tool_filter = self._build_pattern_filter(
            [
                "srvsvc",
                "netuse",
                "net.share",
                "net.view",
                "smbclient",
                "crackmapexec",
                "netexec",
                "enum.share",
                "share.enum",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"Share recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "share_enumeration"
        result["_mitre_technique"] = "T1135"
        result["_red_team_tool"] = "enumerate_shares"

        return result

    # =========================================================================
    # CREDENTIAL ACCESS (TA0006)
    # Maps to: secretsdump, kerberoast, asrep_roast, crack_with_hashcat
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_secretsdump(
        self,
        target_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect credential dumping via impacket-secretsdump.

        Detects red team's secretsdump tool which extracts:
        - SAM database (local accounts)
        - LSA secrets
        - NTDS.dit (domain accounts)
        - Cached domain credentials

        MITRE ATT&CK: T1003 (OS Credential Dumping)
        Sub-techniques: T1003.001 (LSASS), T1003.002 (SAM), T1003.003 (NTDS), T1003.004 (LSA)

        Args:
            target_host: Optional hostname to focus on.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with secretsdump indicators.
        """
        dn.log_metric("query_template_secretsdump", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=target_host)
        tool_filter = self._build_pattern_filter(
            [
                "drsuapi",
                "samr",
                "secretsdump",
                "lsadump",
                "ntds.dit",
                "sam.dump",
                "replicate",
                "1131f6",
                "ds-replication",
                "mimikatz",
                "impacket",
            ]
        )

        logql = f"{selector} {tool_filter}"

        logger.info(f"Secretsdump detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "secretsdump"
        result["_mitre_technique"] = "T1003"
        result["_mitre_subtechniques"] = ["T1003.001", "T1003.002", "T1003.003", "T1003.004"]
        result["_red_team_tool"] = "secretsdump"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_dcsync(
        self,
        domain_controller: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect DCSync attack (secretsdump against DC).

        DCSync allows attackers with replication rights to extract all domain credentials
        including krbtgt hash (enables golden ticket). Critical to detect.

        MITRE ATT&CK: T1003.006 (DCSync)

        Args:
            domain_controller: Optional DC hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with DCSync indicators.
        """
        dn.log_metric("query_template_dcsync", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=domain_controller)
        # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
        # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All
        event_filter = self._build_event_filter(["4662"])
        tool_filter = self._build_pattern_filter(
            [
                "dcsync",
                "ds-replication",
                "1131f6aa",
                "1131f6ad",
                "replication",
                "drsuapi",
                "directory.service.access",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"DCSync detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "dcsync"
        result["_mitre_technique"] = "T1003.006"
        result["_red_team_tool"] = "secretsdump"
        result["_severity"] = "critical"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_kerberoasting(
        self,
        domain_controller: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect Kerberoasting attack (impacket-GetUserSPNs).

        Detects red team's kerberoast tool which requests TGS tickets for
        service accounts with SPNs. These tickets can be cracked offline.

        MITRE ATT&CK: T1558.003 (Kerberoasting)

        Args:
            domain_controller: Optional DC hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with Kerberoasting indicators.
        """
        dn.log_metric("query_template_kerberoast", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=domain_controller)
        event_filter = self._build_event_filter(["4769"])
        tool_filter = self._build_pattern_filter(
            [
                "kerberos.ticket",
                "tgs.request",
                "getuserspn",
                "service.ticket",
                "spn",
                "rc4",
                "0x17",
                "kerberoast",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"Kerberoasting detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "kerberoasting"
        result["_mitre_technique"] = "T1558.003"
        result["_red_team_tool"] = "kerberoast"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_asrep_roasting(
        self,
        domain_controller: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect AS-REP Roasting attack (impacket-GetNPUsers).

        Detects red team's asrep_roast tool which targets accounts with
        'Do not require Kerberos preauthentication' enabled.

        MITRE ATT&CK: T1558.004 (AS-REP Roasting)

        Args:
            domain_controller: Optional DC hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with AS-REP roasting indicators.
        """
        dn.log_metric("query_template_asrep", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=domain_controller)
        # Event 4768: Kerberos TGT Request (AS-REQ)
        # Event 4771: Kerberos Pre-Authentication Failed
        event_filter = self._build_event_filter(["4768", "4771"])
        tool_filter = self._build_pattern_filter(
            [
                "as-req",
                "getnpusers",
                "asrep",
                "pre.auth",
                "tgt.request",
                "roast",
                "dont.require.preauth",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"AS-REP roasting detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "asrep_roasting"
        result["_mitre_technique"] = "T1558.004"
        result["_red_team_tool"] = "asrep_roast"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_brute_force(
        self,
        target_host: str | None = None,
        hours_back: int | None = None,
        threshold: int = 10,
    ) -> dict[str, Any]:
        """Detect brute force and password spray attacks.

        Detects credential stuffing attempts from red team's authentication tests.
        Looks for multiple failed logins from same source or against multiple accounts.

        MITRE ATT&CK: T1110 (Brute Force), T1110.003 (Password Spraying)

        Args:
            target_host: Optional hostname to focus on.
            hours_back: Hours of logs to search (default: 1 hour).
            threshold: Minimum failures to flag (default 10).

        Returns:
            Query results with auth failure analysis.
        """
        dn.log_metric("query_template_brute_force", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=target_host)
        # Event 4625: Failed Logon
        # Event 4771: Kerberos Pre-Auth Failed
        event_filter = self._build_event_filter(["4625", "4771"])
        # Use contains for common failure keywords (faster than regex)
        logql = f'{selector} {event_filter} |~ "(?i)(failed|invalid|denied)" |~ "(?i)(logon|auth)"'

        logger.info(f"Brute force detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=1000)

        # Analyze patterns
        total_failures = self._count_results(result)
        result["_analysis"] = {
            "total_failures": total_failures,
            "is_likely_attack": total_failures >= threshold,
            "recommendation": (
                "High auth failure volume - investigate source IPs and target accounts"
                if total_failures >= threshold
                else "Normal failure volume"
            ),
        }
        result["_query_template"] = "brute_force"
        result["_mitre_technique"] = "T1110"

        return result

    # =========================================================================
    # LATERAL MOVEMENT (TA0008)
    # Maps to: domain_admin_checker (pass-the-hash), netexec
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_pass_the_hash(
        self,
        target_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect Pass-the-Hash attacks.

        Detects red team's domain_admin_checker using NTLM hashes for auth.
        Looks for NTLM authentications without corresponding password usage.

        MITRE ATT&CK: T1550.002 (Pass the Hash)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with PtH indicators.
        """
        dn.log_metric("query_template_pth", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=target_host)
        event_filter = self._build_event_filter(["4624"])
        tool_filter = self._build_pattern_filter(
            [
                "ntlm",
                "ntlmssp",
                "pass.the.hash",
                "logon.type.3",
                "network.logon",
                "crackmapexec",
                "netexec",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"Pass-the-Hash detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "pass_the_hash"
        result["_mitre_technique"] = "T1550.002"
        result["_red_team_tool"] = "domain_admin_checker"
        result["_auto_pivot"] = True  # Triggers auto-pivot investigation

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_lateral_movement(
        self,
        source_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect lateral movement patterns.

        Detects various lateral movement techniques used during post-exploitation:
        - PSExec service creation
        - WMI execution
        - WinRM/PowerShell remoting
        - SMB admin share access

        MITRE ATT&CK: T1021 (Remote Services)

        Args:
            source_host: Optional source to pivot from.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with lateral movement indicators.
        """
        dn.log_metric("query_template_lateral", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=source_host)
        # Event 7045: Service installed
        # Event 4648: Explicit credential logon
        event_filter = self._build_event_filter(["7045", "4648"])
        tool_filter = self._build_pattern_filter(
            [
                "psexec",
                "wmic",
                "winrm",
                "powershell.-session",
                "admin\\$",
                "c\\$",
                "ipc\\$",
                "service.install",
                "remote.execution",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"Lateral movement detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "lateral_movement"
        result["_mitre_technique"] = "T1021"
        result["_mitre_subtechniques"] = ["T1021.002", "T1021.003", "T1021.006"]
        result["_auto_pivot"] = True  # Triggers auto-pivot investigation

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_smb_file_access(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect suspicious file access on SMB shares.

        Detects red team's share pilfering tools (enumerate_share_files, download_file_content).
        Looks for access to sensitive files like scripts, configs, GPP XML.

        MITRE ATT&CK: T1039 (Data from Network Shared Drive)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with file access indicators.
        """
        dn.log_metric("query_template_smb_access", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Event 5145: Detailed file share access
        # Look for sensitive file extensions and paths
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(5145|file.*access|share.*access|smbclient)"'
            ' |~ "(?i)(\\.ps1|\\.bat|\\.cmd|\\.xml|\\.config|sysvol|netlogon|groups\\.xml)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"SMB file access detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "smb_file_access"
        result["_mitre_technique"] = "T1039"
        result["_red_team_tools"] = ["enumerate_share_files", "download_file_content"]

        return result

    # =========================================================================
    # PRIVILEGE ESCALATION (TA0004)
    # Maps to: certipy (ADCS), delegation tools, bloodhound
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_adcs_exploitation(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect ADCS certificate abuse (ESC1-ESC15).

        Detects red team's certipy tools exploiting certificate template misconfigurations.
        ESC1 is particularly dangerous - allows requesting certs for any user.

        MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with ADCS exploitation indicators.
        """
        dn.log_metric("query_template_adcs", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Event 4886: Certificate request submitted
        # Event 4887: Certificate Services approved certificate request
        # Look for certipy patterns, suspicious certificate requests
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(4886|4887|4876|certipy|certificate.*request)"'
            ' |~ "(?i)(esc[0-9]|enrollee.*supplies.*subject|altname|upn)"'
        )

        logger.info(f"ADCS exploitation detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "adcs_exploitation"
        result["_mitre_technique"] = "T1649"
        result["_red_team_tools"] = ["certipy_find", "certipy_req_esc1", "certipy_auth"]
        result["_severity"] = "high"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_delegation_abuse(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect Kerberos delegation attacks (RBCD, unconstrained, constrained).

        Detects red team's delegation tools for privilege escalation:
        - Resource-Based Constrained Delegation (RBCD)
        - Unconstrained delegation exploitation
        - S4U2Self/S4U2Proxy abuse

        MITRE ATT&CK: T1134.001 (Token Impersonation/Theft)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with delegation abuse indicators.
        """
        dn.log_metric("query_template_delegation", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Look for: msDS-AllowedToActOnBehalfOfOtherIdentity modification
        # S4U2Self/S4U2Proxy ticket requests, delegation attribute changes
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(delegation|msds-allowedtoactonbehalf|rbcd|s4u2)"'
            ' |~ "(?i)(impersonate|constrained|unconstrained|getst|addcomputer)"'
        )

        logger.info(f"Delegation abuse detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "delegation_abuse"
        result["_mitre_technique"] = "T1134.001"
        result["_red_team_tools"] = ["find_delegation", "add_computer", "rbcd_write", "get_st"]

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_bloodhound_collection(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect BloodHound/SharpHound data collection.

        Detects red team's BloodHound collection which maps AD relationships
        to find privilege escalation paths.

        MITRE ATT&CK: T1087 (Account Discovery), T1069 (Permission Groups Discovery)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with BloodHound collection indicators.
        """
        dn.log_metric("query_template_bloodhound", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # LDAP recon patterns, BloodHound/SharpHound signatures
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(bloodhound|sharphound|adexplorer|ldap.*query)"'
            ' |~ "(?i)(acl|objectsid|memberof|primarygroup|msds)"'
        )

        logger.info(f"BloodHound collection detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "bloodhound_collection"
        result["_mitre_techniques"] = ["T1087", "T1069", "T1482"]
        result["_red_team_tool"] = "run_bloodhound"

        return result

    # =========================================================================
    # PERSISTENCE (TA0003)
    # Maps to: golden_ticket
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_golden_ticket(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect Golden Ticket creation and usage.

        Detects red team's golden ticket generation (impacket-ticketer).
        Golden tickets provide persistent domain admin access using krbtgt hash.

        MITRE ATT&CK: T1558.001 (Golden Ticket)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with Golden Ticket indicators.
        """
        dn.log_metric("query_template_golden_ticket", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Event 4769 with suspicious patterns (krbtgt access, invalid timestamps)
        # Look for ticketer tool patterns, krbtgt references
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(golden.*ticket|krbtgt|ticketer|krbcred)"'
            ' |~ "(?i)(forged|4769|kerberos.*ticket|enterprise.*admin)"'
        )

        logger.info(f"Golden ticket detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "golden_ticket"
        result["_mitre_technique"] = "T1558.001"
        result["_red_team_tool"] = "generate_golden_ticket"
        result["_severity"] = "critical"

        return result

    # =========================================================================
    # EXECUTION (TA0002)
    # Maps to: general command execution patterns
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_suspicious_execution(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect suspicious command execution.

        Detects encoded PowerShell, LOLBins, and script interpreter abuse
        commonly used during post-exploitation.

        MITRE ATT&CK: T1059 (Command and Scripting Interpreter)

        Args:
            target_host: Optional hostname to focus on.
            hours_back: Hours of logs to search.

        Returns:
            Query results with execution indicators.
        """
        dn.log_metric("query_template_execution", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Event 4688: Process Creation (with command line logging)
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(4688|powershell|pwsh|cmd\\.exe|wscript|cscript)"'
            ' |~ "(?i)(encodedcommand|bypass|hidden|downloadstring|invoke)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Suspicious execution detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "suspicious_execution"
        result["_mitre_technique"] = "T1059"

        return result

    # =========================================================================
    # ADCS/CERTIPY SPECIFIC DETECTIONS (ESC1-ESC11)
    # Maps to: certipy_find, certipy_req_esc1, certipy_auth
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_certipy_enumeration(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect Certipy certificate template recon.

        Detects red team's certipy_find tool scanning for vulnerable certificate
        templates. This is the reconnaissance phase before ADCS exploitation.

        MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with Certipy recon indicators.
        """
        dn.log_metric("query_template_certipy_enum", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Certipy recon queries LDAP for certificate templates
        # Look for: msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag queries
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(certipy|ldap|389|636)"'
            ' |~ "(?i)(mspki|pkienrollmentservice|certificatetemplates|pki)"'
        )

        logger.info(f"Certipy recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "certipy_enumeration"
        result["_mitre_technique"] = "T1649"
        result["_red_team_tool"] = "certipy_find"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_esc1_attack(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect ESC1 - Enrollee Supplies Subject attack.

        ESC1 allows attackers to request certificates with arbitrary Subject
        Alternative Names (SANs), enabling impersonation of any user including
        Domain Admins. This is the most critical ADCS vulnerability.

        MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with ESC1 attack indicators.
        """
        dn.log_metric("query_template_esc1", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # ESC1 indicators:
        # - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in template
        # - Certificate request with SAN different from requester
        # - Event 4886/4887 with suspicious SAN
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(4886|4887|certificate.*request|certipy)"'
            ' |~ "(?i)(san=|subjectaltname|upn=|enrollee.*supplies|ct_flag)"'
        )

        logger.info(f"ESC1 attack detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "esc1_attack"
        result["_mitre_technique"] = "T1649"
        result["_red_team_tool"] = "certipy_req_esc1"
        result["_severity"] = "critical"
        result["_description"] = "ESC1: Enrollee supplies subject - allows impersonation"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_esc4_attack(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect ESC4 - Vulnerable Certificate Template ACL attack.

        ESC4 exploits misconfigured ACLs on certificate templates where low-priv
        users have write access to modify template settings.

        MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with ESC4 attack indicators.
        """
        dn.log_metric("query_template_esc4", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # ESC4 involves modifying certificate template attributes
        # Event 5136: Directory service object modified (on certificate template)
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(5136|ldap.*modify|template.*modif)"'
            ' |~ "(?i)(pki|certificatetemplate|mspki|enrollmentflag)"'
        )

        logger.info(f"ESC4 attack detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "esc4_attack"
        result["_mitre_technique"] = "T1649"
        result["_severity"] = "high"
        result["_description"] = "ESC4: Certificate template ACL modification"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_esc8_attack(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect ESC8 - NTLM Relay to AD CS HTTP Endpoints.

        ESC8 exploits AD CS web enrollment endpoints (certsrv) via NTLM relay.
        Attackers coerce authentication then relay to the CA to request certs.

        MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with ESC8 attack indicators.
        """
        dn.log_metric("query_template_esc8", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # ESC8 indicators:
        # - HTTP requests to /certsrv/certfnsh.asp
        # - NTLM relay patterns
        # - PetitPotam/PrinterBug coercion followed by cert request
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(certsrv|certfnsh|certenroll|ntlmrelayx)"'
            ' |~ "(?i)(relay|coerce|petitpotam|printerbug|dfscoerce)"'
        )

        logger.info(f"ESC8 attack detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "esc8_attack"
        result["_mitre_technique"] = "T1649"
        result["_severity"] = "critical"
        result["_description"] = "ESC8: NTLM relay to AD CS web enrollment"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_certificate_authentication(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect authentication using stolen/forged certificates.

        Detects red team's certipy_auth using certificates for PKINIT auth
        to obtain TGTs and NTLM hashes.

        MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with cert auth indicators.
        """
        dn.log_metric("query_template_cert_auth", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # PKINIT authentication, certificate-based Kerberos
        # Event 4768 with certificate auth
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(pkinit|pkca|smartcard|certificate.*auth)"'
            ' |~ "(?i)(4768|tgt.*request|kerberos|certipy.*auth)"'
        )

        logger.info(f"Certificate authentication detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "certificate_authentication"
        result["_mitre_technique"] = "T1649"
        result["_red_team_tool"] = "certipy_auth"

        return result

    # =========================================================================
    # BLOODHOUND SPECIFIC LDAP QUERY SIGNATURES
    # Maps to: run_bloodhound
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_bloodhound_domain_enum(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect BloodHound domain trust and forest recon.

        BloodHound queries for cross-domain trust relationships and forest
        topology to map potential attack paths.

        MITRE ATT&CK: T1482 (Domain Trust Discovery)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with domain enum indicators.
        """
        dn.log_metric("query_template_bh_domain", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # BloodHound domain recon LDAP queries:
        # - trusteddomain objectclass queries
        # - crossRef objects for forest structure
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(ldap|389|636|bloodhound|sharphound)"'
            ' |~ "(?i)(trusteddomain|crossref|trusttype|trustdirection|trustattributes)"'
        )

        logger.info(f"BloodHound domain recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "bloodhound_domain_enum"
        result["_mitre_technique"] = "T1482"
        result["_red_team_tool"] = "run_bloodhound"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_bloodhound_acl_enum(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect BloodHound ACL/DACL recon.

        BloodHound's ACL collection queries for nTSecurityDescriptor on AD
        objects to find privilege escalation paths via ACL abuse.

        MITRE ATT&CK: T1069.002 (Permission Groups Discovery: Domain Groups)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with ACL recon indicators.
        """
        dn.log_metric("query_template_bh_acl", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # BloodHound ACL collection LDAP patterns:
        # - nTSecurityDescriptor attribute requests
        # - Large LDAP queries for DACL
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(ldap|389|636|bloodhound|sharphound)"'
            ' |~ "(?i)(ntsecuritydescriptor|dacl|securitydescriptor|allowedtoactonbehalf)"'
        )

        logger.info(f"BloodHound ACL recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "bloodhound_acl_enum"
        result["_mitre_technique"] = "T1069.002"
        result["_red_team_tool"] = "run_bloodhound"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_bloodhound_session_enum(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect BloodHound session recon.

        BloodHound enumerates active user sessions on computers using
        NetSessionEnum and NetWkstaUserEnum APIs to map where users are logged in.

        MITRE ATT&CK: T1033 (System Owner/User Discovery)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with session enum indicators.
        """
        dn.log_metric("query_template_bh_session", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Session recon APIs:
        # - NetSessionEnum (srvsvc)
        # - NetWkstaUserEnum (wkssvc)
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(srvsvc|wkssvc|netsession|netwksta)"'
            ' |~ "(?i)(enum|bloodhound|sharphound|session.*collection)"'
        )

        logger.info(f"BloodHound session recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "bloodhound_session_enum"
        result["_mitre_technique"] = "T1033"
        result["_red_team_tool"] = "run_bloodhound"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_bloodhound_gpo_enum(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect BloodHound GPO recon.

        BloodHound enumerates Group Policy Objects to find GPO-based attack
        paths and privilege escalation opportunities.

        MITRE ATT&CK: T1615 (Group Policy Discovery)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with GPO enum indicators.
        """
        dn.log_metric("query_template_bh_gpo", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # GPO recon queries:
        # - groupPolicyContainer objectclass
        # - gPLink, gPCFileSysPath attributes
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(ldap|389|636|bloodhound|sharphound)"'
            ' |~ "(?i)(grouppolicycontainer|gplink|gpcfilesyspath|gpo)"'
        )

        logger.info(f"BloodHound GPO recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "bloodhound_gpo_enum"
        result["_mitre_technique"] = "T1615"
        result["_red_team_tool"] = "run_bloodhound"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_bloodhound_computer_enum(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect BloodHound computer recon.

        BloodHound queries for computer objects with specific attributes
        to identify targets for lateral movement.

        MITRE ATT&CK: T1018 (Remote System Discovery)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with computer enum indicators.
        """
        dn.log_metric("query_template_bh_computer", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Computer recon with BloodHound-specific attributes:
        # - operatingsystem, operatingsystemversion
        # - serviceprincipalname, msds-allowedtodelegateto
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(ldap|389|636|bloodhound|sharphound)"'
            ' |~ "(?i)(objectclass=computer|operatingsystem|serviceprincipalname|allowedtodelegateto)"'
        )

        logger.info(f"BloodHound computer recon detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "bloodhound_computer_enum"
        result["_mitre_technique"] = "T1018"
        result["_red_team_tool"] = "run_bloodhound"

        return result

    # =========================================================================
    # IMPACKET TOOL FINGERPRINTS
    # Maps to: secretsdump, smbclient, wmiexec, psexec, atexec, dcomexec
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_wmiexec(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-wmiexec remote execution.

        Wmiexec uses WMI for semi-interactive shell, creating processes via
        Win32_Process.Create. Output retrieved via SMB temp files.

        MITRE ATT&CK: T1047 (Windows Management Instrumentation)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with wmiexec indicators.
        """
        dn.log_metric("query_template_wmiexec", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Wmiexec patterns:
        # - WMI process creation events
        # - cmd.exe /Q /c with output redirection to ADMIN$
        # - __InstanceCreationEvent subscription
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(wmi|win32_process|root\\\\cimv2)"'
            ' |~ "(?i)(wmiexec|impacket|cmd.*\\/q.*\\/c|127\\.0\\.0\\.1.*admin\\$)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Wmiexec detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_wmiexec"
        result["_mitre_technique"] = "T1047"
        result["_red_team_tool"] = "wmiexec"
        result["_auto_pivot"] = True  # Triggers auto-pivot investigation

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_psexec(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-psexec remote execution.

        Psexec uploads a service executable to ADMIN$ share, creates and starts
        a service, then communicates via named pipe. Creates distinctive events.

        MITRE ATT&CK: T1569.002 (Service Execution)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with psexec indicators.
        """
        dn.log_metric("query_template_psexec", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Psexec patterns:
        # - Event 7045: Service installed (random 8-char name)
        # - Service binary in ADMIN$ or C:\Windows
        # - RemComSvc or similar service names
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(7045|service.*install|psexec|remcom)"'
            ' |~ "(?i)(admin\\$|\\\\\\\\.*\\\\admin|service.*creat|cmd\\.exe)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Psexec detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_psexec"
        result["_mitre_technique"] = "T1569.002"
        result["_red_team_tool"] = "psexec"
        result["_auto_pivot"] = True  # Triggers auto-pivot investigation

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_smbexec(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-smbexec remote execution.

        Smbexec creates a service that executes commands via cmd.exe with
        output redirected to a share file. More stealthy than psexec.

        MITRE ATT&CK: T1569.002 (Service Execution)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with smbexec indicators.
        """
        dn.log_metric("query_template_smbexec", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Smbexec patterns:
        # - Service with cmd.exe /Q /c echo command
        # - BTOBTO service name pattern (default)
        # - Output to C:\__output or __output
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(7045|service|smbexec)"'
            ' |~ "(?i)(btobto|cmd.*echo.*\\^>|__output|execute\\.bat)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Smbexec detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_smbexec"
        result["_mitre_technique"] = "T1569.002"
        result["_red_team_tool"] = "smbexec"
        result["_auto_pivot"] = True  # Triggers auto-pivot investigation

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_atexec(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-atexec remote execution.

        Atexec uses the Task Scheduler (ATSVC) to create scheduled tasks
        for command execution. Creates Event 4698 (scheduled task created).

        MITRE ATT&CK: T1053.002 (Scheduled Task)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with atexec indicators.
        """
        dn.log_metric("query_template_atexec", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Atexec patterns:
        # - Event 4698: Scheduled task created
        # - Task name pattern (random characters)
        # - cmd.exe /C execution in task
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(4698|4699|4700|4701|schtask|taskscheduler|atsvc)"'
            ' |~ "(?i)(atexec|impacket|cmd.*\\/c|schtasks)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Atexec detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_atexec"
        result["_mitre_technique"] = "T1053.002"
        result["_red_team_tool"] = "atexec"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_dcomexec(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-dcomexec remote execution.

        Dcomexec uses DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow)
        to execute commands remotely. Operates over TCP 135 (RPC).

        MITRE ATT&CK: T1021.003 (DCOM)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with dcomexec indicators.
        """
        dn.log_metric("query_template_dcomexec", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Dcomexec patterns:
        # - DCOM/RPC connections
        # - MMC20.Application, ShellWindows, ShellBrowserWindow instantiation
        # - Process created by mmc.exe or explorer.exe
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(dcom|135/tcp|rpc|mmc20|shellwindows|shellbrowser)"'
            ' |~ "(?i)(dcomexec|impacket|executeshellcommand|document\\.application)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Dcomexec detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_dcomexec"
        result["_mitre_technique"] = "T1021.003"
        result["_red_team_tool"] = "dcomexec"
        result["_auto_pivot"] = True  # Triggers auto-pivot investigation

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_secretsdump_sam(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-secretsdump SAM database dump.

        Secretsdump can dump local SAM database by accessing registry hives
        remotely via SMB. Retrieves local account hashes.

        MITRE ATT&CK: T1003.002 (SAM)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with SAM dump indicators.
        """
        dn.log_metric("query_template_secretsdump_sam", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # SAM dump patterns:
        # - Remote registry access to SAM, SYSTEM, SECURITY hives
        # - Event 4663: Object access on registry
        # - reg save commands
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(registry|hklm|winreg|samr)"'
            ' |~ "(?i)(sam|system|security|secretsdump|reg.*save)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"SAM dump detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_secretsdump_sam"
        result["_mitre_technique"] = "T1003.002"
        result["_red_team_tool"] = "secretsdump"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_secretsdump_lsa(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-secretsdump LSA secrets dump.

        Secretsdump extracts LSA secrets which may contain service account
        passwords, autologon credentials, and other sensitive data.

        MITRE ATT&CK: T1003.004 (LSA Secrets)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with LSA dump indicators.
        """
        dn.log_metric("query_template_secretsdump_lsa", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # LSA secrets dump patterns:
        # - SECURITY hive access
        # - LSA policy queries
        # - $MACHINE.ACC, DefaultPassword, NL$KM patterns
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(lsa|security|policy|secrets)"'
            ' |~ "(?i)(\\$machine|defaultpassword|nl\\$|dpapi|secretsdump)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"LSA secrets dump detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_secretsdump_lsa"
        result["_mitre_technique"] = "T1003.004"
        result["_red_team_tool"] = "secretsdump"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_ntlmrelayx(
        self,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-ntlmrelayx NTLM relay attacks.

        Ntlmrelayx intercepts NTLM authentication and relays it to target
        services like SMB, LDAP, HTTP for unauthorized access.

        MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Coercion and SMB Relay)

        Args:
            hours_back: Hours of logs to search.

        Returns:
            Query results with NTLM relay indicators.
        """
        dn.log_metric("query_template_ntlmrelayx", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # NTLM relay patterns:
        # - Authentication from unexpected source IP
        # - Rapid auth attempts with same NTLM challenge
        # - SMB signing not required warnings
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(ntlm|relay|responder|inveigh)"'
            ' |~ "(?i)(ntlmrelayx|smbrelay|signing.*not.*required|coerce)"'
        )

        logger.info(f"NTLM relay detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_ntlmrelayx"
        result["_mitre_technique"] = "T1557.001"
        result["_red_team_tool"] = "ntlmrelayx"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_impacket_smbclient(
        self,
        target_host: str | None = None,
        hours_back: int = 4,
    ) -> dict[str, Any]:
        """Detect impacket-smbclient share access.

        Smbclient provides interactive SMB access for recon and
        file operations on remote shares.

        MITRE ATT&CK: T1021.002 (SMB/Windows Admin Shares)

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search.

        Returns:
            Query results with smbclient indicators.
        """
        dn.log_metric("query_template_smbclient", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Smbclient patterns:
        # - Interactive SMB session characteristics
        # - Multiple share recon
        # - File browsing patterns
        logql = (
            f"{self._build_selector()}"
            ' |~ "(?i)(smb|445/tcp|cifs|smbclient)"'
            ' |~ "(?i)(impacket|tree.*connect|shares.*enum|file.*access)"'
        )

        if target_host:
            logql = self._build_selector(hostname=target_host) + logql.split("}", 1)[1]

        logger.info(f"Smbclient detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "impacket_smbclient"
        result["_mitre_technique"] = "T1021.002"
        result["_red_team_tool"] = "smbclient"

        return result

    # =========================================================================
    # ADDITIONAL CREDENTIAL ACCESS DETECTIONS
    # Maps to: S4U delegation abuse, DCSync with GUIDs, LSA secrets, RemoteRegistry
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_s4u_delegation(
        self,
        domain_controller: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect S4U2Self/S4U2Proxy constrained delegation abuse.

        Detects red team's constrained delegation exploitation using impacket-getST
        to impersonate privileged users via S4U protocol extensions.

        MITRE ATT&CK: T1558.003 (Kerberoasting - S4U variant)

        Detection logic:
        - Event 4769: TGS request with S4U ticket options
        - Impersonation of privileged accounts (Administrator, Domain Admins)
        - Service ticket requests to sensitive SPNs (CIFS, HTTP on DCs)

        Args:
            domain_controller: Optional DC hostname to focus on.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with S4U delegation abuse indicators.
        """
        dn.log_metric("query_template_s4u_delegation", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=domain_controller)
        # Event 4769: Kerberos Service Ticket Operations
        event_filter = self._build_event_filter(["4769"])
        # S4U patterns and impersonation indicators
        tool_filter = self._build_pattern_filter(
            [
                "s4u2self",
                "s4u2proxy",
                "constrained.delegation",
                "impersonate",
                "forwardable",
                "getst",
                "cifs/",
                "http/",
                "administrator",
                "trustedfordelegation",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"S4U delegation detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "s4u_delegation"
        result["_mitre_technique"] = "T1558.003"
        result["_red_team_tool"] = "get_st"
        result["_severity"] = "critical"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_dcsync_replication(
        self,
        domain_controller: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect DCSync attacks using DS-Replication GUIDs.

        Detects red team's secretsdump DCSync by looking for Event 4662
        with specific DS-Replication-Get-Changes GUIDs that indicate
        directory replication requests.

        MITRE ATT&CK: T1003.006 (DCSync)

        Detection logic:
        - Event 4662: Directory Service Access with replication GUIDs
        - GUIDs: 1131f6aa (Get-Changes), 1131f6ad (Get-Changes-All),
                 89e95b76 (Get-Changes-In-Filtered-Set)

        Args:
            domain_controller: Optional DC hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with DCSync indicators.
        """
        dn.log_metric("query_template_dcsync_replication", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=domain_controller)
        # Event 4662: Operation performed on directory object
        event_filter = self._build_event_filter(["4662"])
        # DS-Replication GUIDs
        guid_filter = self._build_pattern_filter(
            [
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
                "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
                "1131f6aa",  # Short form
                "1131f6ad",  # Short form
                "89e95b76",  # Short form
            ],
            case_insensitive=True,
        )

        logql = f"{selector} {event_filter} {guid_filter}"

        logger.info(f"DCSync replication detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "dcsync_replication"
        result["_mitre_technique"] = "T1003.006"
        result["_red_team_tool"] = "secretsdump"
        result["_severity"] = "critical"
        result["_attack_chain_indicator"] = "domain_admin"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_lsa_secrets_access(
        self,
        target_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect LSA Secrets extraction attempts.

        Detects red team's secretsdump LSA secrets extraction which
        targets cached credentials, service account passwords, and
        other sensitive data stored in registry.

        MITRE ATT&CK: T1003.004 (LSA Secrets)

        Detection logic:
        - Events 4656/4663: Object handle/access to LSA secrets keys
        - Registry access to SECURITY\\Policy\\Secrets
        - secretsdump tool patterns

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with LSA secrets access indicators.
        """
        dn.log_metric("query_template_lsa_secrets", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        selector = self._build_selector(hostname=target_host)
        # Events for object access
        event_filter = self._build_event_filter(["4656", "4663", "4658"])
        # LSA secrets patterns
        tool_filter = self._build_pattern_filter(
            [
                "security.policy.secrets",
                "lsa.secrets",
                "dpapi",
                "defaultpassword",
                "nlkm",
                "cachedlogon",
                "lsadump",
                "reg.query.*security",
            ]
        )

        logql = f"{selector} {event_filter} {tool_filter}"

        logger.info(f"LSA secrets access detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "lsa_secrets_access"
        result["_mitre_technique"] = "T1003.004"
        result["_red_team_tool"] = "secretsdump"
        result["_severity"] = "high"

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def detect_remote_registry_start(
        self,
        target_host: str | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Detect RemoteRegistry service being started remotely.

        Detects red team's secretsdump enabling RemoteRegistry to
        extract bootKey and registry secrets from remote hosts.

        MITRE ATT&CK: T1569.002 (Service Execution)

        Detection logic:
        - Event 7036: Service Control Manager (service state change)
        - RemoteRegistry service being started
        - Often precedes credential dumping

        Args:
            target_host: Optional target hostname.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            Query results with RemoteRegistry service indicators.
        """
        dn.log_metric("query_template_remote_registry", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Use System log for service events (7036/7045 are in Windows System log)
        if target_host:
            selector = f'{{job="windows-system", hostname=~"{target_host}"}}'
        else:
            selector = '{job="windows-system"}'

        # Event 7036: Service Control Manager
        logql = f'{selector} |~ "(7036|7045)" |~ "(?i)(remoteregistry|remote.registry)" |~ "(?i)(running|started|start)"'

        logger.info(f"RemoteRegistry service detection: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=500)
        result["_query_template"] = "remote_registry_start"
        result["_mitre_technique"] = "T1569.002"
        result["_red_team_tool"] = "secretsdump"
        result["_severity"] = "medium"
        result["_precursor_indicator"] = "credential_dumping"

        return result

    # =========================================================================
    # HOST/USER INVESTIGATION HELPERS
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_host_activity(
        self,
        hostname: str,
        hours_back: int | None = None,
        attack_patterns_only: bool = False,
    ) -> dict[str, Any]:
        """Get all activity for a specific host.

        Comprehensive query to gather logs for a host during investigation.
        Can optionally filter to only show attack-related patterns.

        Args:
            hostname: Hostname to investigate.
            hours_back: Hours of logs to search (default: 1 hour).
            attack_patterns_only: If True, filter for attack patterns only.

        Returns:
            All log activity for the specified host.
        """
        dn.log_metric("query_template_host_activity", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Build optimized selector - use hostname without leading .*
        # Per Grafana docs: Loki optimizes hostname=~"dc" better than hostname=~".*dc.*"
        selector = self._build_selector(hostname=hostname)

        if attack_patterns_only:
            # Event IDs first (most selective) for attack pattern filtering
            event_filter = self._build_event_filter(
                ["4625", "4624", "4662", "4769", "4768", "5140", "7045", "4688"]
            )
            logql = f"{selector} {event_filter}"
        else:
            logql = selector

        logger.info(f"Host activity query: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=1000)
        result["_query_template"] = "host_activity"
        result["_target_host"] = hostname

        return result

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_user_activity(
        self,
        username: str,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """Get all activity for a specific user.

        Comprehensive query to gather all logs mentioning a user account.

        Args:
            username: Username to investigate.
            hours_back: Hours of logs to search (default: 1 hour).

        Returns:
            All log activity mentioning the specified user.
        """
        dn.log_metric("query_template_user_activity", 1, mode="count")
        start_time, end_time = self._get_time_range(hours_back)

        # Build selector with default labels, filter by username in log content
        selector = self._build_selector()
        # Use contains |= for exact username match when possible, regex for flexible
        logql = f'{selector} |~ "(?i){username}"'

        logger.info(f"User activity query: {logql}")

        result = await self._query_loki(logql, start_time, end_time, limit=1000)
        result["_query_template"] = "user_activity"
        result["_target_user"] = username

        return result

    # =========================================================================
    # TEMPLATE LISTING
    # =========================================================================

    @dn.tool_method  # type: ignore[untyped-decorator]
    def list_query_templates(self) -> list[dict[str, Any]]:
        """List all available query templates with MITRE mappings.

        Returns:
            List of templates organized by attack phase, with red team tool correlation.
        """
        return [
            # Reconnaissance
            {
                "name": "detect_port_scanning",
                "description": "Detect nmap/masscan port scanning",
                "mitre": "T1046",
                "tactic": "discovery",
                "red_team_tool": "nmap_scan",
            },
            {
                "name": "detect_user_enumeration",
                "description": "Detect AD user account recon",
                "mitre": "T1087.002",
                "tactic": "discovery",
                "red_team_tool": "enumerate_users",
            },
            {
                "name": "detect_share_enumeration",
                "description": "Detect SMB share discovery",
                "mitre": "T1135",
                "tactic": "discovery",
                "red_team_tool": "enumerate_shares",
            },
            # Credential Access
            {
                "name": "detect_secretsdump",
                "description": "Detect credential dumping via secretsdump",
                "mitre": "T1003",
                "tactic": "credential_access",
                "red_team_tool": "secretsdump",
            },
            {
                "name": "detect_dcsync",
                "description": "Detect DCSync attack against domain controller",
                "mitre": "T1003.006",
                "tactic": "credential_access",
                "red_team_tool": "secretsdump",
                "severity": "critical",
            },
            {
                "name": "detect_kerberoasting",
                "description": "Detect Kerberoasting TGS ticket requests",
                "mitre": "T1558.003",
                "tactic": "credential_access",
                "red_team_tool": "kerberoast",
            },
            {
                "name": "detect_asrep_roasting",
                "description": "Detect AS-REP roasting attacks",
                "mitre": "T1558.004",
                "tactic": "credential_access",
                "red_team_tool": "asrep_roast",
            },
            {
                "name": "detect_brute_force",
                "description": "Detect brute force/password spray attempts",
                "mitre": "T1110",
                "tactic": "credential_access",
                "red_team_tool": None,
            },
            {
                "name": "detect_s4u_delegation",
                "description": "Detect S4U2Self/S4U2Proxy constrained delegation abuse",
                "mitre": "T1558.003",
                "tactic": "credential_access",
                "red_team_tool": "get_st",
                "severity": "critical",
            },
            {
                "name": "detect_dcsync_replication",
                "description": "Detect DCSync via DS-Replication GUIDs (4662)",
                "mitre": "T1003.006",
                "tactic": "credential_access",
                "red_team_tool": "secretsdump",
                "severity": "critical",
            },
            {
                "name": "detect_lsa_secrets_access",
                "description": "Detect LSA Secrets extraction attempts",
                "mitre": "T1003.004",
                "tactic": "credential_access",
                "red_team_tool": "secretsdump",
                "severity": "high",
            },
            {
                "name": "detect_remote_registry_start",
                "description": "Detect RemoteRegistry service start (precursor to dumping)",
                "mitre": "T1569.002",
                "tactic": "execution",
                "red_team_tool": "secretsdump",
                "severity": "medium",
            },
            # Lateral Movement
            {
                "name": "detect_pass_the_hash",
                "description": "Detect Pass-the-Hash NTLM attacks",
                "mitre": "T1550.002",
                "tactic": "lateral_movement",
                "red_team_tool": "domain_admin_checker",
            },
            {
                "name": "detect_lateral_movement",
                "description": "Detect PSExec, WMI, WinRM lateral movement",
                "mitre": "T1021",
                "tactic": "lateral_movement",
                "red_team_tool": None,
            },
            {
                "name": "detect_smb_file_access",
                "description": "Detect suspicious file access on shares",
                "mitre": "T1039",
                "tactic": "collection",
                "red_team_tool": "download_file_content",
            },
            # Privilege Escalation
            {
                "name": "detect_adcs_exploitation",
                "description": "Detect ADCS certificate abuse (ESC1-15)",
                "mitre": "T1649",
                "tactic": "privilege_escalation",
                "red_team_tool": "certipy_*",
                "severity": "high",
            },
            {
                "name": "detect_delegation_abuse",
                "description": "Detect RBCD/delegation privilege escalation",
                "mitre": "T1134.001",
                "tactic": "privilege_escalation",
                "red_team_tool": "rbcd_write",
            },
            {
                "name": "detect_bloodhound_collection",
                "description": "Detect BloodHound AD recon",
                "mitre": "T1087",
                "tactic": "discovery",
                "red_team_tool": "run_bloodhound",
            },
            # Persistence
            {
                "name": "detect_golden_ticket",
                "description": "Detect Golden Ticket creation/usage",
                "mitre": "T1558.001",
                "tactic": "persistence",
                "red_team_tool": "generate_golden_ticket",
                "severity": "critical",
            },
            # Execution
            {
                "name": "detect_suspicious_execution",
                "description": "Detect encoded PowerShell, LOLBins",
                "mitre": "T1059",
                "tactic": "execution",
                "red_team_tool": None,
            },
            # ADCS/Certipy Specific (ESC attacks)
            {
                "name": "detect_certipy_enumeration",
                "description": "Detect Certipy certificate template recon",
                "mitre": "T1649",
                "tactic": "discovery",
                "red_team_tool": "certipy_find",
            },
            {
                "name": "detect_esc1_attack",
                "description": "Detect ESC1 - Enrollee Supplies Subject attack",
                "mitre": "T1649",
                "tactic": "privilege_escalation",
                "red_team_tool": "certipy_req_esc1",
                "severity": "critical",
            },
            {
                "name": "detect_esc4_attack",
                "description": "Detect ESC4 - Certificate template ACL modification",
                "mitre": "T1649",
                "tactic": "privilege_escalation",
                "severity": "high",
            },
            {
                "name": "detect_esc8_attack",
                "description": "Detect ESC8 - NTLM relay to AD CS HTTP endpoints",
                "mitre": "T1649",
                "tactic": "privilege_escalation",
                "severity": "critical",
            },
            {
                "name": "detect_certificate_authentication",
                "description": "Detect authentication using stolen/forged certificates",
                "mitre": "T1649",
                "tactic": "credential_access",
                "red_team_tool": "certipy_auth",
            },
            # BloodHound Specific LDAP Queries
            {
                "name": "detect_bloodhound_domain_enum",
                "description": "Detect BloodHound domain trust recon",
                "mitre": "T1482",
                "tactic": "discovery",
                "red_team_tool": "run_bloodhound",
            },
            {
                "name": "detect_bloodhound_acl_enum",
                "description": "Detect BloodHound ACL/DACL collection",
                "mitre": "T1069.002",
                "tactic": "discovery",
                "red_team_tool": "run_bloodhound",
            },
            {
                "name": "detect_bloodhound_session_enum",
                "description": "Detect BloodHound session recon (NetSessionEnum)",
                "mitre": "T1033",
                "tactic": "discovery",
                "red_team_tool": "run_bloodhound",
            },
            {
                "name": "detect_bloodhound_gpo_enum",
                "description": "Detect BloodHound GPO recon",
                "mitre": "T1615",
                "tactic": "discovery",
                "red_team_tool": "run_bloodhound",
            },
            {
                "name": "detect_bloodhound_computer_enum",
                "description": "Detect BloodHound computer object recon",
                "mitre": "T1018",
                "tactic": "discovery",
                "red_team_tool": "run_bloodhound",
            },
            # Impacket Tool Fingerprints
            {
                "name": "detect_impacket_wmiexec",
                "description": "Detect impacket-wmiexec WMI remote execution",
                "mitre": "T1047",
                "tactic": "execution",
                "red_team_tool": "wmiexec",
            },
            {
                "name": "detect_impacket_psexec",
                "description": "Detect impacket-psexec service-based execution",
                "mitre": "T1569.002",
                "tactic": "execution",
                "red_team_tool": "psexec",
            },
            {
                "name": "detect_impacket_smbexec",
                "description": "Detect impacket-smbexec stealthy service execution",
                "mitre": "T1569.002",
                "tactic": "execution",
                "red_team_tool": "smbexec",
            },
            {
                "name": "detect_impacket_atexec",
                "description": "Detect impacket-atexec scheduled task execution",
                "mitre": "T1053.002",
                "tactic": "execution",
                "red_team_tool": "atexec",
            },
            {
                "name": "detect_impacket_dcomexec",
                "description": "Detect impacket-dcomexec DCOM remote execution",
                "mitre": "T1021.003",
                "tactic": "lateral_movement",
                "red_team_tool": "dcomexec",
            },
            {
                "name": "detect_impacket_secretsdump_sam",
                "description": "Detect secretsdump SAM database extraction",
                "mitre": "T1003.002",
                "tactic": "credential_access",
                "red_team_tool": "secretsdump",
            },
            {
                "name": "detect_impacket_secretsdump_lsa",
                "description": "Detect secretsdump LSA secrets extraction",
                "mitre": "T1003.004",
                "tactic": "credential_access",
                "red_team_tool": "secretsdump",
            },
            {
                "name": "detect_impacket_ntlmrelayx",
                "description": "Detect NTLM relay attacks (ntlmrelayx)",
                "mitre": "T1557.001",
                "tactic": "credential_access",
                "red_team_tool": "ntlmrelayx",
            },
            {
                "name": "detect_impacket_smbclient",
                "description": "Detect impacket-smbclient share access",
                "mitre": "T1021.002",
                "tactic": "lateral_movement",
                "red_team_tool": "smbclient",
            },
            # Investigation Helpers
            {
                "name": "get_host_activity",
                "description": "Get all activity for a specific host",
                "mitre": None,
                "tactic": "investigation",
                "red_team_tool": None,
            },
            {
                "name": "get_user_activity",
                "description": "Get all activity for a specific user",
                "mitre": None,
                "tactic": "investigation",
                "red_team_tool": None,
            },
        ]
