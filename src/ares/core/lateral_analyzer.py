"""Lateral movement analysis for investigation scope expansion.

This module provides:
1. Graph representation of host-to-host connections
2. Detection of lateral movement patterns
3. Pivot suggestions for investigation scope expansion
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from loguru import logger

if TYPE_CHECKING:
    from datetime import datetime


@dataclass
class HostConnection:
    """Represents a connection between two hosts."""

    source_host: str
    destination_host: str
    connection_type: str  # "smb", "rdp", "wmi", "psexec", "ssh", "winrm", "dcom", etc.
    timestamp: datetime | None = None
    user: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    mitre_technique: str | None = None


@dataclass
class LateralGraph:
    """Graph of host connections for lateral movement analysis.

    Tracks which hosts have been investigated and which connections
    have been discovered between hosts.
    """

    connections: list[HostConnection] = field(default_factory=list)
    investigated_hosts: set[str] = field(default_factory=set)
    pending_hosts: set[str] = field(default_factory=set)

    def add_connection(
        self,
        source: str,
        destination: str,
        conn_type: str,
        timestamp: datetime | None = None,
        user: str | None = None,
        evidence_id: str | None = None,
        mitre_technique: str | None = None,
    ) -> HostConnection:
        """Add a connection to the graph.

        Args:
            source: Source hostname
            destination: Destination hostname
            conn_type: Type of connection (smb, rdp, wmi, etc.)
            timestamp: Optional timestamp of the connection
            user: Optional username associated with the connection
            evidence_id: Optional evidence ID that discovered this connection
            mitre_technique: Optional MITRE technique ID

        Returns:
            The created HostConnection
        """
        # Normalize hostnames
        source = source.lower().strip()
        destination = destination.lower().strip()

        # Don't add self-connections
        if source == destination:
            return None  # type: ignore[return-value]

        conn = HostConnection(
            source_host=source,
            destination_host=destination,
            connection_type=conn_type,
            timestamp=timestamp,
            user=user,
            evidence_ids=[evidence_id] if evidence_id else [],
            mitre_technique=mitre_technique,
        )
        self.connections.append(conn)

        # Mark destination as pending if not yet investigated
        if destination not in self.investigated_hosts:
            self.pending_hosts.add(destination)
            logger.info(f"Added pending host for lateral investigation: {destination}")

        return conn

    def mark_investigated(self, host: str) -> None:
        """Mark a host as investigated.

        Args:
            host: Hostname to mark as investigated
        """
        host = host.lower().strip()
        self.investigated_hosts.add(host)
        self.pending_hosts.discard(host)
        logger.info(f"Marked host as investigated: {host}")

    def get_uninvestigated_targets(self, limit: int = 5) -> list[str]:
        """Get hosts that have been connected to but not investigated.

        Args:
            limit: Maximum number of hosts to return

        Returns:
            List of pending hostnames
        """
        return list(self.pending_hosts)[:limit]

    def get_host_connections(self, host: str) -> list[HostConnection]:
        """Get all connections involving a specific host.

        Args:
            host: Hostname to search for

        Returns:
            List of connections involving the host (as source or destination)
        """
        host = host.lower().strip()
        return [c for c in self.connections if host in (c.source_host, c.destination_host)]

    def get_outgoing_connections(self, host: str) -> list[HostConnection]:
        """Get all outgoing connections from a host.

        Args:
            host: Source hostname

        Returns:
            List of connections originating from the host
        """
        host = host.lower().strip()
        return [c for c in self.connections if c.source_host == host]

    def get_incoming_connections(self, host: str) -> list[HostConnection]:
        """Get all incoming connections to a host.

        Args:
            host: Destination hostname

        Returns:
            List of connections targeting the host
        """
        host = host.lower().strip()
        return [c for c in self.connections if c.destination_host == host]

    def get_unique_users(self) -> set[str]:
        """Get all unique users involved in lateral movement.

        Returns:
            Set of usernames
        """
        return {c.user for c in self.connections if c.user}

    def to_summary(self) -> dict[str, Any]:
        """Generate summary for reports.

        Returns:
            Summary dict with connection statistics
        """
        connection_types: dict[str, int] = {}
        for c in self.connections:
            connection_types[c.connection_type] = connection_types.get(c.connection_type, 0) + 1

        return {
            "total_connections": len(self.connections),
            "hosts_investigated": len(self.investigated_hosts),
            "hosts_pending": len(self.pending_hosts),
            "connection_types": connection_types,
            "unique_users": list(self.get_unique_users()),
            "investigated_hosts_list": list(self.investigated_hosts)[:10],
            "pending_hosts_list": list(self.pending_hosts)[:10],
        }


class LateralMovementAnalyzer:
    """Analyzes query results for lateral movement patterns.

    Automatically detects lateral movement indicators in query results
    and builds a graph of host connections.
    """

    # Patterns for detecting lateral movement types
    LATERAL_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "smb": [
            r"(?i)smb|445|admin\$|c\$|ipc\$",
            r"(?i)tree.*connect|share.*access",
            r"(?i)5140|5145",  # SMB share access events
        ],
        "rdp": [
            r"(?i)rdp|3389|remote.*desktop",
            r"(?i)4624.*logon.*type.*10",
            r"(?i)termsrv|mstsc",
        ],
        "wmi": [
            r"(?i)wmi|135|win32_process|root\\\\cimv2",
            r"(?i)wmic|wmiprvse",
        ],
        "psexec": [
            r"(?i)psexec|7045|service.*install",
            r"(?i)psexesvc|remcom",
        ],
        "winrm": [
            r"(?i)winrm|5985|5986|powershell.*session",
            r"(?i)wsman|enter-pssession",
        ],
        "ssh": [
            r"(?i)ssh|22/tcp|publickey|openssh",
        ],
        "dcom": [
            r"(?i)dcom|135/tcp|mmc20|shellwindows",
            r"(?i)dcomexec|ole32",
        ],
        "scheduled_task": [
            r"(?i)4698|schtasks|taskscheduler",
            r"(?i)at.*exec|scheduled.*task",
        ],
    }

    # MITRE technique mappings for lateral movement types
    TECHNIQUE_MAPPINGS: ClassVar[dict[str, str]] = {
        "smb": "T1021.002",
        "rdp": "T1021.001",
        "wmi": "T1047",
        "psexec": "T1569.002",
        "winrm": "T1021.006",
        "ssh": "T1021.004",
        "dcom": "T1021.003",
        "scheduled_task": "T1053.005",
    }

    def __init__(self, graph: LateralGraph | None = None):
        """Initialize the analyzer.

        Args:
            graph: Optional existing LateralGraph to use
        """
        self.graph = graph or LateralGraph()

    def analyze_query_result(
        self,
        result_data: Any,
        source_host: str | None = None,
    ) -> list[HostConnection]:
        """Analyze query results for lateral movement indicators.

        Args:
            result_data: Query result data to analyze
            source_host: Optional source host for context

        Returns:
            List of discovered connections
        """
        from ares.core.evidence_validation import _extract_searchable_values

        connections: list[HostConnection] = []
        values = _extract_searchable_values(result_data)

        hosts: set[str] = set()
        for val in values:
            if self._looks_like_hostname(val):
                hosts.add(val.lower())

        # Also look for hostnames in the raw result string
        result_str = str(result_data)
        for match in re.findall(r"\b([a-zA-Z][a-zA-Z0-9-]*\.[a-zA-Z0-9.-]+)\b", result_str):
            if self._looks_like_hostname(match):
                hosts.add(match.lower())

        conn_type = self._detect_connection_type(result_str)

        if source_host and hosts:
            source_host = source_host.lower()
            for dest_host in hosts:
                if dest_host != source_host:
                    conn = self.graph.add_connection(
                        source=source_host,
                        destination=dest_host,
                        conn_type=conn_type,
                        mitre_technique=self.TECHNIQUE_MAPPINGS.get(conn_type),
                    )
                    if conn:
                        connections.append(conn)

        return connections

    def _looks_like_hostname(self, value: str) -> bool:
        """Check if a value looks like a hostname.

        Args:
            value: Value to check

        Returns:
            True if value looks like a hostname
        """
        # Must have at least one dot, not start with digit
        if "." not in value or value[0].isdigit():
            return False
        # Must not be an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return False
        # Must be reasonable length
        return 4 <= len(value) <= 255

    def _detect_connection_type(self, result_str: str) -> str:
        """Detect the type of lateral movement from result content.

        Args:
            result_str: String representation of query results

        Returns:
            Connection type string
        """
        result_lower = result_str.lower()

        for conn_type, patterns in self.LATERAL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, result_lower):
                    return conn_type

        return "unknown"

    def get_pivot_suggestions(self) -> list[dict[str, Any]]:
        """Get suggestions for investigating pending hosts.

        Returns:
            List of pivot suggestions with host info and recommended queries
        """
        pending = self.graph.get_uninvestigated_targets()
        suggestions: list[dict[str, Any]] = []

        for host in pending:
            # Find how this host was discovered
            conns = self.graph.get_host_connections(host)
            sources = list({c.source_host for c in conns if c.destination_host == host})
            connection_types = list({c.connection_type for c in conns})

            suggestions.append(
                {
                    "host": host,
                    "discovered_from": sources,
                    "connection_types": connection_types,
                    "priority": len(conns),  # More connections = higher priority
                    "suggested_queries": [
                        f'{{hostname=~".*{host}.*"}} |~ "(?i)4624|4625|logon"',
                        f'{{job=~".+"}} |~ "(?i){host}"',
                    ],
                    "suggested_actions": [
                        f"Call track_host_investigation('{host}')",
                        f"Run detect_lateral_movement(source_host='{host}')",
                        f"Run get_host_activity('{host}')",
                    ],
                }
            )

        # Sort by priority (most connections first)
        suggestions.sort(key=lambda x: x["priority"], reverse=True)
        return suggestions

    def get_attack_path(self) -> list[str]:
        """Reconstruct the likely attack path based on connections.

        Returns:
            List of hostnames in likely attack order
        """
        if not self.graph.connections:
            return []

        # Find hosts that are only sources (likely initial compromise)
        destinations = {c.destination_host for c in self.graph.connections}
        sources = {c.source_host for c in self.graph.connections}

        # Entry points: sources that are not destinations
        entry_points = sources - destinations

        # If no clear entry point, use most investigated hosts
        if not entry_points:
            entry_points = sources

        path: list[str] = []
        visited: set[str] = set()

        def dfs(host: str) -> None:
            if host in visited:
                return
            visited.add(host)
            path.append(host)

            # Visit outgoing connections
            for conn in self.graph.get_outgoing_connections(host):
                dfs(conn.destination_host)

        for entry in sorted(entry_points):
            dfs(entry)

        return path
