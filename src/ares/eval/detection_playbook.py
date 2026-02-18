"""
Detection playbook generation from red team operations.

Transforms red team operation state into actionable detection guidance
for blue team agents and security engineers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from ares.core.models import PyramidLevel

if TYPE_CHECKING:
    from ares.core.models import SharedRedTeamState


@dataclass
class PlaybookQuery:
    """A specific LogQL query to detect an attack.

    Attributes:
        technique_id: MITRE ATT&CK technique ID.
        technique_name: Human-readable technique name.
        description: What this query detects.
        logql: The actual LogQL query with IOCs filled in.
        label_selector: The Loki label selector (e.g., '{job="windows-security"}').
        expected_evidence: What evidence should be found.
        time_window_start: Start of relevant time window.
        time_window_end: End of relevant time window.
        priority: Query priority (critical, high, medium, low).
        windows_event_ids: Related Windows Event IDs.
    """

    technique_id: str
    technique_name: str
    description: str
    logql: str
    label_selector: str = '{job="windows-security"}'
    expected_evidence: list[str] = field(default_factory=list)
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None
    priority: str = "medium"
    windows_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "description": self.description,
            "logql": self.logql,
            "label_selector": self.label_selector,
            "expected_evidence": self.expected_evidence,
            "time_window": {
                "start": self.time_window_start.isoformat() if self.time_window_start else None,
                "end": self.time_window_end.isoformat() if self.time_window_end else None,
            },
            "priority": self.priority,
            "windows_event_ids": self.windows_event_ids,
        }


@dataclass
class DetectionTarget:
    """An IOC with specific detection guidance.

    Attributes:
        ioc_type: Type of IOC (ip, user, hash, hostname, domain).
        value: The actual IOC value.
        pyramid_level: Pyramid of Pain level (1-6).
        context: How this IOC was discovered/used.
        detection_queries: LogQL patterns to detect this IOC.
        log_sources: Log sources where this IOC should appear.
        mitre_techniques: Related MITRE techniques.
    """

    ioc_type: str
    value: str
    pyramid_level: int
    context: str = ""
    detection_queries: list[str] = field(default_factory=list)
    log_sources: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "pyramid_level": self.pyramid_level,
            "pyramid_level_name": _pyramid_level_name(self.pyramid_level),
            "context": self.context,
            "detection_queries": self.detection_queries,
            "log_sources": self.log_sources,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class TechniqueDetection:
    """Detection guidance for a specific MITRE technique.

    Attributes:
        technique_id: MITRE ATT&CK technique ID.
        technique_name: Human-readable name.
        description: What the attacker did with this technique.
        occurred_at: Timestamps when technique was used.
        targets: IPs/hosts affected.
        credentials_used: Accounts used in this technique.
        detection_queries: Specific queries to detect this technique.
        windows_event_ids: Windows Event IDs to monitor.
        log_sources: Log sources to query.
        detection_guidance: Human-readable detection advice.
    """

    technique_id: str
    technique_name: str = ""
    description: str = ""
    occurred_at: list[datetime] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    credentials_used: list[str] = field(default_factory=list)
    detection_queries: list[PlaybookQuery] = field(default_factory=list)
    windows_event_ids: list[str] = field(default_factory=list)
    log_sources: list[str] = field(default_factory=list)
    detection_guidance: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "description": self.description,
            "occurred_at": [t.isoformat() for t in self.occurred_at],
            "targets": self.targets,
            "credentials_used": self.credentials_used,
            "detection_queries": [q.to_dict() for q in self.detection_queries],
            "windows_event_ids": self.windows_event_ids,
            "log_sources": self.log_sources,
            "detection_guidance": self.detection_guidance,
        }


@dataclass
class DetectionPlaybook:
    """Complete detection playbook from a red team operation.

    This is the primary export format for blue team consumption.
    Contains everything needed to detect the attacks that occurred.

    Attributes:
        operation_id: Red team operation ID.
        generated_at: When this playbook was generated.
        attack_window_start: Start of attack activity.
        attack_window_end: End of attack activity.
        techniques_used: List of MITRE technique IDs used.
        total_credentials: Number of credentials harvested.
        total_hosts: Number of hosts discovered.
        achieved_domain_admin: Whether DA was achieved.
        domain_admin_path: Attack path to domain admin.
        technique_detections: Detection guidance per technique.
        detection_targets: IOCs with detection guidance.
        priority_queries: Top queries to run first (sorted by priority).
        executive_summary: Human-readable summary.
    """

    operation_id: str
    generated_at: datetime
    attack_window_start: datetime
    attack_window_end: datetime

    # Summary stats
    techniques_used: list[str] = field(default_factory=list)
    total_credentials: int = 0
    total_hosts: int = 0
    achieved_domain_admin: bool = False
    domain_admin_path: str | None = None

    # Detections
    technique_detections: dict[str, TechniqueDetection] = field(default_factory=dict)
    detection_targets: list[DetectionTarget] = field(default_factory=list)
    priority_queries: list[PlaybookQuery] = field(default_factory=list)

    # Summary
    executive_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "operation_id": self.operation_id,
            "generated_at": self.generated_at.isoformat(),
            "attack_window": {
                "start": self.attack_window_start.isoformat(),
                "end": self.attack_window_end.isoformat(),
                "duration_minutes": int(
                    (self.attack_window_end - self.attack_window_start).total_seconds() / 60
                ),
            },
            "summary": {
                "techniques_used": self.techniques_used,
                "technique_count": len(self.techniques_used),
                "total_credentials": self.total_credentials,
                "total_hosts": self.total_hosts,
                "achieved_domain_admin": self.achieved_domain_admin,
                "domain_admin_path": self.domain_admin_path,
            },
            "executive_summary": self.executive_summary,
            "technique_detections": {k: v.to_dict() for k, v in self.technique_detections.items()},
            "detection_targets": [t.to_dict() for t in self.detection_targets],
            "priority_queries": [q.to_dict() for q in self.priority_queries],
        }

    def to_markdown(self) -> str:
        """Generate markdown report for human consumption."""
        lines = [
            "# Detection Playbook",
            "",
            f"**Operation ID:** `{self.operation_id}`",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Attack Window:** {self.attack_window_start.strftime('%Y-%m-%d %H:%M')} to {self.attack_window_end.strftime('%Y-%m-%d %H:%M')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
            "---",
            "",
            "## Attack Statistics",
            "",
            f"- **Techniques Used:** {len(self.techniques_used)}",
            f"- **Credentials Harvested:** {self.total_credentials}",
            f"- **Hosts Discovered:** {self.total_hosts}",
            f"- **Domain Admin Achieved:** {'Yes' if self.achieved_domain_admin else 'No'}",
        ]

        if self.domain_admin_path:
            lines.append(f"- **DA Path:** {self.domain_admin_path}")

        lines.extend(["", "---", "", "## Priority Detection Queries", ""])

        if self.priority_queries:
            lines.append(
                "Run these queries first - they target the most critical attack techniques."
            )
            lines.append("")

            for i, query in enumerate(self.priority_queries[:10], 1):
                lines.extend(
                    [
                        f"### {i}. {query.technique_id}: {query.technique_name}",
                        "",
                        f"**Priority:** {query.priority.upper()}",
                        f"**Description:** {query.description}",
                        "",
                        "```logql",
                        query.logql,
                        "```",
                        "",
                    ]
                )

                if query.windows_event_ids:
                    lines.append(f"**Event IDs:** {', '.join(query.windows_event_ids)}")
                if query.expected_evidence:
                    lines.append(f"**Expected Evidence:** {', '.join(query.expected_evidence)}")
                lines.append("")

        lines.extend(["---", "", "## Detection Targets (IOCs)", ""])

        if self.detection_targets:
            lines.append("| Type | Value | Pyramid Level | Detection |")
            lines.append("|------|-------|---------------|-----------|")

            for target in sorted(self.detection_targets, key=lambda t: -t.pyramid_level)[:20]:
                value_display = (
                    target.value[:40] + "..." if len(target.value) > 40 else target.value
                )
                level_name = _pyramid_level_name(target.pyramid_level)
                detection_preview = (
                    target.detection_queries[0][:30] + "..." if target.detection_queries else "N/A"
                )
                lines.append(
                    f"| {target.ioc_type} | `{value_display}` | {level_name} | {detection_preview} |"
                )

        lines.extend(["", "---", "", "## Technique-Specific Detections", ""])

        for tech_id, detection in sorted(self.technique_detections.items()):
            lines.extend(
                [
                    f"### {tech_id}: {detection.technique_name}",
                    "",
                    detection.description or "No description available.",
                    "",
                ]
            )

            if detection.targets:
                lines.append(f"**Targets:** {', '.join(detection.targets[:5])}")
            if detection.credentials_used:
                lines.append(f"**Credentials Used:** {', '.join(detection.credentials_used[:5])}")
            if detection.windows_event_ids:
                lines.append(f"**Event IDs to Monitor:** {', '.join(detection.windows_event_ids)}")

            if detection.detection_guidance:
                lines.extend(["", f"**Detection Guidance:** {detection.detection_guidance}"])

            if detection.detection_queries:
                lines.extend(["", "**Queries:**", ""])
                for query in detection.detection_queries[:3]:
                    lines.extend(["```logql", query.logql, "```", ""])

            lines.append("")

        lines.extend(
            [
                "---",
                "",
                "*Generated by Ares Detection Playbook Export*",
            ]
        )

        return "\n".join(lines)


def create_detection_playbook(state: SharedRedTeamState) -> DetectionPlaybook:
    """Create a detection playbook from red team operation state.

    Transforms the red team's discovered data into actionable detection
    guidance that blue team agents can use to build and run detections.

    Args:
        state: Red team operation state.

    Returns:
        DetectionPlaybook with queries, IOCs, and detection guidance.
    """
    now = datetime.now(timezone.utc)
    attack_start = state.started_at or now - timedelta(hours=1)
    attack_end = state.completed_at or now

    playbook = DetectionPlaybook(
        operation_id=state.operation_id,
        generated_at=now,
        attack_window_start=attack_start,
        attack_window_end=attack_end,
        techniques_used=list(state.identified_techniques),
        total_credentials=len(state.all_credentials),
        total_hosts=len(state.all_hosts),
        achieved_domain_admin=state.has_domain_admin,
        domain_admin_path=state.domain_admin_path,
    )

    # Build detection targets from IOCs
    detection_targets = []
    priority_queries = []
    technique_detections: dict[str, TechniqueDetection] = {}

    # Extract hosts as detection targets
    for host in state.all_hosts:
        target = DetectionTarget(
            ioc_type="ip",
            value=host.ip,
            pyramid_level=PyramidLevel.IP_ADDRESSES,
            context=f"Discovered host: {host.hostname or 'unknown'}",
            detection_queries=[
                f'{{job="windows-security"}} |= "{host.ip}"',
                f'{{job="firewall"}} |= "{host.ip}"',
            ],
            log_sources=["windows-security", "firewall", "netflow"],
            mitre_techniques=["T1046"],
        )
        detection_targets.append(target)

        if host.hostname:
            detection_targets.append(
                DetectionTarget(
                    ioc_type="hostname",
                    value=host.hostname,
                    pyramid_level=PyramidLevel.DOMAIN_NAMES,
                    context=f"Host: {host.ip}",
                    detection_queries=[
                        f'{{job="windows-security"}} |~ "(?i){host.hostname}"',
                    ],
                    log_sources=["windows-security", "dns"],
                    mitre_techniques=["T1046"],
                )
            )

    # Extract credentials as detection targets
    for cred in state.all_credentials:
        account_name = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
        target = DetectionTarget(
            ioc_type="user",
            value=account_name,
            pyramid_level=PyramidLevel.NETWORK_HOST_ARTIFACTS,
            context=f"Compromised credential (source: {cred.source or 'unknown'})",
            detection_queries=[
                f'{{job="windows-security"}} |~ "(?i)(4624|4625|4648)" |~ "(?i){cred.username}"',
                f'{{job="windows-security"}} |~ "(?i)LogonType.*(3|10)" |~ "(?i){cred.username}"',
            ],
            log_sources=["windows-security"],
            mitre_techniques=["T1078", "T1003"],
        )
        detection_targets.append(target)

    # Extract hashes as detection targets
    for hash_obj in state.all_hashes:
        # Only include NTLM hashes for detection (not full hash values for security)
        hash_preview = (
            hash_obj.hash_value[:16] + "..."
            if len(hash_obj.hash_value) > 16
            else hash_obj.hash_value
        )
        target = DetectionTarget(
            ioc_type="hash",
            value=f"{hash_obj.username}:{hash_preview}",
            pyramid_level=PyramidLevel.HASH_VALUES,
            context=f"Dumped from {hash_obj.source or 'unknown'}",
            detection_queries=[
                f'{{job="windows-security"}} |= "4624" |~ "(?i){hash_obj.username}" |~ "NTLM"',
            ],
            log_sources=["windows-security"],
            mitre_techniques=["T1003"],
        )
        detection_targets.append(target)

    # Build technique-specific detections
    technique_detections = _build_technique_detections(state, attack_start, attack_end)

    # Build priority queries
    priority_queries = _build_priority_queries(state, attack_start, attack_end)

    # Generate executive summary
    summary_parts = []

    summary_parts.append(
        f"Red team operation {state.operation_id} ran from "
        f"{attack_start.strftime('%Y-%m-%d %H:%M')} to {attack_end.strftime('%Y-%m-%d %H:%M')} UTC."
    )

    if state.has_domain_admin:
        summary_parts.append(
            "**CRITICAL:** Domain Admin was achieved. "
            "Focus detection efforts on the attack path and lateral movement."
        )

    summary_parts.append(
        f"The attack used {len(state.identified_techniques)} MITRE ATT&CK techniques, "
        f"compromised {len(state.all_credentials)} credentials, "
        f"and discovered {len(state.all_hosts)} hosts."
    )

    if state.exploited_vulnerabilities:
        summary_parts.append(
            f"Exploited {len(state.exploited_vulnerabilities)} vulnerabilities. "
            "Review technique detections below for specific guidance."
        )

    playbook.detection_targets = detection_targets
    playbook.technique_detections = technique_detections
    playbook.priority_queries = priority_queries
    playbook.executive_summary = " ".join(summary_parts)

    return playbook


def _build_technique_detections(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> dict[str, TechniqueDetection]:
    """Build detection guidance for each technique used."""
    detections: dict[str, TechniqueDetection] = {}

    # Map of technique IDs to detection builders
    technique_builders = {
        "T1046": _build_t1046_detection,  # Network Service Discovery
        "T1003": _build_t1003_detection,  # OS Credential Dumping
        "T1003.001": _build_t1003_001_detection,  # LSASS Memory
        "T1003.006": _build_t1003_006_detection,  # DCSync
        "T1078": _build_t1078_detection,  # Valid Accounts
        "T1078.002": _build_t1078_002_detection,  # Domain Accounts
        "T1110": _build_t1110_detection,  # Brute Force
        "T1558": _build_t1558_detection,  # Kerberos Tickets
        "T1558.001": _build_t1558_001_detection,  # Golden Ticket
        "T1558.003": _build_t1558_003_detection,  # Kerberoasting
        "T1021": _build_t1021_detection,  # Remote Services
        "T1021.002": _build_t1021_002_detection,  # SMB/Admin Shares
        "T1649": _build_t1649_detection,  # ADCS
        "T1550": _build_t1550_detection,  # Alternate Auth Material
        "T1550.002": _build_t1550_002_detection,  # Pass the Hash
    }

    for technique_id in state.identified_techniques:
        # Try exact match first, then parent technique
        builder = technique_builders.get(technique_id)
        if not builder and "." in technique_id:
            parent_id = technique_id.split(".")[0]
            builder = technique_builders.get(parent_id)

        if builder:
            detection = builder(state, attack_start, attack_end)
            detections[technique_id] = detection
        else:
            # Generic detection for unknown techniques
            detections[technique_id] = TechniqueDetection(
                technique_id=technique_id,
                technique_name=_get_technique_name(technique_id),
                description=f"Technique {technique_id} was used during the attack.",
                detection_guidance=(
                    f"Review MITRE ATT&CK documentation for {technique_id} detection guidance."
                ),
            )

    return detections


def _build_priority_queries(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> list[PlaybookQuery]:
    """Build prioritized list of detection queries."""
    queries: list[PlaybookQuery] = []

    # 1. Domain Admin detection (highest priority if achieved)
    if state.has_domain_admin:
        queries.append(
            PlaybookQuery(
                technique_id="T1078.002",
                technique_name="Domain Admin Access",
                description="Detect Domain Admin logon events",
                logql='{job="windows-security"} |= "4672" |~ "(?i)(Domain Admins|Administrator)"',
                priority="critical",
                windows_event_ids=["4672", "4624"],
                expected_evidence=["Special privileges assigned to new logon"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        )

    # 2. Credential dumping detection
    if state.all_hashes:
        usernames = [h.username for h in state.all_hashes[:5]]
        username_pattern = "|".join(usernames)
        queries.append(
            PlaybookQuery(
                technique_id="T1003",
                technique_name="Credential Dumping",
                description=f"Detect credential access for dumped accounts: {', '.join(usernames)}",
                logql=f'{{job="windows-security"}} |~ "(?i)(4624|4648)" |~ "(?i)({username_pattern})"',
                priority="critical",
                windows_event_ids=["4624", "4648", "4672"],
                expected_evidence=[f"Logon events for {u}" for u in usernames],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        )

    # 3. Lateral movement detection
    if len(state.all_hosts) > 1:
        host_ips = [h.ip for h in state.all_hosts[:5]]
        ip_pattern = "|".join(host_ips)
        queries.append(
            PlaybookQuery(
                technique_id="T1021.002",
                technique_name="Lateral Movement via SMB",
                description="Detect lateral movement to discovered hosts",
                logql=f'{{job="windows-security"}} |= "4624" |~ "LogonType.*(3|10)" |~ "({ip_pattern})"',
                priority="high",
                windows_event_ids=["4624", "4648"],
                expected_evidence=["Network logon (Type 3) events"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        )

    # 4. Kerberos attack detection
    if any(t.startswith("T1558") for t in state.identified_techniques):
        queries.append(
            PlaybookQuery(
                technique_id="T1558",
                technique_name="Kerberos Ticket Attacks",
                description="Detect Kerberoasting, AS-REP Roasting, or Golden Ticket",
                logql='{job="windows-security"} |~ "(4768|4769)" |~ "(?i)(RC4|0x17|0x18)"',
                priority="high",
                windows_event_ids=["4768", "4769"],
                expected_evidence=["TGS requests with RC4 encryption (Kerberoasting indicator)"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        )

    # 5. Network discovery detection
    queries.append(
        PlaybookQuery(
            technique_id="T1046",
            technique_name="Network Service Discovery",
            description="Detect network scanning activity",
            logql='{job="firewall"} |~ "(?i)(scan|nmap|masscan)" or {job="windows-security"} |= "5156"',
            priority="medium",
            windows_event_ids=["5156"],
            expected_evidence=["Firewall connection events", "Port scan patterns"],
            time_window_start=attack_start,
            time_window_end=attack_end,
        )
    )

    # 6. Compromised account activity
    for cred in state.all_credentials[:3]:  # Top 3 credentials
        account = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
        queries.append(
            PlaybookQuery(
                technique_id="T1078",
                technique_name="Valid Account Usage",
                description=f"Detect activity from compromised account: {account}",
                logql=f'{{job="windows-security"}} |~ "(?i)(4624|4625|4648|4672)" |~ "(?i){cred.username}"',
                priority="high",
                windows_event_ids=["4624", "4625", "4648", "4672"],
                expected_evidence=[f"Authentication events for {account}"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        )

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    queries.sort(key=lambda q: priority_order.get(q.priority, 4))

    return queries


# Technique-specific detection builders


def _build_t1046_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Network Service Discovery."""
    targets = [h.ip for h in state.all_hosts]
    return TechniqueDetection(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        description="Attacker performed network scanning to discover hosts and services.",
        targets=targets,
        detection_queries=[
            PlaybookQuery(
                technique_id="T1046",
                technique_name="Network Scan Detection",
                description="Detect port scanning activity",
                logql='{job="firewall"} |~ "(?i)(scan|probe)" or {job="windows-security"} |= "5156"',
                priority="medium",
                windows_event_ids=["5156", "5157"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["5156", "5157"],
        log_sources=["firewall", "windows-security", "netflow"],
        detection_guidance=(
            "Look for rapid connection attempts to multiple ports. "
            "Monitor Windows Filtering Platform events (5156/5157) for connection patterns."
        ),
    )


def _build_t1003_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for OS Credential Dumping."""
    credentials_used = [
        f"{c.domain}\\{c.username}" if c.domain else c.username for c in state.all_credentials[:5]
    ]
    return TechniqueDetection(
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        description="Attacker dumped credentials from the operating system.",
        credentials_used=credentials_used,
        detection_queries=[
            PlaybookQuery(
                technique_id="T1003",
                technique_name="Credential Dump Detection",
                description="Detect LSASS access or credential dumping tools",
                logql='{job="windows-security"} |~ "(?i)(lsass|mimikatz|procdump|secretsdump)"',
                priority="critical",
                windows_event_ids=["4624", "4648", "4672", "1"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4624", "4648", "4672", "10"],
        log_sources=["windows-security", "sysmon"],
        detection_guidance=(
            "Monitor Sysmon Event ID 10 (ProcessAccess) for LSASS access. "
            "Alert on known credential dumping tools in command lines."
        ),
    )


def _build_t1003_001_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for LSASS Memory access."""
    return TechniqueDetection(
        technique_id="T1003.001",
        technique_name="LSASS Memory",
        description="Attacker accessed LSASS process memory to extract credentials.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1003.001",
                technique_name="LSASS Access Detection",
                description="Detect processes accessing LSASS memory",
                logql='{job="sysmon"} |= "10" |~ "(?i)lsass.exe" |~ "GrantedAccess"',
                label_selector='{job="sysmon"}',
                priority="critical",
                windows_event_ids=["10"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["10"],
        log_sources=["sysmon"],
        detection_guidance=(
            "Sysmon Event ID 10 with TargetImage containing lsass.exe is highly suspicious. "
            "Legitimate access typically comes from specific system processes only."
        ),
    )


def _build_t1003_006_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for DCSync."""
    return TechniqueDetection(
        technique_id="T1003.006",
        technique_name="DCSync",
        description="Attacker used DCSync to replicate domain credentials.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1003.006",
                technique_name="DCSync Detection",
                description="Detect directory replication requests from non-DC",
                logql='{job="windows-security"} |= "4662" |~ "(?i)(1131f6aa|1131f6ad|89e95b76)"',
                priority="critical",
                windows_event_ids=["4662"],
                expected_evidence=["Replicating Directory Changes requests"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4662"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor Event ID 4662 for DS-Replication-Get-Changes requests. "
            "GUIDs: 1131f6aa (Get-Changes), 1131f6ad (Get-Changes-All). "
            "Alert when source is not a domain controller."
        ),
    )


def _build_t1078_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Valid Accounts."""
    credentials = [
        f"{c.domain}\\{c.username}" if c.domain else c.username for c in state.all_credentials
    ]
    return TechniqueDetection(
        technique_id="T1078",
        technique_name="Valid Accounts",
        description="Attacker used valid credentials for access.",
        credentials_used=credentials[:10],
        detection_queries=[
            PlaybookQuery(
                technique_id="T1078",
                technique_name="Account Usage Detection",
                description="Detect authentication from compromised accounts",
                logql='{job="windows-security"} |~ "(4624|4625)" |~ "LogonType.*(3|10)"',
                priority="high",
                windows_event_ids=["4624", "4625"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4624", "4625", "4648"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor authentication events for unusual source IPs, times, or logon types. "
            "Implement impossible travel detection for user accounts."
        ),
    )


def _build_t1078_002_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Domain Accounts."""
    return TechniqueDetection(
        technique_id="T1078.002",
        technique_name="Domain Accounts",
        description="Attacker used domain account credentials.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1078.002",
                technique_name="Domain Account Abuse",
                description="Detect domain admin or privileged account usage",
                logql='{job="windows-security"} |= "4672" |~ "(?i)admin"',
                priority="critical",
                windows_event_ids=["4672", "4624"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4672", "4624", "4648"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor Event ID 4672 (special privileges assigned). "
            "Alert on Domain Admin logons from unusual sources."
        ),
    )


def _build_t1110_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Brute Force."""
    return TechniqueDetection(
        technique_id="T1110",
        technique_name="Brute Force",
        description="Attacker attempted credential guessing attacks.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1110",
                technique_name="Brute Force Detection",
                description="Detect multiple failed authentication attempts",
                logql='{job="windows-security"} |= "4625"',
                priority="high",
                windows_event_ids=["4625"],
                expected_evidence=["Multiple failed logon attempts"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4625", "4771"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Count Event ID 4625 per source IP and username. "
            "Alert on >5 failures in 5 minutes from same source."
        ),
    )


def _build_t1558_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Kerberos Ticket attacks."""
    return TechniqueDetection(
        technique_id="T1558",
        technique_name="Steal or Forge Kerberos Tickets",
        description="Attacker manipulated Kerberos tickets for access.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1558",
                technique_name="Kerberos Attack Detection",
                description="Detect suspicious Kerberos ticket requests",
                logql='{job="windows-security"} |~ "(4768|4769)" |~ "(?i)(RC4|0x17)"',
                priority="critical",
                windows_event_ids=["4768", "4769"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4768", "4769", "4770"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor for TGS requests with RC4 encryption (Kerberoasting). "
            "Alert on TGT requests without pre-authentication (AS-REP Roasting)."
        ),
    )


def _build_t1558_001_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Golden Ticket."""
    return TechniqueDetection(
        technique_id="T1558.001",
        technique_name="Golden Ticket",
        description="Attacker forged a Kerberos TGT using the krbtgt hash.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1558.001",
                technique_name="Golden Ticket Detection",
                description="Detect forged TGT usage patterns",
                logql='{job="windows-security"} |= "4769" |~ "(?i)krbtgt"',
                priority="critical",
                windows_event_ids=["4769"],
                expected_evidence=["TGS requests for krbtgt", "Unusual ticket lifetimes"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4768", "4769"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Golden Tickets have unusual properties: long lifetimes, "
            "non-standard encryption, requests from unusual clients. "
            "Compare TGT properties against normal baselines."
        ),
    )


def _build_t1558_003_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Kerberoasting."""
    return TechniqueDetection(
        technique_id="T1558.003",
        technique_name="Kerberoasting",
        description="Attacker requested service tickets for offline cracking.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1558.003",
                technique_name="Kerberoasting Detection",
                description="Detect TGS requests with RC4 encryption",
                logql='{job="windows-security"} |= "4769" |~ "(?i)(0x17|RC4)"',
                priority="high",
                windows_event_ids=["4769"],
                expected_evidence=["TGS requests with RC4-HMAC encryption"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4769"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor Event ID 4769 for encryption type 0x17 (RC4-HMAC). "
            "Modern environments should use AES. Alert on RC4 TGS requests."
        ),
    )


def _build_t1021_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Remote Services."""
    targets = [h.ip for h in state.all_hosts]
    return TechniqueDetection(
        technique_id="T1021",
        technique_name="Remote Services",
        description="Attacker used remote services for lateral movement.",
        targets=targets,
        detection_queries=[
            PlaybookQuery(
                technique_id="T1021",
                technique_name="Remote Service Usage",
                description="Detect lateral movement via remote services",
                logql='{job="windows-security"} |= "4624" |~ "LogonType.*(3|10)"',
                priority="high",
                windows_event_ids=["4624"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4624", "4648"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor Type 3 (network) and Type 10 (remote interactive) logons. "
            "Correlate with process execution for lateral movement detection."
        ),
    )


def _build_t1021_002_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for SMB/Windows Admin Shares."""
    targets = [h.ip for h in state.all_hosts]
    shares = [f"{s.host}:{s.name}" for s in state.all_shares[:5]]
    return TechniqueDetection(
        technique_id="T1021.002",
        technique_name="SMB/Windows Admin Shares",
        description="Attacker accessed admin shares for lateral movement.",
        targets=targets,
        detection_queries=[
            PlaybookQuery(
                technique_id="T1021.002",
                technique_name="Admin Share Access",
                description="Detect access to C$, ADMIN$, IPC$ shares",
                logql='{job="windows-security"} |= "5140" |~ "(?i)(C\\$|ADMIN\\$|IPC\\$)"',
                priority="high",
                windows_event_ids=["5140", "5145"],
                expected_evidence=[f"Share access: {s}" for s in shares],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["5140", "5145"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor Event ID 5140/5145 for admin share access. "
            "Alert on C$, ADMIN$, or IPC$ access from non-admin workstations."
        ),
    )


def _build_t1649_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for ADCS attacks."""
    return TechniqueDetection(
        technique_id="T1649",
        technique_name="Steal or Forge Authentication Certificates",
        description="Attacker exploited AD Certificate Services.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1649",
                technique_name="ADCS Attack Detection",
                description="Detect suspicious certificate requests",
                logql='{job="windows-security"} |~ "(4886|4887)" |~ "(?i)certificate"',
                priority="critical",
                windows_event_ids=["4886", "4887"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4886", "4887", "4768"],
        log_sources=["windows-security", "ad-cs"],
        detection_guidance=(
            "Monitor certificate enrollment events (4886/4887). "
            "Alert on certificate requests with unusual templates or SANs. "
            "Watch for ESC1-ESC8 vulnerability patterns."
        ),
    )


def _build_t1550_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Alternate Authentication Material."""
    return TechniqueDetection(
        technique_id="T1550",
        technique_name="Use Alternate Authentication Material",
        description="Attacker used stolen authentication material (hashes, tickets).",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1550",
                technique_name="Auth Material Abuse",
                description="Detect pass-the-hash or ticket reuse",
                logql='{job="windows-security"} |= "4624" |~ "NTLM" |~ "LogonType.*3"',
                priority="critical",
                windows_event_ids=["4624"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4624", "4648"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Monitor for NTLM authentication anomalies. "
            "Pass-the-hash often shows as Type 3 logon with NTLM package."
        ),
    )


def _build_t1550_002_detection(
    state: SharedRedTeamState,
    attack_start: datetime,
    attack_end: datetime,
) -> TechniqueDetection:
    """Build detection for Pass the Hash."""
    return TechniqueDetection(
        technique_id="T1550.002",
        technique_name="Pass the Hash",
        description="Attacker used NTLM hashes for authentication.",
        detection_queries=[
            PlaybookQuery(
                technique_id="T1550.002",
                technique_name="Pass-the-Hash Detection",
                description="Detect NTLM Type 3 logons indicating PtH",
                logql='{job="windows-security"} |= "4624" |~ "NTLM" |~ "LogonType.*3"',
                priority="critical",
                windows_event_ids=["4624"],
                expected_evidence=["Network logon with NTLM authentication"],
                time_window_start=attack_start,
                time_window_end=attack_end,
            )
        ],
        windows_event_ids=["4624"],
        log_sources=["windows-security"],
        detection_guidance=(
            "Pass-the-Hash shows as Event 4624 with LogonType 3 and NTLM package. "
            "Correlate with process creation to detect lateral movement chains."
        ),
    )


def _pyramid_level_name(level: int) -> str:
    """Get human-readable name for pyramid level."""
    names = {
        1: "Hash Values (L1)",
        2: "IP Addresses (L2)",
        3: "Domain Names (L3)",
        4: "Network/Host Artifacts (L4)",
        5: "Tools (L5)",
        6: "TTPs (L6)",
    }
    return names.get(level, f"Unknown (L{level})")


def _get_technique_name(technique_id: str) -> str:
    """Get human-readable name for a MITRE technique."""
    # Common techniques used in Ares
    names = {
        "T1046": "Network Service Discovery",
        "T1003": "OS Credential Dumping",
        "T1003.001": "LSASS Memory",
        "T1003.006": "DCSync",
        "T1078": "Valid Accounts",
        "T1078.002": "Domain Accounts",
        "T1110": "Brute Force",
        "T1558": "Steal or Forge Kerberos Tickets",
        "T1558.001": "Golden Ticket",
        "T1558.003": "Kerberoasting",
        "T1558.004": "AS-REP Roasting",
        "T1021": "Remote Services",
        "T1021.002": "SMB/Windows Admin Shares",
        "T1649": "ADCS Certificate Theft",
        "T1550": "Use Alternate Authentication Material",
        "T1550.002": "Pass the Hash",
        "T1484": "Domain Policy Modification",
        "T1087": "Account Discovery",
    }
    return names.get(technique_id, technique_id)
