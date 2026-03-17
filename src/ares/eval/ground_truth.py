"""
Ground truth schema and transformation for blue team evaluation.

Transforms red team operation state into expected findings that the
blue team investigation should detect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ares.core.models import (
    PyramidLevel,
    SharedRedTeamState,
)

if TYPE_CHECKING:
    from datetime import datetime


@dataclass
class ExpectedIOC:
    """An IOC that the blue team should discover.

    Attributes:
        ioc_type: Type of IOC - ip, hostname, user, hash, domain, process, tool.
        value: The actual IOC value.
        pyramid_level: Expected Pyramid of Pain classification.
        mitre_techniques: Associated MITRE ATT&CK technique IDs.
        required: Whether this IOC is required (vs nice-to-have).
        source: How this IOC was generated (e.g., "host_discovery", "credential").
    """

    ioc_type: str  # ip, hostname, user, hash, domain, process, tool
    value: str
    pyramid_level: PyramidLevel
    mitre_techniques: list[str] = field(default_factory=list)
    required: bool = True
    source: str = ""


@dataclass
class ExpectedTechnique:
    """A MITRE technique that should be identified.

    Attributes:
        technique_id: MITRE ATT&CK technique ID (e.g., T1003, T1003.001).
        technique_name: Human-readable technique name.
        required: Whether this technique is required (vs nice-to-have).
        parent_id: Parent technique ID if this is a sub-technique.
    """

    technique_id: str
    technique_name: str = ""
    required: bool = True
    parent_id: str | None = None

    def matches(self, found_technique: str) -> bool:
        """Check if a found technique matches this expected technique.

        Supports parent/sub-technique matching:
        - T1003 matches T1003.001 (parent matches child)
        - T1003.001 matches T1003 (child matches parent)
        - Exact match always works
        """
        if found_technique == self.technique_id:
            return True

        # Check parent/child relationship
        if "." in self.technique_id:
            # This is a sub-technique, check if found is parent
            parent = self.technique_id.split(".")[0]
            if found_technique == parent:
                return True
        elif found_technique.startswith(f"{self.technique_id}."):
            # This is a parent, check if found is a sub-technique
            return True

        return False


@dataclass
class ExpectedTimelineEvent:
    """An event that should appear in the investigation timeline.

    Attributes:
        description_pattern: Regex or substring to match in event description.
        mitre_techniques: Expected MITRE techniques for this event.
        timestamp_range: Optional (start, end) datetime range for the event.
        required: Whether this event is required.
    """

    description_pattern: str
    mitre_techniques: list[str] = field(default_factory=list)
    timestamp_range: tuple[datetime, datetime] | None = None
    required: bool = True


@dataclass
class ExpectedShare:
    """A network share that should be identified during investigation.

    Attributes:
        host: Host where share was found.
        name: Share name.
        permissions: Access permissions discovered.
        required: Whether this share is required to be detected.
    """

    host: str
    name: str
    permissions: str = ""
    required: bool = False


@dataclass
class ExpectedVulnerability:
    """A vulnerability that should be identified during investigation.

    Attributes:
        vuln_type: Type of vulnerability (ADCS_ESC1, UNCONSTRAINED_DELEGATION, etc.).
        target: Target affected by this vulnerability.
        mitre_techniques: Associated MITRE techniques for this vuln type.
        exploited: Whether this vulnerability was exploited.
        required: Whether this vulnerability is required to be detected.
    """

    vuln_type: str
    target: str
    mitre_techniques: list[str] = field(default_factory=list)
    exploited: bool = False
    required: bool = True


@dataclass
class EvaluationGroundTruth:
    """Complete ground truth for evaluating a blue team investigation.

    Attributes:
        operation_id: Red team operation ID this ground truth is derived from.
        target_ip: Primary target IP address.
        expected_iocs: List of IOCs the blue team should find.
        expected_techniques: List of MITRE techniques to identify.
        expected_timeline: List of timeline events to detect.
        expected_shares: Network shares discovered during attack.
        expected_vulnerabilities: Vulnerabilities discovered/exploited.
        min_pyramid_level: Minimum acceptable highest pyramid level.
        target_pyramid_level: Target highest pyramid level.
        min_technique_coverage: Minimum acceptable technique coverage (0-1).
        min_ioc_detection_rate: Minimum acceptable IOC detection rate (0-1).
    """

    operation_id: str
    target_ip: str
    expected_iocs: list[ExpectedIOC] = field(default_factory=list)
    expected_techniques: list[ExpectedTechnique] = field(default_factory=list)
    expected_timeline: list[ExpectedTimelineEvent] = field(default_factory=list)
    expected_shares: list[ExpectedShare] = field(default_factory=list)
    expected_vulnerabilities: list[ExpectedVulnerability] = field(default_factory=list)

    # Thresholds for pass/fail determination
    min_pyramid_level: int = 4  # Network/Host Artifacts minimum
    target_pyramid_level: int = 6  # TTPs target
    min_technique_coverage: float = 0.6
    min_ioc_detection_rate: float = 0.5

    @property
    def required_iocs(self) -> list[ExpectedIOC]:
        """Get only required IOCs."""
        return [ioc for ioc in self.expected_iocs if ioc.required]

    @property
    def optional_iocs(self) -> list[ExpectedIOC]:
        """Get only optional IOCs."""
        return [ioc for ioc in self.expected_iocs if not ioc.required]

    @property
    def required_techniques(self) -> list[ExpectedTechnique]:
        """Get only required techniques."""
        return [t for t in self.expected_techniques if t.required]

    @property
    def optional_techniques(self) -> list[ExpectedTechnique]:
        """Get only optional techniques."""
        return [t for t in self.expected_techniques if not t.required]


def create_ground_truth_from_red_state(
    state: SharedRedTeamState,
) -> EvaluationGroundTruth:
    """Transform red team operation state into evaluation ground truth.

    Extracts IOCs, techniques, and timeline events from the red team
    state to create expected findings for blue team evaluation.

    Args:
        state: Red team operation state.

    Returns:
        EvaluationGroundTruth with expected findings.
    """
    expected_iocs: list[ExpectedIOC] = []
    expected_techniques: list[ExpectedTechnique] = []
    expected_timeline: list[ExpectedTimelineEvent] = []

    target_ip = state.target.ip if state.target else ""
    hosts = state.all_hosts
    users = state.all_users
    credentials = state.all_credentials
    hashes = state.all_hashes
    timeline = state.operation_timeline
    techniques = state.identified_techniques
    shares = state.all_shares
    discovered_vulns = state.discovered_vulnerabilities
    exploited_vulns = state.exploited_vulnerabilities

    for host in hosts:
        expected_iocs.append(
            ExpectedIOC(
                ioc_type="ip",
                value=host.ip,
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=["T1046"],  # Network Service Discovery
                required=True,
                source="host_discovery",
            )
        )
        if host.hostname:
            expected_iocs.append(
                ExpectedIOC(
                    ioc_type="hostname",
                    value=host.hostname,
                    pyramid_level=PyramidLevel.DOMAIN_NAMES,
                    mitre_techniques=["T1046"],
                    required=False,  # Hostname is nice-to-have
                    source="host_discovery",
                )
            )

    for user in users:
        expected_iocs.append(
            ExpectedIOC(
                ioc_type="user",
                value=user.username,
                pyramid_level=PyramidLevel.NETWORK_HOST_ARTIFACTS,
                mitre_techniques=["T1087"],  # Account Discovery
                required=user.is_admin,
                source="user_enumeration",
            )
        )

    for cred in credentials:
        expected_iocs.append(
            ExpectedIOC(
                ioc_type="user",
                value=cred.username,
                pyramid_level=PyramidLevel.NETWORK_HOST_ARTIFACTS,
                mitre_techniques=["T1003", "T1110"],  # Credential Dumping, Brute Force
                required=cred.is_admin,
                source="credential_harvesting",
            )
        )

    for hash_obj in hashes:
        expected_iocs.append(
            ExpectedIOC(
                ioc_type="hash",
                value=hash_obj.hash_value,
                pyramid_level=PyramidLevel.HASH_VALUES,
                mitre_techniques=["T1003"],  # Credential Dumping
                required=False,  # Hashes are lower priority
                source="hash_extraction",
            )
        )

    for technique_id in techniques:
        required = _is_technique_required(technique_id)
        expected_techniques.append(
            ExpectedTechnique(
                technique_id=technique_id,
                required=required,
                parent_id=technique_id.split(".")[0] if "." in technique_id else None,
            )
        )

    for event in timeline:
        expected_timeline.append(
            ExpectedTimelineEvent(
                description_pattern=event.description,
                mitre_techniques=event.mitre_techniques,
                timestamp_range=(event.timestamp, event.timestamp),
                required=event.confidence >= 0.7,
            )
        )

    has_domain_admin = state.has_domain_admin
    has_golden_ticket = state.has_golden_ticket

    if has_domain_admin:
        expected_techniques.append(
            ExpectedTechnique(
                technique_id="T1078.002",
                technique_name="Valid Accounts: Domain Accounts",
                required=True,
            )
        )
    if has_golden_ticket:
        expected_techniques.append(
            ExpectedTechnique(
                technique_id="T1558.001",
                technique_name="Steal or Forge Kerberos Tickets: Golden Ticket",
                required=True,
            )
        )

    expected_shares: list[ExpectedShare] = []
    for share in shares:
        expected_shares.append(
            ExpectedShare(
                host=share.host,
                name=share.name,
                permissions=share.permissions,
                # Writable shares are important for detection
                required=share.permissions in ("WRITE", "READ/WRITE"),
            )
        )
        # Also add share host as IOC
        expected_iocs.append(
            ExpectedIOC(
                ioc_type="ip",
                value=share.host,
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=["T1021.002"],  # SMB/Windows Admin Shares
                required=False,
                source="share_enumeration",
            )
        )

    # Extract expected vulnerabilities
    expected_vulnerabilities: list[ExpectedVulnerability] = []
    for vuln_id, vuln in discovered_vulns.items():
        vuln_techniques = _get_techniques_for_vuln_type(vuln.vuln_type)
        expected_vulnerabilities.append(
            ExpectedVulnerability(
                vuln_type=vuln.vuln_type,
                target=vuln.target,
                mitre_techniques=vuln_techniques,
                exploited=vuln_id in exploited_vulns,
                required=vuln_id in exploited_vulns,  # Exploited vulns are required
            )
        )
        # Add vulnerability-specific techniques
        for tech_id in vuln_techniques:
            if tech_id not in [t.technique_id for t in expected_techniques]:
                expected_techniques.append(
                    ExpectedTechnique(
                        technique_id=tech_id,
                        required=vuln_id in exploited_vulns,
                        parent_id=tech_id.split(".")[0] if "." in tech_id else None,
                    )
                )

    # Deduplicate IOCs by value
    seen_values: set[str] = set()
    unique_iocs: list[ExpectedIOC] = []
    for ioc in expected_iocs:
        if ioc.value not in seen_values:
            seen_values.add(ioc.value)
            unique_iocs.append(ioc)

    # Deduplicate techniques by ID
    seen_techniques: set[str] = set()
    unique_techniques: list[ExpectedTechnique] = []
    for tech in expected_techniques:
        if tech.technique_id not in seen_techniques:
            seen_techniques.add(tech.technique_id)
            unique_techniques.append(tech)

    return EvaluationGroundTruth(
        operation_id=state.operation_id,
        target_ip=target_ip,
        expected_iocs=unique_iocs,
        expected_techniques=unique_techniques,
        expected_timeline=expected_timeline,
        expected_shares=expected_shares,
        expected_vulnerabilities=expected_vulnerabilities,
    )


def _is_technique_required(technique_id: str) -> bool:
    """Determine if a technique should be required for detection.

    High-impact techniques like credential access and privilege escalation
    are required. Lower-impact techniques like discovery are optional.
    """
    required_prefixes = [
        "T1003",  # OS Credential Dumping
        "T1078",  # Valid Accounts
        "T1558",  # Steal or Forge Kerberos Tickets
        "T1110",  # Brute Force
        "T1021",  # Remote Services
        "T1550",  # Use Alternate Authentication Material
    ]

    return any(technique_id.startswith(prefix) for prefix in required_prefixes)


# Mapping of vulnerability types to MITRE ATT&CK techniques
_VULN_TYPE_TECHNIQUES: dict[str, list[str]] = {
    # Active Directory Certificate Services vulnerabilities
    "ADCS_ESC1": ["T1649"],  # Steal or Forge Authentication Certificates
    "ADCS_ESC2": ["T1649"],
    "ADCS_ESC3": ["T1649"],
    "ADCS_ESC4": ["T1649"],
    "ADCS_ESC6": ["T1649"],
    "ADCS_ESC7": ["T1649"],
    "ADCS_ESC8": ["T1649"],
    # Delegation attacks
    "UNCONSTRAINED_DELEGATION": ["T1558"],  # Steal or Forge Kerberos Tickets
    "CONSTRAINED_DELEGATION": ["T1558"],
    "RESOURCE_BASED_CONSTRAINED_DELEGATION": ["T1558"],
    # ACL-based attacks
    "ACL_ABUSE": ["T1222", "T1484"],  # File Permissions Modification, Domain Policy Modification
    "DACL_ABUSE": ["T1222", "T1484"],
    "WRITEDACL": ["T1222"],
    "GENERICALL": ["T1222", "T1098"],  # Account Manipulation
    "GENERICWRITE": ["T1222", "T1098"],
    "WRITEOWNER": ["T1222"],
    # Kerberos attacks
    "KERBEROASTING": ["T1558.003"],  # Kerberoasting
    "ASREPROASTING": ["T1558.004"],  # AS-REP Roasting
    # GPO abuse
    "GPO_ABUSE": ["T1484.001"],  # Group Policy Modification
    # DCSync
    "DCSYNC": ["T1003.006"],  # DCSync
    # Password attacks
    "PASSWORD_SPRAY": ["T1110.003"],  # Password Spraying
    "CREDENTIAL_STUFFING": ["T1110.004"],  # Credential Stuffing
    # Default - generic privilege escalation
    "DEFAULT": ["T1068"],  # Exploitation for Privilege Escalation
}


def _get_techniques_for_vuln_type(vuln_type: str) -> list[str]:
    """Get MITRE techniques associated with a vulnerability type."""
    return _VULN_TYPE_TECHNIQUES.get(vuln_type.upper(), _VULN_TYPE_TECHNIQUES["DEFAULT"])
