"""Red team penetration testing tools."""

# ACL exploitation
from ares.tools.red.acl_attacks import ACLExploitTools

# Coercion and relay
from ares.tools.red.coercion import CoercionNetworkTools, CoercionTools

# Credential discovery and harvesting
from ares.tools.red.credential_discovery import (
    CrackingTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    SharePilferingTools,
)

# CVE exploits
from ares.tools.red.cve_exploits import CVEExploitTools

# Kerberos and certificate attacks
from ares.tools.red.kerberos_attacks import (
    CertipyTools,
    DelegationTools,
    GMSATools,
    GoldenTicketTools,
    TrustAttackTools,
)

# Lateral movement
from ares.tools.red.lateral_movement import LateralMovementTools, MSSQLTools

# Orchestrator tools
from ares.tools.red.orchestrator import (
    CrackerCallbackTools,
    LateralCallbackTools,
    OrchestratorTools,
)

# Privilege escalation
from ares.tools.red.privilege_escalation import PrivilegeEscalationTools

# Reconnaissance
from ares.tools.red.reconnaissance import (
    BloodHoundTools,
    NetworkEnumerationTools,
    PostureValidationTools,
)

# Reporting
from ares.tools.red.reporting import RedTeamReportingTools

__all__ = [
    "ACLExploitTools",
    "BloodHoundTools",
    "CVEExploitTools",
    "CertipyTools",
    "CoercionNetworkTools",
    "CoercionTools",
    "CrackerCallbackTools",
    "CrackingTools",
    "CredentialDiscoveryTools",
    "CredentialHarvestingTools",
    "DelegationTools",
    "GMSATools",
    "GoldenTicketTools",
    "LateralCallbackTools",
    "LateralMovementTools",
    "MSSQLTools",
    "NetworkEnumerationTools",
    "OrchestratorTools",
    "PostureValidationTools",
    "PrivilegeEscalationTools",
    "RedTeamReportingTools",
    "SharePilferingTools",
    "TrustAttackTools",
]
