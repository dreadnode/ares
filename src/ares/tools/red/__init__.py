"""Red team penetration testing tools."""

from ares.tools.red.network import (
    ACLExploitTools,
    BloodHoundTools,
    CertipyTools,
    CoercionTools,
    CrackingTools,
    CredentialHarvestingTools,
    CVEExploitTools,
    DelegationTools,
    GoldenTicketTools,
    LateralMovementTools,
    MSSQLTools,
    NetworkEnumerationTools,
    RedTeamReportingTools,
    SharePilferingTools,
    TrustAttackTools,
)
from ares.tools.red.orchestrator import (
    CrackerCallbackTools,
    LateralCallbackTools,
    OrchestratorTools,
)

__all__ = [
    # Existing toolsets
    "ACLExploitTools",
    "BloodHoundTools",
    "CVEExploitTools",
    "CertipyTools",
    "CoercionTools",
    # Multi-agent orchestration tools
    "CrackerCallbackTools",
    "CrackingTools",
    "CredentialHarvestingTools",
    "DelegationTools",
    "GoldenTicketTools",
    "LateralCallbackTools",
    "LateralMovementTools",
    "MSSQLTools",
    "NetworkEnumerationTools",
    "OrchestratorTools",
    "RedTeamReportingTools",
    "SharePilferingTools",
    "TrustAttackTools",
]
