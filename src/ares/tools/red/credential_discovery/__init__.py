"""Red Team credential discovery and harvesting tools package.

This package provides toolsets for credential attacks including:
- Low-hanging fruit discovery (passwords in descriptions, username=password)
- Password spraying
- Kerberoasting and AS-REP roasting
- Hash cracking
- Share pilfering

Package Structure:
    - _credential_discovery.py: Main toolset implementations

Usage:
    from ares.tools.red.credential_discovery import (
        CredentialDiscoveryTools,
        CredentialHarvestingTools,
        CrackingTools,
        SharePilferingTools,
    )
"""

from __future__ import annotations

# Re-export all tool classes
from ares.tools.red.credential_discovery._credential_discovery import (
    CrackingTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    SharePilferingTools,
)

__all__ = [
    "CrackingTools",
    "CredentialDiscoveryTools",
    "CredentialHarvestingTools",
    "SharePilferingTools",
]
