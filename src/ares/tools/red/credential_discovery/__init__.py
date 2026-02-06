"""Red Team credential discovery and harvesting tools package.

This package provides toolsets for credential attacks including:
- Low-hanging fruit discovery (passwords in descriptions, username=password)
- Password spraying
- Kerberoasting and AS-REP roasting
- Hash cracking
- Share pilfering

Package Structure:
    - discovery.py: Low-hanging fruit (LDAP descriptions, password spray)
    - harvesting.py: Kerberoasting, AS-REP roasting, secretsdump
    - cracking.py: Hash cracking with hashcat and John
    - pilfering.py: SMB share pilfering, GPP passwords, SYSVOL search

Usage:
    from ares.tools.red.credential_discovery import (
        CredentialDiscoveryTools,
        CredentialHarvestingTools,
        CrackingTools,
        SharePilferingTools,
    )
"""

from __future__ import annotations

# Re-export all tool classes from split modules
from ares.tools.red.credential_discovery.cracking import CrackingTools
from ares.tools.red.credential_discovery.discovery import CredentialDiscoveryTools
from ares.tools.red.credential_discovery.harvesting import CredentialHarvestingTools
from ares.tools.red.credential_discovery.pilfering import SharePilferingTools

__all__ = [
    "CrackingTools",
    "CredentialDiscoveryTools",
    "CredentialHarvestingTools",
    "SharePilferingTools",
]
