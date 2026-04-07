"""Dispatcher package for multi-agent red team coordination.

This package provides the central dispatcher for coordinating multi-agent
red team operations. The main entry point is the RedTeamDispatcher class.

Package Structure:
    - _dispatcher.py: Main RedTeamDispatcher class
    - extraction.py: Output parsing utilities for tool results

Usage:
    from ares.core.dispatcher import RedTeamDispatcher

    dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")
    await dispatcher.start(operation_id)

The extraction submodule provides standalone functions for parsing tool output:
    from ares.core.dispatcher.extraction import (
        extract_hosts_from_output,
        extract_users_from_output,
        extract_shares_from_output,
    )
"""

from __future__ import annotations

# Re-export the main dispatcher class
from ares.core.dispatcher._dispatcher import RedTeamDispatcher

# Re-export extraction utilities
from ares.core.dispatcher.extraction import (
    extract_delegation_entries,
    extract_domain_sid,
    extract_host_from_spn,
    extract_hosts_from_output,
    extract_kerberos_hashes,
    extract_ntlm_hashes,
    extract_plaintext_passwords_from_output,
    extract_secretsdump_hashes,
    extract_shares_from_output,
    extract_ticket_path_from_output,
    extract_users_from_output,
)

__all__ = [
    # Main dispatcher class
    "RedTeamDispatcher",
    # Extraction utilities
    "extract_delegation_entries",
    "extract_domain_sid",
    "extract_host_from_spn",
    "extract_hosts_from_output",
    "extract_kerberos_hashes",
    "extract_ntlm_hashes",
    "extract_plaintext_passwords_from_output",
    "extract_secretsdump_hashes",
    "extract_shares_from_output",
    "extract_ticket_path_from_output",
    "extract_users_from_output",
]
