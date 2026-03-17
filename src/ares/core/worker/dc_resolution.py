"""Domain Controller IP resolution helpers.

This module provides utilities for resolving and validating DC IPs
based on discovered hosts in the shared state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from ares.core.models import SharedRedTeamState


def _hostname_matches_domain(hostname: str, domain: str) -> bool:
    """Check if hostname belongs to the specified domain."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    domain_lower = domain.lower()
    # Match both FQDN suffix and short domain name in hostname
    # e.g., for domain "corp": srv01.corp.contoso.local matches
    # e.g., for domain "corp.contoso.local": same hostname matches
    return f".{domain_lower}" in hostname_lower or hostname_lower.endswith(f".{domain_lower}")


def _has_dc_services(host: Any) -> bool:
    """Check if host has domain controller services (Kerberos, LDAP)."""
    for svc in getattr(host, "services", []):
        svc_lower = svc.lower()
        if any(svc_lower.startswith(p) for p in ("88/tcp", "389/tcp")):
            return True
        if any(n in svc_lower for n in ("kerberos", "ldap")):
            return True
    return False


def _has_dc_role(host: Any) -> bool:
    """Check if host has a domain controller role."""
    roles = getattr(host, "roles", [])
    if not roles:
        return False
    roles_str = str(roles).lower()
    return any(m in roles_str for m in ("dc", "domain controller", "ad dc"))


def resolve_dc_ip_for_domain(
    state: SharedRedTeamState | None,
    domain: str,
    provided_dc_ip: str,
) -> tuple[str, str | None]:
    """Validate and potentially re-resolve DC IP for a domain.

    If provided_dc_ip doesn't match a host serving the specified domain,
    attempt to find the correct DC from current state.

    Args:
        state: The shared red team state containing discovered hosts
        domain: The target domain to find a DC for
        provided_dc_ip: The currently provided DC IP to validate

    Returns:
        Tuple of (dc_ip, warning_message). warning_message is None if DC IP is valid.
    """
    if not state or not domain:
        return provided_dc_ip, None

    domain_lower = domain.lower()

    # Priority 0: Check cached domain_controllers (populated by orchestrator)
    # This handles child domains where hostname doesn't match domain FQDN
    # e.g., child.contoso.local DC is dc02.contoso.local
    cached_dc = getattr(state, "domain_controllers", {}).get(domain_lower)
    if cached_dc:
        if provided_dc_ip and provided_dc_ip != cached_dc:
            logger.info(f"DC IP from cache: {cached_dc} (overriding {provided_dc_ip}) for {domain}")
        else:
            logger.debug(f"DC IP from cache: {cached_dc} for {domain}")
        return cached_dc, None

    # Check if provided DC IP belongs to a host matching this domain
    provided_host = None
    if provided_dc_ip:
        for host in state.all_hosts:
            if host.ip == provided_dc_ip:
                provided_host = host
                break

    if provided_host and _hostname_matches_domain(provided_host.hostname or "", domain_lower):
        # Provided DC IP is valid for this domain
        return provided_dc_ip, None

    # Search for a DC that serves this domain
    # Priority 1: Hostname matches domain + has DC services
    for host in state.all_hosts:
        hostname = host.hostname or ""
        if _hostname_matches_domain(hostname, domain_lower) and _has_dc_services(host):
            if not provided_dc_ip:
                logger.info(f"DC IP resolved: {host.ip} ({hostname}) for domain {domain}")
            else:
                logger.warning(
                    f"DC IP RE-RESOLVED: {provided_dc_ip} -> {host.ip} ({hostname}) for domain {domain}"
                )
            return host.ip, None

    # Priority 2: Has DC role + hostname matches domain
    for host in state.all_hosts:
        hostname = host.hostname or ""
        if _hostname_matches_domain(hostname, domain_lower) and _has_dc_role(host):
            if not provided_dc_ip:
                logger.info(f"DC IP resolved via role: {host.ip} ({hostname}) for domain {domain}")
            else:
                logger.warning(
                    f"DC IP RE-RESOLVED via role: {provided_dc_ip} -> {host.ip} ({hostname}) for domain {domain}"
                )
            return host.ip, None

    # Priority 3: Any host with DC services (fallback, less accurate)
    for host in state.all_hosts:
        if _has_dc_services(host):
            warning = (
                f"⚠️ DC IP FALLBACK: No DC found for domain {domain}. "
                f"Using {host.ip} ({host.hostname or 'unknown'}) which has DC services."
            )
            logger.warning(warning)
            return host.ip, warning

    # No DC found at all
    if provided_dc_ip:
        warning = (
            f"⚠️ DC IP WARNING: {provided_dc_ip} may not serve domain {domain}. "
            f"No matching DC found in state."
        )
        return provided_dc_ip, warning

    logger.warning(f"No DC IP could be resolved for domain {domain}")
    return "", None


# Backwards compatibility alias
_resolve_dc_ip_for_domain = resolve_dc_ip_for_domain


__all__ = [
    "_has_dc_role",
    "_has_dc_services",
    "_hostname_matches_domain",
    "_resolve_dc_ip_for_domain",
    "resolve_dc_ip_for_domain",
]
