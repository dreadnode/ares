"""OpenTelemetry tracing for Ares agents.

This module provides tracing infrastructure with MITRE ATT&CK mappings
for both red and blue team agents. Spans are created using the dreadnode
SDK and include attributes for:
- attack_team: "red" or "blue"
- mitre.tactic: MITRE tactic shortname (e.g., "credential-access")
- mitre.technique.id: MITRE technique ID (e.g., "T1003")
- attack_phase: Current phase of the operation

OTel Semantic Convention attributes:
- destination.address: Target FQDN only (for dashboard "Target FQDN" column)
- destination.ip: Target IP only (for dashboard "Target IP" column)
- server.address: Target FQDN when attacking a server
- host.name: Target hostname (short name, derived from FQDN or NetBIOS name)
- host.name.type: Hostname resolution quality ("fqdn", "netbios", or "ip_only")
- user.name: Target username when attacking a user account

Custom attack namespace attributes:
- attack_target_type: Target type (domain_controller, server, workstation, user)
- attack_target_domain: Domain name of the target (e.g., contoso.local)

OTEL Export Configuration:
- Call setup_otel_tracing() early in worker entry points to enable OTLP export
- Respects OTEL_EXPORTER_OTLP_TRACES_ENDPOINT environment variable
- Required because dreadnode SDK doesn't auto-configure from OTEL env vars
"""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from typing import Any

import dreadnode as dn
from loguru import logger
from opentelemetry import trace
from opentelemetry.trace import Span, SpanKind

# IP address pattern for validation
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Common domain TLDs for FQDN detection (not usernames!)
# This prevents treating "jane.doe" as an FQDN
FQDN_SUFFIXES = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".ad",
    ".domain",
    ".com",
    ".net",
    ".org",
    ".io",
)


def is_likely_fqdn(value: str) -> bool:
    """Check if value looks like an FQDN vs a username.

    FQDNs have domain suffixes (.local, .com, etc.) or 3+ segments.
    Usernames like 'jane.doe' have 2 segments and no TLD.

    Args:
        value: The string to check.

    Returns:
        True if the value looks like an FQDN, False otherwise.

    Examples:
        >>> is_likely_fqdn("dc01.contoso.local")
        True
        >>> is_likely_fqdn("jane.doe")
        False
        >>> is_likely_fqdn("dc01.child.parent")
        True
        >>> is_likely_fqdn("192.168.58.10")
        False  # IPs should be checked separately
    """
    if not value or not isinstance(value, str):
        return False

    # IPs are not FQDNs
    if IP_PATTERN.match(value):
        return False

    val_lower = value.lower()

    # Has common TLD suffix -> FQDN
    if any(val_lower.endswith(suffix) for suffix in FQDN_SUFFIXES):
        return True

    # 3+ segments (e.g., 'dc01.contoso.local') -> FQDN
    if value.count(".") >= 2:
        return True

    # Single dot with hostname-like prefix (dc, sql, web, etc.) -> FQDN
    parts = value.split(".")
    if len(parts) == 2:
        prefix = parts[0].lower()
        if prefix.startswith(("dc", "sql", "web", "ws", "pc", "srv")):
            return True

    return False


# =============================================================================
# OTEL TracerProvider Setup
# =============================================================================

# Track whether we've already set up the TracerProvider
_otel_initialized = False


def setup_otel_tracing() -> bool:
    """Configure OpenTelemetry TracerProvider with OTLP exporter.

    This function sets up direct OTLP export using the standard OpenTelemetry
    environment variables. It's required because the dreadnode SDK doesn't
    automatically configure from OTEL_EXPORTER_OTLP_TRACES_ENDPOINT.

    Environment variables used:
    - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: Full URL for trace export (e.g., http://alloy:4318/v1/traces)
    - OTEL_EXPORTER_OTLP_ENDPOINT: Base URL (fallback, /v1/traces appended)
    - OTEL_SERVICE_NAME: Service name for resource attributes
    - OTEL_RESOURCE_ATTRIBUTES: Additional resource attributes (comma-separated key=value)

    Returns:
        True if OTLP exporter was configured, False otherwise.

    Example:
        >>> from ares.core.tracing import setup_otel_tracing
        >>> setup_otel_tracing()  # Call early in worker startup
        True
    """
    global _otel_initialized

    if _otel_initialized:
        return True

    traces_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    base_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")

    if not traces_endpoint and not base_endpoint:
        logger.debug("No OTEL_EXPORTER_OTLP_TRACES_ENDPOINT set, skipping OTLP setup")
        return False

    # Determine final endpoint - traces_endpoint takes precedence
    # At this point, at least one of traces_endpoint or base_endpoint is set
    # (we returned early above if neither was set)
    endpoint = (
        traces_endpoint or f"{base_endpoint.rstrip('/')}/v1/traces"  # type: ignore[union-attr]
    )

    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        service_name = os.environ.get("OTEL_SERVICE_NAME", "ares-agent")
        resource_attrs = {"service.name": service_name}

        resource_attrs_str = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
        if resource_attrs_str:
            for raw_pair in resource_attrs_str.split(","):
                pair = raw_pair.strip()
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    resource_attrs[key.strip()] = value.strip()

        resource = Resource.create(resource_attrs)
        provider = TracerProvider(resource=resource)

        # Configure OTLP exporter
        # Use http/protobuf by default (matches K8s configmap OTEL_EXPORTER_OTLP_PROTOCOL)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _otel_initialized = True

        logger.info(f"OTEL tracing configured: {endpoint} (service: {service_name})")
        return True

    except ImportError as e:
        logger.warning(f"OTEL dependencies not available: {e}")
        return False
    except Exception as e:
        logger.warning(f"Failed to configure OTEL tracing: {e}")
        return False


# =============================================================================
# MITRE Tactic Mappings
# =============================================================================

# Map red team agent roles to primary MITRE tactics
ROLE_TO_TACTIC: dict[str, str] = {
    "orchestrator": "command-and-control",
    "recon": "discovery",
    "credential_access": "credential-access",
    "cracker": "credential-access",
    "acl": "privilege-escalation",
    "privesc": "privilege-escalation",
    "lateral": "lateral-movement",
    "coercion": "credential-access",
}

# Map blue team roles to their investigative focus
BLUE_ROLE_TO_TACTIC: dict[str, str] = {
    "orchestrator": "collection",  # Collecting investigation results
    "triage": "discovery",  # Initial discovery of threat indicators
    "threat_hunter": "discovery",  # Active threat hunting
    "lateral_analyst": "lateral-movement",  # Analyzing lateral movement
}

# =============================================================================
# MITRE Technique Mappings
# =============================================================================

# Map tool names to MITRE technique IDs
# This is a comprehensive mapping of Ares tools to their MITRE techniques
TOOL_TO_TECHNIQUE: dict[str, str] = {
    # Reconnaissance / Discovery
    "nmap_scan": "T1046",  # Network Service Discovery
    "portscan": "T1046",
    "ping_sweep": "T1018",  # Remote System Discovery
    "smb_sweep": "T1046",  # Network Service Scanning
    "resolve_domain_controllers": "T1018",  # Remote System Discovery
    "ldap_domain_dump": "T1087.002",  # Domain Account Discovery
    "ldap_search": "T1087.002",
    "ldap_search_descriptions": "T1087.002",
    "bloodhound_collection": "T1087.002",
    "run_bloodhound": "T1087.002",  # Domain Account Discovery (also T1482)
    "sharphound": "T1087.002",
    "get_domain_info": "T1087.002",
    "enumerate_users": "T1087.002",  # Domain Account Discovery
    "enum_domain_trusts": "T1482",  # Domain Trust Discovery
    "enumerate_domain_trusts": "T1482",  # Domain Trust Discovery
    "enumerate_foreign_security_principals": "T1482",  # Domain Trust Discovery
    "enumerate_forest": "T1482",
    "enum_constrained_delegation": "T1087.002",
    "enum_unconstrained_delegation": "T1087.002",
    "enum_rbcd_targets": "T1087.002",
    "smb_share_enum": "T1135",  # Network Share Discovery
    "enumerate_shares": "T1135",
    "smbclient_ls": "T1135",
    # Credential Access
    "secretsdump": "T1003.006",  # DCSync  # pragma: allowlist secret
    "secretsdump_kerberos": "T1003.006",  # pragma: allowlist secret
    "ntds_dit_extract": "T1003.003",  # NTDS
    "kerberoast": "T1558.003",  # Kerberoasting
    "targeted_kerberoast": "T1558.003",
    "asrep_roast": "T1558.004",  # AS-REP Roasting
    "certipy_auth": "T1649",  # Steal or Forge Authentication Certificates
    "certipy_find": "T1649",
    "laps_dump": "T1003.008",  # LSASS Memory
    "dump_lsass": "T1003.001",  # LSASS Memory
    "gpp_password_finder": "T1552.006",  # Group Policy Preferences  # pragma: allowlist secret
    "gmsa_dump_passwords": "T1003.006",  # pragma: allowlist secret
    "extract_trust_key": "T1003.006",
    "smbclient_spider": "T1552.001",  # Credentials in Files
    "sysvol_script_search": "T1552.001",
    # Credential cracking
    "hashcat_crack": "T1110.002",  # Password Cracking
    "crack_hash": "T1110.002",
    # Privilege Escalation
    "certipy_req": "T1649",  # ADCS abuse
    "rbcd_attack": "T1134.001",  # Token Impersonation
    "constrained_delegation_attack": "T1134.001",
    "unconstrained_delegation_attack": "T1558.001",  # Golden Ticket
    "dcsync": "T1003.006",  # DCSync
    "add_shadow_credentials": "T1556.006",  # Shadow Credentials
    "set_rbcd": "T1098.001",  # Account Manipulation
    "add_computer": "T1136.002",  # Create Account: Domain Account
    # ACL Exploitation
    "dacl_edit": "T1222.001",  # File/Dir Permissions Modification
    "add_user_to_group": "T1098.001",  # Account Manipulation
    "modify_owner": "T1222.001",
    "modify_dacl": "T1222.001",
    "write_gpo": "T1484.001",  # Group Policy Modification
    # Lateral Movement
    "psexec": "T1021.002",  # SMB/Windows Admin Shares
    "wmiexec": "T1047",  # WMI
    "smbexec": "T1021.002",
    "atexec": "T1053.005",  # Scheduled Task/Job
    "dcomexec": "T1021.003",  # Distributed COM
    "evil_winrm": "T1021.006",  # WinRM
    "rdp_connect": "T1021.001",  # RDP
    "ssh_connect": "T1021.004",  # SSH
    "mssql_exec": "T1021.002",  # SMB
    # Coercion / Relay
    "petitpotam": "T1187",  # Forced Authentication
    "printerbug": "T1187",
    "dfscoerce": "T1187",
    "shadowcoerce": "T1187",
    "coerce_auth": "T1187",
    "ntlm_relay": "T1557.001",  # LLMNR/NBT-NS Poisoning
    "relay_to_ldap": "T1557.001",
    "relay_to_smb": "T1557.001",
    # MSSQL
    "mssql_enum_impersonation": "T1078.002",  # Valid Accounts: Domain
    "mssql_enum_linked_servers": "T1021.002",
    "mssql_impersonate": "T1134.001",
    "mssql_xp_cmdshell": "T1059.001",  # Command and Scripting Interpreter
    # Golden Ticket / Persistence
    "generate_golden_ticket": "T1558.001",  # Golden Ticket
    "forge_golden_ticket": "T1558.001",  # Golden Ticket (alias)  # nosec B105
    "forge_silver_ticket": "T1558.002",  # Silver Ticket
    "create_machine_account": "T1136.002",
    # Reporting / Documentation tools
    "record_credential": "T1087.002",  # Account Discovery (documenting discovered credentials)
    "record_weakness": "T1518.001",  # Software Discovery: Security Software
    "record_timeline_event": "T1087",  # Account Discovery (general)
}

# Map tool categories to tactics for fallback
TOOL_CATEGORY_TO_TACTIC: dict[str, str] = {
    "NetworkEnumerationTools": "discovery",
    "BloodHoundTools": "discovery",
    "PostureValidationTools": "discovery",
    "TrustEnumerationTools": "discovery",
    "CredentialDiscoveryTools": "credential-access",
    "CredentialHarvestingTools": "credential-access",
    "SharePilferingTools": "collection",
    "CrackingTools": "credential-access",
    "ACLExploitTools": "privilege-escalation",
    "CertipyTools": "privilege-escalation",
    "DelegationTools": "privilege-escalation",
    "MSSQLTools": "lateral-movement",
    "CVEExploitTools": "privilege-escalation",
    "GoldenTicketTools": "persistence",
    "TrustAttackTools": "privilege-escalation",
    "GMSATools": "credential-access",
    "LateralMovementTools": "lateral-movement",
    "CoercionTools": "credential-access",
    "CoercionNetworkTools": "credential-access",
    "ReportingTools": "discovery",
}

# Map tool names to their category (toolset class name)
# This enables attack_tool_category span attribute for metrics/dashboards
TOOL_TO_CATEGORY: dict[str, str] = {
    # NetworkEnumerationTools - Discovery tools
    "nmap_scan": "NetworkEnumerationTools",
    "portscan": "NetworkEnumerationTools",
    "ping_sweep": "NetworkEnumerationTools",
    "smb_sweep": "NetworkEnumerationTools",
    "resolve_domain_controllers": "NetworkEnumerationTools",
    "ldap_domain_dump": "NetworkEnumerationTools",
    "ldap_search": "NetworkEnumerationTools",
    "ldap_search_descriptions": "NetworkEnumerationTools",
    "bloodhound_collection": "NetworkEnumerationTools",
    "run_bloodhound": "BloodHoundTools",
    "sharphound": "NetworkEnumerationTools",
    "get_domain_info": "NetworkEnumerationTools",
    "enumerate_users": "NetworkEnumerationTools",
    "enum_domain_trusts": "TrustEnumerationTools",
    "enumerate_domain_trusts": "TrustEnumerationTools",
    "enumerate_foreign_security_principals": "TrustEnumerationTools",
    "enumerate_forest": "NetworkEnumerationTools",
    "enum_constrained_delegation": "NetworkEnumerationTools",
    "enum_unconstrained_delegation": "NetworkEnumerationTools",
    "enum_rbcd_targets": "NetworkEnumerationTools",
    "smb_share_enum": "NetworkEnumerationTools",
    "enumerate_shares": "NetworkEnumerationTools",
    "smbclient_ls": "NetworkEnumerationTools",
    # CredentialHarvestingTools - Credential extraction
    "secretsdump": "CredentialHarvestingTools",  # pragma: allowlist secret
    "secretsdump_kerberos": "CredentialHarvestingTools",  # pragma: allowlist secret
    "ntds_dit_extract": "CredentialHarvestingTools",
    "kerberoast": "CredentialHarvestingTools",
    "targeted_kerberoast": "CredentialHarvestingTools",
    "asrep_roast": "CredentialHarvestingTools",
    "laps_dump": "CredentialHarvestingTools",
    "dump_lsass": "CredentialHarvestingTools",
    "gpp_password_finder": "CredentialHarvestingTools",  # pragma: allowlist secret
    "smbclient_spider": "SharePilferingTools",
    "sysvol_script_search": "SharePilferingTools",
    # GMSATools - GMSA password extraction
    "gmsa_dump_passwords": "GMSATools",  # pragma: allowlist secret
    # TrustAttackTools - Forest/trust attacks
    "extract_trust_key": "TrustAttackTools",
    # CertipyTools - ADCS attacks
    "certipy_auth": "CertipyTools",
    "certipy_find": "CertipyTools",
    "certipy_req": "CertipyTools",
    # CrackingTools - Hash cracking
    "hashcat_crack": "CrackingTools",
    "crack_hash": "CrackingTools",
    # DelegationTools - Delegation attacks
    "rbcd_attack": "DelegationTools",
    "constrained_delegation_attack": "DelegationTools",
    "unconstrained_delegation_attack": "DelegationTools",
    "set_rbcd": "DelegationTools",
    # PrivilegeEscalationTools - Generic privesc
    "dcsync": "PrivilegeEscalationTools",
    "add_shadow_credentials": "PrivilegeEscalationTools",
    "add_computer": "PrivilegeEscalationTools",
    # ACLExploitTools - ACL manipulation
    "dacl_edit": "ACLExploitTools",
    "add_user_to_group": "ACLExploitTools",
    "modify_owner": "ACLExploitTools",
    "modify_dacl": "ACLExploitTools",
    "write_gpo": "ACLExploitTools",
    # LateralMovementTools - Lateral movement
    "psexec": "LateralMovementTools",
    "wmiexec": "LateralMovementTools",
    "smbexec": "LateralMovementTools",
    "atexec": "LateralMovementTools",
    "dcomexec": "LateralMovementTools",
    "evil_winrm": "LateralMovementTools",
    "rdp_connect": "LateralMovementTools",
    "ssh_connect": "LateralMovementTools",
    "mssql_exec": "LateralMovementTools",
    # CoercionTools - NTLM coercion/relay
    "petitpotam": "CoercionTools",
    "printerbug": "CoercionTools",
    "dfscoerce": "CoercionTools",
    "shadowcoerce": "CoercionTools",
    "coerce_auth": "CoercionTools",
    "ntlm_relay": "CoercionTools",
    "relay_to_ldap": "CoercionTools",
    "relay_to_smb": "CoercionTools",
    # MSSQLTools - MSSQL attacks
    "mssql_enum_impersonation": "MSSQLTools",
    "mssql_enum_linked_servers": "MSSQLTools",
    "mssql_impersonate": "MSSQLTools",
    "mssql_xp_cmdshell": "MSSQLTools",
    # GoldenTicketTools - Kerberos ticket forging
    "forge_golden_ticket": "GoldenTicketTools",  # nosec B105
    "forge_silver_ticket": "GoldenTicketTools",
    "create_machine_account": "GoldenTicketTools",
    # ReportingTools - Documentation and findings recording
    "record_credential": "ReportingTools",
    "record_weakness": "ReportingTools",
    "record_timeline_event": "ReportingTools",
}

# =============================================================================
# Attack Phases
# =============================================================================

# Map agent roles to attack phases
ROLE_TO_PHASE: dict[str, str] = {
    "orchestrator": "coordination",
    "recon": "reconnaissance",
    "credential_access": "credential-theft",
    "cracker": "credential-theft",
    "acl": "privilege-escalation",
    "privesc": "privilege-escalation",
    "lateral": "lateral-movement",
    "coercion": "credential-theft",
}

# Blue team investigation phases
BLUE_ROLE_TO_PHASE: dict[str, str] = {
    "orchestrator": "coordination",
    "triage": "initial-triage",
    "threat_hunter": "threat-hunting",
    "lateral_analyst": "lateral-analysis",
}


# =============================================================================
# Target Type Detection
# =============================================================================

# Hostname patterns that indicate target type
DC_HOSTNAME_PATTERNS = {"dc", "dc01", "dc02", "dc1", "dc2", "pdc", "bdc", "domaincontroller"}
SQL_HOSTNAME_PATTERNS = {"sql", "sql01", "sql1", "mssql", "db", "database"}
WEB_HOSTNAME_PATTERNS = {"web", "www", "iis", "apache", "nginx"}
WORKSTATION_PATTERNS = {"ws", "pc", "desktop", "laptop", "client"}


def infer_target_type(hostname: str | None, dc_ips: set[str] | None = None) -> str | None:
    """Infer target type from hostname patterns.

    Args:
        hostname: Target hostname or IP.
        dc_ips: Optional set of known DC IPs for matching.

    Returns:
        Target type string or None if unknown.
    """
    if not hostname:
        return None

    hostname_lower = hostname.lower().split(".")[0]

    if dc_ips and hostname in dc_ips:
        return "domain_controller"

    if hostname_lower in DC_HOSTNAME_PATTERNS or hostname_lower.startswith("dc"):
        return "domain_controller"
    if any(hostname_lower.startswith(p) for p in SQL_HOSTNAME_PATTERNS):
        return "sql_server"
    if any(hostname_lower.startswith(p) for p in WEB_HOSTNAME_PATTERNS):
        return "web_server"
    if any(hostname_lower.startswith(p) for p in WORKSTATION_PATTERNS):
        return "workstation"

    # Default to server for other hostnames
    return "server"


# =============================================================================
# Span Creation Functions
# =============================================================================


def _get_current_span_for_events() -> Span | None:
    """Get current span if it is recording, else None for fallback.

    This helper enables the event-based tracing pattern: when there's an active
    span (e.g., the worker's process_task span), we add events to it instead of
    creating orphan child spans. If no active span exists, callers can fall back
    to creating standalone spans for backward compatibility.

    Returns:
        The current span if it exists and is recording, otherwise None.
    """
    span = trace.get_current_span()
    if span and span.is_recording():
        return span
    return None


def get_tool_mitre_info(tool_name: str) -> tuple[str | None, str | None]:
    """Get MITRE technique ID and tactic for a tool.

    Args:
        tool_name: Name of the tool being executed.

    Returns:
        Tuple of (technique_id, tactic) or (None, None) if not mapped.
    """
    technique_id = TOOL_TO_TECHNIQUE.get(tool_name)
    tactic = None

    if technique_id:
        # Derive tactic from technique ID prefix patterns
        if technique_id.startswith(("T1087", "T1018", "T1046", "T1135", "T1482", "T1518")):
            tactic = "discovery"
        elif technique_id.startswith(("T1003", "T1558", "T1187", "T1557", "T1552", "T1110")):
            tactic = "credential-access"
        elif technique_id.startswith(("T1134", "T1098", "T1078", "T1222", "T1484", "T1649")):
            tactic = "privilege-escalation"
        elif technique_id.startswith(("T1021", "T1047", "T1053")):
            tactic = "lateral-movement"
        elif technique_id.startswith(("T1136",)):
            tactic = "persistence"
        elif technique_id.startswith(("T1059",)):
            tactic = "execution"

    return technique_id, tactic


def get_tool_category(tool_name: str) -> str | None:
    """Get the category (toolset class name) for a tool.

    Args:
        tool_name: Name of the tool being executed.

    Returns:
        Category string (e.g., "LateralMovementTools") or None if not mapped.
    """
    return TOOL_TO_CATEGORY.get(tool_name)


def create_agent_span_attributes(
    role: str,
    team: str,
    tool_name: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_environment: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
    dc_ips: set[str] | None = None,
    credential_domain: str | None = None,
) -> dict[str, Any]:
    """Create span attributes for an agent operation.

    Args:
        role: Agent role (e.g., "recon", "credential_access").
        team: Team name ("red" or "blue").
        tool_name: Optional tool being executed.
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN (e.g., "dc01.contoso.local").
        target_hostname: Optional hostname (e.g., "dc01").
        target_type: Optional target type (e.g., "domain_controller", "server", "workstation", "user").
        target_user: Optional target username (e.g., "svc_backup").
        target_domain: Optional target domain (e.g., "contoso.local").
        target_environment: Optional target environment (e.g., "dev", "staging", "prod").
        additional_attrs: Optional additional attributes to include.
        dc_ips: Optional set of known DC IP addresses for target type inference.
        credential_domain: Optional domain where the authenticating credential belongs
            (may differ from target_domain in cross-domain/trust scenarios).

    Returns:
        Dictionary of span attributes.
    """
    attrs: dict[str, Any] = {
        "attack_team": team,
        "agent.role": role,
    }

    if team == "red":
        phase = ROLE_TO_PHASE.get(role, "unknown")
        tactic = ROLE_TO_TACTIC.get(role, "unknown")
    else:
        phase = BLUE_ROLE_TO_PHASE.get(role, "investigation")
        tactic = BLUE_ROLE_TO_TACTIC.get(role, "discovery")

    attrs["attack_phase"] = phase
    attrs["mitre.tactic"] = tactic

    # Get tool-specific MITRE info
    if tool_name:
        technique_id, tool_tactic = get_tool_mitre_info(tool_name)
        if technique_id:
            attrs["mitre.technique.id"] = technique_id
        if tool_tactic:
            # Tool-specific tactic overrides role default
            attrs["mitre.tactic"] = tool_tactic
        attrs["tool.name"] = tool_name
        # Set attack_tool_name for Tempo metrics extraction
        attrs["attack_tool_name"] = tool_name
        # Set attack_tool_category for dashboard grouping
        category = get_tool_category(tool_name)
        if category:
            attrs["attack_tool_category"] = category

    # Add target attributes using OTel semantic conventions
    # IMPORTANT: Keep IP and FQDN in SEPARATE fields for clean dashboard filtering
    #
    # destination.address = FQDN only (for dashboard "Target FQDN" column)
    # destination.ip = IP only (for dashboard "Target IP" column)
    # server.address = FQDN (OTel standard for server hostname)

    # Set destination.address to FQDN only
    if target_fqdn:
        attrs["destination.address"] = target_fqdn
        attrs["server.address"] = target_fqdn

    # Set destination.ip to IP only (never FQDN)
    if target_ip:
        attrs["destination.ip"] = target_ip

    # Add hostname as host.name (OTel standard)
    if target_hostname:
        attrs["host.name"] = target_hostname
    elif target_fqdn:
        attrs["host.name"] = target_fqdn.split(".")[0]

    # Indicate hostname resolution quality for observability
    # - "fqdn": Full FQDN available (e.g., dc01.contoso.local)
    # - "netbios": Only NetBIOS/plain hostname (e.g., dc01) - resolution failed or unavailable
    # - "ip_only": Only IP address, no hostname at all
    if target_fqdn:
        attrs["host.name.type"] = "fqdn"
    elif target_hostname:
        attrs["host.name.type"] = "netbios"
    elif target_ip:
        attrs["host.name.type"] = "ip_only"

    if target_user:
        # OTel standard: user.name for usernames
        attrs["user.name"] = target_user

    # Custom attack namespace for domain-specific enrichment
    # Determine target host for type inference (prefer FQDN > hostname > IP)
    effective_host = target_fqdn or target_hostname or target_ip
    if target_type:
        attrs["attack_target_type"] = target_type
    elif effective_host:
        # Infer target type if not provided, using DC IPs for accurate detection
        inferred_type = infer_target_type(effective_host, dc_ips)
        if inferred_type:
            attrs["attack_target_type"] = inferred_type
    elif target_user:
        # If only user is specified, target type is user
        attrs["attack_target_type"] = "user"

    if target_domain:
        attrs["attack_target_domain"] = target_domain
    elif target_fqdn and "." in target_fqdn:
        # Extract domain from FQDN
        parts = target_fqdn.split(".", 1)
        if len(parts) > 1:
            attrs["attack_target_domain"] = parts[1]

    # Credential domain: where the authenticating user actually belongs
    # This differs from target_domain in cross-domain/trust scenarios
    # (e.g., child domain user attacking parent domain)
    if credential_domain:
        attrs["credential.domain"] = credential_domain

    # Add target environment for filtering spans by deployment target
    # OTel requires primitive types - ensure string even if dict was passed
    if target_environment:
        if isinstance(target_environment, str):
            attrs["target.environment"] = target_environment
        elif isinstance(target_environment, dict):
            # Handle case where target_environment is accidentally a dict
            # (e.g., from deserialization of Target object)
            attrs["target.environment"] = str(target_environment.get("environment", ""))
        else:
            attrs["target.environment"] = str(target_environment)

    # Merge additional attributes
    if additional_attrs:
        attrs.update(additional_attrs)

    return attrs


@contextmanager
def agent_span(
    name: str,
    role: str,
    team: str,
    tool_name: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_environment: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
    dc_ips: set[str] | None = None,
    credential_domain: str | None = None,
):
    """Create a traced span for agent operations.

    This context manager creates an OpenTelemetry span with proper
    MITRE ATT&CK attributes for observability.

    Args:
        name: Span name (e.g., "tool_execution", "agent_step").
        role: Agent role (e.g., "recon", "credential_access").
        team: Team name ("red" or "blue").
        tool_name: Optional tool being executed.
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN (e.g., "dc01.contoso.local").
        target_hostname: Optional hostname (e.g., "dc01").
        target_type: Optional target type.
        target_user: Optional target username.
        target_domain: Optional target domain (where the attack is directed).
        target_environment: Optional target environment.
        additional_attrs: Optional additional attributes.
        dc_ips: Optional set of known DC IP addresses for target type inference.
        credential_domain: Optional domain where the credential belongs (may differ
            from target_domain in cross-domain/trust scenarios).

    Yields:
        The span object for adding additional attributes.

    Example:
        >>> with agent_span("tool_execution", "recon", "red", "nmap_scan",
        ...                 target_ip="192.168.58.10") as span:
        ...     # Execute tool
        ...     pass
    """
    attrs = create_agent_span_attributes(
        role,
        team,
        tool_name,
        target_ip,
        target_fqdn,
        target_hostname,
        target_type,
        target_user,
        target_domain,
        target_environment,
        additional_attrs,
        dc_ips,
        credential_domain,
    )

    with dn.span(name, attributes=attrs) as span:
        yield span


def trace_tool_call(
    role: str,
    team: str,
    tool_name: str,
    is_error: bool = False,
    error_message: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    dc_ips: set[str] | None = None,
    operation_id: str | None = None,
    credential_domain: str | None = None,
) -> None:
    """Record a tool call as an event on the current span, or standalone span as fallback.

    Prefers adding an event to the current active span (e.g., worker's process_task
    span) to avoid creating orphan spans that appear disconnected in Tempo.
    Falls back to creating a standalone span if no active span exists.

    Args:
        role: Agent role executing the tool.
        team: Team name ("red" or "blue").
        tool_name: Name of the tool being executed.
        is_error: Whether the tool call resulted in an error.
        error_message: Optional error message if is_error is True.
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN (e.g., "dc01.contoso.local").
        target_hostname: Optional hostname (e.g., "dc01").
        target_type: Optional target type.
        target_user: Optional target username.
        target_domain: Optional target domain (where the attack is directed).
        dc_ips: Optional set of known DC IP addresses for target type inference.
        operation_id: Optional operation ID for correlation (attack_operation_id).
        credential_domain: Optional domain where the credential belongs (may differ
            from target_domain in cross-domain/trust scenarios).
    """
    attrs = create_agent_span_attributes(
        role,
        team,
        tool_name,
        target_ip=target_ip,
        target_fqdn=target_fqdn,
        target_hostname=target_hostname,
        target_type=target_type,
        target_user=target_user,
        target_domain=target_domain,
        dc_ips=dc_ips,
        credential_domain=credential_domain,
    )
    attrs["tool.status"] = "error" if is_error else "success"
    if is_error and error_message:
        attrs["error.message"] = error_message[:500]  # Truncate long errors
    if operation_id:
        attrs["attack_operation_id"] = operation_id

    try:
        # Prefer adding event to current span to avoid orphan spans
        current_span = _get_current_span_for_events()
        if current_span:
            current_span.add_event(f"tool.{tool_name}", attributes=attrs)
            return

        # Fallback: standalone span (backward compat when no active span)
        with dn.span(f"tool.{tool_name}", attributes=attrs):
            pass  # Point-in-time span
    except Exception as e:
        # Don't let tracing errors break the agent
        logger.debug(f"Failed to create trace span: {e}")


def trace_discovery(
    discovery_type: str,
    source_agent: str,
    operation_id: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    weakness_type: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
) -> None:
    """Record a discovery as an event on the current span, or standalone span as fallback.

    Prefers adding an event to the current active span (e.g., worker's process_task
    span) to avoid creating orphan spans that appear disconnected in Tempo.
    Falls back to creating a standalone span if no active span exists.

    Creates events/spans for state-changing discoveries like credentials,
    hashes, weaknesses, and vulnerabilities. These are separate from
    tool calls because the discovery info is extracted from tool OUTPUT,
    not arguments.

    Args:
        discovery_type: Type of discovery ("credential", "hash", "weakness", "vulnerability").
        source_agent: Agent that made the discovery.
        operation_id: Operation ID for correlation.
        target_user: Username discovered (for credentials/hashes).
        target_domain: Domain of the target.
        target_ip: Optional target IP.
        target_fqdn: Optional target FQDN.
        target_hostname: Optional target hostname.
        weakness_type: Type of weakness (e.g., "constrained_delegation").
        additional_attrs: Optional additional attributes.
    """
    attrs: dict[str, Any] = {
        "service.namespace": "ares",
        "attack_team": "red",
        "attack_phase": "discovery",
        "discovery.type": discovery_type,
        "discovery.source_agent": source_agent,
    }

    if operation_id:
        attrs["attack_operation_id"] = operation_id

    # Add target info using OTel conventions
    if target_user:
        attrs["user.name"] = target_user
        attrs["attack_target_type"] = "user"

    if target_domain:
        attrs["attack_target_domain"] = target_domain

    if target_ip:
        attrs["destination.ip"] = target_ip

    if target_fqdn:
        attrs["destination.address"] = target_fqdn
        attrs["server.address"] = target_fqdn
        if not target_hostname:
            attrs["host.name"] = target_fqdn.split(".")[0]

    if target_hostname:
        attrs["host.name"] = target_hostname

    if weakness_type:
        attrs["weakness.type"] = weakness_type
        # Map weakness types to MITRE techniques
        weakness_mitre_map = {
            "constrained_delegation": "T1134.001",
            "unconstrained_delegation": "T1558.001",
            "kerberoastable": "T1558.003",
            "asreproastable": "T1558.004",
            "dcsync_rights": "T1003.006",
        }
        if weakness_type in weakness_mitre_map:
            attrs["mitre.technique.id"] = weakness_mitre_map[weakness_type]

    if additional_attrs:
        attrs.update(additional_attrs)

    try:
        # Prefer adding event to current span to avoid orphan spans
        current_span = _get_current_span_for_events()
        if current_span:
            current_span.add_event(f"discovery.{discovery_type}", attributes=attrs)
            return

        # Fallback: standalone span (backward compat when no active span)
        with dn.span(f"discovery.{discovery_type}", attributes=attrs):
            pass  # Point-in-time span
    except Exception as e:
        logger.debug(f"Failed to create discovery span: {e}")


def trace_decision(
    role: str,
    team: str,
    tools_considered: list[str],
    tool_chosen: str,
    reasoning_summary: str,
    confidence: float | None = None,
    operation_id: str | None = None,
    task_id: str | None = None,
) -> None:
    """Record an agent tool selection decision as an event on the current span, or standalone span as fallback.

    Prefers adding an event to the current active span (e.g., worker's process_task
    span) to avoid creating orphan spans that appear disconnected in Tempo.
    Falls back to creating a standalone span if no active span exists.

    Captures why an agent chose specific tools, including
    the reasoning and alternatives considered. This enables post-hoc analysis
    of agent decision patterns in Tempo.

    Args:
        role: Agent role making the decision (e.g., "credential_access").
        team: Team name ("red" or "blue").
        tools_considered: List of tool names the agent could have chosen.
        tool_chosen: The tool name that was actually selected.
        reasoning_summary: Truncated reasoning text from LLM response.
        confidence: Optional confidence score (0.0 to 1.0) inferred from language.
        operation_id: Optional operation ID for correlation.
        task_id: Optional task ID for correlation.
    """
    attrs: dict[str, Any] = {
        "service.namespace": "ares",
        "attack_team": team,
        "agent.role": role,
        "decision.type": "tool_selection",
        "decision.tool_chosen": tool_chosen,
        "decision.reasoning_length": len(reasoning_summary),
    }

    # Store up to 5 considered tools (OTel array attribute)
    if tools_considered:
        attrs["decision.tools_considered"] = tools_considered[:5]

    if confidence is not None:
        attrs["decision.confidence"] = confidence

    if operation_id:
        attrs["attack_operation_id"] = operation_id

    if task_id:
        attrs["task.id"] = task_id

    # Add MITRE technique for the chosen tool
    technique_id = TOOL_TO_TECHNIQUE.get(tool_chosen)
    if technique_id:
        attrs["mitre.technique.id"] = technique_id

    # Add tool category for the chosen tool
    category = TOOL_TO_CATEGORY.get(tool_chosen)
    if category:
        attrs["attack_tool_category"] = category

    try:
        # Prefer adding event to current span to avoid orphan spans
        current_span = _get_current_span_for_events()
        if current_span:
            current_span.add_event(f"decision.{role}", attributes=attrs)
            return

        # Fallback: standalone span (backward compat when no active span)
        with dn.span(f"decision.{role}", attributes=attrs):
            pass  # Point-in-time span
    except Exception as e:
        logger.debug(f"Failed to create decision span: {e}")


def trace_blue_investigation(
    role: str,
    investigation_id: str,
    techniques_found: list[str] | None = None,
    severity: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    operation_id: str | None = None,
) -> None:
    """Record a blue team investigation span.

    Creates a span for blue team investigation activities with
    proper attributes for dashboard correlation.

    Args:
        role: Blue team role (e.g., "triage", "threat_hunter").
        investigation_id: ID of the investigation.
        techniques_found: List of MITRE technique IDs found.
        severity: Severity assessment if available.
        target_ip: Optional target IP being investigated.
        target_fqdn: Optional target FQDN being investigated.
        target_user: Optional target user being investigated.
        target_domain: Optional target domain.
        operation_id: Red team operation ID for correlation (attack_operation_id).
    """
    attrs = create_agent_span_attributes(
        role,
        "blue",
        target_ip=target_ip,
        target_fqdn=target_fqdn,
        target_user=target_user,
        target_domain=target_domain,
    )
    attrs["investigation.id"] = investigation_id

    if techniques_found:
        # Set the first technique as the primary one
        attrs["mitre.technique.id"] = techniques_found[0]
        attrs["mitre.techniques.count"] = len(techniques_found)

    if severity:
        attrs["investigation.severity"] = severity

    if operation_id:
        attrs["attack_operation_id"] = operation_id

    try:
        with dn.span(f"investigation.{role}", attributes=attrs):
            pass
    except Exception as e:
        logger.debug(f"Failed to create investigation span: {e}")


# =============================================================================
# Service Graph Spans (CLIENT/SERVER for Tempo service graph)
# =============================================================================

# Get a tracer for spans that need explicit span kinds
_tracer = trace.get_tracer("ares.agents")


@contextmanager
def _create_span_context(
    name: str,
    kind: SpanKind,
    attrs: dict[str, Any],
):
    """Internal factory for span context managers.

    Creates a span with proper error handling and cleanup.

    Args:
        name: Span name.
        kind: OpenTelemetry SpanKind (CLIENT, SERVER, PRODUCER, CONSUMER).
        attrs: Span attributes dict.

    Yields:
        The span object (may be None if creation failed).
    """
    span = None
    try:
        span = _tracer.start_span(name, kind=kind, attributes=attrs)
    except Exception as e:
        logger.debug(f"Failed to create {kind.name.lower()} span: {e}")
    try:
        yield span
    finally:
        if span:
            span.end()


@contextmanager
def client_span(
    name: str,
    target_service: str,
    role: str,
    team: str,
    tool_name: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_environment: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
    credential_domain: str | None = None,
):
    """Create a CLIENT span for outgoing calls to another service.

    Use this when the orchestrator dispatches work to an agent.
    The target_service attribute enables Tempo service graph.

    Args:
        name: Span name (e.g., "dispatch_agent", "call_agent").
        target_service: Name of the service being called (e.g., "ares-credential-access-agent").
        role: Agent role making the call.
        team: Team name ("red" or "blue").
        tool_name: Optional tool being requested.
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN.
        target_hostname: Optional hostname.
        target_type: Optional target type.
        target_user: Optional target username.
        target_domain: Optional target domain.
        target_environment: Optional target environment.
        additional_attrs: Optional additional attributes.
        credential_domain: Optional domain where the credential belongs.

    Yields:
        The span object for adding additional attributes.

    Example:
        >>> with client_span("dispatch", "ares-recon-agent", "orchestrator", "red",
        ...                  target_fqdn="dc01.contoso.local") as span:
        ...     # Dispatch task to agent
        ...     span.set_attribute("task.id", task_id)
    """
    attrs = create_agent_span_attributes(
        role,
        team,
        tool_name,
        target_ip,
        target_fqdn,
        target_hostname,
        target_type,
        target_user,
        target_domain,
        target_environment,
        additional_attrs,
        credential_domain=credential_domain,
    )
    # peer.service is the standard OTel attribute for service graph edges
    attrs["peer.service"] = target_service
    attrs["rpc.service"] = target_service

    with _create_span_context(name, SpanKind.CLIENT, attrs) as span:
        yield span


@contextmanager
def server_span(
    name: str,
    role: str,
    team: str,
    tool_name: str | None = None,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_environment: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
    credential_domain: str | None = None,
):
    """Create a SERVER span for incoming requests.

    Use this when an agent receives and handles a task.
    SERVER spans pair with CLIENT spans for Tempo service graph.

    Args:
        name: Span name (e.g., "handle_task", "execute_tool").
        role: Agent role handling the request.
        team: Team name ("red" or "blue").
        tool_name: Optional tool being executed.
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN.
        target_hostname: Optional hostname.
        target_type: Optional target type.
        target_user: Optional target username.
        target_domain: Optional target domain.
        target_environment: Optional target environment.
        additional_attrs: Optional additional attributes.
        credential_domain: Optional domain where the credential belongs.

    Yields:
        The span object for adding additional attributes.

    Example:
        >>> with server_span("handle_task", "credential_access", "red",
        ...                  target_fqdn="dc01.contoso.local") as span:
        ...     # Execute the agent's task
        ...     span.set_attribute("task.id", task_id)
    """
    attrs = create_agent_span_attributes(
        role,
        team,
        tool_name,
        target_ip,
        target_fqdn,
        target_hostname,
        target_type,
        target_user,
        target_domain,
        target_environment,
        additional_attrs,
        credential_domain=credential_domain,
    )

    with _create_span_context(name, SpanKind.SERVER, attrs) as span:
        yield span


@contextmanager
def producer_span(
    name: str,
    target_service: str,
    role: str,
    team: str,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_environment: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
    dc_ips: set[str] | None = None,
    credential_domain: str | None = None,
):
    """Create a PRODUCER span for async message publishing.

    Use this when publishing tasks to a queue for async processing.

    Args:
        name: Span name (e.g., "publish_task", "enqueue").
        target_service: Name of the consuming service.
        role: Agent role publishing the message.
        team: Team name ("red" or "blue").
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN.
        target_hostname: Optional hostname.
        target_type: Optional target type.
        target_user: Optional target username.
        target_domain: Optional target domain.
        dc_ips: Optional set of known DC IP addresses for target type inference.
        target_environment: Optional target environment.
        additional_attrs: Optional additional attributes.
        credential_domain: Optional domain where the credential belongs.

    Yields:
        The span object for adding additional attributes.
    """
    attrs = create_agent_span_attributes(
        role,
        team,
        None,
        target_ip,
        target_fqdn,
        target_hostname,
        target_type,
        target_user,
        target_domain,
        target_environment,
        additional_attrs,
        dc_ips,
        credential_domain,
    )
    attrs["messaging.destination.name"] = target_service
    attrs["peer.service"] = target_service

    with _create_span_context(name, SpanKind.PRODUCER, attrs) as span:
        yield span


@contextmanager
def consumer_span(
    name: str,
    role: str,
    team: str,
    target_ip: str | None = None,
    target_fqdn: str | None = None,
    target_hostname: str | None = None,
    target_type: str | None = None,
    target_user: str | None = None,
    target_domain: str | None = None,
    target_environment: str | None = None,
    additional_attrs: dict[str, Any] | None = None,
    dc_ips: set[str] | None = None,
    credential_domain: str | None = None,
):
    """Create a CONSUMER span for async message consumption.

    Use this when consuming tasks from a queue.

    Args:
        name: Span name (e.g., "consume_task", "process_message").
        role: Agent role consuming the message.
        team: Team name ("red" or "blue").
        target_ip: Optional validated IP address.
        target_fqdn: Optional FQDN.
        target_hostname: Optional hostname.
        target_type: Optional target type.
        target_user: Optional target username.
        target_domain: Optional target domain.
        target_environment: Optional target environment.
        additional_attrs: Optional additional attributes.
        dc_ips: Optional set of known DC IP addresses for target type inference.
        credential_domain: Optional domain where the credential belongs.

    Yields:
        The span object for adding additional attributes.
    """
    attrs = create_agent_span_attributes(
        role,
        team,
        None,
        target_ip,
        target_fqdn,
        target_hostname,
        target_type,
        target_user,
        target_domain,
        target_environment,
        additional_attrs,
        dc_ips,
        credential_domain,
    )

    with _create_span_context(name, SpanKind.CONSUMER, attrs) as span:
        yield span
