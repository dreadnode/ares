"""Capability Registry for Config-Driven Tool Access.

This module maps YAML capability strings to tool method names, enabling
the multi-agent-production.yaml to control which tools each agent role
has access to.

The CAPABILITY_REGISTRY is the single source of truth for mapping binary/tool
capabilities (e.g., "nmap", "impacket-secretsdump") to the actual tool method
names defined in the toolset classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dreadnode.agent.tools.base import Toolset

if TYPE_CHECKING:
    from dreadnode.agent.tools.base import AnyTool as Tool

# Maps YAML capability string -> list of tool method names it enables
# This is the authoritative mapping between external tool names and internal method names
CAPABILITY_REGISTRY: dict[str, list[str]] = {
    # ===================
    # Network/Recon Tools
    # ===================
    "nmap": ["nmap_scan"],
    "netexec": [
        "smb_sweep",
        "enumerate_users",
        "enumerate_shares",
        "password_spray",
        "username_as_password",
        "password_policy",
        "laps_dump",  # netexec ldap -M laps
        "check_credman_entries",
        "check_autologon_registry",
        "check_lm_compatibility_level",
        "check_webclient_service",
        "check_rdp_sessions",
        "smbclient_spider",
        "gpp_password_finder",
        "sysvol_script_search",
        "domain_admin_checker",  # netexec smb -x whoami
        "zerologon_check",  # netexec smb -M zerologon
    ],
    "rpcclient": ["enumerate_users", "force_change_password"],
    "ldapsearch": [
        "ldap_search_descriptions",
        "check_sidhistory",
        "enumerate_domain_netbios_mappings",
        "enumerate_domain_trusts",
    ],
    "enum4linux": ["enumerate_users"],
    "enum4linux-ng": ["enumerate_users"],
    "dig": ["resolve_domain_controllers"],
    "nslookup": ["resolve_domain_controllers"],
    "whois": [],  # Not directly mapped to a tool method
    "adidnsdump": ["adidnsdump"],
    # ===================
    # BloodHound
    # ===================
    "bloodhound-python": ["run_bloodhound"],
    # ===================
    # Impacket Tools
    # ===================
    "impacket-secretsdump": [
        "secretsdump",
        "secretsdump_kerberos",
        "extract_trust_key",
        "ntds_dit_extract",
    ],
    "impacket-psexec": ["psexec", "psexec_kerberos"],
    "impacket-wmiexec": ["wmiexec", "wmiexec_kerberos"],
    "impacket-smbexec": ["smbexec", "smbexec_kerberos"],
    "impacket-getst": ["s4u_attack"],
    "impacket-gettgt": ["get_tgt"],
    "impacket-getuserspns": ["kerberoast"],
    "impacket-getnpusers": ["asrep_roast", "kerberos_user_enum_noauth"],
    "impacket-ticketer": ["generate_golden_ticket", "create_inter_realm_ticket"],
    "impacket-dacledit": ["dacl_edit"],
    "impacket-ntlmrelayx": [
        "ntlmrelayx_to_ldaps",
        "ntlmrelayx_to_adcs",
        "ntlmrelayx_to_smb",
        "ntlmrelayx_multirelay",
    ],
    "impacket-addcomputer": ["add_computer"],
    "impacket-finddelegation": ["find_delegation"],
    "impacket-lookupsid": ["get_sid"],
    "impacket-raisechild": ["raise_child"],
    "impacket-mssqlclient": [
        "mssql_command",
        "mssql_enable_xp_cmdshell",
        "mssql_enum_impersonation",
        "mssql_impersonate",
        "mssql_enum_linked_servers",
        "mssql_exec_linked",
        "mssql_ntlm_coerce",
        "mssql_linked_enable_xpcmdshell",
        "mssql_linked_xpcmdshell",
    ],
    "impacket-rbcd": ["rbcd_write"],
    # ===================
    # ADCS/Certipy
    # ===================
    "certipy": [
        "certipy_find",
        "certipy_request",
        "certipy_auth",
        "certipy_shadow",
        "certipy_template_esc4",
        "certipy_esc4_full_chain",
    ],
    # ===================
    # ACL Abuse Tools
    # ===================
    "bloodyad": [
        "bloodyad_add_group_member",
        "bloodyad_set_password",
        "bloodyad_add_genericall",
        "adminsd_holder_add_ace",
        "gmsa_read_password_bloodyad",
    ],
    "pywhisker": ["pywhisker"],
    "targetedkerberoast": ["targeted_kerberoast"],
    "sharpgpoabuse": ["sharpgpoabuse"],
    "pygpoabuse": ["pygpoabuse_immediate_task"],
    # ===================
    # Coercion Tools
    # ===================
    "responder": ["start_responder"],
    "mitm6": ["start_mitm6"],
    "coercer": ["coercer"],
    "petitpotam": ["petitpotam", "petitpotam_unauth"],
    "dfscoerce": ["dfscoerce"],
    "printerbug": ["unconstrained_coerce_and_capture"],
    "krbrelayx": [],  # Used for relay attacks but no direct method mapping
    "addspn": ["addspn"],  # SPN manipulation for Kerberoast/delegation attacks
    "dnstool": ["dnstool"],  # DNS record manipulation for relay attacks
    # ===================
    # Kerberos Attack Tools
    # ===================
    "nopac": ["nopac"],
    "krbrelayup": ["krbrelayup"],
    # ===================
    # Lateral Movement
    # ===================
    "evil-winrm": ["evil_winrm"],
    "xfreerdp": ["xfreerdp"],
    "sshpass": ["ssh_with_password"],
    "proxychains4": [],  # Infrastructure tool, not a method
    # Pass-the-Hash toolkit (apt: passing-the-hash)
    "pth-winexe": ["pth_winexe"],
    "pth-smbclient": ["pth_smbclient"],
    "pth-rpcclient": ["pth_rpcclient"],
    "pth-net": [],  # PTH net commands - not directly mapped
    "pth-wmic": ["pth_wmic"],
    # ===================
    # SMB Tools
    # ===================
    "smbclient": [
        "smbclient_spider",
        "smbclient_kerberos_shares",
        "sysvol_script_search",
    ],
    # ===================
    # Credential Harvesting
    # ===================
    "lsassy": ["unconstrained_tgt_dump", "lsassy"],
    "sprayhound": ["password_spray"],
    "gmsadumper": ["gmsa_dump_passwords"],
    # ===================
    # Cracking Tools
    # ===================
    "hashcat": ["crack_with_hashcat"],
    "john": ["crack_with_john"],
    "rockyou": [],  # Wordlist, not a tool method
    "seclists": [],  # Wordlist collection, not a tool method
    # ===================
    # CVE Exploits
    # ===================
    "printnightmare": ["printnightmare"],
    "zerologon": [],  # Zerologon check now uses netexec -M zerologon
    # ===================
    # Windows Privesc Binaries (PrivilegeEscalationTools toolset)
    # Config uses PascalCase to match binary names, registry normalizes to lowercase
    # NOTE: krbrelayup, sharpgpoabuse are defined earlier - do not duplicate!
    # ===================
    "printspoofer": ["printspoofer"],  # SeImpersonatePrivilege exploit
    "godpotato": ["godpotato"],  # SeImpersonatePrivilege exploit
    "sweetpotato": ["sweetpotato"],  # SeImpersonatePrivilege exploit
    "seatbelt": ["seatbelt"],  # Windows enumeration
    "sharpup": ["sharpup"],  # Privesc checks
    "runascs": ["runas_cs"],  # Run commands as another user
    "scmuacbypass": ["scm_uac_bypass"],  # UAC bypass via SCM
    "powerup": ["powerup"],  # PowerShell privesc enumeration
    "powerupsql": ["powerupsql"],  # MSSQL enumeration/exploitation
    "winpeas": ["winpeas"],  # Windows privesc enumeration
    "linpeas": ["linpeas"],  # Linux privesc enumeration
    # ===================
    # Posture Validation (always available for status checks)
    # ===================
    "posture_validation": [
        "check_rdp_reachability",
        "check_winrm_reachability",
        "save_users_to_file",
    ],
}


def get_enabled_tools(capabilities: set[str]) -> set[str]:
    """Get all tool method names enabled by the given capabilities.

    Args:
        capabilities: Set of capability strings from YAML config.

    Returns:
        Set of tool method names that are enabled by the given capabilities.
    """
    enabled: set[str] = set()
    for cap in capabilities:
        # Normalize capability name (case-insensitive lookup)
        cap_lower = cap.lower()
        if cap_lower in CAPABILITY_REGISTRY:
            enabled.update(CAPABILITY_REGISTRY[cap_lower])
        elif cap in CAPABILITY_REGISTRY:
            enabled.update(CAPABILITY_REGISTRY[cap])
    return enabled


class FilteredToolset(Toolset):
    """Wrapper that filters a toolset's tools based on enabled capabilities.

    This class wraps a Toolset and only exposes tools whose names are in
    the enabled_tools set. This allows the YAML capabilities configuration
    to control which tools each agent role has access to.

    Inherits from Toolset so the dreadnode SDK recognizes it properly.
    """

    def __init__(self, toolset: Toolset, enabled_tools: set[str]) -> None:
        """Initialize the filtered toolset.

        Args:
            toolset: The original toolset to wrap.
            enabled_tools: Set of tool method names that should be exposed.
        """
        # Don't call super().__init__() - we're a wrapper, not a real toolset
        self._toolset = toolset
        self._enabled_tools = enabled_tools

    def get_tools(self, *, variant: str | None = None) -> list[Tool]:
        """Return only tools whose names are in enabled_tools.

        Args:
            variant: Optional variant string passed to underlying toolset.

        Returns:
            List of Tool objects that are enabled by capabilities.
        """
        all_tools = self._toolset.get_tools(variant=variant)
        return [t for t in all_tools if t.name in self._enabled_tools]

    def __getattr__(self, name: str) -> Any:
        """Delegate all other attributes to the wrapped toolset."""
        return getattr(self._toolset, name)

    def __repr__(self) -> str:
        """Return a string representation of the filtered toolset."""
        return f"FilteredToolset({self._toolset.__class__.__name__}, enabled={len(self._enabled_tools)} tools)"


def create_filtered_toolsets(
    toolset_classes: list[type],
    enabled_tools: set[str],
    shared_state: Any = None,
    dispatcher: Any = None,
) -> list[FilteredToolset]:
    """Create filtered toolset instances from a list of toolset classes.

    Instantiates each toolset class, sets state/dispatcher if applicable,
    wraps in FilteredToolset, and returns only those with at least one
    enabled tool.

    Args:
        toolset_classes: List of toolset classes to instantiate.
        enabled_tools: Set of tool method names that should be exposed.
        shared_state: Optional shared state to set on toolsets.
        dispatcher: Optional dispatcher to set on toolsets.

    Returns:
        List of FilteredToolset wrappers that have at least one enabled tool.
    """
    filtered_toolsets: list[FilteredToolset] = []

    for cls in toolset_classes:
        toolset = cls()

        # Set state if the toolset supports it
        if hasattr(toolset, "set_state") and shared_state is not None:
            toolset.set_state(shared_state)

        # Set dispatcher if the toolset supports it
        if hasattr(toolset, "set_dispatcher") and dispatcher is not None:
            toolset.set_dispatcher(dispatcher)

        # Wrap with capability filter
        wrapped = FilteredToolset(toolset, enabled_tools)

        # Only include if this toolset has at least one enabled tool
        if wrapped.get_tools():
            filtered_toolsets.append(wrapped)

    return filtered_toolsets
