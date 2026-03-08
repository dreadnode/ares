"""Tests for RECON agent toolset configuration.

This test module verifies that the capability-based tool configuration
works correctly for the RECON role.
"""

from __future__ import annotations

from ares.core.capability_registry import get_enabled_tools
from ares.core.config import get_agent_config
from ares.core.factories.red_agents import ALL_TOOLSETS
from ares.tools.red import (
    BloodHoundTools,
    CredentialDiscoveryTools,
    NetworkEnumerationTools,
)


class TestReconRoleCapabilities:
    """Tests for RECON role capability configuration."""

    def test_recon_config_has_capabilities(self):
        """RECON config should have capabilities defined."""
        config = get_agent_config("recon")
        assert len(config.capabilities) > 0

    def test_recon_capabilities_include_nmap(self):
        """RECON capabilities should include nmap."""
        config = get_agent_config("recon")
        # Check if nmap or network scanning capability is present
        assert "nmap" in config.capabilities

    def test_recon_capabilities_include_bloodhound(self):
        """RECON capabilities should include bloodhound-python."""
        config = get_agent_config("recon")
        assert "bloodhound-python" in config.capabilities

    def test_recon_capabilities_map_to_tools(self):
        """RECON capabilities should map to expected tool methods."""
        config = get_agent_config("recon")
        enabled = get_enabled_tools(set(config.capabilities))

        # Should have network scanning tools
        assert "nmap_scan" in enabled
        assert "run_bloodhound" in enabled


class TestToolsetClassesAvailable:
    """Tests that required toolset classes are in ALL_TOOLSETS."""

    def test_network_enumeration_in_all_toolsets(self):
        """NetworkEnumerationTools should be in ALL_TOOLSETS."""
        assert NetworkEnumerationTools in ALL_TOOLSETS

    def test_bloodhound_in_all_toolsets(self):
        """BloodHoundTools should be in ALL_TOOLSETS."""
        assert BloodHoundTools in ALL_TOOLSETS

    def test_credential_discovery_in_all_toolsets(self):
        """CredentialDiscoveryTools should be in ALL_TOOLSETS."""
        assert CredentialDiscoveryTools in ALL_TOOLSETS


class TestCredentialDiscoveryTools:
    """Tests for CredentialDiscoveryTools functionality."""

    def test_credential_discovery_has_password_spray(self):
        """CredentialDiscoveryTools should have password_spray method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "password_spray")
        assert callable(tools.password_spray)

    def test_credential_discovery_has_username_as_password(self):
        """CredentialDiscoveryTools should have username_as_password method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "username_as_password")
        assert callable(tools.username_as_password)

    def test_credential_discovery_has_ldap_search_descriptions(self):
        """CredentialDiscoveryTools should have ldap_search_descriptions method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "ldap_search_descriptions")
        assert callable(tools.ldap_search_descriptions)

    def test_credential_discovery_has_password_policy(self):
        """CredentialDiscoveryTools should have password_policy method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "password_policy")
        assert callable(tools.password_policy)

    def test_credential_discovery_has_add_credential(self):
        """CredentialDiscoveryTools should have _add_credential method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "_add_credential")
        assert callable(tools._add_credential)

    def test_credential_discovery_has_laps_dump(self):
        """CredentialDiscoveryTools should have laps_dump method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "laps_dump")
        assert callable(tools.laps_dump)


class TestCapabilityToToolMapping:
    """Tests for capability to tool method mapping."""

    def test_nmap_capability_maps_to_nmap_scan(self):
        """nmap capability should map to nmap_scan tool method."""
        enabled = get_enabled_tools({"nmap"})
        assert "nmap_scan" in enabled

    def test_bloodhound_capability_maps_to_run_bloodhound(self):
        """bloodhound-python capability should map to run_bloodhound tool method."""
        enabled = get_enabled_tools({"bloodhound-python"})
        assert "run_bloodhound" in enabled

    def test_netexec_capability_maps_to_smb_tools(self):
        """netexec capability should map to SMB tool methods."""
        enabled = get_enabled_tools({"netexec"})
        assert "smb_sweep" in enabled
        assert "enumerate_users" in enabled
        assert "enumerate_shares" in enabled

    def test_ldapsearch_capability_maps_to_ldap_tools(self):
        """ldapsearch capability should map to LDAP tool methods."""
        enabled = get_enabled_tools({"ldapsearch"})
        assert "ldap_search_descriptions" in enabled
        assert "check_sidhistory" in enabled


class TestNetBIOSHostnameEnrichment:
    """Tests for NetBIOS hostname enrichment in nmap_scan.

    The nmap_scan tool has a Phase 3 that attempts to resolve hostnames
    for hosts that don't have them, using NetBIOS name resolution.
    """

    def test_fqdn_regex_extracts_hostname_from_nmap_report(self):
        """Test that FQDN can be extracted from nmap scan report output."""
        import re

        ip = "192.168.58.10"
        nmap_output = f"Nmap scan report for dc01.contoso.local ({ip})\n"

        fqdn_match = re.search(
            r"Nmap scan report for ([^\s]+)\s+\(" + re.escape(ip) + r"\)",
            nmap_output,
        )

        assert fqdn_match is not None
        assert fqdn_match.group(1) == "dc01.contoso.local"

    def test_fqdn_regex_handles_short_hostname(self):
        """Test FQDN extraction handles short hostnames without domain."""
        import re

        ip = "192.168.58.20"
        nmap_output = f"Nmap scan report for sql01 ({ip})\n"

        fqdn_match = re.search(
            r"Nmap scan report for ([^\s]+)\s+\(" + re.escape(ip) + r"\)",
            nmap_output,
        )

        assert fqdn_match is not None
        assert fqdn_match.group(1) == "sql01"

    def test_netbios_name_regex_extracts_name(self):
        """Test NetBIOS name extraction from nbstat output."""
        import re

        nbstat_output = """
Starting Nmap 7.93 ( https://nmap.org )
Host script results:
| nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:xx:xx:xx
|_  Names:
|   DC01<00>            Flags: <unique><active>
|   CONTOSO<00>         Flags: <group><active>
"""

        nb_match = re.search(r"nbstat:\s*NetBIOS name:\s*([^,]+)", nbstat_output)

        assert nb_match is not None
        assert nb_match.group(1).strip() == "DC01"

    def test_domain_group_regex_extracts_domain(self):
        """Test domain extraction from NetBIOS Names section.

        The regex from reconnaissance.py matches entries with <00> suffix
        and <group> flag to identify the domain/workgroup name.
        """
        import re

        # Nmap nbstat output format (indented entries under Names section)
        nbstat_output = """
Names:
  DC01<00>              Flags: <unique><active>
  CONTOSO<00>           Flags: <group><active>
  CONTOSO<1c>           Flags: <group><active>
"""

        # The regex from reconnaissance.py expects whitespace-prefixed lines
        domain_match = re.search(
            r"^\s+([A-Z0-9_-]+)<00>\s+Flags:.*<group>",
            nbstat_output,
            re.MULTILINE,
        )

        assert domain_match is not None
        assert domain_match.group(1).strip() == "CONTOSO"

    def test_aws_internal_hostname_detection(self):
        """Test detection of AWS internal hostnames that need enrichment."""
        # AWS EC2 internal hostnames follow pattern: ip-XXX-XXX-XXX-XXX.region.compute.internal
        aws_hostname = "ip-10-0-1-50.us-east-1.compute.internal"

        needs_enrichment = (
            aws_hostname.lower().startswith("ip-") and "compute.internal" in aws_hostname.lower()
        )

        assert needs_enrichment is True

    def test_normal_hostname_does_not_need_enrichment(self):
        """Test that normal hostnames don't trigger enrichment."""
        normal_hostname = "dc01.contoso.local"

        needs_enrichment = (
            normal_hostname.lower().startswith("ip-")
            and "compute.internal" in normal_hostname.lower()
        )

        assert needs_enrichment is False

    def test_empty_hostname_needs_enrichment(self):
        """Test that empty/None hostnames need enrichment."""
        hostname = None

        # Logic from reconnaissance.py
        needs_enrichment = not hostname or (
            hostname.lower().startswith("ip-") and "compute.internal" in hostname.lower()
        )

        assert needs_enrichment is True

    def test_fqdn_construction_from_netbios(self):
        """Test FQDN construction from NetBIOS name and domain."""
        netbios_name = "DC01"
        domain = "CONTOSO"

        # Logic from reconnaissance.py - assumes .local TLD
        fqdn = f"{netbios_name.lower()}.{domain.lower()}.local"

        assert fqdn == "dc01.contoso.local"
