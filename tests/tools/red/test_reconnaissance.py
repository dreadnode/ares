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
