"""Tests for RECON agent toolset configuration."""

from __future__ import annotations

from ares.core.factories.red_agents import ROLE_TOOLSETS
from ares.core.models import AgentRole
from ares.tools.red import (
    BloodHoundTools,
    CredentialDiscoveryTools,
    NetworkEnumerationTools,
    RedTeamReportingTools,
)


class TestReconRoleToolset:
    """Tests for RECON role toolset configuration."""

    def test_recon_role_has_network_enumeration(self):
        """RECON role should have NetworkEnumerationTools."""
        toolset = ROLE_TOOLSETS.get(AgentRole.RECON, [])
        assert NetworkEnumerationTools in toolset

    def test_recon_role_has_bloodhound(self):
        """RECON role should have BloodHoundTools."""
        toolset = ROLE_TOOLSETS.get(AgentRole.RECON, [])
        assert BloodHoundTools in toolset

    def test_recon_role_has_credential_discovery(self):
        """RECON role should have CredentialDiscoveryTools."""
        toolset = ROLE_TOOLSETS.get(AgentRole.RECON, [])
        assert CredentialDiscoveryTools in toolset

    def test_recon_role_has_reporting(self):
        """RECON role should have RedTeamReportingTools."""
        toolset = ROLE_TOOLSETS.get(AgentRole.RECON, [])
        assert RedTeamReportingTools in toolset

    def test_recon_toolset_order(self):
        """RECON toolset should have tools in expected order."""
        toolset = ROLE_TOOLSETS.get(AgentRole.RECON, [])

        # NetworkEnumerationTools should come first (basic recon)
        assert toolset[0] == NetworkEnumerationTools

        # BloodHoundTools second (AD mapping)
        assert toolset[1] == BloodHoundTools

        # CredentialDiscoveryTools third (credential hunting)
        assert toolset[2] == CredentialDiscoveryTools

        # ReportingTools last
        assert toolset[-1] == RedTeamReportingTools

    def test_recon_has_at_least_four_toolsets(self):
        """RECON role should have at least 4 toolsets."""
        toolset = ROLE_TOOLSETS.get(AgentRole.RECON, [])
        assert len(toolset) >= 4


class TestCredentialDiscoveryInRecon:
    """Tests for CredentialDiscoveryTools functionality within RECON context."""

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
