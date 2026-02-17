"""Tests for the capability registry and FilteredToolset."""

from __future__ import annotations

from unittest.mock import MagicMock

from ares.core.capability_registry import (
    CAPABILITY_REGISTRY,
    FilteredToolset,
    create_filtered_toolsets,
    get_enabled_tools,
)


class TestCapabilityRegistry:
    """Tests for the CAPABILITY_REGISTRY constant."""

    def test_registry_has_expected_capabilities(self):
        """Test that registry contains key capabilities."""
        expected_capabilities = [
            "nmap",
            "netexec",
            "bloodhound-python",
            "impacket-secretsdump",
            "impacket-psexec",
            "certipy",
            "bloodyad",
            "hashcat",
            "john",
        ]
        for cap in expected_capabilities:
            assert cap in CAPABILITY_REGISTRY, f"Missing capability: {cap}"

    def test_registry_values_are_lists(self):
        """Test that all registry values are lists of strings."""
        for cap, tools in CAPABILITY_REGISTRY.items():
            assert isinstance(tools, list), f"{cap} value is not a list"
            for tool in tools:
                assert isinstance(tool, str), f"{cap} contains non-string: {tool}"

    def test_nmap_maps_to_nmap_scan(self):
        """Test that nmap capability maps to nmap_scan tool."""
        assert "nmap_scan" in CAPABILITY_REGISTRY["nmap"]

    def test_secretsdump_maps_correctly(self):
        """Test that impacket-secretsdump maps to expected tools."""
        tools = CAPABILITY_REGISTRY["impacket-secretsdump"]
        assert "secretsdump" in tools
        assert "secretsdump_kerberos" in tools


class TestGetEnabledTools:
    """Tests for the get_enabled_tools function."""

    def test_single_capability(self):
        """Test getting tools for a single capability."""
        enabled = get_enabled_tools({"nmap"})
        assert "nmap_scan" in enabled

    def test_multiple_capabilities(self):
        """Test getting tools for multiple capabilities."""
        enabled = get_enabled_tools({"nmap", "impacket-secretsdump"})
        assert "nmap_scan" in enabled
        assert "secretsdump" in enabled
        assert "secretsdump_kerberos" in enabled

    def test_unknown_capability(self):
        """Test that unknown capabilities return empty set."""
        enabled = get_enabled_tools({"unknown_capability_xyz"})
        assert len(enabled) == 0

    def test_case_insensitive_lookup(self):
        """Test that capability lookup is case-insensitive."""
        enabled_lower = get_enabled_tools({"nmap"})
        enabled_upper = get_enabled_tools({"NMAP"})
        assert enabled_lower == enabled_upper

    def test_empty_capabilities(self):
        """Test that empty capabilities returns empty set."""
        enabled = get_enabled_tools(set())
        assert len(enabled) == 0


class TestFilteredToolset:
    """Tests for the FilteredToolset class."""

    def test_filters_tools_correctly(self):
        """Test that FilteredToolset only returns enabled tools."""
        # Create a mock toolset
        mock_toolset = MagicMock()
        mock_tool1 = MagicMock()
        mock_tool1.name = "nmap_scan"
        mock_tool2 = MagicMock()
        mock_tool2.name = "smb_sweep"
        mock_tool3 = MagicMock()
        mock_tool3.name = "other_tool"

        mock_toolset.get_tools.return_value = [mock_tool1, mock_tool2, mock_tool3]

        # Filter to only nmap_scan
        filtered = FilteredToolset(mock_toolset, {"nmap_scan"})
        tools = filtered.get_tools()

        assert len(tools) == 1
        assert tools[0].name == "nmap_scan"

    def test_returns_empty_when_no_match(self):
        """Test that FilteredToolset returns empty list when no tools match."""
        mock_toolset = MagicMock()
        mock_tool = MagicMock()
        mock_tool.name = "some_tool"
        mock_toolset.get_tools.return_value = [mock_tool]

        filtered = FilteredToolset(mock_toolset, {"other_tool"})
        tools = filtered.get_tools()

        assert len(tools) == 0

    def test_delegates_attributes(self):
        """Test that FilteredToolset delegates attribute access to wrapped toolset."""
        mock_toolset = MagicMock()
        mock_toolset.some_attribute = "test_value"

        filtered = FilteredToolset(mock_toolset, set())
        assert filtered.some_attribute == "test_value"

    def test_repr(self):
        """Test FilteredToolset string representation."""
        mock_toolset = MagicMock()
        mock_toolset.__class__.__name__ = "TestToolset"

        filtered = FilteredToolset(mock_toolset, {"tool1", "tool2"})
        repr_str = repr(filtered)

        assert "FilteredToolset" in repr_str
        assert "TestToolset" in repr_str
        assert "2 tools" in repr_str


class TestCreateFilteredToolsets:
    """Tests for the create_filtered_toolsets function."""

    def test_creates_filtered_toolsets(self):
        """Test that create_filtered_toolsets instantiates and filters correctly."""

        class MockToolset:
            def __init__(self):
                self.state = None
                self.dispatcher = None

            def set_state(self, state):
                self.state = state

            def set_dispatcher(self, dispatcher):
                self.dispatcher = dispatcher

            def get_tools(self, *, variant=None):
                mock_tool = MagicMock()
                mock_tool.name = "test_tool"
                return [mock_tool]

        enabled = {"test_tool"}
        shared_state = MagicMock()
        dispatcher = MagicMock()

        toolsets = create_filtered_toolsets(
            [MockToolset], enabled, shared_state=shared_state, dispatcher=dispatcher
        )

        assert len(toolsets) == 1
        assert toolsets[0]._toolset.state == shared_state
        assert toolsets[0]._toolset.dispatcher == dispatcher

    def test_excludes_toolsets_with_no_enabled_tools(self):
        """Test that toolsets with no enabled tools are excluded."""

        class MockToolset:
            def get_tools(self, *, variant=None):
                mock_tool = MagicMock()
                mock_tool.name = "excluded_tool"
                return [mock_tool]

        enabled = {"other_tool"}  # Doesn't match the mock toolset's tool

        toolsets = create_filtered_toolsets([MockToolset], enabled)

        assert len(toolsets) == 0


class TestCapabilityIntegration:
    """Integration tests for capability-driven tool access."""

    def test_recon_capabilities_map_to_tools(self):
        """Test that typical recon capabilities map to expected tools."""
        recon_caps = {"nmap", "ldapsearch", "bloodhound-python", "netexec"}
        enabled = get_enabled_tools(recon_caps)

        assert "nmap_scan" in enabled
        assert "ldap_search_descriptions" in enabled
        assert "run_bloodhound" in enabled
        assert "smb_sweep" in enabled
        assert "enumerate_users" in enabled

    def test_credential_access_capabilities(self):
        """Test that credential access capabilities map correctly."""
        cred_caps = {"impacket-getnpusers", "impacket-getuserspns", "impacket-secretsdump"}
        enabled = get_enabled_tools(cred_caps)

        assert "asrep_roast" in enabled
        assert "kerberoast" in enabled
        assert "secretsdump" in enabled

    def test_lateral_capabilities(self):
        """Test that lateral movement capabilities map correctly."""
        lateral_caps = {"evil-winrm", "impacket-psexec", "impacket-wmiexec"}
        enabled = get_enabled_tools(lateral_caps)

        assert "evil_winrm" in enabled
        assert "psexec" in enabled
        assert "psexec_kerberos" in enabled
        assert "wmiexec" in enabled
        assert "wmiexec_kerberos" in enabled

    def test_privesc_capabilities(self):
        """Test that privilege escalation capabilities map correctly."""
        privesc_caps = {"certipy", "impacket-getst", "nopac"}
        enabled = get_enabled_tools(privesc_caps)

        assert "certipy_find" in enabled
        assert "certipy_request" in enabled
        assert "s4u_attack" in enabled
        assert "nopac" in enabled


class TestAgentToolRequirements:
    """Tests that verify agents have access to their required tools.

    These tests use the actual config to catch capability regressions.
    If a required tool is removed from an agent's capabilities, CI will fail.
    """

    @staticmethod
    def _get_agent_tools(agent_name: str) -> set[str]:
        """Get tools available to an agent from actual config."""
        from ares.core.config import get_agent_config

        config = get_agent_config(agent_name)
        capabilities = getattr(config, "capabilities", []) or []
        return get_enabled_tools(set(capabilities))

    def test_credential_access_has_required_tools(self):
        """credential_access must have credential harvesting tools."""
        tools = self._get_agent_tools("credential_access")

        # Core credential harvesting
        assert "secretsdump" in tools, "credential_access needs secretsdump"
        assert "asrep_roast" in tools, "credential_access needs asrep_roast"
        assert "gmsa_dump_passwords" in tools, "credential_access needs gmsa_dump_passwords"
        assert "targeted_kerberoast" in tools, "credential_access needs targeted_kerberoast"

    def test_lateral_has_required_tools(self):
        """lateral must have movement and validation tools."""
        tools = self._get_agent_tools("lateral")

        # Movement tools
        assert "psexec" in tools, "lateral needs psexec"
        assert "wmiexec" in tools, "lateral needs wmiexec"
        assert "evil_winrm" in tools, "lateral needs evil_winrm"

        # Kerberos variants
        assert "psexec_kerberos" in tools, "lateral needs psexec_kerberos"
        assert "wmiexec_kerberos" in tools, "lateral needs wmiexec_kerberos"

        # Pre-connection validation (requires posture_validation)
        assert "check_rdp_reachability" in tools, (
            "lateral needs check_rdp_reachability (add posture_validation)"
        )
        assert "check_winrm_reachability" in tools, (
            "lateral needs check_winrm_reachability (add posture_validation)"
        )

    def test_recon_has_required_tools(self):
        """recon must have discovery and enumeration tools."""
        tools = self._get_agent_tools("recon")

        assert "nmap_scan" in tools, "recon needs nmap_scan"
        assert "run_bloodhound" in tools, "recon needs run_bloodhound"
        assert "smb_sweep" in tools, "recon needs smb_sweep"
        assert "enumerate_domain_netbios_mappings" in tools, (
            "recon needs enumerate_domain_netbios_mappings"
        )

    def test_privesc_has_required_tools(self):
        """privesc must have escalation and exploitation tools."""
        tools = self._get_agent_tools("privesc")

        # Delegation attacks
        assert "find_delegation" in tools, "privesc needs find_delegation"
        assert "s4u_attack" in tools, "privesc needs s4u_attack"

        # ADCS
        assert "certipy_find" in tools, "privesc needs certipy_find"
        assert "certipy_request" in tools, "privesc needs certipy_request"

        # Post-exploitation
        assert "secretsdump" in tools, "privesc needs secretsdump"
        assert "psexec" in tools, "privesc needs psexec"

    def test_coercion_has_required_tools(self):
        """coercion must have relay and coercion tools."""
        tools = self._get_agent_tools("coercion")

        assert "start_responder" in tools, "coercion needs start_responder"
        assert "petitpotam" in tools, "coercion needs petitpotam"
        assert "coercer" in tools, "coercion needs coercer"
        assert "unconstrained_coerce_and_capture" in tools, (
            "coercion needs unconstrained_coerce_and_capture"
        )

    def test_acl_has_required_tools(self):
        """acl must have ACL exploitation tools."""
        tools = self._get_agent_tools("acl")

        assert "bloodyad_add_group_member" in tools, "acl needs bloodyad_add_group_member"
        assert "pywhisker" in tools, "acl needs pywhisker"
        assert "targeted_kerberoast" in tools, "acl needs targeted_kerberoast"
        assert "dacl_edit" in tools, "acl needs dacl_edit"

    def test_all_registry_tools_are_accessible(self):
        """Verify all tools in registry are accessible to at least one agent."""
        all_registry_tools: set[str] = set()
        for tools in CAPABILITY_REGISTRY.values():
            all_registry_tools.update(tools)

        all_agent_tools: set[str] = set()
        for agent in [
            "recon",
            "credential_access",
            "lateral",
            "privesc",
            "acl",
            "coercion",
            "cracker",
        ]:
            all_agent_tools.update(self._get_agent_tools(agent))

        unmapped = all_registry_tools - all_agent_tools
        assert not unmapped, f"Tools in registry but not accessible to any agent: {unmapped}"
