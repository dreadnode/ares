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
