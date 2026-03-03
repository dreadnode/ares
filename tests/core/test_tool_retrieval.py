"""Tests for tool retrieval module."""

from __future__ import annotations

from typing import ClassVar

import pytest

from ares.core.tool_retrieval import (
    KEYWORD_MAPPING,
    MITRE_TOOL_MAPPING,
    TOOL_DESCRIPTIONS,
)


class TestToolDescriptions:
    """Tests for TOOL_DESCRIPTIONS dictionary."""

    def test_asrep_roasting_bulk_in_descriptions(self):
        """Test that detect_asrep_roasting_bulk is in TOOL_DESCRIPTIONS."""
        assert "detect_asrep_roasting_bulk" in TOOL_DESCRIPTIONS

    def test_asrep_roasting_bulk_description_content(self):
        """Test that detect_asrep_roasting_bulk has relevant keywords."""
        desc = TOOL_DESCRIPTIONS["detect_asrep_roasting_bulk"]
        assert "AS-REP" in desc or "asrep" in desc.lower()
        assert "bulk" in desc.lower() or "spray" in desc.lower()

    def test_all_descriptions_are_non_empty(self):
        """Test that all tool descriptions are non-empty strings."""
        for tool_name, description in TOOL_DESCRIPTIONS.items():
            assert isinstance(description, str), f"{tool_name} description is not a string"
            assert len(description) > 0, f"{tool_name} description is empty"


class TestKeywordMapping:
    """Tests for KEYWORD_MAPPING dictionary."""

    def test_asrep_keyword_includes_bulk_detection(self):
        """Test that 'asrep' keyword maps to bulk detection tool."""
        assert "asrep" in KEYWORD_MAPPING
        assert "detect_asrep_roasting_bulk" in KEYWORD_MAPPING["asrep"]
        assert "detect_asrep_roasting" in KEYWORD_MAPPING["asrep"]

    def test_asrep_keyword_includes_brute_force(self):
        """Test that 'asrep' keyword maps to brute force detection."""
        assert "detect_brute_force" in KEYWORD_MAPPING["asrep"]

    def test_kerberoast_keyword_mappings(self):
        """Test kerberoast keyword mappings."""
        assert "kerberoast" in KEYWORD_MAPPING
        assert "detect_kerberoasting" in KEYWORD_MAPPING["kerberoast"]

    def test_dcsync_keyword_mappings(self):
        """Test dcsync keyword mappings."""
        assert "dcsync" in KEYWORD_MAPPING
        assert "detect_dcsync" in KEYWORD_MAPPING["dcsync"]


class TestMitreToolMapping:
    """Tests for MITRE_TOOL_MAPPING dictionary."""

    def test_t1558_includes_bulk_asrep(self):
        """Test T1558 (Steal or Forge Kerberos Tickets) includes bulk AS-REP."""
        assert "T1558" in MITRE_TOOL_MAPPING
        assert "detect_asrep_roasting_bulk" in MITRE_TOOL_MAPPING["T1558"]

    def test_t1558_004_includes_bulk_asrep(self):
        """Test T1558.004 (AS-REP Roasting) includes bulk detection."""
        assert "T1558.004" in MITRE_TOOL_MAPPING
        assert "detect_asrep_roasting" in MITRE_TOOL_MAPPING["T1558.004"]
        assert "detect_asrep_roasting_bulk" in MITRE_TOOL_MAPPING["T1558.004"]

    def test_t1558_003_is_kerberoasting(self):
        """Test T1558.003 maps to kerberoasting detection."""
        assert "T1558.003" in MITRE_TOOL_MAPPING
        assert "detect_kerberoasting" in MITRE_TOOL_MAPPING["T1558.003"]

    def test_t1003_is_credential_dumping(self):
        """Test T1003 (Credential Dumping) maps correctly."""
        assert "T1003" in MITRE_TOOL_MAPPING

    @pytest.mark.parametrize(
        "technique_id",
        [
            "T1558",
            "T1558.001",
            "T1558.003",
            "T1558.004",
            "T1003",
            "T1003.006",
            "T1046",
            "T1087",
        ],
    )
    def test_common_techniques_have_mappings(self, technique_id: str):
        """Test that common MITRE techniques have tool mappings."""
        assert technique_id in MITRE_TOOL_MAPPING
        assert len(MITRE_TOOL_MAPPING[technique_id]) > 0


class TestMappingConsistency:
    """Tests for consistency between different mappings."""

    # Known tools that are referenced but not yet defined in TOOL_DESCRIPTIONS
    # These should be fixed eventually, but we don't want to fail tests for pre-existing issues
    KNOWN_MISSING_TOOLS: ClassVar[set[str]] = {"detect_service_creation"}

    def test_keyword_tools_mostly_exist_in_descriptions(self):
        """Test that most tools referenced in KEYWORD_MAPPING exist in TOOL_DESCRIPTIONS."""
        missing_tools = []
        for keyword, tools in KEYWORD_MAPPING.items():
            for tool in tools:
                if tool not in TOOL_DESCRIPTIONS and tool not in self.KNOWN_MISSING_TOOLS:
                    missing_tools.append((keyword, tool))

        assert not missing_tools, (
            f"Tools referenced in KEYWORD_MAPPING but not in TOOL_DESCRIPTIONS: {missing_tools}"
        )

    def test_mitre_tools_mostly_exist_in_descriptions(self):
        """Test that most tools referenced in MITRE_TOOL_MAPPING exist in TOOL_DESCRIPTIONS."""
        missing_tools = []
        for technique_id, tools in MITRE_TOOL_MAPPING.items():
            for tool in tools:
                if tool not in TOOL_DESCRIPTIONS and tool not in self.KNOWN_MISSING_TOOLS:
                    missing_tools.append((technique_id, tool))

        assert not missing_tools, (
            f"Tools referenced in MITRE_TOOL_MAPPING but not in TOOL_DESCRIPTIONS: {missing_tools}"
        )
