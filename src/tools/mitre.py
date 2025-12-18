"""MITRE ATT&CK lookup tools."""

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset

from src.mitre import MITREAttackClient


class MITRELookupTools(Toolset):  # type: ignore[misc]
    """Tools for looking up MITRE ATT&CK data."""

    mitre_client: MITREAttackClient | None = None

    def set_client(self, client: MITREAttackClient):
        self.mitre_client = client

    @dn.tool_method  # type: ignore[untyped-decorator]
    def lookup_technique(self, technique_id: str) -> dict | None:
        """
        Look up a MITRE ATT&CK technique by ID.

        Args:
            technique_id: The technique ID (e.g., "T1059.001", "T1105")

        Returns:
            Technique details including name, description, tactic, and data sources
        """
        if not self.mitre_client:
            return {"error": "MITRE client not initialized"}

        technique = self.mitre_client.get_technique(technique_id)
        if not technique:
            return None

        return {
            "id": technique.id,
            "name": technique.name,
            "description": technique.description,
            "tactic": technique.tactic,
            "tactic_id": technique.tactic_id,
            "platforms": technique.platforms,
            "data_sources": technique.data_sources,
            "detection": technique.detection,
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    def get_related_techniques(self, technique_id: str) -> list[dict]:
        """
        Get techniques related to the given technique.

        Useful for understanding what other techniques might appear
        alongside the one you've identified.

        Args:
            technique_id: The technique ID to find relations for

        Returns:
            List of related techniques with relationship type
        """
        if not self.mitre_client:
            return [{"error": "MITRE client not initialized"}]

        return self.mitre_client.get_related_techniques(technique_id)

    @dn.tool_method  # type: ignore[untyped-decorator]
    def identify_tactical_gaps(self) -> list[dict]:
        """
        Identify which attack tactics haven't been investigated yet.

        Use this to ensure complete attack lifecycle coverage.

        Returns:
            List of uncovered tactics with example techniques
        """
        if not self.mitre_client:
            return [{"error": "MITRE client not initialized"}]

        uncovered = self.mitre_client.get_all_tactics()

        return [
            {
                "tactic_id": t.id,
                "tactic_name": t.name,
                "description": t.description,
            }
            for t in uncovered[:10]
        ]

    @dn.tool_method  # type: ignore[untyped-decorator]
    def search_techniques(self, keyword: str) -> list[dict]:
        """
        Search for techniques by keyword.

        Args:
            keyword: Search term to find in technique names/descriptions

        Returns:
            Matching techniques
        """
        if not self.mitre_client:
            return [{"error": "MITRE client not initialized"}]

        matches = self.mitre_client.search_by_keyword(keyword)

        return [
            {
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
            }
            for t in matches
        ]
