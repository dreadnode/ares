"""MITRE ATT&CK STIX/TAXII client for live technique data."""

from dataclasses import dataclass

import httpx
from loguru import logger

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


@dataclass
class Technique:
    """A MITRE ATT&CK technique."""

    id: str  # e.g., T1059.001
    name: str
    description: str
    tactic: str
    tactic_id: str
    platforms: list[str]
    data_sources: list[str]
    detection: str
    is_subtechnique: bool
    parent_technique: str | None


@dataclass
class Tactic:
    """A MITRE ATT&CK tactic."""

    id: str  # e.g., TA0001
    name: str
    shortname: str
    description: str


class MITREAttackClient:
    """
    Client for MITRE ATT&CK data.

    Fetches live data from the MITRE STIX repository and provides
    lookups for techniques, tactics, and relationships.
    """

    def __init__(self):
        self._techniques: dict[str, Technique] = {}
        self._tactics: dict[str, Tactic] = {}
        self._tactic_to_techniques: dict[str, list[str]] = {}
        self._technique_to_tactics: dict[str, list[str]] = {}
        self._subtechniques: dict[str, list[str]] = {}
        self._loaded = False

    # Tactic shortname to ID mapping
    TACTIC_MAP = {
        "reconnaissance": "TA0043",
        "resource-development": "TA0042",
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "command-and-control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }

    async def load(self) -> None:
        """Load ATT&CK data from MITRE STIX repository."""
        if self._loaded:
            return

        logger.info("Fetching MITRE ATT&CK data from STIX repository...")

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(MITRE_STIX_URL)
            response.raise_for_status()
            bundle = response.json()

        # Parse STIX objects
        for obj in bundle.get("objects", []):
            obj_type = obj.get("type")

            if obj_type == "attack-pattern":
                self._parse_technique(obj)
            elif obj_type == "x-mitre-tactic":
                self._parse_tactic(obj)

        self._loaded = True
        logger.success(f"Loaded {len(self._techniques)} techniques, {len(self._tactics)} tactics")

    def _parse_technique(self, obj: dict) -> None:
        """Parse a STIX attack-pattern into a Technique."""
        # Skip revoked/deprecated
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            return

        external_refs = obj.get("external_references", [])
        technique_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            return

        # Get tactic from kill chain
        kill_chain = obj.get("kill_chain_phases", [])
        tactic_shortname = kill_chain[0]["phase_name"] if kill_chain else "unknown"
        tactic_id = self.TACTIC_MAP.get(tactic_shortname, "")

        # Check if subtechnique
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        parent = None
        if is_subtechnique and "." in technique_id:
            parent = technique_id.rsplit(".", 1)[0]

        technique = Technique(
            id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", "")[:1000],  # Truncate
            tactic=tactic_shortname,
            tactic_id=tactic_id,
            platforms=obj.get("x_mitre_platforms", []),
            data_sources=obj.get("x_mitre_data_sources", []),
            detection=obj.get("x_mitre_detection", "")[:500],
            is_subtechnique=is_subtechnique,
            parent_technique=parent,
        )

        self._techniques[technique_id] = technique

        # Index by tactic
        if tactic_id:
            self._tactic_to_techniques.setdefault(tactic_id, []).append(technique_id)
            self._technique_to_tactics.setdefault(technique_id, []).append(tactic_id)

        # Index subtechniques
        if parent:
            self._subtechniques.setdefault(parent, []).append(technique_id)

    def _parse_tactic(self, obj: dict) -> None:
        """Parse a STIX x-mitre-tactic into a Tactic."""
        external_refs = obj.get("external_references", [])
        tactic_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id")
                break

        if not tactic_id:
            return

        tactic = Tactic(
            id=tactic_id,
            name=obj.get("name", ""),
            shortname=obj.get("x_mitre_shortname", ""),
            description=obj.get("description", "")[:500],
        )

        self._tactics[tactic_id] = tactic

    def get_technique(self, technique_id: str) -> Technique | None:
        """Get a technique by ID."""
        return self._techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> Tactic | None:
        """Get a tactic by ID."""
        return self._tactics.get(tactic_id)

    def get_techniques_for_tactic(self, tactic_id: str) -> list[Technique]:
        """Get all techniques in a tactic."""
        tech_ids = self._tactic_to_techniques.get(tactic_id, [])
        return [self._techniques[tid] for tid in tech_ids if tid in self._techniques]

    def get_subtechniques(self, technique_id: str) -> list[Technique]:
        """Get subtechniques of a parent technique."""
        sub_ids = self._subtechniques.get(technique_id, [])
        return [self._techniques[sid] for sid in sub_ids if sid in self._techniques]

    def get_all_tactics(self) -> list[Tactic]:
        """Get all tactics in attack lifecycle order."""
        order = [
            "TA0043",
            "TA0042",
            "TA0001",
            "TA0002",
            "TA0003",
            "TA0004",
            "TA0005",
            "TA0006",
            "TA0007",
            "TA0008",
            "TA0009",
            "TA0011",
            "TA0010",
            "TA0040",
        ]
        return [self._tactics[tid] for tid in order if tid in self._tactics]

    def get_uncovered_tactics(self, identified_techniques: list[str]) -> list[Tactic]:
        """Get tactics not covered by identified techniques."""
        covered_tactics = set()
        for tech_id in identified_techniques:
            tactics = self._technique_to_tactics.get(tech_id, [])
            covered_tactics.update(tactics)

        all_tactics = set(self._tactics.keys())
        uncovered = all_tactics - covered_tactics

        return [self._tactics[tid] for tid in uncovered if tid in self._tactics]

    def get_related_techniques(self, technique_id: str) -> list[dict]:
        """
        Get techniques related to the given technique.

        Returns subtechniques, parent, and same-tactic techniques.
        """
        technique = self.get_technique(technique_id)
        if not technique:
            return []

        related = []

        # Subtechniques
        for sub in self.get_subtechniques(technique_id):
            related.append(
                {
                    "technique_id": sub.id,
                    "name": sub.name,
                    "relationship": "subtechnique",
                    "relevance": 0.9,
                }
            )

        # Parent technique
        if technique.parent_technique:
            parent = self.get_technique(technique.parent_technique)
            if parent:
                related.append(
                    {
                        "technique_id": parent.id,
                        "name": parent.name,
                        "relationship": "parent",
                        "relevance": 0.9,
                    }
                )

        # Same tactic (limit to prevent explosion)
        same_tactic = self.get_techniques_for_tactic(technique.tactic_id)
        for t in same_tactic[:10]:
            if t.id != technique_id and t.id not in [r["technique_id"] for r in related]:
                related.append(
                    {
                        "technique_id": t.id,
                        "name": t.name,
                        "relationship": "same_tactic",
                        "relevance": 0.5,
                    }
                )

        return related

    def search_by_keyword(self, keyword: str, limit: int = 10) -> list[Technique]:
        """Search techniques by keyword in name or description."""
        keyword_lower = keyword.lower()
        matches = []

        for technique in self._techniques.values():
            if keyword_lower in technique.name.lower():
                matches.append(technique)
            elif keyword_lower in technique.description.lower():
                matches.append(technique)

            if len(matches) >= limit:
                break

        return matches
