"""Tests for MITRE ATT&CK STIX/TAXII client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.integrations.mitre import (
    MITREAttackClient,
    Tactic,
    Technique,
)
from ares.tools.shared.mitre import MITRELookupTools


class TestTechniqueDataclass:
    """Tests for Technique dataclass."""

    def test_technique_creation(self):
        """Test creating a technique."""
        technique = Technique(
            id="T1003.006",
            name="DCSync",
            description="Adversaries may attempt to access credentials",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=["Windows"],
            data_sources=["Active Directory"],
            detection="Monitor for Event ID 4662",
            is_subtechnique=True,
            parent_technique="T1003",
        )
        assert technique.id == "T1003.006"
        assert technique.name == "DCSync"
        assert technique.is_subtechnique is True
        assert technique.parent_technique == "T1003"

    def test_technique_without_parent(self):
        """Test technique without parent."""
        technique = Technique(
            id="T1059",
            name="Command and Scripting Interpreter",
            description="Adversaries may abuse command interpreters",
            tactic="execution",
            tactic_id="TA0002",
            platforms=["Windows", "Linux", "macOS"],
            data_sources=["Process", "Command"],
            detection="Monitor process execution",
            is_subtechnique=False,
            parent_technique=None,
        )
        assert technique.is_subtechnique is False
        assert technique.parent_technique is None


class TestTacticDataclass:
    """Tests for Tactic dataclass."""

    def test_tactic_creation(self):
        """Test creating a tactic."""
        tactic = Tactic(
            id="TA0006",
            name="Credential Access",
            shortname="credential-access",
            description="The adversary is trying to steal credentials",
        )
        assert tactic.id == "TA0006"
        assert tactic.name == "Credential Access"
        assert tactic.shortname == "credential-access"


class TestMITREAttackClientInit:
    """Tests for MITREAttackClient initialization."""

    def test_init_creates_empty_dicts(self):
        """Test initialization creates empty dictionaries."""
        client = MITREAttackClient()
        assert client._techniques == {}
        assert client._tactics == {}
        assert client._tactic_to_techniques == {}
        assert client._technique_to_tactics == {}
        assert client._subtechniques == {}
        assert client._loaded is False

    def test_tactic_map_constant(self):
        """Test TACTIC_MAP has expected entries."""
        assert "credential-access" in MITREAttackClient.TACTIC_MAP
        assert MITREAttackClient.TACTIC_MAP["credential-access"] == "TA0006"
        assert "execution" in MITREAttackClient.TACTIC_MAP
        assert MITREAttackClient.TACTIC_MAP["execution"] == "TA0002"


class TestMITREAttackClientLoad:
    """Tests for load method."""

    @pytest.fixture
    def mock_stix_bundle(self) -> dict:
        """Create a mock STIX bundle."""
        return {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "DCSync",
                    "description": "Adversaries may attempt to access credentials",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1003.006"}
                    ],
                    "kill_chain_phases": [{"phase_name": "credential-access"}],
                    "x_mitre_is_subtechnique": True,
                    "x_mitre_platforms": ["Windows"],
                    "x_mitre_data_sources": ["Active Directory"],
                    "x_mitre_detection": "Monitor for replication",
                },
                {
                    "type": "attack-pattern",
                    "name": "OS Credential Dumping",
                    "description": "Dump credentials from OS",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1003"}
                    ],
                    "kill_chain_phases": [{"phase_name": "credential-access"}],
                    "x_mitre_is_subtechnique": False,
                    "x_mitre_platforms": ["Windows", "Linux"],
                    "x_mitre_data_sources": ["Process"],
                },
                {
                    "type": "x-mitre-tactic",
                    "name": "Credential Access",
                    "description": "Steal credentials",
                    "x_mitre_shortname": "credential-access",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "TA0006"}
                    ],
                },
            ]
        }

    @pytest.mark.asyncio
    async def test_load_fetches_data(self, mock_stix_bundle: dict):
        """Test load fetches and parses data."""
        client = MITREAttackClient()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_stix_bundle
            mock_response.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            await client.load()

            assert client._loaded is True
            assert len(client._techniques) == 2
            assert len(client._tactics) == 1
            assert "T1003.006" in client._techniques
            assert "T1003" in client._techniques
            assert "TA0006" in client._tactics

    @pytest.mark.asyncio
    async def test_load_skips_if_already_loaded(self, mock_stix_bundle: dict):
        """Test load is idempotent."""
        client = MITREAttackClient()
        client._loaded = True

        with patch("httpx.AsyncClient") as mock_client_class:
            await client.load()
            mock_client_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_load_skips_revoked_techniques(self):
        """Test revoked techniques are skipped."""
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Revoked Technique",
                    "revoked": True,
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T9999"}
                    ],
                }
            ]
        }

        client = MITREAttackClient()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.json.return_value = bundle
            mock_response.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            await client.load()

            assert "T9999" not in client._techniques

    @pytest.mark.asyncio
    async def test_load_skips_deprecated_techniques(self):
        """Test deprecated techniques are skipped."""
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Deprecated Technique",
                    "x_mitre_deprecated": True,
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T9998"}
                    ],
                }
            ]
        }

        client = MITREAttackClient()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.json.return_value = bundle
            mock_response.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            await client.load()

            assert "T9998" not in client._techniques


class TestMITREAttackClientParsing:
    """Tests for parsing methods."""

    def test_parse_technique_basic(self):
        """Test parsing a basic technique."""
        client = MITREAttackClient()
        obj = {
            "type": "attack-pattern",
            "name": "PowerShell",
            "description": "Adversaries may use PowerShell",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
            "kill_chain_phases": [{"phase_name": "execution"}],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_data_sources": ["Process"],
            "x_mitre_detection": "Monitor PowerShell",
            "x_mitre_is_subtechnique": True,
        }

        client._parse_technique(obj)

        assert "T1059.001" in client._techniques
        technique = client._techniques["T1059.001"]
        assert technique.name == "PowerShell"
        assert technique.is_subtechnique is True
        assert technique.parent_technique == "T1059"

    def test_parse_technique_truncates_long_description(self):
        """Test description truncation."""
        client = MITREAttackClient()
        obj = {
            "type": "attack-pattern",
            "name": "Test",
            "description": "A" * 2000,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            "kill_chain_phases": [{"phase_name": "execution"}],
        }

        client._parse_technique(obj)

        assert len(client._techniques["T0001"].description) <= 1000

    def test_parse_technique_without_id_skipped(self):
        """Test technique without ID is skipped."""
        client = MITREAttackClient()
        obj = {
            "type": "attack-pattern",
            "name": "No ID Technique",
            "external_references": [],
        }

        client._parse_technique(obj)

        assert len(client._techniques) == 0

    def test_parse_tactic_basic(self):
        """Test parsing a basic tactic."""
        client = MITREAttackClient()
        obj = {
            "type": "x-mitre-tactic",
            "name": "Execution",
            "description": "Execution description",
            "x_mitre_shortname": "execution",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
        }

        client._parse_tactic(obj)

        assert "TA0002" in client._tactics
        tactic = client._tactics["TA0002"]
        assert tactic.name == "Execution"
        assert tactic.shortname == "execution"


class TestMITREAttackClientLookups:
    """Tests for lookup methods."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create a client with test data."""
        client = MITREAttackClient()

        # Add techniques
        client._techniques["T1003"] = Technique(
            id="T1003",
            name="OS Credential Dumping",
            description="Dump credentials",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=["Windows"],
            data_sources=["Process"],
            detection="Monitor",
            is_subtechnique=False,
            parent_technique=None,
        )
        client._techniques["T1003.006"] = Technique(
            id="T1003.006",
            name="DCSync",
            description="DCSync attack",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=["Windows"],
            data_sources=["AD"],
            detection="Monitor 4662",
            is_subtechnique=True,
            parent_technique="T1003",
        )

        # Add tactics
        client._tactics["TA0006"] = Tactic(
            id="TA0006",
            name="Credential Access",
            shortname="credential-access",
            description="Steal credentials",
        )

        # Add indices
        client._tactic_to_techniques["TA0006"] = ["T1003", "T1003.006"]
        client._technique_to_tactics["T1003"] = ["TA0006"]
        client._technique_to_tactics["T1003.006"] = ["TA0006"]
        client._subtechniques["T1003"] = ["T1003.006"]

        client._loaded = True
        return client

    def test_get_technique_found(self, populated_client: MITREAttackClient):
        """Test getting an existing technique."""
        technique = populated_client.get_technique("T1003.006")
        assert technique is not None
        assert technique.name == "DCSync"

    def test_get_technique_not_found(self, populated_client: MITREAttackClient):
        """Test getting a non-existent technique."""
        technique = populated_client.get_technique("T9999")
        assert technique is None

    def test_get_tactic_found(self, populated_client: MITREAttackClient):
        """Test getting an existing tactic."""
        tactic = populated_client.get_tactic("TA0006")
        assert tactic is not None
        assert tactic.name == "Credential Access"

    def test_get_tactic_not_found(self, populated_client: MITREAttackClient):
        """Test getting a non-existent tactic."""
        tactic = populated_client.get_tactic("TA9999")
        assert tactic is None

    def test_get_techniques_for_tactic(self, populated_client: MITREAttackClient):
        """Test getting techniques for a tactic."""
        techniques = populated_client.get_techniques_for_tactic("TA0006")
        assert len(techniques) == 2
        ids = [t.id for t in techniques]
        assert "T1003" in ids
        assert "T1003.006" in ids

    def test_get_techniques_for_tactic_empty(self, populated_client: MITREAttackClient):
        """Test getting techniques for non-existent tactic."""
        techniques = populated_client.get_techniques_for_tactic("TA9999")
        assert techniques == []

    def test_get_subtechniques(self, populated_client: MITREAttackClient):
        """Test getting subtechniques."""
        subs = populated_client.get_subtechniques("T1003")
        assert len(subs) == 1
        assert subs[0].id == "T1003.006"

    def test_get_subtechniques_none(self, populated_client: MITREAttackClient):
        """Test getting subtechniques for technique with none."""
        subs = populated_client.get_subtechniques("T1003.006")
        assert subs == []


class TestMITREAttackClientAllTactics:
    """Tests for get_all_tactics method."""

    @pytest.fixture
    def client_with_tactics(self) -> MITREAttackClient:
        """Create client with multiple tactics."""
        client = MITREAttackClient()
        tactics = [
            ("TA0001", "Initial Access", "initial-access"),
            ("TA0002", "Execution", "execution"),
            ("TA0006", "Credential Access", "credential-access"),
        ]
        for tid, name, shortname in tactics:
            client._tactics[tid] = Tactic(
                id=tid, name=name, shortname=shortname, description=f"{name} description"
            )
        return client

    def test_get_all_tactics_order(self, client_with_tactics: MITREAttackClient):
        """Test tactics are returned in attack lifecycle order."""
        tactics = client_with_tactics.get_all_tactics()
        # Should be ordered by the predefined order in the method
        ids = [t.id for t in tactics]
        # TA0001 should come before TA0002 which should come before TA0006
        if "TA0001" in ids and "TA0002" in ids:
            assert ids.index("TA0001") < ids.index("TA0002")


class TestMITREAttackClientUncoveredTactics:
    """Tests for get_uncovered_tactics method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create client with test data."""
        client = MITREAttackClient()

        client._tactics["TA0001"] = Tactic("TA0001", "Initial Access", "initial-access", "")
        client._tactics["TA0002"] = Tactic("TA0002", "Execution", "execution", "")
        client._tactics["TA0006"] = Tactic("TA0006", "Credential Access", "credential-access", "")

        client._technique_to_tactics["T1059"] = ["TA0002"]
        client._technique_to_tactics["T1003"] = ["TA0006"]

        return client

    def test_uncovered_tactics_all_covered(self, populated_client: MITREAttackClient):
        """Test when all tactics are covered."""
        identified = ["T1059", "T1003"]  # Covers TA0002 and TA0006
        # But not TA0001
        uncovered = populated_client.get_uncovered_tactics(identified)
        ids = [t.id for t in uncovered]
        assert "TA0001" in ids
        assert "TA0002" not in ids
        assert "TA0006" not in ids

    def test_uncovered_tactics_none_covered(self, populated_client: MITREAttackClient):
        """Test when no tactics are covered."""
        uncovered = populated_client.get_uncovered_tactics([])
        assert len(uncovered) == 3


class TestMITREAttackClientRelatedTechniques:
    """Tests for get_related_techniques method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create client with test data."""
        client = MITREAttackClient()

        # Parent technique
        client._techniques["T1003"] = Technique(
            id="T1003",
            name="OS Credential Dumping",
            description="",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=False,
            parent_technique=None,
        )

        # Subtechnique
        client._techniques["T1003.006"] = Technique(
            id="T1003.006",
            name="DCSync",
            description="",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=True,
            parent_technique="T1003",
        )

        # Another technique in same tactic
        client._techniques["T1003.001"] = Technique(
            id="T1003.001",
            name="LSASS Memory",
            description="",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=True,
            parent_technique="T1003",
        )

        client._subtechniques["T1003"] = ["T1003.006", "T1003.001"]
        client._tactic_to_techniques["TA0006"] = ["T1003", "T1003.006", "T1003.001"]

        return client

    def test_related_techniques_subtechniques(self, populated_client: MITREAttackClient):
        """Test related techniques includes subtechniques."""
        related = populated_client.get_related_techniques("T1003")
        technique_ids = [r["technique_id"] for r in related]
        assert "T1003.006" in technique_ids
        assert "T1003.001" in technique_ids

    def test_related_techniques_parent(self, populated_client: MITREAttackClient):
        """Test related techniques includes parent."""
        related = populated_client.get_related_techniques("T1003.006")
        technique_ids = [r["technique_id"] for r in related]
        assert "T1003" in technique_ids

    def test_related_techniques_not_found(self, populated_client: MITREAttackClient):
        """Test related techniques for non-existent technique."""
        related = populated_client.get_related_techniques("T9999")
        assert related == []


class TestMITREAttackClientSearchByKeyword:
    """Tests for search_by_keyword method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create client with test data."""
        client = MITREAttackClient()

        client._techniques["T1003"] = Technique(
            id="T1003",
            name="OS Credential Dumping",
            description="Dump credentials from OS",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=False,
            parent_technique=None,
        )

        client._techniques["T1059"] = Technique(
            id="T1059",
            name="Command and Scripting Interpreter",
            description="Use scripts and commands",
            tactic="execution",
            tactic_id="TA0002",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=False,
            parent_technique=None,
        )

        return client

    def test_search_by_name(self, populated_client: MITREAttackClient):
        """Test search by keyword in name."""
        results = populated_client.search_by_keyword("credential")
        assert len(results) == 1
        assert results[0].id == "T1003"

    def test_search_by_description(self, populated_client: MITREAttackClient):
        """Test search by keyword in description."""
        results = populated_client.search_by_keyword("dump")
        assert len(results) == 1
        assert results[0].id == "T1003"

    def test_search_case_insensitive(self, populated_client: MITREAttackClient):
        """Test search is case insensitive."""
        results = populated_client.search_by_keyword("CREDENTIAL")
        assert len(results) == 1

    def test_search_with_limit(self, populated_client: MITREAttackClient):
        """Test search respects limit."""
        # Add more matching techniques
        for i in range(20):
            populated_client._techniques[f"T{i}"] = Technique(
                id=f"T{i}",
                name=f"Test Technique {i}",
                description="Test description",
                tactic="",
                tactic_id="",
                platforms=[],
                data_sources=[],
                detection="",
                is_subtechnique=False,
                parent_technique=None,
            )

        results = populated_client.search_by_keyword("test", limit=5)
        assert len(results) == 5

    def test_search_no_results(self, populated_client: MITREAttackClient):
        """Test search with no matching results."""
        results = populated_client.search_by_keyword("nonexistent")
        assert results == []


# =============================================================================
# Tests for MITRELookupTools (ares.tools.shared.mitre)
# =============================================================================


class TestMITRELookupToolsInit:
    """Tests for MITRELookupTools initialization."""

    def test_init_without_client(self):
        """Test initialization without client."""
        tools = MITRELookupTools()
        assert tools.mitre_client is None

    def test_set_client(self):
        """Test setting MITRE client."""
        tools = MITRELookupTools()
        client = MITREAttackClient()
        tools.set_client(client)
        assert tools.mitre_client is client


class TestMITRELookupToolsLookupTechnique:
    """Tests for lookup_technique method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create a client with test data."""
        client = MITREAttackClient()
        client._techniques["T1003.006"] = Technique(
            id="T1003.006",
            name="DCSync",
            description="DCSync attack",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=["Windows"],
            data_sources=["AD"],
            detection="Monitor 4662",
            is_subtechnique=True,
            parent_technique="T1003",
        )
        return client

    def test_lookup_without_client(self):
        """Test lookup without client returns error."""
        tools = MITRELookupTools()
        result = tools.lookup_technique("T1003.006")
        assert "error" in result
        assert "not initialized" in result["error"]

    def test_lookup_found(self, populated_client: MITREAttackClient):
        """Test lookup returns technique details."""
        tools = MITRELookupTools()
        tools.set_client(populated_client)
        result = tools.lookup_technique("T1003.006")
        assert result["id"] == "T1003.006"
        assert result["name"] == "DCSync"
        assert result["tactic"] == "credential-access"

    def test_lookup_not_found(self, populated_client: MITREAttackClient):
        """Test lookup returns None for non-existent technique."""
        tools = MITRELookupTools()
        tools.set_client(populated_client)
        result = tools.lookup_technique("T9999")
        assert result is None


class TestMITRELookupToolsRelatedTechniques:
    """Tests for get_related_techniques method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create a client with test data."""
        client = MITREAttackClient()
        client._techniques["T1003"] = Technique(
            id="T1003",
            name="OS Credential Dumping",
            description="",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=False,
            parent_technique=None,
        )
        client._techniques["T1003.006"] = Technique(
            id="T1003.006",
            name="DCSync",
            description="",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=True,
            parent_technique="T1003",
        )
        client._subtechniques["T1003"] = ["T1003.006"]
        return client

    def test_related_without_client(self):
        """Test get_related_techniques without client returns error."""
        tools = MITRELookupTools()
        result = tools.get_related_techniques("T1003")
        assert len(result) == 1
        assert "error" in result[0]

    def test_related_techniques(self, populated_client: MITREAttackClient):
        """Test get_related_techniques returns related techniques."""
        tools = MITRELookupTools()
        tools.set_client(populated_client)
        result = tools.get_related_techniques("T1003")
        assert isinstance(result, list)


class TestMITRELookupToolsTacticalGaps:
    """Tests for identify_tactical_gaps method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create client with tactics."""
        client = MITREAttackClient()
        client._tactics["TA0001"] = Tactic("TA0001", "Initial Access", "initial-access", "")
        client._tactics["TA0002"] = Tactic("TA0002", "Execution", "execution", "")
        return client

    def test_gaps_without_client(self):
        """Test identify_tactical_gaps without client returns error."""
        tools = MITRELookupTools()
        result = tools.identify_tactical_gaps()
        assert len(result) == 1
        assert "error" in result[0]

    def test_identify_gaps(self, populated_client: MITREAttackClient):
        """Test identify_tactical_gaps returns tactics."""
        tools = MITRELookupTools()
        tools.set_client(populated_client)
        result = tools.identify_tactical_gaps()
        assert isinstance(result, list)
        assert len(result) > 0
        assert "tactic_id" in result[0]
        assert "tactic_name" in result[0]


class TestMITRELookupToolsSearchTechniques:
    """Tests for search_techniques method."""

    @pytest.fixture
    def populated_client(self) -> MITREAttackClient:
        """Create client with techniques."""
        client = MITREAttackClient()
        client._techniques["T1003"] = Technique(
            id="T1003",
            name="OS Credential Dumping",
            description="Dump credentials",
            tactic="credential-access",
            tactic_id="TA0006",
            platforms=[],
            data_sources=[],
            detection="",
            is_subtechnique=False,
            parent_technique=None,
        )
        return client

    def test_search_without_client(self):
        """Test search_techniques without client returns error."""
        tools = MITRELookupTools()
        result = tools.search_techniques("credential")
        assert len(result) == 1
        assert "error" in result[0]

    def test_search_techniques(self, populated_client: MITREAttackClient):
        """Test search_techniques returns matching techniques."""
        tools = MITRELookupTools()
        tools.set_client(populated_client)
        result = tools.search_techniques("credential")
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0]["id"] == "T1003"
        assert result[0]["name"] == "OS Credential Dumping"
