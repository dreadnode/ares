"""Tests for the user summary report generator."""

import uuid
from datetime import datetime, timezone

import pytest

from ares.core.models import (
    Credential,
    Hash,
    SharedRedTeamState,
    Target,
    User,
)
from ares.reports.user_summary import (
    AttackChainStep,
    UserSummary,
    format_attack_chain,
    generate_user_summaries,
    trace_attack_chain,
)


class TestUserSummaryGeneration:
    """Tests for user summary generation."""

    @pytest.fixture
    def state_with_chain(self, sample_target: Target) -> SharedRedTeamState:
        """Create state with attack chain data."""
        state = SharedRedTeamState(operation_id=f"op-{uuid.uuid4().hex[:8]}")
        state.target = sample_target

        # Create attack chain: initial cred -> hash -> cracked cred
        initial_cred = Credential(
            id="cred-001",
            username="svc_backup",
            password="Password123!",  # pragma: allowlist secret
            domain="contoso.local",
            source="manual-inject",
            is_admin=False,
            parent_id=None,
            attack_step=0,
        )

        dumped_hash = Hash(
            id="hash-001",
            username="admin",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump",  # pragma: allowlist secret
            parent_id="cred-001",
            attack_step=1,
            discovered_at=datetime.now(timezone.utc),
        )

        cracked_cred = Credential(
            id="cred-002",
            username="admin",
            password="Cr4cked!",  # pragma: allowlist secret
            domain="contoso.local",
            source="hashcat",
            is_admin=True,
            parent_id="hash-001",
            attack_step=2,
        )

        state.all_credentials = [initial_cred, cracked_cred]
        state.all_hashes = [dumped_hash]
        state.all_users = [
            User(username="svc_backup", domain="contoso.local", is_admin=False),
            User(username="admin", domain="contoso.local", is_admin=True),
        ]

        return state

    def test_generate_returns_list(self, red_team_state: SharedRedTeamState) -> None:
        """Test generate_user_summaries returns a list."""
        summaries = generate_user_summaries(red_team_state)
        assert isinstance(summaries, list)

    def test_empty_state_returns_empty_list(self, sample_target: Target) -> None:
        """Test empty state returns empty list."""
        state = SharedRedTeamState(operation_id="op-test")
        state.target = sample_target
        summaries = generate_user_summaries(state)
        assert summaries == []

    def test_aggregates_by_user(self, state_with_chain: SharedRedTeamState) -> None:
        """Test credentials and hashes are aggregated by user."""
        summaries = generate_user_summaries(state_with_chain)

        # Should have 2 users: svc_backup and admin
        assert len(summaries) == 2

        # Find each user
        svc_user = next((s for s in summaries if s.username == "svc_backup"), None)
        admin_user = next((s for s in summaries if s.username == "admin"), None)

        assert svc_user is not None
        assert admin_user is not None

        # svc_backup has 1 credential, no hashes
        assert len(svc_user.credentials) == 1
        assert len(svc_user.hashes) == 0

        # admin has 1 credential and 1 hash
        assert len(admin_user.credentials) == 1
        assert len(admin_user.hashes) == 1

    def test_admin_status_aggregated(self, state_with_chain: SharedRedTeamState) -> None:
        """Test admin status is properly aggregated."""
        summaries = generate_user_summaries(state_with_chain)

        admin_user = next((s for s in summaries if s.username == "admin"), None)
        svc_user = next((s for s in summaries if s.username == "svc_backup"), None)

        assert admin_user is not None
        assert admin_user.is_admin is True

        assert svc_user is not None
        assert svc_user.is_admin is False

    def test_discovery_sources_collected(self, state_with_chain: SharedRedTeamState) -> None:
        """Test discovery sources are collected."""
        summaries = generate_user_summaries(state_with_chain)

        admin_user = next((s for s in summaries if s.username == "admin"), None)
        assert admin_user is not None
        assert "secretsdump" in admin_user.discovery_sources  # pragma: allowlist secret
        assert "hashcat" in admin_user.discovery_sources

    def test_attack_chains_traced(self, state_with_chain: SharedRedTeamState) -> None:
        """Test attack chains are traced."""
        summaries = generate_user_summaries(state_with_chain)

        admin_user = next((s for s in summaries if s.username == "admin"), None)
        assert admin_user is not None

        # Should have attack chains for the hash and credential
        assert len(admin_user.attack_chains) >= 1

        # The cracked credential (cred-002) should have a chain back to initial cred
        if "cred-002" in admin_user.attack_chains:
            chain = admin_user.attack_chains["cred-002"]
            assert len(chain) >= 2  # At least hash-001 and cred-001

    def test_max_attack_depth(self, state_with_chain: SharedRedTeamState) -> None:
        """Test max attack depth is calculated."""
        summaries = generate_user_summaries(state_with_chain)

        admin_user = next((s for s in summaries if s.username == "admin"), None)
        assert admin_user is not None
        assert admin_user.max_attack_depth >= 1  # At least depth 1 from secretsdump


class TestTraceAttackChain:
    """Tests for attack chain tracing."""

    def test_single_item_chain(self) -> None:
        """Test tracing a single item with no parent."""
        cred = Credential(
            id="cred-001",
            username="testuser",
            password="pass",  # pragma: allowlist secret
            domain="contoso.local",
            source="manual",
            parent_id=None,
            attack_step=0,
        )
        item_index = {cred.id: cred}

        chain = trace_attack_chain(cred, item_index)
        assert len(chain) == 1
        assert chain[0].username == "testuser"
        assert chain[0].step_number == 0

    def test_multi_step_chain(self) -> None:
        """Test tracing a multi-step chain."""
        cred1 = Credential(
            id="cred-001",
            username="user1",
            password="pass1",  # pragma: allowlist secret
            domain="contoso.local",
            source="manual",
            parent_id=None,
            attack_step=0,
        )
        hash1 = Hash(
            id="hash-001",
            username="user2",
            hash_value="abc123",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump",  # pragma: allowlist secret
            parent_id="cred-001",
            attack_step=1,
        )
        cred2 = Credential(
            id="cred-002",
            username="user2",
            password="cracked",  # pragma: allowlist secret
            domain="contoso.local",
            source="hashcat",
            parent_id="hash-001",
            attack_step=2,
        )

        item_index = {cred1.id: cred1, hash1.id: hash1, cred2.id: cred2}

        chain = trace_attack_chain(cred2, item_index)
        assert len(chain) == 3
        # Chain should be in order: cred1 -> hash1 -> cred2
        assert chain[0].username == "user1"
        assert chain[0].step_number == 0
        assert chain[1].username == "user2"
        assert chain[1].step_number == 1
        assert chain[2].username == "user2"
        assert chain[2].step_number == 2

    def test_broken_chain(self) -> None:
        """Test tracing with missing parent."""
        cred = Credential(
            id="cred-002",
            username="testuser",
            password="pass",  # pragma: allowlist secret
            domain="contoso.local",
            source="hashcat",
            parent_id="missing-parent",  # Parent doesn't exist
            attack_step=1,
        )
        item_index = {cred.id: cred}

        chain = trace_attack_chain(cred, item_index)
        # Should still return the single item
        assert len(chain) == 1
        assert chain[0].username == "testuser"


class TestFormatAttackChain:
    """Tests for attack chain formatting."""

    def test_empty_chain(self) -> None:
        """Test formatting empty chain."""
        result = format_attack_chain([], compact=True)
        assert result == "(no chain data)"

    def test_compact_format(self) -> None:
        """Test compact chain formatting."""
        chain = [
            AttackChainStep(
                step_number=0,
                item_type="credential",
                username="user1",
                domain="contoso.local",
                source="manual",
                item_id="cred-001",
            ),
            AttackChainStep(
                step_number=1,
                item_type="hash",
                username="user2",
                domain="contoso.local",
                source="secretsdump",  # pragma: allowlist secret
                item_id="hash-001",
            ),
        ]

        result = format_attack_chain(chain, compact=True)
        assert "manual" in result
        assert "secretsdump" in result  # pragma: allowlist secret
        assert " -> " in result

    def test_verbose_format(self) -> None:
        """Test verbose chain formatting."""
        chain = [
            AttackChainStep(
                step_number=0,
                item_type="credential",
                username="user1",
                domain="contoso.local",
                source="manual",
                item_id="cred-001",
            ),
        ]

        result = format_attack_chain(chain, compact=False)
        assert "[0]" in result
        assert "manual" in result
        assert "user1" in result


class TestUserSummaryProperties:
    """Tests for UserSummary dataclass properties."""

    def test_user_key(self) -> None:
        """Test user_key property."""
        summary = UserSummary(username="TestUser", domain="CONTOSO.LOCAL")
        assert summary.user_key == "contoso.local\\testuser"

    def test_display_name_with_domain(self) -> None:
        """Test display_name with domain."""
        summary = UserSummary(username="testuser", domain="contoso.local")
        assert summary.display_name == "contoso.local\\testuser"

    def test_display_name_without_domain(self) -> None:
        """Test display_name without domain."""
        summary = UserSummary(username="testuser", domain="")
        assert summary.display_name == "testuser"

    def test_has_cleartext(self) -> None:
        """Test has_cleartext method."""
        summary = UserSummary(username="testuser", domain="contoso.local")
        assert summary.has_cleartext() is False

        summary.credentials = [
            Credential(
                username="testuser",
                password="pass",  # pragma: allowlist secret
                domain="contoso.local",
            )
        ]
        assert summary.has_cleartext() is True

    def test_has_hash(self) -> None:
        """Test has_hash method."""
        summary = UserSummary(username="testuser", domain="contoso.local")
        assert summary.has_hash() is False

        summary.hashes = [
            Hash(
                username="testuser",
                hash_value="abc123",
                hash_type="NTLM",
                domain="contoso.local",
            )
        ]
        assert summary.has_hash() is True
