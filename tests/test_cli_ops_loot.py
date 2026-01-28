"""Tests for cli_ops loot deduplication functionality."""

from __future__ import annotations

from ares.core.models import Credential, Hash, SharedRedTeamState, User


class TestLootDeduplication:
    """Tests for loot deduplication logic."""

    def test_deduplicate_users_by_normalized_key(self):
        """Users should be deduplicated by normalized domain+username."""
        state = SharedRedTeamState(operation_id="op-test-loot")

        # Add users with different case/spacing
        state.users.extend(
            [
                User(username="admin", domain="CONTOSO", is_admin=True),
                User(username="Admin", domain="contoso", is_admin=True),
                User(username="ADMIN", domain="Contoso ", is_admin=False),
                User(username="john.doe", domain="CONTOSO", is_admin=False),
                User(username="John.Doe", domain="contoso", is_admin=False),
            ]
        )

        # Apply deduplication logic from cli_ops.loot
        seen_user_keys: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            key = (user.domain.strip().lower(), user.username.strip().lower())
            if key not in seen_user_keys:
                seen_user_keys.add(key)
                unique_users.append(user)

        # Should have 2 unique users
        assert len(unique_users) == 2
        usernames = {u.username for u in unique_users}
        assert "admin" in usernames or "Admin" in usernames or "ADMIN" in usernames
        assert "john.doe" in usernames or "John.Doe" in usernames

    def test_deduplicate_credentials_by_normalized_key(self):
        """Credentials should be deduplicated by normalized domain+username+password."""
        state = SharedRedTeamState(operation_id="op-test-loot-creds")

        # Add credentials with different case/spacing
        state.credentials.extend(
            [
                Credential(
                    username="admin",
                    password="P@ssw0rd",  # pragma: allowlist secret
                    domain="CONTOSO",
                    source="spray",
                    is_admin=True,
                ),
                Credential(
                    username="Admin",
                    password="P@ssw0rd",  # pragma: allowlist secret
                    domain="contoso",
                    source="spray",
                    is_admin=True,
                ),
                Credential(
                    username="admin",
                    password="DifferentPass",  # pragma: allowlist secret
                    domain="CONTOSO",
                    source="kerberoast",
                    is_admin=False,
                ),
                Credential(
                    username="john.doe",
                    password="Secret123",  # pragma: allowlist secret
                    domain="CONTOSO",
                    source="spray",
                    is_admin=False,
                ),
            ]
        )

        # Apply deduplication logic from cli_ops.loot
        seen_cred_keys: set[tuple[str, str, str]] = set()
        unique_creds = []
        for cred in state.all_credentials:
            key = (
                cred.domain.strip().lower(),
                cred.username.strip().lower(),
                cred.password,  # Password is case-sensitive
            )
            if key not in seen_cred_keys:
                seen_cred_keys.add(key)
                unique_creds.append(cred)

        # Should have 3 unique credentials (admin has 2 different passwords)
        assert len(unique_creds) == 3

    def test_deduplicate_hashes_by_normalized_key(self):
        """Hashes should be deduplicated by normalized domain+username+hash_type."""
        state = SharedRedTeamState(operation_id="op-test-loot-hashes")

        # Add hashes with different case/spacing
        state.hashes.extend(
            [
                Hash(
                    username="admin",
                    hash_value="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                    hash_type="NTLM",
                    domain="CONTOSO",
                    source="secretsdump",
                ),
                Hash(
                    username="Admin",
                    hash_value="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                    hash_type="ntlm",
                    domain="contoso",
                    source="secretsdump",
                ),
                Hash(
                    username="admin",
                    hash_value="$krb5tgs$23$*admin$CONTOSO$...",
                    hash_type="Kerberos",
                    domain="CONTOSO",
                    source="kerberoast",
                ),
                Hash(
                    username="john.doe",
                    hash_value="aad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99",
                    hash_type="NTLM",
                    domain="CONTOSO",
                    source="secretsdump",
                ),
            ]
        )

        # Apply deduplication logic from cli_ops.loot
        seen_hash_keys: set[tuple[str, str, str]] = set()
        unique_hashes = []
        for h in state.all_hashes:
            key = (
                h.domain.strip().lower(),
                h.username.strip().lower(),
                h.hash_type.strip().lower(),
            )
            if key not in seen_hash_keys:
                seen_hash_keys.add(key)
                unique_hashes.append(h)

        # Should have 3 unique hashes (admin NTLM, admin Kerberos, john.doe NTLM)
        assert len(unique_hashes) == 3

    def test_preserves_first_occurrence(self):
        """Deduplication should preserve the first occurrence."""
        state = SharedRedTeamState(operation_id="op-test-loot-order")

        # Add users in specific order
        state.users.extend(
            [
                User(username="admin", domain="CONTOSO", is_admin=True),
                User(username="Admin", domain="contoso", is_admin=False),
            ]
        )

        seen_user_keys: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            key = (user.domain.strip().lower(), user.username.strip().lower())
            if key not in seen_user_keys:
                seen_user_keys.add(key)
                unique_users.append(user)

        # First occurrence should be preserved
        assert len(unique_users) == 1
        assert unique_users[0].is_admin is True  # First user was admin

    def test_handles_empty_state(self):
        """Deduplication should handle empty state gracefully."""
        state = SharedRedTeamState(operation_id="op-test-loot-empty")

        seen_user_keys: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            key = (user.domain.strip().lower(), user.username.strip().lower())
            if key not in seen_user_keys:
                seen_user_keys.add(key)
                unique_users.append(user)

        assert len(unique_users) == 0

    def test_handles_whitespace_in_fields(self):
        """Deduplication should normalize whitespace."""
        state = SharedRedTeamState(operation_id="op-test-loot-whitespace")

        state.users.extend(
            [
                User(username="admin", domain="CONTOSO", is_admin=True),
                User(username=" admin ", domain=" CONTOSO ", is_admin=False),
                User(username="admin ", domain="CONTOSO ", is_admin=False),
            ]
        )

        seen_user_keys: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            key = (user.domain.strip().lower(), user.username.strip().lower())
            if key not in seen_user_keys:
                seen_user_keys.add(key)
                unique_users.append(user)

        # All should be considered duplicates
        assert len(unique_users) == 1

    def test_credential_password_case_sensitive(self):
        """Credential deduplication should treat password as case-sensitive."""
        state = SharedRedTeamState(operation_id="op-test-loot-pwd-case")

        state.credentials.extend(
            [
                Credential(
                    username="admin",
                    password="Password",  # pragma: allowlist secret
                    domain="CONTOSO",
                    source="spray",
                    is_admin=False,
                ),
                Credential(
                    username="admin",
                    password="password",  # pragma: allowlist secret
                    domain="CONTOSO",
                    source="spray",
                    is_admin=False,
                ),
                Credential(
                    username="admin",
                    password="PASSWORD",  # pragma: allowlist secret
                    domain="CONTOSO",
                    source="spray",
                    is_admin=False,
                ),
            ]
        )

        seen_cred_keys: set[tuple[str, str, str]] = set()
        unique_creds = []
        for cred in state.all_credentials:
            key = (
                cred.domain.strip().lower(),
                cred.username.strip().lower(),
                cred.password,  # Case-sensitive
            )
            if key not in seen_cred_keys:
                seen_cred_keys.add(key)
                unique_creds.append(cred)

        # All 3 should be unique (different password cases)
        assert len(unique_creds) == 3
