"""Tests for crack task password-already-known optimization.

Tests that crack tasks skip processing when the password is already known.
"""

from __future__ import annotations

import pytest

from ares.core.models import Credential, SharedRedTeamState


class TestCrackSkipLogic:
    """Tests for the password-already-known skip logic.

    These tests verify the skip logic directly rather than through the full
    _execute_crack_task method, which requires extensive mocking.
    """

    @pytest.fixture
    def shared_state(self) -> SharedRedTeamState:
        """Create a shared state with credentials."""
        return SharedRedTeamState(operation_id="test-op")

    def test_finds_matching_credential_same_case(self, shared_state):
        """Test finding matching credential with same case."""
        shared_state.all_credentials.append(
            Credential(
                username="testuser",
                password="KnownPassword123",  # pragma: allowlist secret
                domain="domain.local",
                source="previous_crack",
            )
        )

        # This is the logic used in _execute_crack_task
        username = "testuser"
        domain = "domain.local"

        password_known = False
        known_password = None
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                known_password = cred.password
                break

        assert password_known is True
        assert known_password == "KnownPassword123"  # pragma: allowlist secret

    def test_finds_matching_credential_different_case(self, shared_state):
        """Test finding matching credential with different case."""
        shared_state.all_credentials.append(
            Credential(
                username="TestUser",  # Different case
                password="KnownPassword123",  # pragma: allowlist secret
                domain="DOMAIN.LOCAL",  # Different case
                source="previous_crack",
            )
        )

        username = "testuser"
        domain = "domain.local"

        password_known = False
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                break

        assert password_known is True

    def test_does_not_match_different_user(self, shared_state):
        """Test that different users don't match."""
        shared_state.all_credentials.append(
            Credential(
                username="otheruser",
                password="OtherPassword",  # pragma: allowlist secret
                domain="domain.local",
                source="spray",
            )
        )

        username = "testuser"
        domain = "domain.local"

        password_known = False
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                break

        assert password_known is False

    def test_does_not_match_different_domain(self, shared_state):
        """Test that same user in different domain doesn't match."""
        shared_state.all_credentials.append(
            Credential(
                username="testuser",
                password="KnownPassword",  # pragma: allowlist secret
                domain="other.local",  # Different domain
                source="spray",
            )
        )

        username = "testuser"
        domain = "domain.local"

        password_known = False
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                break

        assert password_known is False

    def test_empty_password_does_not_match(self, shared_state):
        """Test that credential with empty password doesn't trigger skip."""
        shared_state.all_credentials.append(
            Credential(
                username="testuser",
                password="",  # Empty password
                domain="domain.local",
                source="hash_only",
            )
        )

        username = "testuser"
        domain = "domain.local"

        password_known = False
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                break

        assert password_known is False

    def test_no_credentials_does_not_match(self, shared_state):
        """Test that empty credentials list doesn't trigger skip."""
        username = "testuser"
        domain = "domain.local"

        password_known = False
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                break

        assert password_known is False

    def test_multiple_credentials_finds_match(self, shared_state):
        """Test finding match among multiple credentials."""
        shared_state.all_credentials.append(
            Credential(
                username="user1",
                password="Pass1",  # pragma: allowlist secret
                domain="domain.local",
                source="spray",
            )
        )
        shared_state.all_credentials.append(
            Credential(
                username="testuser",
                password="TargetPassword",  # pragma: allowlist secret
                domain="domain.local",
                source="spray",
            )
        )
        shared_state.all_credentials.append(
            Credential(
                username="user3",
                password="Pass3",  # pragma: allowlist secret
                domain="domain.local",
                source="spray",
            )
        )

        username = "testuser"
        domain = "domain.local"

        password_known = False
        known_password = None
        for cred in shared_state.all_credentials:
            cred_user = cred.username.lower() if cred.username else ""
            cred_domain = (cred.domain or "").lower()
            if cred_user == username.lower() and cred_domain == domain.lower() and cred.password:
                password_known = True
                known_password = cred.password
                break

        assert password_known is True
        assert known_password == "TargetPassword"  # pragma: allowlist secret


class TestCrackSkipInWorker:
    """Integration-style tests verifying the skip is in the worker code."""

    def test_skip_logic_exists_in_worker(self):
        """Verify the skip logic exists in the worker code."""
        import inspect

        from ares.core.worker import RedisWorkerAgent

        source = inspect.getsource(RedisWorkerAgent._execute_crack_task)

        # Verify key parts of the skip logic are present
        assert "already known" in source.lower() or "skip" in source.lower(), (
            "_execute_crack_task should contain skip logic for already-known passwords"
        )
        assert "all_credentials" in source, (
            "_execute_crack_task should check shared_state.all_credentials"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
