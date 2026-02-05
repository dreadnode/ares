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
    """Integration-style tests verifying the skip works in the worker code."""

    @pytest.mark.asyncio
    async def test_skip_when_password_already_known(self):
        """Verify _execute_crack_task skips cracking when password is already known."""
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        from ares.core.models import AgentRole
        from ares.core.task_queue import TaskMessage
        from ares.core.worker import RedisWorkerAgent

        state = SharedRedTeamState(operation_id="op-skip-test")
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="KnownPass!",  # pragma: allowlist secret
                domain="contoso.local",
                source="spray",
            )
        )

        task_queue = SimpleNamespace(send_result=AsyncMock())
        worker = RedisWorkerAgent(
            role=AgentRole.CRACKER,
            task_queue=task_queue,
            agent=AsyncMock(),
            agent_name="ares-cracker",
            shared_state=state,
        )

        task = TaskMessage(
            task_id="task-skip",
            task_type="crack",
            source_agent="orchestrator",
            target_agent="cracker",
            payload={
                "hash_value": "$krb5tgs$23$*testuser$contoso.local*",
                "hash_type": "TGS",
                "username": "testuser",
                "domain": "contoso.local",
            },
        )

        await worker._execute_crack_task(task)

        # Should have sent a success result indicating skip
        task_queue.send_result.assert_awaited_once()
        call_kwargs = task_queue.send_result.call_args.kwargs
        assert call_kwargs["success"] is True
        assert "already known" in call_kwargs["result"]["output"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
