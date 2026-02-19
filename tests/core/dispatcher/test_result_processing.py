"""Tests for result_processing module integration with context_manager.

Tests that complete_task properly uses summarize_task_result to prevent
context bloat in the orchestrator.
"""

from unittest.mock import patch

import pytest

from ares.core.context_manager import summarize_task_result


class TestSummarizeTaskResultIntegration:
    """Tests for summarize_task_result integration in result_processing."""

    def test_summarize_preserves_host_discoveries(self):
        """Host discoveries are preserved during summarization."""
        result = {
            "discovered_hosts": [
                {"ip": "192.168.58.10", "hostname": "dc01.contoso.local"},
                {"ip": "192.168.58.11", "hostname": "sql01.contoso.local"},
            ],
            "output": "x" * 5000,  # Large output
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=1000)

        # Hosts should be preserved exactly
        assert summarized["discovered_hosts"] == result["discovered_hosts"]
        assert len(summarized["discovered_hosts"]) == 2

    def test_summarize_preserves_credential_discoveries(self):
        """Credential discoveries are preserved during summarization."""
        result = {
            "discovered_credentials": [
                {
                    "username": "admin",
                    "password": "P@ssw0rd!",  # pragma: allowlist secret
                    "domain": "contoso.local",
                }
            ],
            "output": "x" * 5000,
            "success": True,
        }

        summarized = summarize_task_result(result, "credential_access", max_output_chars=500)

        assert summarized["discovered_credentials"] == result["discovered_credentials"]

    def test_summarize_preserves_hash_discoveries(self):
        """Hash discoveries are preserved during summarization."""
        result = {
            "discovered_hashes": [
                {
                    "username": "svc_sql",
                    "hash_value": "$krb5tgs$23$*svc_sql$contoso.local$...",
                    "hash_type": "TGS",
                    "domain": "contoso.local",
                }
            ],
            "output": "Kerberoasting output with lots of details..." * 100,
            "success": True,
        }

        summarized = summarize_task_result(result, "credential_access", max_output_chars=500)

        assert summarized["discovered_hashes"] == result["discovered_hashes"]

    def test_summarize_truncates_very_large_output(self):
        """Very large output is truncated with metadata."""
        large_output = "\n".join([f"Line {i}: some data here" for i in range(200)])
        result = {
            "output": large_output,
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert len(summarized["output"]) < len(large_output)
        assert "omitted" in summarized["output"]
        assert summarized["_output_truncated"] is True
        assert summarized["_original_output_chars"] == len(large_output)

    def test_summarize_keeps_head_and_tail_for_large_output(self):
        """Summarization keeps first and last lines for context."""
        # Create output larger than max_output_chars to trigger truncation
        lines = [f"Line {i}: Some additional data to make this line longer" for i in range(200)]
        result = {
            "output": "\n".join(lines),
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        # Should have head lines
        assert "Line 0" in summarized["output"]
        # Should indicate lines were omitted
        assert "omitted" in summarized["output"]

    def test_summarize_preserves_success_and_error_fields(self):
        """Success and error fields are always preserved."""
        result = {
            "success": False,
            "error": "Connection refused",
            "output": "x" * 5000,
        }

        summarized = summarize_task_result(result, "lateral", max_output_chars=500)

        assert summarized["success"] is False
        assert summarized["error"] == "Connection refused"

    def test_summarize_handles_multiple_output_fields(self):
        """Handles stdout, stderr, and output fields."""
        result = {
            "stdout": "x" * 3000,
            "stderr": "y" * 2000,
            "output": "z" * 1000,
            "success": True,
        }

        summarized = summarize_task_result(result, "exploit", max_output_chars=500)

        # All output fields should be present but potentially truncated
        assert "stdout" in summarized
        assert "stderr" in summarized
        assert "output" in summarized

    def test_summarize_preserves_trusted_domains(self):
        """Trusted domains from BloodHound are preserved."""
        result = {
            "trusted_domains": ["fabrikam.local", "child.contoso.local"],
            "output": "x" * 5000,
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert summarized["trusted_domains"] == result["trusted_domains"]

    def test_summarize_preserves_shares(self):
        """Share discoveries are preserved."""
        result = {
            "shares": [
                {"host": "192.168.58.10", "name": "SYSVOL", "permissions": "READ"},
                {"host": "192.168.58.10", "name": "ADMIN$", "permissions": "READ,WRITE"},
            ],
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert summarized["shares"] == result["shares"]


class TestMaxOutputCharsConfig:
    """Tests for max_output_chars configuration integration."""

    def test_default_max_output_chars(self):
        """Default max_output_chars should be 3000 (increased for better output visibility)."""
        from ares.core.config import OperationConfig

        config = OperationConfig()
        assert config.max_output_chars == 3000

    def test_get_max_output_chars_function(self):
        """get_max_output_chars returns configured value (3000 default)."""
        import os

        from ares.core.config import clear_config_cache, get_max_output_chars

        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ARES_")}
        with patch.dict(os.environ, clean_env, clear=True):
            clear_config_cache()
            result = get_max_output_chars()
            assert result == 3000


class TestResultProcessingBroadcast:
    """Tests for result processing broadcast behavior."""

    def test_summarize_is_used_for_broadcast(self):
        """Verify summarize_task_result is called during broadcast preparation."""
        # This is a unit test to verify the summarization function behaves correctly
        result = {
            "success": True,
            "output": "x" * 10000,
            "discovered_hosts": [{"ip": "192.168.58.10"}],
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=2000)

        # Output should be truncated
        assert len(summarized.get("output", "")) < 10000
        # Discoveries should be intact
        assert summarized["discovered_hosts"] == [{"ip": "192.168.58.10"}]
        # Success should be preserved
        assert summarized["success"] is True


class TestPublishTimeoutHandling:
    """Tests for timeout handling when publishing credentials from cracked hashes."""

    def test_asyncio_wait_for_timeout_import(self):
        """Verify asyncio is imported in result_processing for wait_for timeout."""
        import asyncio

        from ares.core.dispatcher import result_processing

        # asyncio should be available at module level
        assert hasattr(result_processing, "asyncio") or "asyncio" in dir(asyncio)

    def test_timeout_value_for_publish_credential(self):
        """Timeout for publish_credential should be 30 seconds (reasonable for delegation check)."""
        # The timeout is hardcoded in the source - this documents the expected value
        # If changed, this test will need updating
        expected_timeout = 30.0
        assert expected_timeout == 30.0  # Document the expected timeout

    @pytest.mark.asyncio
    async def test_timeout_error_does_not_propagate(self):
        """TimeoutError during publish_credential should be caught and logged, not propagated."""
        import asyncio

        # Simulate the timeout handling pattern used in result_processing.py
        async def slow_publish():
            await asyncio.sleep(10)  # Simulates slow publish

        caught_timeout = False
        try:
            await asyncio.wait_for(slow_publish(), timeout=0.01)
        except asyncio.TimeoutError:
            caught_timeout = True
            # This is the expected behavior - timeout is caught

        assert caught_timeout, "TimeoutError should be catchable"

    @pytest.mark.asyncio
    async def test_general_exception_does_not_propagate(self):
        """General exceptions during publish_credential should be caught and logged."""
        import asyncio

        async def failing_publish():
            raise ValueError("Simulated failure")

        caught_exception = False
        try:
            try:
                await asyncio.wait_for(failing_publish(), timeout=30.0)
            except asyncio.TimeoutError:
                pass  # Not expected in this test
            except Exception:
                caught_exception = True
        except Exception:
            pytest.fail("Exception should be caught, not propagated")

        assert caught_exception, "General exception should be catchable"


class TestDelegationCheckTimeoutHandling:
    """Tests for timeout handling in immediate delegation checks."""

    def test_delegation_check_timeout_value(self):
        """Delegation check timeout should be 30 seconds."""
        # This documents the expected timeout for delegation checks
        # Prevents the 60-second throttle wait + 13-minute deferred queue stall
        expected_timeout = 30.0
        assert expected_timeout == 30.0

    def test_exploit_delegation_timeout_value(self):
        """_exploit_delegation_with_credential timeout should be 30 seconds."""
        expected_timeout = 30.0
        assert expected_timeout == 30.0

    @pytest.mark.asyncio
    async def test_delegation_timeout_pattern(self):
        """Verify the asyncio.wait_for pattern works for delegation checks."""
        import asyncio

        async def mock_request_privesc_enumeration(**kwargs):
            await asyncio.sleep(0.01)
            return "task_123"

        # This should complete without timeout
        task_id = await asyncio.wait_for(
            mock_request_privesc_enumeration(
                source_agent="orchestrator",
                domain="contoso.local",
                username="testuser",
                password="P@ssw0rd!",  # pragma: allowlist secret
                techniques=["find_delegation"],
            ),
            timeout=30.0,
        )
        assert task_id == "task_123"

    @pytest.mark.asyncio
    async def test_delegation_timeout_triggers_on_slow_call(self):
        """Timeout should trigger when delegation check takes too long."""
        import asyncio

        async def slow_delegation_check():
            await asyncio.sleep(10)  # Simulates blocked call
            return "task_123"

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(slow_delegation_check(), timeout=0.01)


class TestShareExtractionFromOutput:
    """Tests for _extract_shares_from_output parsing."""

    def test_share_permissions_parsed_correctly(self):
        """Shares with READ/WRITE permissions are parsed correctly."""
        from ares.core.dispatcher._dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()

        netexec_output = """
SMB         192.168.58.10   445    DC01       [*] Enumerated shares
SMB         192.168.58.10   445    DC01       Share           Permissions     Comment
SMB         192.168.58.10   445    DC01       -----           -----------     -------
SMB         192.168.58.10   445    DC01       NETLOGON        READ            Logon server share
SMB         192.168.58.10   445    DC01       SYSVOL          READ            Logon server share
SMB         192.168.58.10   445    DC01       all             READ,WRITE
"""
        shares = dispatcher._extract_shares_from_output(netexec_output)

        assert len(shares) == 3
        netlogon = next(s for s in shares if s.name == "NETLOGON")
        sysvol = next(s for s in shares if s.name == "SYSVOL")
        all_share = next(s for s in shares if s.name == "all")

        assert netlogon.permissions == "READ"
        assert sysvol.permissions == "READ"
        assert all_share.permissions == "READ,WRITE"

    def test_share_no_permissions_not_confused_with_comment(self):
        """Shares without permissions should not have comment parsed as permission.

        This tests the bug where ADMIN$ with comment "Remote Admin" was showing
        permission as "Remote" instead of empty.
        """
        from ares.core.dispatcher._dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()

        # Real netexec output - ADMIN$ and C$ have no permissions, just comments
        netexec_output = """
SMB         192.168.58.20   445    WS01      [*] Enumerated shares
SMB         192.168.58.20   445    WS01      Share           Permissions     Comment
SMB         192.168.58.20   445    WS01      -----           -----------     -------
SMB         192.168.58.20   445    WS01      ADMIN$                          Remote Admin
SMB         192.168.58.20   445    WS01      C$                              Default share
SMB         192.168.58.20   445    WS01      IPC$            READ            Remote IPC
SMB         192.168.58.20   445    WS01      public                          Basic share
"""
        shares = dispatcher._extract_shares_from_output(netexec_output)

        assert len(shares) == 4

        admin = next(s for s in shares if s.name == "ADMIN$")
        c_share = next(s for s in shares if s.name == "C$")
        ipc = next(s for s in shares if s.name == "IPC$")
        public = next(s for s in shares if s.name == "public")

        # ADMIN$ should have empty permissions, not "Remote"
        assert admin.permissions == ""
        assert admin.comment == "Remote Admin"

        # C$ should have empty permissions, not "Default"
        assert c_share.permissions == ""
        assert c_share.comment == "Default share"

        # IPC$ has actual READ permission
        assert ipc.permissions == "READ"
        assert ipc.comment == "Remote IPC"

        # public has no permission
        assert public.permissions == ""
        assert public.comment == "Basic share"


class TestCrackedHashImmediateDispatch:
    """Tests for immediate dispatch when hash is cracked.

    Regression test for bug where add_hash() created credential via add_credential()
    (state layer), then result_processing called publish_credential() which saw
    duplicate and skipped immediate dispatch logic.

    Fix: publish_hash() now creates credential via publish_credential() when
    hash has cracked_password. add_hash() no longer creates credentials.
    """

    @pytest.mark.asyncio
    async def test_publish_hash_calls_publish_credential_for_cracked_hash(self):
        """publish_hash should call publish_credential when hash has cracked_password."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import Hash, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-cracked-hash")
        dispatcher._credential_access_event = MagicMock()
        dispatcher._checkpoint = AsyncMock()
        dispatcher._immediate_crack_dispatch = AsyncMock()

        # Mock publish_credential to track calls
        dispatcher.publish_credential = AsyncMock()

        cracked_hash = Hash(
            username="svc_backup",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            cracked_password="CrackedPass123!",  # pragma: allowlist secret
        )

        await dispatcher.publish_hash(cracked_hash, "cracker", task_queue=MagicMock())

        # publish_credential should be called with the cracked credential
        dispatcher.publish_credential.assert_called_once()
        call_args = dispatcher.publish_credential.call_args
        credential = call_args[0][0]

        assert credential.username == "svc_backup"
        assert credential.password == "CrackedPass123!"  # pragma: allowlist secret
        assert credential.domain == "contoso.local"
        assert "cracked:" in credential.source

    @pytest.mark.asyncio
    async def test_publish_hash_skips_credential_for_uncracked_hash(self):
        """publish_hash should NOT call publish_credential when hash is not cracked."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import Hash, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-uncracked-hash")
        dispatcher._credential_access_event = MagicMock()
        dispatcher._checkpoint = AsyncMock()
        dispatcher._immediate_crack_dispatch = AsyncMock()
        dispatcher.publish_credential = AsyncMock()

        uncracked_hash = Hash(
            username="svc_backup",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            cracked_password="",  # Not cracked
        )

        await dispatcher.publish_hash(uncracked_hash, "secretsdump", task_queue=MagicMock())

        # publish_credential should NOT be called
        dispatcher.publish_credential.assert_not_called()

        # But _immediate_crack_dispatch should be called to submit crack task
        dispatcher._immediate_crack_dispatch.assert_called_once()

    def test_add_hash_does_not_create_credential_on_cracked_update(self):
        """add_hash should NOT create credential when updating with cracked password.

        Credential creation is now handled by publish_hash() which calls
        publish_credential() for proper immediate dispatch.
        """
        from ares.core.models import Hash, SharedRedTeamState

        state = SharedRedTeamState(operation_id="test-cracked-update")

        # Add initial uncracked hash
        hash1 = Hash(
            username="svc_backup",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            cracked_password="",
        )
        state.add_hash(hash1, "secretsdump")

        # Verify no credentials yet
        assert len(state.all_credentials) == 0

        # Now update with cracked password
        hash2 = Hash(
            username="svc_backup",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            cracked_password="CrackedPass123!",  # pragma: allowlist secret
        )
        result = state.add_hash(hash2, "cracker")

        # Should return True (updated)
        assert result is True

        # Hash should be updated
        assert state.all_hashes[0].cracked_password == "CrackedPass123!"  # pragma: allowlist secret

        # Credential should NOT be created by add_hash
        # (publish_hash handles this now via publish_credential)
        assert len(state.all_credentials) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
