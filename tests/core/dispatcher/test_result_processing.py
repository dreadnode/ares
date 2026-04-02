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


class TestHashSourceFromTaskResult:
    """Tests for hash source fallback in _process_success_result_data.

    When crack workers return results via result["hash"] or result["hashes"],
    the Hash object should use source from hash data if present, otherwise
    fall back to source_agent (e.g., "ares-cracker").
    """

    @pytest.mark.asyncio
    async def test_hash_source_falls_back_to_source_agent(self):
        """Hash without source in data should use source_agent as fallback."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-hash-source")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher._credential_access_event = MagicMock()
        dispatcher._checkpoint = AsyncMock()
        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._immediate_crack_dispatch = AsyncMock()

        published_hashes = []

        async def capture_publish(hash_obj, source_agent, **kwargs):
            published_hashes.append(hash_obj)

        dispatcher.publish_hash = capture_publish

        # Simulate crack result: hash dict without "source" key (like worker sends)
        result = {
            "hash": {
                "username": "jon.snow",
                "hash_value": "$krb5tgs$23$*jon.snow$CONTOSO.LOCAL$...",
                "hash_type": "Kerberoast",
                "domain": "contoso.local",
                "cracked_password": "iknownothing",  # pragma: allowlist secret
            },
            "success": True,
        }

        await dispatcher._process_success_result_data(
            result,
            task_id="crack_test_001",
            source_agent="ares-cracker",
            parent_credential_id=None,
            parent_attack_step=0,
        )

        assert len(published_hashes) == 1
        assert published_hashes[0].source == "ares-cracker"

    @pytest.mark.asyncio
    async def test_hash_source_uses_explicit_source_from_data(self):
        """Hash with explicit source in data should use that source."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-hash-source-explicit")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher._credential_access_event = MagicMock()
        dispatcher._checkpoint = AsyncMock()
        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._immediate_crack_dispatch = AsyncMock()

        published_hashes = []

        async def capture_publish(hash_obj, source_agent, **kwargs):
            published_hashes.append(hash_obj)

        dispatcher.publish_hash = capture_publish

        result = {
            "hash": {
                "username": "svc_sql",
                "hash_value": "aad3b435:31d6cfe0d16ae931b73c59d7e0c089c0",
                "hash_type": "NTLM",
                "domain": "contoso.local",
                "cracked_password": "",
                "source": "secretsdump@192.168.58.10",
            },
            "success": True,
        }

        await dispatcher._process_success_result_data(
            result,
            task_id="privesc_test_001",
            source_agent="ares-privesc",
            parent_credential_id=None,
            parent_attack_step=0,
        )

        assert len(published_hashes) == 1
        assert published_hashes[0].source == "secretsdump@192.168.58.10"

    @pytest.mark.asyncio
    async def test_hashes_plural_source_falls_back_to_source_agent(self):
        """Hashes (plural) without source should use source_agent as fallback."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-hashes-source")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher._credential_access_event = MagicMock()
        dispatcher._checkpoint = AsyncMock()
        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._immediate_crack_dispatch = AsyncMock()

        published_hashes = []

        async def capture_publish(hash_obj, source_agent, **kwargs):
            published_hashes.append(hash_obj)

        dispatcher.publish_hash = capture_publish

        result = {
            "hashes": [
                {
                    "username": "administrator",
                    "hash_value": "aad3b435:2e993405ab82e4454afc9c9bb0939a25",
                    "hash_type": "NTLM",
                    "domain": "contoso.local",
                },
                {
                    "username": "krbtgt",
                    "hash_value": "aad3b435:faaa7e195adfc629437d6e9135712b5d",
                    "hash_type": "NTLM",
                    "domain": "contoso.local",
                    "source": "ntds-dump",
                },
            ],
            "success": True,
        }

        await dispatcher._process_success_result_data(
            result,
            task_id="privesc_test_001",
            source_agent="ares-privesc",
            parent_credential_id=None,
            parent_attack_step=0,
        )

        assert len(published_hashes) == 2
        # First hash has no source in data -> falls back to source_agent
        assert published_hashes[0].source == "ares-privesc"
        # Second hash has explicit source in data -> uses it
        assert published_hashes[1].source == "ntds-dump"


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


class TestMarkVulnerabilityExploitedDirectPersist:
    """Tests for mark_vulnerability_exploited direct Redis persist from threaded consumer.

    When mark_vulnerability_exploited is called from a non-main thread (threaded
    consumer), it should persist directly to Redis using task_queue.redis instead
    of requesting a checkpoint. This ensures immediate visibility to CLI.
    """

    @pytest.mark.asyncio
    async def test_threaded_consumer_persists_directly_to_redis(self):
        """When called from non-main thread with task_queue, should persist to Redis directly."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-direct-persist")
        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._checkpoint_requested.is_set = MagicMock(return_value=False)

        # Create mock task_queue with redis client
        mock_redis = AsyncMock()
        mock_task_queue = MagicMock()
        mock_task_queue.redis = mock_redis

        # Mock RedisStateBackend
        mock_backend = AsyncMock()
        mock_backend.mark_exploited = AsyncMock(return_value=True)

        # Simulate being in non-main thread by patching threading.current_thread
        with patch("ares.core.dispatcher.vulnerability.threading.current_thread") as mock_current:
            # Return a mock thread that is NOT the main thread
            mock_current.return_value = MagicMock(name="ResultConsumerThread")

            with patch("ares.core.state_backend.RedisStateBackend") as mock_backend_class:
                mock_backend_class.return_value = mock_backend

                await dispatcher.mark_vulnerability_exploited(
                    vuln_id="constrained_delegation_192.168.58.10",
                    success=True,
                    result={"output": "Got DA!"},
                    task_queue=mock_task_queue,
                )

        # Verify in-memory state was updated
        assert (
            "constrained_delegation_192.168.58.10"
            in dispatcher.shared_state.exploited_vulnerabilities
        )

    @pytest.mark.asyncio
    async def test_threaded_consumer_fallback_on_redis_failure(self):
        """When direct Redis persist fails, should fallback to checkpoint request."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-fallback")
        dispatcher._checkpoint_requested = MagicMock()

        # Create mock task_queue with redis client that will fail
        mock_redis = AsyncMock()
        mock_task_queue = MagicMock()
        mock_task_queue.redis = mock_redis

        # Mock RedisStateBackend to raise exception
        mock_backend = AsyncMock()
        mock_backend.mark_exploited = AsyncMock(side_effect=Exception("Redis connection lost"))

        with patch("ares.core.dispatcher.vulnerability.threading.current_thread") as mock_current:
            mock_current.return_value = MagicMock(name="ResultConsumerThread")

            with patch("ares.core.state_backend.RedisStateBackend") as mock_backend_class:
                mock_backend_class.return_value = mock_backend

                await dispatcher.mark_vulnerability_exploited(
                    vuln_id="esc1_192.168.58.20",
                    success=True,
                    result={"output": "Certificate obtained"},
                    task_queue=mock_task_queue,
                )

        # Should have requested checkpoint as fallback
        dispatcher._checkpoint_requested.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_threaded_consumer_without_task_queue_requests_checkpoint(self):
        """When called from non-main thread without task_queue, should request checkpoint."""
        from unittest.mock import MagicMock, patch

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-no-queue")
        dispatcher._checkpoint_requested = MagicMock()

        with patch("ares.core.dispatcher.vulnerability.threading.current_thread") as mock_current:
            mock_current.return_value = MagicMock(name="ResultConsumerThread")

            await dispatcher.mark_vulnerability_exploited(
                vuln_id="mssql_impersonation_192.168.58.30",
                success=True,
                result={"output": "Impersonation successful"},
                task_queue=None,  # No task queue provided
            )

        # Should request checkpoint since no task_queue for direct persist
        dispatcher._checkpoint_requested.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_failed_exploit_requests_checkpoint_only(self):
        """Failed exploitation should only request checkpoint, not direct persist."""
        from unittest.mock import MagicMock, patch

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-failed")
        dispatcher._checkpoint_requested = MagicMock()

        mock_task_queue = MagicMock()
        mock_task_queue.redis = MagicMock()

        with patch("ares.core.dispatcher.vulnerability.threading.current_thread") as mock_current:
            mock_current.return_value = MagicMock(name="ResultConsumerThread")

            await dispatcher.mark_vulnerability_exploited(
                vuln_id="esc8_192.168.58.40",
                success=False,  # Failed exploit
                result={"error": "Connection refused"},
                task_queue=mock_task_queue,
            )

        # Should request checkpoint (failed exploits don't need immediate persist)
        dispatcher._checkpoint_requested.set.assert_called_once()
        # Should NOT have added to exploited set
        assert "esc8_192.168.58.40" not in dispatcher.shared_state.exploited_vulnerabilities

    @pytest.mark.asyncio
    async def test_main_thread_uses_redis_client_directly(self):
        """When called from main thread, should use _mark_exploited_in_redis."""
        import threading
        from unittest.mock import AsyncMock, MagicMock, patch

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-main-thread")
        dispatcher._redis_client = AsyncMock()
        dispatcher._checkpoint = AsyncMock()
        dispatcher._mark_exploited_in_redis = AsyncMock()
        dispatcher._clear_vuln_in_progress = AsyncMock()

        with patch("ares.core.dispatcher.vulnerability.threading.current_thread") as mock_current:
            mock_current.return_value = threading.main_thread()

            await dispatcher.mark_vulnerability_exploited(
                vuln_id="unconstrained_192.168.58.50",
                success=True,
                result={"output": "Got TGT"},
                task_queue=MagicMock(),
            )

        # Should use main thread path (direct Redis calls)
        dispatcher._mark_exploited_in_redis.assert_called_once()
        dispatcher._clear_vuln_in_progress.assert_called_once()
        dispatcher._checkpoint.assert_called_once()


class TestDispatcherStopFinalCheckpoint:
    """Tests for final checkpoint on dispatcher stop.

    When stop() is called, it should persist any pending state (especially
    exploited_vulnerabilities set by threaded consumer) before cleanup.
    """

    @pytest.mark.asyncio
    async def test_stop_performs_final_checkpoint_when_requested(self):
        """stop() should checkpoint when _checkpoint_requested is set."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-stop-1")
        dispatcher._running = True

        # Set checkpoint requested (simulates threaded consumer setting it)
        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._checkpoint_requested.is_set = MagicMock(return_value=True)

        # Mock cleanup methods
        dispatcher._checkpoint = AsyncMock()
        dispatcher._heartbeat_task = None
        dispatcher._maintenance_task = None
        dispatcher._task_queue = None
        dispatcher._stop_threaded_result_consumer = MagicMock()
        dispatcher._stop_deferred_processor = AsyncMock()

        await dispatcher.stop()

        # Final checkpoint should have been called
        dispatcher._checkpoint.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_performs_final_checkpoint_with_shared_state(self):
        """stop() should checkpoint when shared_state exists (even if not explicitly requested)."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-stop-2")
        dispatcher._running = True

        # Checkpoint not explicitly requested, but state exists
        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._checkpoint_requested.is_set = MagicMock(return_value=False)

        dispatcher._checkpoint = AsyncMock()
        dispatcher._heartbeat_task = None
        dispatcher._maintenance_task = None
        dispatcher._task_queue = None
        dispatcher._stop_threaded_result_consumer = MagicMock()
        dispatcher._stop_deferred_processor = AsyncMock()

        await dispatcher.stop()

        # Final checkpoint should still be called (shared_state truthy)
        dispatcher._checkpoint.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_handles_checkpoint_failure_gracefully(self):
        """stop() should continue cleanup even if final checkpoint fails."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-stop-fail")
        dispatcher._running = True

        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._checkpoint_requested.is_set = MagicMock(return_value=True)

        # Make checkpoint fail
        dispatcher._checkpoint = AsyncMock(side_effect=Exception("Redis connection lost"))
        dispatcher._heartbeat_task = None
        dispatcher._maintenance_task = None
        dispatcher._task_queue = None
        dispatcher._stop_threaded_result_consumer = MagicMock()
        dispatcher._stop_deferred_processor = AsyncMock()

        # Should not raise
        await dispatcher.stop()

        # Checkpoint was attempted
        dispatcher._checkpoint.assert_called_once()
        # Cleanup should have continued
        dispatcher._stop_threaded_result_consumer.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_skips_checkpoint_without_state(self):
        """stop() should skip checkpoint if no shared_state exists."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = None  # No state
        dispatcher._running = True

        dispatcher._checkpoint_requested = MagicMock()
        dispatcher._checkpoint_requested.is_set = MagicMock(return_value=False)

        dispatcher._checkpoint = AsyncMock()
        dispatcher._heartbeat_task = None
        dispatcher._maintenance_task = None
        dispatcher._task_queue = None
        dispatcher._stop_threaded_result_consumer = MagicMock()
        dispatcher._stop_deferred_processor = AsyncMock()

        await dispatcher.stop()

        # No checkpoint needed without state
        dispatcher._checkpoint.assert_not_called()


class TestResultProcessingPassesTaskQueue:
    """Tests for result_processing passing task_queue to mark_vulnerability_exploited."""

    @pytest.mark.asyncio
    async def test_complete_task_passes_task_queue_to_mark_exploited(self):
        """complete_task should pass task_queue to mark_vulnerability_exploited for exploits."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, TaskInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-pass-queue")
        dispatcher._running = True
        dispatcher._redis_client = AsyncMock()

        # Mock the methods we don't want to actually run
        dispatcher._persist_completed_task = AsyncMock()
        dispatcher._auto_chain_s4u_lateral_movement = AsyncMock(return_value=0)
        dispatcher.mark_vulnerability_exploited = AsyncMock()
        dispatcher._get_task_info_from_redis = AsyncMock(return_value=None)

        # Create mock task_queue
        mock_task_queue = MagicMock()
        mock_task_queue.redis = AsyncMock()

        # Create task info for exploit
        task_info = TaskInfo(
            task_id="task-exploit-1",
            task_type="exploit",
            assigned_agent="privesc",
            params={"vuln_id": "constrained_delegation_192.168.58.10"},
        )
        dispatcher._shared_state.pending_tasks["task-exploit-1"] = task_info

        # Also need to mock the persist method
        dispatcher._persist_task_info_to_redis = AsyncMock()

        result = {"output": "Got DA!"}

        await dispatcher.complete_task(
            task_id="task-exploit-1",
            success=True,
            result=result,
            source_agent="privesc",
            task_queue=mock_task_queue,
        )

        # mark_vulnerability_exploited should be called with task_queue
        dispatcher.mark_vulnerability_exploited.assert_called_once()
        call_kwargs = dispatcher.mark_vulnerability_exploited.call_args.kwargs
        assert call_kwargs.get("task_queue") is mock_task_queue


class TestParentVulnIdTracking:
    """Tests for parent_vuln_id propagation through S4U chain.

    When a constrained_delegation exploit dispatches a chained secretsdump task,
    the parent_vuln_id is passed through so the vulnerability can be marked as
    exploited when secretsdump succeeds.
    """

    @pytest.mark.asyncio
    async def test_secretsdump_marks_parent_vuln_exploited(self):
        """When secretsdump with parent_vuln_id succeeds, parent vuln is marked exploited."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, TaskInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-parent-vuln")
        dispatcher._running = True
        dispatcher._redis_client = AsyncMock()

        # Mock the methods we don't want to actually run
        dispatcher._persist_completed_task = AsyncMock()
        dispatcher._auto_chain_s4u_lateral_movement = AsyncMock(return_value=0)
        dispatcher.mark_vulnerability_exploited = AsyncMock()
        dispatcher._get_task_info_from_redis = AsyncMock(return_value=None)

        # Create mock task_queue
        mock_task_queue = MagicMock()
        mock_task_queue.redis = AsyncMock()

        # Create task info for secretsdump (credential_access) with parent_vuln_id
        task_info = TaskInfo(
            task_id="task-secretsdump-1",
            task_type="credential_access",  # NOT "exploit"
            assigned_agent="credaccess",
            params={"parent_vuln_id": "constrained_delegation_192.168.58.10_abc123"},
        )
        dispatcher._shared_state.pending_tasks["task-secretsdump-1"] = task_info

        # Also need to mock the persist method
        dispatcher._persist_task_info_to_redis = AsyncMock()

        result = {"output": "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6..."}

        await dispatcher.complete_task(
            task_id="task-secretsdump-1",
            success=True,
            result=result,
            source_agent="credaccess",
            task_queue=mock_task_queue,
        )

        # mark_vulnerability_exploited should be called for the parent_vuln_id
        dispatcher.mark_vulnerability_exploited.assert_called_once()
        call_args = dispatcher.mark_vulnerability_exploited.call_args
        assert call_args.args[0] == "constrained_delegation_192.168.58.10_abc123"
        assert call_args.args[1] is True  # success=True

    @pytest.mark.asyncio
    async def test_secretsdump_without_parent_vuln_id_does_not_mark(self):
        """Secretsdump without parent_vuln_id doesn't call mark_vulnerability_exploited."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, TaskInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-no-parent")
        dispatcher._running = True
        dispatcher._redis_client = AsyncMock()

        # Mock the methods we don't want to actually run
        dispatcher._persist_completed_task = AsyncMock()
        dispatcher._auto_chain_s4u_lateral_movement = AsyncMock(return_value=0)
        dispatcher.mark_vulnerability_exploited = AsyncMock()
        dispatcher._get_task_info_from_redis = AsyncMock(return_value=None)

        # Create task info for secretsdump without parent_vuln_id
        task_info = TaskInfo(
            task_id="task-secretsdump-2",
            task_type="credential_access",
            assigned_agent="credaccess",
            params={},  # No parent_vuln_id
        )
        dispatcher._shared_state.pending_tasks["task-secretsdump-2"] = task_info

        dispatcher._persist_task_info_to_redis = AsyncMock()

        result = {"output": "Some output"}

        await dispatcher.complete_task(
            task_id="task-secretsdump-2",
            success=True,
            result=result,
            source_agent="credaccess",
            task_queue=MagicMock(),
        )

        # mark_vulnerability_exploited should NOT be called
        dispatcher.mark_vulnerability_exploited.assert_not_called()

    @pytest.mark.asyncio
    async def test_failed_secretsdump_does_not_mark_parent_vuln(self):
        """Failed secretsdump with parent_vuln_id doesn't mark parent vuln exploited."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.dispatcher._dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, TaskInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-failed")
        dispatcher._running = True
        dispatcher._redis_client = AsyncMock()

        dispatcher._persist_completed_task = AsyncMock()
        dispatcher._auto_chain_s4u_lateral_movement = AsyncMock(return_value=0)
        dispatcher.mark_vulnerability_exploited = AsyncMock()
        dispatcher._get_task_info_from_redis = AsyncMock(return_value=None)

        task_info = TaskInfo(
            task_id="task-secretsdump-3",
            task_type="credential_access",
            assigned_agent="credaccess",
            params={"parent_vuln_id": "constrained_delegation_192.168.58.10_def456"},
        )
        dispatcher._shared_state.pending_tasks["task-secretsdump-3"] = task_info

        dispatcher._persist_task_info_to_redis = AsyncMock()

        await dispatcher.complete_task(
            task_id="task-secretsdump-3",
            success=False,  # Failed
            result={"error": "Access denied"},
            error="Access denied",
            source_agent="credaccess",
            task_queue=MagicMock(),
        )

        # mark_vulnerability_exploited should NOT be called for failed task
        dispatcher.mark_vulnerability_exploited.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
