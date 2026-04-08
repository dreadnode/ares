"""Tests for the thin tool executor (Rust-driven agent loop support)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.models import SharedRedTeamState
from ares.core.worker.tool_executor import (
    TOOL_EXEC_PREFIX,
    TOOL_RESULT_PREFIX,
    ToolExecutor,
    _load_state_from_backend,
    run_tool_executor,
)


class TestToolExecutor:
    """Tests for ToolExecutor initialization and tool dispatch."""

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_build_tool_map_fallback(self, mock_config):
        """When agent config fails, all capabilities are enabled."""
        mock_config.side_effect = Exception("config not found")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        # Should have registered some tools despite config failure
        # (falls back to all capabilities)
        assert len(executor._tool_map) > 0

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_unknown_tool_returns_error(self, mock_config):
        """Calling an unknown tool should return an error response."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        # Simulate handling a request for a non-existent tool
        mock_conn = AsyncMock()
        request_data = json.dumps(
            {
                "call_id": "test_123",
                "task_id": "task_456",
                "tool_name": "nonexistent_tool_xyz",
                "arguments": {},
            }
        )

        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, request_data)
        )

        # Should have pushed an error result
        mock_conn.lpush.assert_called_once()
        result_key = mock_conn.lpush.call_args[0][0]
        result_json = mock_conn.lpush.call_args[0][1]

        assert result_key == f"{TOOL_RESULT_PREFIX}:test_123"

        result = json.loads(result_json)
        assert result["call_id"] == "test_123"
        assert result["error"] is not None
        assert "Unknown tool" in result["error"]
        assert result["output"] == ""

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_handle_invalid_json(self, mock_config):
        """Invalid JSON should be logged but not crash."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        mock_conn = AsyncMock()

        # Should not raise
        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, "not valid json{{{")
        )

        # Should not have pushed any result (invalid request)
        mock_conn.lpush.assert_not_called()

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_tool_execution_success(self, mock_config):
        """Successful tool execution returns output without error."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        # Inject a mock tool
        executor._tool_map["mock_tool"] = lambda target: f"scanned {target}"

        mock_conn = AsyncMock()
        request_data = json.dumps(
            {
                "call_id": "call_789",
                "task_id": "task_abc",
                "tool_name": "mock_tool",
                "arguments": {"target": "192.168.1.1"},
            }
        )

        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, request_data)
        )

        mock_conn.lpush.assert_called_once()
        result_json = mock_conn.lpush.call_args[0][1]
        result = json.loads(result_json)

        assert result["call_id"] == "call_789"
        assert result["output"] == "scanned 192.168.1.1"
        assert result["error"] is None

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_tool_execution_dict_result(self, mock_config):
        """Tools returning dicts should be JSON-serialized."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        executor._tool_map["dict_tool"] = lambda: {"hosts": ["10.0.0.1"], "count": 1}

        mock_conn = AsyncMock()
        request_data = json.dumps(
            {
                "call_id": "call_dict",
                "task_id": "task_d",
                "tool_name": "dict_tool",
                "arguments": {},
            }
        )

        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, request_data)
        )

        result = json.loads(mock_conn.lpush.call_args[0][1])
        assert result["error"] is None
        output = json.loads(result["output"])
        assert output["hosts"] == ["10.0.0.1"]

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_tool_execution_exception(self, mock_config):
        """Tool exceptions should be caught and returned as errors."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        def failing_tool():
            raise RuntimeError("connection refused")

        executor._tool_map["failing_tool"] = failing_tool

        mock_conn = AsyncMock()
        request_data = json.dumps(
            {
                "call_id": "call_fail",
                "task_id": "task_f",
                "tool_name": "failing_tool",
                "arguments": {},
            }
        )

        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, request_data)
        )

        result = json.loads(mock_conn.lpush.call_args[0][1])
        assert result["call_id"] == "call_fail"
        assert result["error"] is not None
        assert "connection refused" in result["error"]

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_tool_argument_type_error(self, mock_config):
        """Type errors from wrong arguments should be caught."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        def typed_tool(target: str, port: int) -> str:
            return f"{target}:{port}"

        executor._tool_map["typed_tool"] = typed_tool

        mock_conn = AsyncMock()
        # Missing required 'port' argument
        request_data = json.dumps(
            {
                "call_id": "call_type",
                "task_id": "task_t",
                "tool_name": "typed_tool",
                "arguments": {"target": "10.0.0.1"},
            }
        )

        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, request_data)
        )

        result = json.loads(mock_conn.lpush.call_args[0][1])
        assert result["error"] is not None
        assert "argument error" in result["error"].lower()

    @patch("ares.core.worker.tool_executor.get_agent_config")
    def test_async_tool_execution(self, mock_config):
        """Async tool methods should be awaited properly."""
        mock_config.side_effect = Exception("no config")

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
        )

        async def async_tool(target: str) -> str:
            return f"async result for {target}"

        executor._tool_map["async_tool"] = async_tool

        mock_conn = AsyncMock()
        request_data = json.dumps(
            {
                "call_id": "call_async",
                "task_id": "task_a",
                "tool_name": "async_tool",
                "arguments": {"target": "10.0.0.1"},
            }
        )

        asyncio.get_event_loop().run_until_complete(
            executor._handle_request(mock_conn, request_data)
        )

        result = json.loads(mock_conn.lpush.call_args[0][1])
        assert result["error"] is None
        assert result["output"] == "async result for 10.0.0.1"

    def test_stop_sets_running_flag(self):
        """stop() should set _running to False."""
        with patch("ares.core.worker.tool_executor.get_agent_config") as mock_config:
            mock_config.side_effect = Exception("no config")
            executor = ToolExecutor(
                role="recon",
                redis_url="redis://localhost:6379",
            )
            executor._running = True
            executor.stop()
            assert not executor._running

    def test_redis_key_format(self):
        """Verify Redis key format matches Rust tool_dispatcher.rs constants."""
        assert TOOL_EXEC_PREFIX == "ares:tool_exec"
        assert TOOL_RESULT_PREFIX == "ares:tool_results"

        # Queue key should be ares:tool_exec:{role}
        role = "credential_access"
        assert f"{TOOL_EXEC_PREFIX}:{role}" == "ares:tool_exec:credential_access"

        # Result key should be ares:tool_results:{call_id}
        call_id = "nmap_scan_abc123"
        assert f"{TOOL_RESULT_PREFIX}:{call_id}" == "ares:tool_results:nmap_scan_abc123"


class TestStateWriteback:
    """Tests for state writeback to Redis (operation_id + RedisStateBackend)."""

    @patch("ares.core.worker.tool_executor.get_agent_config")
    @patch.dict(
        "os.environ",
        {
            "ARES_REDIS_URL": "redis://localhost:6379",
            "ARES_WORKER_ROLE": "recon",
            "ARES_OPERATION_ID": "op-test-123",
        },
    )
    def test_main_creates_shared_state_from_env(self, mock_config):
        """When ARES_OPERATION_ID is set, main() creates SharedRedTeamState with correct operation_id."""
        mock_config.side_effect = Exception("no config")

        with (
            patch(
                "ares.core.worker.tool_executor.run_tool_executor", new_callable=AsyncMock
            ) as mock_run,
            patch("ares.core.worker.tool_executor.asyncio") as mock_asyncio,
        ):
            # Make asyncio.run call the coroutine directly
            mock_asyncio.run = MagicMock(
                side_effect=lambda coro: asyncio.get_event_loop().run_until_complete(coro)
            )

            from ares.core.worker.tool_executor import main

            main()

            # Verify run_tool_executor was called with a SharedRedTeamState
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["redis_url"] == "redis://localhost:6379"
            assert call_kwargs["role"] == "recon"
            assert isinstance(call_kwargs["shared_state"], SharedRedTeamState)
            assert call_kwargs["shared_state"].operation_id == "op-test-123"

    @patch("ares.core.worker.tool_executor.get_agent_config")
    @patch.dict(
        "os.environ",
        {"ARES_REDIS_URL": "redis://localhost:6379", "ARES_WORKER_ROLE": "recon"},
        clear=False,
    )
    def test_main_without_operation_id_tries_discovery(self, mock_config):
        """When ARES_OPERATION_ID is not set, main() tries discover_active_operation."""
        mock_config.side_effect = Exception("no config")

        # Remove ARES_OPERATION_ID if present
        import os

        os.environ.pop("ARES_OPERATION_ID", None)

        with (
            patch(
                "ares.core.worker.tool_executor.run_tool_executor", new_callable=AsyncMock
            ) as mock_run,
            patch(
                "ares.core.worker.operations.discover_active_operation", new_callable=AsyncMock
            ) as mock_discover,
        ):
            mock_discover.return_value = "op-discovered-456"

            from ares.core.worker.tool_executor import main

            main()

            # Should have attempted discovery
            mock_discover.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert isinstance(call_kwargs["shared_state"], SharedRedTeamState)
            assert call_kwargs["shared_state"].operation_id == "op-discovered-456"

    @pytest.mark.asyncio
    @patch("ares.core.worker.tool_executor.get_agent_config")
    @patch("ares.core.worker.tool_executor.RedisStateBackend")
    async def test_run_tool_executor_wires_backend(self, mock_backend_cls, mock_config):
        """run_tool_executor() calls set_backend when shared_state has operation_id."""
        mock_config.side_effect = Exception("no config")

        state = SharedRedTeamState(operation_id="op-wire-789")

        mock_backend_instance = MagicMock()
        mock_backend_cls.return_value = mock_backend_instance

        # Mock all backend getters used by _load_state_from_backend
        mock_backend_instance.get_credentials = AsyncMock(return_value=[])
        mock_backend_instance.get_hashes = AsyncMock(return_value=[])
        mock_backend_instance.get_hosts = AsyncMock(return_value=[])
        mock_backend_instance.get_users = AsyncMock(return_value=[])
        mock_backend_instance.get_shares = AsyncMock(return_value=[])
        mock_backend_instance.get_domains = AsyncMock(return_value=[])
        mock_backend_instance.get_vulnerabilities = AsyncMock(return_value={})
        mock_backend_instance.get_all_dcs = AsyncMock(return_value={})
        mock_backend_instance.get_all_netbios_mappings = AsyncMock(return_value={})
        mock_backend_instance.get_domain_admin = AsyncMock(return_value=(False, None, None))

        with patch("ares.core.worker.tool_executor.aioredis") as mock_aioredis:
            mock_aioredis.from_url.return_value = MagicMock()

            # Patch ToolExecutor.run to exit immediately instead of looping
            with (
                patch.object(ToolExecutor, "run", new_callable=AsyncMock),
                patch("asyncio.get_event_loop") as mock_loop,
            ):
                mock_loop.return_value.add_signal_handler = MagicMock()
                await run_tool_executor(
                    redis_url="redis://localhost:6379",
                    role="recon",
                    shared_state=state,
                )

        # Verify RedisStateBackend was created with correct params
        mock_backend_cls.assert_called_once()
        call_args = mock_backend_cls.call_args
        assert call_args[0][1] == "op-wire-789"  # operation_id

        # Verify set_backend was called (state._backend should be set)
        assert state._backend is mock_backend_instance

    @pytest.mark.asyncio
    @patch("ares.core.worker.tool_executor.get_agent_config")
    @patch("ares.core.worker.tool_executor.RedisStateBackend")
    async def test_run_tool_executor_no_backend_without_operation_id(
        self, mock_backend_cls, mock_config
    ):
        """run_tool_executor() does NOT wire backend when shared_state is None."""
        mock_config.side_effect = Exception("no config")

        with (
            patch.object(ToolExecutor, "run", new_callable=AsyncMock),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            mock_loop.return_value.add_signal_handler = MagicMock()
            await run_tool_executor(
                redis_url="redis://localhost:6379",
                role="recon",
                shared_state=None,
            )

        # Should NOT have created a backend
        mock_backend_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_load_state_from_backend_populates_state(self):
        """_load_state_from_backend should hydrate state from backend getters."""
        from ares.core.models import Credential, Host

        state = SharedRedTeamState(operation_id="op-load-test")

        mock_cred = MagicMock(spec=Credential)
        mock_host = MagicMock(spec=Host)

        backend = MagicMock()
        backend.get_credentials = AsyncMock(return_value=[mock_cred])
        backend.get_hashes = AsyncMock(return_value=[])
        backend.get_hosts = AsyncMock(return_value=[mock_host])
        backend.get_users = AsyncMock(return_value=[])
        backend.get_shares = AsyncMock(return_value=[])
        backend.get_domains = AsyncMock(return_value=["contoso.local"])
        backend.get_vulnerabilities = AsyncMock(return_value={})
        backend.get_all_dcs = AsyncMock(return_value={"contoso.local": "192.168.58.10"})
        backend.get_all_netbios_mappings = AsyncMock(return_value={})
        backend.get_domain_admin = AsyncMock(return_value=(False, None, None))

        await _load_state_from_backend(state, backend)

        assert len(state.all_credentials) == 1
        assert state.all_credentials[0] is mock_cred
        assert len(state.all_hosts) == 1
        assert state.all_hosts[0] is mock_host
        assert "contoso.local" in state.all_domains
        assert state.domain_controllers["contoso.local"] == "192.168.58.10"
        assert state.has_domain_admin is False

    @pytest.mark.asyncio
    async def test_load_state_from_backend_handles_errors(self):
        """_load_state_from_backend should not raise on backend errors."""
        state = SharedRedTeamState(operation_id="op-err-test")

        backend = MagicMock()
        backend.get_credentials = AsyncMock(side_effect=Exception("Redis down"))

        # Should not raise
        await _load_state_from_backend(state, backend)

        # State should remain empty
        assert len(state.all_credentials) == 0

    @pytest.mark.asyncio
    @patch("ares.core.worker.tool_executor.get_agent_config")
    async def test_tool_mutation_triggers_backend_persistence(self, mock_config):
        """When a tool calls state.add_credential(), the backend persists it."""
        mock_config.side_effect = Exception("no config")

        state = SharedRedTeamState(operation_id="op-persist-test")

        # Use AsyncMock as the backend so all method calls return coroutines.
        # add_credential, add_domain, add_user, etc. all persist via
        # loop.create_task(backend.method()), which requires coroutines.
        mock_backend = AsyncMock()
        mock_backend.add_credential.return_value = True
        mock_backend.add_domain.return_value = True
        mock_backend.add_user.return_value = True
        state.set_backend(mock_backend)

        executor = ToolExecutor(
            role="recon",
            redis_url="redis://localhost:6379",
            shared_state=state,
        )

        # Inject a tool that adds a credential via state
        from ares.core.models import Credential

        def discover_cred_tool():
            cred = Credential(
                username="admin",
                password="P@ssw0rd",
                domain="contoso.local",
                source="test",
            )
            state.add_credential(cred, source_agent="recon")
            return "found credential"

        executor._tool_map["discover_cred"] = discover_cred_tool

        mock_conn = AsyncMock()
        request_data = json.dumps(
            {
                "call_id": "call_cred",
                "task_id": "task_cred",
                "tool_name": "discover_cred",
                "arguments": {},
            }
        )

        await executor._handle_request(mock_conn, request_data)

        # Allow background tasks created by add_credential to complete
        await asyncio.sleep(0)

        # Verify the tool executed successfully
        result = json.loads(mock_conn.lpush.call_args[0][1])
        assert result["error"] is None
        assert result["output"] == "found credential"

        # Verify the credential was added to in-memory state
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].username == "admin"

        # Verify backend persistence was triggered
        mock_backend.add_credential.assert_called_once()
