"""Tests for orchestrator module."""

from __future__ import annotations

import asyncio
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.models import SharedRedTeamState, Target, TaskInfo
from ares.core.orchestrator import run_multi_agent_operation


@pytest.mark.asyncio
async def test_run_multi_agent_operation_requires_model(monkeypatch):
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_MODEL", raising=False)

    with pytest.raises(ValueError, match="No model specified"):
        await run_multi_agent_operation(
            operation_id="op-1",
            target_domain="contoso.local",
            target_ips=["192.168.58.1"],
        )


@pytest.mark.asyncio
async def test_run_multi_agent_operation_skips_wait_when_completed(monkeypatch):
    from ares.core.orchestrator import _orchestrator as orch

    shared_state = SimpleNamespace(
        completed=False,
        has_domain_admin=False,
        domain_admin_path=None,
        has_golden_ticket=False,
        all_credentials=[],
        all_hashes=[],
        all_hosts=[],
        discovered_vulnerabilities=[],
        exploited_vulnerabilities=[],
        completed_tasks=[],
        pending_tasks={},
    )

    dispatcher = SimpleNamespace(shared_state=shared_state)
    dispatcher.start = AsyncMock()
    dispatcher.recover_state = AsyncMock(return_value=None)
    dispatcher.register = AsyncMock()
    dispatcher.stop = AsyncMock()
    dispatcher.get_exploitation_status = AsyncMock(
        return_value={"pending": [], "total_discovered": 0, "total_succeeded": 0}
    )

    task_queue = SimpleNamespace()
    task_queue.connect = AsyncMock()
    task_queue.acquire_operation_lock = AsyncMock(return_value=True)
    task_queue.release_operation_lock = AsyncMock()
    task_queue.disconnect = AsyncMock()

    recovery = SimpleNamespace()
    recovery.start = AsyncMock()
    recovery.start_periodic_checkpoint = AsyncMock()

    class DummyAgent:
        async def run(self, _prompt):
            dispatcher.shared_state.completed = True
            return SimpleNamespace(stop_reason="completed")

    monkeypatch.setattr(orch, "RedTeamDispatcher", lambda **_kwargs: dispatcher)
    monkeypatch.setattr(orch, "RedisTaskQueue", lambda *_args, **_kwargs: task_queue)
    monkeypatch.setattr(orch, "OperationRecoveryManager", lambda **_kwargs: recovery)
    monkeypatch.setattr(orch, "get_redis_url", lambda: "redis://")
    monkeypatch.setattr(orch, "get_namespace", lambda: "default")
    monkeypatch.setattr(orch, "_load_or_initialize_state", AsyncMock())
    monkeypatch.setattr(orch, "_create_agent_ensemble", AsyncMock(return_value=[]))
    monkeypatch.setattr(orch, "_register_agents", AsyncMock())
    monkeypatch.setattr(orch, "_ensure_required_workers", AsyncMock())
    monkeypatch.setattr(orch, "_prime_operation", AsyncMock())
    monkeypatch.setattr(orch, "_create_orchestrator_agent", AsyncMock(return_value=DummyAgent()))
    monkeypatch.setattr(orch, "_build_orchestrator_prompt", lambda **_kwargs: "prompt")
    monkeypatch.setattr(orch, "_log_orchestrator_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        orch, "_generate_multi_agent_report", lambda *_args, **_kwargs: (None, None)
    )

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orch, "exploitation_workflow", _noop)
    monkeypatch.setattr(orch, "_monitor_agent_health", _noop)
    monkeypatch.setattr(orch, "_extend_operation_lock", _noop)

    wait_mock = AsyncMock()
    monkeypatch.setattr(orch, "_wait_for_completion", wait_mock)

    monkeypatch.setattr(orch.dn, "run", lambda **_kwargs: nullcontext())
    monkeypatch.setattr(orch.dn, "log_params", MagicMock())

    await run_multi_agent_operation(
        operation_id="op-2",
        target_domain="contoso.local",
        target_ips=["192.168.58.2"],
        model="test-model",
    )

    wait_mock.assert_not_awaited()


class TestAutoBloodHound:
    """Tests for automatic BloodHound collection."""

    @pytest.mark.asyncio
    async def test_auto_bloodhound_dispatches_on_credentials(self, monkeypatch):
        """Test that BloodHound collection is dispatched when credentials are discovered."""
        from ares.core.models import Credential
        from ares.core.orchestrator import _auto_bloodhound

        # Setup mock dispatcher
        state = SharedRedTeamState(
            operation_id="op-bloodhound",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        # Add a credential
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                domain="contoso.local",
                source="test",
            )
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.request_recon = AsyncMock(return_value="task-123")

        # Run auto_bloodhound for one cycle
        task = asyncio.create_task(_auto_bloodhound(dispatcher, check_interval=0.1))

        # Let it run one iteration
        await asyncio.sleep(0.2)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched BloodHound task
        dispatcher.request_recon.assert_called_once()
        call_kwargs = dispatcher.request_recon.call_args.kwargs
        assert "bloodhound" in call_kwargs.get("reason", "")
        assert "bloodhound" in call_kwargs.get("techniques", [])

    @pytest.mark.asyncio
    async def test_auto_bloodhound_skips_when_no_credentials(self, monkeypatch):
        """Test that BloodHound is not dispatched without credentials."""
        from ares.core.orchestrator import _auto_bloodhound

        state = SharedRedTeamState(
            operation_id="op-no-creds",
            target=Target(ip="192.168.58.11", domain="contoso.local"),
        )
        # No credentials

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.request_recon = AsyncMock(return_value="task-123")

        task = asyncio.create_task(_auto_bloodhound(dispatcher, check_interval=0.1))

        await asyncio.sleep(0.2)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should NOT have dispatched
        dispatcher.request_recon.assert_not_called()

    @pytest.mark.asyncio
    async def test_auto_bloodhound_stops_when_complete(self):
        """Test that BloodHound automation stops when operation is complete."""
        from ares.core.models import Credential
        from ares.core.orchestrator import _auto_bloodhound

        state = SharedRedTeamState(
            operation_id="op-complete",
            target=Target(ip="192.168.58.12", domain="contoso.local"),
        )
        state.completed = True
        state.all_credentials.append(
            Credential(
                username="user",
                password="pass",  # pragma: allowlist secret
                domain="contoso.local",
                source="test",
            )  # pragma: allowlist secret
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.request_recon = AsyncMock(return_value="task-123")

        # Should exit immediately when completed=True
        await _auto_bloodhound(dispatcher, check_interval=0.1)

        # Should NOT dispatch when completed
        dispatcher.request_recon.assert_not_called()


class TestAutoCoercion:
    """Tests for automatic coercion attacks."""

    @pytest.mark.asyncio
    async def test_auto_coercion_esc8_when_adcs_found(self):
        """Test that ESC8 coercion is dispatched when ADCS server is detected."""
        from ares.core.models import Credential, Host
        from ares.core.orchestrator import _auto_coercion

        state = SharedRedTeamState(
            operation_id="op-esc8",
            target=Target(ip="192.168.58.13", domain="contoso.local"),
        )
        # Add a credential to enable coercion
        state.all_credentials.append(
            Credential(
                username="user",
                password="pass",  # pragma: allowlist secret
                domain="contoso.local",
                source="test",
            )  # pragma: allowlist secret
        )
        # Add DC host
        dc_host = Host(ip="192.168.58.14", hostname="DC01", roles=["DC"])
        state.all_hosts.append(dc_host)

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.request_coercion = AsyncMock(return_value="task-456")
        # Mock find_adcs_servers to return an ADCS server
        dispatcher.find_adcs_servers = MagicMock(return_value=[("192.168.58.15", "ADCS01")])

        task = asyncio.create_task(_auto_coercion(dispatcher, check_interval=0.1))

        await asyncio.sleep(0.2)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched ESC8 coercion (may dispatch LDAPS relay too)
        assert dispatcher.request_coercion.call_count >= 1
        # Check the first call was ESC8
        first_call_kwargs = dispatcher.request_coercion.call_args_list[0].kwargs
        payload = first_call_kwargs.get("payload_override", {})
        assert payload.get("attack_type") == "esc8"
        assert "192.168.58.15" in payload.get("adcs_server", "")

    @pytest.mark.asyncio
    async def test_auto_coercion_ldaps_relay_to_dc(self):
        """Test that LDAPS relay coercion is dispatched to DCs."""
        from ares.core.models import Credential, Host
        from ares.core.orchestrator import _auto_coercion

        state = SharedRedTeamState(
            operation_id="op-ldaps",
            target=Target(ip="192.168.58.16", domain="contoso.local"),
        )
        state.all_credentials.append(
            Credential(
                username="user",
                password="pass",  # pragma: allowlist secret
                domain="contoso.local",
                source="test",
            )  # pragma: allowlist secret
        )
        # Add DC
        dc_host = Host(ip="192.168.58.17", hostname="DC02", roles=["Domain Controller"])
        state.all_hosts.append(dc_host)

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.request_coercion = AsyncMock(return_value="task-789")
        dispatcher.find_adcs_servers = MagicMock(return_value=[])  # No ADCS

        task = asyncio.create_task(_auto_coercion(dispatcher, check_interval=0.01))

        # Give it time to complete at least one cycle
        await asyncio.sleep(0.1)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched LDAPS relay coercion
        assert dispatcher.request_coercion.call_count >= 1
        call_kwargs = dispatcher.request_coercion.call_args.kwargs
        payload = call_kwargs.get("payload_override", {})
        assert payload.get("attack_type") == "ldaps_relay"

    @pytest.mark.asyncio
    async def test_auto_coercion_waits_for_credentials(self):
        """Test that coercion waits for credentials before starting."""
        from ares.core.models import Host
        from ares.core.orchestrator import _auto_coercion

        state = SharedRedTeamState(
            operation_id="op-wait",
            target=Target(ip="192.168.58.18", domain="contoso.local"),
        )
        # No credentials yet
        dc_host = Host(ip="192.168.58.19", hostname="DC03", roles=["DC"])
        state.all_hosts.append(dc_host)

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.request_coercion = AsyncMock(return_value="task-999")
        dispatcher.find_adcs_servers = MagicMock(return_value=[])

        task = asyncio.create_task(_auto_coercion(dispatcher, check_interval=0.1))

        await asyncio.sleep(0.2)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should NOT have dispatched without credentials
        dispatcher.request_coercion.assert_not_called()


class TestWaitForCrackTasks:
    """Tests for crack task grace period."""

    @pytest.mark.asyncio
    async def test_wait_for_crack_tasks_waits_until_complete(self):
        """Test that _wait_for_crack_tasks waits for running crack tasks to complete."""
        from ares.core.models import TaskInfo, TaskStatus
        from ares.core.orchestrator import _wait_for_crack_tasks

        state = SharedRedTeamState(operation_id="op-crack")
        # Add a running crack task
        crack_task = TaskInfo(
            task_id="crack-001",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.IN_PROGRESS,
        )
        state.pending_tasks["crack-001"] = crack_task

        dispatcher = SimpleNamespace(shared_state=state)

        # Start wait in background
        wait_task = asyncio.create_task(_wait_for_crack_tasks(dispatcher, timeout=5.0))

        # Wait a bit, then mark task complete
        await asyncio.sleep(0.1)
        state.pending_tasks.pop("crack-001")  # Simulate completion

        # Should complete without timeout
        await wait_task

    @pytest.mark.asyncio
    async def test_wait_for_crack_tasks_times_out(self):
        """Test that _wait_for_crack_tasks respects timeout."""
        from ares.core.models import TaskInfo, TaskStatus
        from ares.core.orchestrator import _wait_for_crack_tasks

        state = SharedRedTeamState(operation_id="op-crack-timeout")
        # Add a crack task that won't complete
        crack_task = TaskInfo(
            task_id="crack-002",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.IN_PROGRESS,
        )
        state.pending_tasks["crack-002"] = crack_task

        dispatcher = SimpleNamespace(shared_state=state)

        # Should timeout after 0.5 seconds
        await _wait_for_crack_tasks(dispatcher, timeout=0.5, check_interval=0.1)

        # Task should still be in pending (not removed)
        assert "crack-002" in state.pending_tasks

    @pytest.mark.asyncio
    async def test_wait_for_crack_tasks_returns_immediately_when_none(self):
        """Test that _wait_for_crack_tasks returns immediately when no crack tasks."""
        from ares.core.orchestrator import _wait_for_crack_tasks

        state = SharedRedTeamState(operation_id="op-no-crack")
        dispatcher = SimpleNamespace(shared_state=state)

        # Should return immediately
        await _wait_for_crack_tasks(dispatcher, timeout=5.0)


class TestAutoDelegationEnumeration:
    """Tests for _auto_delegation_enumeration background task."""

    @pytest.mark.asyncio
    async def test_auto_delegation_dispatches_on_credentials(self):
        """_auto_delegation_enumeration should dispatch find_delegation when credentials discovered."""
        from ares.core.models import Credential
        from ares.core.orchestrator import _auto_delegation_enumeration

        dispatcher = SimpleNamespace()
        dispatcher.shared_state = SharedRedTeamState(operation_id="op-test-delegation-1")
        dispatcher.shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Add a credential with password
        dispatcher.shared_state.all_credentials.append(
            Credential(
                username="testuser",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
            )
        )

        # Mock request_privesc_enumeration - also register in pending_tasks so
        # the retry logic doesn't treat the task as "lost"
        async def _mock_request(*args, **kwargs):
            task_id = "task-delegation-1"
            dispatcher.shared_state.pending_tasks[task_id] = TaskInfo(
                task_id=task_id, task_type="find_delegation", assigned_agent="privesc"
            )
            return task_id

        dispatcher.request_privesc_enumeration = AsyncMock(side_effect=_mock_request)

        # Run one iteration with short interval
        task = asyncio.create_task(_auto_delegation_enumeration(dispatcher, check_interval=0.01))

        # Wait briefly for task to process
        await asyncio.sleep(0.05)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched delegation enumeration
        dispatcher.request_privesc_enumeration.assert_awaited_once()
        call_kwargs = dispatcher.request_privesc_enumeration.call_args.kwargs
        assert call_kwargs["domain"] == "contoso.local"
        assert call_kwargs["username"] == "testuser"
        assert call_kwargs["password"] == "P@ssw0rd!"  # pragma: allowlist secret
        assert call_kwargs["techniques"] == ["find_delegation"]

    @pytest.mark.asyncio
    async def test_auto_delegation_waits_for_credentials(self):
        """_auto_delegation_enumeration should wait until credentials exist."""
        from ares.core.orchestrator import _auto_delegation_enumeration

        dispatcher = SimpleNamespace()
        dispatcher.shared_state = SharedRedTeamState(operation_id="op-test-delegation-2")
        dispatcher.request_privesc_enumeration = AsyncMock()

        # Run one iteration with no credentials
        task = asyncio.create_task(_auto_delegation_enumeration(dispatcher, check_interval=0.01))

        await asyncio.sleep(0.05)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should not have dispatched anything
        dispatcher.request_privesc_enumeration.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_auto_delegation_processes_credential_only_once(self):
        """_auto_delegation_enumeration should not re-process same credential."""
        from ares.core.models import Credential
        from ares.core.orchestrator import _auto_delegation_enumeration

        dispatcher = SimpleNamespace()
        dispatcher.shared_state = SharedRedTeamState(operation_id="op-test-delegation-3")
        dispatcher.shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Add a credential
        dispatcher.shared_state.all_credentials.append(
            Credential(
                username="testuser",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
            )
        )

        # Mock request_privesc_enumeration - register in pending_tasks so
        # the retry logic doesn't treat the task as "lost"
        async def _mock_request(*args, **kwargs):
            task_id = "task-delegation-1"
            dispatcher.shared_state.pending_tasks[task_id] = TaskInfo(
                task_id=task_id, task_type="find_delegation", assigned_agent="privesc"
            )
            return task_id

        dispatcher.request_privesc_enumeration = AsyncMock(side_effect=_mock_request)

        # Run multiple iterations
        task = asyncio.create_task(_auto_delegation_enumeration(dispatcher, check_interval=0.01))

        await asyncio.sleep(0.1)  # Let multiple iterations run
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should only have dispatched once (not on every iteration)
        assert dispatcher.request_privesc_enumeration.await_count == 1

    @pytest.mark.asyncio
    async def test_auto_delegation_stops_when_complete(self):
        """_auto_delegation_enumeration should stop when operation completes."""
        from ares.core.orchestrator import _auto_delegation_enumeration

        dispatcher = SimpleNamespace()
        dispatcher.shared_state = SharedRedTeamState(operation_id="op-test-delegation-4")
        dispatcher.shared_state.completed = True  # Mark as complete

        # Should exit immediately
        await _auto_delegation_enumeration(dispatcher, check_interval=0.01)

        # No assertions needed - test is that it doesn't hang


class TestHashCrackingPriority:
    """Tests for priority-based hash cracking."""

    @pytest.mark.asyncio
    async def test_kerberoast_hash_gets_high_priority(self):
        """Kerberoast hashes should get priority 2 (high)."""
        from ares.core.dispatcher import RedTeamDispatcher
        from ares.core.models import Hash, Host
        from ares.core.orchestrator import _auto_credential_access

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-priority-1")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Add at least 1 host (required by _auto_credential_access)
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.10", hostname="dc01", roles=["DC"])
        )

        # Add Kerberoast hash
        dispatcher._shared_state.all_hashes.append(
            Hash(
                username="svc_sql",
                hash_value="$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$...",
                hash_type="Kerberoast",
                domain="contoso.local",
            )
        )

        dispatcher.request_crack = AsyncMock(return_value="task-crack-1")
        dispatcher.request_credential_access = AsyncMock(return_value="task-cred-1")

        # Run one iteration
        task = asyncio.create_task(_auto_credential_access(dispatcher, check_interval=0.01))

        await asyncio.sleep(0.05)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched crack with priority=2
        dispatcher.request_crack.assert_awaited_once()
        call_kwargs = dispatcher.request_crack.call_args.kwargs
        assert call_kwargs["priority"] == 2

    @pytest.mark.asyncio
    async def test_asrep_hash_gets_medium_priority(self):
        """AS-REP hashes should get priority 3 (medium-high)."""
        from ares.core.dispatcher import RedTeamDispatcher
        from ares.core.models import Hash, Host
        from ares.core.orchestrator import _auto_credential_access

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-priority-2")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Add at least 1 host
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.10", hostname="dc01", roles=["DC"])
        )

        # Add AS-REP hash
        dispatcher._shared_state.all_hashes.append(
            Hash(
                username="user_no_preauth",
                hash_value="$krb5asrep$23$user_no_preauth@CONTOSO.LOCAL:...",
                hash_type="ASREP",
                domain="contoso.local",
            )
        )

        dispatcher.request_crack = AsyncMock(return_value="task-crack-2")
        dispatcher.request_credential_access = AsyncMock(return_value="task-cred-2")

        task = asyncio.create_task(_auto_credential_access(dispatcher, check_interval=0.01))

        await asyncio.sleep(0.05)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched crack with priority=3
        dispatcher.request_crack.assert_awaited_once()
        call_kwargs = dispatcher.request_crack.call_args.kwargs
        assert call_kwargs["priority"] == 3

    @pytest.mark.asyncio
    async def test_normal_hash_gets_default_priority(self):
        """Normal hashes (NTLM, etc.) should get default priority 5."""
        from ares.core.dispatcher import RedTeamDispatcher
        from ares.core.models import Hash, Host
        from ares.core.orchestrator import _auto_credential_access

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-priority-3")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Add at least 1 host
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.10", hostname="dc01", roles=["DC"])
        )

        # Add normal NTLM hash
        dispatcher._shared_state.all_hashes.append(
            Hash(
                username="testuser",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="NTLM",
                domain="contoso.local",
            )
        )

        dispatcher.request_crack = AsyncMock(return_value="task-crack-3")
        dispatcher.request_credential_access = AsyncMock(return_value="task-cred-3")

        task = asyncio.create_task(_auto_credential_access(dispatcher, check_interval=0.01))

        await asyncio.sleep(0.05)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have dispatched crack with default priority=5
        dispatcher.request_crack.assert_awaited_once()
        call_kwargs = dispatcher.request_crack.call_args.kwargs
        assert call_kwargs["priority"] == 5
