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
        processed_asrep_domains=set(),  # For immediate AS-REP dispatch
        golden_tickets=[],  # For _wait_for_golden_ticket
        refresh_from_redis=AsyncMock(),  # For final state refresh
    )

    dispatcher = SimpleNamespace(shared_state=shared_state)
    dispatcher.request_credential_access = AsyncMock(return_value="task-123")
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
    monkeypatch.setattr(orch, "_run_direct_nmap", AsyncMock())
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
        # Check that a bloodhound-related technique was dispatched
        techniques = call_kwargs.get("techniques", [])
        assert any("bloodhound" in t.lower() for t in techniques)

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


class TestAutoGoldenTicket:
    """Tests for _auto_golden_ticket background task."""

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_uses_password_credential(self):
        """Test that _auto_golden_ticket prefers password credential for lookupsid."""
        from unittest.mock import patch

        from ares.core.models import Credential, Hash
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-password",
            target=Target(ip="192.168.58.20", domain="contoso.local"),
        )
        # Add krbtgt hash
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )
        # Add password credential
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
            )
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.21")
        dispatcher._task_queue = None  # Disable Redis sync for test

        # Mock run_tool to capture the command
        captured_cmds = []

        def mock_run_tool(cmd, timeout_seconds=60):
            captured_cmds.append(cmd)
            # Return lookupsid-like output with SID
            return ("Domain SID is: S-1-5-21-1234567890-1234567890-1234567890", "", 0)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should have used password credential, not hash
        assert len(captured_cmds) >= 1
        lookupsid_cmd = captured_cmds[0]
        assert "impacket-lookupsid" in lookupsid_cmd[0]
        # Password auth format: domain/user:password@target
        assert "testuser:TestPass123!" in lookupsid_cmd[1]
        assert "-hashes" not in lookupsid_cmd

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_falls_back_to_pth(self):
        """Test that _auto_golden_ticket uses PTH when no password credential available."""
        from unittest.mock import patch

        from ares.core.models import Hash
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-pth",
            target=Target(ip="192.168.58.22", domain="contoso.local"),
        )
        # Add krbtgt hash
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )
        # Add user hash (for PTH) - no password credentials
        state.all_hashes.append(
            Hash(
                username="admin",
                hash_value="aabbccdd11223344aabbccdd11223344",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.23")
        dispatcher._task_queue = None  # Disable Redis sync for test

        captured_cmds = []

        def mock_run_tool(cmd, timeout_seconds=60):
            captured_cmds.append(cmd)
            return ("Domain SID is: S-1-5-21-1234567890-1234567890-1234567890", "", 0)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should have used PTH with -hashes flag
        assert len(captured_cmds) >= 1
        lookupsid_cmd = captured_cmds[0]
        assert "impacket-lookupsid" in lookupsid_cmd[0]
        assert "-hashes" in lookupsid_cmd
        # Should use the admin hash, not krbtgt
        hashes_idx = lookupsid_cmd.index("-hashes")
        assert ":aabbccdd11223344" in lookupsid_cmd[hashes_idx + 1]

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_pth_extracts_nt_from_lm_nt(self):
        """Test that PTH correctly extracts NT hash from LM:NT format."""
        from unittest.mock import patch

        from ares.core.models import Hash
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-lmnt",
            target=Target(ip="192.168.58.24", domain="contoso.local"),
        )
        # Add krbtgt hash
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )
        # Add user hash with LM:NT format
        state.all_hashes.append(
            Hash(
                username="svc_backup",
                hash_value="deadbeef00001111:cafebabe22223333",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.25")
        dispatcher._task_queue = None  # Disable Redis sync for test

        captured_cmds = []

        def mock_run_tool(cmd, timeout_seconds=60):
            captured_cmds.append(cmd)
            return ("Domain SID is: S-1-5-21-1234567890-1234567890-1234567890", "", 0)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should have extracted NT hash (after colon)
        assert len(captured_cmds) >= 1
        lookupsid_cmd = captured_cmds[0]
        hashes_idx = lookupsid_cmd.index("-hashes")
        # Should use :NTHASH format (empty LM, just NT)
        assert ":cafebabe22223333" in lookupsid_cmd[hashes_idx + 1]

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_skips_krbtgt_for_pth(self):
        """Test that PTH does not use krbtgt hash for authentication."""
        from unittest.mock import patch

        from ares.core.models import Hash
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-skip-krbtgt",
            target=Target(ip="192.168.58.26", domain="contoso.local"),
        )
        # Add only krbtgt hash - no user hashes
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.27")
        dispatcher._task_queue = None  # Disable Redis sync for test

        captured_cmds = []

        def mock_run_tool(cmd, timeout_seconds=60):
            captured_cmds.append(cmd)
            return ("Domain SID is: S-1-5-21-1234567890-1234567890-1234567890", "", 0)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should NOT have run lookupsid - no valid credential available
        assert len(captured_cmds) == 0

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_prefers_same_domain_hash(self):
        """Test that PTH prefers hash from same domain as krbtgt."""
        from unittest.mock import patch

        from ares.core.models import Hash
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-same-domain",
            target=Target(ip="192.168.58.28", domain="contoso.local"),
        )
        # Add krbtgt hash for contoso.local
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )
        # Add hash from different domain (added first)
        state.all_hashes.append(
            Hash(
                username="other_user",
                hash_value="aaaa11112222bbbb",
                hash_type="ntlm",
                domain="fabrikam.local",
                source="secretsdump",
            )
        )
        # Add hash from same domain (added second)
        state.all_hashes.append(
            Hash(
                username="same_domain_user",
                hash_value="cccc33334444dddd",
                hash_type="ntlm",
                domain="contoso.local",
                source="secretsdump",
            )
        )

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.29")
        dispatcher._task_queue = None  # Disable Redis sync for test

        captured_cmds = []

        def mock_run_tool(cmd, timeout_seconds=60):
            captured_cmds.append(cmd)
            return ("Domain SID is: S-1-5-21-1234567890-1234567890-1234567890", "", 0)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should have used same_domain_user (contoso.local), not other_user (fabrikam.local)
        assert len(captured_cmds) >= 1
        lookupsid_cmd = captured_cmds[0]
        assert "same_domain_user" in lookupsid_cmd[1]
        assert ":cccc33334444dddd" in lookupsid_cmd[3]

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_child_domain_validates_parent_dc(self):
        """Test that child domain golden ticket correctly validates parent DC.

        Bug fix test: When cached DC IP belongs to a child DC (e.g., ws01.child.parent.local)
        but is incorrectly mapped to parent domain, the code should reject it and find the correct
        parent DC instead.
        """
        from unittest.mock import patch

        from ares.core.models import Credential, Hash, Host
        from ares.core.orchestrator import _auto_golden_ticket

        # Child domain: child.contoso.local, Parent domain: contoso.local
        state = SharedRedTeamState(
            operation_id="op-gt-child-parent",
            target=Target(ip="192.168.58.10", domain="child.contoso.local"),
        )

        # Add krbtgt hash for CHILD domain (triggers ExtraSid golden ticket)
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:childkrbtgthash1234567890123456",
                hash_type="ntlm",
                domain="child.contoso.local",
                source="secretsdump",
            )
        )

        # Add password credential for authentication
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123!",  # pragma: allowlist secret
                domain="child.contoso.local",
                source="manual",
            )
        )

        # Add CHILD DC host (this is the WRONG DC for parent domain DCSync)
        child_dc = Host(
            ip="192.168.58.121",  # Child DC IP
            hostname="ws01.child.contoso.local",  # Child DC hostname
            is_dc=True,
        )
        state.all_hosts.append(child_dc)

        # Add PARENT DC host (this is the CORRECT DC for parent domain DCSync)
        parent_dc = Host(
            ip="192.168.58.238",  # Parent DC IP
            hostname="dc01.contoso.local",  # Parent DC hostname
            is_dc=True,
        )
        state.all_hosts.append(parent_dc)

        # BUG SCENARIO: Cache has WRONG mapping - child DC IP mapped to parent domain
        state.domain_controllers["contoso.local"] = "192.168.58.121"  # WRONG!

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.10")
        dispatcher._task_queue = None  # Disable Redis sync for test
        dispatcher.announce_golden_ticket = AsyncMock()
        dispatcher._auto_dispatch_trust_key_extraction = AsyncMock()

        captured_cmds = []
        captured_dc_ips = []

        def mock_run_tool(cmd, timeout_seconds=60):
            captured_cmds.append(cmd)
            # Extract the target IP from the command (last argument for lookupsid)
            if "impacket-lookupsid" in str(cmd):
                # Format: impacket-lookupsid 'domain/user:pass@TARGET_IP'
                for arg in cmd:
                    if "@" in arg:
                        target_ip = arg.split("@")[-1]
                        captured_dc_ips.append(target_ip)
            return ("Domain SID is: S-1-5-21-1234567890-1234567890-1234567890", "", 0)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # The fix should have:
        # 1. Detected child domain (child.contoso.local has 3 parts)
        # 2. Determined parent domain (contoso.local)
        # 3. Checked cached DC (192.168.58.121) but REJECTED it because hostname
        #    ws01.child.contoso.local ends with child domain, not parent
        # 4. Found correct parent DC via host enumeration (192.168.58.238)
        # 5. Used parent DC IP for lookupsid (to get parent domain SID for ExtraSid)

        # Verify at least one command was captured
        assert len(captured_cmds) >= 1, "No commands were captured"

        # First lookupsid should target the child DC (for child domain SID)
        # Then parent DC should be used for parent domain operations
        # The key is that we should NOT see lookupsid against the wrong DC
        # for the parent domain DCSync

        # Check that parent DC IP was resolved correctly by verifying logs or
        # by checking that the parent SID lookup used the correct IP
        # For this test, we verify the logic by checking captured IPs include parent DC
        if len(captured_dc_ips) >= 2:
            # Second lookup should be against parent DC for ExtraSid
            assert "192.168.58.238" in captured_dc_ips, (
                f"Parent DC IP 192.168.58.238 not found in captured IPs: {captured_dc_ips}. "
                f"Fix may not be working - check that cached child DC IP was rejected."
            )

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_child_domain_uses_trust_key_referral(self):
        """Test that child→parent escalation uses referral routing, not direct DCSync.

        The ExtraSid golden ticket can't DCSync the parent domain directly because
        Impacket's cross-realm referral following is broken in all versions
        (fortra/impacket#315). The fix monkey-patches sendReceive() to route
        referral TGS requests to the correct parent DC. Step 1 extracts the trust
        key from the child domain, Step 2 re-forges the golden ticket and uses
        referral routing to DCSync the parent.

        Expected command sequence:
        1. lookupsid (child domain SID)
        2. lookupsid (parent domain SID for ExtraSid)
        3. ticketer (golden ticket with ExtraSid) + secretsdump (child for trust key)
        4. ticketer (golden ticket again) + python3 -c (referral-routed parent DCSync)
        """
        from unittest.mock import patch

        from ares.core.models import Credential, Hash, Host
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-trust-key",
            target=Target(ip="192.168.58.10", domain="child.contoso.local"),
        )

        # krbtgt hash for child domain (triggers ExtraSid golden ticket path)
        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:childkrbtgthash1234567890123456",
                hash_type="ntlm",
                domain="child.contoso.local",
                source="secretsdump",
            )
        )

        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123!",  # pragma: allowlist secret
                domain="child.contoso.local",
                source="manual",
            )
        )

        # Child DC
        state.all_hosts.append(
            Host(
                ip="192.168.58.121",
                hostname="ws01.child.contoso.local",
                is_dc=True,
            )
        )
        # Parent DC
        state.all_hosts.append(
            Host(
                ip="192.168.58.238",
                hostname="dc01.contoso.local",
                is_dc=True,
            )
        )

        state.domain_controllers["child.contoso.local"] = "192.168.58.121"
        state.domain_controllers["contoso.local"] = "192.168.58.238"

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.121")
        dispatcher._task_queue = None
        dispatcher.announce_golden_ticket = AsyncMock()
        dispatcher._auto_dispatch_trust_key_extraction = AsyncMock()

        captured_cmds = []

        def mock_run_tool(cmd, timeout_seconds=60):
            cmd_str = str(cmd)
            captured_cmds.append(cmd)

            # 1. lookupsid calls → return domain SIDs
            if "impacket-lookupsid" in cmd_str:
                # Route by target DC IP
                if "192.168.58.238" in cmd_str:
                    return (
                        "Domain SID is: S-1-5-21-9999999999-9999999999-9999999999",
                        "",
                        0,
                    )
                return (
                    "Domain SID is: S-1-5-21-1111111111-1111111111-1111111111",
                    "",
                    0,
                )

            # 2. Step 1: Combined ticketer + child DCSync for trust key
            # Has CANDIDATE_DC markers for DC resolution (Step 2 uses python3 -c instead)
            if "impacket-ticketer" in cmd_str and "CANDIDATE_DC" in cmd_str:
                return (
                    "Saving ticket in Administrator.ccache\n"
                    "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
                    "CONTOSO$:1234:aad3b435b51404eeaad3b435b51404ee"  # pragma: allowlist secret
                    ":abcdef1234567890abcdef1234567890:::\n"
                    "[*] Kerberos keys grabbed\n"
                    "CONTOSO$:aes256-cts-hmac-sha1-96"
                    ":aaff00112233445566778899aabbccddeeff00112233445566778899aabbccddee\n",
                    "",
                    0,
                )

            # 3. Step 2: Combined ticketer + parent DCSync via referral routing (python3 -c)
            if "impacket-ticketer" in cmd_str and "secretsdump" in cmd_str:
                return (
                    "Saving ticket in Administrator.ccache\n"
                    "[*] Dumping Domain Credentials\n"
                    "contoso.local\\Administrator:500"  # pragma: allowlist secret
                    ":aad3b435b51404eeaad3b435b51404ee"
                    ":aabb00112233445566778899aabbccdd:::\n",
                    "",
                    0,
                )

            # 4. Standalone ticketer (golden ticket) → success
            if "impacket-ticketer" in cmd_str:
                return ("Saving ticket in Administrator.ccache", "", 0)

            return ("", "", 1)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Verify the trust key referral sequence occurred
        cmd_strs = [str(c) for c in captured_cmds]

        # Should have DCSync'd child for trust account (CONTOSO$)
        trust_extract_cmds = [c for c in cmd_strs if "secretsdump" in c and "CONTOSO$" in c]
        assert len(trust_extract_cmds) >= 1, (
            f"Expected trust key extraction DCSync for CONTOSO$. Commands: {cmd_strs}"
        )

        # The trust extraction should target the CHILD DC
        trust_cmd = trust_extract_cmds[0]
        assert "192.168.58.121" in trust_cmd, (
            f"Trust key extraction should target child DC (192.168.58.121), got: {trust_cmd}"
        )
        # Identity should use child domain
        assert "child.contoso.local/Administrator" in trust_cmd, (
            f"Trust key extraction identity should use child domain. Got: {trust_cmd}"
        )

        # Step 2 should reuse golden ticket (NOT forge inter-realm TGT)
        # and use referral routing with child DC for Kerberos.
        # Step 1 uses bash + impacket-secretsdump -just-dc-user 'CONTOSO$'
        # Step 2 uses python3 -c with runpy for referral routing
        step2_cmds = [c for c in cmd_strs if "impacket-ticketer" in c and "python3 -c" in c]
        assert len(step2_cmds) >= 1, (
            f"Expected Step 2 golden ticket + referral DCSync command. Commands: {cmd_strs}"
        )

        # Step 2 should use child DC for -dc-ip (Kerberos referral routing)
        step2_cmd = step2_cmds[0]
        assert "192.168.58.121" in step2_cmd, (
            f"Step 2 should reference child DC (192.168.58.121) for "
            f"Kerberos referral routing. Got: {step2_cmd}"
        )
        # Step 2 should use child domain identity (golden ticket is for child realm)
        assert "CHILD.CONTOSO.LOCAL" in step2_cmd, (
            f"Step 2 identity should use child domain (golden ticket realm). Got: {step2_cmd}"
        )
        # Step 2 should target parent DC FQDN
        assert "dc01.contoso.local" in step2_cmd, (
            f"Step 2 should target parent DC FQDN. Got: {step2_cmd}"
        )
        # Step 2 should NOT use inter-realm TGT approach
        assert "krbtgt/contoso.local" not in step2_cmd, (
            f"Step 2 should NOT forge inter-realm TGT. Got: {step2_cmd}"
        )

        # Verify parent hash was stored (add_hash lowercases username/domain)
        parent_hashes = [
            h
            for h in state.all_hashes
            if h.username.lower() == "administrator"
            and (h.domain or "").lower() == "contoso.local"
            and h.hash_type
            and h.hash_type.lower() == "ntlm"
            and h.source
            and "parent_dcsync" in h.source
        ]
        assert len(parent_hashes) >= 1, (
            f"Parent Administrator hash not stored in state. "
            f"Hashes: {[(h.username, h.domain, h.source) for h in state.all_hashes]}"
        )
        expected = "aabb00112233445566778899aabbccdd"  # pragma: allowlist secret
        assert parent_hashes[0].hash_value == expected

        # Verify parent domain marked as DA
        assert "contoso.local" in [d.lower() for d in state.domain_admin_domains], (
            "Parent domain not marked as domain admin"
        )

        # Verify trust extraction was dispatched for foreign forests
        dispatcher._auto_dispatch_trust_key_extraction.assert_called()

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_trust_key_uses_aes_when_available(self):
        """Test that trust key AES256 is extracted and stored from child DCSync."""
        from unittest.mock import patch

        from ares.core.models import Credential, Hash, Host
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-trust-aes",
            target=Target(ip="192.168.58.10", domain="child.contoso.local"),
        )

        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:childkrbtgthash1234567890123456",
                hash_type="ntlm",
                domain="child.contoso.local",
                source="secretsdump",
            )
        )
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123!",  # pragma: allowlist secret
                domain="child.contoso.local",
                source="manual",
            )
        )

        state.all_hosts.append(
            Host(ip="192.168.58.121", hostname="dc01.child.contoso.local", is_dc=True)
        )
        state.all_hosts.append(Host(ip="192.168.58.238", hostname="dc01.contoso.local", is_dc=True))
        state.domain_controllers["child.contoso.local"] = "192.168.58.121"
        state.domain_controllers["contoso.local"] = "192.168.58.238"

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.121")
        dispatcher._task_queue = None
        dispatcher.announce_golden_ticket = AsyncMock()
        dispatcher._auto_dispatch_trust_key_extraction = AsyncMock()

        captured_cmds = []
        aes_key_value = "aaff00112233445566778899aabbccddeeff00112233445566778899aabbccddee"  # pragma: allowlist secret

        def mock_run_tool(cmd, timeout_seconds=60):
            cmd_str = str(cmd)
            captured_cmds.append(cmd)

            if "impacket-lookupsid" in cmd_str:
                if "192.168.58.238" in cmd_str:
                    return (
                        "Domain SID is: S-1-5-21-9999999999-9999999999-9999999999",
                        "",
                        0,
                    )
                return (
                    "Domain SID is: S-1-5-21-1111111111-1111111111-1111111111",
                    "",
                    0,
                )
            # Step 1: Combined ticketer + child DCSync for trust key
            # Has CANDIDATE_DC markers for DC resolution (Step 2 uses python3 -c instead)
            if "impacket-ticketer" in cmd_str and "CANDIDATE_DC" in cmd_str:
                return (
                    "Saving ticket in Administrator.ccache\n"
                    "CONTOSO$:1234:aad3b435b51404eeaad3b435b51404ee"  # pragma: allowlist secret
                    ":abcdef1234567890abcdef1234567890:::\n"
                    "CONTOSO$:aes256-cts-hmac-sha1-96"
                    f":{aes_key_value}\n",
                    "",
                    0,
                )
            # Step 2: Combined ticketer + parent DCSync via referral routing (python3 -c)
            if "impacket-ticketer" in cmd_str and "secretsdump" in cmd_str:
                return (
                    "Saving ticket in Administrator.ccache\n"
                    "Administrator:500:aad3b435b51404eeaad3b435b51404ee"  # pragma: allowlist secret
                    ":aabb00112233445566778899aabbccdd:::\n",
                    "",
                    0,
                )
            if "impacket-ticketer" in cmd_str:
                return ("Saving ticket in Administrator.ccache", "", 0)
            return ("", "", 1)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Verify trust key AES was extracted and stored
        trust_hashes = [
            h
            for h in state.all_hashes
            if h.username.upper() == "CONTOSO$" and h.hash_type and h.hash_type.lower() == "ntlm"
        ]
        assert len(trust_hashes) >= 1, (
            f"Expected CONTOSO$ trust hash in state. "
            f"Hashes: {[(h.username, h.domain, h.source) for h in state.all_hashes]}"
        )
        trust_hash = trust_hashes[0]
        assert trust_hash.aes_key == aes_key_value, (
            f"Trust key AES256 should be stored. Got: {trust_hash.aes_key}"
        )

        # Step 2 should reuse the golden ticket (NOT forge inter-realm TGT)
        # Step 1 uses bash + impacket-secretsdump -just-dc-user 'CONTOSO$'
        # Step 2 uses python3 -c with runpy for referral routing
        step2_cmds = [
            str(c)
            for c in captured_cmds
            if "impacket-ticketer" in str(c) and "python3 -c" in str(c)
        ]
        assert len(step2_cmds) >= 1, (
            f"Expected Step 2 golden ticket + referral DCSync. "
            f"Got: {[str(c) for c in captured_cmds]}"
        )
        # Should NOT have -spn krbtgt/contoso.local (no inter-realm TGT)
        assert "krbtgt/contoso.local" not in step2_cmds[0], (
            f"Step 2 should NOT forge inter-realm TGT. Got: {step2_cmds[0]}"
        )

    @pytest.mark.asyncio
    async def test_auto_golden_ticket_trust_key_extraction_failure_handled(self):
        """Test graceful handling when trust key extraction fails."""
        from unittest.mock import patch

        from ares.core.models import Credential, Hash, Host
        from ares.core.orchestrator import _auto_golden_ticket

        state = SharedRedTeamState(
            operation_id="op-gt-trust-fail",
            target=Target(ip="192.168.58.10", domain="child.contoso.local"),
        )

        state.all_hashes.append(
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:childkrbtgthash1234567890123456",
                hash_type="ntlm",
                domain="child.contoso.local",
                source="secretsdump",
            )
        )
        state.all_credentials.append(
            Credential(
                username="testuser",
                password="TestPass123!",  # pragma: allowlist secret
                domain="child.contoso.local",
                source="manual",
            )
        )

        state.all_hosts.append(
            Host(ip="192.168.58.121", hostname="dc01.child.contoso.local", is_dc=True)
        )
        state.all_hosts.append(Host(ip="192.168.58.238", hostname="dc01.contoso.local", is_dc=True))
        state.domain_controllers["child.contoso.local"] = "192.168.58.121"
        state.domain_controllers["contoso.local"] = "192.168.58.238"

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._find_domain_controller_ip = MagicMock(return_value="192.168.58.121")
        dispatcher._task_queue = None
        dispatcher.announce_golden_ticket = AsyncMock()

        def mock_run_tool(cmd, timeout_seconds=60):
            cmd_str = str(cmd)
            if "impacket-lookupsid" in cmd_str:
                return (
                    "Domain SID is: S-1-5-21-1111111111-1111111111-1111111111",
                    "",
                    0,
                )
            if "impacket-ticketer" in cmd_str:
                return ("Saving ticket in Administrator.ccache", "", 0)
            # Trust key extraction FAILS (access denied, no output)
            if "secretsdump" in cmd_str and "CONTOSO$" in cmd_str:
                return ("[-] ERROR: Could not connect", "Access denied", 1)
            return ("", "", 1)

        with patch("ares.tools.red.common.run_tool", side_effect=mock_run_tool):
            task = asyncio.create_task(_auto_golden_ticket(dispatcher, check_interval=0.1))
            await asyncio.sleep(0.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should NOT crash — golden ticket was still created for the child domain
        assert dispatcher.announce_golden_ticket.called, (
            "Golden ticket should still be announced even if trust key extraction fails"
        )

        # No parent domain hash should be in state
        parent_hashes = [
            h
            for h in state.all_hashes
            if h.username == "Administrator" and h.domain == "contoso.local"
        ]
        assert len(parent_hashes) == 0, (
            "No parent Administrator hash should exist when trust key extraction fails"
        )


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


class TestDirectNmapNetBIOSEnrichment:
    """Tests for NetBIOS hostname enrichment in direct nmap scan."""

    @pytest.mark.asyncio
    async def test_netbios_enrichment_resolves_hostname_from_fqdn(self, monkeypatch):
        """Test that Phase 3 resolves hostname from FQDN in nmap output."""
        from ares.core.orchestrator._orchestrator import _run_nmap_on_worker

        # Mock executor
        call_count = 0

        async def mock_execute(role, command, timeout_seconds):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # Phase 1: port scan
                return (
                    "Nmap scan report for 192.168.58.10\n"
                    "PORT    STATE SERVICE\n"
                    "445/tcp open  microsoft-ds\n",
                    "",
                    0,
                )
            if call_count == 2:
                # Phase 2: service scan
                return (
                    "Nmap scan report for 192.168.58.10\n"
                    "PORT    STATE SERVICE       VERSION\n"
                    "445/tcp open  microsoft-ds  Windows Server 2019\n",
                    "",
                    0,
                )
            # Phase 3: nbstat - returns FQDN
            return (
                "Nmap scan report for sql02.north.contoso.local (192.168.58.10)\n"
                "PORT    STATE  SERVICE\n"
                "137/udp open   netbios-ns\n",
                "",
                0,
            )

        mock_executor = MagicMock()
        mock_executor.execute = AsyncMock(side_effect=mock_execute)

        monkeypatch.setattr(
            "ares.core.k8s_executor.KubernetesPodExecutor",
            lambda **_kwargs: mock_executor,
        )

        _output, hosts = await _run_nmap_on_worker(["192.168.58.10"], "test-ns")

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.58.10"
        assert hosts[0].hostname == "sql02.north.contoso.local"

    @pytest.mark.asyncio
    async def test_netbios_enrichment_parses_netbios_name(self, monkeypatch):
        """Test that Phase 3 parses NetBIOS name when FQDN not available."""
        from ares.core.orchestrator._orchestrator import _run_nmap_on_worker

        call_count = 0

        async def mock_execute(role, command, timeout_seconds):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                return (
                    "Nmap scan report for 192.168.58.11\n"
                    "PORT    STATE SERVICE\n"
                    "445/tcp open  microsoft-ds\n",
                    "",
                    0,
                )
            if call_count == 2:
                return (
                    "Nmap scan report for 192.168.58.11\n"
                    "PORT    STATE SERVICE       VERSION\n"
                    "445/tcp open  microsoft-ds  Windows Server 2019\n",
                    "",
                    0,
                )
            # Phase 3: nbstat - returns NetBIOS name only
            return (
                "Nmap scan report for 192.168.58.11\n"
                "| nbstat: NetBIOS name: SQL01, NetBIOS user: <unknown>\n"
                "|   Names:\n"
                "|     SQL01<00>          Flags: <unique>\n"
                "|     CONTOSO<00>        Flags: <group>\n",
                "",
                0,
            )

        mock_executor = MagicMock()
        mock_executor.execute = AsyncMock(side_effect=mock_execute)

        monkeypatch.setattr(
            "ares.core.k8s_executor.KubernetesPodExecutor",
            lambda **_kwargs: mock_executor,
        )

        _output, hosts = await _run_nmap_on_worker(["192.168.58.11"], "test-ns")

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.58.11"
        # Only NetBIOS name - we don't construct fake FQDNs like "sql01.contoso.local"
        # because we don't know the actual domain suffix. The FQDN will be discovered
        # via DNS/LDAP enumeration.
        assert hosts[0].hostname == "sql01"

    @pytest.mark.asyncio
    async def test_netbios_enrichment_skips_aws_hostnames(self, monkeypatch):
        """Test that Phase 3 skips AWS internal hostnames."""
        from ares.core.orchestrator._orchestrator import _run_nmap_on_worker

        call_count = 0

        async def mock_execute(role, command, timeout_seconds):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                return (
                    "Nmap scan report for ip-10-0-1-50.ec2.internal (192.168.58.12)\n"
                    "PORT    STATE SERVICE\n"
                    "445/tcp open  microsoft-ds\n",
                    "",
                    0,
                )
            if call_count == 2:
                return (
                    "Nmap scan report for ip-10-0-1-50.ec2.compute.internal (192.168.58.12)\n"
                    "PORT    STATE SERVICE       VERSION\n"
                    "445/tcp open  microsoft-ds  Windows Server 2019\n",
                    "",
                    0,
                )
            # Phase 3: nbstat returns AWS hostname (should be skipped)
            return (
                "Nmap scan report for ip-10-0-1-50.ec2.compute.internal (192.168.58.12)\n"
                "| nbstat: NetBIOS name: WEB01, NetBIOS user: <unknown>\n"
                "|   Names:\n"
                "|     WEB01<00>          Flags: <unique>\n",
                "",
                0,
            )

        mock_executor = MagicMock()
        mock_executor.execute = AsyncMock(side_effect=mock_execute)

        monkeypatch.setattr(
            "ares.core.k8s_executor.KubernetesPodExecutor",
            lambda **_kwargs: mock_executor,
        )

        _output, hosts = await _run_nmap_on_worker(["192.168.58.12"], "test-ns")

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.58.12"
        # Should use NetBIOS name since FQDN was AWS internal
        assert hosts[0].hostname == "web01"

    @pytest.mark.asyncio
    async def test_netbios_enrichment_skips_hosts_with_hostname(self, monkeypatch):
        """Test that Phase 3 skips hosts that already have hostnames."""
        from ares.core.orchestrator._orchestrator import _run_nmap_on_worker

        call_count = 0

        async def mock_execute(role, command, timeout_seconds):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                return (
                    "Nmap scan report for dc01.contoso.local (192.168.58.13)\n"
                    "PORT    STATE SERVICE\n"
                    "445/tcp open  microsoft-ds\n",
                    "",
                    0,
                )
            if call_count == 2:
                return (
                    "Nmap scan report for dc01.contoso.local (192.168.58.13)\n"
                    "PORT    STATE SERVICE       VERSION\n"
                    "445/tcp open  microsoft-ds  Windows Server 2019\n",
                    "",
                    0,
                )
            # Should NOT reach Phase 3 - host already has hostname
            raise AssertionError("Phase 3 should not run for hosts with hostnames")

        mock_executor = MagicMock()
        mock_executor.execute = AsyncMock(side_effect=mock_execute)

        monkeypatch.setattr(
            "ares.core.k8s_executor.KubernetesPodExecutor",
            lambda **_kwargs: mock_executor,
        )

        _output, hosts = await _run_nmap_on_worker(["192.168.58.13"], "test-ns")

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.58.13"
        assert hosts[0].hostname == "dc01.contoso.local"
        # Only 2 calls (Phase 1 + Phase 2), no Phase 3
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_netbios_enrichment_handles_timeout(self, monkeypatch):
        """Test that Phase 3 handles timeout gracefully."""
        from ares.core.orchestrator._orchestrator import _run_nmap_on_worker

        call_count = 0

        async def mock_execute(role, command, timeout_seconds):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                return (
                    "Nmap scan report for 192.168.58.14\n"
                    "PORT    STATE SERVICE\n"
                    "445/tcp open  microsoft-ds\n",
                    "",
                    0,
                )
            if call_count == 2:
                return (
                    "Nmap scan report for 192.168.58.14\n"
                    "PORT    STATE SERVICE       VERSION\n"
                    "445/tcp open  microsoft-ds  Windows Server 2019\n",
                    "",
                    0,
                )
            # Phase 3: timeout
            raise TimeoutError("Command timed out")

        mock_executor = MagicMock()
        mock_executor.execute = AsyncMock(side_effect=mock_execute)

        monkeypatch.setattr(
            "ares.core.k8s_executor.KubernetesPodExecutor",
            lambda **_kwargs: mock_executor,
        )

        _output, hosts = await _run_nmap_on_worker(["192.168.58.14"], "test-ns")

        # Should still return the host, just without hostname
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.58.14"
        assert hosts[0].hostname == ""


class TestShouldStopBackgroundTask:
    """Tests for _should_stop_background_task helper."""

    def test_stops_when_completed(self):
        """Should always stop when operation is completed."""
        from ares.core.orchestrator import _should_stop_background_task

        state = SharedRedTeamState(
            operation_id="op-test-stop-1",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.completed = True
        assert _should_stop_background_task(state) is True

    def test_continues_when_no_da(self):
        """Should continue running when DA not yet achieved."""
        from ares.core.orchestrator import _should_stop_background_task

        state = SharedRedTeamState(
            operation_id="op-test-stop-2",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = False
        assert _should_stop_background_task(state) is False

    def test_stops_on_da_single_domain(self, monkeypatch):
        """Should stop on DA in single-domain (non-multi-forest) mode."""
        from ares.core.orchestrator import _should_stop_background_task

        monkeypatch.setattr(
            "ares.core.orchestrator._orchestrator.get_multi_forest_mode",
            lambda: False,
        )

        state = SharedRedTeamState(
            operation_id="op-test-stop-3",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = True
        assert _should_stop_background_task(state) is True

    def test_continues_on_da_multi_forest_undominated(self, monkeypatch):
        """Should continue when DA achieved but foreign forests remain undominated."""
        from ares.core.models import Host
        from ares.core.orchestrator import _should_stop_background_task

        monkeypatch.setattr(
            "ares.core.orchestrator._orchestrator.get_multi_forest_mode",
            lambda: True,
        )

        state = SharedRedTeamState(
            operation_id="op-test-stop-4",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = True
        state.domain_admin_domains = ["contoso.local"]
        # Add a foreign domain host to make it discoverable
        state.add_host(
            Host(
                ip="192.168.58.20",
                hostname="dc01.fabrikam.local",
                services=["88/tcp kerberos-sec"],
                is_dc=True,
            )
        )
        # fabrikam.local is foreign and undominated
        assert state.all_forests_dominated() is False
        assert _should_stop_background_task(state) is False

    def test_stops_on_da_multi_forest_all_dominated(self, monkeypatch):
        """Should stop when all forests dominated in multi-forest mode."""
        from ares.core.models import Host
        from ares.core.orchestrator import _should_stop_background_task

        monkeypatch.setattr(
            "ares.core.orchestrator._orchestrator.get_multi_forest_mode",
            lambda: True,
        )

        state = SharedRedTeamState(
            operation_id="op-test-stop-5",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = True
        state.domain_admin_domains = ["contoso.local", "fabrikam.local"]
        state.add_host(
            Host(
                ip="192.168.58.20",
                hostname="dc01.fabrikam.local",
                services=["88/tcp kerberos-sec"],
                is_dc=True,
            )
        )
        # Both forests dominated
        assert state.all_forests_dominated() is True
        assert _should_stop_background_task(state) is True


class TestAutoMssqlDetectionMultiForest:
    """Test that MSSQL detection continues in multi-forest mode after DA."""

    @pytest.mark.asyncio
    async def test_mssql_detection_continues_after_da_in_multi_forest(self, monkeypatch):
        """MSSQL detection should NOT stop after DA when undominated forests remain."""
        from ares.core.models import Host
        from ares.core.orchestrator import _auto_mssql_detection

        monkeypatch.setattr(
            "ares.core.orchestrator._orchestrator.get_multi_forest_mode",
            lambda: True,
        )

        state = SharedRedTeamState(
            operation_id="op-test-mssql-mf",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = True
        state.domain_admin_domains = ["contoso.local"]
        # Add foreign domain host so forests are not all dominated
        state.add_host(
            Host(
                ip="192.168.58.20",
                hostname="dc01.fabrikam.local",
                services=["88/tcp kerberos-sec"],
                is_dc=True,
            )
        )
        # Add an MSSQL host
        state.add_host(
            Host(
                ip="192.168.58.17",
                hostname="sql01.contoso.local",
                services=["1433/tcp ms-sql-s"],
            )
        )

        scan_called = False

        async def mock_scan():
            nonlocal scan_called
            scan_called = True
            # Complete the operation to stop the loop
            state.domain_admin_domains.append("fabrikam.local")
            return 1

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher.scan_hosts_for_mssql = mock_scan

        await _auto_mssql_detection(dispatcher, check_interval=0.05)

        assert scan_called, "MSSQL scan should have been called despite DA on first domain"


class TestAutoCrossForestPivot:
    """Tests for _auto_cross_forest_pivot background task."""

    @pytest.mark.asyncio
    async def test_cross_forest_pivot_stops_when_not_multi_forest(self, monkeypatch):
        """Should exit when not in multi-forest mode."""
        from ares.core.orchestrator import _auto_cross_forest_pivot

        monkeypatch.setattr(
            "ares.core.orchestrator._orchestrator.get_multi_forest_mode",
            lambda: False,
        )

        state = SharedRedTeamState(
            operation_id="op-test-cfp-1",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.completed = True  # Will stop on first iteration

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._task_queue = None

        await _auto_cross_forest_pivot(dispatcher, check_interval=0.05)

    @pytest.mark.asyncio
    async def test_cross_forest_pivot_dispatches_fsp_and_mssql(self, monkeypatch):
        """Should dispatch FSP enumeration and MSSQL re-scan for undominated forests."""
        from ares.core.models import Credential, Host
        from ares.core.orchestrator import _auto_cross_forest_pivot

        monkeypatch.setattr(
            "ares.core.orchestrator._orchestrator.get_multi_forest_mode",
            lambda: True,
        )

        state = SharedRedTeamState(
            operation_id="op-test-cfp-2",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = True
        state.domain_admin_domains = ["contoso.local"]
        state.domain_controllers["fabrikam.local"] = "192.168.58.20"
        state.add_host(
            Host(
                ip="192.168.58.20",
                hostname="dc01.fabrikam.local",
                services=["88/tcp kerberos-sec"],
                is_dc=True,
            )
        )
        # Add a DA credential for contoso.local
        state.all_credentials.append(
            Credential(
                username="Administrator",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
                source="test",
                is_admin=True,
            )  # pragma: allowlist secret
        )

        dispatched_tasks: list[dict] = []
        mssql_scanned = False

        async def mock_submit(task_type, target_role, payload, source_agent, priority):
            dispatched_tasks.append(
                {
                    "tool": payload.get("tool"),
                    "domain": payload.get("domain") or payload.get("target_domain", ""),
                }
            )
            # After first dispatch, mark all forests dominated to stop loop
            state.domain_admin_domains.append("fabrikam.local")

        async def mock_mssql_scan(force_requeue=False):
            nonlocal mssql_scanned
            mssql_scanned = True
            return 0

        dispatcher = SimpleNamespace(shared_state=state)
        dispatcher._task_queue = None
        dispatcher._throttled_submit_task = mock_submit
        dispatcher.scan_hosts_for_mssql = mock_mssql_scan

        await _auto_cross_forest_pivot(dispatcher, check_interval=0.05)

        # Should have dispatched FSP enumeration
        fsp_dispatches = [
            t for t in dispatched_tasks if t["tool"] == "enumerate_foreign_security_principals"
        ]
        assert len(fsp_dispatches) >= 1, f"Expected FSP dispatch, got: {dispatched_tasks}"
        assert fsp_dispatches[0]["domain"] == "fabrikam.local"

        # Should have done MSSQL re-scan
        assert mssql_scanned
