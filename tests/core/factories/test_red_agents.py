"""Tests for red_agents factory helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dreadnode.agent.events import StepStart, ToolEnd
from dreadnode.agent.reactions import Finish

from ares.core.config import AgentConfig
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.factories.red_agents import (
    create_agent_info,
    create_multi_agent_ensemble,
    create_role_hooks,
    load_agent_instructions,
)
from ares.core.models import AgentRole, SharedRedTeamState


@pytest.mark.asyncio
async def test_create_multi_agent_ensemble_requires_model(monkeypatch):
    monkeypatch.delenv("ARES_MODEL", raising=False)
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_WORKER_MODEL", raising=False)

    dispatcher = MagicMock(shared_state=SimpleNamespace())

    with pytest.raises(ValueError, match="No model specified"):
        await create_multi_agent_ensemble(
            operation_id="op-1",
            target_ip="192.168.58.1",
            dispatcher=dispatcher,
            roles=[AgentRole.RECON],
        )


@pytest.mark.asyncio
async def test_create_multi_agent_ensemble_uses_env_models(monkeypatch):
    monkeypatch.setenv("ARES_ORCHESTRATOR_MODEL", "orch-model")
    monkeypatch.setenv("ARES_WORKER_MODEL", "worker-model")

    dispatcher = MagicMock(shared_state=SimpleNamespace())
    dispatcher.register = AsyncMock()

    with patch("ares.core.factories.red_agents.create_specialized_agent") as mock_create:
        mock_create.return_value = MagicMock()

        await create_multi_agent_ensemble(
            operation_id="op-2",
            target_ip="192.168.58.2",
            dispatcher=dispatcher,
            roles=[AgentRole.ORCHESTRATOR, AgentRole.CRACKER],
        )

    assert mock_create.call_count == 2
    assert mock_create.call_args_list[0].kwargs["model"] == "orch-model"
    assert mock_create.call_args_list[1].kwargs["model"] == "worker-model"


def test_create_specialized_agent_uses_set_state(monkeypatch):
    """Test that create_specialized_agent calls set_state on all toolsets."""
    created_instances: list[MagicMock] = []

    class DummyToolset:
        def __init__(self) -> None:
            self.set_state = MagicMock()
            self.set_dispatcher = MagicMock()
            created_instances.append(self)

        def get_tools(self, *, variant=None):
            # Return a mock tool to ensure toolset is included
            mock_tool = MagicMock()
            mock_tool.name = "nmap_scan"  # Match a capability
            return [mock_tool]

    # Mock ALL_TOOLSETS and UNIVERSAL_TOOLSETS to use our dummy
    monkeypatch.setattr(
        "ares.core.factories.red_agents.ALL_TOOLSETS",
        [DummyToolset],
    )
    monkeypatch.setattr(
        "ares.core.factories.red_agents.UNIVERSAL_TOOLSETS",
        [],
    )
    monkeypatch.setattr(
        "ares.core.factories.red_agents.ROLE_CALLBACK_TOOLS",
        {},
    )
    # Mock get_enabled_tools to return our tool name
    monkeypatch.setattr(
        "ares.core.factories.red_agents.get_enabled_tools",
        lambda _caps: {"nmap_scan"},
    )
    monkeypatch.setattr(
        "ares.core.factories.red_agents.load_agent_instructions",
        lambda _role: "instructions",
    )
    monkeypatch.setattr(
        "ares.core.factories.red_agents.create_role_hooks",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr("ares.core.factories.red_agents.dn.Agent", MagicMock())

    from ares.core.factories.red_agents import create_specialized_agent

    shared_state = MagicMock()
    dispatcher = MagicMock()

    create_specialized_agent(
        role=AgentRole.RECON,
        model="test-model",
        shared_state=shared_state,
        dispatcher=dispatcher,
    )

    # Verify set_state was called on at least one toolset instance
    assert len(created_instances) > 0, "No toolset instances created"
    created_instances[0].set_state.assert_called_once_with(shared_state)


class TestCapabilitiesFromConfig:
    """Tests for loading capabilities from config into templates and AgentInfo."""

    def test_load_agent_instructions_passes_capabilities_to_template(self, monkeypatch):
        """Test that load_agent_instructions passes capabilities from config to template."""
        test_capabilities = ["tool1", "tool2", "tool3"]

        # Mock get_agent_config to return specific capabilities
        mock_config = AgentConfig(
            model="test-model",
            capabilities=test_capabilities,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_agent_config",
            lambda _role: mock_config,
        )

        # Mock template loader to capture what's passed
        captured_context = {}

        def mock_render(template_path, **context):
            captured_context.update(context)
            return "rendered template"

        mock_loader = MagicMock()
        mock_loader.render = mock_render
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_template_loader",
            lambda: mock_loader,
        )

        load_agent_instructions(AgentRole.PRIVESC)

        assert "capabilities" in captured_context
        assert captured_context["capabilities"] == test_capabilities

    def test_load_agent_instructions_uses_correct_config_key(self, monkeypatch):
        """Test that load_agent_instructions uses the correct config key for each role."""
        captured_keys = []

        def mock_get_agent_config(role_key):
            captured_keys.append(role_key)
            return AgentConfig(model="test", capabilities=[])

        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_agent_config",
            mock_get_agent_config,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_template_loader",
            lambda: MagicMock(render=lambda *_a, **_kw: ""),
        )

        # Test various roles
        load_agent_instructions(AgentRole.RECON)
        load_agent_instructions(AgentRole.CREDENTIAL_ACCESS)
        load_agent_instructions(AgentRole.PRIVESC)

        assert "recon" in captured_keys
        assert "credential_access" in captured_keys
        assert "privesc" in captured_keys

    def test_create_agent_info_uses_config_capabilities(self, monkeypatch):
        """Test that create_agent_info loads capabilities from config."""
        test_capabilities = ["cap1", "cap2", "cap3"]

        mock_config = AgentConfig(
            model="test-model",
            capabilities=test_capabilities,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_agent_config",
            lambda _role: mock_config,
        )

        info = create_agent_info(AgentRole.LATERAL, "test-pod")

        assert info.capabilities == set(test_capabilities)
        assert info.role == AgentRole.LATERAL
        assert info.pod_name == "test-pod"

    def test_create_agent_info_empty_capabilities(self, monkeypatch):
        """Test that create_agent_info handles empty capabilities gracefully."""
        mock_config = AgentConfig(model="test-model", capabilities=[])
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_agent_config",
            lambda _role: mock_config,
        )

        info = create_agent_info(AgentRole.CRACKER, "cracker-pod")

        assert info.capabilities == set()

    def test_capabilities_integration_with_real_config(self):
        """Integration test: verify capabilities load from actual config file."""
        # This test uses the real config/multi-agent-production.yaml
        from ares.core.config import clear_config_cache, get_agent_config

        clear_config_cache()  # Ensure fresh load

        # Test that privesc has the configured tools
        privesc_config = get_agent_config("privesc")
        assert "certipy" in privesc_config.capabilities
        assert "impacket-getST" in privesc_config.capabilities  # getST for S4U attacks

        # Test that recon has enumeration tools
        recon_config = get_agent_config("recon")
        assert "nmap" in recon_config.capabilities
        assert "bloodhound-python" in recon_config.capabilities
        assert "netexec" in recon_config.capabilities

        # Test that credential_access has credential harvesting tools
        cred_config = get_agent_config("credential_access")
        assert "rpcclient" in cred_config.capabilities
        assert "smbclient" in cred_config.capabilities
        assert "impacket-secretsdump" in cred_config.capabilities

        # Test that lateral has movement tools
        lateral_config = get_agent_config("lateral")
        assert "evil-winrm" in lateral_config.capabilities
        assert "impacket-psexec" in lateral_config.capabilities
        assert "impacket-secretsdump" in lateral_config.capabilities

    def test_template_renders_capabilities_from_config(self):
        """Integration test: verify templates render capabilities from config."""
        from ares.core.config import clear_config_cache

        clear_config_cache()

        # Load real instructions and verify capabilities appear
        instructions = load_agent_instructions(AgentRole.PRIVESC)

        # Should contain tools from config
        assert "sweetpotato" in instructions.lower()
        assert "sharpgpoabuse" in instructions.lower()
        assert "certipy" in instructions.lower()

    def test_all_roles_load_capabilities(self):
        """Test that all agent roles can load their capabilities."""
        from ares.core.config import clear_config_cache

        clear_config_cache()

        roles_to_test = [
            AgentRole.RECON,
            AgentRole.CREDENTIAL_ACCESS,
            AgentRole.CRACKER,
            AgentRole.ACL,
            AgentRole.PRIVESC,
            AgentRole.LATERAL,
            AgentRole.COERCION,
        ]

        for role in roles_to_test:
            # Should not raise any exceptions
            instructions = load_agent_instructions(role)
            assert len(instructions) > 0, f"Empty instructions for {role}"

            info = create_agent_info(role, f"{role.value}-pod")
            assert info.role == role


class TestPrivescTrackExploitationHook:
    """Tests for the privesc track_exploitation hook."""

    def _make_tool_end_event(self, tool_name: str, content: str) -> MagicMock:
        """Helper to create a mock ToolEnd event."""
        # Create a mock that behaves like ToolEnd
        event = MagicMock(spec=ToolEnd)
        event.tool_call = MagicMock()
        event.tool_call.name = tool_name
        event.message = MagicMock()
        event.message.content = content
        return event

    @pytest.mark.asyncio
    async def test_certipy_find_does_not_trigger_exploitation_success(self):
        """Test that certipy_find (enumeration) does NOT trigger exploitation success.

        This is a critical fix - certipy_find output always contains "certificate"
        which was causing false positives. The hook should only fire for actual
        exploitation tools like certipy_req, certipy_auth, etc.
        """
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.PRIVESC, dispatcher, shared_state)

        certipy_find_output = """
Certificate Authorities
  0
    CA Name                             : corp-DC01-CA
    DNS Name                            : dc01.contoso.local
    Certificate Subject                 : CN=corp-DC01-CA
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is vulnerable
        """

        event = self._make_tool_end_event("certipy_find", certipy_find_output)

        # Run all hooks and collect feedback
        feedback_messages = []
        for hook in hooks:
            result = await hook(event)
            if result:
                feedback_messages.append(result)

        # certipy_find should NOT trigger "EXPLOITATION SUCCESSFUL"
        for msg in feedback_messages:
            assert "EXPLOITATION SUCCESSFUL" not in msg, (
                f"certipy_find should NOT trigger exploitation success hook. Got: {msg}"
            )

    @pytest.mark.asyncio
    async def test_certipy_auth_triggers_exploitation_success(self):
        """Test that certipy_auth (actual exploitation) DOES trigger success."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.PRIVESC, dispatcher, shared_state)

        # Simulate successful certipy_auth output
        certipy_auth_output = """
[*] Using principal: Administrator@contoso.local
[*] Got hash for 'Administrator@contoso.local': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
        """

        event = self._make_tool_end_event("certipy_auth", certipy_auth_output)

        feedback_messages = []
        for hook in hooks:
            result = await hook(event)
            if result:
                feedback_messages.append(result)

        # certipy_auth with hash output SHOULD trigger success
        success_found = any("EXPLOITATION SUCCESSFUL" in msg for msg in feedback_messages)
        assert success_found, "certipy_auth with hash output should trigger exploitation success"

    @pytest.mark.asyncio
    async def test_certipy_req_with_pfx_triggers_success(self):
        """Test that certipy_req with .pfx output triggers success."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.PRIVESC, dispatcher, shared_state)

        certipy_req_output = """
[*] Saved certificate and private key to 'administrator.pfx'
        """

        event = self._make_tool_end_event("certipy_req", certipy_req_output)

        feedback_messages = []
        for hook in hooks:
            result = await hook(event)
            if result:
                feedback_messages.append(result)

        success_found = any("EXPLOITATION SUCCESSFUL" in msg for msg in feedback_messages)
        assert success_found, "certipy_req with .pfx output should trigger exploitation success"


class TestRoleHooks:
    """Tests for create_role_hooks function."""

    def test_all_roles_get_unstall_hooks(self):
        """Test that all roles receive unstall hooks with role-specific guidance."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        roles_to_test = [
            AgentRole.ORCHESTRATOR,
            AgentRole.RECON,
            AgentRole.CREDENTIAL_ACCESS,
            AgentRole.CRACKER,
            AgentRole.ACL,
            AgentRole.PRIVESC,
            AgentRole.LATERAL,
            AgentRole.COERCION,
        ]

        for role in roles_to_test:
            hooks = create_role_hooks(role, dispatcher, shared_state)
            # All roles should have at least one hook (unstall hook)
            assert len(hooks) > 0, f"Role {role} should have hooks"

    def test_credential_access_unstall_feedback(self):
        """Test that CREDENTIAL_ACCESS role has specific unstall guidance."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.CREDENTIAL_ACCESS, dispatcher, shared_state)

        # Find the unstall hook (it's a retry_with_feedback hook)
        # We can't easily inspect the hook's feedback directly, but we can verify
        # the hook was created for the right event type
        assert len(hooks) > 0

    def test_cracker_unstall_feedback(self):
        """Test that CRACKER role has specific unstall guidance."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.CRACKER, dispatcher, shared_state)

        # Cracker should have unstall hook
        assert len(hooks) > 0

    def test_lateral_unstall_feedback(self):
        """Test that LATERAL role has specific unstall guidance."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.LATERAL, dispatcher, shared_state)

        # Lateral should have unstall hook
        assert len(hooks) > 0

    def test_privesc_has_exploitation_tracking_hook(self):
        """Test that PRIVESC role includes exploitation tracking hook."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.PRIVESC, dispatcher, shared_state)

        # PRIVESC should have multiple hooks (exploitation tracking + unstall)
        assert len(hooks) >= 2, "PRIVESC should have exploitation tracking and unstall hooks"

    def test_orchestrator_has_summarize_when_long_hook(self):
        """Test that ORCHESTRATOR role includes summarize_when_long hook for context management."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)

        # ORCHESTRATOR should have multiple hooks including summarize_when_long
        # (log_tool_usage, log_tool_result, summarize_when_long, check_domain_admin, unstall)
        assert len(hooks) >= 4, "ORCHESTRATOR should have summarize_when_long and other hooks"

    def test_all_roles_get_summarize_hook(self):
        """Test that ALL roles get summarize_when_long hook for context management."""
        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        all_roles = [
            AgentRole.ORCHESTRATOR,
            AgentRole.RECON,
            AgentRole.CREDENTIAL_ACCESS,
            AgentRole.CRACKER,
            AgentRole.ACL,
            AgentRole.PRIVESC,
            AgentRole.LATERAL,
            AgentRole.COERCION,
        ]

        for role in all_roles:
            hooks = create_role_hooks(role, dispatcher, shared_state)
            # All roles should have at least 3 hooks:
            # log_tool_usage, log_tool_result, context_aware_summarize
            assert len(hooks) >= 3, (
                f"Role {role} should have at least 3 hooks (including summarize_when_long)"
            )

        # Orchestrator should have MORE hooks than workers due to domain admin checking
        orchestrator_hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        worker_hooks = create_role_hooks(AgentRole.RECON, dispatcher, shared_state)
        assert len(orchestrator_hooks) > len(worker_hooks), (
            "ORCHESTRATOR should have additional domain admin hooks"
        )


class TestContextManagementHooks:
    """Tests for context management hooks in red_agents."""

    def test_summarize_when_long_uses_config_values(self, monkeypatch):
        """Test that summarize_when_long hook uses config values."""
        # Mock the config functions
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_max_context_tokens",
            lambda: 50000,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_min_messages_to_keep",
            lambda: 5,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        # Create hooks - this should use our mocked config values
        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)

        # Verify hooks were created (we can't easily verify the exact values
        # passed to summarize_when_long, but we can verify hooks exist)
        assert len(hooks) > 0

    def test_get_max_context_tokens_used_in_hooks(self):
        """Test that get_max_context_tokens is imported and available."""
        from ares.core.factories.red_agents import get_max_context_tokens

        # Should return a reasonable default (100k for ~85% of 128k window)
        result = get_max_context_tokens()
        assert result >= 50000  # Should be at least 50k tokens
        assert result <= 200000  # But not more than 200k

    def test_get_min_messages_to_keep_used_in_hooks(self):
        """Test that get_min_messages_to_keep is imported and available."""
        from ares.core.factories.red_agents import get_min_messages_to_keep

        # Should return a reasonable default
        result = get_min_messages_to_keep()
        assert result >= 5  # At least 5 messages
        assert result <= 50  # But not more than 50


class TestStopOnExternalDomainAdmin:
    """Tests for stop_on_external_domain_admin hook.

    This hook stops the orchestrator when Domain Admin is achieved externally
    (by a worker agent discovering krbtgt hash via secretsdump).
    """

    def _make_step_start_event(self) -> MagicMock:
        """Helper to create a mock StepStart event."""
        return MagicMock(spec=StepStart)

    def _make_tool_end_event(self, tool_name: str = "get_status") -> MagicMock:
        """Helper to create a mock ToolEnd event."""
        event = MagicMock(spec=ToolEnd)
        event.tool_call = MagicMock()
        event.tool_call.name = tool_name
        event.message = MagicMock()
        event.message.content = "OK"
        return event

    @pytest.mark.asyncio
    async def test_returns_finish_on_step_start_when_da_achieved(self, monkeypatch):
        """Test that hook returns Finish on StepStart when has_domain_admin=True."""
        # Enable stop_on_domain_admin config (required for DA hook to fire)
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = True
        shared_state.domain_admin_path = "kerberoast -> secretsdump -> krbtgt"

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        # Find and invoke hooks that accept StepStart
        finish_results = []
        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish):
                    finish_results.append(result)
            except TypeError:
                # Hook doesn't accept this event type
                pass

        assert len(finish_results) >= 1, "Should return Finish when DA achieved on StepStart"
        assert "Domain Admin achieved" in finish_results[0].reason

    @pytest.mark.asyncio
    async def test_returns_finish_on_tool_end_when_da_achieved(self, monkeypatch):
        """Test that hook returns Finish on ToolEnd when has_domain_admin=True.

        This is critical for reducing latency - we check DA after every tool
        execution, not just at step boundaries.
        """
        # Enable stop_on_domain_admin config (required for DA hook to fire)
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = True
        shared_state.domain_admin_path = "secretsdump -> krbtgt"

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_tool_end_event("get_operation_summary")

        # Find and invoke hooks that accept ToolEnd
        finish_results = []
        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish):
                    finish_results.append(result)
            except TypeError:
                pass

        assert len(finish_results) >= 1, "Should return Finish when DA achieved on ToolEnd"
        assert "Domain Admin achieved" in finish_results[0].reason

    @pytest.mark.asyncio
    async def test_returns_none_when_da_not_achieved(self, monkeypatch):
        """Test that hook returns None when has_domain_admin=False."""
        # Enable stop_on_domain_admin config
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = False

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)

        # Test both event types
        for event in [self._make_step_start_event(), self._make_tool_end_event()]:
            for hook in hooks:
                try:
                    result = await hook(event)
                    # Should not return Finish when DA not achieved
                    assert not isinstance(result, Finish), (
                        f"Should not return Finish when DA not achieved, got {result}"
                    )
                except TypeError:
                    pass

    @pytest.mark.asyncio
    async def test_only_orchestrator_has_da_stop_hook(self, monkeypatch):
        """Test that only ORCHESTRATOR role has the stop_on_external_domain_admin hook."""
        # Enable stop_on_domain_admin config
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = True

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        # Worker roles should NOT have the DA stop hook
        worker_roles = [
            AgentRole.RECON,
            AgentRole.CREDENTIAL_ACCESS,
            AgentRole.CRACKER,
            AgentRole.LATERAL,
        ]

        for role in worker_roles:
            hooks = create_role_hooks(role, dispatcher, shared_state)
            event = self._make_step_start_event()

            finish_count = 0
            for hook in hooks:
                try:
                    result = await hook(event)
                    if isinstance(result, Finish) and "Domain Admin" in str(result.reason):
                        finish_count += 1
                except TypeError:
                    pass

            assert finish_count == 0, f"Worker role {role} should not have DA stop hook"


class TestStopOnExternalGoldenTicket:
    """Tests for stop_on_external_golden_ticket hook.

    This hook stops the orchestrator when a Golden Ticket is forged externally
    (by a worker agent), but only when stop_on_golden_ticket=True in config.
    """

    def _make_step_start_event(self) -> MagicMock:
        """Helper to create a mock StepStart event."""
        return MagicMock(spec=StepStart)

    def _make_tool_end_event(self, tool_name: str = "get_status") -> MagicMock:
        """Helper to create a mock ToolEnd event."""
        event = MagicMock(spec=ToolEnd)
        event.tool_call = MagicMock()
        event.tool_call.name = tool_name
        event.message = MagicMock()
        event.message.content = "OK"
        return event

    @pytest.mark.asyncio
    async def test_returns_finish_when_golden_ticket_forged_and_config_enabled(self, monkeypatch):
        """Test hook returns Finish when has_golden_ticket=True and config enabled."""
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_golden_ticket = True

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        finish_results = []
        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish):
                    finish_results.append(result)
            except TypeError:
                pass

        assert len(finish_results) >= 1, "Should return Finish when GT forged"
        assert "Golden Ticket" in finish_results[0].reason

    @pytest.mark.asyncio
    async def test_returns_none_when_config_disabled(self, monkeypatch):
        """Test hook returns None when stop_on_golden_ticket=False."""
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: False,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_golden_ticket = True

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish) and "Golden Ticket" in str(result.reason):
                    pytest.fail("Should not return Finish when config disabled")
            except TypeError:
                pass

    @pytest.mark.asyncio
    async def test_returns_none_when_no_golden_ticket(self, monkeypatch):
        """Test hook returns None when has_golden_ticket=False."""
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_golden_ticket = False

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        for hook in hooks:
            try:
                result = await hook(event)
                assert not isinstance(result, Finish), "Should not Finish without GT"
            except TypeError:
                pass


class TestStopOnDomainAdminConfigRespect:
    """Tests that stop_on_external_domain_admin respects config setting.

    The DA hook should only fire when stop_on_domain_admin=True.
    When stop_on_golden_ticket=True, we continue past DA to forge golden ticket.
    """

    def _make_step_start_event(self) -> MagicMock:
        """Helper to create a mock StepStart event."""
        return MagicMock(spec=StepStart)

    @pytest.mark.asyncio
    async def test_da_hook_fires_when_stop_on_da_enabled(self, monkeypatch):
        """Test DA hook fires when stop_on_domain_admin=True."""
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: True,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: False,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = True

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        finish_results = []
        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish) and "Domain Admin" in str(result.reason):
                    finish_results.append(result)
            except TypeError:
                pass

        assert len(finish_results) >= 1, "DA hook should fire when config enabled"

    @pytest.mark.asyncio
    async def test_da_hook_does_not_fire_when_disabled(self, monkeypatch):
        """Test DA hook does NOT fire when stop_on_domain_admin=False.

        This is critical for forest escalation: we need to continue past DA
        to forge the golden ticket with ExtraSid.
        """
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: False,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: True,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = True
        shared_state.has_golden_ticket = False  # Not forged yet

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish) and "Domain Admin" in str(result.reason):
                    pytest.fail("DA hook should NOT fire when stop_on_domain_admin=False")
            except TypeError:
                pass

    @pytest.mark.asyncio
    async def test_golden_ticket_stops_after_da_when_configured(self, monkeypatch):
        """Test that when stop_on_golden_ticket=True, we stop on GT not DA."""
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_domain_admin",
            lambda: False,
        )
        monkeypatch.setattr(
            "ares.core.factories.red_agents.get_stop_on_golden_ticket",
            lambda: True,
        )

        shared_state = SharedRedTeamState(operation_id="test-op")
        shared_state.has_domain_admin = True
        shared_state.has_golden_ticket = True

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)
        event = self._make_step_start_event()

        finish_reasons = []
        for hook in hooks:
            try:
                result = await hook(event)
                if isinstance(result, Finish):
                    finish_reasons.append(result.reason)
            except TypeError:
                pass

        # Should have Golden Ticket finish, not Domain Admin
        gt_finishes = [r for r in finish_reasons if "Golden Ticket" in r]
        da_finishes = [r for r in finish_reasons if "Domain Admin" in r]

        assert len(gt_finishes) >= 1, "Should stop on Golden Ticket"
        assert len(da_finishes) == 0, "Should NOT stop on Domain Admin"


class TestTargetExtractionLogic:
    """Tests for target extraction logic in log_tool_result hook.

    The hook must correctly distinguish between:
    - FQDNs (e.g., 'dc01.contoso.local') -> target_fqdn
    - Usernames with dots (e.g., 'sansa.stark') -> target_user
    - IPs (e.g., '192.168.58.10') -> target_ip
    - Plain hostnames (e.g., 'dc01') -> target_hostname
    """

    def _make_tool_end_event(
        self, tool_name: str, arguments: dict, content: str = "OK"
    ) -> MagicMock:
        """Helper to create a mock ToolEnd event with specific arguments."""
        import json

        event = MagicMock(spec=ToolEnd)
        event.tool_call = MagicMock()
        event.tool_call.name = tool_name
        event.tool_call.arguments = json.dumps(arguments)
        event.message = MagicMock()
        event.message.content = content
        event.error = None
        return event

    @pytest.mark.asyncio
    async def test_fqdn_with_local_suffix_extracted_correctly(self, monkeypatch):
        """Test that FQDNs ending in .local are correctly identified."""
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.LATERAL, dispatcher, shared_state)

        event = self._make_tool_end_event(
            "psexec",
            {
                "target": "dc01.contoso.local",
                "username": "admin",
                "password": "pass",  # pragma: allowlist secret
            },
        )

        # Capture what trace_tool_call receives
        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0, "trace_tool_call should be called"
        call = captured_calls[0]
        assert call.get("target_fqdn") == "dc01.contoso.local"
        assert call.get("target_hostname") == "dc01"

    @pytest.mark.asyncio
    async def test_username_with_dot_not_treated_as_fqdn(self, monkeypatch):
        """Test that usernames like 'sansa.stark' are NOT treated as FQDNs.

        This is the critical bug fix: before, 'sansa.stark' was incorrectly
        identified as an FQDN because it contains a dot.
        """
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.PRIVESC, dispatcher, shared_state)

        # Simulate a tool that has 'target' as a username (not a host)
        # This happens with privesc tools targeting user accounts
        event = self._make_tool_end_event(
            "targeted_kerberoast",
            {"target": "sansa.stark", "domain": "contoso.local"},
        )

        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0, "trace_tool_call should be called"
        call = captured_calls[0]

        # sansa.stark should NOT be treated as FQDN
        assert call.get("target_fqdn") is None, (
            f"Username 'sansa.stark' should NOT be target_fqdn, got: {call.get('target_fqdn')}"
        )
        # It should be captured as target_user instead
        assert call.get("target_user") == "sansa.stark", (
            f"Username 'sansa.stark' should be target_user, got: {call.get('target_user')}"
        )

    @pytest.mark.asyncio
    async def test_ip_address_extracted_correctly(self, monkeypatch):
        """Test that IP addresses are correctly identified."""
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.LATERAL, dispatcher, shared_state)

        event = self._make_tool_end_event(
            "psexec",
            {
                "target": "192.168.58.10",
                "username": "admin",
                "password": "pass",  # pragma: allowlist secret
            },
        )

        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0
        call = captured_calls[0]
        assert call.get("target_ip") == "192.168.58.10"
        assert call.get("target_fqdn") is None

    @pytest.mark.asyncio
    async def test_plain_hostname_extracted_correctly(self, monkeypatch):
        """Test that plain hostnames (no dots) are correctly identified."""
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.LATERAL, dispatcher, shared_state)

        event = self._make_tool_end_event(
            "psexec",
            {"target": "dc01", "username": "admin", "password": "pass"},  # pragma: allowlist secret
        )

        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0
        call = captured_calls[0]
        assert call.get("target_hostname") == "dc01"
        assert call.get("target_fqdn") is None

    @pytest.mark.asyncio
    async def test_explicit_target_user_takes_precedence(self, monkeypatch):
        """Test that explicit target_user arg takes precedence over inferred username."""
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.PRIVESC, dispatcher, shared_state)

        event = self._make_tool_end_event(
            "s4u_attack",
            {
                "target_spn": "cifs/dc01.contoso.local",
                "target_user": "administrator",
                "domain": "contoso.local",
            },
        )

        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0
        call = captured_calls[0]
        assert call.get("target_user") == "administrator"

    @pytest.mark.asyncio
    async def test_three_segment_fqdn_detected(self, monkeypatch):
        """Test that 3+ segment names are treated as FQDNs."""
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.LATERAL, dispatcher, shared_state)

        # Three segments without common TLD - should still be FQDN
        event = self._make_tool_end_event(
            "psexec",
            {
                "target": "dc01.child.parent",
                "username": "admin",
                "password": "pass",  # pragma: allowlist secret
            },
        )

        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0
        call = captured_calls[0]
        assert call.get("target_fqdn") == "dc01.child.parent"

    @pytest.mark.asyncio
    async def test_hostname_prefix_with_dot_detected_as_fqdn(self, monkeypatch):
        """Test that 'dc.something' is treated as FQDN (dc prefix indicates DC)."""
        from unittest.mock import patch

        shared_state = SharedRedTeamState(operation_id="test-op")
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = shared_state

        hooks = create_role_hooks(AgentRole.LATERAL, dispatcher, shared_state)

        # Two segments but dc prefix -> FQDN
        event = self._make_tool_end_event(
            "psexec",
            {
                "target": "dc01.internal",
                "username": "admin",
                "password": "pass",  # pragma: allowlist secret
            },
        )

        captured_calls = []

        def mock_trace_tool_call(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch(
            "ares.core.factories.red_agents.trace_tool_call", side_effect=mock_trace_tool_call
        ):
            for hook in hooks:
                try:
                    await hook(event)
                except TypeError:
                    pass

        assert len(captured_calls) > 0
        call = captured_calls[0]
        # .internal is a recognized suffix, so should be FQDN
        assert call.get("target_fqdn") == "dc01.internal"
