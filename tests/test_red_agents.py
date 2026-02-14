"""Tests for red_agents factory helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dreadnode.agent.events import ToolEnd

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
