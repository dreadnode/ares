"""Tests for red_agents factory helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.config import AgentConfig
from ares.core.factories.red_agents import (
    create_agent_info,
    create_multi_agent_ensemble,
    load_agent_instructions,
)
from ares.core.models import AgentRole


@pytest.mark.asyncio
async def test_create_multi_agent_ensemble_requires_model(monkeypatch):
    monkeypatch.delenv("ARES_MODEL", raising=False)
    monkeypatch.delenv("ARES_ORCHESTRATOR_MODEL", raising=False)
    monkeypatch.delenv("ARES_WORKER_MODEL", raising=False)

    dispatcher = MagicMock(shared_state=SimpleNamespace())

    with pytest.raises(ValueError, match="No model specified"):
        await create_multi_agent_ensemble(
            operation_id="op-1",
            target_ip="192.168.56.1",
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
            target_ip="192.168.56.2",
            dispatcher=dispatcher,
            roles=[AgentRole.ORCHESTRATOR, AgentRole.CRACKER],
        )

    assert mock_create.call_count == 2
    assert mock_create.call_args_list[0].kwargs["model"] == "orch-model"
    assert mock_create.call_args_list[1].kwargs["model"] == "worker-model"


def test_create_specialized_agent_uses_set_state_when_shared_state_missing(monkeypatch):
    created: dict[str, MagicMock] = {}

    class DummyToolset:
        def __init__(self) -> None:
            self.set_state = MagicMock()
            created["instance"] = self

    monkeypatch.setattr(
        "ares.core.factories.red_agents.ROLE_TOOLSETS",
        {AgentRole.RECON: [DummyToolset]},
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

    created["instance"].set_state.assert_called_once_with(shared_state)


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

        # Test that privesc has the new tools we added
        privesc_config = get_agent_config("privesc")
        assert "sweetpotato" in privesc_config.capabilities
        assert "sharpgpoabuse" in privesc_config.capabilities
        assert "certipy" in privesc_config.capabilities

        # Test that recon has the impacket tools
        recon_config = get_agent_config("recon")
        assert "impacket-getnpusers" in recon_config.capabilities
        assert "impacket-secretsdump" in recon_config.capabilities

        # Test that credential_access has rpcclient
        cred_config = get_agent_config("credential_access")
        assert "rpcclient" in cred_config.capabilities
        assert "netexec" in cred_config.capabilities
        assert "ldapsearch" in cred_config.capabilities
        assert "smbclient" in cred_config.capabilities

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
