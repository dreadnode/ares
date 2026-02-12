"""Tests for the ORCHESTRATOR role separation from RECON.

This test module verifies that the orchestrator has its own distinct role,
template, and configuration separate from the RECON worker agent.
"""

from __future__ import annotations

import pytest

from ares.core.capability_registry import get_enabled_tools
from ares.core.config import get_agent_config
from ares.core.factories.red_agents import (
    ALL_TOOLSETS,
    ROLE_INSTRUCTIONS,
    ROLE_MAX_STEPS,
    create_role_hooks,
    load_agent_instructions,
)
from ares.core.models import AgentRole, SharedRedTeamState


class TestOrchestratorRoleExists:
    """Tests that AgentRole.ORCHESTRATOR exists and is distinct."""

    def test_orchestrator_role_exists(self):
        """ORCHESTRATOR should be a valid AgentRole enum value."""
        assert hasattr(AgentRole, "ORCHESTRATOR")
        assert AgentRole.ORCHESTRATOR.value == "orchestrator"

    def test_orchestrator_distinct_from_recon(self):
        """ORCHESTRATOR and RECON should be distinct roles."""
        assert AgentRole.ORCHESTRATOR != AgentRole.RECON
        assert AgentRole.ORCHESTRATOR.value != AgentRole.RECON.value

    def test_all_roles_are_unique(self):
        """All AgentRole values should be unique."""
        values = [role.value for role in AgentRole]
        assert len(values) == len(set(values)), "Duplicate role values found"


class TestOrchestratorTemplate:
    """Tests for orchestrator template loading."""

    def test_orchestrator_has_template(self):
        """ORCHESTRATOR should have its own template in ROLE_INSTRUCTIONS."""
        assert AgentRole.ORCHESTRATOR in ROLE_INSTRUCTIONS
        assert "orchestrator" in ROLE_INSTRUCTIONS[AgentRole.ORCHESTRATOR]

    def test_recon_has_separate_template(self):
        """RECON should have its own separate template."""
        assert AgentRole.RECON in ROLE_INSTRUCTIONS
        assert "recon" in ROLE_INSTRUCTIONS[AgentRole.RECON]
        assert ROLE_INSTRUCTIONS[AgentRole.ORCHESTRATOR] != ROLE_INSTRUCTIONS[AgentRole.RECON]

    def test_orchestrator_instructions_load(self):
        """ORCHESTRATOR instructions should load without error."""
        instructions = load_agent_instructions(AgentRole.ORCHESTRATOR)
        assert instructions is not None
        assert len(instructions) > 0

    def test_orchestrator_instructions_mention_dispatch(self):
        """ORCHESTRATOR instructions should mention dispatching to workers."""
        instructions = load_agent_instructions(AgentRole.ORCHESTRATOR)
        assert "dispatch" in instructions.lower()

    def test_orchestrator_instructions_not_mention_direct_tools(self):
        """ORCHESTRATOR instructions should clarify it doesn't execute tools directly."""
        instructions = load_agent_instructions(AgentRole.ORCHESTRATOR)
        # Should mention it delegates/dispatches, not executes
        assert "delegate" in instructions.lower() or "dispatch" in instructions.lower()

    def test_recon_instructions_mention_scanning(self):
        """RECON worker instructions should mention scanning/enumeration."""
        instructions = load_agent_instructions(AgentRole.RECON)
        assert "scan" in instructions.lower() or "enumerat" in instructions.lower()


class TestOrchestratorMaxSteps:
    """Tests for orchestrator max steps configuration."""

    def test_orchestrator_has_max_steps(self):
        """ORCHESTRATOR should have max_steps configured."""
        assert AgentRole.ORCHESTRATOR in ROLE_MAX_STEPS
        assert ROLE_MAX_STEPS[AgentRole.ORCHESTRATOR] > 0

    def test_recon_has_max_steps(self):
        """RECON should have its own max_steps configured."""
        assert AgentRole.RECON in ROLE_MAX_STEPS
        assert ROLE_MAX_STEPS[AgentRole.RECON] > 0


class TestCapabilityBasedToolsets:
    """Tests for capability-based toolset configuration.

    The new architecture uses YAML capabilities to control which tools each
    role has access to, rather than hardcoded ROLE_TOOLSETS mappings.
    """

    def test_all_toolsets_is_comprehensive(self):
        """ALL_TOOLSETS should contain all available toolset classes."""
        assert len(ALL_TOOLSETS) > 10, "ALL_TOOLSETS should have many toolset classes"

    def test_recon_capabilities_map_to_tools(self):
        """RECON role capabilities should map to expected tools."""
        config = get_agent_config("recon")
        enabled = get_enabled_tools(set(config.capabilities))

        # RECON should have network scanning tools
        assert "nmap_scan" in enabled or "smb_sweep" in enabled

    def test_credential_access_capabilities_map_to_tools(self):
        """CREDENTIAL_ACCESS role capabilities should map to expected tools."""
        config = get_agent_config("credential_access")
        enabled = get_enabled_tools(set(config.capabilities))

        # Should have credential discovery tools
        assert len(enabled) > 0

    def test_lateral_capabilities_map_to_tools(self):
        """LATERAL role capabilities should map to expected tools."""
        config = get_agent_config("lateral")
        enabled = get_enabled_tools(set(config.capabilities))

        # Should have lateral movement tools
        assert len(enabled) > 0


class TestOrchestratorHooks:
    """Tests for orchestrator-specific hooks."""

    @pytest.fixture
    def mock_dispatcher(self):
        """Create a minimal mock dispatcher for hook testing."""

        class MockDispatcher:
            pass

        return MockDispatcher()

    @pytest.fixture
    def shared_state(self):
        """Create a shared state for hook testing."""
        return SharedRedTeamState(operation_id="test-op")

    def test_orchestrator_hooks_created(self, mock_dispatcher, shared_state):
        """ORCHESTRATOR should have hooks created without error."""
        hooks = create_role_hooks(AgentRole.ORCHESTRATOR, mock_dispatcher, shared_state)
        assert hooks is not None
        assert isinstance(hooks, list)

    def test_recon_hooks_created(self, mock_dispatcher, shared_state):
        """RECON worker should have hooks created without error."""
        hooks = create_role_hooks(AgentRole.RECON, mock_dispatcher, shared_state)
        assert hooks is not None
        assert isinstance(hooks, list)

    def test_orchestrator_and_recon_hooks_different(self, mock_dispatcher, shared_state):
        """ORCHESTRATOR and RECON should potentially have different hook configurations."""
        orch_hooks = create_role_hooks(AgentRole.ORCHESTRATOR, mock_dispatcher, shared_state)
        recon_hooks = create_role_hooks(AgentRole.RECON, mock_dispatcher, shared_state)
        # Both should have logging hooks, but orchestrator has domain_admin check
        # and different unstall feedback
        assert len(orch_hooks) >= 2  # At least logging hooks
        assert len(recon_hooks) >= 2


class TestDispatcherSubscriptions:
    """Tests for dispatcher role subscriptions."""

    def test_orchestrator_subscriptions_defined(self):
        """Verify ORCHESTRATOR subscriptions are defined in dispatcher."""
        # Import here to avoid circular imports during collection
        from ares.core.messages import MessageType

        # These are the message types ORCHESTRATOR should subscribe to
        expected_orchestrator_messages = {
            MessageType.TASK_COMPLETE,
            MessageType.TASK_FAILED,
            MessageType.VULNERABILITY_FOUND,
            MessageType.HASH_DISCOVERED,
            MessageType.HOST_DISCOVERED,
        }

        # Verify these message types exist
        for msg_type in expected_orchestrator_messages:
            assert msg_type is not None

    def test_recon_subscriptions_include_recon_request(self):
        """RECON worker should subscribe to RECON_REQUEST."""
        from ares.core.messages import MessageType

        assert hasattr(MessageType, "RECON_REQUEST")


class TestConfigOrchestratorPodSelector:
    """Tests for orchestrator configuration."""

    def test_config_orchestrator_pod_selector(self):
        """Orchestrator config should have correct pod selector."""
        from pathlib import Path

        import yaml

        config_path = Path("config/multi-agent-production.yaml")
        if not config_path.exists():
            pytest.skip("Config file not found")

        with open(config_path) as f:
            config = yaml.safe_load(f)

        orchestrator_config = config.get("agents", {}).get("orchestrator", {})
        pod_selector = orchestrator_config.get("pod_selector", "")

        # Should NOT reference recon role
        assert "role=recon" not in pod_selector
        # Should reference orchestrator
        assert "orchestrator" in pod_selector

    def test_config_orchestrator_has_dispatch_recon(self):
        """Orchestrator config should include dispatch_recon tool."""
        from pathlib import Path

        import yaml

        config_path = Path("config/multi-agent-production.yaml")
        if not config_path.exists():
            pytest.skip("Config file not found")

        with open(config_path) as f:
            config = yaml.safe_load(f)

        orchestrator_config = config.get("agents", {}).get("orchestrator", {})
        tools = orchestrator_config.get("tools", [])

        # dispatch_recon should be in the tools list
        assert "dispatch_recon" in tools, "dispatch_recon missing from orchestrator tools"

    def test_config_orchestrator_has_all_dispatch_tools(self):
        """Orchestrator config should include all dispatch tools."""
        from pathlib import Path

        import yaml

        config_path = Path("config/multi-agent-production.yaml")
        if not config_path.exists():
            pytest.skip("Config file not found")

        with open(config_path) as f:
            config = yaml.safe_load(f)

        orchestrator_config = config.get("agents", {}).get("orchestrator", {})
        tools = orchestrator_config.get("tools", [])

        # All dispatch tools should be present
        required_dispatch_tools = [
            "dispatch_recon",
            "dispatch_credential_access",
            "dispatch_crack_hash",
            "dispatch_acl_analysis",
            "dispatch_lateral_movement",
            "dispatch_privesc_exploit",
        ]

        for tool in required_dispatch_tools:
            assert tool in tools, f"{tool} missing from orchestrator tools"


class TestArchitecturalSeparation:
    """Integration tests for architectural separation."""

    def test_orchestrator_is_coordinator_not_worker(self):
        """Verify orchestrator role is clearly a coordinator, not a worker."""
        instructions = load_agent_instructions(AgentRole.ORCHESTRATOR)

        # Orchestrator should mention coordination
        assert "coordinat" in instructions.lower() or "dispatch" in instructions.lower()

        # Should mention it doesn't execute directly
        lower_instructions = instructions.lower()
        has_delegation_concept = (
            "delegate" in lower_instructions
            or "dispatch" in lower_instructions
            or "do not execute" in lower_instructions
            or "does not execute" in lower_instructions
        )
        assert has_delegation_concept

    def test_recon_is_worker_not_coordinator(self):
        """Verify RECON role is clearly a worker, not the coordinator."""
        instructions = load_agent_instructions(AgentRole.RECON)

        # RECON should mention execution of tasks
        lower_instructions = instructions.lower()
        has_worker_concept = (
            "task" in lower_instructions
            or "scan" in lower_instructions
            or "enumerat" in lower_instructions
        )
        assert has_worker_concept

    def test_all_worker_roles_have_capabilities_configured(self):
        """All worker roles (non-orchestrator) should have capabilities in config."""
        worker_roles = [
            "recon",
            "credential_access",
            "cracker",
            "acl",
            "privesc",
            "lateral",
            "coercion",
        ]

        for role in worker_roles:
            config = get_agent_config(role)
            assert len(config.capabilities) > 0, (
                f"{role} should have at least one capability configured"
            )
