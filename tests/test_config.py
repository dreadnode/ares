"""Tests for configuration module."""

import os
from unittest.mock import patch

import pytest

from ares.core.config import AgentConfig, _apply_env_overrides


class TestModelResolution:
    """Tests for model resolution from environment variables."""

    def test_resolve_role_specific_model_override(self):
        """Test role-specific model override takes precedence."""
        config_data = {
            "agents": {
                "recon": {"model": "default-model"},
                "orchestrator": {"model": "default-orchestrator"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_AGENT_RECON_MODEL": "role-specific-model",
                "ARES_WORKER_MODEL": "worker-model",
                "ARES_MODEL": "global-model",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            # Role-specific should win
            assert config.agents["recon"].model == "role-specific-model"

    def test_orchestrator_model_override(self):
        """Test ARES_ORCHESTRATOR_MODEL applies to orchestrator role."""
        config_data = {
            "agents": {
                "orchestrator": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_ORCHESTRATOR_MODEL": "orchestrator-specific",
                "ARES_MODEL": "global-model",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            assert config.agents["orchestrator"].model == "orchestrator-specific"

    def test_worker_model_override_for_non_orchestrator(self):
        """Test ARES_WORKER_MODEL applies to worker roles but not orchestrator."""
        config_data = {
            "agents": {
                "recon": {"model": "default-recon"},
                "cracker": {"model": "default-cracker"},
                "orchestrator": {"model": "default-orchestrator"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_WORKER_MODEL": "worker-model",
                "ARES_MODEL": "global-model",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            # Workers should use ARES_WORKER_MODEL
            assert config.agents["recon"].model == "worker-model"
            assert config.agents["cracker"].model == "worker-model"
            # Orchestrator should use ARES_MODEL (not ARES_WORKER_MODEL)
            assert config.agents["orchestrator"].model == "global-model"

    def test_global_model_override(self):
        """Test ARES_MODEL applies as fallback for all roles."""
        config_data = {
            "agents": {
                "recon": {"model": "default-model"},
                "orchestrator": {"model": "default-orchestrator"},
            }
        }

        with patch.dict(
            os.environ,
            {"ARES_MODEL": "global-override"},
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            assert config.agents["recon"].model == "global-override"
            assert config.agents["orchestrator"].model == "global-override"

    def test_precedence_role_over_worker(self):
        """Test role-specific overrides worker-level override."""
        config_data = {
            "agents": {
                "recon": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_AGENT_RECON_MODEL": "recon-specific",
                "ARES_WORKER_MODEL": "worker-level",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            assert config.agents["recon"].model == "recon-specific"

    def test_precedence_worker_over_global(self):
        """Test worker-level override takes precedence over global."""
        config_data = {
            "agents": {
                "cracker": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_WORKER_MODEL": "worker-level",
                "ARES_MODEL": "global-level",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            assert config.agents["cracker"].model == "worker-level"

    def test_precedence_orchestrator_over_global(self):
        """Test orchestrator-level override takes precedence over global."""
        config_data = {
            "agents": {
                "orchestrator": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_ORCHESTRATOR_MODEL": "orchestrator-level",
                "ARES_MODEL": "global-level",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            assert config.agents["orchestrator"].model == "orchestrator-level"

    def test_no_override_uses_config_default(self):
        """Test that without overrides, config defaults are used."""
        config_data = {
            "agents": {
                "recon": {"model": "config-default"},
            }
        }

        with patch.dict(os.environ, {}, clear=False):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            assert config.agents["recon"].model == "config-default"

    def test_add_role_from_env_variable(self):
        """Test that role-specific env creates agent config if not in file."""
        config_data = {
            "agents": {
                "recon": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_AGENT_NEWROLE_MODEL": "newrole-model",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            # Should have created newrole agent
            assert "newrole" in config.agents
            assert config.agents["newrole"].model == "newrole-model"

    def test_env_variable_case_insensitive_for_role(self):
        """Test that role name in env variable is case-insensitive."""
        config_data = {
            "agents": {
                "recon": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_AGENT_CRACKER_MODEL": "cracker-model",  # uppercase in env
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            # Should create with lowercase role name
            assert "cracker" in config.agents
            assert config.agents["cracker"].model == "cracker-model"

    def test_empty_env_variable_ignored(self):
        """Test that empty environment variables are ignored."""
        config_data = {
            "agents": {
                "recon": {"model": "default-model"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_MODEL": "",  # Empty value
                "ARES_WORKER_MODEL": "",
                "ARES_AGENT_RECON_MODEL": "",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            # Should keep config default since env is empty
            assert config.agents["recon"].model == "default-model"

    def test_model_resolution_from_config_with_env_vars(self):
        """Test that model can be specified with env vars in config file."""
        config_data = {
            "agents": {
                "recon": {"model": "${ARES_CUSTOM_MODEL}"},
            }
        }

        with patch.dict(
            os.environ,
            {"ARES_CUSTOM_MODEL": "custom-from-env"},
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)

            # _resolve_env should have been applied during build
            assert config.agents["recon"].model == "custom-from-env"

    def test_multiple_agents_with_different_overrides(self):
        """Test complex scenario with multiple agents and override levels."""
        config_data = {
            "agents": {
                "recon": {"model": "default-recon"},
                "cracker": {"model": "default-cracker"},
                "orchestrator": {"model": "default-orchestrator"},
                "lateral": {"model": "default-lateral"},
            }
        }

        with patch.dict(
            os.environ,
            {
                "ARES_MODEL": "global-model",
                "ARES_WORKER_MODEL": "worker-model",
                "ARES_ORCHESTRATOR_MODEL": "orchestrator-model",
                "ARES_AGENT_CRACKER_MODEL": "cracker-specific",
            },
            clear=False,
        ):
            from ares.core.config import _build_config

            config = _build_config(config_data)
            config = _apply_env_overrides(config)

            # recon: worker-model (no role-specific, uses worker)
            assert config.agents["recon"].model == "worker-model"
            # cracker: cracker-specific (role-specific wins)
            assert config.agents["cracker"].model == "cracker-specific"
            # orchestrator: orchestrator-model (orchestrator-specific)
            assert config.agents["orchestrator"].model == "orchestrator-model"
            # lateral: worker-model (no role-specific, uses worker)
            assert config.agents["lateral"].model == "worker-model"


class TestAgentConfig:
    """Tests for AgentConfig model."""

    def test_agent_config_defaults(self):
        """Test AgentConfig uses proper defaults."""
        agent = AgentConfig(model="test-model")
        assert agent.model == "test-model"
        assert agent.max_steps == 100
        assert agent.pod_selector == ""
        assert agent.capabilities == []

    def test_agent_config_custom_values(self):
        """Test AgentConfig with custom values."""
        agent = AgentConfig(
            model="custom-model",
            max_steps=50,
            pod_selector="app=test",
            capabilities=["cap1", "cap2"],
        )
        assert agent.model == "custom-model"
        assert agent.max_steps == 50
        assert agent.pod_selector == "app=test"
        assert agent.capabilities == ["cap1", "cap2"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
