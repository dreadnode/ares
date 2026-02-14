"""Agent factories for creating configured blue and red team agents.

Imports are lazy to prevent blue team factory from being loaded in red team contexts.
"""

__all__ = [
    # Multi-agent factories
    "ALL_TOOLSETS",
    "ROLE_CALLBACK_TOOLS",
    "UNIVERSAL_TOOLSETS",
    "create_agent_info",
    # Single-agent factories
    "create_investigation_agent",
    "create_multi_agent_ensemble",
    "create_redteam_agent",
    "create_role_hooks",
    "create_specialized_agent",
    "load_agent_instructions",
]


def __getattr__(name: str):
    # Blue team factory
    if name == "create_investigation_agent":
        from ares.core.factories.blue_factory import create_investigation_agent

        return create_investigation_agent

    # Red team factory (single-agent)
    if name == "create_redteam_agent":
        from ares.core.factories.red_factory import create_redteam_agent

        return create_redteam_agent

    # Red team multi-agent factories
    if name in (
        "ALL_TOOLSETS",
        "ROLE_CALLBACK_TOOLS",
        "UNIVERSAL_TOOLSETS",
        "create_agent_info",
        "create_multi_agent_ensemble",
        "create_role_hooks",
        "create_specialized_agent",
        "load_agent_instructions",
    ):
        from ares.core.factories import red_agents

        return getattr(red_agents, name)

    raise AttributeError(f"module 'ares.core.factories' has no attribute {name!r}")
