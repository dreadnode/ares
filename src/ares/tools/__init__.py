"""Tools for Ares SOC Investigation and Red Team Agents.

Imports are lazy to prevent blue team tools from being loaded in red team contexts.
"""

__all__ = [
    # Blue team tools
    "CompletionTools",
    "GrafanaTools",
    "InvestigationTools",
    "LokiTools",
    "MITRELookupTools",
    "PrometheusTools",
    "QuestionEngineTools",
    "connect_grafana_mcp",
    "escalate_investigation",
    # Red team tools imported separately as needed
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "CompletionTools": ("ares.tools.blue.actions", "CompletionTools"),
    "escalate_investigation": ("ares.tools.blue.actions", "escalate_investigation"),
    "GrafanaTools": ("ares.tools.blue.grafana", "GrafanaTools"),
    "connect_grafana_mcp": ("ares.tools.blue.grafana", "connect_grafana_mcp"),
    "InvestigationTools": ("ares.tools.blue.investigation", "InvestigationTools"),
    "QuestionEngineTools": ("ares.tools.blue.investigation", "QuestionEngineTools"),
    "LokiTools": ("ares.tools.blue.observability", "LokiTools"),
    "PrometheusTools": ("ares.tools.blue.observability", "PrometheusTools"),
    "MITRELookupTools": ("ares.tools.shared.mitre", "MITRELookupTools"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, attr_name)

    raise AttributeError(f"module 'ares.tools' has no attribute {name!r}")
