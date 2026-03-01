"""Blue team investigation tools.

Imports are lazy to prevent loading blue team code in red team contexts.
"""

__all__ = [
    "BlueWorkerCallbackTools",
    "CompletionTools",
    "EscalationTriageTools",
    "GrafanaTools",
    "InvestigationTools",
    "LearningTools",
    "LokiTools",
    "PrometheusTools",
    "QueryTemplateTools",
    "QuestionEngineTools",
    "SharedInvestigationTools",
    "connect_grafana_mcp",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "BlueWorkerCallbackTools": ("ares.tools.blue.callbacks", "BlueWorkerCallbackTools"),
    "CompletionTools": ("ares.tools.blue.actions", "CompletionTools"),
    "EscalationTriageTools": ("ares.tools.blue.triage_tools", "EscalationTriageTools"),
    "GrafanaTools": ("ares.tools.blue.grafana", "GrafanaTools"),
    "connect_grafana_mcp": ("ares.tools.blue.grafana", "connect_grafana_mcp"),
    "InvestigationTools": ("ares.tools.blue.investigation", "InvestigationTools"),
    "QuestionEngineTools": ("ares.tools.blue.investigation", "QuestionEngineTools"),
    "LearningTools": ("ares.tools.blue.learning", "LearningTools"),
    "LokiTools": ("ares.tools.blue.observability", "LokiTools"),
    "PrometheusTools": ("ares.tools.blue.observability", "PrometheusTools"),
    "QueryTemplateTools": ("ares.tools.blue.query_templates", "QueryTemplateTools"),
    "SharedInvestigationTools": ("ares.tools.blue.shared_wrappers", "SharedInvestigationTools"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, attr_name)

    raise AttributeError(f"module 'ares.tools.blue' has no attribute {name!r}")
