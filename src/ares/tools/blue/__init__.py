"""Blue team investigation tools."""

from ares.tools.blue.actions import CompletionTools, escalate_investigation
from ares.tools.blue.grafana import GrafanaTools, connect_grafana_mcp
from ares.tools.blue.investigation import InvestigationTools, QuestionEngineTools
from ares.tools.blue.observability import LokiTools, PrometheusTools
from ares.tools.blue.query_templates import QueryTemplateTools

__all__ = [
    "CompletionTools",
    "GrafanaTools",
    "InvestigationTools",
    "LokiTools",
    "PrometheusTools",
    "QueryTemplateTools",
    "QuestionEngineTools",
    "connect_grafana_mcp",
    "escalate_investigation",
]
