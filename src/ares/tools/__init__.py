"""Tools for Ares SOC Investigation and Red Team Agents."""

from ares.tools.blue.actions import CompletionTools, escalate_investigation
from ares.tools.blue.grafana import GrafanaTools, connect_grafana_mcp
from ares.tools.blue.investigation import InvestigationTools, QuestionEngineTools
from ares.tools.blue.observability import LokiTools, PrometheusTools
from ares.tools.shared.mitre import MITRELookupTools

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
