"""Report generators for investigations and red team operations."""

from ares.reports.blueteam import (
    BlueTeamOperation,
    BlueTeamReportGenerator,
    create_operation_from_investigations,
    generate_operation_report,
)
from ares.reports.investigation import MarkdownReportGenerator
from ares.reports.redteam import RedTeamReportGenerator, generate_comprehensive_report
from ares.reports.user_summary import (
    AttackChainStep,
    UserSummary,
    format_attack_chain,
    generate_user_summaries,
    trace_attack_chain,
)

__all__ = [
    "AttackChainStep",
    "BlueTeamOperation",
    "BlueTeamReportGenerator",
    "MarkdownReportGenerator",
    "RedTeamReportGenerator",
    "UserSummary",
    "create_operation_from_investigations",
    "format_attack_chain",
    "generate_comprehensive_report",
    "generate_operation_report",
    "generate_user_summaries",
    "trace_attack_chain",
]
