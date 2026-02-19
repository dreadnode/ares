"""Report generators for investigations and red team operations."""

from ares.reports.blueteam import (
    BlueTeamOperation,
    BlueTeamReportGenerator,
    create_operation_from_investigations,
    generate_operation_report,
)
from ares.reports.investigation import MarkdownReportGenerator
from ares.reports.redteam import RedTeamReportGenerator, generate_comprehensive_report

__all__ = [
    "BlueTeamOperation",
    "BlueTeamReportGenerator",
    "MarkdownReportGenerator",
    "RedTeamReportGenerator",
    "create_operation_from_investigations",
    "generate_comprehensive_report",
    "generate_operation_report",
]
