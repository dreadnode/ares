"""Report generators for investigations and red team operations."""

from ares.reports.investigation import MarkdownReportGenerator
from ares.reports.redteam import RedTeamReportGenerator

__all__ = [
    "MarkdownReportGenerator",
    "RedTeamReportGenerator",
]
