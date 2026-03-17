"""
Blue Team Operation Report Generator.

Produces consolidated markdown reports from multiple related investigations,
similar to the red team comprehensive report format.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ares.core.models import Evidence, InvestigationState, PyramidLevel, TimelineEvent
from ares.core.templates import get_template_loader

if TYPE_CHECKING:
    from ares.core.alert_correlation import AlertCluster


@dataclass
class BlueTeamOperation:
    """Aggregates multiple investigations into a single operation.

    Similar to SharedRedTeamState for red team operations, this provides
    a unified view of all investigations from a session or cluster.

    Attributes:
        operation_id: Unique identifier for this operation.
        started_at: When the operation began.
        completed_at: When the operation ended.
        investigations: List of individual investigation states.
        cluster: Optional alert cluster this operation is based on.
    """

    operation_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    investigations: list[InvestigationState] = field(default_factory=list)
    cluster: AlertCluster | None = None

    def add_investigation(self, state: InvestigationState) -> None:
        """Add an investigation to this operation."""
        self.investigations.append(state)
        self.started_at = min(self.started_at, state.started_at)

    @property
    def all_evidence(self) -> list[Evidence]:
        """Get all evidence across all investigations, deduplicated."""
        seen: set[str] = set()
        result = []
        for inv in self.investigations:
            for ev in inv.evidence:
                if ev.id not in seen:
                    seen.add(ev.id)
                    result.append(ev)
        return result

    @property
    def all_timeline_events(self) -> list[TimelineEvent]:
        """Get all timeline events across investigations, sorted by timestamp."""
        events = []
        for inv in self.investigations:
            events.extend(inv.timeline)
        return sorted(events, key=lambda e: e.timestamp)

    @property
    def all_techniques(self) -> set[str]:
        """Get all MITRE techniques identified."""
        techniques = set()
        for inv in self.investigations:
            techniques.update(inv.identified_techniques)
        return techniques

    @property
    def all_tactics(self) -> set[str]:
        """Get all MITRE tactics identified."""
        tactics = set()
        for inv in self.investigations:
            tactics.update(inv.identified_tactics)
        return tactics

    @property
    def all_hosts(self) -> set[str]:
        """Get all hosts investigated."""
        hosts = set()
        for inv in self.investigations:
            hosts.update(inv.queried_hosts)
        return hosts

    @property
    def all_users(self) -> set[str]:
        """Get all users investigated."""
        users = set()
        for inv in self.investigations:
            users.update(inv.queried_users)
        return users

    @property
    def all_alerts(self) -> list[dict[str, Any]]:
        """Get all alerts that triggered investigations."""
        return [inv.alert for inv in self.investigations if inv.alert]

    @property
    def highest_pyramid_level(self) -> int:
        """Get the highest pyramid level achieved across all investigations."""
        if not self.all_evidence:
            return 0
        return max(e.pyramid_level.value for e in self.all_evidence)

    @property
    def ttp_count(self) -> int:
        """Count of TTP-level evidence items."""
        return len([e for e in self.all_evidence if e.pyramid_level == PyramidLevel.TTPS])

    @property
    def escalation_count(self) -> int:
        """Count of escalated investigations."""
        return sum(1 for inv in self.investigations if inv.escalated)

    @property
    def all_recommendations(self) -> list[str]:
        """Get all unique recommendations."""
        seen = set()
        result = []
        for inv in self.investigations:
            for rec in inv.recommendations:
                if rec not in seen:
                    seen.add(rec)
                    result.append(rec)
        return result

    @property
    def attack_synopses(self) -> list[str]:
        """Get all attack synopses."""
        return [inv.attack_synopsis for inv in self.investigations if inv.attack_synopsis]

    def get_technique_names(self) -> dict[str, str]:
        """Get mapping of technique IDs to names."""
        names = {}
        for inv in self.investigations:
            names.update(inv.technique_names)
        return names

    def get_technique_to_tactic(self) -> dict[str, str]:
        """Get mapping of techniques to tactics."""
        mapping = {}
        for inv in self.investigations:
            mapping.update(inv.technique_to_tactic)
        return mapping

    def get_pyramid_distribution(self) -> dict[PyramidLevel, int]:
        """Get count of evidence at each pyramid level."""
        distribution: dict[PyramidLevel, int] = dict.fromkeys(PyramidLevel, 0)
        for ev in self.all_evidence:
            distribution[ev.pyramid_level] += 1
        return distribution

    def to_summary(self) -> dict[str, Any]:
        """Generate operation summary."""
        return {
            "operation_id": self.operation_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "investigation_count": len(self.investigations),
            "alert_count": len(self.all_alerts),
            "evidence_count": len(self.all_evidence),
            "technique_count": len(self.all_techniques),
            "highest_pyramid_level": self.highest_pyramid_level,
            "ttp_count": self.ttp_count,
            "escalation_count": self.escalation_count,
            "hosts_investigated": list(self.all_hosts),
            "users_investigated": list(self.all_users),
        }


class BlueTeamReportGenerator:
    """Generates consolidated markdown reports from blue team operations.

    Attributes:
        loader: Template loader for rendering report sections.
    """

    def __init__(self):
        self.loader = get_template_loader()

    def generate(self, operation: BlueTeamOperation) -> str:
        """Generate the full markdown report.

        Args:
            operation: Blue team operation containing all investigations.

        Returns:
            Complete markdown report as a string.
        """
        # Use persisted completed_at if available
        completed_at = operation.completed_at or datetime.now(timezone.utc)
        duration = completed_at - operation.started_at
        duration_str = str(duration).split(".")[0]

        alert_summaries = []
        for inv in operation.investigations:
            alert = inv.alert if isinstance(inv.alert, dict) else {}
            labels = alert.get("labels", {})
            alert_summaries.append(
                {
                    "investigation_id": inv.investigation_id,
                    "alert_name": labels.get("alertname", "Unknown"),
                    "severity": labels.get("severity", "unknown"),
                    "escalated": inv.escalated,
                    "evidence_count": len(inv.evidence),
                    "highest_pyramid_level": inv.highest_pyramid_level,
                    "techniques": list(inv.identified_techniques),
                }
            )

        evidence_by_level: dict[int, list[dict[str, Any]]] = {i: [] for i in range(1, 7)}
        for ev in operation.all_evidence:
            evidence_by_level[ev.pyramid_level.value].append(
                {
                    "id": ev.id,
                    "type": ev.type,
                    "value": ev.value[:80] + "..." if len(ev.value) > 80 else ev.value,
                    "source": ev.source,
                    "techniques": ev.mitre_techniques[:3] if ev.mitre_techniques else [],
                    "confidence": ev.confidence,
                }
            )

        timeline = []
        for event in operation.all_timeline_events:
            timeline.append(
                {
                    "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "description": event.description,
                    "mitre_techniques": event.mitre_techniques,
                    "confidence": event.confidence,
                }
            )

        technique_names = operation.get_technique_names()
        technique_to_tactic = operation.get_technique_to_tactic()
        techniques = []
        for tech_id in sorted(operation.all_techniques):
            techniques.append(
                {
                    "id": tech_id,
                    "name": technique_names.get(tech_id, tech_id),
                    "tactic": technique_to_tactic.get(tech_id, "Unknown"),
                }
            )

        tactics = sorted(operation.all_tactics)

        # Pyramid distribution (convert enum keys to int for template)
        pyramid_dist = {
            level.value: count for level, count in operation.get_pyramid_distribution().items()
        }

        investigation_details = []
        for inv in operation.investigations:
            alert = inv.alert if isinstance(inv.alert, dict) else {}
            labels = alert.get("labels", {})

            detail = {
                "investigation_id": inv.investigation_id,
                "alert_name": labels.get("alertname", "Unknown"),
                "severity": labels.get("severity", "unknown"),
                "status": "ESCALATED" if inv.escalated else "Completed",
                "evidence_count": len(inv.evidence),
                "techniques": list(inv.identified_techniques),
                "alert_payload": json.dumps(alert, indent=2, default=str) if alert else None,
                "queries": [
                    {
                        "type": q.get("type", "unknown"),
                        "query": q.get("query", "N/A"),
                        "result_count": q.get("result_count", 0),
                    }
                    for q in inv.executed_queries
                ],
            }
            investigation_details.append(detail)

        return self.loader.render(
            "blueteam/reports/comprehensive_report.md.jinja",
            operation_id=operation.operation_id,
            started_at=operation.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            completed_at=completed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration=duration_str,
            # Counts
            investigation_count=len(operation.investigations),
            alert_count=len(operation.all_alerts),
            evidence_count=len(operation.all_evidence),
            technique_count=len(operation.all_techniques),
            tactic_count=len(tactics),
            host_count=len(operation.all_hosts),
            user_count=len(operation.all_users),
            highest_pyramid_level=operation.highest_pyramid_level,
            ttp_count=operation.ttp_count,
            escalation_count=operation.escalation_count,
            # Details
            alert_summaries=alert_summaries,
            evidence_by_level=evidence_by_level,
            timeline=timeline,
            techniques=techniques,
            tactics=tactics,
            hosts=sorted(operation.all_hosts),
            users=sorted(operation.all_users),
            recommendations=operation.all_recommendations,
            attack_synopses=operation.attack_synopses,
            pyramid_distribution=pyramid_dist,
            # Per-investigation appendix
            investigation_details=investigation_details,
            # Metadata
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )


def generate_operation_report(operation: BlueTeamOperation) -> str:
    """Generate a comprehensive markdown report from BlueTeamOperation.

    This is the main entry point for generating consolidated blue team reports.

    Args:
        operation: BlueTeamOperation containing all investigation data.

    Returns:
        Complete markdown report as a string.
    """
    generator = BlueTeamReportGenerator()
    return generator.generate(operation)


def create_operation_from_investigations(
    investigations: list[InvestigationState],
    operation_id: str | None = None,
    cluster: AlertCluster | None = None,
) -> BlueTeamOperation:
    """Create a BlueTeamOperation from a list of investigations.

    Args:
        investigations: List of investigation states to aggregate.
        operation_id: Optional operation ID (auto-generated if not provided).
        cluster: Optional alert cluster these investigations belong to.

    Returns:
        BlueTeamOperation aggregating all investigations.
    """
    if not investigations:
        raise ValueError("At least one investigation is required")

    if operation_id is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        operation_id = f"blue-op-{timestamp}"

    # Find time bounds
    started_at = min(inv.started_at for inv in investigations)

    return BlueTeamOperation(
        operation_id=operation_id,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
        investigations=list(investigations),
        cluster=cluster,
    )
