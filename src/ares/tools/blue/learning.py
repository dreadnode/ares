"""
Learning tools for querying past investigations and improving detection.

These tools allow the agent to learn from previous investigations
and apply that knowledge to new alerts.
"""

from typing import Any

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.persistence import InvestigationStore, get_investigation_store


class LearningTools(Toolset):  # type: ignore[misc]
    """Tools for learning from past investigations.

    Provides access to historical investigation data, query effectiveness
    statistics, and false positive patterns.

    Attributes:
        store: Optional investigation store (uses global store if not provided).
    """

    store: InvestigationStore | None = None

    def get_store(self) -> InvestigationStore:
        """Get the investigation store, initializing if needed."""
        if self.store is None:
            self.store = get_investigation_store()
        return self.store

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def find_similar_investigations(
        self,
        alert_name: str | None = None,
        technique_id: str | None = None,
        severity: str | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Find similar past investigations to learn from.

        Use this at the start of an investigation to see how similar alerts
        were handled in the past and what queries were effective.

        Args:
            alert_name: Name of the current alert
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003.001")
            severity: Alert severity level
            limit: Maximum number of results (default 5)

        Returns:
            Dictionary containing similar investigations and their outcomes
        """
        dn.log_metric("learning_similar_lookup", 1, mode="count")
        logger.info(
            f"Looking up similar investigations: alert={alert_name}, technique={technique_id}"
        )

        similar = self.get_store().find_similar_investigations(
            alert_name=alert_name,
            technique_id=technique_id,
            severity=severity,
            limit=limit,
        )

        if not similar:
            return {
                "found": False,
                "message": "No similar investigations found. This may be a new alert type.",
                "investigations": [],
            }

        results = []
        for sim in similar:
            inv = sim.investigation
            results.append(
                {
                    "investigation_id": inv.investigation_id,
                    "alert_name": inv.alert_name,
                    "technique_id": inv.technique_id,
                    "similarity_score": sim.similarity_score,
                    "matching_factors": sim.matching_factors,
                    "outcome": {
                        "status": inv.status,
                        "evidence_count": inv.evidence_count,
                        "highest_pyramid_level": inv.highest_pyramid_level,
                        "is_true_positive": inv.is_true_positive,
                    },
                    "duration_seconds": inv.duration_seconds,
                    "effective_queries": inv.effective_queries[:3],  # Top 3 effective queries
                    "techniques_identified": inv.techniques_identified,
                }
            )

        # Add summary guidance
        completed_count = sum(1 for s in similar if s.investigation.status == "completed")
        avg_evidence = sum(s.investigation.evidence_count for s in similar) / len(similar)

        true_positive_count = sum(1 for s in similar if s.investigation.is_true_positive is True)
        false_positive_count = sum(1 for s in similar if s.investigation.is_true_positive is False)

        return {
            "found": True,
            "count": len(results),
            "summary": {
                "completion_rate": f"{completed_count / len(similar) * 100:.0f}%",
                "avg_evidence_count": round(avg_evidence, 1),
                "true_positives": true_positive_count,
                "false_positives": false_positive_count,
            },
            "investigations": results,
            "guidance": self._generate_guidance(similar),
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_effective_queries(
        self,
        alert_name: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Get the most effective queries for this type of alert.

        Returns queries that have historically produced evidence,
        ranked by effectiveness.

        Args:
            alert_name: Filter by alert type (optional)
            limit: Maximum number of queries to return

        Returns:
            Dictionary with effective queries and their statistics
        """
        dn.log_metric("learning_query_lookup", 1, mode="count")
        logger.info(f"Looking up effective queries for alert: {alert_name}")

        effective = self.get_store().get_effective_queries(
            alert_type=alert_name,
            min_evidence_rate=0.2,  # At least 20% evidence rate
            limit=limit,
        )

        if not effective:
            return {
                "found": False,
                "message": "No query effectiveness data available yet.",
                "queries": [],
            }

        queries = []
        for qe in effective:
            queries.append(
                {
                    "query_pattern": qe.query_pattern,
                    "total_uses": qe.total_executions,
                    "success_rate": f"{qe.success_rate * 100:.0f}%",
                    "evidence_rate": f"{qe.evidence_rate * 100:.0f}%",
                    "used_for_alerts": qe.alert_types[:5],  # Limit alert types shown
                }
            )

        return {
            "found": True,
            "count": len(queries),
            "queries": queries,
            "recommendation": (
                "Use these queries as starting points. They have historically "
                "produced evidence for similar alerts. Adapt the patterns to "
                "your specific investigation context."
            ),
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def check_false_positive_pattern(
        self,
        alert_name: str,
        alert_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        """Check if this alert matches a known false positive pattern.

        Use this to quickly identify if an alert is likely a false positive
        based on historical data.

        Args:
            alert_name: Name of the alert
            alert_fingerprint: Unique fingerprint/rule UID of the alert

        Returns:
            Dictionary with false positive assessment
        """
        dn.log_metric("learning_fp_check", 1, mode="count")
        logger.info(f"Checking false positive patterns for: {alert_name}")

        # Check for similar false positives
        similar = self.get_store().find_similar_investigations(
            alert_name=alert_name,
            alert_fingerprint=alert_fingerprint,
            limit=20,
        )

        if not similar:
            return {
                "is_known_pattern": False,
                "message": "No historical data for this alert type.",
                "confidence": "low",
            }

        # Count true/false positives
        true_positives = sum(1 for s in similar if s.investigation.is_true_positive is True)
        false_positives = sum(1 for s in similar if s.investigation.is_true_positive is False)
        unlabeled = len(similar) - true_positives - false_positives

        # Calculate false positive likelihood
        if true_positives + false_positives > 0:
            fp_rate = false_positives / (true_positives + false_positives)
        else:
            fp_rate = 0.0

        # Check known FP patterns
        fp_patterns = self.get_store().get_false_positive_patterns(min_occurrences=2)
        matching_pattern = None
        for pattern in fp_patterns:
            if pattern["alert_name"] == alert_name:
                matching_pattern = pattern
                break

        if matching_pattern and matching_pattern["occurrences"] >= 3:
            return {
                "is_known_pattern": True,
                "confidence": "high",
                "false_positive_rate": f"{fp_rate * 100:.0f}%",
                "occurrences": matching_pattern["occurrences"],
                "pattern": matching_pattern,
                "recommendation": (
                    "This alert has been marked as false positive multiple times. "
                    "Consider quick validation and early completion if indicators match."
                ),
            }

        if fp_rate > 0.7:
            return {
                "is_known_pattern": True,
                "confidence": "medium",
                "false_positive_rate": f"{fp_rate * 100:.0f}%",
                "true_positives": true_positives,
                "false_positives": false_positives,
                "recommendation": (
                    "This alert type has a high false positive rate. "
                    "Prioritize quick validation queries before deep investigation."
                ),
            }

        return {
            "is_known_pattern": False,
            "confidence": "medium" if unlabeled < len(similar) / 2 else "low",
            "false_positive_rate": f"{fp_rate * 100:.0f}%",
            "true_positives": true_positives,
            "false_positives": false_positives,
            "unlabeled": unlabeled,
            "message": "No strong false positive pattern detected. Proceed with normal investigation.",
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_investigation_statistics(self) -> dict[str, Any]:
        """Get overall investigation statistics.

        Returns aggregated statistics about past investigations,
        useful for understanding overall detection performance.

        Returns:
            Dictionary with investigation statistics
        """
        dn.log_metric("learning_stats_lookup", 1, mode="count")

        stats = self.get_store().get_statistics()

        return {
            "total_investigations": stats["total_investigations"],
            "status_distribution": stats["status_distribution"],
            "performance": {
                "avg_evidence_count": stats["avg_evidence_count"],
                "avg_pyramid_level": stats["avg_pyramid_level"],
                "avg_duration_seconds": stats["avg_duration_seconds"],
            },
            "query_insights": {
                "total_query_patterns": stats["total_query_patterns"],
                "avg_evidence_rate": f"{stats['avg_query_evidence_rate']}%",
            },
            "labeling": stats["labeling"],
        }

    def _generate_guidance(self, similar: list) -> str:
        """Generate investigation guidance based on similar investigations."""
        if not similar:
            return "No historical guidance available."

        # Find most successful investigation
        completed = [s for s in similar if s.investigation.status == "completed"]
        if not completed:
            return "Previous investigations of this type did not complete successfully."

        # Get investigation with most evidence
        best = max(completed, key=lambda x: x.investigation.evidence_count)

        guidance_parts = []

        if best.investigation.evidence_count > 0:
            guidance_parts.append(
                f"Past investigations found an average of "
                f"{sum(s.investigation.evidence_count for s in completed) / len(completed):.1f} "
                f"evidence items."
            )

        if best.investigation.effective_queries:
            guidance_parts.append(
                f"Effective queries to try: {', '.join(best.investigation.effective_queries[:2])}"
            )

        # Check for common outcomes
        true_positive_rate = (
            sum(1 for s in similar if s.investigation.is_true_positive is True) / len(similar) * 100
            if similar
            else 0
        )

        if true_positive_rate > 70:
            guidance_parts.append(
                f"This alert type has a {true_positive_rate:.0f}% true positive rate - "
                "likely worth thorough investigation."
            )
        elif true_positive_rate < 30:
            guidance_parts.append(
                f"This alert type has only a {true_positive_rate:.0f}% true positive rate - "
                "consider quick validation first."
            )

        return (
            " ".join(guidance_parts)
            if guidance_parts
            else "Proceed with standard investigation approach."
        )
