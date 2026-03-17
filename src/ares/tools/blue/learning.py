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

        true_positives = sum(1 for s in similar if s.investigation.is_true_positive is True)
        false_positives = sum(1 for s in similar if s.investigation.is_true_positive is False)
        unlabeled = len(similar) - true_positives - false_positives

        if true_positives + false_positives > 0:
            fp_rate = false_positives / (true_positives + false_positives)
        else:
            fp_rate = 0.0

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

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_attack_playbook(
        self,
        operation_id: str | None = None,
        redis_url: str | None = None,
    ) -> dict[str, Any]:
        """Load detection playbook from a red team operation.

        This gives you specific detection guidance based on what the red team
        actually did during their operation. Use this to build targeted
        detections for the exact techniques and IOCs discovered.

        Args:
            operation_id: Red team operation ID. If not provided, uses latest.
            redis_url: Redis URL for connecting to state backend.

        Returns:
            Dictionary containing:
            - attack_window: Start and end times of the attack
            - techniques_used: MITRE technique IDs used
            - priority_queries: Top LogQL queries to run (most important first)
            - detection_targets: IOCs with specific detection guidance
            - technique_detections: Per-technique detection advice
        """
        import os

        from ares.core.redis_client import create_redis_client

        dn.log_metric("learning_playbook_load", 1, mode="count")
        logger.info(f"Loading attack playbook for operation: {operation_id or 'latest'}")

        effective_redis_url = redis_url or os.environ.get(
            "ARES_REDIS_URL", "redis://localhost:6379"
        )

        try:
            client = await create_redis_client(effective_redis_url, decode_responses=False)

            # Find latest operation if not specified
            if not operation_id:
                # Look for most recent operation
                meta_keys = await client.keys("ares:op:*:meta")
                if not meta_keys:
                    await client.aclose()
                    return {
                        "found": False,
                        "error": "No red team operations found in Redis.",
                    }

                latest_op = None
                for key in meta_keys:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    parts = key_str.split(":")
                    if len(parts) >= 3:
                        op_id = parts[2]
                        if not latest_op or op_id > latest_op:
                            latest_op = op_id
                operation_id = latest_op

            if not operation_id:
                await client.aclose()
                return {"found": False, "error": "Could not determine operation ID."}

            from ares.cli_ops import _load_state_from_redis

            state = await _load_state_from_redis(client, operation_id)
            await client.aclose()

            if not state:
                return {
                    "found": False,
                    "error": f"No state found for operation: {operation_id}",
                }

            # Filter extracted IOCs to only include domains/users from the attack
            from ares.core.evidence_validation import (
                extract_domains_from_red_team_state,
                set_target_domains,
            )

            target_domains = extract_domains_from_red_team_state(state)
            if target_domains:
                set_target_domains(target_domains)
                logger.info(f"Set evidence scope to target domains: {target_domains}")

            # Generate the detection playbook
            from ares.eval.detection_playbook import create_detection_playbook

            playbook = create_detection_playbook(state)

            # Return a condensed version suitable for agent consumption
            return {
                "found": True,
                "operation_id": playbook.operation_id,
                "target_domains": sorted(target_domains),  # Domains used for evidence scoping
                "attack_window": {
                    "start": playbook.attack_window_start.isoformat(),
                    "end": playbook.attack_window_end.isoformat(),
                },
                "summary": {
                    "techniques_used": playbook.techniques_used,
                    "technique_count": len(playbook.techniques_used),
                    "credentials_compromised": playbook.total_credentials,
                    "hosts_discovered": playbook.total_hosts,
                    "domain_admin_achieved": playbook.achieved_domain_admin,
                },
                "executive_summary": playbook.executive_summary,
                # Top 10 priority queries
                "priority_queries": [
                    {
                        "technique": q.technique_id,
                        "name": q.technique_name,
                        "description": q.description,
                        "logql": q.logql,
                        "priority": q.priority,
                        "event_ids": q.windows_event_ids,
                    }
                    for q in playbook.priority_queries[:10]
                ],
                # Detection targets (IOCs)
                "detection_targets": [
                    {
                        "type": t.ioc_type,
                        "value": t.value,
                        "pyramid_level": t.pyramid_level,
                        "context": t.context,
                        "queries": t.detection_queries[:2],  # Top 2 queries per IOC
                    }
                    for t in playbook.detection_targets[:20]  # Limit to 20 IOCs
                ],
                "guidance": (
                    "Run the priority_queries in order. They are sorted by importance. "
                    "Focus on 'critical' and 'high' priority queries first. "
                    "Use detection_targets to search for specific IOCs in your logs."
                ),
            }

        except Exception as e:
            logger.error(f"Failed to load attack playbook: {e}")
            return {
                "found": False,
                "error": f"Failed to load playbook: {e!s}",
            }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_detection_queries_for_technique(
        self,
        technique_id: str,
        operation_id: str | None = None,
        redis_url: str | None = None,
    ) -> dict[str, Any]:
        """Get specific detection queries for a MITRE technique.

        Returns LogQL queries tailored to detect a specific technique,
        populated with actual IOCs from the red team operation.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003", "T1558.001")
            operation_id: Red team operation ID. If not provided, uses latest.
            redis_url: Redis URL for connecting to state backend.

        Returns:
            Dictionary with technique-specific detection guidance and queries.
        """
        dn.log_metric("learning_technique_queries", 1, mode="count")
        logger.info(f"Getting detection queries for technique: {technique_id}")

        # Load the full playbook
        playbook_result = await self.get_attack_playbook(
            operation_id=operation_id,
            redis_url=redis_url,
        )

        if not playbook_result.get("found"):
            return playbook_result

        # Check if technique was used
        techniques_used = playbook_result.get("summary", {}).get("techniques_used", [])

        # Try to find exact match or parent match
        found_technique = None
        for tech in techniques_used:
            if tech == technique_id:
                found_technique = tech
                break
            # Check parent/child relationship
            if "." in technique_id:
                parent = technique_id.split(".", maxsplit=1)[0]
                if tech == parent or tech.startswith(f"{technique_id}."):
                    found_technique = tech
                    break
            elif tech.startswith(f"{technique_id}."):
                found_technique = tech
                break

        if not found_technique:
            # Return generic queries for the technique
            return {
                "found": True,
                "technique_used": False,
                "technique_id": technique_id,
                "message": (
                    f"Technique {technique_id} was not explicitly used in operation "
                    f"{playbook_result['operation_id']}, but here are general detection queries."
                ),
                "queries": self._get_generic_queries_for_technique(technique_id),
            }

        # Find relevant queries from the playbook
        relevant_queries = [
            q
            for q in playbook_result.get("priority_queries", [])
            if q["technique"] == found_technique
            or q["technique"].startswith(f"{technique_id}.")
            or technique_id.startswith(f"{q['technique']}.")
        ]

        return {
            "found": True,
            "technique_used": True,
            "technique_id": found_technique,
            "operation_id": playbook_result["operation_id"],
            "attack_window": playbook_result["attack_window"],
            "queries": relevant_queries or self._get_generic_queries_for_technique(technique_id),
            "guidance": (
                f"Technique {found_technique} was used during the attack. "
                "Run these queries within the attack window to find evidence."
            ),
        }

    def _get_generic_queries_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Return generic detection queries for common techniques."""
        generic_queries: dict[str, list[dict[str, Any]]] = {
            "T1003": [
                {
                    "technique": "T1003",
                    "name": "Credential Dumping",
                    "logql": '{job="windows-security"} |~ "(?i)(lsass|mimikatz|secretsdump)"',
                    "priority": "critical",
                    "event_ids": ["4624", "4672", "10"],
                },
            ],
            "T1078": [
                {
                    "technique": "T1078",
                    "name": "Valid Accounts",
                    "logql": '{job="windows-security"} |~ "(4624|4625)" |~ "LogonType.*(3|10)"',
                    "priority": "high",
                    "event_ids": ["4624", "4625"],
                },
            ],
            "T1558": [
                {
                    "technique": "T1558",
                    "name": "Kerberos Attacks",
                    "logql": '{job="windows-security"} |~ "(4768|4769)" |~ "(?i)(RC4|0x17)"',
                    "priority": "critical",
                    "event_ids": ["4768", "4769"],
                },
            ],
            "T1021": [
                {
                    "technique": "T1021",
                    "name": "Remote Services",
                    "logql": '{job="windows-security"} |= "4624" |~ "LogonType.*(3|10)"',
                    "priority": "high",
                    "event_ids": ["4624"],
                },
            ],
            "T1110": [
                {
                    "technique": "T1110",
                    "name": "Brute Force",
                    "logql": '{job="windows-security"} |= "4625"',
                    "priority": "high",
                    "event_ids": ["4625"],
                },
            ],
        }

        # Try exact match, then parent technique
        if technique_id in generic_queries:
            return generic_queries[technique_id]

        parent = technique_id.split(".", maxsplit=1)[0] if "." in technique_id else technique_id
        if parent in generic_queries:
            return generic_queries[parent]

        # Default query
        return [
            {
                "technique": technique_id,
                "name": "Generic Detection",
                "logql": '{job="windows-security"} |~ "(?i)(4624|4625|4672)"',
                "priority": "medium",
                "event_ids": ["4624", "4625", "4672"],
                "note": f"No specific query template for {technique_id}. Check MITRE ATT&CK for guidance.",
            },
        ]
