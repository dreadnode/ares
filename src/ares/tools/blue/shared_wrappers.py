"""Shared investigation tools that publish to the blue team dispatcher.

SharedInvestigationTools subclasses InvestigationTools but redirects
state mutations to the BlueStateBackend (Redis) instead of mutating
a local InvestigationState. This allows multiple worker agents to
share a single investigation state via Redis.

Read methods fetch from the backend snapshot so all agents see
consistent data.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import dreadnode as dn
from loguru import logger

from ares.core.evidence_validation import (
    adjust_confidence_for_validation,
    validate_evidence_value,
)
from ares.core.models import (
    Evidence,
    InvestigationStage,
    PyramidLevel,
    TimelineEvent,
)
from ares.tools.blue.investigation import (
    PYRAMID_EMOJI,
    STATUS_INFO,
    STATUS_SUCCESS,
    InvestigationTools,
)

if TYPE_CHECKING:
    from ares.core.blue_state_backend import BlueStateBackend
    from ares.core.models import SharedBlueTeamState
    from ares.integrations.mitre import MITREAttackClient


class SharedInvestigationTools(InvestigationTools):
    """Investigation tools that publish state to Redis via BlueStateBackend.

    Instead of mutating a local InvestigationState, all writes go through
    the backend so that all worker agents share consistent state.

    Attributes:
        _backend: The BlueStateBackend for Redis persistence.
        _shared_state: Reference to the shared state object.
        _mitre_client: MITRE client for technique lookups.
    """

    _backend: BlueStateBackend | None = None
    _shared_state: SharedBlueTeamState | None = None
    _mitre_client: MITREAttackClient | None = None
    _evidence_counter: int = 0
    _timeline_counter: int = 0

    def set_backend(self, backend: BlueStateBackend) -> None:
        """Set the Redis backend for state persistence."""
        self._backend = backend

    def set_shared_state(self, shared_state: SharedBlueTeamState) -> None:
        """Set reference to shared state for reads."""
        self._shared_state = shared_state

    def set_mitre_client(self, client: MITREAttackClient) -> None:
        """Set the MITRE client for technique lookups."""
        self._mitre_client = client
        # Also set on parent class
        self.mitre_client = client

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def record_evidence(  # type: ignore[override]
        self,
        evidence_type: str,
        value: str,
        source: str,
        timestamp: str | None,
        pyramid_level: int,
        mitre_techniques: list[str] | None = None,
        confidence: float = 0.5,
    ) -> str:
        """Record evidence and publish to shared state via Redis.

        CALL THIS FOR EVERY FINDING. Evidence types include:
        - ip, domain, hash, url (IOCs)
        - process, file, user, service (host artifacts)
        - artifact, certificate, user_agent (network artifacts)
        - tool, malware (tools)
        - technique, behavior (TTPs)

        Pyramid levels (higher = more valuable):
        1. Hash Values, 2. IP Addresses, 3. Domain Names,
        4. Network/Host Artifacts, 5. Tools, 6. TTPs (the goal!)

        Args:
            evidence_type: Type of evidence (ip, domain, hash, process, etc.).
            value: The actual evidence value.
            source: What query or tool found this.
            timestamp: ISO8601 timestamp (can be None).
            pyramid_level: Pyramid of Pain level 1-6.
            mitre_techniques: Optional MITRE technique IDs.
            confidence: Confidence score 0.0-1.0.

        Returns:
            Evidence ID and validation status.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        self._evidence_counter += 1
        evidence_id = f"ev-{self._evidence_counter:04d}"

        ts = None
        if timestamp:
            with contextlib.suppress(ValueError):
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        # Validate evidence against recent query results
        validated, source_query_id = validate_evidence_value(value)
        adjusted_confidence = adjust_confidence_for_validation(confidence, validated)

        level = PyramidLevel(min(max(pyramid_level, 1), 6))

        ev = Evidence(
            id=evidence_id,
            type=evidence_type,
            value=value,
            source=source,
            timestamp=ts,
            pyramid_level=level,
            mitre_techniques=mitre_techniques or [],
            confidence=adjusted_confidence,
            source_query_id=source_query_id,
            validated=validated,
        )

        # Publish to Redis backend
        added = await self._backend.add_evidence(ev.to_dict())

        # Track techniques
        if mitre_techniques:
            for tech_id in mitre_techniques:
                name = ""
                if self._mitre_client:
                    technique = self._mitre_client.get_technique(tech_id)
                    if technique:
                        name = technique.name
                        if technique.tactic:
                            await self._backend.add_tactic(technique.tactic)
                await self._backend.add_technique(tech_id, name)

        dn.log_metric("evidence_count", 1, mode="count")
        dn.log_metric("highest_pyramid_level", pyramid_level, mode="max")

        validation_status = "validated" if validated else "UNVALIDATED - confidence reduced"
        level_emoji = PYRAMID_EMOJI.get(pyramid_level, "")
        value_preview = value[:60] + "..." if len(value) > 60 else value

        if not added:
            return f"{STATUS_INFO} Evidence already recorded (dedup): {evidence_type}={value_preview}"

        lines = [
            f"{STATUS_SUCCESS} Recorded evidence: {evidence_id}",
            f"  {level_emoji} Type: {evidence_type} | Level: {pyramid_level}/6",
            f"  Value: {value_preview}",
            f"  Status: {'v' if validated else '!'} {validation_status}",
        ]
        if mitre_techniques:
            lines.append(f"  Techniques: {', '.join(mitre_techniques)}")

        return "\n".join(lines)

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def add_timeline_event(  # type: ignore[override]
        self,
        timestamp: str,
        description: str,
        evidence_ids: list[str],
        mitre_techniques: list[str] | None = None,
        confidence: float = 0.5,
    ) -> str:
        """Add an event to the shared investigation timeline.

        Args:
            timestamp: ISO8601 timestamp of when this occurred.
            description: Human-readable description of what happened.
            evidence_ids: List of evidence IDs supporting this event.
            mitre_techniques: MITRE technique IDs for this event.
            confidence: Confidence score 0.0-1.0.

        Returns:
            Timeline event ID.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        self._timeline_counter += 1
        event_id = f"tl-{self._timeline_counter:04d}"

        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)

        event = TimelineEvent(
            id=event_id,
            timestamp=ts,
            description=description,
            evidence_ids=evidence_ids,
            mitre_techniques=mitre_techniques or [],
            confidence=confidence,
        )

        await self._backend.add_timeline_event(event.to_dict())
        dn.log_metric("timeline_events", 1, mode="count")
        logger.info(f"Timeline event: {description[:50]}...")

        return event_id

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def track_host_investigation(self, hostname: str) -> str:  # type: ignore[override]
        """Mark a host as investigated in shared state.

        Args:
            hostname: The hostname to track.

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        hostname_lower = hostname.strip().lower()
        await self._backend.track_host(hostname_lower)
        logger.debug(f"Tracked host: {hostname_lower}")
        return f"{STATUS_SUCCESS} Tracking host: {hostname}"

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def track_user_investigation(self, username: str) -> str:  # type: ignore[override]
        """Mark a user as investigated in shared state.

        Args:
            username: The username to track.

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        username_lower = username.strip().lower()
        await self._backend.track_user(username_lower)
        logger.debug(f"Tracked user: {username_lower}")
        return f"{STATUS_SUCCESS} Tracking user: {username}"

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def record_lateral_connection(  # type: ignore[override]
        self,
        source: str,
        destination: str,
        connection_type: str,
        user: str = "",
        mitre_technique: str = "",
    ) -> str:
        """Record a lateral movement connection in shared state.

        Args:
            source: Source host.
            destination: Destination host.
            connection_type: Type of connection (rdp, smb, wmi, etc.).
            user: User account used for the connection.
            mitre_technique: Associated MITRE technique ID.

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        connection = {
            "source": source,
            "destination": destination,
            "connection_type": connection_type,
            "user": user,
            "mitre_technique": mitre_technique,
        }
        await self._backend.add_lateral_connection(connection)

        # Track hosts
        await self._backend.track_host(source.strip().lower())
        await self._backend.track_host(destination.strip().lower())

        logger.info(f"Lateral connection: {source} -> {destination} ({connection_type})")
        return f"{STATUS_SUCCESS} Recorded lateral connection: {source} -> {destination} via {connection_type}"

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_investigation_summary(self) -> dict:  # type: ignore[override]
        """Get current investigation summary from shared state.

        Returns:
            Summary dict with evidence count, techniques, etc.
        """
        if not self._backend:
            return {"error": "No backend configured"}

        snapshot = await self._backend.snapshot()
        meta = snapshot.get("meta", {})

        return {
            "investigation_id": snapshot["investigation_id"],
            "stage": meta.get("stage", "triage"),
            "evidence_count": len(snapshot["evidence"]),
            "timeline_events": len(snapshot["timeline"]),
            "techniques_identified": list(snapshot["techniques"]),
            "highest_pyramid_level": max(
                (e.get("pyramid_level", 0) for e in snapshot["evidence"]),
                default=0,
            ),
            "hosts_investigated": list(snapshot["hosts"]),
            "users_investigated": list(snapshot["users"]),
            "pending_tasks": len(snapshot["pending_tasks"]),
            "completed_tasks": len(snapshot["completed_tasks"]),
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_queued_queries(self) -> dict:  # type: ignore[override]
        """Get auto-queued pivot and chain queries from shared state.

        Returns:
            Dict with queued_pivot_queries and queued_chain_queries.
        """
        if not self._backend:
            return {"error": "No backend configured"}

        snapshot = await self._backend.snapshot()
        return {
            "queued_pivot_queries": snapshot["pivot_queue"],
            "queued_chain_queries": snapshot["chain_queue"],
            "total_queued": len(snapshot["pivot_queue"]) + len(snapshot["chain_queue"]),
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def get_correlated_alerts(self) -> dict:  # type: ignore[override]
        """Get correlated alert context from shared state.

        Returns:
            Correlation context dict.
        """
        if not self._backend:
            return {"error": "No backend configured"}

        meta = await self._backend.get_meta("correlation_context")
        if meta:
            return meta
        return {"related_alerts": 0, "message": "No correlation context available"}

    @dn.tool_method  # type: ignore[untyped-decorator]
    async def transition_stage(self, new_stage: str) -> str:  # type: ignore[override]
        """Transition the investigation to a new stage.

        Args:
            new_stage: One of: triage, causation, lateral, synthesis.

        Returns:
            Confirmation message.
        """
        if not self._backend:
            return "ERROR: No backend configured"

        valid_stages = {s.value for s in InvestigationStage}
        if new_stage not in valid_stages:
            return f"ERROR: Invalid stage '{new_stage}'. Must be one of: {', '.join(valid_stages)}"

        await self._backend.set_meta("stage", new_stage)
        logger.info(f"Investigation stage transition -> {new_stage}")
        return f"{STATUS_SUCCESS} Transitioned to stage: {new_stage}"
