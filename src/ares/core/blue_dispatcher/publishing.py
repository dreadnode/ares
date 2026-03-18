"""Evidence and discovery publishing for blue team dispatcher."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from ares.core.blue_state_backend import BlueStateBackend


class BluePublishingMixin:
    """Publishes evidence, timeline events, and techniques to shared state."""

    _backend: BlueStateBackend

    async def publish_evidence(self, evidence_dict: dict[str, Any], source_agent: str = "") -> bool:
        """Publish evidence to shared state with deduplication.

        Args:
            evidence_dict: Evidence data dict (from Evidence.to_dict()).
            source_agent: Name of the agent that found this evidence.

        Returns:
            True if new evidence (not duplicate).
        """
        if source_agent:
            evidence_dict["source_agent"] = source_agent
        added = await self._backend.add_evidence(evidence_dict)
        if added:
            logger.debug(
                f"Published evidence: {evidence_dict.get('type')}="
                f"{str(evidence_dict.get('value', ''))[:50]}"
            )
        return added

    async def publish_timeline_event(
        self, event_dict: dict[str, Any], source_agent: str = ""
    ) -> None:
        """Publish a timeline event to shared state.

        Args:
            event_dict: Timeline event data dict.
            source_agent: Name of the source agent.
        """
        if source_agent:
            event_dict["source_agent"] = source_agent
        await self._backend.add_timeline_event(event_dict)
        logger.debug(f"Published timeline event: {str(event_dict.get('description', ''))[:50]}")

    async def publish_technique(self, technique_id: str, name: str = "", tactic: str = "") -> None:
        """Publish a MITRE technique to shared state.

        Args:
            technique_id: MITRE ATT&CK technique ID.
            name: Human-readable technique name.
            tactic: Associated tactic.
        """
        await self._backend.add_technique(technique_id, name)
        if tactic:
            await self._backend.add_tactic(tactic)
        logger.debug(f"Published technique: {technique_id} ({name})")

    async def publish_lateral_connection(
        self,
        source: str,
        destination: str,
        connection_type: str,
        user: str = "",
        mitre_technique: str = "",
    ) -> None:
        """Publish a lateral movement connection to shared state.

        Args:
            source: Source host.
            destination: Destination host.
            connection_type: Connection type (rdp, smb, wmi, etc.).
            user: User account used.
            mitre_technique: Associated MITRE technique.
        """
        source_norm = source.strip().lower()
        destination_norm = destination.strip().lower()
        connection = {
            "source": source_norm,
            "destination": destination_norm,
            "connection_type": connection_type,
            "user": user,
            "mitre_technique": mitre_technique,
        }
        await self._backend.add_lateral_connection(connection)
        await self._backend.track_host(source_norm)
        await self._backend.track_host(destination_norm)
        logger.debug(f"Published lateral: {source_norm} -> {destination_norm} ({connection_type})")
