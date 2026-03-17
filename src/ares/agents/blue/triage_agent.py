"""Escalation triage agent for blue team investigations.

This agent evaluates escalated investigations to determine if they
truly require human analyst review, or if they can be handled automatically.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dreadnode as dn
from dreadnode.agent import Thread
from loguru import logger

from ares.core.models import TriageDecision, TriageRecord

if TYPE_CHECKING:
    from ares.core.blue_state_backend import BlueStateBackend
    from ares.core.models import SharedBlueTeamState


# Default timeout for triage (includes potential reinvestigation)
TRIAGE_TIMEOUT_SECONDS = 60 * 15  # 15 minutes
MAX_REINVESTIGATION_CYCLES = 2


class EscalationTriageAgent:
    """Agent that triages escalated investigations.

    Evaluates whether an escalated investigation truly requires human review
    or can be handled automatically (downgraded, routed, etc.).

    Attributes:
        model: LLM model identifier.
        max_steps: Maximum agent steps per triage attempt.
    """

    def __init__(
        self,
        model: str,
        max_steps: int = 10,
    ):
        """Initialize the triage agent.

        Args:
            model: LLM model identifier.
            max_steps: Maximum agent steps for triage.
        """
        self.model = model
        self.max_steps = max_steps

    async def triage(
        self,
        investigation_id: str,
        shared_state: SharedBlueTeamState,
        backend: BlueStateBackend,
    ) -> TriageRecord:
        """Run triage on an escalated investigation.

        Args:
            investigation_id: The investigation ID.
            shared_state: Shared blue team state with investigation data.
            backend: Redis state backend for persistence.

        Returns:
            TriageRecord with the decision and reasoning.
        """
        from ares.core.templates import get_template_loader
        from ares.tools.blue.triage_tools import EscalationTriageTools

        logger.info(f"Starting escalation triage for {investigation_id}")

        # Load instructions
        try:
            loader = get_template_loader()
            instructions = loader.render("blueteam/agents/escalation_triage.md.jinja")
        except Exception as e:
            logger.warning(f"Failed to load triage template: {e}")
            instructions = "You are an escalation triage agent. Evaluate the investigation and make a decision."

        # Create triage tools
        triage_tools = EscalationTriageTools()
        triage_tools.set_backend(backend)
        triage_tools.set_shared_state(shared_state)

        # Create completion event
        completion_event = asyncio.Event()
        triage_tools.set_completion_event(completion_event)

        agent = dn.Agent(
            name="Escalation Triage",
            model=self.model,
            instructions=instructions,
            max_steps=self.max_steps,
            tools=[triage_tools],
            thread=Thread(),  # type: ignore[call-arg]
        )

        initial_prompt = f"""Triage escalated investigation: {investigation_id}

Escalation reason: {shared_state.escalation_reason or "Not specified"}

Call get_investigation_context() first to understand the investigation, then make a triage decision.
"""

        try:
            # Run triage with timeout
            result = await asyncio.wait_for(
                agent.run(initial_prompt),
                timeout=TRIAGE_TIMEOUT_SECONDS,
            )
            logger.info(f"Triage completed: {result.steps} steps, {result.stop_reason}")

            # Get decision from tools
            decision_data = triage_tools.result_data

            if not decision_data:
                # Agent didn't make a decision - default to confirmed
                logger.warning("Triage agent didn't make a decision, defaulting to confirmed")
                decision_data = {
                    "decision": "confirmed",
                    "reasoning": "Triage agent did not make an explicit decision",
                    "confidence": 0.5,
                }

        except asyncio.TimeoutError:
            logger.error(f"Triage timed out after {TRIAGE_TIMEOUT_SECONDS}s")
            decision_data = {
                "decision": "confirmed",
                "reasoning": f"Triage timed out after {TRIAGE_TIMEOUT_SECONDS}s, defaulting to escalated",
                "confidence": 0.5,
            }

        except Exception as e:
            logger.error(f"Triage failed: {e}")
            decision_data = {
                "decision": "confirmed",
                "reasoning": f"Triage failed with error: {e}",
                "confidence": 0.5,
            }

        # Create triage record
        import uuid
        from datetime import datetime, timezone

        record = TriageRecord(
            triage_id=f"triage-{uuid.uuid4().hex[:8]}",
            investigation_id=investigation_id,
            decision=TriageDecision(decision_data.get("decision", "confirmed")),
            reasoning=decision_data.get("reasoning", ""),
            confidence=decision_data.get("confidence", 0.5),
            routed_to=decision_data.get("team"),
            focus_areas=decision_data.get("focus_areas", []),
            reinvestigation_cycle=decision_data.get("cycle", 0),
            created_at=datetime.now(timezone.utc),
        )

        # Update shared state
        shared_state.triage_decision = record.decision
        shared_state.triage_records.append(record)

        logger.success(
            f"Triage decision: {record.decision.value} (confidence={record.confidence:.2f})"
        )

        return record


__all__ = ["EscalationTriageAgent"]
