"""Investigation state management and question engine tools."""

import contextlib
from datetime import datetime, timezone

import dreadnode as dn
from dreadnode.agent.tools.base import Toolset
from loguru import logger

from ares.core.engines import (
    MITRENavigator,
    PyramidClimber,
    _load_attack_chains,
    _load_detection_recipes,
)
from ares.core.models import (
    Evidence,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
    TimelineEvent,
)
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient


class InvestigationTools(Toolset):  # type: ignore[misc]
    """Tools for managing investigation state.

    These tools record evidence, build the timeline, and track
    MITRE mappings and Pyramid of Pain levels.

    Attributes:
        state: Current investigation state being managed.
        mitre_client: MITRE ATT&CK client for technique lookups.
    """

    state: InvestigationState | None = None
    mitre_client: MITREAttackClient | None = None

    def set_state(self, state: InvestigationState):
        """Set the investigation state (called by orchestrator)."""
        self.state = state

    def set_mitre_client(self, client: MITREAttackClient):
        """Set the MITRE client for technique lookups."""
        self.mitre_client = client

    @dn.tool_method  # type: ignore[untyped-decorator]
    def record_evidence(
        self,
        evidence_type: str,
        value: str,
        source: str,
        timestamp: str | None,
        pyramid_level: int,
        mitre_techniques: list[str] | None = None,
        confidence: float = 0.5,
    ) -> str:
        """Record a piece of evidence discovered during investigation.

        CALL THIS FOR EVERY FINDING. Evidence types include:
        - ip, domain, hash, url (IOCs)
        - process, file, user, service (host artifacts)
        - artifact, certificate, user_agent (network artifacts)
        - tool, malware (tools)
        - technique, behavior (TTPs)

        Pyramid levels (higher = more valuable):
        1. Hash Values (trivial to change)
        2. IP Addresses (easy)
        3. Domain Names (simple)
        4. Network/Host Artifacts (annoying)
        5. Tools (challenging)
        6. TTPs (tough - this is the goal!)

        Args:
            evidence_type: Type of evidence (ip, domain, hash, process, etc.).
            value: The actual evidence value.
            source: What query or tool found this.
            timestamp: ISO8601 timestamp of when this occurred (can be None).
            pyramid_level: Pyramid of Pain level 1-6.
            mitre_techniques: Optional list of MITRE technique IDs (e.g., ["T1059.001"]).
            confidence: Confidence score 0.0-1.0.

        Returns:
            Evidence ID for reference.

        Example:
            >>> record_evidence(
            ...     evidence_type="ip",
            ...     value="192.168.1.100",
            ...     source="Loki query: {job='auth'}",
            ...     timestamp="2024-01-15T14:30:00Z",
            ...     pyramid_level=2,
            ...     confidence=0.8
            ... )
            'ev-0001'
        """
        if not self.state:
            return "ERROR: No investigation state"

        evidence_id = f"ev-{len(self.state.evidence):04d}"

        ts = None
        if timestamp:
            with contextlib.suppress(ValueError):
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        ev = Evidence(
            id=evidence_id,
            type=evidence_type,
            value=value,
            source=source,
            timestamp=ts,
            pyramid_level=PyramidLevel(min(max(pyramid_level, 1), 6)),
            mitre_techniques=mitre_techniques or [],
            confidence=confidence,
        )

        self.state.evidence.append(ev)

        if mitre_techniques:
            self.state.identified_techniques.update(mitre_techniques)
            # Look up technique names and tactics
            self._resolve_technique_metadata(mitre_techniques)

        dn.log_output(f"evidence_{evidence_id}", ev.to_dict())
        dn.log_metric("evidence_count", 1, mode="count")
        dn.log_metric("highest_pyramid_level", pyramid_level, mode="max")

        logger.info(
            f"Recorded evidence: {evidence_type}={value[:50]}... (pyramid level {pyramid_level})"
        )

        return evidence_id

    def _resolve_technique_metadata(self, technique_ids: list[str]) -> None:
        """Look up and cache technique names and tactics."""
        if not self.state or not self.mitre_client:
            return

        for tech_id in technique_ids:
            # Skip if already resolved
            if tech_id in self.state.technique_names:
                continue

            technique = self.mitre_client.get_technique(tech_id)
            if technique:
                self.state.technique_names[tech_id] = technique.name
                self.state.technique_to_tactic[tech_id] = technique.tactic or "Unknown"
                if technique.tactic:
                    self.state.identified_tactics.add(technique.tactic)
                logger.debug(f"Resolved technique {tech_id}: {technique.name} ({technique.tactic})")

    @dn.tool_method  # type: ignore[untyped-decorator]
    def add_timeline_event(
        self,
        timestamp: str,
        description: str,
        evidence_ids: list[str],
        mitre_techniques: list[str] | None = None,
        confidence: float = 0.5,
    ) -> str:
        """Add an event to the investigation timeline.

        Build a coherent timeline of what happened and when.

        Args:
            timestamp: ISO8601 timestamp of when this occurred.
            description: Human-readable description of what happened.
            evidence_ids: List of evidence IDs supporting this event.
            mitre_techniques: MITRE technique IDs for this event.
            confidence: Confidence score 0.0-1.0.

        Returns:
            Timeline event ID.

        Example:
            >>> add_timeline_event(
            ...     timestamp="2024-01-15T14:30:00Z",
            ...     description="Suspicious PowerShell execution detected",
            ...     evidence_ids=["ev-0001", "ev-0002"],
            ...     mitre_techniques=["T1059.001"],
            ...     confidence=0.9
            ... )
            'tl-0001'

        See Also:
            record_evidence: For recording evidence to reference in timeline events.
        """
        if not self.state:
            return "ERROR: No investigation state"

        event_id = f"tl-{len(self.state.timeline):04d}"

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

        self.state.timeline.append(event)
        self.state.timeline.sort(key=lambda e: e.timestamp)

        dn.log_metric("timeline_events", 1, mode="count")

        logger.info(f"Timeline event: {description[:50]}...")

        return event_id

    @dn.tool_method  # type: ignore[untyped-decorator]
    def transition_stage(self, new_stage: str) -> str:
        """Transition to a new investigation stage.

        Stages in order:
        1. triage - WHAT is happening
        2. causation - WHY it happened
        3. lateral - What is the SCOPE
        4. synthesis - Generate report

        Args:
            new_stage: One of: triage, causation, lateral, synthesis.

        Returns:
            Confirmation message.
        """
        if not self.state:
            return "ERROR: No investigation state"

        old_stage = self.state.stage
        self.state.stage = InvestigationStage(new_stage)

        dn.log_metric(f"stage_{new_stage}_entered", 1)
        dn.tag(f"stage:{new_stage}")

        logger.info(f"Stage transition: {old_stage.value} -> {new_stage}")

        return f"Transitioned from {old_stage.value} to {new_stage}"

    @dn.tool_method  # type: ignore[untyped-decorator]
    def get_investigation_summary(self) -> dict:
        """Get a summary of the current investigation state.

        Use this to understand what you've discovered so far.

        Returns:
            Summary with evidence count, techniques, pyramid state, etc.
        """
        if not self.state:
            return {"error": "No investigation state"}

        return self.state.to_summary()

    @dn.tool_method  # type: ignore[untyped-decorator]
    def track_host_investigation(self, hostname: str) -> str:
        """Mark a host as being investigated for lateral scope.

        Args:
            hostname: The hostname being investigated.

        Returns:
            Suggested queries for this host.
        """
        if not self.state:
            return "ERROR: No investigation state"

        self.state.queried_hosts.add(hostname)
        dn.log_metric("hosts_investigated", 1, mode="count")

        loader = get_template_loader()
        return loader.render("tools/host_queries.md.jinja", hostname=hostname)

    @dn.tool_method  # type: ignore[untyped-decorator]
    def track_user_investigation(self, username: str) -> str:
        """Mark a user as being investigated for lateral scope.

        Args:
            username: The username being investigated.

        Returns:
            Suggested queries for this user.
        """
        if not self.state:
            return "ERROR: No investigation state"

        self.state.queried_users.add(username)
        dn.log_metric("users_investigated", 1, mode="count")

        loader = get_template_loader()
        return loader.render("tools/user_queries.md.jinja", username=username)


class QuestionEngineTools(Toolset):  # type: ignore[misc]
    """Tools for the question engines that drive the investigation.

    These are the CORE drivers - call them frequently to get
    the next questions to investigate.

    Attributes:
        mitre_navigator: MITRE ATT&CK-driven question generator.
        pyramid_climber: Pyramid of Pain climbing question generator.
        state: Current investigation state.
    """

    mitre_navigator: MITRENavigator | None = None
    pyramid_climber: PyramidClimber | None = None
    state: InvestigationState | None = None

    def set_engines(
        self,
        mitre_client: MITREAttackClient,
        state: InvestigationState,
    ):
        """Initialize engines with MITRE client and state."""
        self.mitre_navigator = MITRENavigator(mitre_client)
        self.pyramid_climber = PyramidClimber()
        self.state = state

    @dn.tool_method  # type: ignore[untyped-decorator]
    def generate_mitre_questions(self) -> list[dict]:
        """Generate investigative questions based on MITRE ATT&CK framework.

        This is a CORE DRIVER of the investigation. Call this after
        recording evidence to get the next questions.

        The MITRE Navigator generates questions about:
        1. Follow-on techniques (what might come next in the attack)
        2. Tactical gaps (what attack phases haven't we checked)
        3. Evidence mapping (what technique does this evidence indicate)

        Returns:
            List of prioritized questions with rationale.
        """
        if not self.mitre_navigator or not self.state:
            return [{"error": "Engines not initialized"}]

        dn.log_metric("mitre_question_calls", 1, mode="count")

        questions = self.mitre_navigator.generate_questions(self.state)
        questions.sort(key=lambda q: q.priority_score, reverse=True)

        return [q.to_dict() for q in questions[:10]]

    @dn.tool_method  # type: ignore[untyped-decorator]
    def generate_pyramid_questions(self) -> list[dict]:
        """Generate questions to climb the Pyramid of Pain.

        This is a CORE DRIVER of the investigation. Call this after
        recording evidence to get questions that elevate understanding.

        The Pyramid Climber generates questions that move from:
        - Hash Values (trivial) -> Tools/TTPs
        - IP Addresses (easy) -> Domains/Infrastructure/Tools
        - Domains (simple) -> Infrastructure patterns/Tools
        - Artifacts (annoying) -> Tools/TTPs
        - Tools (challenging) -> TTPs

        The GOAL is always to reach TTPs (level 6).

        Returns:
            List of questions prioritized by elevation potential.
        """
        if not self.pyramid_climber or not self.state:
            return [{"error": "Engines not initialized"}]

        dn.log_metric("pyramid_question_calls", 1, mode="count")

        questions = self.pyramid_climber.generate_questions(self.state)
        questions.sort(key=lambda q: q.priority_score, reverse=True)

        return [q.to_dict() for q in questions[:10]]

    @dn.tool_method  # type: ignore[untyped-decorator]
    def assess_pyramid_state(self) -> dict:
        """Assess the current Pyramid of Pain state of the investigation.

        Use this to check if you're stuck at low-level indicators
        or successfully climbing toward TTPs.

        Returns:
            Assessment with distribution, elevation score, and recommendations.
        """
        if not self.pyramid_climber or not self.state:
            return {"error": "Engines not initialized"}

        return self.pyramid_climber.assess_pyramid_state(self.state)

    @dn.tool_method  # type: ignore[untyped-decorator]
    def get_combined_questions(self, max_questions: int = 10) -> list[dict]:
        """Get prioritized questions from BOTH engines combined.

        This is the recommended way to drive the investigation -
        get questions from both MITRE and Pyramid engines, combined
        and sorted by priority.

        Args:
            max_questions: Maximum number of questions to return.

        Returns:
            Combined, prioritized list of questions.

        Example:
            >>> get_combined_questions(max_questions=5)
            [
                {
                    'id': 'mitre-followon-a1b2c3d4',
                    'question': 'We identified T1059.001...',
                    'source': 'mitre',
                    'priority_score': 8.5,
                    ...
                },
                ...
            ]

        See Also:
            generate_mitre_questions: For MITRE-only questions.
            generate_pyramid_questions: For Pyramid-only questions.
            assess_pyramid_state: For understanding current pyramid position.
        """
        if not self.mitre_navigator or not self.pyramid_climber or not self.state:
            return [{"error": "Engines not initialized"}]

        mitre_qs = self.mitre_navigator.generate_questions(self.state)
        pyramid_qs = self.pyramid_climber.generate_questions(self.state)

        all_questions = mitre_qs + pyramid_qs
        all_questions.sort(key=lambda q: q.priority_score, reverse=True)

        dn.log_metric("combined_questions_generated", len(all_questions))

        return [q.to_dict() for q in all_questions[:max_questions]]

    @dn.tool_method  # type: ignore[untyped-decorator]
    def get_attack_chain_precursors(self, technique_id: str) -> dict:
        """Get precursor techniques for a detected technique.

        When you detect a technique, call this to find out what typically
        happens BEFORE this attack. Precursors are CRITICAL for understanding
        the full attack chain.

        Args:
            technique_id: MITRE technique ID (e.g., "T1003.006" for DCSync).

        Returns:
            Dict with precursors, windows_events, log_patterns, and investigation_questions.

        Example:
            >>> get_attack_chain_precursors("T1003.006")
            {
                'technique': 'T1003.006',
                'name': 'DCSync',
                'precursors': [
                    {'technique': 'T1087', 'name': 'Account Discovery', ...},
                    {'technique': 'T1135', 'name': 'Network Share Discovery', ...},
                    ...
                ],
                'windows_events': [
                    {'event_id': 4625, 'name': 'Failed Logon', ...},
                    ...
                ],
                ...
            }
        """
        attack_chains = _load_attack_chains()

        if technique_id not in attack_chains:
            return {
                "technique": technique_id,
                "message": "No attack chain data available for this technique",
                "suggestion": "Check related techniques or parent techniques",
            }

        chain_data = attack_chains[technique_id]
        return {
            "technique": technique_id,
            "name": chain_data.get("name", ""),
            "description": chain_data.get("description", ""),
            "precursors": chain_data.get("precursors", []),
            "windows_events": chain_data.get("windows_events", []),
            "log_patterns": chain_data.get("log_patterns", []),
            "investigation_questions": chain_data.get("investigation_questions", []),
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    def get_detection_recipe(self, recipe_name: str) -> dict:
        """Get a specific detection recipe with Windows event patterns.

        Detection recipes provide specific patterns for detecting attack
        techniques using Windows Security Event logs and LogQL queries.

        Available recipes:
        - password_spray: Detect password spray attacks
        - credential_stuffing: Detect credential stuffing
        - share_enumeration: Detect network share enumeration
        - ldap_enumeration: Detect LDAP/AD enumeration
        - kerberos_attacks: Detect Kerberoasting, AS-REP roasting, etc.
        - dcsync: Detect DCSync attacks
        - pass_the_hash: Detect pass-the-hash attacks
        - service_enumeration: Detect network service scanning

        Args:
            recipe_name: Name of the detection recipe.

        Returns:
            Dict with indicators, windows_events, logql_queries, and investigation_steps.

        Example:
            >>> get_detection_recipe("password_spray")
            {
                'name': 'Password Spray Attack Detection',
                'mitre_technique': 'T1110.003',
                'indicators': [...],
                'windows_events': {...},
                'logql_queries': [...],
                'investigation_steps': {...}
            }
        """
        recipes = _load_detection_recipes()

        if recipe_name not in recipes:
            available = [k for k in recipes if not k.startswith("query_")]
            return {"error": f"Recipe '{recipe_name}' not found", "available_recipes": available}

        recipe = recipes[recipe_name]
        return {
            "name": recipe.get("name", recipe_name),
            "description": recipe.get("description", ""),
            "mitre_technique": recipe.get("mitre_technique") or recipe.get("mitre_techniques"),
            "indicators": recipe.get("indicators", []),
            "windows_events": recipe.get("windows_events", {}),
            "logql_queries": recipe.get("logql_queries", []),
            "investigation_steps": recipe.get("investigation_steps", {}),
            "detection_logic": recipe.get("detection_patterns", {}),
        }

    @dn.tool_method  # type: ignore[untyped-decorator]
    def list_detection_recipes(self) -> list[dict]:
        """List all available detection recipes.

        Use this to see what detection patterns are available for
        different attack techniques.

        Returns:
            List of available recipes with name and MITRE technique mapping.
        """
        recipes = _load_detection_recipes()

        result = []
        for key, value in recipes.items():
            if key.startswith("query_"):
                continue  # Skip query template section
            if isinstance(value, dict):
                result.append(
                    {
                        "recipe_name": key,
                        "name": value.get("name", key),
                        "mitre_technique": value.get("mitre_technique")
                        or value.get("mitre_techniques"),
                        "description": value.get("description", "")[:100] + "..."
                        if value.get("description")
                        else "",
                    }
                )

        return result
