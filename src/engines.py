"""
Question Engines - The core drivers of the investigation.

These engines generate investigative questions based on:
1. MITRE ATT&CK Navigator: Technique chains, tactical gaps, attack lifecycle
2. Pyramid of Pain Climber: Elevating from trivial IOCs to meaningful TTPs
"""

import uuid
from typing import TypedDict

from .mitre import MITREAttackClient
from .models import (
    InvestigationState,
    InvestigativeQuestion,
    PyramidLevel,
    QuestionSource,
)


class ClimbStrategy(TypedDict):
    """Type definition for pyramid climbing strategies."""

    template: str
    target: PyramidLevel
    insight: str
    elevation: int


class MITRENavigator:
    """
    MITRE ATT&CK-driven question generator.

    Generates questions that:
    1. Map evidence to techniques
    2. Predict follow-on techniques based on attack patterns
    3. Identify tactical gaps in the investigation
    4. Ensure complete attack lifecycle coverage
    """

    def __init__(self, mitre_client: MITREAttackClient):
        self.mitre = mitre_client

    def generate_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate MITRE-informed investigative questions."""
        questions = []

        # 1. Follow-on technique questions
        questions.extend(self._generate_followon_questions(state))

        # 2. Tactical gap questions
        questions.extend(self._generate_gap_questions(state))

        # 3. Unmapped evidence questions
        questions.extend(self._generate_mapping_questions(state))

        return questions

    def _generate_followon_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate questions about techniques that commonly follow identified ones."""
        questions = []

        for tech_id in state.identified_techniques:
            technique = self.mitre.get_technique(tech_id)
            if not technique:
                continue

            related = self.mitre.get_related_techniques(tech_id)

            for rel in related[:5]:  # Limit per technique
                if rel["technique_id"] in state.identified_techniques:
                    continue

                rel_tech = self.mitre.get_technique(rel["technique_id"])
                if not rel_tech:
                    continue

                questions.append(
                    InvestigativeQuestion(
                        id=f"mitre-followon-{uuid.uuid4().hex[:8]}",
                        text=(
                            f"We identified {tech_id} ({technique.name}). "
                            f"Check for {rel['technique_id']} ({rel['name']}) "
                            f"which is {rel['relationship']}. "
                            f"What evidence would indicate this technique?"
                        ),
                        source=QuestionSource.MITRE_NAVIGATOR,
                        rationale=f"{rel['technique_id']} commonly appears with {tech_id}",
                        target_insight=f"Detect presence of {rel['technique_id']}",
                        target_technique=rel["technique_id"],
                        technique_chain_from=tech_id,
                        mitre_coverage_score=rel["relevance"],
                        confidence_impact_score=0.6,
                    )
                )

        return questions

    def _generate_gap_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate questions to fill tactical gaps."""
        questions = []

        uncovered = self.mitre.get_uncovered_tactics(list(state.identified_techniques))

        # Prioritize certain tactics
        priority_map = {
            "TA0001": 0.9,  # Initial Access
            "TA0003": 0.85,  # Persistence
            "TA0008": 0.8,  # Lateral Movement
            "TA0006": 0.75,  # Credential Access
            "TA0010": 0.7,  # Exfiltration
            "TA0011": 0.7,  # C2
        }

        for tactic in uncovered:
            priority = priority_map.get(tactic.id, 0.5)

            # Get example techniques for this tactic
            example_techs = self.mitre.get_techniques_for_tactic(tactic.id)[:3]
            examples = ", ".join([t.name for t in example_techs])

            questions.append(
                InvestigativeQuestion(
                    id=f"mitre-gap-{uuid.uuid4().hex[:8]}",
                    text=(
                        f"Tactical gap: No evidence found for {tactic.name} ({tactic.id}). "
                        f"Common techniques include: {examples}. "
                        f"What would indicate activity in this attack phase?"
                    ),
                    source=QuestionSource.MITRE_NAVIGATOR,
                    rationale=f"Complete attacks usually involve {tactic.name}",
                    target_insight=f"Determine if {tactic.name} occurred",
                    mitre_coverage_score=priority,
                    confidence_impact_score=0.5,
                )
            )

        return questions

    def _generate_mapping_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate questions to map evidence to techniques."""
        questions = []

        # Find evidence not mapped to techniques
        unmapped = [e for e in state.evidence if not e.mitre_techniques]

        for ev in unmapped[:5]:  # Limit
            questions.append(
                InvestigativeQuestion(
                    id=f"mitre-map-{uuid.uuid4().hex[:8]}",
                    text=(
                        f"Evidence '{ev.type}={ev.value}' is not mapped to any MITRE technique. "
                        f"What ATT&CK technique does this indicate?"
                    ),
                    source=QuestionSource.MITRE_NAVIGATOR,
                    rationale="Unmapped evidence may indicate additional techniques",
                    target_insight="Map evidence to MITRE technique",
                    confidence_impact_score=0.6,
                    generated_from_evidence_ids=[ev.id],
                )
            )

        return questions


# Pyramid of Pain climbing strategies
CLIMB_STRATEGIES: dict[PyramidLevel, list[ClimbStrategy]] = {
    PyramidLevel.HASH_VALUES: [
        {
            "template": "What process or tool created the file with hash {value}?",
            "target": PyramidLevel.TOOLS,
            "insight": "Identify the tool that generated this artifact",
            "elevation": 4,
        },
        {
            "template": "What behavior led to the creation of file with hash {value}?",
            "target": PyramidLevel.TTPS,
            "insight": "Understand the TTP that produced this artifact",
            "elevation": 5,
        },
    ],
    PyramidLevel.IP_ADDRESSES: [
        {
            "template": "What domain names have resolved to IP {value}?",
            "target": PyramidLevel.DOMAIN_NAMES,
            "insight": "Identify associated domains",
            "elevation": 1,
        },
        {
            "template": "What TLS certificates are served by IP {value}?",
            "target": PyramidLevel.NETWORK_HOST_ARTIFACTS,
            "insight": "Identify infrastructure artifacts",
            "elevation": 2,
        },
        {
            "template": "What C2 framework or tool communicates with IP {value}?",
            "target": PyramidLevel.TOOLS,
            "insight": "Identify the tool using this IP",
            "elevation": 3,
        },
    ],
    PyramidLevel.DOMAIN_NAMES: [
        {
            "template": (
                "What is the registration pattern of domain {value}? "
                "(DGA, typosquat, newly registered?)"
            ),
            "target": PyramidLevel.TTPS,
            "insight": "Understand adversary infrastructure TTP",
            "elevation": 3,
        },
        {
            "template": "What tool or malware is known to use domains similar to {value}?",
            "target": PyramidLevel.TOOLS,
            "insight": "Attribute domain to known tooling",
            "elevation": 2,
        },
    ],
    PyramidLevel.NETWORK_HOST_ARTIFACTS: [
        {
            "template": "What tool creates the artifact pattern '{value}'?",
            "target": PyramidLevel.TOOLS,
            "insight": "Identify tool from artifact",
            "elevation": 1,
        },
        {
            "template": "What behavior or TTP does artifact '{value}' indicate?",
            "target": PyramidLevel.TTPS,
            "insight": "Map artifact to TTP",
            "elevation": 2,
        },
    ],
    PyramidLevel.TOOLS: [
        {
            "template": "What TTPs does tool '{value}' enable?",
            "target": PyramidLevel.TTPS,
            "insight": "Understand tool capabilities as TTPs",
            "elevation": 1,
        },
        {
            "template": "What threat actors are known to use tool '{value}'?",
            "target": PyramidLevel.TTPS,
            "insight": "Attribute to threat actor TTP profile",
            "elevation": 1,
        },
    ],
}

PYRAMID_NAMES = {
    PyramidLevel.HASH_VALUES: "Hash Values",
    PyramidLevel.IP_ADDRESSES: "IP Addresses",
    PyramidLevel.DOMAIN_NAMES: "Domain Names",
    PyramidLevel.NETWORK_HOST_ARTIFACTS: "Network/Host Artifacts",
    PyramidLevel.TOOLS: "Tools",
    PyramidLevel.TTPS: "TTPs",
}


class PyramidClimber:
    """
    Pyramid of Pain-driven question generator.

    Focuses on ELEVATING understanding from trivial indicators to TTPs.

    The pyramid levels (1-6):
    1. Hash Values - Trivial to change
    2. IP Addresses - Easy
    3. Domain Names - Simple
    4. Network/Host Artifacts - Annoying
    5. Tools - Challenging
    6. TTPs - Tough!

    Every question aims to climb the pyramid.
    """

    def generate_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate questions that climb the Pyramid of Pain."""
        questions = []

        for ev in state.evidence:
            # Skip if already at TTP level
            if ev.pyramid_level == PyramidLevel.TTPS:
                continue

            strategies = CLIMB_STRATEGIES.get(ev.pyramid_level, [])

            for strategy in strategies:
                elevation_score = strategy["elevation"] / 5.0  # Normalize to 0-1

                questions.append(
                    InvestigativeQuestion(
                        id=f"pyramid-{uuid.uuid4().hex[:8]}",
                        text=strategy["template"].format(value=ev.value),
                        source=QuestionSource.PYRAMID_CLIMBER,
                        rationale=(
                            f"Elevate from {PYRAMID_NAMES[ev.pyramid_level]} "
                            f"(level {ev.pyramid_level.value}) "
                            f"to {PYRAMID_NAMES[strategy['target']]} "
                            f"(level {strategy['target'].value})"
                        ),
                        target_insight=strategy["insight"],
                        current_pyramid_level=ev.pyramid_level.value,
                        target_pyramid_level=strategy["target"].value,
                        pyramid_elevation_score=elevation_score,
                        confidence_impact_score=0.5,
                        generated_from_evidence_ids=[ev.id],
                    )
                )

        return questions

    def assess_pyramid_state(self, state: InvestigationState) -> dict:
        """
        Assess the current Pyramid of Pain state.

        Returns distribution and recommendations.
        """
        distribution = {level: 0 for level in PyramidLevel}

        for ev in state.evidence:
            distribution[ev.pyramid_level] += 1

        total = len(state.evidence) or 1

        # Calculate elevation score (how high we've climbed)
        weighted_sum = sum(level.value * count for level, count in distribution.items())
        elevation_score = weighted_sum / (total * 6)  # Max is 6

        # Generate recommendations
        recommendations = []
        if distribution[PyramidLevel.HASH_VALUES] > distribution[PyramidLevel.TOOLS]:
            recommendations.append("Too many trivial hash indicators - focus on identifying tools")
        if distribution[PyramidLevel.IP_ADDRESSES] > distribution[PyramidLevel.DOMAIN_NAMES]:
            recommendations.append("Investigate domain infrastructure behind IPs")
        if distribution[PyramidLevel.TTPS] == 0:
            recommendations.append("CRITICAL: No TTPs identified - this should be the primary goal")

        return {
            "distribution": {PYRAMID_NAMES[level]: count for level, count in distribution.items()},
            "elevation_score": elevation_score,
            "total_evidence": total,
            "recommendations": recommendations,
        }


class QuestionPrioritizer:
    """Combines and prioritizes questions from all engines."""

    def __init__(
        self,
        mitre_navigator: MITRENavigator,
        pyramid_climber: PyramidClimber,
    ):
        self.mitre = mitre_navigator
        self.pyramid = pyramid_climber

    def generate_all_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate questions from both engines and prioritize."""
        questions = []

        # Generate from both engines
        questions.extend(self.mitre.generate_questions(state))
        questions.extend(self.pyramid.generate_questions(state))

        # Sort by priority score (highest first)
        questions.sort(key=lambda q: q.priority_score, reverse=True)

        return questions

    def get_parallel_batch(
        self,
        questions: list[InvestigativeQuestion],
        max_size: int = 5,
    ) -> list[InvestigativeQuestion]:
        """
        Get a batch of questions that can be executed in parallel.

        Selects high-priority questions that don't conflict.
        """
        batch: list[InvestigativeQuestion] = []

        for q in questions:
            if len(batch) >= max_size:
                break

            # Check if can parallelize with current batch
            can_add = all(q.can_parallelize_with(existing) for existing in batch)

            if can_add:
                batch.append(q)

        return batch
