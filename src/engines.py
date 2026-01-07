"""
Question Engines - The core drivers of the investigation.

These engines generate investigative questions based on:
1. MITRE ATT&CK Navigator: Technique chains, tactical gaps, attack lifecycle
2. Pyramid of Pain Climber: Elevating from trivial IOCs to meaningful TTPs
"""

import uuid
from pathlib import Path
from typing import TypedDict

import yaml

from .mitre import MITREAttackClient
from .models import (
    InvestigationState,
    InvestigativeQuestion,
    PyramidLevel,
    QuestionSource,
)
from .templates import get_template_loader


class ClimbStrategy(TypedDict):
    """Type definition for pyramid climbing strategies.

    Attributes:
        template: Question template string with {value} placeholder.
        target: Target PyramidLevel to climb toward.
        insight: Description of what insight this strategy provides.
        elevation: Numeric elevation score indicating climb difficulty.
    """

    template: str
    target: PyramidLevel
    insight: str
    elevation: int


class MITRENavigator:
    """MITRE ATT&CK-driven question generator.

    Generates questions that:
    1. Map evidence to techniques
    2. Predict follow-on techniques based on attack patterns
    3. Identify tactical gaps in the investigation
    4. Ensure complete attack lifecycle coverage

    Attributes:
        mitre: MITREAttackClient instance for technique lookups.
    """

    def __init__(self, mitre_client: MITREAttackClient):
        self.mitre = mitre_client

    def generate_questions(
        self,
        state: InvestigationState,
    ) -> list[InvestigativeQuestion]:
        """Generate MITRE-informed investigative questions.

        Args:
            state: Current investigation state with evidence and identified techniques.

        Returns:
            List of InvestigativeQuestion objects prioritized by relevance.

        Example:
            >>> navigator = MITRENavigator(mitre_client)
            >>> questions = navigator.generate_questions(state)
            >>> questions[0].source
            <QuestionSource.MITRE: 'mitre'>
            >>> questions[0].target_technique
            'T1003.001'

        See Also:
            PyramidClimber.generate_questions: For Pyramid of Pain questions.
        """
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

            loader = get_template_loader()
            for rel in related[:5]:  # Limit per technique
                if rel["technique_id"] in state.identified_techniques:
                    continue

                rel_tech = self.mitre.get_technique(rel["technique_id"])
                if not rel_tech:
                    continue

                question_text = loader.render(
                    "engines/mitre_followon.md.jinja",
                    source_technique_id=tech_id,
                    source_technique_name=technique.name,
                    target_technique_id=rel["technique_id"],
                    target_technique_name=rel["name"],
                    relationship=rel["relationship"],
                )

                questions.append(
                    InvestigativeQuestion(
                        id=f"mitre-followon-{uuid.uuid4().hex[:8]}",
                        text=question_text,
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

        loader = get_template_loader()
        for tactic in uncovered:
            priority = priority_map.get(tactic.id, 0.5)

            # Get example techniques for this tactic
            example_techs = self.mitre.get_techniques_for_tactic(tactic.id)[:3]
            examples = ", ".join([t.name for t in example_techs])

            question_text = loader.render(
                "engines/mitre_gap.md.jinja",
                tactic_name=tactic.name,
                tactic_id=tactic.id,
                example_techniques=examples,
            )

            questions.append(
                InvestigativeQuestion(
                    id=f"mitre-gap-{uuid.uuid4().hex[:8]}",
                    text=question_text,
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

        loader = get_template_loader()
        for ev in unmapped[:5]:  # Limit
            question_text = loader.render(
                "engines/mitre_mapping.md.jinja",
                evidence_type=ev.type,
                evidence_value=ev.value,
            )

            questions.append(
                InvestigativeQuestion(
                    id=f"mitre-map-{uuid.uuid4().hex[:8]}",
                    text=question_text,
                    source=QuestionSource.MITRE_NAVIGATOR,
                    rationale="Unmapped evidence may indicate additional techniques",
                    target_insight="Map evidence to MITRE technique",
                    confidence_impact_score=0.6,
                    generated_from_evidence_ids=[ev.id],
                )
            )

        return questions


# Load Pyramid of Pain climbing strategies from YAML
def _load_climb_strategies() -> dict[PyramidLevel, list[ClimbStrategy]]:
    """Load climb strategies from YAML configuration file."""
    # Get project root (parent of src/)
    project_root = Path(__file__).parent.parent
    strategies_path = project_root / "templates" / "engines" / "climb_strategies.yaml"

    with strategies_path.open() as f:
        data = yaml.safe_load(f)

    # Map YAML keys to PyramidLevel enums
    level_mapping = {
        "hash_values": PyramidLevel.HASH_VALUES,
        "ip_addresses": PyramidLevel.IP_ADDRESSES,
        "domain_names": PyramidLevel.DOMAIN_NAMES,
        "network_host_artifacts": PyramidLevel.NETWORK_HOST_ARTIFACTS,
        "tools": PyramidLevel.TOOLS,
    }

    # Map YAML target values to PyramidLevel enums
    target_mapping = {
        "hash_values": PyramidLevel.HASH_VALUES,
        "ip_addresses": PyramidLevel.IP_ADDRESSES,
        "domain_names": PyramidLevel.DOMAIN_NAMES,
        "network_host_artifacts": PyramidLevel.NETWORK_HOST_ARTIFACTS,
        "tools": PyramidLevel.TOOLS,
        "ttps": PyramidLevel.TTPS,
    }

    strategies: dict[PyramidLevel, list[ClimbStrategy]] = {}
    for level_key, level_enum in level_mapping.items():
        if level_key in data:
            strategies[level_enum] = [
                {
                    "template": strategy["template"],
                    "target": target_mapping[strategy["target"]],
                    "insight": strategy["insight"],
                    "elevation": strategy["elevation"],
                }
                for strategy in data[level_key]
            ]

    return strategies


CLIMB_STRATEGIES = _load_climb_strategies()

PYRAMID_NAMES = {
    PyramidLevel.HASH_VALUES: "Hash Values",
    PyramidLevel.IP_ADDRESSES: "IP Addresses",
    PyramidLevel.DOMAIN_NAMES: "Domain Names",
    PyramidLevel.NETWORK_HOST_ARTIFACTS: "Network/Host Artifacts",
    PyramidLevel.TOOLS: "Tools",
    PyramidLevel.TTPS: "TTPs",
}


class PyramidClimber:
    """Pyramid of Pain-driven question generator.

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
        """Generate questions that climb the Pyramid of Pain.

        Args:
            state: Current investigation state with evidence to elevate.

        Returns:
            List of InvestigativeQuestion objects that promote climbing to higher
            pyramid levels, prioritized by elevation potential.

        Example:
            >>> climber = PyramidClimber()
            >>> questions = climber.generate_questions(state)
            >>> questions[0].source
            <QuestionSource.PYRAMID: 'pyramid'>
            >>> questions[0].current_pyramid_level
            2
            >>> questions[0].target_pyramid_level
            5

        See Also:
            MITRENavigator.generate_questions: For MITRE ATT&CK questions.
            assess_pyramid_state: For current pyramid position assessment.
        """
        questions = []
        loader = get_template_loader()

        for ev in state.evidence:
            # Skip if already at TTP level
            if ev.pyramid_level == PyramidLevel.TTPS:
                continue

            strategies = CLIMB_STRATEGIES.get(ev.pyramid_level, [])

            for strategy in strategies:
                elevation_score = strategy["elevation"] / 5.0  # Normalize to 0-1

                # Format the question text using the template format string
                question_text = loader.render(
                    "engines/pyramid_climb.md.jinja",
                    question_text=strategy["template"].format(value=ev.value),
                )

                questions.append(
                    InvestigativeQuestion(
                        id=f"pyramid-{uuid.uuid4().hex[:8]}",
                        text=question_text,
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
        """Assess the current Pyramid of Pain state.

        Args:
            state: Current investigation state to assess.

        Returns:
            A dict containing:
                - distribution: Count of evidence at each pyramid level
                - elevation_score: Score from 0-1 indicating how high we've climbed
                - total_evidence: Total number of evidence items
                - recommendations: List of suggestions for improving pyramid position
        """
        distribution = dict.fromkeys(PyramidLevel, 0)

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
    """Combines and prioritizes questions from all engines.

    Attributes:
        mitre: MITRENavigator instance for MITRE-driven questions.
        pyramid: PyramidClimber instance for Pyramid of Pain questions.
    """

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
        """Generate questions from both engines and prioritize.

        Args:
            state: Current investigation state.

        Returns:
            Combined list of questions sorted by priority score (highest first).
        """
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
        """Get a batch of questions that can be executed in parallel.

        Selects high-priority questions that don't conflict with each other.

        Args:
            questions: List of questions to select from.
            max_size: Maximum number of questions to include in batch.

        Returns:
            List of questions that can be safely parallelized, limited to max_size.
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
