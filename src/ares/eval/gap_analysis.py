"""
Detection gap analysis and recommendations.

Analyzes evaluation results to identify detection gaps and provide
actionable recommendations for improving blue team detection capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ares.eval.ground_truth import ExpectedIOC, ExpectedTechnique
    from ares.eval.results import EvaluationResult


@dataclass
class DetectionRecommendation:
    """A recommendation for improving detection.

    Attributes:
        category: Category of recommendation (log_source, rule, query, training).
        priority: Priority level (critical, high, medium, low).
        title: Short title for the recommendation.
        description: Detailed description of the recommendation.
        techniques: Related MITRE technique IDs.
        implementation_hint: Suggested implementation approach.
    """

    category: str  # log_source, rule, query, training
    priority: str  # critical, high, medium, low
    title: str
    description: str
    techniques: list[str] = field(default_factory=list)
    implementation_hint: str = ""


@dataclass
class GapAnalysisReport:
    """Complete gap analysis report for an evaluation.

    Attributes:
        evaluation_id: ID of the evaluated investigation.
        operation_id: Red team operation ID.
        overall_grade: Letter grade from evaluation.
        detection_gaps: List of specific detection gaps identified.
        recommendations: Prioritized list of recommendations.
        summary: Executive summary of findings.
    """

    evaluation_id: str
    operation_id: str
    overall_grade: str
    detection_gaps: list[str] = field(default_factory=list)
    recommendations: list[DetectionRecommendation] = field(default_factory=list)
    summary: str = ""

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# Detection Gap Analysis Report",
            "",
            f"**Evaluation ID:** {self.evaluation_id}",
            f"**Operation ID:** {self.operation_id}",
            f"**Grade:** {self.overall_grade}",
            "",
            "## Executive Summary",
            "",
            self.summary,
            "",
            "## Detection Gaps",
            "",
        ]

        if self.detection_gaps:
            for gap in self.detection_gaps:
                lines.append(f"- {gap}")
        else:
            lines.append("No significant detection gaps identified.")

        lines.extend(
            [
                "",
                "## Recommendations",
                "",
            ]
        )

        if self.recommendations:
            # Group by priority
            for priority in ["critical", "high", "medium", "low"]:
                priority_recs = [r for r in self.recommendations if r.priority == priority]
                if priority_recs:
                    lines.append(f"### {priority.title()} Priority")
                    lines.append("")
                    for rec in priority_recs:
                        lines.append(f"#### {rec.title}")
                        lines.append("")
                        lines.append(f"**Category:** {rec.category}")
                        if rec.techniques:
                            lines.append(f"**Techniques:** {', '.join(rec.techniques)}")
                        lines.append("")
                        lines.append(rec.description)
                        if rec.implementation_hint:
                            lines.append("")
                            lines.append(f"**Implementation:** {rec.implementation_hint}")
                        lines.append("")
        else:
            lines.append("No specific recommendations at this time.")

        return "\n".join(lines)


def analyze_detection_gaps(result: EvaluationResult) -> GapAnalysisReport:
    """Analyze an evaluation result and generate gap analysis report.

    Args:
        result: Completed evaluation result.

    Returns:
        GapAnalysisReport with gaps and recommendations.
    """
    detection_gaps: list[str] = []
    recommendations: list[DetectionRecommendation] = []

    # Analyze missed IOCs
    for ioc in result.missed_iocs:
        gap = _describe_ioc_gap(ioc)
        detection_gaps.append(gap)
        rec = _recommend_for_ioc(ioc)
        if rec:
            recommendations.append(rec)

    # Analyze missed techniques
    for tech in result.missed_techniques:
        gap = _describe_technique_gap(tech)
        detection_gaps.append(gap)
        rec = _recommend_for_technique(tech)
        if rec:
            recommendations.append(rec)

    # Check for alert coverage gap
    if not result.alert_fired:
        detection_gaps.append("No alert fired for this attack scenario")
        recommendations.append(
            DetectionRecommendation(
                category="rule",
                priority="critical",
                title="Create detection rules for attack indicators",
                description=(
                    "The attack did not trigger any alerts. Review the attack "
                    "timeline and create Grafana/Prometheus alerting rules for "
                    "the observed indicators."
                ),
                implementation_hint=(
                    "Create alertmanager rules matching network anomalies, "
                    "authentication events, and process execution patterns."
                ),
            )
        )

    # Check for investigation completion
    if result.investigation_started and not result.investigation_completed:
        detection_gaps.append("Investigation started but did not complete")
        recommendations.append(
            DetectionRecommendation(
                category="training",
                priority="medium",
                title="Improve investigation workflow completion",
                description=(
                    "The investigation was started but did not complete all stages. "
                    "This may indicate gaps in tool availability, data access, "
                    "or investigation methodology."
                ),
            )
        )

    # Check pyramid level
    if result.highest_pyramid_level < 4:
        detection_gaps.append(
            f"Only reached pyramid level {result.highest_pyramid_level}/6 "
            "(did not reach Network/Host Artifacts)"
        )
        recommendations.append(
            DetectionRecommendation(
                category="log_source",
                priority="high",
                title="Enable higher-fidelity log sources",
                description=(
                    "Investigation evidence stayed at lower pyramid levels. "
                    "Enable additional log sources to identify tools and TTPs."
                ),
                implementation_hint=(
                    "Enable Sysmon, PowerShell script block logging, and command-line auditing."
                ),
            )
        )

    # Generate summary
    summary = _generate_summary(result, detection_gaps)

    # Sort recommendations by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda r: priority_order.get(r.priority, 4))

    return GapAnalysisReport(
        evaluation_id=result.evaluation_id,
        operation_id=result.operation_id,
        overall_grade=result.grade,
        detection_gaps=detection_gaps,
        recommendations=recommendations,
        summary=summary,
    )


def _describe_ioc_gap(ioc: ExpectedIOC) -> str:
    """Describe a missed IOC as a gap."""
    required_str = " (required)" if ioc.required else ""
    return f"Missed {ioc.ioc_type} IOC: {ioc.value}{required_str}"


def _describe_technique_gap(tech: ExpectedTechnique) -> str:
    """Describe a missed technique as a gap."""
    required_str = " (required)" if tech.required else ""
    name = f" - {tech.technique_name}" if tech.technique_name else ""
    return f"Missed technique {tech.technique_id}{name}{required_str}"


def _recommend_for_ioc(ioc: ExpectedIOC) -> DetectionRecommendation | None:
    """Generate recommendation for a missed IOC."""
    if ioc.ioc_type == "ip":
        return DetectionRecommendation(
            category="query",
            priority="high" if ioc.required else "medium",
            title=f"Add network IOC detection for {ioc.value}",
            description=(
                f"The IP address {ioc.value} was involved in the attack but not "
                f"detected. Add network-based detection for this and similar IPs."
            ),
            techniques=ioc.mitre_techniques,
            implementation_hint=(
                "Query firewall logs, netflow data, and DNS logs for this IP. "
                "Consider adding threat intelligence feeds."
            ),
        )

    if ioc.ioc_type == "user":
        return DetectionRecommendation(
            category="query",
            priority="critical" if ioc.required else "high",
            title=f"Monitor compromised account: {ioc.value}",
            description=(
                f"User account {ioc.value} was compromised but not detected. "
                f"Add behavioral analysis for this account type."
            ),
            techniques=ioc.mitre_techniques,
            implementation_hint=(
                "Query authentication logs (Windows Security, Kerberos). "
                "Set up anomaly detection for account behavior."
            ),
        )

    if ioc.ioc_type in ("hostname", "domain"):
        return DetectionRecommendation(
            category="query",
            priority="high" if ioc.required else "medium",
            title=f"Add host/domain detection for {ioc.value}",
            description=(
                f"The host/domain {ioc.value} was involved but not detected. "
                f"Ensure logs from this host are being collected."
            ),
            techniques=ioc.mitre_techniques,
            implementation_hint=(
                "Verify log forwarding from this host. Add to asset inventory if missing."
            ),
        )

    if ioc.ioc_type == "hash":
        return DetectionRecommendation(
            category="rule",
            priority="medium",
            title="Implement hash-based detection",
            description=(
                f"File hash {ioc.value[:16]}... was not detected. "
                f"Consider adding hash-based IOC detection."
            ),
            techniques=ioc.mitre_techniques,
            implementation_hint=(
                "Integrate with threat intelligence for hash lookups. "
                "Enable file integrity monitoring."
            ),
        )

    return None


def _recommend_for_technique(tech: ExpectedTechnique) -> DetectionRecommendation | None:
    """Generate recommendation for a missed technique."""
    # Map technique IDs to specific recommendations
    technique_recommendations = {
        "T1003": {
            "title": "Improve credential dumping detection",
            "description": (
                "OS Credential Dumping (T1003) was not detected. This is a "
                "critical technique used in most advanced attacks."
            ),
            "hint": (
                "Enable Sysmon Event ID 10 (process access), monitor LSASS access, "
                "and alert on known credential dumping tools."
            ),
        },
        "T1078": {
            "title": "Enhance valid account abuse detection",
            "description": (
                "Valid Accounts (T1078) abuse was not detected. Monitor for "
                "unusual authentication patterns."
            ),
            "hint": (
                "Implement impossible travel detection, monitor service account "
                "usage, and alert on privilege escalation."
            ),
        },
        "T1558": {
            "title": "Improve Kerberos attack detection",
            "description": (
                "Kerberos attacks (T1558) were not detected. These include "
                "Golden/Silver ticket and Kerberoasting."
            ),
            "hint": (
                "Monitor Event ID 4768/4769, detect TGT anomalies, and alert on "
                "encryption downgrade attacks."
            ),
        },
        "T1021": {
            "title": "Detect lateral movement via remote services",
            "description": (
                "Remote Services (T1021) lateral movement was not detected. "
                "Monitor for unusual remote connections."
            ),
            "hint": (
                "Monitor Event ID 4624 Type 3/10, SMB/RDP connections, and "
                "WinRM/PSRemoting activity."
            ),
        },
        "T1110": {
            "title": "Improve brute force detection",
            "description": (
                "Brute Force (T1110) attacks were not detected. Implement "
                "failed authentication monitoring."
            ),
            "hint": (
                "Alert on multiple failed logins (Event ID 4625), implement "
                "account lockout policies."
            ),
        },
        "T1649": {
            "title": "Detect certificate-based attacks",
            "description": (
                "Certificate abuse (T1649) was not detected. ADCS attacks are increasingly common."
            ),
            "hint": (
                "Monitor certificate requests (Event ID 4886/4887), detect "
                "ESC1-ESC8 vulnerabilities."
            ),
        },
    }

    # Find matching recommendation
    tech_base = tech.technique_id.split(".")[0]
    if tech_base in technique_recommendations:
        rec_info = technique_recommendations[tech_base]
        return DetectionRecommendation(
            category="rule",
            priority="critical" if tech.required else "high",
            title=rec_info["title"],
            description=rec_info["description"],
            techniques=[tech.technique_id],
            implementation_hint=rec_info["hint"],
        )

    # Generic recommendation for unknown techniques
    return DetectionRecommendation(
        category="rule",
        priority="high" if tech.required else "medium",
        title=f"Add detection for {tech.technique_id}",
        description=(
            f"Technique {tech.technique_id} ({tech.technique_name or 'Unknown'}) "
            f"was used but not detected. Research and implement detection."
        ),
        techniques=[tech.technique_id],
        implementation_hint=(
            "Review MITRE ATT&CK documentation for detection guidance. "
            "Consider Sigma rules from the community."
        ),
    )


def _generate_summary(result: EvaluationResult, gaps: list[str]) -> str:
    """Generate executive summary for the report."""
    parts = []

    # Overall assessment
    if result.grade in ("A", "B"):
        parts.append(f"The investigation performed well with a grade of {result.grade}.")
    elif result.grade == "C":
        parts.append(
            f"The investigation achieved a passing grade of {result.grade} but "
            f"has room for improvement."
        )
    else:
        parts.append(
            f"The investigation received a grade of {result.grade}, indicating "
            f"significant detection gaps that need to be addressed."
        )

    # Alert status
    if result.alert_fired:
        parts.append("An alert was successfully triggered for this attack.")
    else:
        parts.append("No alert was triggered, indicating a critical gap in detection rules.")

    # Detection rates
    parts.append(
        f"IOC detection rate was {result.ioc_detection_rate:.0%} and technique "
        f"coverage was {result.technique_coverage:.0%}."
    )

    # Gap count
    if gaps:
        parts.append(f"A total of {len(gaps)} detection gaps were identified.")
    else:
        parts.append("No significant detection gaps were identified.")

    return " ".join(parts)
