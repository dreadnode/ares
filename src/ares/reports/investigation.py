"""
Markdown Report Generator for Ares investigations.

Produces local markdown reports with timeline, MITRE mapping,
Pyramid of Pain assessment, and evidence inventory.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from ares.core.models import InvestigationState, PyramidLevel
from ares.core.templates import get_template_loader

PYRAMID_EMOJI = {
    PyramidLevel.HASH_VALUES: "🔵",
    PyramidLevel.IP_ADDRESSES: "🟢",
    PyramidLevel.DOMAIN_NAMES: "🟡",
    PyramidLevel.NETWORK_HOST_ARTIFACTS: "🟠",
    PyramidLevel.TOOLS: "🔴",
    PyramidLevel.TTPS: "⭐",
}

PYRAMID_NAMES = {
    PyramidLevel.HASH_VALUES: "Hash Values",
    PyramidLevel.IP_ADDRESSES: "IP Addresses",
    PyramidLevel.DOMAIN_NAMES: "Domain Names",
    PyramidLevel.NETWORK_HOST_ARTIFACTS: "Network/Host Artifacts",
    PyramidLevel.TOOLS: "Tools",
    PyramidLevel.TTPS: "TTPs",
}


class MarkdownReportGenerator:
    """Generates local markdown reports from investigation results.

    Attributes:
        output_dir: Directory where reports will be written.
        loader: Template loader for rendering report sections.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.loader = get_template_loader()

    def generate(self, state: InvestigationState) -> Path:
        """Generate the full markdown report.

        Args:
            state: Investigation state containing all findings.

        Returns:
            Path to the generated markdown report file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        alert_name = state.alert.get("labels", {}).get("alertname", "unknown")
        # Sanitize filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in alert_name)
        filename = f"investigation_{safe_name}_{timestamp}.md"
        filepath = self.output_dir / filename

        content = self._build_report(state)
        filepath.write_text(content)

        return filepath

    def _build_report(self, state: InvestigationState) -> str:
        """Build the full report content.

        Args:
            state: Investigation state to generate report from.

        Returns:
            Complete markdown report as a string.
        """
        sections = [
            self._header(state),
            self._executive_summary(state),
            self._timeline_section(state),
            self._mitre_mapping(state),
            self._pyramid_assessment(state),
            self._evidence_inventory(state),
            self._scope_section(state),
            self._recommendations(state),
            self._appendix(state),
        ]

        return "\n\n---\n\n".join(filter(None, sections))

    def _header(self, state: InvestigationState) -> str:
        alert = state.alert
        labels = alert.get("labels", {})

        return self.loader.render(
            "reports/header.md.jinja",
            investigation_id=state.investigation_id,
            generated_timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            duration=self._format_duration(state),
            alert_name=labels.get("alertname", "Unknown"),
            severity=labels.get("severity", "Unknown"),
            instance=labels.get("instance", "Unknown"),
            job=labels.get("job", "Unknown"),
            status="ESCALATED ⚠️" if state.escalated else "COMPLETED ✓",
            alert_json=json.dumps(alert, indent=2, default=str),
        )

    def _executive_summary(self, state: InvestigationState) -> str:
        technique_count = len(state.identified_techniques)
        evidence_count = len(state.evidence)
        ttp_count = state.ttp_count

        # Determine overall assessment
        if state.escalated:
            assessment = "⚠️ **ESCALATED** - Human analyst review required"
        elif ttp_count > 0:
            assessment = "✓ Investigation reached TTP level - actionable intelligence produced"
        elif technique_count > 0:
            assessment = "⚡ Techniques identified but TTP elevation recommended"
        else:
            assessment = "⚪ Limited findings - may require additional investigation"

        # Key findings bullet points
        findings = []
        if state.identified_techniques:
            tech_list = ", ".join(list(state.identified_techniques)[:5])
            findings.append(f"- **MITRE Techniques:** {tech_list}")

        if state.queried_hosts:
            hosts = ", ".join(list(state.queried_hosts)[:3])
            findings.append(f"- **Hosts Investigated:** {hosts}")

        if state.queried_users:
            users = ", ".join(list(state.queried_users)[:3])
            findings.append(f"- **Users Investigated:** {users}")

        high_level_evidence = [e for e in state.evidence if e.pyramid_level.value >= 5]
        if high_level_evidence:
            findings.append(
                f"- **High-Value Indicators:** {len(high_level_evidence)} tools/TTPs identified"
            )

        findings_text = "\n".join(findings) if findings else "- No significant findings recorded"

        return f"""## Executive Summary

{assessment}

**Evidence Collected:** {evidence_count} items
**MITRE Techniques:** {technique_count} identified
**TTPs Identified:** {ttp_count}
**Highest Pyramid Level:** {state.highest_pyramid_level}/6

### Key Findings

{findings_text}

### Attack Synopsis

{state.attack_synopsis or "_No attack synopsis generated. Check recommendations._"}
"""

    def _timeline_section(self, state: InvestigationState) -> str:
        if not state.timeline:
            return """## Timeline

_No timeline events recorded during investigation._
"""

        events = sorted(state.timeline, key=lambda e: e.timestamp)

        rows = []
        for event in events:
            time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            techniques = ", ".join(event.mitre_techniques) if event.mitre_techniques else "-"
            conf = f"{event.confidence:.0%}"
            desc = (
                event.description[:60] + "..." if len(event.description) > 60 else event.description
            )

            rows.append(f"| {time_str} | {desc} | {techniques} | {conf} |")

        table = "\n".join(rows)

        return f"""## Timeline

| Time (UTC) | Event | Techniques | Confidence |
|------------|-------|------------|------------|
{table}
"""

    def _mitre_mapping(self, state: InvestigationState) -> str:
        if not state.identified_techniques:
            return """## MITRE ATT&CK Mapping

_No techniques identified during investigation._
"""

        # Group by tactic (simplified - in full impl would use MITRE data)
        techniques_list = []
        for tech_id in sorted(state.identified_techniques):
            name = state.technique_names.get(tech_id, tech_id)
            tactic = state.technique_to_tactic.get(tech_id, "Unknown")

            # Find supporting evidence
            supporting = [e.id for e in state.evidence if tech_id in e.mitre_techniques]
            evidence_text = ", ".join(supporting[:3]) if supporting else "Inferred"

            techniques_list.append(f"| {tech_id} | {name} | {tactic} | {evidence_text} |")

        table = "\n".join(techniques_list)

        return f"""## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Supporting Evidence |
|--------------|------|--------|---------------------|
{table}

### Attack Lifecycle Coverage

Tactics investigated: {len(state.identified_tactics) if state.identified_tactics else "Unknown"}

_Refer to MITRE ATT&CK Navigator for visual representation._
"""

    def _pyramid_assessment(self, state: InvestigationState) -> str:
        # Count by level
        distribution = dict.fromkeys(PyramidLevel, 0)
        for ev in state.evidence:
            distribution[ev.pyramid_level] += 1

        # Calculate elevation score
        total = len(state.evidence) or 1
        weighted_sum = sum(level.value * count for level, count in distribution.items())
        elevation_score = weighted_sum / (total * 6)

        # Build pyramid visualization
        pyramid_viz = f"""```
                    ▲ TTPs ({distribution[PyramidLevel.TTPS]})
                   ▲▲▲ Tools ({distribution[PyramidLevel.TOOLS]})
                  ▲▲▲▲▲ Artifacts ({distribution[PyramidLevel.NETWORK_HOST_ARTIFACTS]})
                 ▲▲▲▲▲▲▲ Domains ({distribution[PyramidLevel.DOMAIN_NAMES]})
                ▲▲▲▲▲▲▲▲▲ IPs ({distribution[PyramidLevel.IP_ADDRESSES]})
               ▲▲▲▲▲▲▲▲▲▲▲ Hashes ({distribution[PyramidLevel.HASH_VALUES]})
```"""

        # Assessment text
        if distribution[PyramidLevel.TTPS] > 0:
            assessment = (
                "✓ **Investigation successfully elevated to TTP level.** "
                "Actionable intelligence produced."
            )
        elif distribution[PyramidLevel.TOOLS] > 0:
            assessment = (
                "⚡ **Tool-level indicators identified.** Consider further elevation to TTPs."
            )
        elif (
            distribution[PyramidLevel.HASH_VALUES] + distribution[PyramidLevel.IP_ADDRESSES]
            > distribution[PyramidLevel.TOOLS]
        ):
            assessment = (
                "⚠️ **Heavy on trivial indicators.** "
                "Investigation may benefit from deeper analysis to identify tools and TTPs."
            )
        else:
            assessment = "⚪ **Limited evidence.** More investigation may be needed."

        return f"""## Pyramid of Pain Assessment

**Elevation Score:** {elevation_score:.1%} (higher is better)

{pyramid_viz}

### Assessment

{assessment}

### Distribution

| Level | Name | Count | Adversary Pain |
|-------|------|-------|----------------|
| 6 | TTPs | {distribution[PyramidLevel.TTPS]} | Tough! |
| 5 | Tools | {distribution[PyramidLevel.TOOLS]} | Challenging |
| 4 | Artifacts | {distribution[PyramidLevel.NETWORK_HOST_ARTIFACTS]} | Annoying |
| 3 | Domains | {distribution[PyramidLevel.DOMAIN_NAMES]} | Simple |
| 2 | IPs | {distribution[PyramidLevel.IP_ADDRESSES]} | Easy |
| 1 | Hashes | {distribution[PyramidLevel.HASH_VALUES]} | Trivial |
"""

    def _evidence_inventory(self, state: InvestigationState) -> str:
        if not state.evidence:
            return """## Evidence Inventory

_No evidence recorded during investigation._
"""

        sections = []

        # Group by pyramid level (highest first)
        for level in reversed(PyramidLevel):
            level_evidence = [e for e in state.evidence if e.pyramid_level == level]
            if not level_evidence:
                continue

            emoji = PYRAMID_EMOJI[level]
            name = PYRAMID_NAMES[level]

            rows = []
            for ev in level_evidence:
                techniques = ", ".join(ev.mitre_techniques[:2]) if ev.mitre_techniques else "-"
                value_display = ev.value[:40] + "..." if len(ev.value) > 40 else ev.value
                conf = f"{ev.confidence:.0%}"

                rows.append(f"| {ev.id} | {ev.type} | `{value_display}` | {techniques} | {conf} |")

            table = "\n".join(rows)

            sections.append(f"""### {emoji} {name} (Level {level.value})

| ID | Type | Value | Techniques | Confidence |
|----|------|-------|------------|------------|
{table}
""")

        return "## Evidence Inventory\n\n" + "\n".join(sections)

    def _scope_section(self, state: InvestigationState) -> str:
        hosts = list(state.queried_hosts)
        users = list(state.queried_users)

        if not hosts and not users:
            return """## Scope Assessment

_No lateral investigation performed._
"""

        hosts_text = "\n".join([f"- `{h}`" for h in hosts]) if hosts else "_None_"
        users_text = "\n".join([f"- `{u}`" for u in users]) if users else "_None_"

        return f"""## Scope Assessment

### Hosts Investigated

{hosts_text}

### Users Investigated

{users_text}

### Scope Summary

- **{len(hosts)}** hosts investigated
- **{len(users)}** users investigated
"""

    def _recommendations(self, state: InvestigationState) -> str:
        recs = state.recommendations or []

        if state.escalated:
            escalation_section = f"""### ⚠️ ESCALATION REQUIRED

**Reason:** {state.escalation_reason or "Not specified"}

This investigation has been escalated for human analyst review.
"""
        else:
            escalation_section = ""

        if recs:
            recs_text = "\n".join([f"{i}. {r}" for i, r in enumerate(recs, 1)])
        else:
            recs_text = "_No specific recommendations generated._"

        # Auto-generate detection recommendations
        detection_recs = []
        for tech_id in list(state.identified_techniques)[:5]:
            detection_recs.append(f"- Add detection rule for **{tech_id}**")

        detection_text = (
            "\n".join(detection_recs)
            if detection_recs
            else "_No detection improvements suggested._"
        )

        return f"""## Recommendations

{escalation_section}

### Immediate Actions

{recs_text}

### Detection Improvements

{detection_text}
"""

    def _appendix(self, state: InvestigationState) -> str:
        queries = state.executed_queries[:20] if state.executed_queries else []

        if not queries:
            return """## Appendix

### Queries Executed

_No query data recorded._
"""

        query_sections = []
        for i, q in enumerate(queries, 1):
            query_sections.append(f"""**Query {i}** ({q.get("type", "unknown")})
```
{q.get("query", "N/A")}
```
Results: {q.get("result_count", "N/A")} items
""")

        queries_text = "\n".join(query_sections)

        return f"""## Appendix

### Queries Executed

{queries_text}

### Investigation Metadata

- **Started:** {state.started_at.isoformat()}Z
- **Evidence Items:** {len(state.evidence)}
- **Timeline Events:** {len(state.timeline)}
- **Questions Generated:** {len(state.questions)}
"""

    def _format_duration(self, state: InvestigationState) -> str:
        """Format the investigation duration."""
        duration = datetime.now(timezone.utc) - state.started_at
        minutes = int(duration.total_seconds() / 60)
        seconds = int(duration.total_seconds() % 60)
        return f"{minutes}m {seconds}s"
