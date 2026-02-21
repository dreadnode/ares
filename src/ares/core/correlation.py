"""
Red-Blue Correlation Engine.

Correlates red team attack activities with blue team detections
to measure detection coverage and identify gaps.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

from loguru import logger


@dataclass
class RedTeamActivity:
    """A single red team activity/action."""

    timestamp: datetime
    technique_id: str | None
    technique_name: str | None
    action: str
    target_ip: str | None
    target_host: str | None
    credential_used: str | None
    success: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Generate a unique key for this activity."""
        return f"{self.timestamp.isoformat()}:{self.technique_id}:{self.target_ip}"


@dataclass
class BlueTeamDetection:
    """A blue team detection/alert."""

    timestamp: datetime
    alert_name: str
    technique_id: str | None
    severity: str
    target_ip: str | None
    target_host: str | None
    investigation_id: str | None
    status: str  # completed, escalated, timeout
    evidence_count: int
    highest_pyramid_level: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Generate a unique key for this detection."""
        return f"{self.timestamp.isoformat()}:{self.technique_id}:{self.alert_name}"


@dataclass
class CorrelationMatch:
    """A match between red team activity and blue team detection."""

    red_activity: RedTeamActivity
    blue_detection: BlueTeamDetection
    time_delta_seconds: float
    technique_match: bool
    target_match: bool
    confidence: float

    @property
    def match_quality(self) -> str:
        """Assess the quality of this match."""
        if self.technique_match and self.target_match and abs(self.time_delta_seconds) < 300:
            return "STRONG"
        if self.technique_match and abs(self.time_delta_seconds) < 600:
            return "GOOD"
        if self.technique_match or (self.target_match and abs(self.time_delta_seconds) < 300):
            return "WEAK"
        return "TENUOUS"


@dataclass
class DetectionGap:
    """An undetected red team activity."""

    red_activity: RedTeamActivity
    reason: str
    recommended_detection: str | None = None
    mitre_data_sources: list[str] = field(default_factory=list)


@dataclass
class CorrelationReport:
    """Full correlation analysis report."""

    analysis_timestamp: datetime
    red_operation_id: str
    time_window_start: datetime
    time_window_end: datetime

    # Counts
    total_red_activities: int
    total_blue_detections: int
    matched_activities: int
    undetected_activities: int
    false_positive_detections: int

    # Details
    matches: list[CorrelationMatch]
    gaps: list[DetectionGap]
    false_positives: list[BlueTeamDetection]

    # Metrics
    detection_rate: float
    false_positive_rate: float
    mean_time_to_detect: float | None  # seconds

    # By technique
    technique_coverage: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "red_operation_id": self.red_operation_id,
            "time_window": {
                "start": self.time_window_start.isoformat(),
                "end": self.time_window_end.isoformat(),
            },
            "summary": {
                "total_red_activities": self.total_red_activities,
                "total_blue_detections": self.total_blue_detections,
                "matched_activities": self.matched_activities,
                "undetected_activities": self.undetected_activities,
                "false_positive_detections": self.false_positive_detections,
                "detection_rate": f"{self.detection_rate * 100:.1f}%",
                "false_positive_rate": f"{self.false_positive_rate * 100:.1f}%",
                "mean_time_to_detect": f"{self.mean_time_to_detect:.1f}s"
                if self.mean_time_to_detect
                else "N/A",
            },
            "technique_coverage": self.technique_coverage,
            "matches": [
                {
                    "red_technique": m.red_activity.technique_id,
                    "red_action": m.red_activity.action[:100],
                    "blue_alert": m.blue_detection.alert_name,
                    "time_delta_seconds": m.time_delta_seconds,
                    "match_quality": m.match_quality,
                    "confidence": m.confidence,
                }
                for m in self.matches
            ],
            "gaps": [
                {
                    "technique": g.red_activity.technique_id,
                    "action": g.red_activity.action[:100],
                    "timestamp": g.red_activity.timestamp.isoformat(),
                    "reason": g.reason,
                    "recommended_detection": g.recommended_detection,
                }
                for g in self.gaps
            ],
            "false_positives": [
                {
                    "alert_name": fp.alert_name,
                    "technique": fp.technique_id,
                    "timestamp": fp.timestamp.isoformat(),
                }
                for fp in self.false_positives
            ],
        }


class RedBlueCorrelator:
    """Correlates red team activities with blue team detections.

    This engine:
    1. Parses red team operation reports
    2. Parses blue team investigation reports
    3. Matches activities based on time, technique, and target
    4. Identifies detection gaps
    5. Calculates coverage metrics
    """

    # Time window for matching (activities within this window are considered related)
    DEFAULT_TIME_WINDOW_MINUTES = 30

    TECHNIQUE_PATTERNS: ClassVar[list[str]] = [
        r"T\d{4}(?:\.\d{3})?",  # T1234 or T1234.001
    ]

    @staticmethod
    def _techniques_match(red_technique: str | None, blue_technique: str | None) -> bool:
        """Check if MITRE techniques match, supporting hierarchical matching.

        Supports:
        - Exact match: T1003 == T1003
        - Parent matches child: T1003 matches T1003.006 (blue detected parent, red used sub-technique)
        - Child matches parent: T1003.006 matches T1003 (blue detected sub-technique, red logged parent)

        Args:
            red_technique: Red team technique ID (e.g., T1003.006)
            blue_technique: Blue team detected technique ID (e.g., T1003)

        Returns:
            True if techniques match hierarchically
        """
        if red_technique is None or blue_technique is None:
            return False

        # Normalize to uppercase for comparison
        red = red_technique.upper().strip()
        blue = blue_technique.upper().strip()

        # Exact match
        if red == blue:
            return True

        # Extract parent technique (T1003 from T1003.006)
        red_parent = red.split(".")[0] if "." in red else red
        blue_parent = blue.split(".")[0] if "." in blue else blue

        # Parent techniques must match for any hierarchical relationship
        # T1003 matches T1003.006 (parent matches child)
        # T1003.006 matches T1003 (child matches parent)
        return red_parent == blue_parent

    def __init__(
        self,
        reports_dir: Path,
        time_window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES,
    ):
        """Initialize the correlator.

        Args:
            reports_dir: Directory containing red team and investigation reports
            time_window_minutes: Time window for matching activities
        """
        self.reports_dir = Path(reports_dir)
        self.time_window = timedelta(minutes=time_window_minutes)

    def load_red_team_report(self, report_path: Path) -> tuple[str, list[RedTeamActivity]]:
        """Load and parse a red team report.

        Args:
            report_path: Path to the red team report markdown file

        Returns:
            Tuple of (operation_id, list of activities)
        """
        content = report_path.read_text()
        activities = []

        operation_id_match = re.search(r"\*\*Operation ID\*\*:\s*(\S+)", content)
        operation_id = operation_id_match.group(1) if operation_id_match else "unknown"

        target_ip_match = re.search(r"\*\*Target\*\*:\s*(\d+\.\d+\.\d+\.\d+)", content)
        target_ip = target_ip_match.group(1) if target_ip_match else None

        started_match = re.search(r"\*\*Started\*\*:\s*(.+?)(?:\n|$)", content)
        if started_match:
            try:
                started_at = datetime.strptime(
                    started_match.group(1).strip(), "%Y-%m-%d %H:%M:%S UTC"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                started_at = datetime.now(timezone.utc)
        else:
            started_at = datetime.now(timezone.utc)

        hosts_section = re.search(r"### Hosts \((\d+)\)(.*?)(?=###|\Z)", content, re.DOTALL)
        if hosts_section:
            host_count = int(hosts_section.group(1))
            if host_count > 0:
                activities.append(
                    RedTeamActivity(
                        timestamp=started_at,
                        technique_id="T1046",  # Network Service Discovery
                        technique_name="Network Service Discovery",
                        action=f"Discovered {host_count} host(s) via network scanning",
                        target_ip=target_ip,
                        target_host=None,
                        credential_used=None,
                        success=True,
                    )
                )

        creds_section = re.search(r"### Credentials \((\d+)\)(.*?)(?=###|\Z)", content, re.DOTALL)
        if creds_section:
            creds_content = creds_section.group(2)

            cred_matches = re.findall(
                r"\*\*(\S+)\*\*\s*\n.*?Source:\s*(.+?)(?:\n|$)", creds_content
            )
            for username, source in cred_matches:
                activities.append(
                    RedTeamActivity(
                        timestamp=started_at + timedelta(minutes=1),  # Slightly after start
                        technique_id="T1110" if "guessing" in source.lower() else "T1003",
                        technique_name="Credential Guessing"
                        if "guessing" in source.lower()
                        else "Credential Dumping",
                        action=f"Obtained credential for {username} via {source}",
                        target_ip=target_ip,
                        target_host=None,
                        credential_used=None,
                        success=True,
                        metadata={"username": username, "source": source},
                    )
                )

        timeline_section = re.search(
            r"### Timeline of Key Events(.*?)(?=---|\Z)", content, re.DOTALL
        )
        if timeline_section:
            timeline_content = timeline_section.group(1)
            event_matches = re.findall(
                r"\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*(T\d{4}(?:\.\d{3})?)\s*\|", timeline_content
            )
            for timestamp_str, description, technique_id in event_matches:
                try:
                    event_time = datetime.fromisoformat(
                        timestamp_str.strip().replace("Z", "+00:00")
                    )
                except ValueError:
                    event_time = started_at
                activities.append(
                    RedTeamActivity(
                        timestamp=event_time,
                        technique_id=technique_id.strip(),
                        technique_name=None,
                        action=description.strip(),
                        target_ip=target_ip,
                        target_host=None,
                        credential_used=None,
                        success=True,
                    )
                )

        if "Domain Admin Access**: ✓" in content or "has_domain_admin: true" in content.lower():
            activities.append(
                RedTeamActivity(
                    timestamp=started_at + timedelta(minutes=5),
                    technique_id="T1078.002",
                    technique_name="Valid Accounts: Domain Accounts",
                    action="Achieved Domain Admin access",
                    target_ip=target_ip,
                    target_host=None,
                    credential_used=None,
                    success=True,
                )
            )

        if "Golden Ticket**: ✓" in content or "has_golden_ticket: true" in content.lower():
            activities.append(
                RedTeamActivity(
                    timestamp=started_at + timedelta(minutes=6),
                    technique_id="T1558.001",
                    technique_name="Golden Ticket",
                    action="Generated Golden Ticket for persistence",
                    target_ip=target_ip,
                    target_host=None,
                    credential_used=None,
                    success=True,
                )
            )

        logger.info(f"Loaded {len(activities)} activities from red team report {operation_id}")
        return operation_id, activities

    def load_investigation_report(self, report_path: Path) -> BlueTeamDetection | None:
        """Load and parse a blue team investigation report.

        Args:
            report_path: Path to the investigation report markdown file

        Returns:
            BlueTeamDetection object or None if parsing fails
        """
        content = report_path.read_text()

        # Skip DatasourceNoData reports
        if "DatasourceNoData" in report_path.name:
            return None

        inv_id_match = re.search(r"\*\*Investigation ID:\*\*\s*`?(\S+?)`?(?:\n|$)", content)
        investigation_id = inv_id_match.group(1) if inv_id_match else None

        alert_match = re.search(r"\|\s*Alert Name\s*\|\s*(.+?)\s*\|", content)
        alert_name = alert_match.group(1).strip() if alert_match else "Unknown"

        severity_match = re.search(r"\|\s*Severity\s*\|\s*(\w+)\s*\|", content)
        severity = severity_match.group(1).strip() if severity_match else "unknown"

        starts_at_match = re.search(r'"startsAt":\s*"([^"]+)"', content)
        if starts_at_match:
            try:
                timestamp = datetime.fromisoformat(starts_at_match.group(1).replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            # Try to extract from filename
            date_match = re.search(r"(\d{8}_\d{6})", report_path.name)
            if date_match:
                try:
                    timestamp = datetime.strptime(date_match.group(1), "%Y%m%d_%H%M%S").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)

        technique_match = re.search(r"(T\d{4}(?:\.\d{3})?)", content)
        technique_id = technique_match.group(1) if technique_match else None

        status_match = re.search(r"\|\s*Status\s*\|\s*(\w+)", content)
        status = status_match.group(1).strip().lower() if status_match else "unknown"

        evidence_match = re.search(r"\*\*Evidence Collected:\*\*\s*(\d+)", content)
        evidence_count = int(evidence_match.group(1)) if evidence_match else 0

        pyramid_match = re.search(r"\*\*Highest Pyramid Level:\*\*\s*(\d+)", content)
        highest_pyramid_level = int(pyramid_match.group(1)) if pyramid_match else 0

        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", content)
        target_ip = ip_match.group(1) if ip_match else None

        return BlueTeamDetection(
            timestamp=timestamp,
            alert_name=alert_name,
            technique_id=technique_id,
            severity=severity,
            target_ip=target_ip,
            target_host=None,
            investigation_id=investigation_id,
            status=status,
            evidence_count=evidence_count,
            highest_pyramid_level=highest_pyramid_level,
        )

    def load_all_reports(
        self,
    ) -> tuple[list[tuple[str, list[RedTeamActivity]]], list[BlueTeamDetection]]:
        """Load all reports from the reports directory.

        Returns:
            Tuple of (list of (operation_id, activities), list of detections)
        """
        red_team_reports = []
        blue_team_detections = []

        for report_file in self.reports_dir.glob("*.md"):
            if report_file.name.startswith("redteam-"):
                try:
                    operation_id, activities = self.load_red_team_report(report_file)
                    red_team_reports.append((operation_id, activities))
                except Exception as e:
                    logger.warning(f"Failed to parse red team report {report_file}: {e}")

            elif report_file.name.startswith("investigation_"):
                try:
                    detection = self.load_investigation_report(report_file)
                    if detection:
                        blue_team_detections.append(detection)
                except Exception as e:
                    logger.warning(f"Failed to parse investigation report {report_file}: {e}")

        logger.info(
            f"Loaded {len(red_team_reports)} red team reports, "
            f"{len(blue_team_detections)} investigation reports"
        )
        return red_team_reports, blue_team_detections

    def correlate(
        self,
        red_activities: list[RedTeamActivity],
        blue_detections: list[BlueTeamDetection],
        operation_id: str = "unknown",
    ) -> CorrelationReport:
        """Correlate red team activities with blue team detections.

        Args:
            red_activities: List of red team activities
            blue_detections: List of blue team detections
            operation_id: Red team operation ID

        Returns:
            CorrelationReport with analysis results
        """
        matches: list[CorrelationMatch] = []
        matched_red_keys: set[str] = set()
        matched_blue_keys: set[str] = set()

        red_activities = sorted(red_activities, key=lambda x: x.timestamp)
        blue_detections = sorted(blue_detections, key=lambda x: x.timestamp)

        if red_activities:
            time_window_start = min(a.timestamp for a in red_activities) - self.time_window
            time_window_end = max(a.timestamp for a in red_activities) + self.time_window
        else:
            time_window_start = datetime.now(timezone.utc) - timedelta(hours=1)
            time_window_end = datetime.now(timezone.utc)

        # Match activities to detections
        for red_activity in red_activities:
            best_match: CorrelationMatch | None = None
            best_confidence = 0.0

            for detection in blue_detections:
                time_delta = (detection.timestamp - red_activity.timestamp).total_seconds()

                if abs(time_delta) > self.time_window.total_seconds():
                    continue

                technique_match = self._techniques_match(
                    red_activity.technique_id, detection.technique_id
                )

                target_match = (
                    red_activity.target_ip is not None
                    and detection.target_ip is not None
                    and red_activity.target_ip == detection.target_ip
                )

                confidence = 0.0
                if technique_match:
                    confidence += 0.5
                if target_match:
                    confidence += 0.3
                # Time proximity bonus (closer = higher confidence)
                time_bonus = max(0, 1 - abs(time_delta) / self.time_window.total_seconds()) * 0.2
                confidence += time_bonus

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = CorrelationMatch(
                        red_activity=red_activity,
                        blue_detection=detection,
                        time_delta_seconds=time_delta,
                        technique_match=technique_match,
                        target_match=target_match,
                        confidence=confidence,
                    )

            if best_match and best_match.confidence >= 0.3:
                matches.append(best_match)
                matched_red_keys.add(red_activity.key)
                matched_blue_keys.add(best_match.blue_detection.key)

        # Identify detection gaps (undetected red activities)
        gaps: list[DetectionGap] = []
        for activity in red_activities:
            if activity.key not in matched_red_keys:
                gap = DetectionGap(
                    red_activity=activity,
                    reason=self._determine_gap_reason(activity, blue_detections),
                    recommended_detection=self._recommend_detection(activity),
                )
                gaps.append(gap)

        # Identify false positives (detections without matching red activity)
        false_positives: list[BlueTeamDetection] = []
        for detection in blue_detections:
            if (
                detection.key not in matched_blue_keys
                and time_window_start <= detection.timestamp <= time_window_end
            ):
                false_positives.append(detection)

        total_red = len(red_activities)
        matched_count = len(matches)
        detection_rate = matched_count / total_red if total_red > 0 else 0.0

        detections_in_window = len(
            [d for d in blue_detections if time_window_start <= d.timestamp <= time_window_end]
        )
        false_positive_rate = (
            len(false_positives) / detections_in_window if detections_in_window > 0 else 0.0
        )

        time_deltas = [abs(m.time_delta_seconds) for m in matches if m.time_delta_seconds >= 0]
        mean_ttd = sum(time_deltas) / len(time_deltas) if time_deltas else None

        technique_coverage = self._calculate_technique_coverage(red_activities, matches, gaps)

        return CorrelationReport(
            analysis_timestamp=datetime.now(timezone.utc),
            red_operation_id=operation_id,
            time_window_start=time_window_start,
            time_window_end=time_window_end,
            total_red_activities=total_red,
            total_blue_detections=len(blue_detections),
            matched_activities=matched_count,
            undetected_activities=len(gaps),
            false_positive_detections=len(false_positives),
            matches=matches,
            gaps=gaps,
            false_positives=false_positives,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            mean_time_to_detect=mean_ttd,
            technique_coverage=technique_coverage,
        )

    def _determine_gap_reason(
        self,
        activity: RedTeamActivity,
        detections: list[BlueTeamDetection],
    ) -> str:
        """Determine why an activity was not detected."""
        if not activity.technique_id:
            return "Activity has no associated MITRE technique"

        # Check for any technique match (including hierarchical)
        technique_alerts = [
            d for d in detections if self._techniques_match(activity.technique_id, d.technique_id)
        ]
        if not technique_alerts:
            return f"No alert rules configured for technique {activity.technique_id}"

        return "Alert exists but did not trigger within time window (possible log ingestion delay or query timeout)"

    def _recommend_detection(self, activity: RedTeamActivity) -> str | None:
        """Recommend a detection for an undetected activity."""
        technique_recommendations = {
            "T1046": "Add alert for network scanning patterns (nmap, masscan)",
            "T1110": "Add alert for multiple failed authentication attempts",
            "T1003": "Add alert for LSASS access or credential dumping tools",
            "T1078.002": "Add alert for new domain admin group membership",
            "T1558.001": "Add alert for krbtgt service ticket requests with RC4",
            "T1021.002": "Add alert for remote SMB connections from unusual sources",
        }
        if activity.technique_id:
            return technique_recommendations.get(activity.technique_id)
        return None

    def _calculate_technique_coverage(
        self,
        activities: list[RedTeamActivity],
        matches: list[CorrelationMatch],
        gaps: list[DetectionGap],
    ) -> dict[str, dict[str, Any]]:
        """Calculate detection coverage per technique."""
        coverage: dict[str, dict[str, Any]] = {}

        for activity in activities:
            if activity.technique_id:
                if activity.technique_id not in coverage:
                    coverage[activity.technique_id] = {
                        "total": 0,
                        "detected": 0,
                        "missed": 0,
                        "detection_rate": 0.0,
                    }
                coverage[activity.technique_id]["total"] += 1

        for match in matches:
            if match.red_activity.technique_id:
                coverage[match.red_activity.technique_id]["detected"] += 1

        for gap in gaps:
            if gap.red_activity.technique_id:
                coverage[gap.red_activity.technique_id]["missed"] += 1

        for data in coverage.values():
            if data["total"] > 0:
                data["detection_rate"] = data["detected"] / data["total"]

        return coverage

    def generate_report_markdown(self, report: CorrelationReport) -> str:
        """Generate a markdown report from correlation results.

        Args:
            report: CorrelationReport object

        Returns:
            Markdown formatted report string
        """
        lines = [
            "# Red-Blue Correlation Report",
            "",
            f"**Analysis Time:** {report.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Red Team Operation:** {report.red_operation_id}",
            f"**Time Window:** {report.time_window_start.strftime('%Y-%m-%d %H:%M')} to {report.time_window_end.strftime('%Y-%m-%d %H:%M')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Red Team Activities | {report.total_red_activities} |",
            f"| Blue Team Detections | {report.total_blue_detections} |",
            f"| Matched (Detected) | {report.matched_activities} |",
            f"| Detection Gaps | {report.undetected_activities} |",
            f"| False Positives | {report.false_positive_detections} |",
            f"| **Detection Rate** | **{report.detection_rate * 100:.1f}%** |",
            f"| False Positive Rate | {report.false_positive_rate * 100:.1f}% |",
            f"| Mean Time to Detect | {f'{report.mean_time_to_detect:.0f}s' if report.mean_time_to_detect else 'N/A'} |",
            "",
        ]

        # Detection rate assessment
        if report.detection_rate >= 0.8:
            assessment = "EXCELLENT - Blue team is detecting most red team activities"
        elif report.detection_rate >= 0.6:
            assessment = "GOOD - Majority of activities detected, some gaps remain"
        elif report.detection_rate >= 0.4:
            assessment = "MODERATE - Significant detection gaps exist"
        else:
            assessment = "POOR - Most red team activities went undetected"

        lines.extend(
            [
                f"### Assessment: {assessment}",
                "",
                "---",
                "",
            ]
        )

        # Technique coverage
        if report.technique_coverage:
            lines.extend(
                [
                    "## Technique Coverage",
                    "",
                    "| Technique | Total | Detected | Missed | Rate |",
                    "|-----------|-------|----------|--------|------|",
                ]
            )
            for tech_id, data in sorted(report.technique_coverage.items()):
                rate_str = f"{data['detection_rate'] * 100:.0f}%"
                rate_emoji = (
                    "✅"
                    if data["detection_rate"] >= 0.8
                    else "⚠️"
                    if data["detection_rate"] >= 0.5
                    else "❌"
                )
                lines.append(
                    f"| {tech_id} | {data['total']} | {data['detected']} | {data['missed']} | {rate_emoji} {rate_str} |"
                )
            lines.extend(["", "---", ""])

        # Successful detections
        if report.matches:
            lines.extend(
                [
                    "## Successful Detections",
                    "",
                    "| Red Activity | Blue Alert | Time Delta | Quality |",
                    "|--------------|------------|------------|---------|",
                ]
            )
            for match in report.matches[:20]:  # Limit to 20
                lines.append(
                    f"| {match.red_activity.technique_id or 'N/A'}: {match.red_activity.action[:40]}... | "
                    f"{match.blue_detection.alert_name[:30]}... | "
                    f"{match.time_delta_seconds:.0f}s | "
                    f"{match.match_quality} |"
                )
            lines.extend(["", "---", ""])

        # Detection gaps
        if report.gaps:
            lines.extend(
                [
                    "## Detection Gaps (Undetected Activities)",
                    "",
                    "| Technique | Activity | Reason | Recommendation |",
                    "|-----------|----------|--------|----------------|",
                ]
            )
            for gap in report.gaps[:20]:  # Limit to 20
                lines.append(
                    f"| {gap.red_activity.technique_id or 'N/A'} | "
                    f"{gap.red_activity.action[:40]}... | "
                    f"{gap.reason[:40]}... | "
                    f"{gap.recommended_detection or 'N/A'} |"
                )
            lines.extend(["", "---", ""])

        # False positives
        if report.false_positives:
            lines.extend(
                [
                    "## False Positives (Detections without Red Activity)",
                    "",
                    "| Alert | Technique | Time |",
                    "|-------|-----------|------|",
                ]
            )
            for fp in report.false_positives[:10]:  # Limit to 10
                lines.append(
                    f"| {fp.alert_name[:40]}... | {fp.technique_id or 'N/A'} | {fp.timestamp.strftime('%H:%M:%S')} |"
                )
            lines.extend(["", "---", ""])

        # Recommendations
        lines.extend(
            [
                "## Recommendations",
                "",
            ]
        )

        if report.gaps:
            # Group recommendations by technique
            recommendations = {}
            for gap in report.gaps:
                if gap.recommended_detection:
                    tech = gap.red_activity.technique_id or "General"
                    if tech not in recommendations:
                        recommendations[tech] = gap.recommended_detection

            for i, (tech, rec) in enumerate(recommendations.items(), 1):
                lines.append(f"{i}. **{tech}**: {rec}")

        if report.detection_rate < 0.8:
            lines.extend(
                [
                    "",
                    "### General Improvements",
                    "- Review query timeout issues in Loki/Grafana",
                    "- Ensure log ingestion latency is < 60 seconds",
                    "- Add missing detection rules for uncovered techniques",
                    "- Consider increasing alert rule evaluation frequency",
                ]
            )

        lines.extend(
            [
                "",
                "---",
                "",
                "*Report generated by Ares Red-Blue Correlation Engine*",
            ]
        )

        return "\n".join(lines)

    def run_full_analysis(self) -> list[CorrelationReport]:
        """Run correlation analysis on all reports in the directory.

        Returns:
            List of CorrelationReport objects, one per red team operation
        """
        red_reports, blue_detections = self.load_all_reports()

        reports = []
        for operation_id, activities in red_reports:
            report = self.correlate(activities, blue_detections, operation_id)
            reports.append(report)

            # Generate and save markdown report
            markdown = self.generate_report_markdown(report)
            report_path = self.reports_dir / f"correlation_{operation_id}.md"
            report_path.write_text(markdown)
            logger.success(f"Generated correlation report: {report_path}")

        return reports
