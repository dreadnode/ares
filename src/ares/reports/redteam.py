"""
Markdown Report Generator for red team operations.

Produces detailed penetration testing reports with discovered assets,
credentials, attack paths, and MITRE ATT&CK mapping.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from ares.core.templates import get_template_loader

if TYPE_CHECKING:
    from ares.core.models import SharedRedTeamState


@lru_cache(maxsize=1)
def _load_mitre_techniques() -> dict[str, str]:
    """Load MITRE technique names from YAML file.

    Returns:
        Dict mapping technique IDs to names (e.g., "T1003" -> "OS Credential Dumping")
    """
    yaml_path = Path(__file__).parent.parent / "templates" / "mitre_techniques.yaml"
    try:
        with open(yaml_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _get_technique_display(technique_id: str) -> str:
    """Get display string for a MITRE technique ID.

    Args:
        technique_id: MITRE technique ID (e.g., "T1003.006")

    Returns:
        Formatted string like "T1003.006 (DCSync)" or just "T1003.006" if unknown
    """
    techniques = _load_mitre_techniques()
    name = techniques.get(technique_id)
    if name:
        return f"{technique_id} ({name})"
    return technique_id


def _format_vuln_details(details: Any) -> str:
    """Format vulnerability details dict as readable text.

    Args:
        details: Vulnerability details (dict, str, or other)

    Returns:
        Human-readable formatted string
    """
    if not details:
        return "-"
    if isinstance(details, str):
        return details
    if not isinstance(details, dict):
        return str(details)

    # Key display names and order
    key_display = {
        "account": "Account",
        "account_name": "Account",
        "username": "Username",
        "domain": "Domain",
        "target_spn": "Target SPN",
        "delegation_type": "Type",
        "dc_ip": "DC IP",
        "ca_name": "CA Name",
        "ca_host": "CA Host",
        "hostname": "Hostname",
        "hash": "Hash",
        "note": "Note",
        "attack_type": "Attack Type",
        "adcs_server": "ADCS Server",
    }

    # Skip internal/redundant keys
    skip_keys = {
        "has_credentials",
        "discovered_by",
        "services",
        "available_credentials",
        "attack_steps",
        "is_sql_account",
    }

    parts = []
    for key, display_name in key_display.items():
        if key in details and key not in skip_keys:
            value = details[key]
            if value is not None and value != "":
                parts.append(f"{display_name}: {value}")

    for key, value in details.items():
        if (
            key not in key_display
            and key not in skip_keys
            and value is not None
            and value != ""
            and not isinstance(value, (list, dict))
        ):
            display_key = key.replace("_", " ").title()
            parts.append(f"{display_key}: {value}")

    return "; ".join(parts) if parts else "-"


def _parse_weakness_block(block: str) -> dict[str, str]:
    """Parse a markdown weakness block into structured fields."""
    result: dict[str, str] = {}
    if not block:
        return result

    lines = block.strip().split("\n")
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue

        if stripped.startswith("### "):
            result["title"] = stripped[4:].strip()
        elif stripped.startswith("**") and ":**" not in stripped and stripped.endswith("**"):
            result["title"] = stripped.strip("*").strip()

        elif ":**" in stripped:
            clean = stripped.lstrip("-").strip()
            match = re.match(r"\*\*([^*:]+):\*\*\s*(.*)$", clean)
            if match:
                key = match.group(1).strip().lower().replace(" ", "_")
                value = match.group(2).strip()
                result[key] = value

    return result


def _deduplicate_weaknesses(weaknesses: list[str]) -> list[dict[str, str]]:
    """Parse and deduplicate weaknesses by normalized title.

    This provides a final deduplication pass at report generation time
    to catch any duplicates that might have slipped through.
    """
    seen_titles: set[str] = set()
    result: list[dict[str, str]] = []

    for w in weaknesses:
        parsed = _parse_weakness_block(w)
        title = parsed.get("title", "").strip()
        # Normalize title for deduplication: lowercase, normalize dashes (em-dash \u2014, en-dash \u2013)
        normalized_title = title.lower().replace("\u2014", "-").replace("\u2013", "-")
        normalized_title = " ".join(normalized_title.split())

        if normalized_title and normalized_title in seen_titles:
            continue
        if normalized_title:
            seen_titles.add(normalized_title)
        result.append(parsed)

    return result


class RedTeamReportGenerator:
    """Generates markdown reports from red team operation results.

    Attributes:
        loader: Template loader for rendering report sections.
    """

    def __init__(self):
        self.loader = get_template_loader()

    def generate(self, state: SharedRedTeamState) -> str:
        """Generate the full markdown report.

        Args:
            state: Red team operation state containing all findings.

        Returns:
            Complete markdown report as a string.
        """
        # Use persisted completed_at if available (for SharedRedTeamState)
        completed_at = getattr(state, "completed_at", None) or datetime.now(timezone.utc)
        duration = completed_at - state.started_at
        duration_str = str(duration).split(".")[0]

        executive_summary = self._generate_executive_summary(state)
        vulnerability_count = len(state.discovered_vulnerabilities)
        exploited_count = len(state.exploited_vulnerabilities)

        # Deduplicate users (case-insensitive on domain+username)
        seen_users: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            user_key = (user.domain.lower(), user.username.lower())
            if user_key not in seen_users:
                seen_users.add(user_key)
                # Normalize is_admin for known admin usernames
                if user.username.lower() in ("administrator", "krbtgt"):
                    user.is_admin = True
                unique_users.append(user)

        # Deduplicate credentials (case-insensitive on domain+username+password)
        seen_creds: set[tuple[str, str, str]] = set()
        unique_creds = []
        for cred in state.all_credentials:
            cred_key = (cred.domain.lower(), cred.username.lower(), cred.password)
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)
                # Normalize is_admin for known admin usernames
                if cred.username.lower() in ("administrator", "krbtgt"):
                    cred.is_admin = True
                unique_creds.append(cred)

        host_count = len(state.all_hosts)
        credential_count = len(unique_creds)
        admin_count = sum(1 for c in unique_creds if c.is_admin)

        all_techniques: set[str] = set(state.identified_techniques)
        for event in state.operation_timeline:
            if event.mitre_techniques:
                all_techniques.update(event.mitre_techniques)

        discovered_vulns = []
        for vuln_id, vuln in state.discovered_vulnerabilities.items():
            discovered_vulns.append(
                {
                    "vuln_id": vuln_id,
                    "vuln_type": vuln.vuln_type,
                    "target": vuln.target,
                    "priority": vuln.priority,
                    "exploited": vuln_id in state.exploited_vulnerabilities,
                    "details": _format_vuln_details(vuln.details),
                }
            )
        discovered_vulns.sort(key=lambda v: v.get("priority", 999))  # type: ignore[arg-type,return-value]

        techniques_enriched = [_get_technique_display(t) for t in sorted(all_techniques)]

        target_ips = state.target_ips or ([state.target.ip] if state.target else [])
        return self.loader.render(
            "redteam/reports/operation_summary.md.jinja",
            operation_id=state.operation_id,
            target_ip=state.target.ip if state.target else "Unknown",
            target_ips=target_ips,
            started_at=state.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            completed_at=completed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration=duration_str,
            stage="completed" if (state.completed or state.completed_at) else "in_progress",
            executive_summary=executive_summary,
            has_domain_admin=state.has_domain_admin,
            has_golden_ticket=state.has_golden_ticket,
            host_count=host_count,
            user_count=len(unique_users),
            credential_count=credential_count,
            admin_count=admin_count,
            vulnerability_count=vulnerability_count,
            exploited_count=exploited_count,
            share_count=len(state.all_shares),
            hosts=state.all_hosts,
            users=unique_users,
            credentials=unique_creds,
            shares=state.all_shares,
            weaknesses=_deduplicate_weaknesses(state.all_weaknesses),
            discovered_vulns=discovered_vulns,
            timeline=state.operation_timeline,
            techniques_identified=techniques_enriched,
        )

    def _generate_executive_summary(self, state: SharedRedTeamState) -> str:
        """Generate the executive summary section.

        Args:
            state: Red team operation state.

        Returns:
            Executive summary text.
        """
        if state.report_summary:
            return state.report_summary

        # Deduplicate credentials (case-insensitive on domain+username+password)
        # Must match generate() deduplication logic
        seen_creds: set[tuple[str, str, str]] = set()
        unique_creds = []
        for cred in state.all_credentials:
            cred_key = (cred.domain.lower(), cred.username.lower(), cred.password)
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)
                # Normalize is_admin for known admin usernames (match generate())
                if cred.username.lower() in ("administrator", "krbtgt"):
                    cred.is_admin = True
                unique_creds.append(cred)

        host_count = len(state.all_hosts)
        credential_count = len(unique_creds)
        admin_count = sum(1 for c in unique_creds if c.is_admin)
        vulnerability_count = len(state.discovered_vulnerabilities)
        exploited_count = len(state.exploited_vulnerabilities)

        summary_parts = []

        # Operation overview
        target_ips = state.target_ips or ([state.target.ip] if state.target else [])
        if len(target_ips) > 1:
            target_desc = f"**{len(target_ips)} targets** ({', '.join(target_ips[:3])}{'...' if len(target_ips) > 3 else ''})"
        elif target_ips:
            target_desc = f"target **{target_ips[0]}**"
        else:
            target_desc = "target **Unknown**"
        summary_parts.append(
            f"Red team operation **{state.operation_id}** was executed against {target_desc} "
            f"in an Active Directory penetration testing engagement."
        )

        # Key achievements
        achievements = []
        if state.has_domain_admin:
            achievements.append("✓ **Domain Administrator access achieved**")
        if state.has_golden_ticket:
            achievements.append("✓ **Golden ticket generated** for persistent access")
        if admin_count > 0:
            achievements.append(f"✓ **{admin_count} administrator account(s)** discovered")
        if credential_count > 0:
            achievements.append(f"✓ **{credential_count} credential(s)** obtained")

        if achievements:
            summary_parts.append("\n\n**Key Achievements:**\n" + "\n".join(achievements))

        # Deduplicate users (case-insensitive on domain+username) - match generate()
        seen_users: set[tuple[str, str]] = set()
        unique_user_count = 0
        for user in state.all_users:
            user_key = (user.domain.lower(), user.username.lower())
            if user_key not in seen_users:
                seen_users.add(user_key)
                unique_user_count += 1

        # Discovery statistics
        summary_parts.append(
            f"\n\n**Discovery Statistics:**\n"
            f"- Hosts Discovered: {host_count}\n"
            f"- User Accounts: {unique_user_count}\n"
            f"- Network Shares: {len(state.all_shares)}\n"
            f"- Password Hashes: {len(state.all_hashes)}\n"
            f"- Vulnerabilities: {vulnerability_count}\n"
            f"- Vulnerabilities Exploited: {exploited_count}"
        )

        # Attack path summary - use actual captured path, not generic text
        if state.has_domain_admin or state.has_golden_ticket:
            if state.domain_admin_path:
                summary_parts.append(f"\n\n**Attack Path:**\n{state.domain_admin_path}")
            else:
                # Fallback only if no path was captured
                summary_parts.append(
                    "\n\n**Attack Path:**\nDomain admin achieved. See timeline below for details."
                )

        # Security posture assessment
        if state.has_domain_admin or state.has_golden_ticket:
            posture = "**CRITICAL**"
            assessment = (
                "The target environment has critical security weaknesses that allowed "
                "full domain compromise. Immediate remediation is required."
            )
        elif admin_count > 0:
            posture = "**HIGH**"
            assessment = (
                "The target environment has significant security weaknesses with administrative "
                "access obtained. Remediation is strongly recommended."
            )
        elif credential_count > 0:
            posture = "**MEDIUM**"
            assessment = (
                "The target environment has moderate security weaknesses with credentials "
                "compromised. Security improvements are recommended."
            )
        else:
            posture = "**LOW**"
            assessment = (
                "The target environment demonstrated resilience against the red team operation. "
                "Continue monitoring and maintain security posture."
            )

        summary_parts.append(f"\n\n**Security Posture:** {posture}\n\n{assessment}")

        return "".join(summary_parts)


def generate_comprehensive_report(state: SharedRedTeamState) -> str:
    """Generate a comprehensive markdown report from SharedRedTeamState.

    This is the main report generator for completed operations. It includes
    the full attack path, all credentials with passwords, hashes, and
    detailed vulnerability information.

    Args:
        state: SharedRedTeamState from Redis containing all operation data.

    Returns:
        Complete markdown report as a string.
    """
    loader = get_template_loader()
    # Use persisted completed_at if available, fallback to now
    completed_at = state.completed_at or datetime.now(timezone.utc)
    duration = completed_at - state.started_at
    duration_str = str(duration).split(".")[0]

    # Deduplicate credentials and hashes
    seen_creds: set[tuple[str, str, str]] = set()
    unique_creds = []
    for cred in state.all_credentials:
        key = (cred.domain.lower(), cred.username.lower(), cred.password)
        if key not in seen_creds:
            seen_creds.add(key)
            # Normalize is_admin for known admin usernames
            if cred.username.lower() in ("administrator", "krbtgt"):
                cred.is_admin = True
            unique_creds.append(cred)

    seen_hashes: set[tuple[str, str, str]] = set()
    unique_hashes = []
    for h in state.all_hashes:
        key = (h.domain.lower(), h.username.lower(), h.hash_value.lower())
        if key not in seen_hashes:
            seen_hashes.add(key)
            unique_hashes.append(h)

    # Sort hashes to put important ones first (Administrator, krbtgt)
    def hash_priority(h) -> tuple[int, str]:
        name = h.username.lower()
        if name == "administrator":
            return (0, name)
        if name == "krbtgt":
            return (1, name)
        return (2, name)

    unique_hashes.sort(key=hash_priority)

    dc_count = sum(1 for h in state.all_hosts if h.is_dc)

    discovered_vulns = []
    for vuln_id, vuln in state.discovered_vulnerabilities.items():
        discovered_vulns.append(
            {
                "vuln_id": vuln_id,
                "vuln_type": vuln.vuln_type,
                "target_ip": vuln.target,
                "target_host": vuln.target,
                "priority": vuln.priority,
                "exploited": vuln_id in state.exploited_vulnerabilities,
                "details": _format_vuln_details(vuln.details),
            }
        )
    discovered_vulns.sort(key=lambda v: v.get("priority", 999))  # type: ignore[arg-type,return-value]

    timeline = []
    all_techniques: set[str] = set(state.identified_techniques)
    for event in state.operation_timeline:
        timeline.append(
            {
                "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "description": event.description,
                "mitre_techniques": event.mitre_techniques,
            }
        )
        # Collect techniques from timeline events into the aggregate set
        if event.mitre_techniques:
            all_techniques.update(event.mitre_techniques)

    techniques_enriched = [_get_technique_display(t) for t in sorted(all_techniques)]

    target_ip = state.target.ip if state.target else "Unknown"
    target_domain = state.target.domain if state.target else "Unknown"
    target_ips = state.target_ips or ([target_ip] if target_ip != "Unknown" else [])

    return loader.render(
        "redteam/reports/comprehensive_report.md.jinja",
        operation_id=state.operation_id,
        target_ip=target_ip,
        target_ips=target_ips,
        target_domain=target_domain,
        started_at=state.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        completed_at=completed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=duration_str,
        has_domain_admin=state.has_domain_admin,
        has_golden_ticket=state.has_golden_ticket,
        domain_admin_path=state.domain_admin_path,
        domain_admin_chain=state.build_attack_chain() if state.has_domain_admin else None,
        domains=sorted({d.lower() for d in state.all_domains if d}),
        hosts=state.all_hosts,
        dc_count=dc_count,
        users=state.all_users,
        credentials=unique_creds,
        hashes=unique_hashes,
        shares=state.all_shares,
        weaknesses=_deduplicate_weaknesses(state.all_weaknesses),
        timeline=timeline,
        techniques=techniques_enriched,
        discovered_vulns=discovered_vulns,
        vulnerabilities_found=len(state.discovered_vulnerabilities),
        vulnerabilities_exploited=len(state.exploited_vulnerabilities),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
