"""Tests comparing Python-rendered report structure against Rust Tera templates.

Verifies that the Rust Tera templates produce structurally similar output to
the Python Jinja2 templates by comparing headers, table structures, and
section ordering.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ares.core.models import (
    Credential,
    Evidence,
    Hash,
    Host,
    InvestigationStage,
    InvestigationState,
    PyramidLevel,
    Share,
    SharedRedTeamState,
    Target,
    TimelineEvent,
    User,
    VulnerabilityInfo,
)
from ares.reports.blueteam import BlueTeamOperation, BlueTeamReportGenerator
from ares.reports.redteam import (
    RedTeamReportGenerator,
    generate_comprehensive_report,
)

# ---------------------------------------------------------------------------
# Paths to Rust Tera templates
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_TERA_DIR = _PROJECT_ROOT / "ares-rust" / "ares-core" / "templates"

TERA_REDTEAM_SUMMARY = _TERA_DIR / "redteam" / "reports" / "operation_summary.md.tera"
TERA_REDTEAM_COMPREHENSIVE = _TERA_DIR / "redteam" / "reports" / "comprehensive_report.md.tera"
TERA_BLUETEAM_COMPREHENSIVE = _TERA_DIR / "blueteam" / "reports" / "comprehensive_report.md.tera"


# ---------------------------------------------------------------------------
# Structural extraction helpers
# ---------------------------------------------------------------------------


def extract_headers(text: str) -> list[tuple[int, str]]:
    """Extract all markdown headers with their levels.

    Returns a list of (level, title) tuples, e.g. (2, "Executive Summary").
    """
    headers = []
    for line in text.splitlines():
        m = re.match(r"^(#{1,6})\s+(.+)$", line.strip())
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            headers.append((level, title))
    return headers


def extract_table_sections(text: str) -> dict[str, list[list[str]]]:
    """Extract tables grouped by the nearest preceding header.

    Returns a dict mapping header title -> list of table header rows.
    Each table header row is a list of column names.
    """
    current_header = "__top__"
    tables: dict[str, list[list[str]]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        header_match = re.match(r"^#{1,6}\s+(.+)$", line)
        if header_match:
            current_header = header_match.group(1).strip()

        # Detect table header: line with | ... | followed by a separator |---|
        if "|" in line and i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if re.match(r"^\|[\s\-:|]+\|$", next_line):
                # Parse column headers
                cols = [c.strip() for c in line.split("|") if c.strip()]
                tables.setdefault(current_header, []).append(cols)
                # Skip past the separator
                i += 2
                continue
        i += 1
    return tables


def extract_section_order(text: str) -> list[str]:
    """Extract top-level (##) section titles in order."""
    order = []
    for line in text.splitlines():
        m = re.match(r"^##\s+(.+)$", line.strip())
        if m:
            order.append(m.group(1).strip())
    return order


def normalize_header(title: str) -> str:
    """Normalize a header title for comparison.

    Strips Tera/Jinja variable syntax, template conditionals, and
    count annotations like "({{ host_count }})".
    """
    # Remove Tera/Jinja expressions like {{ ... }} and {%...%}
    title = re.sub(r"\{\{.*?\}\}", "", title)
    title = re.sub(r"\{%.*?%\}", "", title)
    # Remove parenthesized count annotations like "(3)" or "({{ count }})"
    title = re.sub(r"\s*\(.*?\)\s*", "", title)
    # Remove brackets like [DC] or [DOMAIN CONTROLLER]
    title = re.sub(r"\s*\[.*?\]\s*", "", title)
    # Normalize whitespace
    title = " ".join(title.split()).strip()
    return title.lower()


def _is_degenerate_header(normalized: str) -> bool:
    """Check if a normalized header is degenerate (only punctuation/whitespace).

    This happens when a Tera template header is entirely composed of template
    variables, e.g. ``### Level {{ level }}: {{ name }}`` normalizes to ``level :``.
    """
    stripped = re.sub(r"[^a-z0-9]", "", normalized)
    # If only a single short word remains (like "level"), it's degenerate
    return len(stripped) <= 5 and ":" in normalized


# ---------------------------------------------------------------------------
# Fixtures -- realistic mock data using contoso.local / 192.168.58.x
# ---------------------------------------------------------------------------

_BASE_TIME = datetime(2026, 4, 6, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def red_team_state_full() -> SharedRedTeamState:
    """Create a fully populated SharedRedTeamState exercising all sections."""
    state = SharedRedTeamState(operation_id="op-redteam-test-001")
    state.target = Target(
        ip="192.168.58.10",
        hostname="dc01.contoso.local",
        domain="contoso.local",
    )
    state.target_ips = ["192.168.58.10", "192.168.58.11"]
    state.started_at = _BASE_TIME
    state.completed_at = _BASE_TIME + timedelta(hours=2, minutes=30)
    state.completed = True
    state.has_domain_admin = True
    state.has_golden_ticket = True
    state.domain_admin_path = (
        "svc_sql (kerberoast) -> Administrator (secretsdump) -> krbtgt (dcsync)"
    )

    state.all_domains = ["contoso.local", "child.contoso.local"]

    state.all_hosts = [
        Host(
            ip="192.168.58.10",
            hostname="dc01.contoso.local",
            os="Windows Server 2019",
            roles=["Domain Controller"],
            services=["88/tcp kerberos", "389/tcp ldap", "445/tcp smb"],
            is_dc=True,
        ),
        Host(
            ip="192.168.58.11",
            hostname="srv01.contoso.local",
            os="Windows Server 2016",
            roles=["Member Server"],
            services=["445/tcp smb", "1433/tcp mssql"],
            is_dc=False,
        ),
    ]

    state.all_users = [
        User(
            username="Administrator",
            domain="contoso.local",
            is_admin=True,
            description="Built-in admin",
        ),
        User(
            username="svc_sql",
            domain="contoso.local",
            is_admin=False,
            description="SQL service account",
        ),
        User(
            username="jdoe",
            domain="contoso.local",
            is_admin=False,
            description="Regular user",
        ),
    ]

    state.all_credentials = [
        Credential(
            id="cred-001",
            username="svc_sql",
            password="Summer2026!",
            domain="contoso.local",
            source="kerberoast",
            is_admin=False,
            attack_step=0,
        ),
        Credential(
            id="cred-002",
            username="Administrator",
            password="P@ssw0rd!",
            domain="contoso.local",
            source="secretsdump",
            is_admin=True,
            parent_id="cred-001",
            attack_step=1,
        ),
    ]

    state.all_hashes = [
        Hash(
            id="hash-001",
            username="krbtgt",
            hash_value="aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump (dcsync)",
            parent_id="cred-002",
            attack_step=2,
        ),
        Hash(
            id="hash-002",
            username="Administrator",
            hash_value="aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump",
            parent_id="cred-001",
            attack_step=1,
        ),
    ]
    state.da_hash_id = "hash-001"

    state.all_shares = [
        Share(
            host="dc01.contoso.local", name="SYSVOL", permissions="READ", comment="Logon scripts"
        ),
        Share(host="dc01.contoso.local", name="NETLOGON", permissions="READ", comment=""),
        Share(
            host="srv01.contoso.local", name="C$", permissions="READ/WRITE", comment="Default share"
        ),
    ]

    state.all_weaknesses = [
        (
            "### SMB Signing Disabled\n"
            "**Vulnerability:** SMB signing is not required\n"
            "**Affected Resource:** srv01.contoso.local\n"
            "**Impact:** Enables relay attacks\n"
        ),
        (
            "### Kerberoastable Service Account\n"
            "**Vulnerability:** SPN set on user account with weak password\n"
            "**Affected Resource:** svc_sql@contoso.local\n"
            "**Impact:** Offline password cracking possible\n"
        ),
    ]

    vuln_id_1 = "vuln-kerb-001"
    vuln_id_2 = "vuln-smb-001"
    state.discovered_vulnerabilities = {
        vuln_id_1: VulnerabilityInfo(
            vuln_id=vuln_id_1,
            vuln_type="kerberoast",
            target="192.168.58.10",
            discovered_by="recon",
            priority=2,
            details={"account": "svc_sql", "domain": "contoso.local"},
        ),
        vuln_id_2: VulnerabilityInfo(
            vuln_id=vuln_id_2,
            vuln_type="smb_signing_disabled",
            target="192.168.58.11",
            discovered_by="recon",
            priority=4,
            details={"hostname": "srv01.contoso.local"},
        ),
    }
    state.exploited_vulnerabilities = {vuln_id_1}

    state.operation_timeline = [
        TimelineEvent(
            id="te-001",
            timestamp=_BASE_TIME + timedelta(minutes=5),
            description="Port scan completed on 192.168.58.0/24",
            mitre_techniques=["T1046"],
            confidence=1.0,
            source="nmap",
        ),
        TimelineEvent(
            id="te-002",
            timestamp=_BASE_TIME + timedelta(minutes=30),
            description="Kerberoasted svc_sql account",
            mitre_techniques=["T1558.003"],
            confidence=0.95,
            source="impacket",
        ),
        TimelineEvent(
            id="te-003",
            timestamp=_BASE_TIME + timedelta(hours=1),
            description="DCSync attack captured krbtgt hash",
            mitre_techniques=["T1003.006"],
            confidence=1.0,
            source="secretsdump",
        ),
    ]

    state.identified_techniques = {"T1046", "T1558.003", "T1003.006", "T1078"}

    return state


@pytest.fixture
def blue_team_operation() -> BlueTeamOperation:
    """Create a BlueTeamOperation exercising all report sections."""
    from ares.core.lateral_analyzer import LateralGraph

    inv1 = InvestigationState(
        investigation_id="inv-blue-001-abcdef01",
        alert={
            "fingerprint": "fp-001",
            "status": "firing",
            "labels": {
                "alertname": "DCSync_Attack_Detected",
                "severity": "critical",
                "instance": "dc01.contoso.local",
            },
            "annotations": {"summary": "DCSync detected"},
        },
        started_at=_BASE_TIME,
        stage=InvestigationStage.SYNTHESIS,
        evidence=[
            Evidence(
                id="ev-blue-001-abcdef01",
                type="ttp",
                value="DCSync replication attack via mimikatz",
                source="Windows Event 4662",
                timestamp=_BASE_TIME + timedelta(minutes=2),
                pyramid_level=PyramidLevel.TTPS,
                mitre_techniques=["T1003.006"],
                confidence=0.95,
                validated=True,
            ),
            Evidence(
                id="ev-blue-002-abcdef02",
                type="ip_address",
                value="192.168.58.50",
                source="Firewall logs",
                timestamp=_BASE_TIME + timedelta(minutes=5),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=["T1071"],
                confidence=0.80,
                validated=True,
            ),
            Evidence(
                id="ev-blue-003-abcdef03",
                type="tool",
                value="mimikatz.exe",
                source="Process creation event",
                timestamp=_BASE_TIME + timedelta(minutes=3),
                pyramid_level=PyramidLevel.TOOLS,
                mitre_techniques=["T1003"],
                confidence=0.90,
                validated=True,
            ),
        ],
        timeline=[
            TimelineEvent(
                id="te-blue-001",
                timestamp=_BASE_TIME + timedelta(minutes=1),
                description="Alert triggered: DCSync_Attack_Detected on dc01.contoso.local",
                mitre_techniques=["T1003.006"],
                confidence=0.9,
                source="Grafana",
            ),
            TimelineEvent(
                id="te-blue-002",
                timestamp=_BASE_TIME + timedelta(minutes=10),
                description="Lateral movement to srv01.contoso.local confirmed",
                mitre_techniques=["T1021.002"],
                confidence=0.85,
                source="investigation",
            ),
        ],
        identified_techniques={"T1003.006", "T1021.002"},
        identified_tactics={"TA0006", "TA0008"},
        technique_names={
            "T1003.006": "DCSync",
            "T1021.002": "SMB/Windows Admin Shares",
        },
        technique_to_tactic={
            "T1003.006": "credential-access",
            "T1021.002": "lateral-movement",
        },
        queried_hosts={"dc01.contoso.local", "srv01.contoso.local"},
        queried_users={"adminuser", "svc_sql"},
        executed_queries=[
            {
                "type": "loki",
                "query": '{job="windows"} |= "4662"',
                "result_count": 5,
            },
            {
                "type": "prometheus",
                "query": "rate(windows_logon_total[5m])",
                "result_count": 2,
            },
        ],
        escalated=True,
        escalation_reason="Active DCSync attack in progress",
        attack_synopsis="DCSync attack detected targeting domain controllers with lateral movement",
        recommendations=[
            "Reset all domain admin passwords immediately",
            "Audit replication permissions on all DCs",
            "Block source IP 192.168.58.50 at the firewall",
        ],
        lateral_graph=LateralGraph(),
    )

    inv2 = InvestigationState(
        investigation_id="inv-blue-002-abcdef02",
        alert={
            "fingerprint": "fp-002",
            "status": "firing",
            "labels": {
                "alertname": "BruteForce_Detected",
                "severity": "high",
                "instance": "srv01.contoso.local",
            },
            "annotations": {"summary": "Brute force attempt"},
        },
        started_at=_BASE_TIME + timedelta(minutes=15),
        stage=InvestigationStage.CAUSATION,
        evidence=[
            Evidence(
                id="ev-blue-004-abcdef04",
                type="ip_address",
                value="192.168.58.99",
                source="Authentication logs",
                timestamp=_BASE_TIME + timedelta(minutes=16),
                pyramid_level=PyramidLevel.IP_ADDRESSES,
                mitre_techniques=["T1110.001"],
                confidence=0.75,
                validated=True,
            ),
        ],
        timeline=[
            TimelineEvent(
                id="te-blue-003",
                timestamp=_BASE_TIME + timedelta(minutes=16),
                description="Brute force attempts from 192.168.58.99",
                mitre_techniques=["T1110.001"],
                confidence=0.75,
                source="investigation",
            ),
        ],
        identified_techniques={"T1110.001"},
        identified_tactics={"TA0006"},
        technique_names={"T1110.001": "Password Guessing"},
        technique_to_tactic={"T1110.001": "credential-access"},
        queried_hosts={"srv01.contoso.local"},
        queried_users={"jdoe"},
        executed_queries=[
            {
                "type": "loki",
                "query": '{job="auth"} |= "failed"',
                "result_count": 42,
            }
        ],
        escalated=False,
        attack_synopsis=None,
        recommendations=["Enforce account lockout policy"],
        lateral_graph=LateralGraph(),
    )

    return BlueTeamOperation(
        operation_id="blue-op-test-001",
        started_at=_BASE_TIME,
        completed_at=_BASE_TIME + timedelta(hours=1),
        investigations=[inv1, inv2],
    )


# ---------------------------------------------------------------------------
# Helper: read Tera template raw text
# ---------------------------------------------------------------------------


def _read_tera(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"Tera template not found: {path}")
    return path.read_text()


# ===========================================================================
# Tests for Red Team Operation Summary
# ===========================================================================


class TestRedTeamOperationSummaryStructure:
    """Compare Python-rendered operation_summary against Rust Tera template."""

    @pytest.fixture
    def rendered_python(self, red_team_state_full: SharedRedTeamState) -> str:
        gen = RedTeamReportGenerator()
        return gen.generate(red_team_state_full)

    @pytest.fixture
    def tera_raw(self) -> str:
        return _read_tera(TERA_REDTEAM_SUMMARY)

    def test_major_sections_present(self, rendered_python: str, tera_raw: str):
        """Both templates must share the same top-level (##) sections."""
        py_sections = [normalize_header(s) for s in extract_section_order(rendered_python)]
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]

        # Every Tera section must exist in the Python output
        for section in tera_sections:
            assert section in py_sections, (
                f"Rust template section '{section}' not found in Python output.\n"
                f"Python sections: {py_sections}"
            )

        # Every Python section must exist in the Tera template
        for section in py_sections:
            assert section in tera_sections, (
                f"Python output section '{section}' not found in Rust template.\n"
                f"Tera sections: {tera_sections}"
            )

    def test_section_ordering_matches(self, rendered_python: str, tera_raw: str):
        """Top-level sections must appear in the same order."""
        py_sections = [normalize_header(s) for s in extract_section_order(rendered_python)]
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]
        assert py_sections == tera_sections, (
            f"Section order mismatch.\nPython: {py_sections}\nTera:   {tera_sections}"
        )

    def test_tables_in_same_sections(self, rendered_python: str, tera_raw: str):
        """Tables must appear under the same section headers."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_normalized = {normalize_header(k): v for k, v in py_tables.items()}
        tera_normalized = {normalize_header(k): v for k, v in tera_tables.items()}

        # Every section that has a table in Tera must also have one in Python
        for section in tera_normalized:
            assert section in py_normalized, (
                f"Tera has table under '{section}' but Python does not.\n"
                f"Python table sections: {list(py_normalized.keys())}"
            )

    def test_table_column_counts_match(self, rendered_python: str, tera_raw: str):
        """Tables under matching sections should have the same number of columns."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_normalized = {normalize_header(k): v for k, v in py_tables.items()}
        tera_normalized = {normalize_header(k): v for k, v in tera_tables.items()}

        for section, tera_tbls in tera_normalized.items():
            if section not in py_normalized:
                continue
            py_tbls = py_normalized[section]
            for idx, (tera_cols, py_cols) in enumerate(zip(tera_tbls, py_tbls, strict=False)):
                assert len(tera_cols) == len(py_cols), (
                    f"Column count mismatch in section '{section}' table {idx}.\n"
                    f"Tera columns ({len(tera_cols)}): {tera_cols}\n"
                    f"Python columns ({len(py_cols)}): {py_cols}"
                )

    def test_no_critical_sections_missing_from_rust(self, tera_raw: str):
        """Critical sections must be present in Rust template."""
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]
        critical = [
            "executive summary",
            "success metrics",
            "discovered assets",
            "attack path",
            "mitre att&ck mapping",
            "vulnerabilities and weaknesses",
            "recommendations",
        ]
        for section in critical:
            assert section in tera_sections, (
                f"Critical section '{section}' missing from Rust template.\n"
                f"Tera sections: {tera_sections}"
            )

    def test_header_levels_consistent(self, rendered_python: str, tera_raw: str):
        """Both templates should use the same header level for the title."""
        py_headers = extract_headers(rendered_python)
        tera_headers = extract_headers(tera_raw)

        # Title header (first one)
        assert py_headers[0][0] == tera_headers[0][0], (
            f"Title header level mismatch: Python={py_headers[0]}, Tera={tera_headers[0]}"
        )

    def test_subheaders_under_discovered_assets(self, rendered_python: str, tera_raw: str):
        """Discovered Assets should have the same structural sub-sections in both.

        Only compares level-3 (###) sub-sections, not level-4 (####) which are
        data-driven (individual host names, etc.) and differ between rendered
        output and raw template.
        """
        py_headers = extract_headers(rendered_python)
        tera_headers = extract_headers(tera_raw)

        def subsections_of(headers, parent_title_norm, target_level=3):
            """Get sub-headers at a specific level under a given parent."""
            result = []
            found = False
            parent_level = None
            for level, title in headers:
                if normalize_header(title) == parent_title_norm:
                    found = True
                    parent_level = level
                    continue
                if found:
                    if level <= parent_level:
                        break
                    if level == target_level:
                        result.append(normalize_header(title))
            return result

        py_subs = subsections_of(py_headers, "discovered assets")
        tera_subs = subsections_of(tera_headers, "discovered assets")

        assert set(py_subs) == set(tera_subs), (
            f"Discovered Assets sub-sections differ.\nPython: {py_subs}\nTera: {tera_subs}"
        )


# ===========================================================================
# Tests for Red Team Comprehensive Report
# ===========================================================================


class TestRedTeamComprehensiveReportStructure:
    """Compare Python comprehensive report against Rust Tera template."""

    @pytest.fixture
    def rendered_python(self, red_team_state_full: SharedRedTeamState) -> str:
        return generate_comprehensive_report(red_team_state_full)

    @pytest.fixture
    def tera_raw(self) -> str:
        return _read_tera(TERA_REDTEAM_COMPREHENSIVE)

    def test_major_sections_present(self, rendered_python: str, tera_raw: str):
        """Both templates must share the same top-level sections."""
        py_sections = [normalize_header(s) for s in extract_section_order(rendered_python)]
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]

        for section in tera_sections:
            assert section in py_sections, (
                f"Rust template section '{section}' not found in Python output.\n"
                f"Python sections: {py_sections}"
            )
        for section in py_sections:
            assert section in tera_sections, (
                f"Python output section '{section}' not found in Rust template.\n"
                f"Tera sections: {tera_sections}"
            )

    def test_section_ordering_matches(self, rendered_python: str, tera_raw: str):
        """Top-level sections must appear in the same order."""
        py_sections = [normalize_header(s) for s in extract_section_order(rendered_python)]
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]
        assert py_sections == tera_sections

    def test_tables_in_same_sections(self, rendered_python: str, tera_raw: str):
        """Tables must appear under the same section headers."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_normalized = {normalize_header(k): v for k, v in py_tables.items()}
        tera_normalized = {normalize_header(k): v for k, v in tera_tables.items()}

        for section in tera_normalized:
            assert section in py_normalized, (
                f"Tera has table under '{section}' but Python does not.\n"
                f"Python table sections: {list(py_normalized.keys())}"
            )

    def test_no_critical_sections_missing_from_rust(self, tera_raw: str):
        """Critical sections must be present in Rust template."""
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]
        critical = [
            "executive summary",
            "success metrics",
            "domains",
            "discovered hosts",
            "network shares",
            "credentials & hashes",
            "attack path & timeline",
            "vulnerabilities & weaknesses",
            "mitre att&ck mapping",
            "recommendations",
        ]
        for section in critical:
            assert section in tera_sections, (
                f"Critical section '{section}' missing from Rust template.\n"
                f"Tera sections: {tera_sections}"
            )

    def test_credentials_table_columns(self, rendered_python: str, tera_raw: str):
        """Credentials table must have matching column count."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        # Both should have a credentials/hashes section with at least one table
        creds_key = "credentials & hashes"
        if creds_key in py_norm and creds_key in tera_norm:
            for idx, (py_cols, tera_cols) in enumerate(
                zip(py_norm[creds_key], tera_norm[creds_key], strict=False)
            ):
                assert len(py_cols) == len(tera_cols), (
                    f"Credentials table {idx} column count mismatch.\n"
                    f"Python: {py_cols}\nTera: {tera_cols}"
                )

    def test_success_metrics_table_present(self, rendered_python: str, tera_raw: str):
        """Success Metrics section should have a table in both."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        assert "success metrics" in py_norm, "Python missing Success Metrics table"
        assert "success metrics" in tera_norm, "Tera missing Success Metrics table"


# ===========================================================================
# Tests for Blue Team Comprehensive Report
# ===========================================================================


class TestBlueTeamComprehensiveReportStructure:
    """Compare Python blue team report against Rust Tera template."""

    @pytest.fixture
    def rendered_python(self, blue_team_operation: BlueTeamOperation) -> str:
        gen = BlueTeamReportGenerator()
        return gen.generate(blue_team_operation)

    @pytest.fixture
    def tera_raw(self) -> str:
        return _read_tera(TERA_BLUETEAM_COMPREHENSIVE)

    def test_major_sections_present(self, rendered_python: str, tera_raw: str):
        """Both templates must share the same top-level sections."""
        py_sections = [normalize_header(s) for s in extract_section_order(rendered_python)]
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]

        for section in tera_sections:
            assert section in py_sections, (
                f"Rust template section '{section}' not found in Python output.\n"
                f"Python sections: {py_sections}"
            )
        for section in py_sections:
            assert section in tera_sections, (
                f"Python output section '{section}' not found in Rust template.\n"
                f"Tera sections: {tera_sections}"
            )

    def test_section_ordering_matches(self, rendered_python: str, tera_raw: str):
        """Top-level sections must appear in the same order."""
        py_sections = [normalize_header(s) for s in extract_section_order(rendered_python)]
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]
        assert py_sections == tera_sections

    def test_tables_in_same_sections(self, rendered_python: str, tera_raw: str):
        """Tables must appear under the same section headers.

        Skips degenerate headers that result from Tera template variables
        being stripped during normalization (e.g. ``Level {{ n }}: {{ name }}``
        becomes ``level :``).
        """
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_normalized = {normalize_header(k): v for k, v in py_tables.items()}
        tera_normalized = {normalize_header(k): v for k, v in tera_tables.items()}

        for section in tera_normalized:
            if _is_degenerate_header(section):
                continue
            assert section in py_normalized, (
                f"Tera has table under '{section}' but Python does not.\n"
                f"Python table sections: {list(py_normalized.keys())}"
            )

    def test_no_critical_sections_missing_from_rust(self, tera_raw: str):
        """Critical sections must be present in Rust template."""
        tera_sections = [normalize_header(s) for s in extract_section_order(tera_raw)]
        critical = [
            "executive summary",
            "investigation summary",
            "mitre att&ck coverage",
            "pyramid of pain assessment",
            "evidence inventory",
            "timeline",
            "scope",
            "recommendations",
            "appendix: investigation details",
        ]
        for section in critical:
            assert section in tera_sections, (
                f"Critical section '{section}' missing from Rust template.\n"
                f"Tera sections: {tera_sections}"
            )

    def test_investigation_summary_table_columns(self, rendered_python: str, tera_raw: str):
        """Investigation Summary table should have matching column count."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        key = "investigation summary"
        if key in py_norm and key in tera_norm:
            for idx, (py_cols, tera_cols) in enumerate(
                zip(py_norm[key], tera_norm[key], strict=False)
            ):
                assert len(py_cols) == len(tera_cols), (
                    f"Investigation Summary table {idx} column count mismatch.\n"
                    f"Python: {py_cols}\nTera: {tera_cols}"
                )

    def test_pyramid_table_present(self, rendered_python: str, tera_raw: str):
        """Pyramid of Pain Assessment should have a table in both."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        key = "pyramid of pain assessment"
        assert key in py_norm, "Python missing Pyramid of Pain table"
        assert key in tera_norm, "Tera missing Pyramid of Pain table"

    def test_evidence_inventory_table_columns(self, rendered_python: str, tera_raw: str):
        """Evidence Inventory tables should have matching column counts."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        # Evidence is under sub-headers like "Level 6: TTPs"
        # Check any that match "level *" pattern
        for key, tera_tbl in tera_norm.items():
            if key.startswith("level") and key in py_norm:
                for py_cols, tera_cols in zip(py_norm[key], tera_tbl, strict=False):
                    assert len(py_cols) == len(tera_cols), (
                        f"Evidence table '{key}' column count mismatch.\n"
                        f"Python: {py_cols}\nTera: {tera_cols}"
                    )

    def test_timeline_table_columns(self, rendered_python: str, tera_raw: str):
        """Timeline table should have matching column count."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        key = "timeline"
        if key in py_norm and key in tera_norm:
            for py_cols, tera_cols in zip(py_norm[key], tera_norm[key], strict=False):
                assert len(py_cols) == len(tera_cols), (
                    f"Timeline table column count mismatch.\nPython: {py_cols}\nTera: {tera_cols}"
                )

    def test_techniques_table_present(self, rendered_python: str, tera_raw: str):
        """MITRE ATT&CK Coverage should have a Techniques table."""
        py_tables = extract_table_sections(rendered_python)
        tera_tables = extract_table_sections(tera_raw)

        py_norm = {normalize_header(k): v for k, v in py_tables.items()}
        tera_norm = {normalize_header(k): v for k, v in tera_tables.items()}

        # The techniques table lives under the "Techniques" sub-header
        key = "techniques"
        assert key in py_norm, "Python missing Techniques table"
        assert key in tera_norm, "Tera missing Techniques table"


# ===========================================================================
# Cross-cutting structural consistency tests
# ===========================================================================


class TestCrossCuttingStructure:
    """Verify overall structural patterns are consistent across all templates."""

    def test_all_tera_templates_exist(self):
        """All expected Tera templates must exist."""
        for path in [TERA_REDTEAM_SUMMARY, TERA_REDTEAM_COMPREHENSIVE, TERA_BLUETEAM_COMPREHENSIVE]:
            assert path.exists(), f"Tera template missing: {path}"

    def test_redteam_summary_title_matches(self):
        """Both red team summary templates use same title."""
        py_gen = RedTeamReportGenerator()
        state = SharedRedTeamState(operation_id="op-title-test")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        state.started_at = _BASE_TIME
        rendered = py_gen.generate(state)

        tera = _read_tera(TERA_REDTEAM_SUMMARY)

        py_title = extract_headers(rendered)[0]
        tera_title = extract_headers(tera)[0]

        assert normalize_header(py_title[1]) == normalize_header(tera_title[1]), (
            f"Title mismatch: Python='{py_title[1]}', Tera='{tera_title[1]}'"
        )

    def test_redteam_comprehensive_title_matches(self, red_team_state_full: SharedRedTeamState):
        """Both red team comprehensive templates use same title."""
        rendered = generate_comprehensive_report(red_team_state_full)
        tera = _read_tera(TERA_REDTEAM_COMPREHENSIVE)

        py_title = extract_headers(rendered)[0]
        tera_title = extract_headers(tera)[0]

        assert normalize_header(py_title[1]) == normalize_header(tera_title[1])

    def test_blueteam_comprehensive_title_matches(self, blue_team_operation: BlueTeamOperation):
        """Both blue team comprehensive templates use same title."""
        rendered = BlueTeamReportGenerator().generate(blue_team_operation)
        tera = _read_tera(TERA_BLUETEAM_COMPREHENSIVE)

        py_title = extract_headers(rendered)[0]
        tera_title = extract_headers(tera)[0]

        assert normalize_header(py_title[1]) == normalize_header(tera_title[1])

    def test_all_reports_end_with_generator_attribution(self):
        """All Tera templates should have a generator attribution footer."""
        for path in [TERA_REDTEAM_SUMMARY, TERA_REDTEAM_COMPREHENSIVE, TERA_BLUETEAM_COMPREHENSIVE]:
            text = _read_tera(path)
            last_lines = text.strip().splitlines()[-3:]
            combined = " ".join(last_lines).lower()
            assert "report generated by ares" in combined, (
                f"Missing generator attribution in {path.name}. Last lines: {last_lines}"
            )
