"""Template parity check between Python Jinja2 and Rust Tera report templates.

Compares the structural elements (section headers and template variables) of the
Python (Jinja2) and Rust (Tera) report templates to verify they produce compatible
output. This ensures the Rust migration maintains the same report structure and
references the same data context as the original Python templates.
"""

import re
from pathlib import Path

# Repository root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Template base directories
PYTHON_TEMPLATES = REPO_ROOT / "src" / "ares" / "templates"
RUST_TEMPLATES = REPO_ROOT / "ares-rust" / "ares-core" / "templates"

# Template pairs: (python_path, rust_path)
TEMPLATE_PAIRS = {
    "redteam_summary": (
        PYTHON_TEMPLATES / "redteam" / "reports" / "operation_summary.md.jinja",
        RUST_TEMPLATES / "redteam" / "reports" / "operation_summary.md.tera",
    ),
    "redteam_comprehensive": (
        PYTHON_TEMPLATES / "redteam" / "reports" / "comprehensive_report.md.jinja",
        RUST_TEMPLATES / "redteam" / "reports" / "comprehensive_report.md.tera",
    ),
    "blueteam_comprehensive": (
        PYTHON_TEMPLATES / "blueteam" / "reports" / "comprehensive_report.md.jinja",
        RUST_TEMPLATES / "blueteam" / "reports" / "comprehensive_report.md.tera",
    ),
}


def extract_headers(content: str) -> list[str]:
    """Extract markdown headers (lines starting with #) from template content.

    Strips template expressions from inside headers to compare the structural
    text. For example, ``### Hosts ({{ host_count }})`` becomes
    ``### Hosts ()``.
    """
    headers = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            # Remove template expressions like {{ ... }} and {% ... %}
            cleaned = re.sub(r"\{[{%].*?[%}]\}", "", stripped).strip()
            headers.append(cleaned)
    return headers


def extract_variables(content: str) -> set[str]:
    """Extract template variable names from ``{{ expr }}`` expressions.

    Both Jinja2 and Tera use ``{{ expr }}`` syntax for output expressions.
    This extracts the base variable name (first dotted identifier) from each
    expression, filtering out purely literal strings and empty expressions.

    Filters applied to variables (e.g. ``| join``, ``| length``,
    ``| default``) are stripped so only the root name is compared.
    """
    # Match {{ ... }} expressions (non-greedy)
    raw_exprs = re.findall(r"\{\{(.*?)\}\}", content)
    variables: set[str] = set()
    for raw_expr in raw_exprs:
        expr = raw_expr.strip()
        if not expr:
            continue
        # Strip filters: everything after the first |
        base = expr.split("|")[0].strip()
        # Strip Jinja2 ternary: "X" if var else "Y" -> take the var
        if_match = re.match(r'"[^"]*"\s+if\s+(\w[\w.]*)', base)
        if if_match:
            base = if_match.group(1)
        # Take the first identifier token (handles things like loop.index, host.ip)
        ident_match = re.match(r"(\w[\w.]*)", base)
        if ident_match:
            name = ident_match.group(1)
            # Skip pure string literals and loop metadata
            if name == "loop.index":
                continue
            variables.add(name)
    return variables


def major_headers(headers: list[str]) -> list[str]:
    """Return only level-1 (``#``) and level-2 (``##``) headers."""
    return [h for h in headers if re.match(r"^#{1,2}\s", h)]


class TestReportTemplateParity:
    """Verify structural parity between Python Jinja2 and Rust Tera report templates."""

    def test_templates_exist(self) -> None:
        """All 6 template files must exist on disk."""
        for name, (py_path, rs_path) in TEMPLATE_PAIRS.items():
            assert py_path.exists(), f"Python template missing for {name}: {py_path}"
            assert rs_path.exists(), f"Rust template missing for {name}: {rs_path}"

    def test_redteam_summary_section_headers_match(self) -> None:
        """Red team operation_summary templates share the same major section headers."""
        py_path, rs_path = TEMPLATE_PAIRS["redteam_summary"]
        py_headers = major_headers(extract_headers(py_path.read_text()))
        rs_headers = major_headers(extract_headers(rs_path.read_text()))

        # Both should have the same top-level title
        assert py_headers[0] == rs_headers[0], (
            f"Title mismatch: Python={py_headers[0]!r}, Rust={rs_headers[0]!r}"
        )

        # Compare the set of ## section headers
        py_sections = set(py_headers)
        rs_sections = set(rs_headers)

        missing_in_rust = py_sections - rs_sections
        assert not missing_in_rust, (
            f"Rust redteam summary is missing sections present in Python: {missing_in_rust}"
        )

    def test_redteam_comprehensive_section_headers_match(self) -> None:
        """Red team comprehensive_report templates share the same major section headers."""
        py_path, rs_path = TEMPLATE_PAIRS["redteam_comprehensive"]
        py_headers = major_headers(extract_headers(py_path.read_text()))
        rs_headers = major_headers(extract_headers(rs_path.read_text()))

        assert py_headers[0] == rs_headers[0], (
            f"Title mismatch: Python={py_headers[0]!r}, Rust={rs_headers[0]!r}"
        )

        py_sections = set(py_headers)
        rs_sections = set(rs_headers)

        missing_in_rust = py_sections - rs_sections
        assert not missing_in_rust, (
            f"Rust redteam comprehensive is missing sections present in Python: {missing_in_rust}"
        )

    def test_blueteam_comprehensive_section_headers_match(self) -> None:
        """Blue team comprehensive_report templates share the same major section headers."""
        py_path, rs_path = TEMPLATE_PAIRS["blueteam_comprehensive"]
        py_headers = major_headers(extract_headers(py_path.read_text()))
        rs_headers = major_headers(extract_headers(rs_path.read_text()))

        assert py_headers[0] == rs_headers[0], (
            f"Title mismatch: Python={py_headers[0]!r}, Rust={rs_headers[0]!r}"
        )

        py_sections = set(py_headers)
        rs_sections = set(rs_headers)

        missing_in_rust = py_sections - rs_sections
        assert not missing_in_rust, (
            f"Rust blueteam comprehensive is missing sections present in Python: {missing_in_rust}"
        )

    def test_template_variable_coverage(self) -> None:
        """Rust templates reference the same variable names as their Python counterparts.

        Some variables may be renamed in Rust (e.g. pre-computed display strings
        like ``da_display`` replacing inline conditionals). This test checks that
        the core data variables used by the Python template are covered by the
        Rust template, allowing for known Rust-side pre-computed replacements.
        """
        # Variables that Rust pre-computes in the rendering context rather than
        # using inline Jinja2 conditionals. Maps Python variable -> Rust replacement.
        known_rust_replacements: dict[str, set[str]] = {
            # redteam summary: Python calls .strftime() on timestamp, Rust pre-formats
            "event.timestamp.strftime": {"event.timestamp"},
            # redteam summary: Python uses inline ternary, Rust uses da_display/gt_display
            "has_domain_admin": {"da_display"},
            "has_golden_ticket": {"gt_display"},
            # redteam summary: Python uses host.hostname, Rust uses host.label
            "host.hostname": {"host.label"},
            # Python uses `host.roles|join(', ')`, Rust uses `host.roles | default(...)`
            # Both reference host.roles so this is fine
            # redteam comprehensive: Python uses cred.is_admin inline, Rust uses cred.admin_display
            "cred.is_admin": {"cred.admin_display"},
            "user.is_admin": {"user.admin_display"},
            # Jinja2 event.mitre_techniques|join vs Tera event.mitre_display
            "event.mitre_techniques": {"event.mitre_display"},
            # Jinja2 v.exploited inline conditional vs Tera v.exploited_display
            "v.exploited": {"v.exploited_display"},
            # Blue team: Python uses alert.investigation_id[:16], Rust uses alert.investigation_id_short
            "alert.investigation_id": {"alert.investigation_id_short"},
            "alert.escalated": {"alert.status_display"},
            # Blue team: Python uses ev.id[:12], Rust uses ev.id_short
            "ev.id": {"ev.id_short"},
            # Blue team: Python uses ev.techniques | join, Rust uses ev.techniques_display
            "ev.techniques": {"ev.techniques_display"},
            # Blue team: Python uses format filter on ev.confidence, Rust uses ev.confidence_display
            "ev.confidence": {"ev.confidence_display"},
            # Blue team: Python uses event.description[:60], Rust uses event.description_short
            "event.description": {"event.description_short"},
            # Blue team: Python uses event.confidence, Rust uses event.confidence_display
            "event.confidence": {"event.confidence_display"},
            # Blue team pyramid: Python loops with `for level in range(6, 0, -1)` and
            # uses level_names[level], level_pain[level], etc. Rust pre-builds pyramid_entries.
            "level": {"entry.level"},
            "level_names": {"entry.level", "entry.category", "entry.count", "entry.pain"},
            "level_pain": {"entry.level", "entry.category", "entry.count", "entry.pain"},
            "pyramid_distribution.get": set(),
            # Blue team evidence: Python uses evidence_by_level.get, Rust uses level_group.*
            "evidence_by_level.get": {
                "level_group.evidence",
                "level_group.level",
                "level_group.name",
            },
            # Blue team: Python uses inv.techniques | join, Rust uses inv.techniques_display
            "inv.techniques": {"inv.techniques_display"},
            # Blue team: Python uses inv.queries[:10], Rust uses inv.queries_display
            "inv.queries": {"inv.queries_display"},
            # Blue team: Python computes extra query count inline, Rust uses inv.extra_query_count
            # Python: vuln.exploited -> Rust: vuln.status_display (comprehensive)
            "vuln.exploited": {"vuln.status_display"},
            # Blue team: Python uses techniques[:10] for detection, Rust uses detection_techniques
            "tech.id": {"tech.id"},  # same name, kept for completeness
            "tech.name": {"tech.name"},
            # Python uses shares|length, Rust uses shares | length -- same
        }

        # Flatten replacement targets for quick lookup
        all_rust_replacements = set()
        for targets in known_rust_replacements.values():
            all_rust_replacements.update(targets)

        for name, (py_path, rs_path) in TEMPLATE_PAIRS.items():
            py_vars = extract_variables(py_path.read_text())
            rs_vars = extract_variables(rs_path.read_text())

            # For each Python variable, it should either:
            # 1. Exist in Rust variables, OR
            # 2. Have a known replacement that exists in Rust variables
            missing = set()
            for var in py_vars:
                if var in rs_vars:
                    continue
                if var in known_rust_replacements:
                    # Check that at least one replacement is present in Rust
                    replacements = known_rust_replacements[var]
                    if not replacements or replacements & rs_vars:
                        continue
                missing.add(var)

            assert not missing, (
                f"Template pair '{name}': Python variables not found in Rust template "
                f"(and no known replacement): {sorted(missing)}\n"
                f"  Python vars: {sorted(py_vars)}\n"
                f"  Rust vars:   {sorted(rs_vars)}"
            )
