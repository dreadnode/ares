#!/usr/bin/env python3
"""Pre-commit hook to check agent template sizes.

Large templates consume more LLM tokens per agent turn, which can cause
rate limit issues in multi-agent operations. This hook prevents template
bloat by enforcing size limits.

Token estimation: ~4 characters per token
- 8KB template ≈ 2,000 tokens per turn
- With 8+ agents and multiple turns, this compounds quickly
"""

from __future__ import annotations

import sys
from pathlib import Path

TEMPLATE_SIZE_LIMITS: dict[str, int] = {
    "privesc.md.jinja": 4000,
    "acl.md.jinja": 3000,
    "lateral.md.jinja": 8000,
    "recon.md.jinja": 5000,
    "coercion.md.jinja": 7000,
    "orchestrator.md.jinja": 10000,
    "credential_access.md.jinja": 6000,
    "cracker.md.jinja": 5000,
    "system_instructions.md.jinja": 4000,
}

DEFAULT_LIMIT = 5000
TOTAL_LIMIT = 55000  # ~14,000 tokens


def check_template_sizes() -> int:
    """Check template sizes and return exit code."""
    templates_dir = Path(__file__).parent.parent / "src/ares/templates/redteam/agents"

    if not templates_dir.exists():
        print(f"Templates directory not found: {templates_dir}")
        return 1

    errors: list[str] = []
    warnings: list[str] = []
    total_size = 0

    for template_path in sorted(templates_dir.glob("*.jinja")):
        size = template_path.stat().st_size
        total_size += size
        name = template_path.name
        limit = TEMPLATE_SIZE_LIMITS.get(name, DEFAULT_LIMIT)

        if size > limit:
            errors.append(f"  {name}: {size:,} bytes (limit: {limit:,}, over by {size - limit:,})")
        elif size > limit * 0.9:
            warnings.append(f"  {name}: {size:,} bytes (90%+ of {limit:,} limit)")

    if total_size > TOTAL_LIMIT:
        errors.append(
            f"  TOTAL: {total_size:,} bytes (limit: {TOTAL_LIMIT:,}, "
            f"over by {total_size - TOTAL_LIMIT:,})"
        )

    if errors:
        print("❌ Template size check FAILED")
        print("\nTemplates exceeding size limits:")
        for error in errors:
            print(error)
        print("\nLarge templates consume more LLM tokens and cause rate limit issues.")
        print("Tips to reduce size:")
        print("  - Remove verbose examples (keep one concise example per technique)")
        print("  - Consolidate redundant instructions")
        print("  - Remove inline comments that explain obvious things")
        print("  - Use tables instead of verbose lists")
        return 1

    if warnings:
        print("⚠️  Template size warnings (approaching limits):")
        for warning in warnings:
            print(warning)

    print(f"✓ Template sizes OK (total: {total_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(check_template_sizes())
