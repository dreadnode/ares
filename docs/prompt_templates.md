# Ares Prompt Templates

Jinja2 template system for managing AI prompts with version control, lower
API costs, and team collaboration.

## Quick Start

```python
from ares.core.templates import get_template_loader

loader = get_template_loader()
result = loader.render(
    "agent/initial_alert_prompt.md.jinja",
    alert_name="HighCPU",
    severity="warning",
    instance="web-01"
)
```

## Why Templates?

**Markdown + XML format** following [Anthropic best practices](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/use-xml-tags):

- **Token Efficiency** - 20-30% fewer tokens than YAML/JSON
- **Maintainability** - Git-friendly diffs and version control
- **Collaboration** - Human-readable for team review
- **LLM-Optimized** - Claude is trained on Markdown

## Prerequisites

- Python 3.11+
- Jinja2 3.0+
- PyYAML (for configuration files)

## Directory Structure

| Category | Purpose | Status |
| -------- | ------- | ------ |
| `agent/` | Blue team system instructions & alert prompts | ✅ Complete |
| `engines/` | Question generation & attack chain templates | ✅ Complete |
| `tools/` | Investigation query suggestions | ✅ Complete |
| `reports/` | Report section templates | ⚠️ Partial |
| `redteam/` | Red team agent templates | ✅ Complete |

## API Reference

### List Templates

```python
from ares.core.templates import get_template_loader

loader = get_template_loader()
templates = loader.list_templates()
```

## Template Variables

### Agent Templates

| Template | Required Variables | Purpose |
| -------- | ------------------ | ------- |
| `agent/system_instructions.md.jinja` | None | Agent system instructions |
| `agent/initial_alert_prompt.md.jinja` | `alert_name`, `severity`, `instance`, `job`, `starts_at`, `summary`, `description`, `labels` | Alert investigation context |

### Engine Templates

| Template | Variables | Purpose |
| -------- | --------- | ------- |
| `mitre_followon.md.jinja` | `source_technique_id`, `source_technique_name`, `target_technique_id`, `target_technique_name`, `relationship` | Follow-on technique questions |
| `mitre_gap.md.jinja` | `tactic_name`, `tactic_id`, `example_techniques` | Tactical gap analysis |
| `mitre_mapping.md.jinja` | `evidence_type`, `evidence_value` | Evidence-to-technique mapping |
| `pyramid_climb.md.jinja` | `question_text` | Pyramid elevation questions |

**Note**: `climb_strategies.yaml` is YAML config, not a template.

### Tool Templates

| Template | Variables | Purpose |
| -------- | --------- | ------- |
| `host_queries.md.jinja` | `hostname` | Loki/Prometheus queries for hosts |
| `user_queries.md.jinja` | `username` | Loki queries for users |

### Report Templates

| Template | Key Variables | Purpose |
| -------- | ------------- | ------- |
| `header.md.jinja` | `investigation_id`, `alert_name`, `severity`, `status` | Report header |
| `executive_summary.md.jinja` | `assessment`, `evidence_count`, `technique_count` | Executive summary |
| `timeline.md.jinja` | `events` (list) | Attack timeline |
| `mitre_mapping.md.jinja` | `techniques` (list), `tactics_count` | MITRE ATT&CK mapping |
| `pyramid_assessment.md.jinja` | `elevation_score`, `pyramid_viz`, `*_count` | Pyramid of Pain analysis |
| `evidence_inventory.md.jinja` | `evidence_by_level` (list) | Evidence catalog |
| `scope.md.jinja` | `hosts` (list), `users` (list) | Investigation scope |
| `recommendations.md.jinja` | `is_escalated`, `immediate_actions` | Recommendations |
| `appendix.md.jinja` | `queries` (list), `evidence_count` | Query appendix |

**Note**: All templates support Jinja2 control structures (`{% if %}`, `{% for %}`).

## Best Practices

### Template Design

- Use Markdown headings (`#`, `##`, `###`) for structure
- Use XML tags (`<instructions>`, `<context>`) for semantic sections
- Add comments with `{# comment #}` syntax
- Control whitespace with `{%- if -%}` syntax
- Test with edge cases (empty strings, missing data)

### YAML vs Templates

| Use YAML for | Use Templates for |
| ------------ | ----------------- |
| Configuration data | Prompt text |
| Strategy lists | Questions/responses |
| Behavior flags | Report content |

**Example**: `climb_strategies.yaml` defines strategy data; templates render
the questions.

## Testing

```python
from ares.core.templates import get_template_loader

loader = get_template_loader()

# Test rendering
try:
    result = loader.render("agent/initial_alert_prompt.md.jinja", **test_data)
    print("✓ Template renders successfully")
except Exception as e:
    print(f"✗ Template error: {e}")
```

## Migration Status

| File | Status | Notes |
| ---- | ------ | ----- |
| `src/ares/agents/blue/soc_investigator.py` | ✅ Complete | Uses template loader |
| `src/ares/agents/red/pentester.py` | ✅ Complete | Uses template loader |
| `src/ares/core/factories/blue_factory.py` | ✅ Complete | System instructions from template |
| `src/ares/core/factories/red_factory.py` | ✅ Complete | System instructions from template |
| `src/ares/core/engines.py` | ✅ Complete | All questions templated |
| `src/ares/tools/blue/investigation.py` | ✅ Complete | Query suggestions templated |
| `src/ares/reports/investigation.py` | ⚠️ Partial | Templates exist, integration incomplete |
| `src/ares/reports/redteam.py` | ✅ Complete | Red team reports templated |

## Troubleshooting

| Error | Cause | Solution |
| ----- | ----- | -------- |
| `TemplateNotFound` | Missing template file | Verify file exists in `templates/` |
| `UndefinedError` | Missing variable | Pass all required variables to `render()` |
| `ScannerError` | YAML syntax error | Check indentation in `.yaml` files |

## References

- [Anthropic Claude Prompt Engineering](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview)
- [Using XML Tags in Prompts](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/use-xml-tags)
- [Jinja2 Documentation](https://jinja.palletsprojects.com/)
- [Linear Issue CAP-775](https://linear.app/dreadnode/issue/CAP-775/migrate-ares-prompts-to-jinja2-templates)
