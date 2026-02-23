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
| `blueteam/` | Blue team system instructions & prompts | ✅ Complete |
| `engines/` | Question generation & attack chain templates | ✅ Complete |
| `tools/` | Investigation query suggestions | ✅ Complete |
| `reports/` | Report section templates | ✅ Complete |
| `redteam/` | Red team agent templates | ✅ Complete |

## API Reference

### List Templates

```python
from ares.core.templates import get_template_loader

loader = get_template_loader()
templates = loader.list_templates()
```

## Template Variables

### Blue Team Templates

| Template | Required Variables | Purpose |
| -------- | ------------------ | ------- |
| `blueteam/*.md.jinja` | Varies | Blue team agent instructions |

### Red Team Templates

| Template | Required Variables | Purpose |
| -------- | ------------------ | ------- |
| `redteam/agents/orchestrator.md.jinja` | `state`, `credentials`, etc. | Orchestrator system prompt |
| `redteam/agents/recon.md.jinja` | `task`, `state` | Recon agent instructions |
| `redteam/agents/credential_access.md.jinja` | `task`, `state` | Credential access agent |
| `redteam/agents/cracker.md.jinja` | `task`, `state` | Cracker agent instructions |
| `redteam/agents/acl.md.jinja` | `task`, `state` | ACL agent instructions |
| `redteam/agents/privesc.md.jinja` | `task`, `state` | PrivEsc agent instructions |
| `redteam/agents/lateral.md.jinja` | `task`, `state` | Lateral movement agent |
| `redteam/agents/coercion.md.jinja` | `task`, `state` | Coercion agent instructions |
| `redteam/agents/system_instructions.md.jinja` | `state` | Shared system instructions |

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
| `src/ares/core/factories/blue_factory.py` | ✅ Complete | System instructions from template |
| `src/ares/core/factories/red_agents.py` | ✅ Complete | Red team agent templates |
| `src/ares/core/worker/prompts.py` | ✅ Complete | Worker prompt generation |
| `src/ares/core/engines.py` | ✅ Complete | All questions templated |
| `src/ares/tools/blue/investigation.py` | ✅ Complete | Query suggestions templated |
| `src/ares/reports/investigation.py` | ⚠️ Partial | Templates exist, integration incomplete |
| `src/ares/reports/redteam.py` | ✅ Complete | Red team reports templated |
| `src/ares/reports/blueteam.py` | ✅ Complete | Blue team reports templated |

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
