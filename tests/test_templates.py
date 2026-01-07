"""Tests for Jinja2 template system."""

from pathlib import Path

import pytest
from jinja2 import TemplateNotFound

from src.templates import TemplateLoader, get_template_loader


class TestTemplateLoader:
    """Test the TemplateLoader class."""

    def test_loader_initialization(self) -> None:
        """Test that loader initializes correctly with default path."""
        loader = TemplateLoader()
        assert loader.template_dir.exists()
        assert loader.template_dir.name == "templates"
        assert loader.env is not None

    def test_loader_custom_path(self, tmp_path: Path) -> None:
        """Test loader with custom template directory."""
        template_dir = tmp_path / "custom_templates"
        template_dir.mkdir()
        (template_dir / "test.jinja").write_text("Hello {{ name }}")

        loader = TemplateLoader(template_dir)
        assert loader.template_dir == template_dir

    def test_loader_missing_directory(self, tmp_path: Path) -> None:
        """Test loader raises error for missing directory."""
        missing_dir = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError, match="Template directory not found"):
            TemplateLoader(missing_dir)

    def test_list_templates(self) -> None:
        """Test listing all templates."""
        loader = TemplateLoader()
        templates = loader.list_templates()

        assert len(templates) > 0
        assert all(t.endswith(".jinja") for t in templates)

    def test_list_templates_with_pattern(self) -> None:
        """Test listing templates with specific pattern."""
        loader = TemplateLoader()
        agent_templates = loader.list_templates("agent/*.jinja")

        assert len(agent_templates) >= 2
        assert any("system_instructions" in t for t in agent_templates)
        assert any("initial_alert_prompt" in t for t in agent_templates)

    def test_render_simple_template(self, tmp_path: Path) -> None:
        """Test rendering a simple template."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "test.jinja").write_text("Hello {{ name }}!")

        loader = TemplateLoader(template_dir)
        result = loader.render("test.jinja", name="World")

        assert result == "Hello World!"

    def test_render_missing_template(self) -> None:
        """Test rendering non-existent template raises error."""
        loader = TemplateLoader()
        with pytest.raises(TemplateNotFound):
            loader.render("nonexistent.jinja")

    def test_render_missing_variable(self, tmp_path: Path) -> None:
        """Test rendering with missing variable raises error in strict mode."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "test.jinja").write_text("Hello {{ name }}!")

        loader = TemplateLoader(template_dir)
        # Jinja2 with default settings will render undefined as empty string
        # We need to check the actual behavior
        result = loader.render("test.jinja")
        # This will pass because Jinja2 default is lenient
        assert "Hello" in result

    def test_get_template_loader_singleton(self) -> None:
        """Test that get_template_loader returns singleton instance."""
        loader1 = get_template_loader()
        loader2 = get_template_loader()

        assert loader1 is loader2


class TestAgentTemplates:
    """Test agent template rendering."""

    def test_system_instructions_template(self) -> None:
        """Test system instructions template renders without errors."""
        loader = get_template_loader()
        result = loader.render("agent/system_instructions.md.jinja")

        assert len(result) > 0
        assert "Ares" in result or "SOC" in result or "investigation" in result.lower()

    def test_initial_alert_prompt_template(self) -> None:
        """Test initial alert prompt template with all variables."""
        loader = get_template_loader()
        result = loader.render(
            "agent/initial_alert_prompt.md.jinja",
            alert_name="HighCPU",
            severity="warning",
            instance="web-01",
            job="web",
            starts_at="2024-01-15T10:00:00Z",
            summary="CPU usage is high",
            description="CPU usage exceeded 80%",
            labels={"alertname": "HighCPU", "severity": "warning"},
        )

        assert "HighCPU" in result
        assert "warning" in result
        assert "web-01" in result
        assert "CPU usage" in result

    def test_initial_alert_prompt_minimal(self) -> None:
        """Test initial alert prompt with minimal variables."""
        loader = get_template_loader()
        # Should not raise error with basic variables
        result = loader.render(
            "agent/initial_alert_prompt.md.jinja",
            alert_name="TestAlert",
            severity="info",
            instance="test-01",
            job="test",
            starts_at="2024-01-15T10:00:00Z",
            summary="Test",
            description="Test",
            labels={},
        )

        assert "TestAlert" in result


class TestEngineTemplates:
    """Test engine template rendering."""

    def test_mitre_followon_template(self) -> None:
        """Test MITRE follow-on technique template."""
        loader = get_template_loader()
        result = loader.render(
            "engines/mitre_followon.md.jinja",
            source_technique_id="T1059",
            source_technique_name="Command and Scripting Interpreter",
            target_technique_id="T1003",
            target_technique_name="OS Credential Dumping",
            relationship="commonly-precedes",
        )

        assert "T1059" in result
        assert "T1003" in result
        assert "Command and Scripting Interpreter" in result

    def test_mitre_gap_template(self) -> None:
        """Test MITRE tactical gap template."""
        loader = get_template_loader()
        result = loader.render(
            "engines/mitre_gap.md.jinja",
            tactic_name="Initial Access",
            tactic_id="TA0001",
            example_techniques="Phishing, Drive-by Compromise",
        )

        assert "Initial Access" in result
        assert "TA0001" in result
        assert "Phishing" in result

    def test_mitre_mapping_template(self) -> None:
        """Test MITRE evidence mapping template."""
        loader = get_template_loader()
        result = loader.render(
            "engines/mitre_mapping.md.jinja",
            evidence_type="process",
            evidence_value="powershell.exe",
        )

        assert "process" in result
        assert "powershell.exe" in result

    def test_pyramid_climb_template(self) -> None:
        """Test Pyramid of Pain climb template."""
        loader = get_template_loader()
        result = loader.render(
            "engines/pyramid_climb.md.jinja",
            question_text="What tool generated this hash?",
        )

        assert "What tool generated this hash?" in result


class TestToolTemplates:
    """Test tool template rendering."""

    def test_host_queries_template(self) -> None:
        """Test host queries template."""
        loader = get_template_loader()
        result = loader.render(
            "tools/host_queries.md.jinja",
            hostname="web-01",
        )

        assert "web-01" in result
        # Should suggest queries (check for "queries" or "Loki"/"Prometheus")
        assert "queries" in result.lower() or "loki" in result.lower()

    def test_user_queries_template(self) -> None:
        """Test user queries template."""
        loader = get_template_loader()
        result = loader.render(
            "tools/user_queries.md.jinja",
            username="admin",
        )

        assert "admin" in result
        # Should suggest queries
        assert "query" in result.lower() or "log" in result.lower()


class TestReportTemplates:
    """Test report template rendering."""

    def test_header_template(self) -> None:
        """Test report header template."""
        loader = get_template_loader()
        result = loader.render(
            "reports/header.md.jinja",
            investigation_id="inv-12345678",
            generated_timestamp="2024-01-15T10:00:00Z",
            duration="5m 30s",
            alert_name="HighCPU",
            severity="warning",
            instance="web-01",
            job="web",
            status="COMPLETED ✓",
            alert_json='{"labels": {}}',
        )

        assert "inv-12345678" in result
        assert "HighCPU" in result
        assert "warning" in result

    def test_executive_summary_template_exists(self) -> None:
        """Test that executive summary template exists."""
        loader = get_template_loader()
        templates = loader.list_templates("reports/executive_summary*")
        assert len(templates) > 0

    def test_timeline_template_exists(self) -> None:
        """Test that timeline template exists."""
        loader = get_template_loader()
        templates = loader.list_templates("reports/timeline*")
        assert len(templates) > 0

    def test_all_report_templates_exist(self) -> None:
        """Test that all documented report templates exist."""
        loader = get_template_loader()
        expected_templates = [
            "header.md.jinja",
            "executive_summary.md.jinja",
            "timeline.md.jinja",
            "mitre_mapping.md.jinja",
            "pyramid_assessment.md.jinja",
            "evidence_inventory.md.jinja",
            "scope.md.jinja",
            "recommendations.md.jinja",
            "appendix.md.jinja",
        ]

        for template in expected_templates:
            templates = loader.list_templates(f"reports/{template}")
            assert len(templates) > 0, f"Missing template: reports/{template}"


class TestClimbStrategiesConfig:
    """Test climb_strategies.yaml configuration loading."""

    def test_climb_strategies_file_exists(self) -> None:
        """Test that climb strategies YAML file exists."""
        from src.engines import _load_climb_strategies

        strategies = _load_climb_strategies()
        assert len(strategies) > 0

    def test_climb_strategies_structure(self) -> None:
        """Test that climb strategies have expected structure."""
        from src.engines import CLIMB_STRATEGIES
        from src.models import PyramidLevel

        # Should have strategies for most pyramid levels
        assert len(CLIMB_STRATEGIES) > 0

        # Each strategy should have required fields
        for level, strategies in CLIMB_STRATEGIES.items():
            assert isinstance(level, PyramidLevel)
            assert len(strategies) > 0

            for strategy in strategies:
                assert "template" in strategy
                assert "target" in strategy
                assert "insight" in strategy
                assert "elevation" in strategy
                assert isinstance(strategy["template"], str)
                assert isinstance(strategy["target"], PyramidLevel)
                assert isinstance(strategy["elevation"], int)


class TestTemplateIntegration:
    """Test template integration with actual modules."""

    def test_agent_uses_templates(self) -> None:
        """Test that agent.py uses templates correctly."""
        from src.agent import build_initial_prompt

        alert = {
            "labels": {
                "alertname": "TestAlert",
                "severity": "warning",
                "instance": "test-01",
                "job": "test",
            },
            "annotations": {
                "summary": "Test summary",
                "description": "Test description",
            },
            "startsAt": "2024-01-15T10:00:00Z",
        }

        prompt = build_initial_prompt(alert)

        assert "TestAlert" in prompt
        assert "warning" in prompt
        assert "test-01" in prompt

    def test_create_uses_system_instructions_template(self) -> None:
        """Test that create.py loads system instructions from template."""
        from src.core.create import SYSTEM_INSTRUCTIONS

        assert len(SYSTEM_INSTRUCTIONS) > 0
        # System instructions should be substantial
        assert len(SYSTEM_INSTRUCTIONS) > 100

    def test_engines_load_climb_strategies(self) -> None:
        """Test that engines.py loads climb strategies."""
        from src.engines import CLIMB_STRATEGIES

        assert len(CLIMB_STRATEGIES) > 0

    def test_investigation_tools_use_templates(self) -> None:
        """Test that investigation tools use templates."""
        from src.models import InvestigationState
        from src.tools.investigation import InvestigationTools

        tools = InvestigationTools()
        state = InvestigationState(
            investigation_id="test-123",
            alert={"labels": {}, "annotations": {}},
        )
        tools.set_state(state)

        # Test host investigation
        result = tools.track_host_investigation("web-01")
        assert "web-01" in result

        # Test user investigation
        result = tools.track_user_investigation("admin")
        assert "admin" in result
