"""Jinja2 template loader for Ares prompt templates.

This module provides utilities for loading and rendering Markdown-based
Jinja2 templates used throughout the Ares codebase.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class TemplateLoader:
    """Load and render Jinja2 templates for Ares prompts.

    Templates are stored in the templates/ directory and use Markdown
    format with XML tags for structure, following Anthropic's best
    practices for prompt engineering.

    Attributes:
        env: Jinja2 Environment configured for template rendering.
        template_dir: Path to the templates directory.

    Example:
        >>> loader = TemplateLoader()
        >>> prompt = loader.render(
        ...     "agent/initial_alert_prompt.md.jinja",
        ...     alert_name="HighCPU",
        ...     severity="warning"
        ... )
    """

    def __init__(self, template_dir: Path | None = None):
        """Initialize the template loader.

        Args:
            template_dir: Optional path to templates directory.
                         Defaults to PROJECT_ROOT/templates/.
        """
        if template_dir is None:
            # Get project root (from src/ares/core/templates.py -> ../../..)
            project_root = Path(__file__).parent.parent.parent.parent
            template_dir = project_root / "templates"

        self.template_dir = Path(template_dir)

        if not self.template_dir.exists():
            msg = f"Template directory not found: {self.template_dir}"
            raise FileNotFoundError(msg)

        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def render(self, template_path: str, **context) -> str:
        """Render a template with the provided context variables.

        Args:
            template_path: Relative path to template from templates/ directory.
                          Example: "agent/system_instructions.md.jinja"
            **context: Keyword arguments to pass as template variables.

        Returns:
            Rendered template as a string.

        Raises:
            jinja2.TemplateNotFound: If template file doesn't exist.
            jinja2.TemplateError: If template has syntax errors.

        Example:
            >>> loader = TemplateLoader()
            >>> result = loader.render(
            ...     "tools/host_queries.md.jinja",
            ...     hostname="web-01"
            ... )
        """
        template = self.env.get_template(template_path)
        return template.render(**context)

    def list_templates(self, pattern: str = "**/*.jinja") -> list[str]:
        """List all available templates matching a pattern.

        Args:
            pattern: Glob pattern to match templates (default: all .jinja files).

        Returns:
            List of template paths relative to templates/ directory.

        Example:
            >>> loader = TemplateLoader()
            >>> loader.list_templates("agent/*.jinja")
            ['agent/system_instructions.md.jinja', 'agent/initial_alert_prompt.md.jinja']
        """
        return [
            str(p.relative_to(self.template_dir))
            for p in self.template_dir.glob(pattern)
            if p.is_file()
        ]


# Global template loader instance
_loader: TemplateLoader | None = None


def get_template_loader() -> TemplateLoader:
    """Get or create the global template loader instance.

    Returns:
        Singleton TemplateLoader instance.

    Example:
        >>> from ares.core.templates import get_template_loader
        >>> loader = get_template_loader()
        >>> prompt = loader.render("agent/initial_alert_prompt.md.jinja", ...)
    """
    global _loader  # noqa: PLW0603
    if _loader is None:
        _loader = TemplateLoader()
    return _loader
