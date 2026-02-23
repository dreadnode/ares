"""Task prompt generation for blue team workers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from loguru import logger

from ares.core.models import BlueTaskType


def generate_blue_task_prompt(
    task_type: BlueTaskType,
    params: dict[str, Any],
    shared_state_summary: dict[str, Any] | None = None,
) -> str:
    """Generate a task prompt for a blue team worker.

    Renders the appropriate Jinja template with the task parameters
    and current shared state summary.

    Args:
        task_type: Type of task to generate prompt for.
        params: Task-specific parameters.
        shared_state_summary: Current investigation state summary.

    Returns:
        Rendered prompt string.
    """
    from ares.core.templates import get_template_loader

    loader = get_template_loader()

    template_map = {
        BlueTaskType.TRIAGE_ALERT: "blueteam/agents/triage_task.md.jinja",
        BlueTaskType.THREAT_HUNT: "blueteam/agents/threat_hunt_task.md.jinja",
        BlueTaskType.LATERAL_ANALYSIS: "blueteam/agents/lateral_task.md.jinja",
        BlueTaskType.USER_INVESTIGATION: "blueteam/agents/user_investigation_task.md.jinja",
        BlueTaskType.HOST_INVESTIGATION: "blueteam/agents/host_investigation_task.md.jinja",
    }

    template_name = template_map.get(task_type)
    if not template_name:
        # Fallback to a simple prompt
        return _generate_fallback_prompt(task_type, params)

    try:
        return loader.render(
            template_name,
            current_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            state_summary=shared_state_summary or {},
            **params,
        )
    except Exception as e:
        logger.warning(f"Failed to render template {template_name}: {e}")
        return _generate_fallback_prompt(task_type, params)


def _generate_fallback_prompt(task_type: BlueTaskType, params: dict[str, Any]) -> str:
    """Generate a simple fallback prompt when template rendering fails."""
    import json

    lines = [f"# Task: {task_type.value}", ""]

    if task_type == BlueTaskType.TRIAGE_ALERT:
        alert = params.get("alert", {})
        alert_name = alert.get("labels", {}).get("alertname", "unknown")
        lines.append(f"Triage alert: {alert_name}")
        lines.append(f"Alert data: {json.dumps(alert, indent=2, default=str)[:2000]}")
        lines.append("")
        lines.append(
            "Assess severity and record initial evidence. Call triage_complete() when done."
        )

    elif task_type == BlueTaskType.THREAT_HUNT:
        lines.append(f"Hunt for technique: {params.get('technique_id', 'N/A')}")
        lines.append(f"Detection method: {params.get('detection_method', 'N/A')}")
        if params.get("hostname"):
            lines.append(f"Focus host: {params['hostname']}")
        if params.get("username"):
            lines.append(f"Focus user: {params['username']}")
        lines.append("")
        lines.append("Run detection queries, record evidence, call hunt_complete() when done.")

    elif task_type == BlueTaskType.LATERAL_ANALYSIS:
        lines.append("Analyze lateral movement scope")
        if params.get("focus_host"):
            lines.append(f"Focus host: {params['focus_host']}")
        if params.get("focus_user"):
            lines.append(f"Focus user: {params['focus_user']}")
        lines.append("")
        lines.append(
            "Investigate host/user activity, record lateral connections, "
            "call lateral_complete() when done."
        )

    elif task_type == BlueTaskType.USER_INVESTIGATION:
        lines.append(f"Investigate user: {params.get('username', 'unknown')}")
        lines.append("")
        lines.append("Analyze user activity, record evidence, call hunt_complete() when done.")

    elif task_type == BlueTaskType.HOST_INVESTIGATION:
        lines.append(f"Investigate host: {params.get('hostname', 'unknown')}")
        lines.append("")
        lines.append("Analyze host activity, record evidence, call lateral_complete() when done.")

    if params.get("context"):
        lines.append("")
        lines.append(f"Context: {params['context']}")

    return "\n".join(lines)
