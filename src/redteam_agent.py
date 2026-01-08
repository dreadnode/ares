"""
Ares Red Team Agent.

Orchestrates penetration testing operations for Active Directory environments.
"""

import uuid
from pathlib import Path

import dreadnode as dn
from loguru import logger

from .core.create_redteam import create_redteam_agent
from .mitre import MITREAttackClient
from .models import RedTeamState, Target
from .redteam_report import RedTeamReportGenerator
from .templates import get_template_loader


def build_initial_task(target_ip: str) -> str:
    """Build the initial task prompt for red team operation.

    Args:
        target_ip: IP address of the primary target.

    Returns:
        Formatted task prompt string for agent initialization.

    Example:
        >>> task = build_initial_task("192.168.1.100")
        >>> '192.168.1.100' in task
        True
    """
    loader = get_template_loader()
    return loader.render(
        "redteam/agents/initial_task.md.jinja",
        target_ip=target_ip,
    )


class RedTeamOrchestrator:
    """Main orchestrator for red team operations.

    Creates and manages Dreadnode Agents for penetration testing engagements.

    Attributes:
        model: LLM model identifier string.
        mitre_client: Client for MITRE ATT&CK data lookups.
        report_dir: Directory path for generated reports.
        max_steps: Maximum number of agent steps per operation.
    """

    def __init__(
        self,
        model: str,
        mitre_client: MITREAttackClient,
        report_dir: Path,
        max_steps: int = 200,
    ):
        self.model = model
        self.mitre_client = mitre_client
        self.report_dir = report_dir
        self.max_steps = max_steps

    async def execute_operation(self, target_ip: str) -> dict:
        """Execute a red team operation against a target.

        Creates a new agent for this operation and runs it until completion.

        Args:
            target_ip: IP address of the primary target system.

        Returns:
            A dict containing:
                - operation_id: Unique identifier for this operation
                - status: "completed" or "failed"
                - report_path: Path to the generated markdown report
                - host_count: Number of hosts discovered
                - credential_count: Number of credentials obtained
                - has_domain_admin: Whether domain admin access was achieved
                - has_golden_ticket: Whether golden ticket was generated

        Raises:
            TimeoutError: If operation exceeds the configured timeout.
        """
        operation_id = f"redteam-{uuid.uuid4().hex[:8]}"

        logger.info(f"Starting red team operation {operation_id} against: {target_ip}")

        # Create operation state
        state = RedTeamState(
            operation_id=operation_id,
            target=Target(ip=target_ip),
        )

        initial_task = build_initial_task(target_ip)

        with dn.run(tags=["red-team-operation", target_ip]):
            dn.log_params(
                model=self.model,
                operation_id=operation_id,
                target_ip=target_ip,
                max_steps=self.max_steps,
            )
            dn.log_input("target", {"ip": target_ip})

            agent = create_redteam_agent(
                model=self.model,
                mitre_client=self.mitre_client,
                state=state,
                max_steps=self.max_steps,
            )

            # Run the operation with timeout
            try:
                import asyncio

                logger.info(f"Starting agent.run() with max_steps={self.max_steps}")
                logger.info(f"Initial task length: {len(initial_task)} chars")

                # Add a generous timeout (10 minutes per step for red team operations)
                timeout_seconds = self.max_steps * 600  # 10 minutes per step

                result = await asyncio.wait_for(
                    agent.run(initial_task),
                    timeout=timeout_seconds,
                )

                logger.success(
                    f"Red team agent completed: {result.steps} steps, {result.stop_reason}"
                )

                # Log additional details about the result
                if hasattr(result, "error") and result.error:
                    logger.error(f"Agent error: {result.error}")
                if hasattr(result, "last_error") and result.last_error:
                    logger.error(f"Last error: {result.last_error}")
                if hasattr(result, "messages") and result.messages:
                    logger.info(f"Messages count: {len(result.messages)}")
                    for i, msg in enumerate(result.messages[-3:]):  # Last 3 messages
                        logger.info(f"Message {i}: {type(msg).__name__} - {str(msg)[:200]}")

                # Mark operation as completed
                state.completed = True

                # Generate report
                report_path = self._generate_report(state, result)

                dn.log_output("report_path", str(report_path))
                dn.log_metric("operation_success", 1)
                dn.log_metric("hosts_discovered", state.host_count)
                dn.log_metric("credentials_obtained", state.credential_count)
                dn.log_metric("domain_admin_achieved", 1 if state.has_domain_admin else 0)
                dn.log_metric("golden_ticket_achieved", 1 if state.has_golden_ticket else 0)

                return {
                    "operation_id": operation_id,
                    "status": "completed",
                    "report_path": str(report_path),
                    "host_count": state.host_count,
                    "user_count": len(state.users),
                    "credential_count": state.credential_count,
                    "admin_count": state.admin_count,
                    "has_domain_admin": state.has_domain_admin,
                    "has_golden_ticket": state.has_golden_ticket,
                    "techniques_identified": list(state.identified_techniques),
                }

            except asyncio.TimeoutError:
                logger.error(f"Operation {operation_id} timed out after {timeout_seconds} seconds")
                dn.log_metric("operation_timeout", 1)

                # Generate partial report
                state.report_summary = "Operation timed out before completion"
                report_path = self._generate_report(state, None)

                return {
                    "operation_id": operation_id,
                    "status": "timeout",
                    "report_path": str(report_path),
                    "host_count": state.host_count,
                    "credential_count": state.credential_count,
                    "has_domain_admin": state.has_domain_admin,
                    "has_golden_ticket": state.has_golden_ticket,
                }

            except Exception as e:
                logger.exception(f"Operation {operation_id} failed with error: {e}")
                dn.log_metric("operation_error", 1)

                # Generate error report
                state.report_summary = f"Operation failed: {e!s}"
                report_path = self._generate_report(state, None)

                return {
                    "operation_id": operation_id,
                    "status": "failed",
                    "error": str(e),
                    "report_path": str(report_path),
                }

    def _generate_report(self, state: RedTeamState, result: any) -> Path:
        """Generate the red team operation report.

        Args:
            state: The operation state containing all discoveries.
            result: The agent result object (or None if incomplete).

        Returns:
            Path to the generated report markdown file.
        """
        report_generator = RedTeamReportGenerator()
        report_content = report_generator.generate(state)

        # Write report to file
        report_filename = f"{state.operation_id}_report.md"
        report_path = self.report_dir / report_filename

        self.report_dir.mkdir(parents=True, exist_ok=True)

        with open(report_path, "w") as f:
            f.write(report_content)

        logger.success(f"Red team report generated: {report_path}")

        return report_path
