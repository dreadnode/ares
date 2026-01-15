"""CLI for submitting operations to the orchestrator service."""

import sys
import uuid
from typing import Annotated

import cyclopts
from loguru import logger

from ares.core.config import get_redis_url
from ares.core.orchestrator_client import (
    get_operation_status,
    submit_operation,
    wait_for_operation_completion,
)

app = cyclopts.App(
    name="ares-ops",
    help="Submit and manage operations with the Ares orchestrator service",
)


@app.command
async def submit(
    target: Annotated[str, cyclopts.Parameter(help="Target name or identifier")],
    domain: Annotated[str, cyclopts.Parameter(help="Target domain")],
    *,
    ips: Annotated[list[str] | None, cyclopts.Parameter(help="Target IP addresses")] = None,
    operation_id: Annotated[
        str | None,
        cyclopts.Parameter(help="Operation ID (auto-generated if not provided)"),
    ] = None,
    username: Annotated[str | None, cyclopts.Parameter(help="Initial credential username")] = None,
    password: Annotated[str | None, cyclopts.Parameter(help="Initial credential password")] = None,
    ntlm_hash: Annotated[
        str | None, cyclopts.Parameter(help="Initial credential NTLM hash")
    ] = None,
    resume: Annotated[bool, cyclopts.Parameter(help="Resume from checkpoint")] = False,
    wait: Annotated[bool, cyclopts.Parameter(help="Wait for operation to complete")] = False,
    model: Annotated[str, cyclopts.Parameter(help="LLM model to use")] = "claude-sonnet-4-20250514",
    max_steps: Annotated[int, cyclopts.Parameter(help="Maximum agent steps")] = 200,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Submit a multi-agent red team operation to the orchestrator service.

    Example:
        ares-ops submit dreadgoad sevenkingdoms.local --ips 10.0.4.90 10.0.4.129 --wait
    """
    # Resolve config defaults
    resolved_redis_url = redis_url or get_redis_url()

    # Generate operation ID if not provided
    if not operation_id:
        operation_id = f"multiagent-{uuid.uuid4().hex[:8]}"

    # Resolve target IPs (would normally query infrastructure)
    if not ips:
        logger.error("No target IPs specified. Use --ips to provide target IPs.")
        sys.exit(1)

    # Build initial credential if provided (filter out None values for type safety)
    initial_cred: dict[str, str] | None = None
    if username:
        cred_data = {
            "username": username,
            "password": password,
            "ntlm_hash": ntlm_hash,
            "domain": domain,
        }
        initial_cred = {k: v for k, v in cred_data.items() if v is not None}

    logger.info(f"Submitting operation: {operation_id}")
    logger.info(f"Target: {target} ({domain})")
    logger.info(f"IPs: {', '.join(ips)}")

    try:
        result = await submit_operation(
            operation_id=operation_id,
            target_domain=domain,
            target_ips=ips,
            initial_credential=initial_cred,
            resume_from_checkpoint=resume,
            model=model,
            max_steps=max_steps,
            redis_url=resolved_redis_url,
            wait_for_completion=wait,
        )

        logger.success(f"Operation submitted: {operation_id}")
        logger.info(f"Status: {result['status']}")

        if wait and result["status"] == "completed":
            logger.success("Operation completed successfully!")
        elif wait and result["status"] == "failed":
            logger.error(f"Operation failed: {result.get('error', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Failed to submit operation: {e}")
        sys.exit(1)


@app.command
async def status(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    *,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Get the status of an operation.

    Example:
        ares-ops status multiagent-abc123
    """
    resolved_redis_url = redis_url or get_redis_url()

    try:
        result = await get_operation_status(
            operation_id=operation_id,
            redis_url=resolved_redis_url,
        )

        if result:
            logger.info(f"Operation: {operation_id}")
            logger.info(f"Status: {result['status']}")
            logger.info(f"Updated: {result.get('updated_at', 'Unknown')}")

            if result["status"] == "completed":
                logger.success("Operation completed successfully")
            elif result["status"] == "failed":
                logger.error(f"Operation failed: {result.get('error', 'Unknown')}")
        else:
            logger.warning(f"Operation {operation_id} not found")

    except Exception as e:
        logger.error(f"Failed to get operation status: {e}")
        sys.exit(1)


@app.command
async def wait_for(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    *,
    timeout: Annotated[float, cyclopts.Parameter(help="Timeout in seconds")] = 3600.0,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Wait for an operation to complete.

    Example:
        ares-ops wait-for multiagent-abc123 --timeout 7200
    """
    resolved_redis_url = redis_url or get_redis_url()

    logger.info(f"Waiting for operation: {operation_id}")

    try:
        result = await wait_for_operation_completion(
            operation_id=operation_id,
            redis_url=resolved_redis_url,
            timeout=timeout,
        )

        logger.info(f"Operation {operation_id} {result['status']}")

        if result["status"] == "completed":
            logger.success("Operation completed successfully!")
        elif result["status"] == "failed":
            logger.error(f"Operation failed: {result.get('error', 'Unknown error')}")

    except TimeoutError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error waiting for operation: {e}")
        sys.exit(1)


def main() -> None:
    """Entry point for ares-ops CLI."""
    try:
        app()
    except Exception as e:
        logger.error(f"CLI error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
