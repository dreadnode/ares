"""CLI for submitting operations to the orchestrator service."""

import asyncio
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
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


async def _stream_orchestrator_logs(
    namespace: str,
    log_path: Path | None,
    filter_token: str | None = None,
) -> None:
    command = ["kubectl", "logs", "-f", "-n", namespace, "deploy/ares-orchestrator"]
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    log_handle = None
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("a", encoding="utf-8")

    try:
        while True:
            if not proc.stdout:
                break
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace")
            if filter_token and filter_token not in text:
                continue
            sys.stdout.write(text)
            sys.stdout.flush()
            if log_handle:
                log_handle.write(text)
                log_handle.flush()
    except KeyboardInterrupt:
        logger.info("Stopping orchestrator log follow...")
        proc.terminate()
        await proc.wait()
    finally:
        if log_handle:
            log_handle.close()


def _resolve_log_path(log_file: str | None, operation_id: str) -> Path:
    if log_file is not None:
        return Path(log_file)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    log_dir = Path(os.environ.get("LOG_DIR", "./logs"))
    return log_dir / f"orchestrator-{operation_id}-{timestamp}.log"


@app.command
async def submit(
    target: Annotated[str, cyclopts.Parameter(help="Target name or identifier")],
    domain: Annotated[str, cyclopts.Parameter(help="Target domain")],
    *,
    ips: Annotated[
        list[str] | None,
        cyclopts.Parameter(help="Target IP addresses", consume_multiple=True),
    ] = None,
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
    follow_logs: Annotated[
        bool, cyclopts.Parameter(help="Follow orchestrator logs after submit")
    ] = False,
    k8s_namespace: Annotated[
        str, cyclopts.Parameter(help="K8s namespace for orchestrator logs")
    ] = "attack-simulation",
    log_file: Annotated[
        str | None, cyclopts.Parameter(help="Write orchestrator logs to this file")
    ] = None,
    filter_logs: Annotated[
        bool,
        cyclopts.Parameter(help="Only print orchestrator lines containing the operation ID"),
    ] = False,
    model: Annotated[
        str | None, cyclopts.Parameter(help="LLM model to use (defaults to env)")
    ] = None,
    max_steps: Annotated[int, cyclopts.Parameter(help="Maximum agent steps")] = 200,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Submit a multi-agent red team operation to the orchestrator service.

    Example:
        ares-ops submit dreadgoad example.local --ips 10.0.4.90 10.0.4.129 --wait
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

    # Collect environment variables to pass to orchestrator service
    # These are API keys and model config that need to be available at runtime
    env_var_names = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DREADNODE_API_KEY",
        "DREADNODE_API_TOKEN",
        "DREADNODE_SERVER_URL",
        "DREADNODE_SERVER",
        "DREADNODE_ORGANIZATION",
        "DREADNODE_WORKSPACE",
        "DREADNODE_PROJECT",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "GRAFANA_URL",
        "ARES_MODEL",
        "ARES_ORCHESTRATOR_MODEL",
        "ARES_WORKER_MODEL",
        "ARES_AGENT_ENUM_MODEL",
        "ARES_AGENT_CRACKER_MODEL",
        "ARES_AGENT_ACL_MODEL",
        "ARES_AGENT_PRIVESC_MODEL",
        "ARES_AGENT_LATERAL_MODEL",
        "ARES_AGENT_POISONING_MODEL",
        "ARES_AGENT_ATOMIC_MODEL",
    ]
    env_vars = {name: os.environ.get(name, "") for name in env_var_names if os.environ.get(name)}
    if env_vars:
        present_keys = sorted(env_vars.keys())
        logger.info(f"Submitting with env vars: {', '.join(present_keys)}")
    else:
        logger.warning("No env vars found to submit with operation request")

    effective_model = (
        model or os.environ.get("ARES_ORCHESTRATOR_MODEL") or os.environ.get("ARES_MODEL")
    )
    if (
        effective_model
        and effective_model.startswith("gpt-")
        and not os.environ.get("OPENAI_API_KEY")
    ):
        raise ValueError(
            "OPENAI_API_KEY is required for OpenAI models. Set it in the environment "
            "before submitting the operation."
        )

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
            env_vars=env_vars if env_vars else None,
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

    if follow_logs:
        if not shutil.which("kubectl"):
            logger.error("kubectl not found. Install kubectl or disable --follow-logs.")
            sys.exit(1)

        resolved_log_path = _resolve_log_path(log_file, operation_id)

        logger.info("Following orchestrator logs (Ctrl+C to stop)...")
        logger.info(f"Namespace: {k8s_namespace}")
        logger.info(f"Log file: {resolved_log_path}")
        await _stream_orchestrator_logs(
            namespace=k8s_namespace,
            log_path=resolved_log_path,
            filter_token=operation_id if filter_logs else None,
        )


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
