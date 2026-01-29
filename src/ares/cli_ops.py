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
from ares.core.redis_client import create_redis_client

app = cyclopts.App(
    name="ares-ops",
    help="Submit and manage operations with the Ares orchestrator service",
)


def _persist_report(
    status: dict[str, object],
    *,
    operation_id: str,
    report_dir: Path | None = None,
) -> Path | None:
    result_payload = status.get("result") if isinstance(status.get("result"), dict) else None
    report_markdown = None
    report_path = None
    if result_payload:
        report_markdown = result_payload.get("report_markdown")
        report_path = result_payload.get("report_path")
    else:
        report_markdown = status.get("report_markdown")
        report_path = status.get("report_path")

    if not report_markdown:
        return None

    resolved_dir = Path(report_dir or "./reports").resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)

    if isinstance(report_path, str) and report_path:
        filename = Path(report_path).name
    else:
        filename = f"{operation_id}_report.md"

    output_path = resolved_dir / filename
    output_path.write_text(str(report_markdown))
    logger.success(f"Report saved: {output_path}")
    return output_path


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
        "ARES_AGENT_RECON_MODEL",
        "ARES_AGENT_CREDENTIAL_ACCESS_MODEL",
        "ARES_AGENT_CRACKER_MODEL",
        "ARES_AGENT_ACL_MODEL",
        "ARES_AGENT_PRIVESC_MODEL",
        "ARES_AGENT_LATERAL_MODEL",
        "ARES_AGENT_COERCION_MODEL",
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
            _persist_report(result, operation_id=operation_id)
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
                _persist_report(result, operation_id=operation_id)
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
            _persist_report(result, operation_id=operation_id)
        elif result["status"] == "failed":
            logger.error(f"Operation failed: {result.get('error', 'Unknown error')}")

    except TimeoutError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error waiting for operation: {e}")
        sys.exit(1)


@app.command
async def loot(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    *,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    json_output: Annotated[bool, cyclopts.Parameter(help="Output as JSON")] = False,
) -> None:
    """Dump users, credentials, hosts, and hashes from operation state.

    Example:
        ares-ops loot op-20250128-123456
    """
    import json as json_module

    from ares.core.models import SharedRedTeamState
    from ares.core.redis_client import create_redis_client

    resolved_redis_url = redis_url or get_redis_url()

    try:
        client = await create_redis_client(resolved_redis_url, decode_responses=False)
        data = await client.get(f"ares:operation:{operation_id}:state")
        await client.aclose()

        if not data:
            logger.error(f"No state found for operation: {operation_id}")
            sys.exit(1)

        state = SharedRedTeamState.from_bytes(data)

        # Deduplicate users by normalized domain+username
        seen_user_keys: set[tuple[str, str]] = set()
        unique_users = []
        for user in state.all_users:
            user_key = (user.domain.strip().lower(), user.username.strip().lower())
            if user_key not in seen_user_keys:
                seen_user_keys.add(user_key)
                unique_users.append(user)

        # Deduplicate credentials by normalized domain+username+password
        seen_cred_keys: set[tuple[str, str, str]] = set()
        unique_creds = []
        for cred in state.all_credentials:
            cred_key = (
                cred.domain.strip().lower(),
                cred.username.strip().lower(),
                cred.password,
            )
            if cred_key not in seen_cred_keys:
                seen_cred_keys.add(cred_key)
                unique_creds.append(cred)

        # Deduplicate hashes by normalized domain+username+hash_type+hash_value
        seen_hash_keys: set[tuple[str, str, str, str]] = set()
        unique_hashes = []
        for h in state.all_hashes:
            hash_key = (
                h.domain.strip().lower(),
                h.username.strip().lower(),
                h.hash_type.strip().lower(),
                h.hash_value.strip().lower(),
            )
            if hash_key not in seen_hash_keys:
                seen_hash_keys.add(hash_key)
                unique_hashes.append(h)

        if json_output:
            output = {
                "operation_id": state.operation_id,
                "domains": list(getattr(state, "all_domains", [])),
                "hosts": [
                    {"ip": h.ip, "hostname": h.hostname, "os": h.os} for h in state.all_hosts
                ],
                "users": [
                    {"username": u.username, "domain": u.domain, "is_admin": u.is_admin}
                    for u in unique_users
                ],
                "credentials": [
                    {
                        "username": c.username,
                        "password": c.password,
                        "domain": c.domain,
                        "is_admin": c.is_admin,
                    }
                    for c in unique_creds
                ],
                "hashes": [
                    {
                        "username": h.username,
                        "domain": h.domain,
                        "hash_type": h.hash_type,
                        "hash_value": h.hash_value,
                        "source": h.source,
                    }
                    for h in unique_hashes
                ],
                "shares": [
                    {"host": s.host, "name": s.name, "permissions": s.permissions}
                    for s in state.all_shares
                ],
                "weaknesses": list(state.all_weaknesses),
            }
            print(json_module.dumps(output, indent=2, default=str))
            return

        # Human-readable output
        print(f"Operation: {state.operation_id}")
        print()

        # Domains
        domains = sorted({d.strip().lower() for d in getattr(state, "all_domains", []) if d})
        print(f"Domains ({len(domains)}):")
        for domain in domains or ["None"]:
            print(f"  - {domain}")
        print()

        # Hosts
        print(f"Hosts ({len(state.all_hosts)}):")
        for host in state.all_hosts:
            parts = [p for p in [host.hostname, host.ip] if p]
            line = " / ".join(parts) if parts else "(unknown)"
            if host.os:
                line = f"{line} [{host.os}]"
            print(f"  - {line}")
        print()

        # Users
        print(f"Users ({len(unique_users)}):")
        for user in unique_users:
            prefix = f"{user.domain}\\{user.username}" if user.domain else user.username
            suffix = " (admin)" if user.is_admin else ""
            print(f"  - {prefix}{suffix}")
        print()

        # Credentials
        print(f"Credentials ({len(unique_creds)}):")
        for cred in unique_creds:
            prefix = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
            suffix = " (admin)" if cred.is_admin else ""
            print(f"  - {prefix}:{cred.password}{suffix}")
        print()

        # Hashes
        print(f"Hashes ({len(unique_hashes)}):")
        for h in unique_hashes:
            prefix = f"{h.domain}\\{h.username}" if h.domain else h.username
            print(f"  - {prefix}:{h.hash_type}:{h.hash_value}")
        print()

        # Shares
        print(f"Shares ({len(state.all_shares)}):")
        for share in state.all_shares:
            line = f"{share.host}/{share.name}" if share.host else share.name
            if share.permissions:
                line = f"{line} [{share.permissions}]"
            print(f"  - {line}")
        print()

        # Weaknesses
        print(f"Weaknesses ({len(state.all_weaknesses)}):")
        for w in state.all_weaknesses or ["None"]:
            print(f"  - {w}")

    except Exception as e:
        logger.error(f"Failed to dump loot: {e}")
        sys.exit(1)


@app.command
async def tasks(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    *,
    task_status: Annotated[
        str, cyclopts.Parameter(help="Filter by status (running/completed/failed/pending/all)")
    ] = "running",
    role: Annotated[str | None, cyclopts.Parameter(help="Filter by role")] = None,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """List tasks for an operation.

    Example:
        ares-ops tasks op-20250128-123456 --status running --role lateral
    """
    import json as json_module

    resolved_redis_url = redis_url or get_redis_url()

    try:
        client = await create_redis_client(resolved_redis_url, decode_responses=True)
        found_tasks = []

        # Use KEYS instead of SCAN for reliability - SCAN can miss keys
        task_keys = await client.keys("ares:task_status:*")
        for key in task_keys:
            raw = await client.get(key)
            if not raw:
                continue
            try:
                data = json_module.loads(raw)
            except (json_module.JSONDecodeError, ValueError):
                # Skip malformed JSON entries in Redis
                continue

            if data.get("operation_id") != operation_id:
                continue
            if role and data.get("role") != role:
                continue
            if task_status != "all" and data.get("status") != task_status:
                continue

            found_tasks.append((key, data))

        await client.aclose()

        if not found_tasks:
            print(f"No {task_status} tasks found for operation {operation_id}")
            return

        # Sort by started_at or ended_at
        def sort_key(item: tuple[str, dict]) -> str:
            return item[1].get("started_at") or item[1].get("ended_at") or ""

        for key, data in sorted(found_tasks, key=sort_key):
            print(key)
            print(
                json_module.dumps(
                    {
                        "status": data.get("status"),
                        "started_at": data.get("started_at"),
                        "ended_at": data.get("ended_at"),
                        "pod": data.get("pod_name"),
                        "role": data.get("role"),
                        "task_type": data.get("task_type"),
                        "error": data.get("error"),
                        "payload": data.get("payload"),
                    },
                    indent=2,
                )
            )

    except Exception as e:
        logger.error(f"Failed to list tasks: {e}")
        sys.exit(1)


@app.command(name="list")
async def list_operations(
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Only print the latest operation ID (prefer running)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """List all operations with checkpoints, or get the latest one.

    Examples:
        ares-ops list              # List all operations
        ares-ops list --latest     # Print only the latest/running operation ID
    """
    from ares.core.task_queue import RedisTaskQueue

    resolved_redis_url = redis_url or get_redis_url()

    def pick_latest(items: list[tuple[datetime | None, str]]) -> str:
        with_time = [(t, op) for t, op in items if t is not None]
        if with_time:
            with_time.sort(key=lambda x: x[0], reverse=True)  # type: ignore[arg-type]
            return with_time[0][1]
        items.sort(key=lambda x: x[1])
        return items[0][1]

    try:
        client = await create_redis_client(resolved_redis_url, decode_responses=True)
        await client.ping()

        # Gather all operations with their checkpoint times and running status
        all_ops: list[
            tuple[datetime | None, str, bool]
        ] = []  # (checkpoint_time, op_id, is_running)

        # Check for running operations (have locks)
        # Use KEYS instead of SCAN for reliability - SCAN can miss keys
        running_ops: set[str] = set()
        lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
        for key in lock_keys:
            parts = key.split(":", 2)
            if len(parts) >= 3:
                running_ops.add(parts[2])

        # Get all operations with state
        # Use KEYS instead of SCAN for reliability - SCAN can miss keys
        state_keys = await client.keys("ares:operation:*:state")
        for key in state_keys:
            parts = key.split(":")
            if len(parts) < 3:
                continue
            op_id = parts[2]
            checkpoint = await client.get(f"ares:operation:{op_id}:checkpoint_time")
            checkpoint_time = None
            if checkpoint:
                try:
                    checkpoint_time = datetime.fromisoformat(checkpoint)
                except Exception:
                    pass
            is_running = op_id in running_ops
            all_ops.append((checkpoint_time, op_id, is_running))

        await client.aclose()

        if not all_ops:
            print("No operations found")
            return

        if latest:
            # Prefer running operations, then fall back to latest by checkpoint time
            running = [(t, op) for t, op, is_running in all_ops if is_running]
            if running:
                print(pick_latest(running))
            else:
                print(pick_latest([(t, op) for t, op, _ in all_ops]))
            return

        # Full listing
        print("Multi-Agent Operations:")
        print("=" * 60)
        # Sort by checkpoint time (newest first)
        all_ops.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        for checkpoint_time, op_id, is_running in all_ops:
            status = " [running]" if is_running else ""
            time_str = checkpoint_time.isoformat() if checkpoint_time else "unknown"
            print(f"  {op_id}: checkpoint at {time_str}{status}")

    except Exception as e:
        logger.error(f"Failed to list operations: {e}")
        sys.exit(1)


@app.command
async def queue(
    *,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """List operations and queue state from Redis.

    Example:
        ares-ops queue
    """
    from collections import Counter

    from ares.core.models import SharedRedTeamState
    from ares.core.task_queue import RedisTaskQueue

    resolved_redis_url = redis_url or get_redis_url()

    try:
        client = await create_redis_client(resolved_redis_url, decode_responses=False)
        await client.ping()

        operations = []
        # Use KEYS instead of SCAN for reliability - SCAN can miss keys
        state_keys = await client.keys("ares:operation:*:state")
        for key in state_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            parts = key_str.split(":")
            if len(parts) < 3:
                continue
            op_id = parts[2]
            data = await client.get(key)
            if not data:
                continue

            state = SharedRedTeamState.from_bytes(data)
            checkpoint_raw = await client.get(f"ares:operation:{op_id}:checkpoint_time")
            checkpoint_time = checkpoint_raw.decode() if checkpoint_raw else "unknown"
            lock_key = f"{RedisTaskQueue.LOCK_PREFIX}:{op_id}"
            is_running = await client.exists(lock_key) > 0
            status_counts = Counter(task.status.value for task in state.pending_tasks.values())

            operations.append(
                {
                    "operation_id": op_id,
                    "checkpoint_time": checkpoint_time,
                    "running": is_running,
                    "pending_total": len(state.pending_tasks),
                    "completed_total": len(state.completed_tasks),
                    "status_counts": status_counts,
                    "has_domain_admin": state.has_domain_admin,
                    "vuln_total": len(state.discovered_vulnerabilities),
                    "exploited_total": len(state.exploited_vulnerabilities),
                }
            )

        await client.aclose()

        if not operations:
            print("No operations found")
            return

        print("Multi-Agent Operations (Redis)")
        print("=" * 70)
        for op in sorted(operations, key=lambda x: x["operation_id"]):
            running = "running" if op["running"] else "idle"
            counts = op["status_counts"]
            print(f"  {op['operation_id']} [{running}] checkpoint: {op['checkpoint_time']}")
            print(
                f"    pending: {op['pending_total']} "
                f"(pending {counts.get('pending', 0)}, "
                f"in_progress {counts.get('in_progress', 0)}, "
                f"retrying {counts.get('retrying', 0)}) "
                f"completed: {op['completed_total']}"
            )
            da = "yes" if op["has_domain_admin"] else "no"
            print(
                f"    domain_admin: {da}  "
                f"vulns: {op['vuln_total']}  "
                f"exploited: {op['exploited_total']}"
            )

    except Exception as e:
        logger.error(f"Failed to list queue: {e}")
        sys.exit(1)


@app.command
async def cleanup(
    *,
    max_age_hours: Annotated[int, cyclopts.Parameter(help="Max age in hours")] = 24,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Clean up old operation checkpoints.

    Example:
        ares-ops cleanup --max-age-hours 48
    """
    from ares.core.recovery import OperationRecoveryManager

    resolved_redis_url = redis_url or get_redis_url()

    try:
        recovery = OperationRecoveryManager(redis_url=resolved_redis_url)
        await recovery.start()

        removed = await recovery.cleanup_old_checkpoints(max_age_hours=max_age_hours)
        await recovery.stop()

        print(f"Cleaned up {removed} old checkpoints (older than {max_age_hours} hours)")

    except Exception as e:
        logger.error(f"Failed to cleanup: {e}")
        sys.exit(1)


@app.command
async def backfill_domains(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    *,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Backfill domain list into Redis state from discovered data.

    Example:
        ares-ops backfill-domains op-20250128-123456
    """
    from ares.core.models import SharedRedTeamState
    from ares.core.redis_client import create_redis_client

    resolved_redis_url = redis_url or get_redis_url()

    def extract_domains(state: SharedRedTeamState) -> list[str]:
        domains: set[str] = set()

        def add(value: str | None) -> None:
            value = (value or "").strip().lower()
            if value:
                domains.add(value)

        if state.target:
            add(getattr(state.target, "domain", ""))
            target_host = getattr(state.target, "hostname", "")
            if target_host and "." in target_host:
                parts = target_host.split(".")
                if len(parts) > 1:
                    add(".".join(parts[1:]))

        for cred in state.all_credentials:
            add(cred.domain)
        for user in state.all_users:
            add(user.domain)
        for h in state.all_hashes:
            add(h.domain)
        for host in state.all_hosts:
            hostname = host.hostname
            if hostname and "." in hostname:
                parts = hostname.split(".")
                if len(parts) > 1:
                    add(".".join(parts[1:]))

        return sorted(domains)

    try:
        client = await create_redis_client(resolved_redis_url, decode_responses=False)
        key = f"ares:operation:{operation_id}:state"
        data = await client.get(key)

        if not data:
            logger.error(f"No state found for operation: {operation_id}")
            sys.exit(1)

        state = SharedRedTeamState.from_bytes(data)
        domains = extract_domains(state)

        if not domains:
            print("No domains inferred from current state.")
            await client.aclose()
            return

        before = set(getattr(state, "all_domains", []))
        for domain in domains:
            if hasattr(state, "add_domain"):
                state.add_domain(domain)
            elif domain not in before:
                state.all_domains.append(domain)

        await client.set(key, state.to_bytes())
        await client.aclose()

        added = [d for d in domains if d not in before]
        print(f"Backfilled domains ({len(added)}): {', '.join(added) if added else 'None'}")

    except Exception as e:
        logger.error(f"Failed to backfill domains: {e}")
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
