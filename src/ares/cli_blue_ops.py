"""CLI for submitting investigations to the blue orchestrator service."""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import cyclopts
from loguru import logger


# Suppress DEBUG/INFO logs from noisy modules in CLI output.
def _cli_log_filter(record):
    """Filter out DEBUG/INFO from noisy modules, keep all from cli_blue_ops."""
    module = record["name"]
    level = record["level"].no
    if module in {"ares.cli_blue_ops", "__main__"}:
        return True
    return level >= 30


logger.remove()
logger.add(sys.stderr, filter=_cli_log_filter)

from ares.core.blue_orchestrator_client import (  # noqa: E402
    get_investigation_status,
    submit_investigation,
)
from ares.core.config import get_redis_url  # noqa: E402
from ares.core.redis_client import create_verified_redis_client  # noqa: E402

app = cyclopts.App(
    name="ares-blue-ops",
    help="Submit and manage investigations with the Ares blue team orchestrator service",
)


@app.command
async def submit(
    alert_json: Annotated[str, cyclopts.Parameter(help="Alert JSON string or path to JSON file")],
    *,
    investigation_id: Annotated[
        str, cyclopts.Parameter(help="Investigation ID (auto-generated if not provided)")
    ] = "",
    model: Annotated[str, cyclopts.Parameter(help="LLM model to use")] = "",
    max_steps: Annotated[int, cyclopts.Parameter(help="Maximum agent steps")] = 25,
    multi_agent: Annotated[bool, cyclopts.Parameter(help="Force multi-agent mode")] = False,
    auto_route: Annotated[
        bool, cyclopts.Parameter(help="Auto-route HIGH/CRITICAL to multi-agent")
    ] = True,
    report_dir: Annotated[str, cyclopts.Parameter(help="Report output directory")] = "",
    grafana_url: Annotated[str, cyclopts.Parameter(help="Grafana URL")] = "",
    grafana_api_key: Annotated[str, cyclopts.Parameter(help="Grafana API key")] = "",
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    wait: Annotated[bool, cyclopts.Parameter(help="Wait for investigation to complete")] = False,
    follow_logs: Annotated[bool, cyclopts.Parameter(help="Follow orchestrator logs")] = False,
) -> None:
    """Submit an investigation to the blue team orchestrator service."""
    # Parse alert JSON
    alert_path = Path(alert_json)
    if alert_path.is_file():
        alert = json.loads(alert_path.read_text())
    else:
        try:
            alert = json.loads(alert_json)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            sys.exit(1)

    # Resolve model
    resolved_model = (
        model or os.environ.get("ARES_ORCHESTRATOR_MODEL") or os.environ.get("ARES_MODEL")
    )
    if not resolved_model:
        logger.error("No model specified. Use --model or set ARES_ORCHESTRATOR_MODEL/ARES_MODEL")
        sys.exit(1)

    # Collect env vars to pass
    env_vars = {}
    for key in [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "GRAFANA_API_KEY",
        "GRAFANA_URL",
        "DREADNODE_API_KEY",
        "DREADNODE_SERVER_URL",
        "DREADNODE_ORGANIZATION",
        "DREADNODE_WORKSPACE",
        "DREADNODE_PROJECT",
        "ARES_MODEL",
        "ARES_ORCHESTRATOR_MODEL",
    ]:
        if os.environ.get(key):
            env_vars[key] = os.environ[key]

    result = await submit_investigation(
        alert=alert,
        investigation_id=investigation_id or None,
        model=resolved_model,
        max_steps=max_steps,
        multi_agent=multi_agent,
        auto_route=auto_route,
        report_dir=report_dir or None,
        grafana_url=grafana_url or os.environ.get("GRAFANA_URL"),
        grafana_api_key=grafana_api_key or os.environ.get("GRAFANA_SERVICE_ACCOUNT_TOKEN"),
        redis_url=redis_url or None,
        wait_for_completion=wait,
        env_vars=env_vars,
    )

    inv_id = result["investigation_id"]
    print(f"Investigation submitted: {inv_id}")
    print(f"Status: {result['status']}")

    if wait and result.get("status") in ("completed", "failed"):
        print(f"Final status: {result['status']}")
        if result.get("completed_at"):
            print(f"Completed at: {result['completed_at']}")
        if result.get("result"):
            print(f"Result: {json.dumps(result['result'], indent=2)}")


@app.command
async def status(
    investigation_id: Annotated[str, cyclopts.Parameter(help="Investigation ID")] = "",
    *,
    latest: Annotated[bool, cyclopts.Parameter(help="Get status of latest investigation")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Get the status of an investigation."""
    redis_url = redis_url or get_redis_url()

    if latest:
        # Find latest investigation
        inv_id = await _get_latest_investigation_id(redis_url)
        if not inv_id:
            print("No investigations found")
            return
        investigation_id = inv_id

    if not investigation_id:
        logger.error("Either investigation_id or --latest is required")
        sys.exit(1)

    result = await get_investigation_status(investigation_id, redis_url)

    if result is None:
        print(f"Investigation not found: {investigation_id}")
        return

    print(f"Investigation: {investigation_id}")
    print(f"Status: {result.get('status', 'unknown')}")
    if result.get("started_at"):
        print(f"Started: {result['started_at']}")
    if result.get("completed_at"):
        print(f"Completed: {result['completed_at']}")
    if result.get("failed_at"):
        print(f"Failed: {result['failed_at']}")
    if result.get("error"):
        print(f"Error: {result['error']}")
    if result.get("result"):
        print(f"Result: {json.dumps(result['result'], indent=2)}")


@app.command(name="list")
async def list_investigations(
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Only print the latest investigation ID")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """List all investigations."""
    redis_url = redis_url or get_redis_url()
    client = await create_verified_redis_client(redis_url, decode_responses=True)

    try:
        investigations: list[dict[str, Any]] = []

        # Get investigations from status keys (ares:blue:inv:*:status)
        status_keys = await client.keys("ares:blue:inv:*:status")
        for key in status_keys:
            key_str = key if isinstance(key, str) else key.decode()
            parts = key_str.split(":")
            if len(parts) < 4:
                continue
            inv_id = parts[3]

            status_data = await client.get(key_str)
            if status_data:
                status = json.loads(status_data)
                investigations.append(
                    {
                        "investigation_id": inv_id,
                        "status": status.get("status", "unknown"),
                        "started_at": status.get("started_at"),
                        "completed_at": status.get("completed_at"),
                        "failed_at": status.get("failed_at"),
                    }
                )

        # Also check meta keys for more investigation data
        meta_keys = await client.keys("ares:blue:inv:*:meta")
        seen_ids = {inv["investigation_id"] for inv in investigations}
        for key in meta_keys:
            key_str = key if isinstance(key, str) else key.decode()
            parts = key_str.split(":")
            if len(parts) < 4:
                continue
            inv_id = parts[3]
            if inv_id in seen_ids:
                continue

            meta_data = await client.hgetall(key_str)
            if meta_data:
                started_at = meta_data.get("started_at")
                if isinstance(started_at, bytes):
                    started_at = started_at.decode()
                investigations.append(
                    {
                        "investigation_id": inv_id,
                        "status": meta_data.get("status", b"unknown").decode()
                        if isinstance(meta_data.get("status"), bytes)
                        else meta_data.get("status", "unknown"),
                        "started_at": started_at,
                    }
                )

        # Sort by started_at (most recent first)
        investigations.sort(
            key=lambda x: x.get("started_at") or "",
            reverse=True,
        )

        if latest:
            # Prefer running investigations
            running = [i for i in investigations if i["status"] == "running"]
            if running:
                print(running[0]["investigation_id"])
            elif investigations:
                print(investigations[0]["investigation_id"])
            return

        if not investigations:
            print("No investigations found")
            return

        print(f"{'Investigation ID':<25} {'Status':<12} {'Started':<25} {'Completed':<25}")
        print("-" * 90)
        for inv in investigations:
            started = inv.get("started_at", "")[:25] if inv.get("started_at") else ""
            completed = inv.get("completed_at", "")[:25] if inv.get("completed_at") else ""
            if inv.get("failed_at"):
                completed = f"FAILED: {inv['failed_at'][:15]}"
            print(
                f"{inv['investigation_id']:<25} {inv['status']:<12} {started:<25} {completed:<25}"
            )

    finally:
        await client.aclose()


@app.command
async def delete(
    investigation_id: Annotated[str, cyclopts.Parameter(help="Investigation ID to delete")],
    *,
    force: Annotated[bool, cyclopts.Parameter(help="Skip confirmation")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Delete an investigation and all its data."""
    redis_url = redis_url or get_redis_url()

    if not force:
        confirm = await asyncio.to_thread(
            input, f"Delete investigation {investigation_id} and all data? [y/N] "
        )
        if confirm.lower() != "y":
            print("Aborted")
            return

    client = await create_verified_redis_client(redis_url, decode_responses=True)
    try:
        # Find and delete all keys for this investigation
        pattern = f"ares:blue:inv:{investigation_id}:*"
        keys = await client.keys(pattern)

        deleted = 0
        if keys:
            deleted = await client.delete(*keys)

        # Also remove from active investigations set
        removed = await client.srem("ares:blue:active_investigations", investigation_id)
        if removed:
            deleted += removed

        if deleted == 0:
            print(f"No data found for investigation: {investigation_id}")
            return

        print(f"Deleted {deleted} keys for investigation: {investigation_id}")

    finally:
        await client.aclose()


@app.command(name="delete-operation")
async def delete_operation(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID to delete")],
    *,
    force: Annotated[bool, cyclopts.Parameter(help="Skip confirmation")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Delete an operation and all its investigations."""
    redis_url = redis_url or get_redis_url()

    client = await create_verified_redis_client(redis_url, decode_responses=True)
    try:
        # Get investigation IDs for this operation
        op_inv_key = f"ares:blue:op:{operation_id}:investigations"
        inv_ids = await client.smembers(op_inv_key)

        if not inv_ids:
            print(f"No investigations found for operation: {operation_id}")
            # Check if the operation key exists at all
            exists = await client.exists(op_inv_key)
            if not exists:
                print(f"Operation tracking key does not exist: {op_inv_key}")
            return

        print(f"Operation: {operation_id}")
        print(f"Investigations to delete: {len(inv_ids)}")
        for inv_id in sorted(inv_ids):
            print(f"  - {inv_id}")

        if not force:
            confirm = await asyncio.to_thread(
                input,
                f"\nDelete operation {operation_id} and {len(inv_ids)} investigation(s)? [y/N] ",
            )
            if confirm.lower() != "y":
                print("Aborted")
                return

        # Delete all investigation keys
        total_deleted = 0
        for inv_id in inv_ids:
            pattern = f"ares:blue:inv:{inv_id}:*"
            keys = await client.keys(pattern)
            if keys:
                deleted = await client.delete(*keys)
                total_deleted += deleted

        # Remove from active investigations set
        if inv_ids:
            removed = await client.srem("ares:blue:active_investigations", *inv_ids)
            total_deleted += removed

        # Delete the operation tracking key
        await client.delete(op_inv_key)
        total_deleted += 1

        print(f"\nDeleted {total_deleted} keys")
        print(f"Operation {operation_id} and {len(inv_ids)} investigation(s) deleted")

    finally:
        await client.aclose()


@app.command
async def cleanup(
    *,
    max_age_hours: Annotated[
        int, cyclopts.Parameter(help="Max age in hours for investigations")
    ] = 24,
    all_investigations: Annotated[
        bool, cyclopts.Parameter("--all", help="Delete ALL investigations (ignores max-age-hours)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    dry_run: Annotated[bool, cyclopts.Parameter(help="Show what would be deleted")] = False,
    force: Annotated[bool, cyclopts.Parameter(help="Skip confirmation for --all")] = False,
) -> None:
    """Clean up old investigations."""
    redis_url = redis_url or get_redis_url()
    client = await create_verified_redis_client(redis_url, decode_responses=True)

    try:
        if all_investigations:
            # Clear ALL investigations
            inv_keys = await client.keys("ares:blue:inv:*")
            op_keys = await client.keys("ares:blue:op:*")
            active_exists = await client.exists("ares:blue:active_investigations")
            queue_len = await client.llen("ares:blue:investigations")

            print(f"Found {len(inv_keys)} investigation keys")
            print(f"Found {len(op_keys)} operation tracking keys")
            print(f"Queue length: {queue_len}")

            if dry_run:
                print("(dry run - no changes made)")
                return

            if not force:
                confirm = await asyncio.to_thread(
                    input, "Delete ALL blue team investigations? [y/N] "
                )
                if confirm.lower() != "y":
                    print("Aborted")
                    return

            deleted = 0
            if inv_keys:
                deleted += await client.delete(*inv_keys)
            if op_keys:
                deleted += await client.delete(*op_keys)
            if active_exists:
                deleted += await client.delete("ares:blue:active_investigations")
            if queue_len > 0:
                await client.delete("ares:blue:investigations")
                deleted += 1

            print(f"Deleted {deleted} keys")
            print("All blue team investigations cleared")
            return

        # Original behavior: clean up old investigations
        cutoff = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)

        # Find investigations to clean up
        status_keys = await client.keys("ares:blue:inv:*:status")
        to_delete: list[str] = []

        for key in status_keys:
            key_str = key if isinstance(key, str) else key.decode()
            parts = key_str.split(":")
            if len(parts) < 4:
                continue
            inv_id = parts[3]

            status_data = await client.get(key_str)
            if not status_data:
                continue

            status = json.loads(status_data)
            # Only clean up completed or failed investigations
            if status.get("status") not in ("completed", "failed"):
                continue

            # Check age
            completed_at = status.get("completed_at") or status.get("failed_at")
            if completed_at:
                try:
                    completed_ts = datetime.fromisoformat(
                        completed_at.replace("Z", "+00:00")
                    ).timestamp()
                    if completed_ts < cutoff:
                        to_delete.append(inv_id)
                except (ValueError, AttributeError):
                    pass

        if not to_delete:
            print(f"No investigations older than {max_age_hours} hours to clean up")
            return

        print(f"Found {len(to_delete)} investigation(s) to clean up:")
        for inv_id in to_delete:
            print(f"  - {inv_id}")

        if dry_run:
            print("(dry run - no changes made)")
            return

        # Delete keys for each investigation
        total_deleted = 0
        for inv_id in to_delete:
            pattern = f"ares:blue:inv:{inv_id}:*"
            keys = await client.keys(pattern)
            if keys:
                deleted = await client.delete(*keys)
                total_deleted += deleted

        # Also remove from active investigations set
        if to_delete:
            removed = await client.srem("ares:blue:active_investigations", *to_delete)
            total_deleted += removed

        print(f"Deleted {total_deleted} keys from {len(to_delete)} investigation(s)")

    finally:
        await client.aclose()


@app.command
async def evidence(
    investigation_id: Annotated[str, cyclopts.Parameter(help="Investigation ID")] = "",
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Get evidence from latest investigation")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    json_output: Annotated[bool, cyclopts.Parameter(help="Output as JSON")] = False,
) -> None:
    """Show evidence collected during an investigation."""
    redis_url = redis_url or get_redis_url()

    if latest:
        inv_id = await _get_latest_investigation_id(redis_url)
        if not inv_id:
            print("No investigations found")
            return
        investigation_id = inv_id

    if not investigation_id:
        logger.error("Either investigation_id or --latest is required")
        sys.exit(1)

    client = await create_verified_redis_client(redis_url, decode_responses=True)
    try:
        evidence_key = f"ares:blue:inv:{investigation_id}:evidence"
        evidence_data = await client.hgetall(evidence_key)

        if not evidence_data:
            print(f"No evidence found for investigation: {investigation_id}")
            return

        evidence_items = []
        for value in evidence_data.values():
            try:
                evidence_items.append(json.loads(value))
            except json.JSONDecodeError:
                pass

        if json_output:
            print(json.dumps(evidence_items, indent=2))
            return

        print(f"Evidence for investigation: {investigation_id}")
        print(f"Total items: {len(evidence_items)}")
        print("-" * 60)

        # Group by type
        by_type: dict[str, list] = {}
        for item in evidence_items:
            ev_type = item.get("type", "unknown")
            by_type.setdefault(ev_type, []).append(item)

        for ev_type, items in sorted(by_type.items()):
            print(f"\n{ev_type.upper()} ({len(items)} items):")
            for item in items[:10]:  # Limit to 10 per type
                value = item.get("value", "")
                if isinstance(value, dict):
                    value = json.dumps(value)
                print(f"  - {value[:80]}{'...' if len(str(value)) > 80 else ''}")
            if len(items) > 10:
                print(f"  ... and {len(items) - 10} more")

    finally:
        await client.aclose()


@app.command
async def techniques(
    investigation_id: Annotated[str, cyclopts.Parameter(help="Investigation ID")] = "",
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Get techniques from latest investigation")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Show MITRE ATT&CK techniques identified during an investigation."""
    redis_url = redis_url or get_redis_url()

    if latest:
        inv_id = await _get_latest_investigation_id(redis_url)
        if not inv_id:
            print("No investigations found")
            return
        investigation_id = inv_id

    if not investigation_id:
        logger.error("Either investigation_id or --latest is required")
        sys.exit(1)

    client = await create_verified_redis_client(redis_url, decode_responses=True)
    try:
        # Get techniques
        techniques_key = f"ares:blue:inv:{investigation_id}:techniques"
        techniques = await client.smembers(techniques_key)

        # Get technique names
        names_key = f"ares:blue:inv:{investigation_id}:technique_names"
        names = await client.hgetall(names_key)

        if not techniques:
            print(f"No techniques identified for investigation: {investigation_id}")
            return

        print(f"MITRE ATT&CK Techniques for investigation: {investigation_id}")
        print("-" * 60)

        for tech_id in sorted(techniques):
            name = names.get(tech_id, "")
            print(f"  {tech_id}: {name}" if name else f"  {tech_id}")

    finally:
        await client.aclose()


@app.command
async def runtime(
    investigation_id: Annotated[str, cyclopts.Parameter(help="Investigation ID")] = "",
    *,
    latest: Annotated[bool, cyclopts.Parameter(help="Get runtime of latest investigation")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Show runtime information for an investigation."""
    redis_url = redis_url or get_redis_url()

    if latest:
        inv_id = await _get_latest_investigation_id(redis_url)
        if not inv_id:
            print("No investigations found")
            return
        investigation_id = inv_id

    if not investigation_id:
        logger.error("Either investigation_id or --latest is required")
        sys.exit(1)

    result = await get_investigation_status(investigation_id, redis_url)
    if not result:
        print(f"Investigation not found: {investigation_id}")
        return

    started_at = result.get("started_at")
    completed_at = result.get("completed_at") or result.get("failed_at")
    status = result.get("status", "unknown")

    print(f"Investigation: {investigation_id}")
    print(f"Status: {status}")

    if started_at:
        try:
            start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            print(f"Started: {start_dt.isoformat()}")

            if completed_at:
                end_dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
                elapsed = (end_dt - start_dt).total_seconds()
            elif status == "running":
                elapsed = (datetime.now(timezone.utc) - start_dt).total_seconds()
            else:
                elapsed = 0

            if elapsed > 0:
                hours, remainder = divmod(int(elapsed), 3600)
                minutes, seconds = divmod(remainder, 60)
                if hours > 0:
                    duration = f"{hours}h {minutes}m {seconds}s"
                elif minutes > 0:
                    duration = f"{minutes}m {seconds}s"
                else:
                    duration = f"{seconds}s"
                print(f"Duration: {duration}")

        except (ValueError, AttributeError):
            pass

    if completed_at:
        print(f"Completed: {completed_at}")


async def _get_latest_operation_id(redis_url: str) -> tuple[str | None, bool]:
    """Get the ID of the latest red team operation (prefer running).

    Returns:
        Tuple of (operation_id, is_running)
    """
    from ares.core.task_queue import RedisTaskQueue

    client = await create_verified_redis_client(redis_url, decode_responses=True)
    try:
        # Check for running operations first
        lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
        running_ops: set[str] = set()
        for key in lock_keys:
            key_str = key if isinstance(key, str) else key.decode()
            parts = key_str.split(":")
            if len(parts) >= 2:
                running_ops.add(parts[-1])

        # Get all operations with meta data
        meta_keys = await client.keys("ares:op:*:meta")
        operations: list[tuple[str, str | None]] = []  # (id, started_at)

        for key in meta_keys:
            key_str = key if isinstance(key, str) else key.decode()
            parts = key_str.split(":")
            if len(parts) >= 3:
                op_id = parts[2]
                meta_data = await client.hgetall(key_str)
                started_at = meta_data.get("started_at") or meta_data.get(b"started_at")
                if isinstance(started_at, bytes):
                    started_at = started_at.decode()
                operations.append((op_id, started_at))

        if not operations:
            return None, False

        # Prefer running operations
        running = [(op_id, started) for op_id, started in operations if op_id in running_ops]
        if running:
            running.sort(key=lambda x: x[1] or "", reverse=True)
            return running[0][0], True

        # Otherwise, return most recent
        operations.sort(key=lambda x: x[1] or "", reverse=True)
        return operations[0][0], False

    finally:
        await client.aclose()


@app.command(name="operation-status")
async def operation_status(
    operation_id: Annotated[str, cyclopts.Parameter(help="Red team operation ID")] = "",
    *,
    latest: Annotated[bool, cyclopts.Parameter(help="Use latest red team operation")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    watch: Annotated[int, cyclopts.Parameter(help="Watch mode: refresh every N seconds")] = 0,
) -> None:
    """Show aggregate status of all investigations from a red team operation."""
    redis_url = redis_url or get_redis_url()

    if latest:
        resolved_op, _ = await _get_latest_operation_id(redis_url)
        if not resolved_op:
            logger.error("No red team operations found")
            sys.exit(1)
        operation_id = resolved_op

    if not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    async def show_status() -> bool:
        """Show status, return True if all investigations are done."""
        client = await create_verified_redis_client(redis_url, decode_responses=True)
        try:
            # Get investigation IDs for this operation
            op_inv_key = f"ares:blue:op:{operation_id}:investigations"
            inv_ids = await client.smembers(op_inv_key)

            if not inv_ids:
                print(f"No investigations found for operation: {operation_id}")
                return True

            # Get status for each investigation
            statuses: dict[str, list[dict]] = {
                "submitted": [],
                "running": [],
                "completed": [],
                "escalated": [],
                "failed": [],
            }
            earliest_start: datetime | None = None
            latest_end: datetime | None = None

            for inv_id in sorted(inv_ids):
                status_key = f"ares:blue:inv:{inv_id}:status"
                status_json = await client.get(status_key)
                if status_json:
                    status = json.loads(status_json)
                    status["investigation_id"] = inv_id
                    statuses.setdefault(status.get("status", "unknown"), []).append(status)

                    # Track timing
                    if status.get("started_at"):
                        started = datetime.fromisoformat(
                            status["started_at"].replace("Z", "+00:00")
                        )
                        if earliest_start is None or started < earliest_start:
                            earliest_start = started

                    completed_at = status.get("completed_at") or status.get("failed_at")
                    if completed_at:
                        ended = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
                        if latest_end is None or ended > latest_end:
                            latest_end = ended
                else:
                    statuses["submitted"].append({"investigation_id": inv_id})

            # Calculate duration
            now = datetime.now(timezone.utc)
            if earliest_start:
                if statuses["running"] or statuses["submitted"]:
                    # Still running - duration from start to now
                    elapsed = (now - earliest_start).total_seconds()
                elif latest_end:
                    # All done - duration from start to last completion
                    elapsed = (latest_end - earliest_start).total_seconds()
                else:
                    elapsed = 0
            else:
                elapsed = 0

            # Format duration
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                duration = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                duration = f"{minutes}m {seconds}s"
            else:
                duration = f"{seconds}s"

            # Print summary
            total = len(inv_ids)
            running = len(statuses["running"])
            completed = len(statuses["completed"])
            escalated = len(statuses["escalated"])
            failed = len(statuses["failed"])
            submitted = len(statuses["submitted"])

            print(f"Operation: {operation_id}")
            print(f"Total investigations: {total}")
            print(f"  Running:   {running}")
            print(f"  Completed: {completed}")
            print(f"  Escalated: {escalated}")
            print(f"  Failed:    {failed}")
            print(f"  Submitted: {submitted}")
            print(f"Duration: {duration}")

            if earliest_start:
                print(f"Started: {earliest_start.isoformat()}")
            if latest_end and not (statuses["running"] or statuses["submitted"]):
                print(f"Completed: {latest_end.isoformat()}")

            # Show running investigations
            if statuses["running"]:
                print("\nRunning investigations:")
                for inv in statuses["running"]:
                    inv_id = inv["investigation_id"]
                    started_str = inv.get("started_at", "")[:19] if inv.get("started_at") else ""
                    print(f"  {inv_id} (started: {started_str})")

            # Show failed investigations
            if statuses["failed"]:
                print("\nFailed investigations:")
                for inv in statuses["failed"]:
                    inv_id = inv["investigation_id"]
                    error = inv.get("error", "")[:60] if inv.get("error") else ""
                    print(f"  {inv_id}: {error}")

            return not (statuses["running"] or statuses["submitted"])

        finally:
            await client.aclose()

    if watch > 0:
        while True:
            # Clear screen
            print("\033[2J\033[H", end="")
            all_done = await show_status()
            if all_done:
                print("\nAll investigations complete.")
                break
            print(f"\nRefreshing in {watch}s... (Ctrl+C to stop)")
            try:
                await asyncio.sleep(watch)
            except KeyboardInterrupt:
                break
    else:
        await show_status()


@app.command(name="from-operation")
async def from_operation(
    operation_id: Annotated[str, cyclopts.Parameter(help="Red team operation ID")] = "",
    *,
    latest: Annotated[bool, cyclopts.Parameter(help="Use latest red team operation")] = False,
    model: Annotated[str, cyclopts.Parameter(help="LLM model to use")] = "",
    max_steps: Annotated[int, cyclopts.Parameter(help="Maximum agent steps")] = 25,
    grafana_url: Annotated[str, cyclopts.Parameter(help="Grafana URL")] = "",
    grafana_api_key: Annotated[str, cyclopts.Parameter(help="Grafana API key")] = "",
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    wait: Annotated[bool, cyclopts.Parameter(help="Wait for investigations to complete")] = False,
    batch: Annotated[
        bool, cyclopts.Parameter(help="Batch related alerts into fewer investigations")
    ] = True,
) -> None:
    """Submit multi-agent investigations for alerts from a red team operation.

    This fetches alerts from Grafana that occurred during the red team operation's
    time window and submits each as a multi-agent investigation.
    """
    from ares.cli_ops import _load_state_from_redis
    from ares.eval.detection_playbook import create_detection_playbook
    from ares.tools.blue import GrafanaTools

    if not operation_id and not latest:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    # Resolve Redis URL
    redis_url = redis_url or get_redis_url()
    if not redis_url:
        logger.error("Redis URL required. Use --redis-url or set REDIS_URL")
        sys.exit(1)

    # Resolve operation ID
    operation_is_running = False
    if latest:
        resolved_op, operation_is_running = await _get_latest_operation_id(redis_url)
        if not resolved_op:
            logger.error("No red team operations found")
            sys.exit(1)
        operation_id = resolved_op
        logger.info(f"Using latest operation: {operation_id} (running={operation_is_running})")

    # Load operation state
    client = await create_verified_redis_client(redis_url, decode_responses=False)
    try:
        state = await _load_state_from_redis(client, operation_id)
        if not state:
            logger.error(f"No state found for operation: {operation_id}")
            sys.exit(1)
    finally:
        await client.aclose()

    # Create detection playbook for time window
    playbook = create_detection_playbook(state)
    window_start = playbook.attack_window_start
    window_end = playbook.attack_window_end

    logger.info(f"Operation: {operation_id}")
    logger.info(f"Attack window: {window_start.isoformat()} to {window_end.isoformat()}")
    logger.info(f"Techniques used: {len(playbook.techniques_used)}")

    # Resolve Grafana config
    grafana_url = grafana_url or os.environ.get("GRAFANA_URL", "")
    grafana_api_key = grafana_api_key or os.environ.get("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")

    if not grafana_url:
        logger.error("Grafana URL required. Use --grafana-url or set GRAFANA_URL")
        sys.exit(1)
    if not grafana_api_key:
        logger.error(
            "Grafana API key required. Use --grafana-api-key or set GRAFANA_SERVICE_ACCOUNT_TOKEN"
        )
        sys.exit(1)

    # Fetch alerts from Grafana
    grafana = GrafanaTools(base_url=grafana_url, api_key=grafana_api_key)

    if operation_is_running:
        # Running operation: combine firing + historical alerts
        firing_alerts = await grafana.get_firing_alerts()
        historical_alerts = await grafana.get_alerts_in_time_range(window_start, window_end)
        # Merge and dedupe
        seen_fingerprints: set[str] = set()
        alerts: list[dict] = []
        for alert in firing_alerts + historical_alerts:
            fp = alert.get("fingerprint", "")
            if fp and fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                alerts.append(alert)
            elif not fp:
                alerts.append(alert)
        logger.info(
            f"Alerts: {len(firing_alerts)} firing + {len(historical_alerts)} historical = {len(alerts)} total"
        )
    else:
        # Completed operation: historical alerts only
        alerts = await grafana.get_alerts_in_time_range(window_start, window_end)
        if not alerts:
            logger.info("No historical alerts found, checking currently firing")
            alerts = await grafana.get_firing_alerts()
        logger.info(f"Retrieved {len(alerts)} alerts from operation time window")

    if not alerts:
        logger.warning("No alerts found for this operation")
        return

    # Resolve model
    resolved_model = (
        model or os.environ.get("ARES_ORCHESTRATOR_MODEL") or os.environ.get("ARES_MODEL")
    )
    if not resolved_model:
        logger.error("No model specified. Use --model or set ARES_ORCHESTRATOR_MODEL/ARES_MODEL")
        sys.exit(1)

    # Collect env vars to pass
    env_vars = {}
    for key in [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "GRAFANA_API_KEY",
        "GRAFANA_URL",
        "DREADNODE_API_KEY",
        "DREADNODE_SERVER_URL",
        "DREADNODE_ORGANIZATION",
        "DREADNODE_WORKSPACE",
        "DREADNODE_PROJECT",
        "ARES_MODEL",
        "ARES_ORCHESTRATOR_MODEL",
    ]:
        if os.environ.get(key):
            env_vars[key] = os.environ[key]

    # Create Redis client for tracking operation -> investigations mapping
    tracking_client = await create_verified_redis_client(redis_url, decode_responses=True)
    op_inv_key = f"ares:blue:op:{operation_id}:investigations"

    async def track_investigation(inv_id: str) -> None:
        """Add investigation ID to operation's tracking set."""
        await tracking_client.sadd(op_inv_key, inv_id)
        # Set TTL of 7 days for the operation tracking key
        await tracking_client.expire(op_inv_key, 7 * 24 * 3600)

    try:
        # Batch alerts using AlertCorrelator if enabled
        if batch and len(alerts) > 1:
            from ares.core.alert_correlation import AlertCorrelator

            correlator = AlertCorrelator()
            for alert in alerts:
                correlator.add_alert(alert)

            clusters = correlator.clusters
            logger.info(f"Batched {len(alerts)} alerts into {len(clusters)} investigation clusters")

            submitted = 0
            for cluster in clusters:
                # Create a batch alert that represents the cluster
                primary_alert = cluster.alerts[0]  # Use first alert as primary
                batch_alert = {
                    **primary_alert,
                    "batch_info": {
                        "is_batch": True,
                        "cluster_id": cluster.cluster_id,
                        "alert_count": len(cluster.alerts),
                        "common_hosts": list(cluster.common_hosts)[:10],
                        "common_users": list(cluster.common_users)[:10],
                        "common_ips": list(cluster.common_ips)[:10],
                        "techniques": list(cluster.techniques),
                        "related_alerts": [
                            {
                                "alertname": a.get("labels", {}).get("alertname", "unknown"),
                                "severity": a.get("labels", {}).get("severity", "unknown"),
                                "fingerprint": a.get("fingerprint", ""),
                            }
                            for a in cluster.alerts[1:]  # Exclude primary
                        ],
                    },
                    "operation_context": {
                        "operation_id": operation_id,
                        "attack_window_start": window_start.isoformat(),
                        "attack_window_end": window_end.isoformat(),
                        "techniques_used": list(playbook.techniques_used)[:20],
                    },
                }

                # Merge labels from all alerts (for better context)
                merged_techniques = set()
                for a in cluster.alerts:
                    labels = a.get("labels", {})
                    if "mitre_technique" in labels:
                        merged_techniques.add(labels["mitre_technique"])
                if merged_techniques:
                    batch_alert.setdefault("labels", {})["merged_techniques"] = list(
                        merged_techniques
                    )

                alert_names = [
                    a.get("labels", {}).get("alertname", "?") for a in cluster.alerts[:5]
                ]
                if len(cluster.alerts) > 5:
                    alert_names.append(f"+{len(cluster.alerts) - 5} more")

                logger.info(
                    f"Submitting cluster {cluster.cluster_id}: "
                    f"{len(cluster.alerts)} alerts [{', '.join(alert_names)}]"
                )

                result = await submit_investigation(
                    alert=batch_alert,
                    model=resolved_model,
                    max_steps=max_steps,
                    multi_agent=True,
                    auto_route=False,
                    grafana_url=grafana_url,
                    grafana_api_key=grafana_api_key,
                    redis_url=redis_url,
                    wait_for_completion=wait,
                    env_vars=env_vars,
                )

                inv_id = result["investigation_id"]
                await track_investigation(inv_id)
                print(
                    f"  Investigation: {inv_id} ({len(cluster.alerts)} alerts, "
                    f"status={result['status']})"
                )
                submitted += 1

            print(f"\nSubmitted {submitted} batched investigations from operation {operation_id}")
            print(f"  (Reduced from {len(alerts)} individual alerts)")
            print(
                f"\nTrack progress with: task blue:multi:operation-status OPERATION_ID={operation_id}"
            )

        else:
            # Submit each alert as a separate investigation (original behavior)
            submitted = 0
            for alert in alerts:
                alert_name = alert.get("labels", {}).get("alertname", "unknown")
                severity = alert.get("labels", {}).get("severity", "unknown")

                # Add operation context to alert
                alert["operation_context"] = {
                    "operation_id": operation_id,
                    "attack_window_start": window_start.isoformat(),
                    "attack_window_end": window_end.isoformat(),
                    "techniques_used": list(playbook.techniques_used)[:20],
                }

                logger.info(f"Submitting: {alert_name} (severity={severity})")

                result = await submit_investigation(
                    alert=alert,
                    model=resolved_model,
                    max_steps=max_steps,
                    multi_agent=True,  # Force multi-agent
                    auto_route=False,  # Already forcing multi-agent
                    grafana_url=grafana_url,
                    grafana_api_key=grafana_api_key,
                    redis_url=redis_url,
                    wait_for_completion=wait,
                    env_vars=env_vars,
                )

                inv_id = result["investigation_id"]
                await track_investigation(inv_id)
                print(f"  Investigation: {inv_id} (status={result['status']})")
                submitted += 1

            print(f"\nSubmitted {submitted} investigations from operation {operation_id}")
            print(
                f"\nTrack progress with: task blue:multi:operation-status OPERATION_ID={operation_id}"
            )

    finally:
        await tracking_client.aclose()


async def _get_latest_investigation_id(redis_url: str) -> str | None:
    """Get the ID of the latest investigation (prefer running)."""
    client = await create_verified_redis_client(redis_url, decode_responses=True)
    try:
        investigations: list[tuple[str, str, str | None]] = []  # (id, status, started_at)

        status_keys = await client.keys("ares:blue:inv:*:status")
        for key in status_keys:
            key_str = key if isinstance(key, str) else key.decode()
            parts = key_str.split(":")
            if len(parts) < 4:
                continue
            inv_id = parts[3]

            status_data = await client.get(key_str)
            if status_data:
                status = json.loads(status_data)
                investigations.append(
                    (
                        inv_id,
                        status.get("status", "unknown"),
                        status.get("started_at"),
                    )
                )

        if not investigations:
            return None

        # Prefer running, then sort by started_at
        running = [i for i in investigations if i[1] == "running"]
        if running:
            return running[0][0]

        investigations.sort(key=lambda x: x[2] or "", reverse=True)
        return investigations[0][0]

    finally:
        await client.aclose()


def main():
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
