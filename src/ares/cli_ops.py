"""CLI for submitting operations to the orchestrator service."""

import asyncio
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import cyclopts
from loguru import logger


# Suppress DEBUG/INFO logs from noisy modules (Redis client, config) in CLI output.
# Keep all logs from cli_ops itself and show WARNING+ from other modules.
def _cli_log_filter(record):
    """Filter out DEBUG/INFO from noisy modules, keep all from cli_ops."""
    module = record["name"]
    level = record["level"].no
    # Allow all logs from this module
    if module in {"ares.cli_ops", "__main__"}:
        return True
    # For other modules, only show WARNING (30) and above
    return level >= 30


logger.remove()
logger.add(sys.stderr, filter=_cli_log_filter)

from ares.core.config import get_redis_url, get_vulnerability_priorities  # noqa: E402
from ares.core.orchestrator_client import (  # noqa: E402
    get_operation_status,
    submit_operation,
    wait_for_operation_completion,
)
from ares.core.redis_client import create_verified_redis_client  # noqa: E402


def _get_vuln_priorities() -> dict[str, int]:
    """Get vulnerability priorities with lowercase aliases for CLI convenience."""
    priorities = get_vulnerability_priorities()
    # Add lowercase aliases for CLI convenience (e.g., "esc1" -> "ADCS_ESC1")
    aliases = {
        "esc1": priorities.get("ADCS_ESC1", 1),
        "esc4": priorities.get("ADCS_ESC4", 2),
        "esc8": priorities.get("ADCS_ESC8", 3),
        "smb_signing_disabled": priorities.get("smb_relay_target", 22),
    }
    return {**priorities, **aliases}


app = cyclopts.App(
    name="ares-ops",
    help="Submit and manage operations with the Ares orchestrator service",
)


async def _generate_local_report(
    operation_id: str,
    redis_url: str,
    report_dir: Path | None = None,
    *,
    force_regenerate: bool = False,
) -> Path | None:
    """Generate a comprehensive report locally from Redis state.

    First checks if a report was already stored by the orchestrator.
    If not (or if force_regenerate=True), generates from state.

    Args:
        operation_id: The operation to generate a report for.
        redis_url: Redis connection URL.
        report_dir: Directory to save the report (default: ./reports).
        force_regenerate: If True, regenerate even if cached report exists.

    Returns:
        Path to the generated report, or None if state not found.
    """
    from ares.core.state_backend import RedisStateBackend
    from ares.reports import generate_comprehensive_report

    # Use verified client to avoid stale reads from demoted masters
    client = await create_verified_redis_client(redis_url, decode_responses=False)
    try:
        # Check for cached report first (stored by orchestrator on completion)
        if not force_regenerate:
            backend = RedisStateBackend(client, operation_id)
            cached_report = await backend.get_report()
            if cached_report:
                resolved_dir = Path(report_dir or "./reports").resolve()
                resolved_dir.mkdir(parents=True, exist_ok=True)
                filename = f"{operation_id}_report.md"
                output_path = resolved_dir / filename
                output_path.write_text(cached_report)
                logger.success(f"Report saved (from cache): {output_path}")
                return output_path

        # Fall back to regenerating from state
        state = await _load_state_from_redis(client, operation_id)
        if not state:
            logger.warning(f"No state found for operation {operation_id}")
            return None

        report_content = generate_comprehensive_report(state)

        resolved_dir = Path(report_dir or "./reports").resolve()
        resolved_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{operation_id}_report.md"
        output_path = resolved_dir / filename
        output_path.write_text(report_content)
        logger.success(f"Report saved: {output_path}")
        return output_path
    finally:
        await client.aclose()


def _persist_report(
    status: dict[str, object],
    *,
    operation_id: str,
    report_dir: Path | None = None,
) -> Path | None:
    """Legacy report persistence from orchestrator result.

    This is a fallback that uses the report_markdown from the orchestrator.
    Prefer using _generate_local_report for comprehensive reports.
    """
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
        ares-ops submit dreadgoad contoso.local --ips 192.168.58.90 192.168.58.129 --wait
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
            env_vars=env_vars or None,
        )

        logger.success(f"Operation submitted: {operation_id}")
        logger.info(f"Status: {result['status']}")

        if wait and result["status"] == "completed":
            logger.success("Operation completed successfully!")
            # Generate comprehensive report from Redis state
            await _generate_local_report(operation_id, resolved_redis_url)
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
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Get the status of an operation.

    Examples:
        ares-ops status multiagent-abc123
        ares-ops status --latest
    """
    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
        logger.info(f"Using latest operation: {operation_id}")
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

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
                # Generate comprehensive report from Redis state
                await _generate_local_report(operation_id, resolved_redis_url)
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
            # Generate comprehensive report from Redis state
            await _generate_local_report(operation_id, resolved_redis_url)
        elif result["status"] == "failed":
            logger.error(f"Operation failed: {result.get('error', 'Unknown error')}")

    except TimeoutError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error waiting for operation: {e}")
        sys.exit(1)


def _dedup_users(users: list) -> list:
    """Deduplicate users by normalized domain+username."""
    seen: set[tuple[str, str]] = set()
    result = []
    for user in users:
        domain = (user.domain or "").strip().lower()
        username = (user.username or "").strip().lower()
        key = (domain, username)
        if key not in seen:
            seen.add(key)
            result.append(user)
    return result


def _dedup_credentials(credentials: list) -> list:
    """Deduplicate credentials by normalized domain+username+password."""
    seen: set[tuple[str, str, str]] = set()
    result = []
    for cred in credentials:
        domain = (cred.domain or "").strip().lower()
        username = (cred.username or "").strip().lower()
        password = cred.password or ""
        key = (domain, username, password)
        if key not in seen:
            seen.add(key)
            result.append(cred)
    return result


def _dedup_hashes(hashes: list) -> list:
    """Deduplicate hashes by normalized domain+username+hash_type+hash_value."""
    seen: set[tuple[str, str, str, str]] = set()
    result = []
    for h in hashes:
        key = (
            (h.domain or "").strip().lower(),
            (h.username or "").strip().lower(),
            (h.hash_type or "").strip().lower(),
            (h.hash_value or "").strip().lower(),
        )
        if key not in seen:
            seen.add(key)
            result.append(h)
    return result


def _normalize_source_label(source: str) -> str:
    """Convert internal source identifiers to human-readable labels.

    Maps task types, tool names, and internal identifiers to clean labels
    for display in loot output.
    """
    if not source:
        return "Unknown"

    # Remove duplicate source patterns (e.g., "Task input (x):Task input (x)")
    if ":" in source:
        parts = source.split(":")
        if len(parts) >= 2 and parts[0] == parts[1]:
            source = parts[0]

    # Strip "Task input (...)" wrapper - extract task type from task ID
    lower = source.lower()
    if "task input" in lower:
        # Extract task type from "Task input (exploit_xxx)" -> "exploit"
        match = re.search(r"\((\w+)_[a-f0-9]+\)", source)
        if match:
            source = match.group(1)
            lower = source.lower()  # Update lower for label lookup

    # Map internal names to human-readable labels
    label_map = {
        # Task types
        "exploit": "Exploitation",
        "recon": "Reconnaissance",
        "lateral": "Lateral Movement",
        "privesc": "Privilege Escalation",
        "privesc_enumeration": "Privesc Enumeration",
        "credential_access": "Credential Access",
        "acl_analysis": "ACL Analysis",
        "crack": "Password Cracking",
        # Tool-based sources
        "netexec_user_enum": "NetExec User Enum",
        "netexec_smb": "NetExec SMB",
        "bloodhound": "BloodHound",
        "kerberoast": "Kerberoasting",
        "asreproast": "AS-REP Roasting",
        "secretsdump": "Secretsdump",  # pragma: allowlist secret
        "lsassy": "LSASSY",
        "share_spider": "Share Spider",
        "gpp_password": "GPP Passwords",  # nosec B105 # pragma: allowlist secret
        "ldap_search": "LDAP Search",
        "kerberos_noauth": "Kerberos Enum",
        "user_description": "LDAP Description",
        "manual-inject": "Manual Injection",
        # Generic fallbacks
        "worker": "Agent Discovery",
        "task": "Task Output",
        "unknown": "Unknown",
    }

    # Check for exact match first
    if lower in label_map:
        return label_map[lower]

    # Check for prefix matches (e.g., "recon_task" -> "Reconnaissance")
    for key, label in label_map.items():
        if lower.startswith(key):
            return label

    # Check for task ID patterns (e.g., "exploit_abc123" -> "Exploitation")
    task_match = re.match(r"^(\w+)_[a-f0-9]{8,}$", lower)
    if task_match:
        task_type = task_match.group(1)
        if task_type in label_map:
            return label_map[task_type]

    # Return original with title case if no mapping found
    return source.replace("_", " ").title()


def _parse_weakness_block(block: str) -> dict[str, str]:
    """Parse a markdown weakness block into structured fields.

    Weakness blocks have this format:
        ### Title Here
        **Vulnerability:** Description
        - **Affected Resource:** resource
        - **Discovery Method:** method
        - **Impact:** impact text

    Returns:
        Dictionary with keys: title, vulnerability, affected_resource,
        discovery_method, impact, attack_path
    """
    result: dict[str, str] = {}

    if not block:
        return result

    lines = block.strip().split("\n")

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue

        # Parse title (### Title or **Title**)
        if stripped.startswith("### "):
            result["title"] = stripped[4:].strip()
        elif stripped.startswith("**") and ":**" not in stripped and stripped.endswith("**"):
            # Bold title without colon (e.g., **Domain Admin Achieved**)
            result["title"] = stripped.strip("*").strip()

        # Parse **Key:** Value patterns (e.g., "**Vulnerability:** text" or "- **Impact:** text")
        # Note: The colon is inside the bold markers: **Key:**
        elif ":**" in stripped:
            # Handle both "**Key:** Value" and "- **Key:** Value"
            clean = stripped.lstrip("-").strip()
            # Match **Key:** patterns where colon is inside the bold
            match = re.match(r"\*\*([^*:]+):\*\*\s*(.*)$", clean)
            if match:
                key = match.group(1).strip().lower().replace(" ", "_")
                value = match.group(2).strip()
                result[key] = value

    return result


def _loot_snapshot(state) -> dict:
    """Build a snapshot dict of all loot for diffing."""
    return {
        "domains": frozenset(d.strip().lower() for d in getattr(state, "all_domains", []) if d),
        "host_keys": frozenset((h.hostname, h.ip) for h in state.all_hosts),
        "user_keys": frozenset(
            (u.domain.strip().lower(), u.username.strip().lower()) for u in state.all_users
        ),
        "cred_keys": frozenset(
            (c.domain.strip().lower(), c.username.strip().lower(), c.password)
            for c in state.all_credentials
        ),
        "hash_keys": frozenset(
            (
                h.domain.strip().lower(),
                h.username.strip().lower(),
                h.hash_type.strip().lower(),
                h.hash_value.strip().lower(),
            )
            for h in state.all_hashes
        ),
        "share_keys": frozenset((s.host, s.name) for s in state.all_shares),
        "weaknesses": frozenset(state.all_weaknesses),
    }


_WEAKNESS_NOISE_PREFIXES = (
    "next step:",
    "next action:",
    "next task",
    "task suggestion:",
    "recommendation:",
    "todo:",
    "to do:",
    "action item:",
)


def _filter_real_weaknesses(weaknesses: list[str]) -> list[tuple[str, dict]]:
    """Filter out agent task suggestions incorrectly recorded as weaknesses."""
    real = []
    for w in weaknesses:
        parsed = _parse_weakness_block(w)
        title = parsed.get("title", "").lower().strip()
        if not any(title.startswith(prefix) for prefix in _WEAKNESS_NOISE_PREFIXES):
            real.append((w, parsed))
    return real


def _print_loot(state, *, json_output: bool = False) -> None:
    """Print loot from state in human-readable or JSON format."""
    import json as json_module

    unique_users = _dedup_users(state.all_users)
    unique_creds = _dedup_credentials(state.all_credentials)
    unique_hashes = _dedup_hashes(state.all_hashes)
    real_weaknesses = _filter_real_weaknesses(list(state.all_weaknesses))

    if json_output:
        output = {
            "operation_id": state.operation_id,
            "has_domain_admin": state.has_domain_admin,
            "domain_admin_path": state.domain_admin_path,
            "has_golden_ticket": state.has_golden_ticket,
            "domains": list(getattr(state, "all_domains", [])),
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os": h.os,
                    "is_dc": h.is_dc,
                    "services": h.services,
                }
                for h in state.all_hosts
            ],
            "users": [
                {
                    "username": u.username,
                    "domain": u.domain,
                    "is_admin": u.is_admin,
                    "source": u.source if hasattr(u, "source") else "",
                }
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
            "weaknesses": [w for w, _ in real_weaknesses],
        }
        print(json_module.dumps(output, indent=2, default=str))
        return

    # Human-readable output
    print(f"Operation: {state.operation_id}")
    if state.has_domain_admin:
        print("*** DOMAIN ADMIN ACHIEVED ***")
        if state.domain_admin_path:
            print(f"  Path: {state.domain_admin_path}")
    if state.has_golden_ticket:
        print("*** GOLDEN TICKET OBTAINED ***")
    print()

    # Domains (with hierarchy indicator)
    domains = sorted({d.strip().lower() for d in getattr(state, "all_domains", []) if d})
    # Classify domains as forest roots vs child domains
    forest_roots: list[str] = []
    child_domains: dict[str, str] = {}  # child -> parent
    for domain in domains:
        parts = domain.split(".")
        if len(parts) >= 3:
            # Check if parent domain exists in our list
            parent = ".".join(parts[1:])
            if parent in domains:
                child_domains[domain] = parent
            else:
                forest_roots.append(domain)
        else:
            # Two-part domains (e.g., contoso.local) are forest roots
            forest_roots.append(domain)

    print(f"Domains ({len(domains)}):")
    if not domains:
        print("  - None")
    else:
        # Display forest roots first, then their children indented
        displayed: set[str] = set()
        for root in sorted(forest_roots):
            print(f"  - {root} (forest root)")
            displayed.add(root)
            # Find and display child domains of this root
            for child, parent in sorted(child_domains.items()):
                if parent == root:
                    print(f"    └─ {child} (child)")
                    displayed.add(child)
        # Display any remaining child domains (whose parent isn't a direct forest root)
        for child in sorted(child_domains.keys()):
            if child not in displayed:
                parent = child_domains[child]
                print(f"  - {child} (child of {parent})")
    print()

    # Hosts (with DC indicator, OS, and open ports/services)
    dcs = [h for h in state.all_hosts if h.is_dc]
    print(f"Hosts ({len(state.all_hosts)}, {len(dcs)} DCs):")
    for host in state.all_hosts:
        parts = [p for p in [host.hostname, host.ip] if p]
        line = " / ".join(parts) if parts else "(unknown)"
        if host.os:
            line = f"{line} [{host.os}]"
        if host.is_dc:
            line = f"{line} [DC]"
        print(f"  - {line}")
        if host.services:
            for svc in sorted(host.services):
                print(f"      {svc}")
    print()

    # Users - group by source for readability
    print(f"Users ({len(unique_users)}):")
    users_by_source: dict[str, list] = {}
    for user in unique_users:
        src = user.source if hasattr(user, "source") and user.source else "unknown"
        src = _normalize_source_label(src)
        users_by_source.setdefault(src, []).append(user)
    for src, users in sorted(users_by_source.items()):
        print(f"  [{src}] ({len(users)})")
        for user in users:
            prefix = f"{user.domain}\\{user.username}" if user.domain else user.username
            suffix = " (admin)" if user.is_admin else ""
            print(f"    - {prefix}{suffix}")
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

    # Weaknesses - use pre-filtered list (noise already removed at top of function)
    print(f"Weaknesses ({len(real_weaknesses)}):")
    if not real_weaknesses:
        print("  None")
    else:
        for i, (_w, parsed) in enumerate(real_weaknesses, 1):
            title = parsed.get("title", "Untitled Weakness")
            vuln = parsed.get("vulnerability", "")
            impact = parsed.get("impact", "")
            resource = parsed.get("affected_resource", "")

            # Print compact summary
            print(f"  {i}. {title}")
            if vuln:
                # Truncate long vulnerability descriptions
                vuln_display = vuln[:80] + "..." if len(vuln) > 80 else vuln
                print(f"     └─ {vuln_display}")
            if resource:
                print(f"     Resource: {resource}")
            if impact:
                impact_display = impact[:60] + "..." if len(impact) > 60 else impact
                print(f"     Impact: {impact_display}")


def _print_diff(prev_snapshot: dict, curr_snapshot: dict, state) -> None:
    """Print only new items since the last snapshot."""
    new_domains = curr_snapshot["domains"] - prev_snapshot["domains"]
    new_hosts = curr_snapshot["host_keys"] - prev_snapshot["host_keys"]
    new_users = curr_snapshot["user_keys"] - prev_snapshot["user_keys"]
    new_creds = curr_snapshot["cred_keys"] - prev_snapshot["cred_keys"]
    new_hashes = curr_snapshot["hash_keys"] - prev_snapshot["hash_keys"]
    new_shares = curr_snapshot["share_keys"] - prev_snapshot["share_keys"]
    new_weaknesses = curr_snapshot["weaknesses"] - prev_snapshot["weaknesses"]

    total_new = (
        len(new_domains)
        + len(new_hosts)
        + len(new_users)
        + len(new_creds)
        + len(new_hashes)
        + len(new_shares)
        + len(new_weaknesses)
    )

    if total_new == 0:
        return

    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"\n--- New loot at {ts} ({total_new} items) ---")

    if new_domains:
        for d in sorted(new_domains):
            print(f"  [domain] {d}")

    if new_hosts:
        host_map = {(h.hostname, h.ip): h for h in state.all_hosts}
        for key in new_hosts:
            h = host_map.get(key)
            if h:
                parts = [p for p in [h.hostname, h.ip] if p]
                line = " / ".join(parts)
                if h.is_dc:
                    line += " [DC]"
                print(f"  [host] {line}")

    if new_users:
        for domain, username in sorted(new_users):
            prefix = f"{domain}\\{username}" if domain else username
            print(f"  [user] {prefix}")

    if new_creds:
        for domain, username, password in sorted(new_creds):
            prefix = f"{domain}\\{username}" if domain else username
            print(f"  [cred] {prefix}:{password}")

    if new_hashes:
        for domain, username, hash_type, hash_value in sorted(new_hashes):
            prefix = f"{domain}\\{username}" if domain else username
            print(f"  [hash] {prefix}:{hash_type}:{hash_value}")

    if new_shares:
        for host, name in sorted(new_shares):
            print(f"  [share] {host}/{name}")

    if new_weaknesses:
        for w in sorted(new_weaknesses):
            print(f"  [weakness] {w}")

    sys.stdout.flush()


async def _resolve_latest_operation(redis_url: str) -> str | None:
    """Resolve the latest operation ID (preferring running operations)."""
    from ares.core.task_queue import RedisTaskQueue

    # Use verified client to avoid stale reads from demoted masters
    client = await create_verified_redis_client(redis_url, decode_responses=True)

    all_ops: list[tuple[datetime | None, str, bool]] = []

    # Check for running operations (have locks)
    running_ops: set[str] = set()
    lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
    for key in lock_keys:
        parts = key.split(":", 2)
        if len(parts) >= 3:
            running_ops.add(parts[2])

    # Track seen operation IDs to avoid duplicates
    seen_ops: set[str] = set()

    # Get operations with redis-native state format (ares:op:*:meta)
    meta_keys = await client.keys("ares:op:*:meta")
    for key in meta_keys:
        parts = key.split(":")
        if len(parts) < 3:
            continue
        op_id = parts[2]
        if op_id in seen_ops:
            continue
        seen_ops.add(op_id)
        # Try to get started_at from meta or checkpoint_time
        checkpoint_time = None
        meta_data = await client.hgetall(f"ares:op:{op_id}:meta")
        if meta_data:
            started_raw = meta_data.get("started_at")
            if started_raw:
                try:
                    checkpoint_time = datetime.fromisoformat(started_raw)
                except Exception:
                    pass
        is_running = op_id in running_ops
        all_ops.append((checkpoint_time, op_id, is_running))

    await client.aclose()

    if not all_ops:
        return None

    def pick_latest(items: list[tuple[datetime | None, str]]) -> str:
        with_time = [(t, op) for t, op in items if t is not None]
        if with_time:
            with_time.sort(key=lambda x: x[0], reverse=True)  # type: ignore[arg-type]
            return with_time[0][1]
        # Sort by operation ID descending (IDs contain timestamps: op-YYYYMMDD-HHMMSS)
        items.sort(key=lambda x: x[1], reverse=True)
        return items[0][1]

    # Prefer running operations, then fall back to latest by checkpoint time
    running = [(t, op) for t, op, is_running in all_ops if is_running]
    if running:
        return pick_latest(running)
    return pick_latest([(t, op) for t, op, _ in all_ops])


@app.command
async def loot(
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    json_output: Annotated[bool, cyclopts.Parameter(help="Output as JSON")] = False,
    watch: Annotated[
        int, cyclopts.Parameter(help="Watch mode: refresh every N seconds (0=off)")
    ] = 0,
    diff: Annotated[
        bool,
        cyclopts.Parameter(help="Diff mode: only print new items each refresh (implies --watch)"),
    ] = False,
) -> None:
    """Dump users, credentials, hosts, and hashes from operation state.

    Examples:
        ares-ops loot op-20250128-123456
        ares-ops loot --latest
        ares-ops loot --latest --watch 10
        ares-ops loot op-20250128-123456 --diff --watch 5
    """

    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
        logger.info(f"Using latest operation: {operation_id}")
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    # --diff implies --watch with a default interval
    if diff and watch == 0:
        watch = 10

    try:
        if watch > 0:
            await _loot_watch(operation_id, resolved_redis_url, watch, diff, json_output)
        else:
            await _loot_once(operation_id, resolved_redis_url, json_output)
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        logger.error(f"Failed to dump loot: {e}")
        sys.exit(1)


async def _load_state_from_redis(client: Any, operation_id: str) -> Any:
    """Load SharedRedTeamState from Redis using redis-native format.

    Args:
        client: Redis client (decode_responses=False)
        operation_id: Operation ID

    Returns:
        SharedRedTeamState or None if not found
    """
    from ares.core.models import SharedRedTeamState, Target
    from ares.core.state_backend import RedisStateBackend

    # Check if operation exists by looking for meta key
    meta_exists = await client.exists(f"ares:op:{operation_id}:meta")
    if not meta_exists:
        return None

    # Create backend and load state
    backend = RedisStateBackend(client, operation_id)

    # Load all collections
    credentials = await backend.get_credentials()
    hashes = await backend.get_hashes()
    hosts = await backend.get_hosts()
    users = await backend.get_users()
    domains = await backend.get_domains()
    shares = await backend.get_shares()
    weaknesses = await backend.get_weaknesses()
    vulnerabilities = await backend.get_vulnerabilities()
    exploited_vulns = await backend.get_exploited_vulnerabilities()

    # Load meta
    meta = await backend.get_all_meta()
    has_domain_admin = meta.get("has_domain_admin", False)
    has_golden_ticket = meta.get("has_golden_ticket", False)
    domain_admin_path = meta.get("domain_admin_path")
    started_at_str = meta.get("started_at")
    started_at = None
    if started_at_str:
        try:
            started_at = datetime.fromisoformat(started_at_str)
        except Exception:
            pass

    completed_at_str = meta.get("completed_at")
    completed_at = None
    if completed_at_str:
        try:
            completed_at = datetime.fromisoformat(completed_at_str)
        except Exception:
            pass

    # Load target from meta if present
    target = None
    target_ip = meta.get("target_ip")
    target_domain = meta.get("target_domain")
    if target_ip:
        target = Target(ip=target_ip, domain=target_domain)

    # Load DC map and NetBIOS map
    dc_map = await backend.get_all_dcs()
    netbios_map = await backend.get_all_netbios_mappings()

    # Create state object with correct field names
    kwargs: dict = {
        "operation_id": operation_id,
        "target": target,
        "all_credentials": credentials,
        "all_hashes": hashes,
        "all_hosts": hosts,
        "all_users": users,
        "all_shares": shares,
        "all_domains": list(domains),
        "all_weaknesses": weaknesses,
        "discovered_vulnerabilities": vulnerabilities,
        "exploited_vulnerabilities": exploited_vulns,
        "has_domain_admin": has_domain_admin,
        "has_golden_ticket": has_golden_ticket,
        "domain_admin_path": domain_admin_path,
        "domain_controllers": dc_map,
        "netbios_to_fqdn": netbios_map,
    }
    if started_at is not None:
        kwargs["started_at"] = started_at
    if completed_at is not None:
        kwargs["completed_at"] = completed_at
    return SharedRedTeamState(**kwargs)


async def _loot_once(operation_id: str, redis_url: str, json_output: bool) -> None:
    """Single-shot loot dump."""
    # Use verified client to avoid stale reads from demoted masters
    client = await create_verified_redis_client(redis_url, decode_responses=False)
    state = await _load_state_from_redis(client, operation_id)
    await client.aclose()

    if not state:
        logger.error(f"No state found for operation: {operation_id}")
        sys.exit(1)

    _print_loot(state, json_output=json_output)


async def _loot_watch(
    operation_id: str,
    redis_url: str,
    interval: int,
    diff_mode: bool,
    json_output: bool,
) -> None:
    """Watch mode: continuously poll Redis and display loot."""
    prev_snapshot: dict | None = None
    # Use verified client to avoid stale reads from demoted masters
    client = await create_verified_redis_client(redis_url, decode_responses=False)

    try:
        while True:
            try:
                state = await _load_state_from_redis(client, operation_id)
            except Exception as e:
                logger.warning(f"Redis fetch failed, reconnecting in {interval}s: {e}")
                try:
                    await client.aclose()
                except Exception:
                    pass
                await asyncio.sleep(interval)
                client = await create_verified_redis_client(redis_url, decode_responses=False)
                continue

            if not state:
                logger.warning(f"No state found for {operation_id}, retrying in {interval}s...")
                sys.stdout.flush()
                await asyncio.sleep(interval)
                continue
            curr_snapshot = _loot_snapshot(state)

            if diff_mode:
                if prev_snapshot is None:
                    # First run: print full output then switch to diff
                    _print_loot(state, json_output=json_output)
                else:
                    _print_diff(prev_snapshot, curr_snapshot, state)
            else:
                # Full refresh mode: print separator between refreshes
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                if prev_snapshot is not None:
                    print(f"\n{'=' * 60}")
                print(f"[watch] Refreshing every {interval}s  |  {ts}")
                print(f"{'=' * 60}")
                _print_loot(state, json_output=json_output)

            sys.stdout.flush()
            prev_snapshot = curr_snapshot
            await asyncio.sleep(interval)
    finally:
        await client.aclose()


@app.command
async def report(
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    regenerate: Annotated[
        bool, cyclopts.Parameter(help="Regenerate report from state (ignore cached)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    output_dir: Annotated[
        str, cyclopts.Parameter(help="Output directory for report (default: ./reports)")
    ] = "./reports",
) -> None:
    """Generate a comprehensive markdown report for an operation.

    The report includes full attack path, all credentials with passwords,
    NTLM hashes, discovered vulnerabilities, and timeline events.

    By default, uses the cached report stored by the orchestrator on completion.
    Use --regenerate to rebuild the report from current state.

    Examples:
        ares-ops report op-20250128-123456
        ares-ops report --latest
        ares-ops report --latest --regenerate
        ares-ops report --latest --output-dir ./my-reports
    """
    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
        logger.info(f"Using latest operation: {operation_id}")
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    try:
        report_path = await _generate_local_report(
            operation_id,
            resolved_redis_url,
            report_dir=Path(output_dir),
            force_regenerate=regenerate,
        )
        if report_path:
            logger.success(f"Report generated: {report_path}")
        else:
            logger.error(f"Failed to generate report for {operation_id}")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        sys.exit(1)


@app.command(name="export-detection")
async def export_detection(
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    output_dir: Annotated[
        str, cyclopts.Parameter(help="Output directory (default: ./reports)")
    ] = "./reports",
    json_output: Annotated[
        bool, cyclopts.Parameter(help="Output JSON to stdout instead of files")
    ] = False,
    markdown: Annotated[bool, cyclopts.Parameter(help="Also generate markdown report")] = True,
) -> None:
    """Export detection playbook for blue team from red team operation.

    Generates actionable detection guidance including:
    - Specific LogQL queries with IOCs filled in
    - MITRE technique-specific detection guidance
    - Priority-ordered detection queries
    - Time windows for attack activity

    This export is designed for blue team agents and security engineers
    to build detections based on what the red team actually did.

    Examples:
        ares-ops export-detection op-20250128-123456
        ares-ops export-detection --latest
        ares-ops export-detection --latest --json
        ares-ops export-detection --latest --output-dir ./detections
    """
    import json as json_module

    from ares.eval.detection_playbook import create_detection_playbook

    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
        logger.info(f"Using latest operation: {operation_id}")
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    try:
        # Use verified client to avoid stale reads from demoted masters
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)
        state = await _load_state_from_redis(client, operation_id)
        await client.aclose()

        if not state:
            logger.error(f"No state found for operation: {operation_id}")
            sys.exit(1)

        # Generate the detection playbook
        playbook = create_detection_playbook(state)

        if json_output:
            # Output JSON to stdout
            print(json_module.dumps(playbook.to_dict(), indent=2, default=str))
        else:
            # Write to files
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Write JSON
            json_path = output_path / f"{operation_id}_detection_playbook.json"
            json_content = json_module.dumps(playbook.to_dict(), indent=2, default=str)
            json_path.write_text(json_content)
            logger.success(f"Detection playbook JSON: {json_path}")

            # Write markdown if requested
            if markdown:
                md_path = output_path / f"{operation_id}_detection_playbook.md"
                md_path.write_text(playbook.to_markdown())
                logger.success(f"Detection playbook markdown: {md_path}")

            # Print summary
            print(f"\nDetection Playbook Summary for {operation_id}")
            print("=" * 60)
            print(
                f"Attack Window: {playbook.attack_window_start.strftime('%Y-%m-%d %H:%M')} to {playbook.attack_window_end.strftime('%Y-%m-%d %H:%M')}"
            )
            print(f"Techniques Used: {len(playbook.techniques_used)}")
            print(f"Priority Queries: {len(playbook.priority_queries)}")
            print(f"Detection Targets: {len(playbook.detection_targets)}")
            print(f"Domain Admin Achieved: {'Yes' if playbook.achieved_domain_admin else 'No'}")

            if playbook.priority_queries:
                print("\nTop Priority Queries:")
                for i, q in enumerate(playbook.priority_queries[:5], 1):
                    print(
                        f"  {i}. [{q.priority.upper()}] {q.technique_id}: {q.description[:50]}..."
                    )

    except Exception as e:
        logger.error(f"Failed to export detection playbook: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


@app.command
async def tasks(
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    task_status: Annotated[
        str, cyclopts.Parameter(help="Filter by status (running/completed/failed/pending/all)")
    ] = "running",
    role: Annotated[str | None, cyclopts.Parameter(help="Filter by role")] = None,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """List tasks for an operation.

    Examples:
        ares-ops tasks op-20250128-123456 --task-status running --role lateral
        ares-ops tasks --latest --task-status running
    """
    import json as json_module

    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
        logger.info(f"Using latest operation: {operation_id}")
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    try:
        # Use verified client to avoid stale reads from demoted masters
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=True)
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


def _format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 0:
        return "0s"
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


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
        # Sort by operation ID descending (IDs contain timestamps: op-YYYYMMDD-HHMMSS)
        items.sort(key=lambda x: x[1], reverse=True)
        return items[0][1]

    try:
        # Use decode_responses=False so we can read both state (bytes) and strings
        # Use verified client to avoid stale reads from demoted masters
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)
        await client.ping()

        # Gather all operations with their checkpoint times, running status, and start time
        # (checkpoint_time, op_id, is_running, started_at)
        all_ops: list[tuple[datetime | None, str, bool, datetime | None]] = []

        # Check for running operations (have locks)
        # Use KEYS instead of SCAN for reliability - SCAN can miss keys
        running_ops: set[str] = set()
        lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
        for key in lock_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            parts = key_str.split(":", 2)
            if len(parts) >= 3:
                running_ops.add(parts[2])

        # Track seen operation IDs to avoid duplicates
        seen_ops: set[str] = set()

        # Get operations from redis-native state format (ares:op:*:meta)
        meta_keys = await client.keys("ares:op:*:meta")
        for key in meta_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            parts = key_str.split(":")
            if len(parts) < 3:
                continue
            op_id = parts[2]
            if op_id in seen_ops:
                continue
            seen_ops.add(op_id)

            # For redis-native format, get started_at from meta hash
            started_at = None
            checkpoint_time = None
            meta_data = await client.hgetall(f"ares:op:{op_id}:meta")
            if meta_data:
                started_raw = meta_data.get(b"started_at") or meta_data.get("started_at")
                if started_raw:
                    started_str = (
                        started_raw.decode() if isinstance(started_raw, bytes) else started_raw
                    )
                    try:
                        started_at = datetime.fromisoformat(started_str)
                        # Use started_at as checkpoint_time if no explicit checkpoint
                        checkpoint_time = started_at
                    except Exception:
                        pass

            is_running = op_id in running_ops
            all_ops.append((checkpoint_time, op_id, is_running, started_at))

        await client.aclose()

        if not all_ops:
            print("No operations found")
            return

        if latest:
            # Prefer running operations, then fall back to latest by checkpoint time
            running = [(t, op) for t, op, is_running, _ in all_ops if is_running]
            if running:
                print(pick_latest(running))
            else:
                print(pick_latest([(t, op) for t, op, _, _ in all_ops]))
            return

        # Full listing
        print("Multi-Agent Operations:")
        print("=" * 70)
        # Sort by checkpoint time (newest first)
        all_ops.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        now = datetime.now(timezone.utc)
        for checkpoint_time, op_id, is_running, started_at in all_ops:
            status = " [running]" if is_running else ""

            # Calculate runtime
            runtime_str = ""
            if started_at:
                # For running ops, runtime is until now; for completed, until checkpoint
                end_time = now if is_running else (checkpoint_time or now)
                runtime_seconds = (end_time - started_at).total_seconds()
                runtime_str = f" runtime: {_format_duration(runtime_seconds)}"

            time_str = checkpoint_time.isoformat() if checkpoint_time else "unknown"
            print(f"  {op_id}: checkpoint at {time_str}{status}{runtime_str}")

    except Exception as e:
        logger.error(f"Failed to list operations: {e}")
        sys.exit(1)


@app.command
async def runtime(
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Show runtime for an operation.

    Displays the elapsed time since the operation started, plus key metrics.

    Examples:
        ares-ops runtime --latest
        ares-ops runtime op-20250128-123456
    """
    from ares.core.task_queue import RedisTaskQueue

    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    try:
        # Use verified client to avoid stale reads from demoted masters
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)

        # Get state using redis-native format
        state = await _load_state_from_redis(client, operation_id)
        if not state:
            logger.error(f"No state found for operation: {operation_id}")
            await client.aclose()
            sys.exit(1)

        # Check if running
        lock_key = f"{RedisTaskQueue.LOCK_PREFIX}:{operation_id}"
        is_running = await client.exists(lock_key) > 0

        await client.aclose()

        now = datetime.now(timezone.utc)
        started_at = state.started_at
        completed_at = state.completed_at

        # Calculate runtime
        if completed_at:
            runtime_seconds = (completed_at - started_at).total_seconds()
            status = "completed"
        elif is_running:
            runtime_seconds = (now - started_at).total_seconds()
            status = "running"
        else:
            # Not running, no completed_at - use now as fallback
            runtime_seconds = (now - started_at).total_seconds()
            status = "stopped"

        # Output
        print(f"Operation: {operation_id}")
        print(f"Status:    {status}")
        print(f"Started:   {started_at.isoformat()}")
        print(f"Runtime:   {_format_duration(runtime_seconds)}")
        print()

        # Key metrics
        creds = len(state.all_credentials)
        hashes = len(state.all_hashes)
        hosts = len(state.all_hosts)
        vulns = len(state.discovered_vulnerabilities)
        exploited = len(state.exploited_vulnerabilities)

        print(f"Credentials: {creds}  Hashes: {hashes}  Hosts: {hosts}")
        print(f"Vulns: {vulns} discovered, {exploited} exploited")

        if state.has_domain_admin:
            print("\n*** DOMAIN ADMIN ACHIEVED ***")
        if state.has_golden_ticket:
            print("*** GOLDEN TICKET OBTAINED ***")

    except Exception as e:
        logger.error(f"Failed to get runtime: {e}")
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

    from ares.core.task_queue import RedisTaskQueue

    resolved_redis_url = redis_url or get_redis_url()

    try:
        # Use verified client to avoid stale reads from demoted masters
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)
        await client.ping()

        operations = []
        # Use KEYS instead of SCAN for reliability - SCAN can miss keys
        # Scan redis-native format (ares:op:*:meta)
        meta_keys = await client.keys("ares:op:*:meta")
        for key in meta_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            parts = key_str.split(":")
            if len(parts) < 3:
                continue
            op_id = parts[2]

            state = await _load_state_from_redis(client, op_id)
            if not state:
                continue

            # Get started_at from meta hash as checkpoint reference
            meta_data = await client.hgetall(f"ares:op:{op_id}:meta")
            checkpoint_time = meta_data.get("started_at", "unknown") if meta_data else "unknown"
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
async def delete(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID to delete")],
    *,
    force: Annotated[bool, cyclopts.Parameter(help="Skip confirmation prompt")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Delete an operation and all its associated data from Redis.

    Example:
        ares-ops delete op-20250128-123456
        ares-ops delete op-20250128-123456 --force
    """
    resolved_redis_url = redis_url or get_redis_url()

    try:
        # Use verified client to ensure we're deleting from master
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=True)

        # Check if operation exists (redis-native format)
        meta_key = f"ares:op:{operation_id}:meta"
        exists = await client.exists(meta_key)

        if not exists:
            logger.warning(f"Operation {operation_id} not found")
            await client.aclose()
            return

        if not force:
            confirm = await asyncio.to_thread(input, f"Delete operation {operation_id}? [y/N]: ")
            if confirm.lower() != "y":
                print("Cancelled")
                await client.aclose()
                return

        # Find all keys to delete (redis-native format)
        keys_to_delete: list[str] = []

        # Scan for all redis-native keys: ares:op:{op_id}:*
        native_keys = await client.keys(f"ares:op:{operation_id}:*")
        keys_to_delete.extend(native_keys)

        # Also clean up lock and active pointer if they reference this operation
        keys_to_delete.append(f"ares:lock:{operation_id}")
        active_op = await client.get("ares:op:active")
        if active_op == operation_id:
            keys_to_delete.append("ares:op:active")

        # Find task status keys for this operation
        import json as json_module

        task_keys = await client.keys("ares:task_status:*")
        for key in task_keys:
            raw = await client.get(key)
            if raw:
                try:
                    data = json_module.loads(raw)
                    if data.get("operation_id") == operation_id:
                        keys_to_delete.append(key)
                except (json_module.JSONDecodeError, ValueError):
                    pass

        # Delete all keys
        deleted_count = 0
        for key in keys_to_delete:
            result = await client.delete(key)
            deleted_count += result

        await client.aclose()

        logger.success(f"Deleted operation {operation_id} ({deleted_count} keys removed)")

    except Exception as e:
        logger.error(f"Failed to delete operation: {e}")
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
    from ares.core.state_backend import RedisStateBackend

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
        # Use verified client to ensure we're reading/writing to master
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)
        state = await _load_state_from_redis(client, operation_id)

        if not state:
            logger.error(f"No state found for operation: {operation_id}")
            await client.aclose()
            sys.exit(1)

        domains = extract_domains(state)

        if not domains:
            print("No domains inferred from current state.")
            await client.aclose()
            return

        before = set(getattr(state, "all_domains", []))
        added = []
        backend = RedisStateBackend(client, operation_id)
        for domain in domains:
            if domain not in before:
                # Add to in-memory state and persist via backend
                state.all_domains.append(domain)
                await backend.add_domain(domain)
                added.append(domain)

        await client.aclose()

        if added:
            # Notify subscribers so orchestrator/workers pick it up instantly
            from ares.core.task_queue import RedisTaskQueue

            tq = RedisTaskQueue(resolved_redis_url)
            await tq.connect()
            n = await tq.publish_state_update(operation_id)
            await tq.disconnect()
            print(
                f"Backfilled domains ({len(added)}): {', '.join(added)} ({n} subscribers notified)"
            )
        else:
            print("Backfilled domains (0): None")

    except Exception as e:
        logger.error(f"Failed to backfill domains: {e}")
        sys.exit(1)


@app.command
async def inject_credential(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    username: Annotated[str, cyclopts.Parameter(help="Username to inject")],
    password: Annotated[str, cyclopts.Parameter(help="Password for the credential")],
    *,
    domain: Annotated[str, cyclopts.Parameter(help="Domain for the credential")] = "",
    source: Annotated[str, cyclopts.Parameter(help="Source of the credential")] = "manual-inject",
    is_admin: Annotated[bool, cyclopts.Parameter(help="Mark credential as admin")] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Inject a credential into an operation's shared state.

    Example:
        ares-ops inject-credential op-20250128-123456 svc_sql Password123 --domain corp.contoso.local
    """
    from ares.core.models import Credential
    from ares.core.state_backend import RedisStateBackend

    resolved_redis_url = redis_url or get_redis_url()

    try:
        # Use verified client to ensure we're reading/writing to master
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)
        state = await _load_state_from_redis(client, operation_id)

        if not state:
            logger.error(f"No state found for operation: {operation_id}")
            await client.aclose()
            sys.exit(1)

        # Create and add the credential to in-memory state
        cred = Credential(
            username=username,
            password=password,
            domain=domain,
            source=source,
            is_admin=is_admin,
        )

        added = state.add_credential(cred, source_agent=source)

        if added:
            # Persist to Redis via backend
            backend = RedisStateBackend(client, operation_id)
            await backend.add_credential(cred)
            await client.aclose()

            # Notify subscribers so orchestrator/workers pick it up instantly
            from ares.core.task_queue import RedisTaskQueue

            tq = RedisTaskQueue(resolved_redis_url)
            await tq.connect()
            n = await tq.publish_state_update(operation_id)
            await tq.disconnect()
            logger.success(
                f"Injected credential: {domain}\\{username}:{password} ({n} subscribers notified)"
            )
        else:
            await client.aclose()
            logger.info(f"Credential already exists: {domain}\\{username}")

    except Exception as e:
        logger.error(f"Failed to inject credential: {e}")
        sys.exit(1)


@app.command
async def inject_vulnerability(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    vuln_type: Annotated[
        str, cyclopts.Parameter(help="Vulnerability type (e.g., constrained_delegation)")
    ],
    target_ip: Annotated[str, cyclopts.Parameter(help="Target IP address")],
    *,
    target_hostname: Annotated[str, cyclopts.Parameter(help="Target hostname")] = "",
    target_spn: Annotated[str, cyclopts.Parameter(help="Target SPN for delegation attacks")] = "",
    account_name: Annotated[str, cyclopts.Parameter(help="Account name (for delegation)")] = "",
    domain: Annotated[str, cyclopts.Parameter(help="Domain")] = "",
    details: Annotated[str, cyclopts.Parameter(help="Additional details (JSON string)")] = "{}",
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
) -> None:
    """Inject a vulnerability into an operation's shared state.

    Example:
        ares-ops inject-vulnerability op-xxx constrained_delegation 192.168.58.240 \\
            --target-hostname srv01.corp.contoso.local \\
            --target-spn "cifs/srv01.corp.contoso.local" \\
            --account-name svc_sql \\
            --domain corp.contoso.local
    """
    import json as json_module

    from ares.core.models import VulnerabilityInfo
    from ares.core.state_backend import RedisStateBackend

    resolved_redis_url = redis_url or get_redis_url()

    try:
        # Use verified client to ensure we're reading/writing to master
        client = await create_verified_redis_client(resolved_redis_url, decode_responses=False)
        state = await _load_state_from_redis(client, operation_id)

        if not state:
            logger.error(f"No state found for operation: {operation_id}")
            await client.aclose()
            sys.exit(1)

        # Parse additional details
        try:
            extra_details = json_module.loads(details) if details else {}
        except json_module.JSONDecodeError:
            extra_details = {}

        # Build vulnerability details
        vuln_details = {
            "target_ip": target_ip,
            "target_hostname": target_hostname,
            "domain": domain,
            **extra_details,
        }

        if target_spn:
            vuln_details["target_spn"] = target_spn
        if account_name:
            vuln_details["account_name"] = account_name

        # Look up priority from config (default to 99 if unknown)
        vuln_priorities = _get_vuln_priorities()
        priority = vuln_priorities.get(vuln_type.lower(), 99)
        # Also check without lowercase for case-sensitive types like ADCS_ESC1
        if priority == 99:
            priority = vuln_priorities.get(vuln_type, 99)

        vuln = VulnerabilityInfo(
            vuln_id=f"{vuln_type}_{target_ip}_{account_name or 'manual'}",
            vuln_type=vuln_type,
            target=target_ip,
            discovered_by="manual-inject",
            details=vuln_details,
            priority=priority,
        )

        # Persist to Redis via backend
        backend = RedisStateBackend(client, operation_id)
        await backend.add_vulnerability(vuln)
        await client.aclose()

        # Notify subscribers so orchestrator/workers pick it up instantly
        from ares.core.task_queue import RedisTaskQueue

        tq = RedisTaskQueue(resolved_redis_url)
        await tq.connect()
        n = await tq.publish_state_update(operation_id)
        await tq.disconnect()

        logger.success(
            f"Injected vulnerability: {vuln_type} on {target_ip} "
            f"(priority={priority}, {n} subscribers notified)"
        )
        logger.info(f"Details: {vuln_details}")

    except Exception as e:
        logger.error(f"Failed to inject vulnerability: {e}")
        sys.exit(1)


@app.command(name="loot-users")
async def loot_users(
    operation_id: Annotated[str | None, cyclopts.Parameter(help="Operation ID")] = None,
    *,
    latest: Annotated[
        bool, cyclopts.Parameter(help="Use the latest operation (prefer running)")
    ] = False,
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    json_output: Annotated[bool, cyclopts.Parameter(help="Output as JSON")] = False,
    admin_only: Annotated[
        bool, cyclopts.Parameter(help="Only show users with admin credentials")
    ] = False,
    show_chains: Annotated[
        bool, cyclopts.Parameter(help="Show attack chains for each credential/hash")
    ] = False,
    domain: Annotated[str, cyclopts.Parameter(help="Filter by domain (case-insensitive)")] = "",
) -> None:
    """Display user summaries with credentials, hashes, and attack paths.

    Shows a user-centric view of discovered credentials and hashes, including
    how each credential was obtained (attack chain) and aggregated privilege info.

    Examples:
        ares-ops loot-users op-20250128-123456
        ares-ops loot-users --latest
        ares-ops loot-users --latest --admin-only
        ares-ops loot-users --latest --show-chains
        ares-ops loot-users --latest --domain contoso.local
    """
    from ares.reports.user_summary import generate_user_summaries

    resolved_redis_url = redis_url or get_redis_url()

    # Resolve operation ID
    if latest and not operation_id:
        operation_id = await _resolve_latest_operation(resolved_redis_url)
        if not operation_id:
            logger.error("No operations found")
            sys.exit(1)
        logger.info(f"Using latest operation: {operation_id}")
    elif not operation_id:
        logger.error("Either operation_id or --latest is required")
        sys.exit(1)

    try:
        client = await create_verified_redis_client(resolved_redis_url)
        state = await _load_state_from_redis(client, operation_id)
        await client.aclose()

        if state is None:
            logger.error(f"Operation {operation_id} not found")
            sys.exit(1)

        # Generate user summaries
        summaries = generate_user_summaries(state)

        # Apply filters
        if admin_only:
            summaries = [s for s in summaries if s.is_admin]

        if domain:
            domain_lower = domain.lower()
            summaries = [s for s in summaries if s.domain.lower() == domain_lower]

        if json_output:
            _print_user_summaries_json(summaries, operation_id, state)
        else:
            _print_user_summaries(summaries, operation_id, state, show_chains=show_chains)

    except Exception as e:
        logger.error(f"Failed to generate user summaries: {e}")
        sys.exit(1)


def _print_user_summaries_json(
    summaries: list,
    operation_id: str,
    state,
) -> None:
    """Print user summaries as JSON."""
    import json as json_module

    output = {
        "operation_id": operation_id,
        "has_domain_admin": state.has_domain_admin,
        "domain_admin_path": state.domain_admin_path,
        "user_count": len(summaries),
        "users": [],
    }

    for s in summaries:
        user_data = {
            "username": s.username,
            "domain": s.domain,
            "is_admin": s.is_admin,
            "description": s.description,
            "discovery_sources": list(s.discovery_sources),
            "max_attack_depth": s.max_attack_depth,
            "credentials": [
                {
                    "id": c.id,
                    "password": c.password,
                    "source": c.source,
                    "is_admin": c.is_admin,
                    "attack_step": c.attack_step,
                    "parent_id": c.parent_id,
                }
                for c in s.credentials
            ],
            "hashes": [
                {
                    "id": h.id,
                    "hash_type": h.hash_type,
                    "hash_value": h.hash_value,
                    "cracked_password": h.cracked_password,
                    "source": h.source,
                    "attack_step": h.attack_step,
                    "parent_id": h.parent_id,
                }
                for h in s.hashes
            ],
            "attack_chains": {
                item_id: [
                    {
                        "step": step.step_number,
                        "type": step.item_type,
                        "username": step.username,
                        "domain": step.domain,
                        "source": step.source,
                    }
                    for step in chain
                ]
                for item_id, chain in s.attack_chains.items()
            },
        }
        if s.first_discovered_at:
            user_data["first_discovered_at"] = s.first_discovered_at.isoformat()
        output["users"].append(user_data)

    print(json_module.dumps(output, indent=2, default=str))


def _print_user_summaries(
    summaries: list,
    operation_id: str,
    state,
    *,
    show_chains: bool = False,
) -> None:
    """Print user summaries in human-readable format."""
    from ares.reports.user_summary import format_attack_chain

    print(f"Operation: {operation_id}")
    if state.has_domain_admin:
        print("*** DOMAIN ADMIN ACHIEVED ***")
        if state.domain_admin_path:
            print(f"  Path: {state.domain_admin_path}")
    print()

    admin_count = sum(1 for s in summaries if s.is_admin)
    print(f"User Summaries ({len(summaries)} users, {admin_count} admins)")
    print("=" * 60)
    print()

    for s in summaries:
        # User header
        admin_marker = " [ADMIN]" if s.is_admin else ""
        print(f"{s.display_name}{admin_marker}")
        if s.description:
            print(f"  Description: {s.description}")

        # Sources
        if s.discovery_sources:
            sources_str = ", ".join(
                _normalize_source_label(src) for src in sorted(s.discovery_sources)
            )
            print(f"  Discovered via: {sources_str}")

        # Attack depth
        if s.max_attack_depth > 0:
            print(f"  Max attack depth: {s.max_attack_depth}")

        # Credentials
        if s.credentials:
            print(f"  Credentials ({len(s.credentials)}):")
            for c in s.credentials:
                admin_str = " (admin)" if c.is_admin else ""
                source_str = f" [{_normalize_source_label(c.source)}]" if c.source else ""
                print(f"    - {c.password}{admin_str}{source_str}")
                if show_chains and c.id in s.attack_chains:
                    chain = s.attack_chains[c.id]
                    chain_str = format_attack_chain(chain, compact=True)
                    print(f"      Chain: {chain_str}")

        # Hashes
        if s.hashes:
            print(f"  Hashes ({len(s.hashes)}):")
            for h in s.hashes:
                cracked_str = f" (cracked: {h.cracked_password})" if h.cracked_password else ""
                source_str = f" [{_normalize_source_label(h.source)}]" if h.source else ""
                hash_display = h.hash_value[:32] + "..." if len(h.hash_value) > 32 else h.hash_value
                print(f"    - {h.hash_type}:{hash_display}{cracked_str}{source_str}")
                if show_chains and h.id in s.attack_chains:
                    chain = s.attack_chains[h.id]
                    chain_str = format_attack_chain(chain, compact=True)
                    print(f"      Chain: {chain_str}")

        print()  # Blank line between users


async def _get_all_operations_with_status(
    redis_url: str,
) -> list[tuple[str, str, datetime | None]]:
    """Get all operations with their status and completion time.

    Returns:
        List of (operation_id, status, completed_at) tuples.
    """
    import json as json_module

    from ares.core.task_queue import RedisTaskQueue

    client = await create_verified_redis_client(redis_url, decode_responses=True)

    results: list[tuple[str, str, datetime | None]] = []

    # Check for running operations (have locks)
    running_ops: set[str] = set()
    lock_keys = await client.keys(f"{RedisTaskQueue.LOCK_PREFIX}:*")
    for key in lock_keys:
        parts = key.split(":", 2)
        if len(parts) >= 3:
            running_ops.add(parts[2])

    # Get all operations with meta keys
    meta_keys = await client.keys("ares:op:*:meta")
    seen_ops: set[str] = set()

    for key in meta_keys:
        parts = key.split(":")
        if len(parts) < 3:
            continue
        op_id = parts[2]
        if op_id in seen_ops:
            continue
        seen_ops.add(op_id)

        # Get status from status key
        status_key = f"ares:op:{op_id}:status"
        status_json = await client.get(status_key)
        status = "unknown"
        completed_at = None

        if status_json:
            try:
                status_data = json_module.loads(status_json)
                status = status_data.get("status", "unknown")
                if status == "completed" and status_data.get("completed_at"):
                    try:
                        completed_at = datetime.fromisoformat(status_data["completed_at"])
                    except Exception:
                        pass
            except json_module.JSONDecodeError:
                pass

        # Override status if running (has lock)
        if op_id in running_ops:
            status = "running"

        results.append((op_id, status, completed_at))

    await client.aclose()
    return results


@app.command
async def watch(
    *,
    poll_interval: Annotated[int, cyclopts.Parameter(help="Seconds between polls")] = 30,
    output_dir: Annotated[
        str, cyclopts.Parameter(help="Directory for reports (default: ./reports)")
    ] = "./reports",
    redis_url: Annotated[str, cyclopts.Parameter(help="Redis URL (default: from config)")] = "",
    once: Annotated[
        bool, cyclopts.Parameter(help="Run once and exit (check all completed ops)")
    ] = False,
) -> None:
    """Watch for completed operations and auto-fetch their reports.

    Polls Redis for completed operations and automatically downloads
    reports for any that don't have local reports yet.

    Examples:
        ares-ops watch                    # Poll every 30s
        ares-ops watch --poll-interval 60 # Poll every 60s
        ares-ops watch --once             # Check once and exit
    """
    resolved_redis_url = redis_url or get_redis_url()
    report_dir = Path(output_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    # Track operations we've already processed this session
    processed_ops: set[str] = set()

    # Pre-populate with operations that already have local reports
    for report_file in report_dir.glob("op-*_report.md"):
        # Extract operation ID from filename: op-YYYYMMDD-HHMMSS_report.md
        op_id = report_file.stem.replace("_report", "")
        processed_ops.add(op_id)

    logger.info(f"Watching for completed operations (poll interval: {poll_interval}s)")
    logger.info(f"Reports directory: {report_dir}")
    logger.info(f"Already have reports for {len(processed_ops)} operations")

    try:
        while True:
            try:
                operations = await _get_all_operations_with_status(resolved_redis_url)

                new_reports = 0
                for op_id, status, _completed_at in operations:
                    if op_id in processed_ops:
                        continue

                    if status == "completed":
                        # Auto-fetch the report
                        logger.info(f"Fetching report for completed operation: {op_id}")
                        try:
                            report_path = await _generate_local_report(
                                op_id,
                                resolved_redis_url,
                                report_dir=report_dir,
                            )
                            if report_path:
                                logger.success(f"Report saved: {report_path}")
                                new_reports += 1
                            processed_ops.add(op_id)
                        except Exception as e:
                            logger.warning(f"Failed to fetch report for {op_id}: {e}")
                            # Don't add to processed_ops - retry next poll

                    elif status == "failed":
                        # Mark as processed but don't fetch report
                        logger.warning(f"Operation {op_id} failed - skipping report")
                        processed_ops.add(op_id)

                if new_reports > 0:
                    logger.success(f"Fetched {new_reports} new report(s)")

                if once:
                    logger.info("Single check complete (--once mode)")
                    break

                await asyncio.sleep(poll_interval)

            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error(f"Poll error: {e}")
                if once:
                    sys.exit(1)
                await asyncio.sleep(poll_interval)

    except KeyboardInterrupt:
        logger.info("Watch stopped")


def main() -> None:
    """Entry point for ares-ops CLI."""
    try:
        app()
    except Exception as e:
        logger.error(f"CLI error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
