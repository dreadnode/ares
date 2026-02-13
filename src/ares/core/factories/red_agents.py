"""Factory for creating specialized multi-agent red team agents.

This module provides factories for creating role-specific agents
that work together in a distributed Kubernetes environment.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.events import AgentStalled, GenerationEnd, StepStart, ToolEnd, ToolStart
from dreadnode.agent.hooks import retry_with_feedback, summarize_when_long
from dreadnode.agent.stop import tool_use
from loguru import logger

from ares.core.capability_registry import FilteredToolset, get_enabled_tools
from ares.core.config import get_agent_config, get_max_context_tokens, get_min_messages_to_keep
from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import AgentInfo, AgentRole, SharedRedTeamState
from ares.core.templates import get_template_loader
from ares.tools.red import (
    ACLExploitTools,
    BloodHoundTools,
    CertipyTools,
    CoercionNetworkTools,
    CoercionTools,
    CrackerCallbackTools,
    CrackingTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    CVEExploitTools,
    DelegationTools,
    GMSATools,
    GoldenTicketTools,
    LateralCallbackTools,
    LateralMovementTools,
    MSSQLTools,
    NetworkEnumerationTools,
    PostureValidationTools,
    RedTeamReportingTools,
    SharePilferingTools,
    TrustAttackTools,
)

if TYPE_CHECKING:
    from ares.core.k8s_executor import KubernetesPodExecutor

from dreadnode.agent.reactions import Finish, Reaction


def fix_tool_output_encoding(content: str) -> str:
    """Remove invalid UTF-8 surrogates from tool output.

    Tool output may contain binary data or invalid UTF-8 sequences that cause
    encoding errors when logging or processing. This function replaces any
    problematic characters with the Unicode replacement character.
    """
    if not content:
        return ""
    # Encode with surrogateescape to handle invalid sequences, then decode
    # with replace to convert them to replacement characters
    return content.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")


# All available toolset classes for filtering by capabilities
# Each role gets ALL toolsets, but FilteredToolset restricts to capability-enabled tools
# Note: ORCHESTRATOR is not included here - it uses OrchestratorTools which are
# wired up separately in the orchestrator.py module
ALL_TOOLSETS: list[type] = [
    # Reconnaissance
    NetworkEnumerationTools,
    BloodHoundTools,
    PostureValidationTools,
    # Credential discovery
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    SharePilferingTools,
    # Cracking
    CrackingTools,
    # ACL exploitation
    ACLExploitTools,
    # Privilege escalation
    CertipyTools,
    DelegationTools,
    MSSQLTools,
    CVEExploitTools,
    GoldenTicketTools,
    TrustAttackTools,
    GMSATools,
    # Lateral movement
    LateralMovementTools,
    # Coercion/relay
    CoercionTools,
    CoercionNetworkTools,
]

# Role-specific callback tools (not capability-filtered)
# These are added automatically based on role
ROLE_CALLBACK_TOOLS: dict[AgentRole, list[type]] = {
    AgentRole.CRACKER: [CrackerCallbackTools],
    AgentRole.LATERAL: [LateralCallbackTools],
}

# Always-included toolsets (reporting is needed by all roles)
UNIVERSAL_TOOLSETS: list[type] = [
    RedTeamReportingTools,
]


# System instruction templates per role
ROLE_INSTRUCTIONS: dict[AgentRole, str] = {
    AgentRole.ORCHESTRATOR: "redteam/agents/orchestrator.md.jinja",
    AgentRole.RECON: "redteam/agents/recon.md.jinja",
    AgentRole.CREDENTIAL_ACCESS: "redteam/agents/credential_access.md.jinja",
    AgentRole.CRACKER: "redteam/agents/cracker.md.jinja",
    AgentRole.ACL: "redteam/agents/acl.md.jinja",
    AgentRole.PRIVESC: "redteam/agents/privesc.md.jinja",
    AgentRole.LATERAL: "redteam/agents/lateral.md.jinja",
    AgentRole.COERCION: "redteam/agents/coercion.md.jinja",
}


# Default max steps fallback when role not in YAML config
DEFAULT_MAX_STEPS = 75


def load_agent_instructions(role: AgentRole) -> str:
    """
    Load role-specific system instructions from template.

    Falls back to generic red team instructions if role-specific not found.
    Capabilities are loaded from config and passed to the template.
    """
    # Get capabilities from config (single source of truth)
    config_key = role.value  # e.g., "recon", "credential_access", "privesc"
    agent_config = get_agent_config(config_key)
    capabilities = agent_config.capabilities

    template_path = ROLE_INSTRUCTIONS.get(role)
    if template_path:
        try:
            return get_template_loader().render(template_path, capabilities=capabilities)
        except Exception as e:
            logger.warning(f"Failed to load template {template_path}: {e}")

    # Fallback to generic red team instructions - pass ALL role capabilities
    all_capabilities = {
        "recon": get_agent_config("recon").capabilities,
        "credential_access": get_agent_config("credential_access").capabilities,
        "cracker": get_agent_config("cracker").capabilities,
        "coercion": get_agent_config("coercion").capabilities,
        "acl": get_agent_config("acl").capabilities,
        "privesc": get_agent_config("privesc").capabilities,
        "lateral": get_agent_config("lateral").capabilities,
    }
    return get_template_loader().render(
        "redteam/agents/system_instructions.md.jinja",
        capabilities=capabilities,
        all_capabilities=all_capabilities,
    )


def create_role_hooks(
    role: AgentRole,
    dispatcher: RedTeamDispatcher,
    shared_state: SharedRedTeamState,
    display_name: str | None = None,
) -> list:
    """
    Create hooks for a specific agent role.

    Args:
        role: The agent role.
        dispatcher: The dispatcher for inter-agent communication.
        shared_state: The shared state object.
        display_name: Optional display name for logging (defaults to role.value).

    Returns:
        List of hook functions.
    """
    hooks = []
    log_name = display_name or role.value

    # Circuit breaker state - track consecutive failures per tool
    # This prevents agents from infinitely retrying the same failing approach
    consecutive_failures: dict[str, int] = {}
    circuit_breaker_threshold = 3  # Stop after 3 consecutive failures on same tool
    circuit_breaker_tripped = (
        False  # Flag to prevent redundant Finish reactions from parallel calls
    )

    # Common logging hooks
    async def log_tool_usage(event: ToolStart):
        """Log tool calls for observability."""
        if hasattr(event, "tool_call") and event.tool_call:
            logger.info(f"🔧 [{log_name}] Tool: {event.tool_call.name}")
            dn.log_metric(f"multiagent_{log_name}_tool_{event.tool_call.name}", 1, mode="count")

    async def log_tool_result(event: ToolEnd) -> Reaction | None:  # noqa: PLR0912
        """Log tool results and apply circuit breaker for repeated failures."""
        if not isinstance(event, ToolEnd):
            return None

        if not (hasattr(event, "tool_call") and event.tool_call):
            return None

        tool_name = event.tool_call.name
        is_error = False

        if hasattr(event, "error") and event.error:
            is_error = True
            logger.warning(f"❌ [{log_name}] {tool_name} failed: {event.error}")
        else:
            content = fix_tool_output_encoding(
                str(event.message.content) if event.message and event.message.content else ""
            )
            if not content:
                logger.info(f"✅ [{log_name}] {tool_name}: (empty)")
            else:
                # Detect error content returned by rigging's exception catching
                # (ValidationError, JSONDecodeError are caught and returned as error XML)
                # Also detect common tool failure patterns
                is_error = (
                    content.startswith('<error type="')
                    or "ValidationError" in content
                    or "Login failed" in content
                    or "timed out" in content.lower()
                    or "[-] ERROR" in content
                )
                icon = "❌" if is_error else "✅"
                log_fn = logger.warning if is_error else logger.info

                # Show first 50 lines, max 5000 chars
                lines = content.split("\n")[:50]
                result = "\n".join(lines)
                truncated = len(lines) < len(content.split("\n")) or len(content) > 5000
                if len(result) > 5000:
                    result = result[:5000]
                    truncated = True
                suffix = " ..." if truncated else ""
                if "\n" in result:
                    log_fn(f"{icon} [{log_name}] {tool_name}:\n{result}{suffix}")
                else:
                    log_fn(f"{icon} [{log_name}] {tool_name}: {result}{suffix}")

        # Circuit breaker logic
        # Use nonlocal to modify the tripped flag
        nonlocal circuit_breaker_tripped

        # If already tripped, return Finish immediately to stop parallel calls
        if circuit_breaker_tripped:
            return Finish(reason="Circuit breaker already tripped - stopping agent")

        if is_error:
            consecutive_failures[tool_name] = consecutive_failures.get(tool_name, 0) + 1
            fail_count = consecutive_failures[tool_name]

            if fail_count >= circuit_breaker_threshold:
                # Set flag BEFORE returning to prevent race with parallel calls
                circuit_breaker_tripped = True
                logger.error(
                    f"🔌 [{log_name}] Circuit breaker tripped: {tool_name} failed "
                    f"{fail_count} times consecutively - stopping agent"
                )
                return Finish(
                    reason=f"Circuit breaker: {tool_name} failed {fail_count} times consecutively. "
                    "The approach is not working - task will be retried with a different strategy."
                )
            if fail_count >= 2:
                logger.warning(
                    f"⚠️ [{log_name}] {tool_name} failed {fail_count}x consecutively "
                    f"(circuit breaker at {circuit_breaker_threshold})"
                )
        else:
            # Reset failure counter on success
            consecutive_failures[tool_name] = 0

        return None

    hooks.extend([log_tool_usage, log_tool_result])

    # Context management for ALL roles: summarize conversation when approaching token limits
    # This prevents context window exhaustion from accumulated tool outputs
    # Default threshold is ~100k tokens (~85% of 128k window for Sonnet)
    # Configurable via ARES_MAX_CONTEXT_TOKENS and ARES_MIN_MESSAGES_TO_KEEP
    max_tokens = get_max_context_tokens()
    min_messages = get_min_messages_to_keep()
    _summarize_hook = summarize_when_long(
        max_tokens=max_tokens,
        min_messages_to_keep=min_messages,
    )

    async def context_aware_summarize(event: StepStart | GenerationEnd) -> Reaction | None:
        """Wrap summarize_when_long with logging for observability."""
        # Log token count on each step start
        if isinstance(event, StepStart):
            last_gen = event.get_latest_event_by_type(GenerationEnd)
            if last_gen and last_gen.usage:
                tokens = last_gen.usage.input_tokens
                pct = (tokens / max_tokens) * 100
                if pct >= 80:
                    logger.warning(
                        f"📊 [{log_name}] Context: {tokens:,} / {max_tokens:,} tokens ({pct:.0f}%)"
                    )
                elif pct >= 50:
                    logger.info(
                        f"📊 [{log_name}] Context: {tokens:,} / {max_tokens:,} tokens ({pct:.0f}%)"
                    )

        # Call the actual summarization hook
        result = await _summarize_hook(event)

        if result is not None:
            logger.success(
                f"📝 [{log_name}] Conversation summarized! Keeping {min_messages} recent messages"
            )

        return result

    hooks.append(context_aware_summarize)

    # Role-specific hooks
    if role == AgentRole.ORCHESTRATOR:
        # Orchestrator monitors for domain admin achievement
        async def check_domain_admin(event: ToolEnd):
            if not isinstance(event, ToolEnd):
                return None

            if not event.message or not event.message.content:
                return None

            result = fix_tool_output_encoding(str(event.message.content)).lower()
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            if tool_name == "domain_admin_checker" and "success" in result:
                return (
                    "🎉 DOMAIN ADMIN CONFIRMED!\n"
                    "→ Broadcast this achievement to all agents\n"
                    "→ Run secretsdump on all targets\n"
                    "→ Generate golden ticket if possible"
                )
            return None

        hooks.append(check_domain_admin)

        # Stop orchestrator when DA is achieved externally (by worker agents)
        # This handles the case where a worker discovers krbtgt hash via secretsdump
        # and sets has_domain_admin=True, but the orchestrator LLM doesn't know to stop
        async def stop_on_external_domain_admin(event: StepStart) -> Finish | None:
            """Stop orchestrator when Domain Admin is achieved by worker agents."""
            if not isinstance(event, StepStart):
                return None

            if shared_state.has_domain_admin:
                logger.success(
                    "🎯 Domain Admin detected (achieved externally) - stopping orchestrator agent"
                )
                return Finish(reason="Domain Admin achieved by worker agent")

            return None

        hooks.append(stop_on_external_domain_admin)

    elif role == AgentRole.CRACKER:
        # Cracker broadcasts cracked credentials
        async def broadcast_cracked(event: ToolEnd):
            if not isinstance(event, ToolEnd):
                return None

            if not event.message or not event.message.content:
                return None

            result = fix_tool_output_encoding(str(event.message.content))
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            if tool_name in ["hashcat_crack", "john_crack"] and "cracked" in result.lower():
                return (
                    "🔓 PASSWORD CRACKED!\n"
                    "→ Use report_cracked_credential to broadcast to all agents\n"
                    "→ Include username, password, and original hash"
                )
            return None

        hooks.append(broadcast_cracked)

    elif role == AgentRole.PRIVESC:
        # PrivEsc monitors for successful exploitation AND futility
        _privesc_failures: dict[str, Any] = {
            "adcs_failures": 0,
            "delegation_failures": 0,
            "failed_targets": set(),
        }

        async def track_exploitation(event: ToolEnd):
            if not isinstance(event, ToolEnd):
                return None

            if not event.message or not event.message.content:
                return None

            result = fix_tool_output_encoding(str(event.message.content))
            result_lower = result.lower()
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            # Check for successful ADCS exploitation
            certipy_exploitation_tools = {
                "certipy_request",
                "certipy_req",
                "certipy_req_esc1",
                "certipy_auth",
                "certipy_shadow",
                "certipy_shadow_auto",
                "ntlmrelayx_to_adcs",
            }
            if tool_name in certipy_exploitation_tools and (
                "success" in result_lower
                or ".pfx" in result_lower
                or ("hash" in result_lower and ":" in result)
            ):
                return (
                    "✅ ADCS EXPLOITATION SUCCESSFUL!\n"
                    "→ Report the obtained credential/certificate\n"
                    "→ Use certipy_auth to get NTLM hash if needed"
                )

            # Track ADCS failures - detect unreachable CA/web enrollment
            adcs_failure_indicators = [
                "connection refused",
                "errno 111",
                "timed out",
                "timeout",
                "web enrollment",
                "no ca found",
                "rpc unavailable",
                "rpc_s_server_unavailable",
                "access denied",
                "could not connect",
                "name or service not known",
                "no route to host",
            ]
            adcs_tools = {
                "certipy_find",
                "certipy_request",
                "certipy_req",
                "certipy_req_esc1",
                "certipy_auth",
                "ntlmrelayx_to_adcs",
            }
            if tool_name in adcs_tools and any(
                ind in result_lower for ind in adcs_failure_indicators
            ):
                _privesc_failures["adcs_failures"] += 1
                # Extract target from tool args if possible
                if hasattr(event, "tool_call") and event.tool_call and event.tool_call.arguments:
                    try:
                        import json

                        args = json.loads(event.tool_call.arguments)
                        target = args.get("ca_server") or args.get("target") or args.get("dc_ip")
                        if target:
                            _privesc_failures["failed_targets"].add(target)
                    except Exception:
                        pass

                failures = _privesc_failures["adcs_failures"]
                if failures >= 2:
                    targets = ", ".join(_privesc_failures["failed_targets"]) or "CA"
                    return (
                        f"⚠️ ADCS FUTILITY: {failures} failures on {targets}\n"
                        "→ CA web enrollment appears unreachable\n"
                        "→ STOP retrying ADCS attacks - call task_complete with failure\n"
                        "→ Try OTHER attack paths (delegation, GPO abuse) if available"
                    )

            # Track delegation failures
            delegation_tools = {"constrained_delegation_s4u", "getST", "s4u_attack"}
            if tool_name in delegation_tools and any(
                ind in result_lower for ind in ["failed", "error", "denied", "refused", "not found"]
            ):
                _privesc_failures["delegation_failures"] += 1
                if _privesc_failures["delegation_failures"] >= 3:
                    return (
                        f"⚠️ DELEGATION FUTILITY: {_privesc_failures['delegation_failures']} failures\n"
                        "→ STOP retrying delegation attacks\n"
                        "→ Try OTHER attack paths or call task_complete"
                    )

            return None

        hooks.append(track_exploitation)

    elif role == AgentRole.COERCION:
        # Coercion monitors for futility - too many failures indicate target unreachable
        _coercion_failures: dict[str, Any] = {"count": 0, "targets": set()}

        async def track_coercion_futility(event: ToolEnd):
            if not isinstance(event, ToolEnd) or not event.message:
                return None

            result = fix_tool_output_encoding(str(event.message.content)).lower()
            tool_name = (
                event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
            )

            coercion_tools = {"petitpotam", "coercer", "printerbug", "dfscoerce"}
            if tool_name in coercion_tools:
                # Track target
                if hasattr(event, "tool_call") and event.tool_call and event.tool_call.arguments:
                    try:
                        import json

                        args = json.loads(event.tool_call.arguments)
                        _coercion_failures["targets"].add(args.get("target", "unknown"))
                    except Exception:
                        pass

                # Check for failures
                failure_indicators = [
                    "connection refused",
                    "timed out",
                    "no response",
                    "access denied",
                    "failed",
                    "rpc_s_server_unavailable",
                ]
                if any(ind in result for ind in failure_indicators):
                    _coercion_failures["count"] += 1

                    if _coercion_failures["count"] >= 3:
                        targets = ", ".join(_coercion_failures["targets"])
                        return (
                            f"COERCION FUTILITY: {_coercion_failures['count']} failures on targets: {targets}\n"
                            "→ If all targets exhausted, call task_complete now."
                        )
            return None

        hooks.append(track_coercion_futility)

    # Unstall hook for all roles - provides context-specific guidance when agent stalls
    role_feedback = {
        AgentRole.ORCHESTRATOR: (
            "You seem stuck. As orchestrator, focus on:\n"
            "1. Check pending tasks with get_pending_tasks()\n"
            "2. Review unexploited vulnerabilities with get_exploitation_status()\n"
            "3. Dispatch work to specialized agents\n"
            "4. Don't do exploitation yourself - delegate!"
        ),
        AgentRole.RECON: (
            "You seem stuck. As recon agent, focus on:\n"
            "1. Run network scans with nmap_scan\n"
            "2. Enumerate users and shares\n"
            "3. Run BloodHound collection if credentials available\n"
            "4. Report findings back to orchestrator"
        ),
        AgentRole.CREDENTIAL_ACCESS: (
            "You seem stuck. As credential access agent, focus on:\n"
            "1. LOW-HANGING FRUIT: gpp_password_finder, sysvol_script_search on DCs\n"
            "2. KERBEROAST: kerberoast service accounts (look for sql_svc, svc_*, etc.)\n"
            "3. AS-REP ROAST: asrep_roast users without pre-auth\n"
            "4. LDAP SEARCH: ldap_search_descriptions for passwords in descriptions\n"
            "5. LAPS: laps_dump if we have read access\n"
            "6. SHARES: Enumerate accessible shares for scripts/configs with creds\n"
            "7. If you have admin on a host, run secretsdump to harvest creds\n"
            "8. Use task_complete when no more credential sources available"
        ),
        AgentRole.CRACKER: (
            "You seem stuck. As cracker agent, focus on:\n"
            "1. Check the hash type and pick the right hashcat mode\n"
            "2. Try rockyou.txt first with common rules (best64, d3ad0ne)\n"
            "3. For Kerberos hashes (TGS/AS-REP): mode 18200/23 with wordlists\n"
            "4. For NTLM: mode 1000, try pass-the-hash if cracking fails\n"
            "5. Report cracked passwords with report_cracked_credential\n"
            "6. Use task_complete when cracking exhausted or successful"
        ),
        AgentRole.ACL: (
            "You seem stuck. As ACL exploiter, focus on:\n"
            "1. Run BloodHound collection if not done\n"
            "2. Find shortest paths to Domain Admins\n"
            "3. Execute ACL abuse: shadow credentials, targeted kerberoast, password change"
        ),
        AgentRole.PRIVESC: (
            "You seem stuck. CHECK YOUR PROGRESS:\n"
            "1. ADCS 'connection refused'/'timed out'? → CA unreachable, STOP trying ADCS\n"
            "2. Web enrollment failed? → Skip ESC8, try other paths\n"
            "3. Delegation failed 2+ times? → Move to next attack vector\n"
            "4. All attack paths exhausted? → Call task_complete with summary\n\n"
            "**DO NOT** keep retrying unreachable services. Report failure and move on."
        ),
        AgentRole.LATERAL: (
            "You seem stuck. As lateral agent, focus on:\n"
            "1. TRY ALL CREDENTIALS from shared state against the target\n"
            "2. Methods to try in order: evil-winrm (5985), psexec (445), wmiexec (135)\n"
            "3. If you get access: run secretsdump IMMEDIATELY to harvest creds\n"
            "4. If target is a DC: secretsdump will get NTDS.dit → krbtgt hash → golden ticket\n"
            "5. Check for MSSQL (1433): linked servers can pivot across domains\n"
            "6. Report ALL new credentials found with appropriate tools\n"
            "7. Use task_complete when access achieved or all methods exhausted"
        ),
        AgentRole.COERCION: (
            "You seem stuck. CHECK YOUR PROGRESS:\n"
            "1. All targets attempted? → Call task_complete with summary\n"
            "2. petitpotam/coercer failed? → Skip to next target\n"
            "3. Saw 'connection refused'/'timed out'? → Target blocked, skip it\n"
            "4. responder/ntlmrelayx running? → Wait for captures, don't restart\n\n"
            "**DO NOT** retry failed techniques on same target."
        ),
    }

    # All roles get unstall hooks with role-specific guidance
    unstall_hook = retry_with_feedback(
        event_type=AgentStalled,
        feedback=role_feedback.get(role, "Try a different approach."),
    )
    hooks.append(unstall_hook)

    return hooks


def create_specialized_agent(  # noqa: PLR0912
    role: AgentRole,
    model: str,
    shared_state: SharedRedTeamState,
    dispatcher: RedTeamDispatcher,
    pod_executor: KubernetesPodExecutor | None = None,
    pod_name: str = "",
    max_steps: int | None = None,
    additional_tools: list | None = None,
) -> Agent:
    """
    Create a specialized agent for a specific role.

    Tools are determined by the capabilities list in the YAML configuration.
    The capability registry maps capability strings (e.g., "nmap", "impacket-secretsdump")
    to specific tool method names, and FilteredToolset ensures only those methods
    are exposed to the agent.

    Args:
        role: Agent specialization.
        model: LLM model to use.
        shared_state: Reference to cluster-wide state.
        dispatcher: Message dispatcher for coordination.
        pod_executor: Executor for the agent's pod (optional).
        pod_name: Name of the pod this agent runs in.
        max_steps: Override default max steps for role.
        additional_tools: Additional tools to include.

    Returns:
        Configured Dreadnode Agent.
    """
    # Get capabilities from config - this is now the source of truth for tool access
    agent_config = get_agent_config(role.value)
    enabled_tools = get_enabled_tools(set(agent_config.capabilities))

    if not enabled_tools:
        logger.warning(
            f"No capabilities configured for role {role.value} - agent will have limited tools"
        )

    tools: list[Any] = []

    # Instantiate all toolsets and filter by capabilities
    for cls in ALL_TOOLSETS:
        try:
            toolset = cls()
            # Set shared state on toolset (all toolsets accept AnyRedTeamState)
            if hasattr(toolset, "set_state"):
                toolset.set_state(shared_state)
            if hasattr(toolset, "set_dispatcher"):
                toolset.set_dispatcher(dispatcher)
            if hasattr(toolset, "set_executor") and pod_executor:
                toolset.set_executor(pod_executor)

            # Wrap with capability filter
            filtered = FilteredToolset(toolset, enabled_tools)

            # Only add if this toolset has at least one enabled tool
            if filtered.get_tools():
                tools.append(filtered)
                logger.debug(
                    f"[{role.value}] Added {cls.__name__} with "
                    f"{len(filtered.get_tools())} enabled tools"
                )
        except Exception as e:  # noqa: PERF203
            logger.warning(f"Failed to initialize toolset {cls.__name__}: {e}")

    # Add universal toolsets (not capability-filtered)
    for cls in UNIVERSAL_TOOLSETS:
        try:
            toolset = cls()
            if hasattr(toolset, "set_state"):
                toolset.set_state(shared_state)
            if hasattr(toolset, "set_dispatcher"):
                toolset.set_dispatcher(dispatcher)
            tools.append(toolset)
        except Exception as e:  # noqa: PERF203
            logger.warning(f"Failed to initialize universal toolset {cls.__name__}: {e}")

    # Add role-specific callback tools (not capability-filtered)
    callback_toolsets = ROLE_CALLBACK_TOOLS.get(role, [])
    for cls in callback_toolsets:
        try:
            toolset = cls()
            if hasattr(toolset, "set_state"):
                toolset.set_state(shared_state)
            if hasattr(toolset, "set_dispatcher"):
                toolset.set_dispatcher(dispatcher)
            tools.append(toolset)
        except Exception as e:  # noqa: PERF203
            logger.warning(f"Failed to initialize callback toolset {cls.__name__}: {e}")

    # Add additional tools
    if additional_tools:
        tools.extend(additional_tools)

    # Load role-specific instructions
    instructions = load_agent_instructions(role)

    # Create hooks for this role
    hooks = create_role_hooks(role, dispatcher, shared_state)

    # Determine stop conditions based on role
    stop_conditions = []
    if role == AgentRole.ORCHESTRATOR:
        stop_conditions.append(tool_use("complete_operation"))
    else:
        # Worker agents stop when task is complete or they need assistance
        stop_conditions.extend(
            [
                tool_use("task_complete"),
                tool_use("request_assistance"),
            ]
        )

    agent_name = f"ares-{role.value.replace('_', '-')}"
    # Use role-specific limit from YAML config as hard cap (single source of truth)
    # This stops agents from spinning for 200 steps burning millions of tokens
    role_limit = agent_config.max_steps or DEFAULT_MAX_STEPS
    max_steps = min(max_steps or role_limit, role_limit)

    logger.info(f"Creating {agent_name} agent with {len(tools)} toolsets, max_steps={max_steps}")

    return dn.Agent(
        name=agent_name,
        model=model,
        instructions=instructions,
        max_steps=max_steps,
        tools=tools,
        hooks=hooks,
        stop_conditions=stop_conditions,
        thread=Thread(),  # type: ignore[call-arg]
    )


def create_agent_info(
    role: AgentRole,
    pod_name: str,
) -> AgentInfo:
    """
    Create AgentInfo for registration with dispatcher.

    Capabilities are loaded from config (single source of truth).

    Args:
        role: The agent role.
        pod_name: Name of the Kubernetes pod.

    Returns:
        AgentInfo object.
    """
    # Get capabilities from config (single source of truth)
    config_key = role.value  # e.g., "recon", "credential_access", "privesc"
    agent_config = get_agent_config(config_key)
    capabilities = set(agent_config.capabilities)

    return AgentInfo(
        name=f"ares-{role.value.replace('_', '-')}",
        pod_name=pod_name,
        role=role,
        capabilities=capabilities,
    )


async def create_multi_agent_ensemble(
    operation_id: str,
    target_ip: str,
    model: str | None = None,
    orchestrator_model: str | None = None,
    worker_model: str | None = None,
    dispatcher: RedTeamDispatcher | None = None,
    pod_executor: KubernetesPodExecutor | None = None,
    roles: list[AgentRole] | None = None,
) -> dict[AgentRole, Agent]:
    """
    Create a full ensemble of specialized agents.

    Args:
        operation_id: Unique operation identifier.
        target_ip: Primary target IP.
        model: Default LLM model.
        orchestrator_model: Override model for orchestrator.
        worker_model: Override model for workers.
        dispatcher: Pre-configured dispatcher (created if None).
        pod_executor: Pre-configured pod executor.
        roles: Specific roles to create (all if None).

    Returns:
        Dict mapping role to agent.
    """
    from ares.core.models import Target

    # Default roles if not specified
    if roles is None:
        roles = [
            AgentRole.RECON,
            AgentRole.CREDENTIAL_ACCESS,
            AgentRole.CRACKER,
            AgentRole.ACL,
            AgentRole.PRIVESC,
            AgentRole.LATERAL,
            AgentRole.COERCION,
        ]

    # Create dispatcher if not provided
    if dispatcher is None:
        dispatcher = RedTeamDispatcher()
        await dispatcher.start(operation_id)

    # Create shared state
    shared_state = dispatcher.shared_state
    shared_state.target = Target(ip=target_ip)

    agents: dict[AgentRole, Agent] = {}

    base_model = model or os.getenv("ARES_MODEL")
    orch_model = orchestrator_model or os.getenv("ARES_ORCHESTRATOR_MODEL")
    work_model = worker_model or os.getenv("ARES_WORKER_MODEL")

    if not (base_model or orch_model or work_model):
        raise ValueError(
            "No model specified for multi-agent ensemble. Provide model args or set "
            "ARES_MODEL/ARES_ORCHESTRATOR_MODEL/ARES_WORKER_MODEL in the environment."
        )

    for role in roles:
        # Determine model for this role
        if role == AgentRole.ORCHESTRATOR:
            agent_model = orch_model or base_model
        else:
            agent_model = work_model or base_model
        if not agent_model:
            raise ValueError(
                f"No model specified for role {role.value}. "
                "Provide model args or set ARES_MODEL/ARES_ORCHESTRATOR_MODEL/ARES_WORKER_MODEL."
            )

        # Create agent
        agent = create_specialized_agent(
            role=role,
            model=agent_model,
            shared_state=shared_state,
            dispatcher=dispatcher,
            pod_executor=pod_executor,
            pod_name=f"ares-{role.value.replace('_', '-')}-0",  # Default pod naming
        )

        agents[role] = agent

        # Register with dispatcher
        agent_info = create_agent_info(role, pod_name=f"ares-{role.value.replace('_', '-')}-0")
        await dispatcher.register(agent_info)

    logger.info(f"Created multi-agent ensemble with {len(agents)} agents")
    return agents


# Completion tools for worker agents


@dn.tool
def task_complete(task_id: str, result: str) -> str:
    """
    Mark the current task as complete.

    Use this when you have successfully completed the assigned task.

    Args:
        task_id: The task ID that was assigned
        result: Summary of what was accomplished

    Returns:
        Confirmation message
    """
    logger.info(f"Task {task_id} completed: {result}")
    return f"✓ Task {task_id} marked as complete"


@dn.tool
def request_assistance(issue: str, context: str = "") -> str:
    """
    Request assistance from the orchestrator.

    Use this when you encounter an issue you cannot resolve.

    Args:
        issue: Description of the problem
        context: Additional context about what you were trying to do

    Returns:
        Confirmation that assistance was requested
    """
    logger.info(f"Assistance requested: {issue}")
    return f"⚠️ Assistance requested for: {issue}"


__all__ = [
    "ALL_TOOLSETS",
    "DEFAULT_MAX_STEPS",
    "ROLE_CALLBACK_TOOLS",
    "ROLE_INSTRUCTIONS",
    "UNIVERSAL_TOOLSETS",
    "create_agent_info",
    "create_multi_agent_ensemble",
    "create_role_hooks",
    "create_specialized_agent",
    "load_agent_instructions",
    "request_assistance",
    "task_complete",
]
