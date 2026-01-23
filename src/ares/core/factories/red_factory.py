"""Factory for creating red team agents with presets."""

import time

import dreadnode as dn
from dreadnode.agent import Agent, Thread
from dreadnode.agent.events import (
    AgentEnd,
    AgentError,
    AgentStalled,
    GenerationEnd,
    StepStart,
    ToolEnd,
    ToolStart,
)
from dreadnode.agent.hooks import retry_with_feedback
from dreadnode.agent.stop import tool_use
from loguru import logger

from ares.core.models import RedTeamState
from ares.core.templates import get_template_loader
from ares.integrations.mitre import MITREAttackClient
from ares.tools.red.network import (
    ACLExploitTools,
    BloodHoundTools,
    CertipyTools,
    CoercionTools,
    CrackingTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    CVEExploitTools,
    DelegationTools,
    GoldenTicketTools,
    LateralMovementTools,
    MSSQLTools,
    NetworkEnumerationTools,
    RedTeamReportingTools,
    SharePilferingTools,
    TrustAttackTools,
)

# Load system instructions from template
REDTEAM_SYSTEM_INSTRUCTIONS = get_template_loader().render(
    "redteam/agents/system_instructions.md.jinja"
)

# Event deduplication state
_last_event_times: dict[str, float] = {}
_last_step_number: int | None = None
_DEBOUNCE_WINDOW = 0.1  # 100ms debounce window

# Periodic priority check state
_discovered_vulnerabilities: dict[str, dict] = {}  # vuln_type -> {details, discovered_at_step}
_exploited_vulnerabilities: set[str] = set()  # vuln_types that have been exploited
_last_priority_check_step: int = 0
_PRIORITY_CHECK_INTERVAL = 10  # Check every N steps


def reset_event_tracking():
    """Reset event tracking state for a new agent run."""
    global _last_event_times, _last_step_number
    global _discovered_vulnerabilities, _exploited_vulnerabilities, _last_priority_check_step
    _last_event_times = {}
    _last_step_number = None
    _discovered_vulnerabilities = {}
    _exploited_vulnerabilities = set()
    _last_priority_check_step = 0


def _should_log_event(event_type: str) -> bool:
    """Check if event should be logged (debounce rapid duplicates)."""
    now = time.time()
    last_time = _last_event_times.get(event_type, 0)
    if now - last_time < _DEBOUNCE_WINDOW:
        return False
    _last_event_times[event_type] = now
    return True


async def log_step_start(event: StepStart):
    """Log step start for debugging - only when step number is meaningful."""
    global _last_step_number
    step_num = getattr(event, "step_number", None)

    # Skip if no real step number or if it's the same as last logged step
    if step_num is None or step_num == _last_step_number:
        return

    if not _should_log_event("step_start"):
        return

    _last_step_number = step_num
    logger.info(f"📍 Step {step_num} started")


async def log_generation_end(event: GenerationEnd):
    """Log generation end - only when there's meaningful content."""
    # Skip empty/spurious generation events
    if not hasattr(event, "message") or not event.message:
        return

    msg = event.message
    has_content = hasattr(msg, "content") and msg.content and str(msg.content).strip()
    has_tool_calls = hasattr(msg, "tool_calls") and msg.tool_calls

    # Only log if there's actual content or tool calls
    if not has_content and not has_tool_calls:
        return

    if not _should_log_event("generation_end"):
        return

    # Log concise summary
    if has_tool_calls:
        tool_names = [tc.name for tc in msg.tool_calls]
        logger.info(f"🤖 Agent requesting tools: {tool_names}")
    elif has_content:
        content_preview = str(msg.content)[:200].replace("\n", " ")
        logger.info(f"🤖 Agent: {content_preview}...")


async def log_agent_error(event: AgentError):
    """Log agent errors - only real errors, not spurious SDK events."""
    error = getattr(event, "error", None)
    # Only log if there's an actual error (SDK emits AgentError with None frequently)
    if error is None:
        return  # Silently ignore spurious events

    logger.error(f"🚨 Agent error: {error}")
    if hasattr(event, "traceback") and event.traceback:
        logger.error(f"🚨 Traceback: {event.traceback}")


async def log_agent_end(event: AgentEnd):
    """Log agent end - only when there's a meaningful stop reason."""
    stop_reason = getattr(event, "stop_reason", None)

    # Skip spurious end events with no stop reason
    if stop_reason is None:
        return

    if not _should_log_event("agent_end"):
        return

    logger.info(f"🏁 Agent ended: {stop_reason}")


async def log_tool_usage(event: ToolStart):
    """Log tool calls for observability."""
    if hasattr(event, "tool_call") and event.tool_call:
        logger.info(f"🔧 Red Team Tool: {event.tool_call.name}")
        logger.info(f"🔧 Tool args: {getattr(event.tool_call, 'arguments', {})}")
        dn.log_metric(f"redteam_tool_{event.tool_call.name}", 1, mode="count")


async def log_tool_result(event: ToolEnd):
    """Log tool results."""
    # Only process ToolEnd events
    if not isinstance(event, ToolEnd):
        return

    if hasattr(event, "tool_call") and event.tool_call:
        if hasattr(event, "error") and event.error:
            logger.warning(f"❌ Tool {event.tool_call.name} failed: {event.error}")
            dn.log_metric("redteam_tool_errors", 1, mode="count")
        else:
            result = str(event.message.content) if event.message and event.message.content else None
            result_preview = result[:200] if result else "None"
            logger.info(f"✅ Tool {event.tool_call.name} completed: {result_preview}")


unstall_hook = retry_with_feedback(
    event_type=AgentStalled,
    feedback=(
        "You seem stuck. Remember the priority workflow:\n"
        "0. LOW-HANGING FRUIT: ldap_search_descriptions, username_as_password, password_spray, password_policy\n"
        "1. PRIORITY 1: krbtgt hash found? → Use golden_ticket tool immediately\n"
        "2. PRIORITY 2: Administrator hash found? → domain_admin_checker on ALL targets\n"
        "3. PRIORITY 3: New password found? → Re-enumerate users, shares, kerberoast, asrep_roast\n"
        "4. ACL ABUSE: GenericAll/GenericWrite? → certipy_shadow_auto, targeted_kerberoast, force_change_password\n"
        "5. DELEGATION: Constrained? → constrained_delegation_s4u. Unconstrained? → petitpotam/coercer\n"
        "6. MSSQL: Linked servers? → mssql_enum_linked_servers, mssql_exec_linked\n"
        "7. ADCS: ESC4? → certipy_template_esc4. ESC8? → certipy_relay_esc8 + petitpotam\n"
        "8. LAPS: Try laps_dump for local admin passwords\n"
        "9. Use record_finding to report EVERY discovery\n"
        "10. Continue autonomous execution - don't stop for direction"
    ),
)


async def vulnerability_discovery_hook(event: ToolEnd):  # noqa: PLR0912
    """
    Redirect agent to exploit when vulnerabilities are discovered.

    This hook monitors tool results for vulnerability indicators and
    injects feedback to force immediate exploitation.
    """
    # Only process ToolEnd events
    if not isinstance(event, ToolEnd):
        return None

    if not event.message or not event.message.content:
        return None

    result = str(event.message.content)
    tool_name = event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""

    redirects = []

    # ADCS Vulnerabilities
    esc1_indicators = "recommended_actions" in result or "ACTIONABLE" in result
    if "ESC1" in result and (esc1_indicators or "exploitable" in result.lower()):
        redirects.append(
            "🚨 ESC1 ADCS VULNERABILITY FOUND!\n"
            "→ Try certipy_req_esc1 first with the CA name and template from above\n"
            "→ If RPC fails (ept_s_not_registered), use ESC8 relay instead:\n"
            "   1. certipy_relay_esc8 to start relay listener on web enrollment\n"
            "   2. petitpotam to coerce DC authentication to your relay\n"
            "→ Then run certipy_auth to get Administrator NTLM hash\n"
            "→ DO NOT proceed to other tasks until ESC1/ESC8 is exploited!"
        )

    if "ESC4" in result and ("exploitable" in result.lower() or "vulnerable" in result.lower()):
        redirects.append(
            "🚨 ESC4 ADCS VULNERABILITY FOUND (Template Modification)!\n"
            "→ Use certipy_template_esc4 to modify the template (enable Enrollee Supplies Subject)\n"
            "→ Then run certipy_req_esc1 with the modified template\n"
            "→ Then run certipy_auth to get Administrator NTLM hash\n"
            "→ Remember to restore the template after exploitation!"
        )

    # ESC8 requires explicit ESC8 marker from certipy or specific web enrollment vulnerability context
    is_esc8 = "ESC8" in result and (
        "exploitable" in result.lower() or "vulnerable" in result.lower()
    )
    if is_esc8:
        redirects.append(
            "🚨 ESC8 ADCS VULNERABILITY FOUND (Web Enrollment)!\n"
            "→ Use certipy_relay_esc8 to set up relay listener\n"
            "→ Then use petitpotam or coercer to coerce DC authentication\n"
            "→ Relay will capture DC certificate\n"
            "→ Use certipy_auth with the captured certificate!"
        )

    if any(esc in result for esc in ["ESC2", "ESC3", "ESC6"]):
        redirects.append(
            "⚠️ ADCS vulnerability found (ESC2/3/6)!\n"
            "→ Investigate this path - may require relay attack or additional enumeration"
        )

    # ACL Abuse Paths
    has_acl_indicator = any(
        acl in result.lower() for acl in ["genericall", "genericwrite", "writedacl"]
    )
    is_acl_discovery_tool = tool_name in ["run_bloodhound", "enumerate_users"]
    if has_acl_indicator and is_acl_discovery_tool:
        redirects.append(
            "🎯 ACL ABUSE PATH FOUND!\n"
            "→ BEST: Use certipy_shadow_auto for one-step shadow credentials → NTLM hash\n"
            "→ OR: Use targeted_kerberoast if GenericWrite on user → TGS hash to crack\n"
            "→ OR: Use force_change_password / bloodyad_set_password to reset their password\n"
            "→ OR: Use dacl_edit to grant yourself more permissions (if WriteDacl)\n"
            "→ OR: Use bloodyad_add_group_member to add yourself to privileged groups\n"
            "→ DO NOT summarize until ACL path is exploited!"
        )

    # ForceChangePassword specific
    if "forcechangepassword" in result.lower():
        redirects.append(
            "🔐 FORCECHANGEPASSWORD ACL FOUND!\n"
            "→ Use force_change_password or bloodyad_set_password to reset target's password\n"
            "→ Then use the new credentials for further enumeration!"
        )

    # Delegation
    is_delegation_context = "delegation" in result.lower() or tool_name == "find_delegation"
    if "unconstrained" in result.lower() and is_delegation_context:
        redirects.append(
            "🔗 UNCONSTRAINED DELEGATION FOUND!\n"
            "→ Use petitpotam or coercer to force DC authentication to this machine\n"
            "→ Capture TGT and perform DCSync\n"
            "→ This is a CRITICAL path to Domain Admin!"
        )

    # Constrained delegation
    if "constrained" in result.lower() and is_delegation_context:
        redirects.append(
            "🔗 CONSTRAINED DELEGATION FOUND!\n"
            "→ Use constrained_delegation_s4u to impersonate Administrator to the allowed SPN\n"
            "→ Check msDS-AllowedToDelegateTo for the target SPN\n"
            "→ Use alt_service parameter to access different services (SPN modification)"
        )

    # MSSQL
    is_mssql_context = "mssql" in tool_name.lower() or "sql" in result.lower()
    if "impersonate" in result.lower() and is_mssql_context:
        redirects.append(
            "💾 MSSQL IMPERSONATION POSSIBLE!\n"
            "→ Use mssql_xp_cmdshell with impersonate='sa' to get command execution\n"
            "→ Execute credential harvesting commands"
        )
    if "is_trustworthy_on" in result.lower() and is_mssql_context:
        redirects.append(
            "💾 MSSQL TRUSTWORTHY DATABASE DETECTED!\n"
            "→ Use mssql_execute_as_user (impersonate_user='dbo')\n"
            "→ Check for DB-level impersonation and escalate to sysadmin"
        )

    # MSSQL Linked Servers - require explicit linked server indicators
    has_linked_server = (
        "linked server" in result.lower()
        or "srv_name" in result.lower()
        or "is_linked" in result.lower()
        or "sp_linkedservers" in result.lower()
    )
    if has_linked_server and is_mssql_context:
        redirects.append(
            "💾 MSSQL LINKED SERVERS FOUND!\n"
            "→ Use mssql_exec_linked to execute queries on linked servers\n"
            "→ Chain across servers for cross-domain/forest pivoting\n"
            "→ Try enabling xp_cmdshell on remote servers: sp_configure 'xp_cmdshell', 1"
        )

    # LAPS passwords - only when actual password attribute/value found
    # Avoid false positives from "no LAPS" or "LAPS not configured" messages
    has_laps_data = (
        "ms-mcs-admpwd" in result.lower()
        and "no laps" not in result.lower()
        and "not configured" not in result.lower()
        and "not found" not in result.lower()
    )
    if has_laps_data:
        redirects.append(
            "🔐 LAPS PASSWORDS AVAILABLE!\n"
            "→ These are local Administrator passwords for specific computers\n"
            "→ Use with evil_winrm or psexec against the target computer\n"
            "→ Then run secretsdump on that target!"
        )

    # krbtgt hash
    if "krbtgt" in result.lower() and (":::" in result or "hash" in result.lower()):
        redirects.append(
            "🎫 KRBTGT HASH FOUND!\n"
            "→ If this is a CHILD domain, use raise_child for parent escalation\n"
            "→ Otherwise use generate_golden_ticket then secretsdump all DCs"
        )

    # Password in description - only if non-empty descriptions returned
    # Avoid false positives from "0 entries" or empty results
    if tool_name == "ldap_search_descriptions":
        has_real_description = (
            "description:" in result.lower()
            and "# numEntries: 0" not in result
            and "0 entries" not in result.lower()
        )
        if has_real_description:
            redirects.append(
                "🔐 USER DESCRIPTIONS FOUND - CHECK FOR PASSWORDS!\n"
                "→ Review descriptions for password patterns\n"
                "→ Passwords are sometimes stored in description fields\n"
                "→ Test any found credentials immediately!"
            )

    # Krbtgt hash
    if "krbtgt" in result.lower() and (":::" in result or "hash" in result.lower()):
        redirects.append(
            "👑 KRBTGT HASH FOUND!\n"
            "→ IMMEDIATELY use generate_golden_ticket to forge Enterprise Admin ticket\n"
            "→ Then use secretsdump on ALL domain controllers\n"
            "→ Use raise_child if there are parent domains"
        )

    # Admin hash
    has_admin_indicator = "administrator" in result.lower() and (
        ":::" in result or "ntlm" in result.lower()
    )
    has_hash_pattern = "aad3b435" in result or result.count(":") >= 3
    if has_admin_indicator and has_hash_pattern:
        redirects.append(
            "🔑 ADMINISTRATOR HASH FOUND!\n"
            "→ Use domain_admin_checker with this hash on ALL targets\n"
            "→ Use secretsdump with this hash on ALL targets\n"
            "→ DO NOT summarize - credential pivoting required!"
        )

    if redirects:
        logger.warning("[!] Vulnerability discovery hook triggered - injecting exploit guidance")
        header = "\n\n" + "=" * 50 + "\n⚡ IMMEDIATE ACTION REQUIRED ⚡\n" + "=" * 50 + "\n"
        return header + "\n\n".join(redirects)

    return None


def _track_discovery(vuln_id: str, vuln_type: str, tool: str, step: int) -> None:
    """Helper to track a discovered vulnerability."""
    if vuln_id not in _discovered_vulnerabilities:
        _discovered_vulnerabilities[vuln_id] = {"type": vuln_type, "tool": tool, "step": step}
        logger.info(f"[*] Tracking: {vuln_type} discovered")


def _track_exploitation(tool_name: str) -> None:
    """Helper to track exploitation attempts."""
    exploitation_tools = {
        # ADCS
        "certipy_req_esc1": "esc1_adcs",
        "certipy_auth": "esc1_adcs",
        "certipy_template_esc4": "esc4_adcs",
        "certipy_relay_esc8": "esc8_adcs",
        "certipy_shadow_auto": "acl_abuse",
        # ACL abuse
        "pywhisker": "acl_abuse",
        "bloodyad_set_password": "acl_abuse",  # pragma: allowlist secret
        "bloodyad_add_group_member": "acl_abuse",
        "force_change_password": "acl_abuse",  # pragma: allowlist secret
        "dacl_edit": "acl_abuse",
        "targeted_kerberoast": "acl_abuse",
        # Delegation
        "petitpotam": "unconstrained_delegation",
        "coercer": "unconstrained_delegation",
        "constrained_delegation_s4u": "constrained_delegation",
        # MSSQL
        "mssql_xp_cmdshell": "mssql_impersonation",
        "mssql_enum_linked_servers": "mssql_linked",
        "mssql_exec_linked": "mssql_linked",
        # Golden ticket
        "golden_ticket": "krbtgt_hash",
        "generate_golden_ticket": "krbtgt_hash",
        # Low-hanging fruit
        "ldap_search_descriptions": "ldap_description",
        "username_as_password": "username_password",  # pragma: allowlist secret
        "password_spray": "password_spray",  # pragma: allowlist secret
        "laps_dump": "laps",
    }
    if tool_name in exploitation_tools:
        vuln_type = exploitation_tools[tool_name]
        if vuln_type not in _exploited_vulnerabilities:
            _exploited_vulnerabilities.add(vuln_type)
            logger.info(f"[+] Exploitation attempted: {vuln_type}")


def _track_vulnerability_findings(result: str, tool_name: str, step: int) -> None:
    result_lower = result.lower()
    is_mssql = "mssql" in tool_name.lower() or "sql" in result_lower
    has_acl = any(
        acl in result_lower
        for acl in ["genericall", "genericwrite", "writedacl", "forcechangepassword"]
    )
    is_acl_tool = tool_name in {"run_bloodhound", "enumerate_users"}
    has_linked_server = (
        "linked server" in result_lower
        or "srv_name" in result_lower
        or "is_linked" in result_lower
        or "sp_linkedservers" in result_lower
    )
    has_laps_data = (
        "ms-mcs-admpwd" in result_lower
        and "no laps" not in result_lower
        and "not found" not in result_lower
    )

    checks = [
        (
            "ESC1" in result and ("exploitable" in result_lower or "vulnerable" in result_lower),
            ("esc1_adcs", "ADCS ESC1", "certipy_req_esc1 → certipy_auth"),
        ),
        (
            "ESC4" in result and ("exploitable" in result_lower or "vulnerable" in result_lower),
            (
                "esc4_adcs",
                "ADCS ESC4 (Template Modification)",
                "certipy_template_esc4 → certipy_req_esc1",
            ),
        ),
        (
            "ESC8" in result and ("exploitable" in result_lower or "vulnerable" in result_lower),
            ("esc8_adcs", "ADCS ESC8 (Web Enrollment)", "certipy_relay_esc8 + petitpotam"),
        ),
        (
            has_acl and is_acl_tool,
            (
                "acl_abuse",
                "ACL Abuse Path",
                "certipy_shadow_auto / targeted_kerberoast / force_change_password / dacl_edit",
            ),
        ),
        (
            "unconstrained" in result_lower and "delegation" in result_lower,
            ("unconstrained_delegation", "Unconstrained Delegation", "petitpotam / coercer"),
        ),
        (
            "constrained" in result_lower
            and "delegation" in result_lower
            and "unconstrained" not in result_lower,
            ("constrained_delegation", "Constrained Delegation", "constrained_delegation_s4u"),
        ),
        (
            "impersonate" in result_lower and is_mssql,
            ("mssql_impersonation", "MSSQL Impersonation", "mssql_xp_cmdshell with impersonate"),
        ),
        (
            "is_trustworthy_on" in result_lower and is_mssql,
            (
                "mssql_trustworthy",
                "MSSQL Trustworthy Database",
                "mssql_execute_as_user with impersonate_user='dbo'",
            ),
        ),
        (
            has_linked_server and is_mssql,
            ("mssql_linked", "MSSQL Linked Servers", "mssql_exec_linked"),
        ),
        (has_laps_data, ("laps", "LAPS Passwords", "Use with evil_winrm / psexec")),
        (
            "krbtgt" in result_lower and (":::" in result or "hash" in result_lower),
            ("krbtgt_hash", "Krbtgt Hash", "golden_ticket → secretsdump"),
        ),
    ]

    for condition, (vuln_id, vuln_type, tool) in checks:
        if condition:
            _track_discovery(vuln_id, vuln_type, tool, step)


async def track_vulnerability_discoveries(event: ToolEnd):
    """
    Track discovered vulnerabilities and exploitation attempts.

    This hook monitors tool results to maintain state of what's been
    discovered vs exploited for the periodic priority check.
    """
    # Only process ToolEnd events
    if not isinstance(event, ToolEnd):
        return

    if not event.message or not event.message.content:
        return

    result = str(event.message.content)
    tool_name = event.tool_call.name if hasattr(event, "tool_call") and event.tool_call else ""
    step = _last_step_number or 0
    _track_vulnerability_findings(result, tool_name, step)

    # Track exploitation attempts
    _track_exploitation(tool_name)


async def periodic_priority_check(event: StepStart):
    """
    Periodically remind the agent of unexploited discoveries.

    Fires every N steps to check if there are discovered vulnerabilities
    that haven't been exploited yet, and injects a reminder.
    """
    global _last_priority_check_step

    step_num = getattr(event, "step_number", None)
    if step_num is None:
        return None

    # Only check every N steps
    if step_num - _last_priority_check_step < _PRIORITY_CHECK_INTERVAL:
        return None

    _last_priority_check_step = step_num

    # Find unexploited vulnerabilities
    unexploited = []
    for vuln_id, vuln_info in _discovered_vulnerabilities.items():
        if vuln_id not in _exploited_vulnerabilities:
            steps_ago = step_num - vuln_info["step"]
            unexploited.append(
                f"  - {vuln_info['type']} (found {steps_ago} steps ago)\n"
                f"    → Exploit with: {vuln_info['tool']}"
            )

    if not unexploited:
        return None

    logger.warning(f"[!] Periodic check: {len(unexploited)} unexploited vulnerabilities")

    return (
        "\n\n" + "=" * 50 + "\n"
        "🔔 PRIORITY CHECK: UNEXPLOITED DISCOVERIES 🔔\n" + "=" * 50 + "\n\n"
        "You have discovered vulnerabilities that remain UNEXPLOITED:\n\n"
        + "\n".join(unexploited)
        + "\n\n"
        "⚠️ DO NOT summarize or complete until these are exploited!\n"
        "⚠️ Discovery without exploitation is FAILURE.\n" + "=" * 50
    )


@dn.tool
def complete_operation(summary: str) -> str:
    """
    Mark the red team operation as complete and generate final report.

    Use this tool when you have:
    - Exhausted all credential sources
    - Attempted enumeration on all discovered targets
    - Cracked all obtainable hashes
    - Generated golden ticket (if krbtgt hash was found)
    - Achieved domain admin access (or determined it's not possible)

    Args:
        summary: Executive summary of the operation including:
            - All local administrators found
            - All domain administrators found
            - Attack paths for each admin compromise
            - Total credentials obtained
            - Success metrics achieved

    Returns:
        Confirmation message

    Example:
        >>> complete_operation("Operation successful. Domain admin achieved via...")
    """
    logger.success(f"🎯 Red team operation completed: {summary}")
    return f"✓ Operation marked as complete. Summary: {summary}"


def create_redteam_agent(
    model: str,
    mitre_client: MITREAttackClient,
    state: RedTeamState,
    max_steps: int = 200,
) -> Agent:
    """
    Create a configured red team agent.

    Args:
        model: LLM model to use
        mitre_client: Initialized MITRE ATT&CK client
        state: Red team operation state object
        max_steps: Maximum agent steps (default: 200 for complex operations)

    Returns:
        Configured agent ready for penetration testing operations
    """
    # Reset event tracking for fresh agent run
    reset_event_tracking()

    # Initialize toolsets
    network_tools = NetworkEnumerationTools()
    network_tools.set_state(state)

    # LOW-HANGING FRUIT TOOLS (run these first!)
    credential_discovery_tools = CredentialDiscoveryTools()
    credential_discovery_tools.set_state(state)

    credential_tools = CredentialHarvestingTools()
    credential_tools.set_state(state)

    cracking_tools = CrackingTools()
    cracking_tools.set_state(state)

    share_tools = SharePilferingTools()
    share_tools.set_state(state)

    golden_ticket_tools = GoldenTicketTools()
    golden_ticket_tools.set_state(state)

    # AD analysis toolsets
    bloodhound_tools = BloodHoundTools()
    bloodhound_tools.set_state(state)

    certipy_tools = CertipyTools()
    certipy_tools.set_state(state)

    delegation_tools = DelegationTools()
    delegation_tools.set_state(state)

    reporting_tools = RedTeamReportingTools()
    reporting_tools.set_state(state)

    # New exploitation toolsets (CAP-838)
    coercion_tools = CoercionTools()
    coercion_tools.set_state(state)

    mssql_tools = MSSQLTools()
    mssql_tools.set_state(state)

    acl_tools = ACLExploitTools()
    acl_tools.set_state(state)

    cve_tools = CVEExploitTools()
    cve_tools.set_state(state)

    trust_tools = TrustAttackTools()
    trust_tools.set_state(state)

    lateral_tools = LateralMovementTools()
    lateral_tools.set_state(state)

    tools: list = [
        network_tools,
        # LOW-HANGING FRUIT (prioritize these for quick wins)
        credential_discovery_tools,
        credential_tools,
        cracking_tools,
        share_tools,
        golden_ticket_tools,
        bloodhound_tools,
        certipy_tools,
        delegation_tools,
        # Exploitation tools
        coercion_tools,
        mssql_tools,
        acl_tools,
        cve_tools,
        trust_tools,
        lateral_tools,
        # Reporting and completion
        reporting_tools,
        complete_operation,
    ]

    logger.info(f"Creating red team agent with {len(tools)} toolsets")

    return dn.Agent(
        name="Ares Red Team Operator",
        model=model,
        instructions=REDTEAM_SYSTEM_INSTRUCTIONS,
        max_steps=max_steps,
        tools=tools,
        hooks=[
            log_step_start,
            log_generation_end,
            log_agent_error,
            log_agent_end,
            log_tool_usage,
            log_tool_result,
            vulnerability_discovery_hook,  # Force exploitation when vulns found
            track_vulnerability_discoveries,  # Track discovered vs exploited vulns
            periodic_priority_check,  # Remind agent of unexploited discoveries
            unstall_hook,
        ],
        stop_conditions=[
            tool_use("complete_operation"),
        ],
        thread=Thread(),  # type: ignore[call-arg]
    )
