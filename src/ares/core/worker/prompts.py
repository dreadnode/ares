"""Prompt generation for worker tasks.

This module provides utilities for generating prompts from task payloads
and formatting shared state context for task execution. All prompt content
lives in Jinja templates under ``templates/redteam/tasks/``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ares.core.messages import MessageType
from ares.core.templates import get_template_loader
from ares.core.worker.dc_resolution import resolve_dc_ip_for_domain

if TYPE_CHECKING:
    from ares.core.models import SharedRedTeamState
    from ares.core.task_queue import TaskMessage


def _render(template_name: str, **ctx: Any) -> str:
    """Render a task template with the given context."""
    return get_template_loader().render(f"redteam/tasks/{template_name}", **ctx)


def _is_pass_the_hash_compatible(hash_value: str | None) -> bool:
    """Check if a hash value is compatible with pass-the-hash attacks (NTLM format)."""
    if not hash_value:
        return False
    normalized = hash_value.strip()
    if "$" in normalized:
        return False
    if ":" in normalized:
        parts = normalized.split(":")
        if len(parts) != 2:
            return False
        lm_part, ntlm_part = parts
        if lm_part and not re.fullmatch(r"[0-9a-fA-F]{32}", lm_part):
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", ntlm_part))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", normalized))


def format_state_context(
    state: SharedRedTeamState | None,
    task_type: str,
    current_target: str | None = None,
) -> str:
    """Format shared state as context for task prompts.

    Args:
        state: The shared red team state
        task_type: Type of task (lateral, credential_access, exploit, coercion)
        current_target: The primary target of this task (for prioritization)

    Returns:
        Formatted state context string to append to task prompts
    """
    if not state:
        return ""

    cracked_hashes = [h for h in state.all_hashes if h.cracked_password] if state.all_hashes else []
    dc_hosts = [h for h in state.all_hosts if h.is_dc] if state.all_hosts else []
    other_hosts = [h for h in state.all_hosts if not h.is_dc] if state.all_hosts else []

    unexploited_vulns = []
    if hasattr(state, "discovered_vulnerabilities") and state.discovered_vulnerabilities:
        unexploited_vulns = [
            v
            for v in list(state.discovered_vulnerabilities.values())
            if v.vuln_id not in state.exploited_vulnerabilities
        ]

    return _render(
        "state_context.md.jinja",
        state=state,
        cracked_hashes=cracked_hashes,
        dc_hosts=dc_hosts,
        other_hosts=other_hosts,
        unexploited_vulns=unexploited_vulns,
    )


# ---------------------------------------------------------------------------
# Dispatcher-based message prompt generators (TASK_PROMPTS)
# ---------------------------------------------------------------------------


def _dispatch_crack(msg: Any) -> str:
    return _render(
        "dispatch_crack.md.jinja",
        username=msg.username,
        domain=msg.domain,
        hash_value=msg.hash_value,
        hash_type=msg.hash_type,
        wordlist=msg.wordlist,
        task_id=msg.task_id,
    )


def _dispatch_lateral(msg: Any) -> str:
    cred_type = "password" if msg.password else "hash"
    cred_value = msg.password or msg.hash_value or "N/A"
    return _render(
        "dispatch_lateral.md.jinja",
        target_host=msg.target_host,
        domain=msg.domain,
        username=msg.username,
        cred_type=cred_type,
        cred_value=cred_value,
        method=getattr(msg, "method", None),
        task_id=msg.task_id,
    )


def _dispatch_acl_analysis(msg: Any) -> str:
    return _render(
        "dispatch_acl_analysis.md.jinja",
        target_user=msg.target_user,
        domain=msg.domain,
        find_path_to=msg.find_path_to,
        task_id=msg.task_id,
    )


def _dispatch_credential_access(msg: Any) -> str:
    cred_type = "password" if msg.password else "hash" if msg.hash_value else "none"
    cred_value = msg.password or msg.hash_value or "N/A"
    return _render(
        "dispatch_credential_access.md.jinja",
        domain=msg.domain,
        target_ips=msg.target_ips or [],
        username=msg.username,
        cred_type=cred_type,
        cred_value=cred_value,
        techniques=msg.techniques or [],
        task_id=msg.task_id,
    )


def _dispatch_exploit(msg: Any) -> str:
    return _render(
        "dispatch_exploit.md.jinja",
        vuln_type=msg.vuln_type,
        target=msg.target,
        vuln_id=msg.vuln_id,
        params=msg.params,
        task_id=msg.task_id,
    )


def _dispatch_coercion(msg: Any) -> str:
    return _render(
        "dispatch_coercion.md.jinja",
        interface=msg.interface,
        techniques=msg.techniques,
        duration=msg.duration,
        task_id=msg.task_id,
    )


TASK_PROMPTS: dict[MessageType, Any] = {
    MessageType.CRACK_REQUEST: _dispatch_crack,
    MessageType.LATERAL_REQUEST: _dispatch_lateral,
    MessageType.ACL_ANALYSIS_REQUEST: _dispatch_acl_analysis,
    MessageType.CREDENTIAL_ACCESS_REQUEST: _dispatch_credential_access,
    MessageType.EXPLOIT_REQUEST: _dispatch_exploit,
    MessageType.COERCION_REQUEST: _dispatch_coercion,
}


# ---------------------------------------------------------------------------
# Redis task-queue prompt generation
# ---------------------------------------------------------------------------


def generate_prompt_from_task(
    task: TaskMessage,
    state: SharedRedTeamState | None = None,
) -> str | None:
    """Generate agent prompt from Redis TaskMessage.

    Args:
        task: TaskMessage from Redis queue
        state: Optional shared state to include context

    Returns:
        Prompt string for the agent, or None for direct-execution tasks.
    """
    payload = task.payload

    if task.task_type == "crack":
        return _render(
            "crack.md.jinja",
            username=payload.get("username", "unknown"),
            domain=payload.get("domain", ""),
            hash_value=payload["hash_value"],
            hash_type=payload["hash_type"],
            wordlist=payload.get("wordlist", "rockyou.txt"),
            task_id=task.task_id,
        )

    if task.task_type == "lateral":
        return _generate_lateral_prompt(task, payload, state)

    if task.task_type == "acl_analysis":
        base = _render(
            "acl_analysis.md.jinja",
            target_user=payload["target_user"],
            domain=payload["domain"],
            find_path_to=payload.get("find_path_to", "Domain Admins"),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "acl_analysis")

    if task.task_type == "credential_access":
        return _generate_credential_access_prompt(task, payload, state)

    if task.task_type == "exploit":
        return _generate_exploit_prompt(task, payload, state)

    if task.task_type == "coercion":
        return _generate_coercion_prompt(task, payload, state)

    if task.task_type == "privesc_enumeration":
        return _generate_privesc_enumeration_prompt(task, payload, state)

    if task.task_type == "recon":
        return _generate_recon_prompt(task, payload, state)

    # "command" tasks are handled specially - executed directly, not via agent
    if task.task_type == "command":
        return None

    # Generic fallback
    return f"Execute task: {task.task_type}\nPayload: {payload}\nTask ID: {task.task_id}"


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------


def _generate_lateral_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    action = payload.get("action", "")

    # Special handling for proactive MSSQL enumeration
    if action == "mssql_enum_impersonation":
        target = payload.get("target", "")
        base = _render(
            "lateral_mssql_enum.md.jinja",
            target=target,
            username=payload.get("username", ""),
            password=payload.get("password", ""),
            domain=payload.get("domain", ""),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "lateral", current_target=target)

    # Standard lateral movement
    cred_type = "password" if payload.get("password") else "hash"
    cred_value = payload.get("password") or payload.get("hash_value") or "N/A"
    target_host = payload.get("target_host", "")
    base = _render(
        "lateral.md.jinja",
        target_host=target_host,
        domain=payload.get("domain", ""),
        username=payload["username"],
        cred_type=cred_type,
        cred_value=cred_value,
        method=payload.get("method"),
        task_id=task.task_id,
    )
    return base + format_state_context(state, "lateral", current_target=target_host)


# ---------------------------------------------------------------------------
# Coercion
# ---------------------------------------------------------------------------


def _generate_coercion_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    from ares.core.config import get_default_network_interface

    techniques = payload.get("techniques", ["LLMNR", "NBT-NS"])
    interface = payload.get("interface") or get_default_network_interface()

    base = _render(
        "coercion.md.jinja",
        interface=interface,
        techniques=techniques,
        duration=payload.get("duration", 300),
        attack_type=payload.get("attack_type", "passive"),
        adcs_server=payload.get("adcs_server", ""),
        coerce_target=payload.get("coerce_target", ""),
        coerce_hostname=payload.get("coerce_hostname", ""),
        task_id=task.task_id,
    )
    return base + format_state_context(state, "coercion")


# ---------------------------------------------------------------------------
# Credential access
# ---------------------------------------------------------------------------


def _generate_credential_access_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for credential access tasks."""
    hash_value = payload.get("hash_value")
    hash_is_pth = _is_pass_the_hash_compatible(hash_value)
    techniques = payload.get("techniques", []) or []
    if hash_value and not hash_is_pth:
        techniques = [t for t in techniques if t.lower() not in {"secretsdump", "lsassy"}]

    cred_type = (
        "password" if payload.get("password") else "hash" if payload.get("hash_value") else "none"
    )
    targets = payload.get("target_ips") or []
    dc_ip = payload.get("dc_ip") or ""
    domain = payload.get("domain", "")

    # Handle Kerberos ticket-based auth (from S4U attack auto-chain)
    ticket_path = payload.get("ticket_path")
    no_pass = payload.get("no_pass", False)
    if ticket_path and no_pass and "secretsdump" in techniques:
        target = targets[0] if targets else ""
        username = payload.get("username", "Administrator")
        base = _render(
            "credential_access_kerberos_ticket.md.jinja",
            target=target,
            domain=domain,
            username=username,
            ticket_path=ticket_path,
            dc_ip=dc_ip,
            task_id=task.task_id,
        )
        return base + format_state_context(state, "credential_access", current_target=target)

    # Validate/re-resolve DC IP for Kerberos operations
    dc_warning = None
    kerberos_techniques = {"kerberoast", "as_rep_roast", "secretsdump", "lsassy", "laps_dump"}
    if any(t in kerberos_techniques for t in techniques) and domain:
        dc_ip, dc_warning = resolve_dc_ip_for_domain(state, domain, dc_ip or "")

    reason = payload.get("reason") or ""
    source = payload.get("credential_source") or ""
    hash_type = payload.get("hash_type") or ""
    hash_note = ""
    if hash_value and not hash_is_pth:
        cred_type = "hash (non-NTLM)"
        hash_note = (
            "NOTE: Provided hash is not NTLM pass-the-hash compatible; "
            "do not attempt secretsdump/lsassy with it."
        )

    # Check if this is a low_hanging_fruit task
    has_sysvol = any(t in techniques for t in ("sysvol_script_search", "gpp_password_finder"))
    has_spray = any(t in techniques for t in ("username_as_password", "password_spray"))
    has_low_hanging = "low_hanging_fruit" in reason.lower() or has_sysvol or has_spray

    if has_low_hanging and payload.get("password"):
        base = _render(
            "credential_access_low_hanging.md.jinja",
            domain=domain,
            dc_ip=dc_ip,
            username=payload.get("username"),
            password=payload.get("password"),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "credential_access", current_target=dc_ip)

    # Specific username_as_password task (for new users without creds)
    is_username_spray = "username_as_password" in techniques and "new_users" in reason.lower()
    if is_username_spray:
        base = _render(
            "credential_access_username_spray.md.jinja",
            domain=domain,
            dc_ip=dc_ip,
            username=payload.get("username") or "",
            password=payload.get("password") or "",
            task_id=task.task_id,
        )
        return base + format_state_context(state, "credential_access", current_target=dc_ip)

    # Share spider task
    is_share_spider = "share_spider" in techniques
    if is_share_spider and payload.get("password"):
        username = payload.get("username") or ""
        password = payload.get("password") or ""
        target_ip = targets[0] if targets else ""
        share_name = ""
        if "auto_share_spider_" in reason.lower():
            share_name = reason.lower().split("auto_share_spider_")[-1]
        base = _render(
            "credential_access_share_spider.md.jinja",
            target_ip=target_ip,
            domain=domain,
            username=username,
            password=password,
            share_name=share_name,
            task_id=task.task_id,
        )
        return base + format_state_context(state, "credential_access", current_target=target_ip)

    # No-cred technique enforcement
    no_cred_techniques = not payload.get("password") and not payload.get("hash_value")
    if techniques and no_cred_techniques:
        instructions = _build_no_cred_technique_instructions(techniques, dc_ip, domain)
        if instructions:
            base = _render(
                "credential_access_no_cred_techniques.md.jinja",
                domain=domain,
                dc_ip=dc_ip,
                targets=targets,
                task_id=task.task_id,
                technique_instructions=instructions,
            )
            return base + format_state_context(state, "credential_access", current_target=dc_ip)

    # Low hanging fruit WITHOUT credentials
    if has_low_hanging and not payload.get("password") and not payload.get("hash_value"):
        base = _render(
            "credential_access_low_hanging_no_cred.md.jinja",
            domain=domain,
            dc_ip=dc_ip,
            task_id=task.task_id,
        )
        return base + format_state_context(state, "credential_access", current_target=dc_ip)

    # Explicit technique enforcement with credentials
    has_creds = payload.get("password") or (hash_is_pth and hash_value)
    if techniques and has_creds:
        instructions = _build_cred_technique_instructions(techniques, payload, dc_ip, hash_value)
        if instructions:
            cred_display = payload.get("password") or f"[HASH] {hash_value}"
            base = _render(
                "credential_access_mandatory_techniques.md.jinja",
                domain=domain,
                dc_ip=dc_ip,
                dc_warning=dc_warning,
                targets=targets,
                username=payload.get("username"),
                cred_display=cred_display,
                task_id=task.task_id,
                technique_instructions=instructions,
            )
            return base + format_state_context(state, "credential_access", current_target=dc_ip)

    # Default credential access
    base = _render(
        "credential_access_default.md.jinja",
        domain=domain,
        targets=targets,
        dc_ip=dc_ip,
        username=payload.get("username"),
        cred_type=cred_type,
        cred_value=payload.get("password") or payload.get("hash_value") or "N/A",
        hash_type=hash_type,
        source=source,
        reason=reason,
        techniques=techniques,
        task_id=task.task_id,
        hash_note=hash_note,
    )
    return base + format_state_context(state, "credential_access", current_target=dc_ip)


def _build_no_cred_technique_instructions(
    techniques: list[str], dc_ip: str, domain: str
) -> list[str]:
    """Build numbered technique instructions for no-credential scenarios."""
    technique_map = {
        "asrep_roast": (
            f"asrep_roast(target='{dc_ip}', domain='{domain}') "
            "- find users without Kerberos pre-auth"
        ),
        "username_as_password": (
            f"username_as_password(target='{dc_ip}', domain='{domain}') "
            "- test if users have username=password (e.g., testuser:testuser)"
        ),
        "password_spray": (
            f"password_spray(target='{dc_ip}', domain='{domain}', "
            "password='Password1') - try common passwords"  # pragma: allowlist secret
        ),
        "kerberos_user_enum_noauth": (
            f"kerberos_user_enum_noauth(target='{dc_ip}', domain='{domain}') "
            "- enumerate valid usernames via Kerberos"
        ),
    }
    instructions = []
    for i, technique in enumerate(techniques, 1):
        if technique in technique_map:
            instructions.append(f"{i}. {technique_map[technique]}")
        else:
            instructions.append(f"{i}. {technique}(...)")
    return instructions


def _build_cred_technique_instructions(
    techniques: list[str],
    payload: dict[str, Any],
    dc_ip: str,
    hash_value: str | None,
) -> list[str]:
    """Build numbered technique instructions for credentialed scenarios."""
    cred_param = (
        f"password='{payload.get('password')}'"
        if payload.get("password")
        else f"hashes='{hash_value}'"
    )
    username = payload.get("username", "")
    domain = payload.get("domain", "")

    technique_map = {
        "sysvol_script_search": (
            f"sysvol_script_search(target='{dc_ip}', username='{username}', "
            f"{cred_param}, domain='{domain}') "
            "- ~2 seconds, finds hardcoded passwords in login scripts"
        ),
        "gpp_password_finder": (
            f"gpp_password_finder(target='{dc_ip}', username='{username}', "
            f"{cred_param}, domain='{domain}') "
            "- ~2 seconds, finds GPP/cpassword credentials"
        ),
        "ldap_search_descriptions": (
            f"ldap_search_descriptions(target='{dc_ip}', username='{username}', "
            f"{cred_param}, domain='{domain}') "
            "- finds passwords in LDAP description fields"
        ),
        "kerberoast": (
            f"kerberoast(domain='{domain}', username='{username}', "
            f"{cred_param}, dc_ip='{dc_ip}') "
            "- service account hashes (uses correct DC for the domain)"
        ),
        "secretsdump": (
            f"secretsdump(target='{dc_ip}', username='{username}', "
            f"{cred_param}, domain='{domain}') "
            "- dump hashes (requires admin)"
        ),
        "lsassy": (
            f"lsassy(target='{dc_ip}', username='{username}', "
            f"{cred_param}, domain='{domain}') "
            "- LSASS memory dump"
        ),
        "laps_dump": (
            f"laps_dump(target='{dc_ip}', username='{username}', "
            f"{cred_param}, domain='{domain}') "
            "- LAPS local admin passwords"
        ),
    }
    instructions = []
    for i, technique in enumerate(techniques, 1):
        if technique in technique_map:
            instructions.append(f"{i}. {technique_map[technique]}")
        else:
            instructions.append(f"{i}. {technique}(...)")
    return instructions


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------


def _generate_exploit_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for exploit tasks."""
    vuln_type = payload.get("vuln_type", "")
    target = payload.get("target", "")
    base_prompt = (
        f"Exploit vulnerability:\n"
        f"Type: {vuln_type}\n"
        f"Target: {target}\n"
        f"Vuln ID: {payload.get('vuln_id', 'unknown')}\n"
        f"Params: {payload}\n"
        f"Task ID: {task.task_id}\n\n"
    )

    if vuln_type == "adcs_enumerate":
        base = _render(
            "exploit_adcs_enumerate.md.jinja",
            target=target,
            domain=payload.get("domain", ""),
            dc_ip=payload.get("dc_ip", target),
            username=payload.get("username", ""),
            password=payload.get("password", ""),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "exploit", current_target=target)

    if vuln_type.lower().startswith("mssql_"):
        return _generate_mssql_exploit_prompt(task, payload, state, base_prompt, target)

    if vuln_type == "constrained_delegation":
        return _generate_constrained_delegation_prompt(task, payload, state, target)

    if vuln_type == "unconstrained_delegation":
        base = _render(
            "exploit_unconstrained_delegation.md.jinja",
            account=payload.get("account", target),
            domain=payload.get("domain", ""),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "exploit", current_target=target)

    if vuln_type == "trust_key_extraction":
        base = _render(
            "exploit_trust_key_extraction.md.jinja",
            domain=payload.get("domain", ""),
            trusted_domain=payload.get("trusted_domain", ""),
            dc_ip=payload.get("dc_ip", target),
            username=payload.get("username", "Administrator"),
            password=payload.get("password", ""),
            use_hash=payload.get("use_hash", False),
            source_sid=payload.get("source_sid", ""),
            target_sid=payload.get("target_sid", ""),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "exploit", current_target=target)

    # ADCS ESC vulnerabilities
    vuln_type_lower = vuln_type.lower()
    if "esc1" in vuln_type_lower or "esc4" in vuln_type_lower or "esc8" in vuln_type_lower:
        base = _render(
            "exploit_adcs_esc.md.jinja",
            vuln_type=vuln_type,
            ca_server=payload.get("ca_server", target),
            template=payload.get("template", ""),
            domain=payload.get("domain", ""),
            enrollee_user=payload.get("enrollee_user", payload.get("username", "")),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "exploit", current_target=target)

    # Cross-forest trust key extraction via tool field
    tool = payload.get("tool", "")
    if tool == "extract_trust_key":
        base = _render(
            "exploit_cross_forest_trust_key.md.jinja",
            domain=payload.get("domain", ""),
            dc_ip=payload.get("dc_ip", target),
            trusted_domain=payload.get("trusted_domain", ""),
            username=payload.get("username", ""),
            password=payload.get("password", ""),
            use_hash=payload.get("use_hash", False),
            source_sid=payload.get("source_sid", ""),
            target_sid=payload.get("target_sid", ""),
            task_id=task.task_id,
        )
        return base + format_state_context(state, "exploit", current_target=target)

    # Default exploit prompt
    base = _render("exploit_default.md.jinja", base_prompt=base_prompt)
    return base + format_state_context(state, "exploit", current_target=target)


# ---------------------------------------------------------------------------
# MSSQL exploits
# ---------------------------------------------------------------------------


def _generate_mssql_cross_forest_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
    base_prompt: str,
    target: str,
) -> str:
    """Generate prompt for MSSQL cross-forest linked server pivot.

    Prompt content is loaded from the Jinja template
    ``redteam/tasks/exploit_mssql_cross_forest.md.jinja``.
    """
    available_creds = payload.get("available_credentials", [])
    parsed_creds: list[dict[str, Any]] = []
    if available_creds:
        for cred in available_creds:
            if isinstance(cred, str):
                import json as _json

                try:
                    cred = _json.loads(cred)  # noqa: PLW2901
                except (ValueError, TypeError):
                    continue
            if isinstance(cred, dict):
                parsed_creds.append(cred)

    mssql_port = payload.get("mssql_port", 1433)

    rendered = _render(
        "exploit_mssql_cross_forest.md.jinja",
        target=target,
        mssql_port=mssql_port,
        credentials=parsed_creds,
        task_id=task.task_id,
    )

    prompt = base_prompt + rendered
    return prompt + format_state_context(state, "exploit", current_target=target)


def _generate_mssql_exploit_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
    base_prompt: str,
    target: str,
) -> str:
    """Generate prompt for MSSQL exploit tasks."""
    vuln_type = (payload.get("vuln_type") or "").lower()

    if vuln_type == "mssql_cross_forest_pivot":
        return _generate_mssql_cross_forest_prompt(task, payload, state, base_prompt, target)

    # Detect cross-forest target even for mssql_impersonation/mssql_linked_server tasks
    if state and state.has_domain_admin:
        undominated = state.get_undominated_forests()
        if undominated:
            note = (payload.get("note") or "") if payload else ""
            hostname = (payload.get("hostname") or "") if payload else ""
            host_domain = hostname.lower().split(".", 1)[-1] if "." in hostname else ""
            is_foreign = host_domain and (
                host_domain in {d.lower() for d in undominated} or "cross-forest" in note.lower()
            )
            if is_foreign:
                return _generate_mssql_cross_forest_prompt(
                    task, payload, state, base_prompt, target
                )

    # Build credentials section for available SQL creds
    available_creds = payload.get("available_credentials", [])
    creds_section = ""
    if available_creds:
        creds_section = "\n**AVAILABLE SQL CREDENTIALS (use these!):**\n"
        for cred in available_creds:
            if isinstance(cred, str):
                import json as _json

                try:
                    cred = _json.loads(cred)  # noqa: PLW2901
                except (ValueError, TypeError):
                    continue
            is_sql = cred.get("is_sql_account", "False") == "True"
            marker = " [SQL SERVICE ACCOUNT]" if is_sql else ""
            creds_section += (
                f"- {cred.get('domain', '')}\\{cred.get('username', '')}: "
                f"{cred.get('password', '')}{marker}\n"
            )

    base = _render(
        "exploit_mssql.md.jinja",
        base_prompt=base_prompt,
        target=target,
        creds_section=creds_section,
    )
    return base + format_state_context(state, "exploit", current_target=target)


# ---------------------------------------------------------------------------
# Constrained delegation
# ---------------------------------------------------------------------------


def _generate_constrained_delegation_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
    target: str,
) -> str:
    """Generate prompt for constrained delegation exploit tasks."""
    account = payload.get("account") or payload.get("account_name") or target
    target_spn = payload.get("target_spn", "")
    domain = payload.get("domain", "")
    username = payload.get("username") or payload.get("account_name") or account
    password = payload.get("password", "")

    # Look up password from shared state if not in payload
    if not password and state:
        creds = getattr(state, "all_credentials", getattr(state, "credentials", []))
        for cred in creds:
            if cred.username.lower() == username.lower() and cred.password:
                password = cred.password
                break

    dc_ip = payload.get("dc_ip", "")
    target_hostname = ""
    if "/" in target_spn:
        target_hostname = target_spn.split("/", 1)[1]
    target_ip = payload.get("target_ip") or target_hostname or ""

    base = _render(
        "exploit_constrained_delegation.md.jinja",
        account=account,
        target_spn=target_spn,
        target_hostname=target_hostname,
        target_ip=target_ip,
        domain=domain,
        username=username,
        password=password,
        dc_ip=dc_ip,
        task_id=task.task_id,
    )
    return base + format_state_context(state, "exploit", current_target=target)


# ---------------------------------------------------------------------------
# Privesc enumeration
# ---------------------------------------------------------------------------


def _generate_privesc_enumeration_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for privilege escalation enumeration tasks."""
    domain = payload.get("domain", "")
    dc_ip = payload.get("dc_ip", "")
    username = payload.get("username", "")
    password = payload.get("password", "")
    techniques = payload.get("techniques", [])

    if domain:
        dc_ip, dc_warning = resolve_dc_ip_for_domain(state, domain, dc_ip or "")
    else:
        dc_warning = None

    technique_instructions = []
    for i, technique in enumerate(techniques, 1):
        if technique == "find_delegation":
            technique_instructions.append(
                f"{i}. find_delegation(domain='{domain}', username='{username}', "
                f"password='{password}', dc_ip='{dc_ip}') - Find accounts with Kerberos delegation"
            )
        else:
            technique_instructions.append(f"{i}. {technique}(...)")

    base = _render(
        "privesc_enumeration.md.jinja",
        domain=domain,
        dc_ip=dc_ip,
        dc_warning=dc_warning,
        username=username,
        password=password,
        task_id=task.task_id,
        technique_instructions=technique_instructions,
    )
    return base + format_state_context(state, "privesc", current_target=dc_ip)


# ---------------------------------------------------------------------------
# Recon
# ---------------------------------------------------------------------------


def _generate_recon_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for reconnaissance tasks."""
    techniques = payload.get("techniques", [])
    target_ips = payload.get("target_ips", [])
    domain = payload.get("domain", "")
    dc_ip = payload.get("dc_ip", "")
    username = payload.get("username", "")
    password = payload.get("password", "")
    hash_value = payload.get("hash_value", "")
    reason = payload.get("reason", "")

    # Build credential info
    cred_line = ""
    if username:
        if password:
            cred_line = f"Credentials: {domain}\\{username} / {password}"
        elif hash_value:
            cred_line = f"Credentials: {domain}\\{username} (hash: {hash_value})"
        else:
            cred_line = f"User context: {domain}\\{username}"

    # Build target info
    targets_str = ", ".join(target_ips[:10]) if target_ips else "N/A"
    if len(target_ips) > 10:
        targets_str += f" ... ({len(target_ips)} total)"

    # Build technique instructions
    technique_instructions = []
    for tech in techniques:
        if tech == "nmap_scan":
            technique_instructions.append(
                f"- **nmap_scan(target='{targets_str}')** - Scan for open ports and services"
            )
        elif tech == "enumerate_users":
            technique_instructions.append(
                f"- **enumerate_users(target='{dc_ip}', domain='{domain}')** - List domain users"
            )
        elif tech == "enumerate_shares":
            technique_instructions.append(
                f"- **enumerate_shares(target='{targets_str}')** - Find SMB shares"
            )
        elif tech == "run_bloodhound":
            technique_instructions.append(
                f"- **run_bloodhound(domain='{domain}', dc_ip='{dc_ip}')** - Collect AD data for path analysis"
            )
        elif tech == "smb_signing_check":
            technique_instructions.append(
                f"- **smb_signing_check(targets='{targets_str}')** - Find relay-able hosts"
            )
        else:
            technique_instructions.append(f"- **{tech}(...)**")

    techniques_section = (
        "\n".join(technique_instructions)
        if technique_instructions
        else "Execute appropriate reconnaissance for the task."
    )

    base = _render(
        "recon.md.jinja",
        targets_str=targets_str,
        domain=domain,
        dc_ip=dc_ip,
        cred_line=cred_line,
        reason=reason,
        task_id=task.task_id,
        techniques_section=techniques_section,
    )

    return base + format_state_context(
        state, "recon", current_target=target_ips[0] if target_ips else dc_ip
    )


__all__ = [
    "TASK_PROMPTS",
    "_is_pass_the_hash_compatible",
    "format_state_context",
    "generate_prompt_from_task",
]
